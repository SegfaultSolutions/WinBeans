#include "stdafx.h"
#include "PE.h"
#include "GUI.h"

// WARNING: 
// 
// Scrolling through this file may potentially trigger seizures for people with
// any common sense and or software design experience.
// Nerd discretion is advised.
// 
// This implementation is open to criticism.
// If you can crash it, I wanna know about it! :)

std::vector<PE*> BinList;
std::atomic_uint32_t index = 0;

BOOL
PE::LoadBinary (LPWSTR path) {

	StringCchCopyW (savedPath, MAX_PATH, path);
	StringCchCopyW (savedBasename, MAX_PATH, path);

	PathStripPathW (savedBasename);
	_wcsupr_s (savedBasename, MAX_PATH);

	if (!savedPath) {
		LogMeA (WARN, "Couldn't retrieve path to executable.");
		return false;
	}

	binary = CreateFileW (savedPath, GENERIC_READ, FILE_SHARE_READ, NULL,
						  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!binary) {
		LogMeA (WARN, "Couldn't open file!");
		return false;
	}

	mapped = CreateFileMappingW (binary, NULL, PAGE_READONLY, 0, 0, NULL);

	if (!mapped) {
		LogMeA (WARN, "Couldn't map file to memory!");
		return false;
	}

	data = MapViewOfFile (_Notnull_ mapped, FILE_MAP_READ, 0, 0, 0);

	if (!data) {
		LogMeA (WARN, "Couldn't read file!");
		return false;
	}

	m_fileSizeB = GetFileSize (binary, NULL);

	dosHdr = (PIMAGE_DOS_HEADER)data;
	ntHdr32 = (PIMAGE_NT_HEADERS32)((PBYTE)data + (DWORD)dosHdr->e_lfanew);
	ntHdr64 = (PIMAGE_NT_HEADERS64)((PBYTE)data + (DWORD)dosHdr->e_lfanew);
	fileHdr = &ntHdr64->FileHeader;
	optHdr32 = &ntHdr32->OptionalHeader;
	optHdr64 = &ntHdr64->OptionalHeader;
	
	if (dosHdr->e_magic == 0x4D5A) {
		MessageBoxW (rootWnd, L"DOS-only Header ('ZM') detected.\r\nFile is a DOS executable and won't run on modern Windows.",
					 savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
		return false;
	}
	else if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		MessageBoxW (rootWnd, L"DOS Header Missing.\r\nFile is either malformed or not an executable.",
					 savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
		return false;
	}

	if (((uint64_t)ntHdr64 - (uint64_t)data) > m_fileSizeB ||												// dosHdr->e_lfanew could be huge
		ntHdr64->Signature != IMAGE_NT_SIGNATURE) {															// and/or junk, this is a safeguard.
		MessageBoxW (rootWnd, L"NT Header Missing.\r\nFile could be malformed or a DOS executable.",
					 savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
		return false;
	}

	m_MakeDosStrings ();

	if (((uint64_t)fileHdr - (uint64_t)data) > m_fileSizeB) {
		MessageBoxW (rootWnd, L"This file is malformed and WinBeans doesn't know how to handle it.",
					 savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
		return false;
	}

	m_MakeFileStrings ();

	if (optHdr32->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
		(uint64_t)optHdr32 - (uint64_t)data < m_fileSizeB) {
		m_MakeOptionalStrings32 ();
		secHdr = (PIMAGE_SECTION_HEADER)((int64_t)ntHdr32 + sizeof (IMAGE_NT_HEADERS32));
	}
	
	if (optHdr64->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
		(uint64_t)optHdr64 - (uint64_t)data < m_fileSizeB) {		
		m_MakeOptionalStrings64 ();
		secHdr = (PIMAGE_SECTION_HEADER)((int64_t)ntHdr64 + sizeof (IMAGE_NT_HEADERS64));
	}

	if (((uint64_t)secHdr - (uint64_t)data) > m_fileSizeB) {	
		MessageBoxW (rootWnd, L"This file is malformed and WinBeans doesn't know how to handle it.",
					 savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
		return false;
	}

	m_MakeSectionStrings ();
	m_MakeSummary ();

	LogMeW (INFO, savedBasename);
	return true;
}

VOID
PE::MakeTreeView (HWND leftWnd) {

	HTREEITEM hFileRoot;
	
	Heading DOS{ (LPWSTR)L"DOS Header", 1, NULL };
	Heading NT{ (LPWSTR)L"NT Header", 1, NULL };
	Heading SEC{ (LPWSTR)L"Section Headers", 1, NULL };

	hFileRoot = this->MakeTreeRoot (leftWnd, savedBasename);
	DOS.childHeader = this->MakeTreeItem (leftWnd, hFileRoot, DOS.headerName, DOSHDR);
	NT.childHeader = this->MakeTreeItem (leftWnd, hFileRoot, NT.headerName, NTHDR);
	SEC.childHeader = this->MakeTreeItem (leftWnd, hFileRoot, SEC.headerName, SECHDR);

	this->MakeTreeItem (leftWnd, NT.childHeader, (LPWSTR)L"Signature", NTSIG);
	this->MakeTreeItem (leftWnd, NT.childHeader, (LPWSTR)L"File Header", FILEHDR);
	this->MakeTreeItem (leftWnd, NT.childHeader, (LPWSTR)L"Optional Header", OPTHDR);

	TreeView_Expand (leftWnd, hFileRoot, TVE_EXPAND);
	return;
}

HTREEITEM
PE::MakeTreeRoot (HWND leftWnd, LPWSTR basename) {

	TVITEMW tvi{};
	TVINSERTSTRUCTW tvins{};
	HTREEITEM hPrev = (HTREEITEM)TVI_SORT;

	tvi.mask = TVIF_TEXT | TVIF_PARAM | TVIF_STATE;
	tvi.stateMask = TVIS_BOLD;
	tvi.lParam = (BASENAME | ((uint64_t)index << 32));
	tvi.state = TVIS_BOLD;
	tvi.pszText = basename;
	tvi.cchTextMax = lstrlenW (tvi.pszText);
	tvins.item = tvi;
	tvins.hInsertAfter = hPrev;
	tvins.hParent = NULL;
	hPrev = (HTREEITEM)SendMessageW (leftWnd, TVM_INSERTITEM, 0, (LPARAM)&tvins);

	if (hPrev == NULL) {
		LogMeA (FAIL, "Couldn't create root node in tree.");
		return NULL;
	}

	return hPrev;
}

HTREEITEM
PE::MakeTreeItem (HWND leftWnd, HTREEITEM hParent, LPWSTR name, uint32_t id) {

	TVITEMW tvi{};
	TVINSERTSTRUCTW tvins{};
	HTREEITEM hPrev = (HTREEITEM)TVI_LAST;
	
	tvi.mask = TVIF_TEXT | TVIF_PARAM;
	tvi.lParam = (id | ((uint64_t)index << 32));
	tvi.pszText = name;
	tvi.cchTextMax = lstrlenW (tvi.pszText);
	tvins.item = tvi;
	tvins.hInsertAfter = hPrev;

	tvins.hParent = hParent;
	hPrev = (HTREEITEM)SendMessageW (leftWnd, TVM_INSERTITEM, 0, (LPARAM)&tvins);

	if (hPrev == NULL) {
		LogMeA (FAIL, "Couldn't create child item.");
		return NULL;
	}

	return hPrev;
}

VOID
PE::PopulateList (HWND subWnd, LPARAM selectedHdr) {

	LVITEMW	lvi{};
	std::vector<HEADER_STRINGS> currentHeader;

	// Copy information for the current selection
	switch (selectedHdr) {

	case BASENAME: 
		currentHeader = this->summaryStr;
		break;

	case DOSHDR:
		currentHeader = this->dosStr;
		break;

	case FILEHDR:
		currentHeader = this->fileStr;
		break;

	case OPTHDR:
		currentHeader = this->optStr;
		break;

	case SECHDR:
		currentHeader = this->secStr;
	}

	// Instert items to list view for the current selection
	for (uint32_t i = 0; i < currentHeader.size (); i++) {

		lvi.mask = LVIF_TEXT | LVCF_SUBITEM;
		lvi.iItem = i;
		lvi.iSubItem = NAME;
		lvi.pszText = currentHeader[i].name;

		ListView_InsertItem (subWnd, &lvi);

		lvi.iSubItem = MEMBER;
		lvi.pszText = currentHeader[i].member;

		ListView_SetItem (subWnd, &lvi);

		lvi.iSubItem = VALUE;
		lvi.pszText = currentHeader[i].value;
		ListView_SetItem (subWnd, &lvi);

		lvi.iSubItem = DESCRIPTION;
		lvi.pszText = currentHeader[i].description;

		ListView_SetItem (subWnd, &lvi);
	}

	return;
}

VOID
PE::m_MakeDosStrings (VOID) {

	// DOS Header

	_itow_s (dosHdr->e_magic,		m_magic,	32, 16);
	_itow_s (dosHdr->e_cblp,		m_cblp,		32, 16);
	_itow_s (dosHdr->e_cp,			m_cp,		32, 16);
	_itow_s (dosHdr->e_crlc,		m_crlc,		32, 16);
	_itow_s (dosHdr->e_cparhdr,		m_cparhdr,	32, 16);
	_itow_s (dosHdr->e_minalloc,	m_minalloc, 32, 16);
	_itow_s (dosHdr->e_maxalloc,	m_maxalloc, 32, 16);
	_itow_s (dosHdr->e_ss,			m_ss,		32, 16);
	_itow_s (dosHdr->e_sp,			m_sp,		32, 16);
	_itow_s (dosHdr->e_csum,		m_csum,		32, 16);
	_itow_s (dosHdr->e_ip,			m_ip,		32, 16);
	_itow_s (dosHdr->e_cs,			m_cs,		32, 16);
	_itow_s (dosHdr->e_lfarlc,		m_lfarlc,	32, 16);
	_itow_s (dosHdr->e_ovno,		m_ovno,		32, 16);
	_itow_s (dosHdr->e_lfanew,		m_lfanew,	32, 16);
	_itow_s (dosHdr->e_oemid,		m_oemid,	32, 16);
	_itow_s (dosHdr->e_oeminfo,		m_oeminfo,	32, 16);

	swprintf_s (m_res, L"%x, %X, %X, %X",
				dosHdr->e_res[0], dosHdr->e_res[1],
				dosHdr->e_res[2], dosHdr->e_res[3]);
	
	swprintf_s (m_res2, L"%X, %X, %X, %X, %X, %X, %X, %X, %X, %X",
				dosHdr->e_res2[0], dosHdr->e_res2[1], dosHdr->e_res2[2],
				dosHdr->e_res2[3], dosHdr->e_res2[4], dosHdr->e_res2[5],
				dosHdr->e_res2[6], dosHdr->e_res2[7], dosHdr->e_res2[8],
				dosHdr->e_res2[9]);

	_wcsupr_s (m_magic,		32);
	_wcsupr_s (m_cblp,		32);
	_wcsupr_s (m_cp,		32);
	_wcsupr_s (m_crlc,		32);
	_wcsupr_s (m_cparhdr,	32);
	_wcsupr_s (m_minalloc,	32);
	_wcsupr_s (m_maxalloc,	32);
	_wcsupr_s (m_ss,		32);
	_wcsupr_s (m_sp,		32);
	_wcsupr_s (m_csum,		32);
	_wcsupr_s (m_ip,		32);
	_wcsupr_s (m_cs,		32);
	_wcsupr_s (m_lfarlc,	32);
	_wcsupr_s (m_ovno,		32);
	_wcsupr_s (m_oemid,		32);
	_wcsupr_s (m_oeminfo,	32);
	_wcsupr_s (m_lfanew,	32);

	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Magic number",						(LPWSTR)L"e_magic",		m_magic,	(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Bytes on last page of file",			(LPWSTR)L"e_cblp",		m_cblp,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Pages in file",						(LPWSTR)L"e_cp",		m_cp,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Relocations",						(LPWSTR)L"e_crlc",		m_crlc,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size of header in paragraphs",		(LPWSTR)L"e_cparhdr",	m_cparhdr,	(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minimum extra paragraphs needed",	(LPWSTR)L"e_minalloc",	m_minalloc,	(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Maximum extra paragraphs needed",	(LPWSTR)L"e_maxalloc",	m_maxalloc,	(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Initial (relative) SS value",		(LPWSTR)L"e_ss",		m_ss,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Initial SP value",					(LPWSTR)L"e_sp",		m_sp,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Checksum",							(LPWSTR)L"e_csum",		m_csum,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Initial IP value",					(LPWSTR)L"e_ip",		m_ip,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Initial (relative) CS value",		(LPWSTR)L"e_cs",		m_cs,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"File address of relocation table",	(LPWSTR)L"e_lfarlc",	m_lfarlc,	(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Overlay number",						(LPWSTR)L"e_ovno",		m_ovno,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Reserved words",						(LPWSTR)L"e_res[4]",	m_res,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"OEM identifier (for e_oeminfo)",		(LPWSTR)L"e_oemid",		m_oemid,	(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"OEM information",					(LPWSTR)L"e_oeminfo",	m_oeminfo,	(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Reserved words",						(LPWSTR)L"e_res[10]",	m_res2,		(LPWSTR)L"TODO" });
	dosStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Offset of PE Header Signature",		(LPWSTR)L"e_lfanew",	m_lfanew,	(LPWSTR)L"TODO" });

	return;
}

VOID
PE::m_MakeFileStrings (VOID) {

	// File Header

	_itow_s		(fileHdr->NumberOfSections,		m_NumberOfSections,		32, 16);
	_i64tow_s	(fileHdr->PointerToSymbolTable, m_PointerToSymbolTable, 32, 16);
	_i64tow_s	(fileHdr->NumberOfSymbols,		m_NumberOfSymbols,		32, 16);
	_itow_s		(fileHdr->SizeOfOptionalHeader, m_SizeOfOptionalHeader, 32, 16);
	_itow_s		(fileHdr->Characteristics,		m_Characteristics,		32, 16);

	_wcsupr_s (m_NumberOfSections,		32);
	_wcsupr_s (m_PointerToSymbolTable,	32);
	_wcsupr_s (m_NumberOfSymbols,		32);
	_wcsupr_s (m_SizeOfOptionalHeader,	32);
	_wcsupr_s (m_Characteristics,		32);

	switch (fileHdr->Machine) {

	case IMAGE_FILE_MACHINE_UNKNOWN:
		swprintf_s (m_Machine, L"UKNOWN (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_TARGET_HOST:
		swprintf_s (m_Machine, L"Assume Native (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_I386:
		swprintf_s (m_Machine, L"Intel 386 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_R3000:
		swprintf_s (m_Machine, L"MIPS 'R3000' LE32 (%X)", fileHdr->Machine);
		break;
	case 0x160:
		swprintf_s (m_Machine, L"MIPS 'R3000' BE32 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_R4000:
		swprintf_s (m_Machine, L"MIPS 'R4000' LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_R10000:
		swprintf_s (m_Machine, L"MIPS 'R10000' LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		swprintf_s (m_Machine, L"MIPS LE 'WCE v2' (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_ALPHA:
		swprintf_s (m_Machine, L"ALPHA AXP (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_SH3:
		swprintf_s (m_Machine, L"SH3 LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_SH3DSP:
		swprintf_s (m_Machine, L"SH3DSP (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_SH3E:
		swprintf_s (m_Machine, L"SH3E LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_SH4:
		swprintf_s (m_Machine, L"SH4 LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_SH5:
		swprintf_s (m_Machine, L"SH5 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_ARM:
		swprintf_s (m_Machine, L"ARM LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_THUMB:
		swprintf_s (m_Machine, L"ARM Thumb/Thumb-2 LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_ARMNT:
		swprintf_s (m_Machine, L"ARM Thumb-2 LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_AM33:
		swprintf_s (m_Machine, L"AM33 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		swprintf_s (m_Machine, L"IBM PowerPC LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_POWERPCFP:
		swprintf_s (m_Machine, L"PowerPC FP (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_IA64:
		swprintf_s (m_Machine, L"Intel Itanium (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_MIPS16:
		swprintf_s (m_Machine, L"MIPS 16 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_ALPHA64:
		swprintf_s (m_Machine, L"ALPHA64 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		swprintf_s (m_Machine, L"MIPS FPU(%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU16:
		swprintf_s (m_Machine, L"MIPS FPU16 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_TRICORE:
		swprintf_s (m_Machine, L"Infineon (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_CEF:
		swprintf_s (m_Machine, L"CEF (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_EBC:
		swprintf_s (m_Machine, L"EFI Byte Code (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		swprintf_s (m_Machine, L"AMD64 (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_M32R:
		swprintf_s (m_Machine, L"M32R LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		swprintf_s (m_Machine, L"ARM64 LE (%X)", fileHdr->Machine);
		break;
	case IMAGE_FILE_MACHINE_CEE:
		swprintf_s (m_Machine, L"CEE (%X)", fileHdr->Machine);
		break;
	default:
		swprintf_s (m_Machine, L"John Titor's Binary (%X)", fileHdr->Machine);
	}

	m_timestamp = fileHdr->TimeDateStamp;

	if (m_timestamp != 0) {
		localtime_s (&m_timeinfo, &m_timestamp);
		wcsftime (m_TimeDateStamp, 64, L"%c", &m_timeinfo);
	}
	else {
		swprintf_s (m_TimeDateStamp, L"Invalid timestamp (%X)", fileHdr->TimeDateStamp);
	}

	fileStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Machine architecture",		(LPWSTR)L"Machine",					m_Machine,				(LPWSTR)L"TODO" });
	fileStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Number of sections",		(LPWSTR)L"NumberOfSections",		m_NumberOfSections,		(LPWSTR)L"TODO" });
	fileStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Compilation date",			(LPWSTR)L"TimeDateStamp",			m_TimeDateStamp,		(LPWSTR)L"TODO" });
	fileStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Location of symbol table",	(LPWSTR)L"PointerToSymbolTable",	m_PointerToSymbolTable,	(LPWSTR)L"TODO" });
	fileStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Number of functions",		(LPWSTR)L"NumberOfSymbols",			m_NumberOfSymbols,		(LPWSTR)L"TODO" });
	fileStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size of Optional Header",	(LPWSTR)L"SizeOfOptionalHeader",	m_SizeOfOptionalHeader,	(LPWSTR)L"TODO" });
	fileStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Characteristics",			(LPWSTR)L"Characteristics",			m_Characteristics,		(LPWSTR)L"TODO" });

	m_mask = fileHdr->Characteristics;

	if (m_mask & IMAGE_FILE_BYTES_REVERSED_HI) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_BYTES_REVERSED_HI", NULL });
		m_mask ^= IMAGE_FILE_BYTES_REVERSED_HI;
	}
	if (m_mask & IMAGE_FILE_UP_SYSTEM_ONLY) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_UP_SYSTEM_ONLY", NULL });
		m_mask ^= IMAGE_FILE_UP_SYSTEM_ONLY;
	}
	if (m_mask & IMAGE_FILE_DLL) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_DLL", NULL });
		m_mask ^= IMAGE_FILE_DLL;
	}
	if (m_mask & IMAGE_FILE_SYSTEM) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_SYSTEM", NULL });
		m_mask ^= IMAGE_FILE_SYSTEM;
	}
	if (m_mask & IMAGE_FILE_NET_RUN_FROM_SWAP) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_NET_RUN_FROM_SWAP", NULL });
		m_mask ^= IMAGE_FILE_NET_RUN_FROM_SWAP;
	}
	if (m_mask & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", NULL });
		m_mask ^= IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP;
	}
	if (m_mask & IMAGE_FILE_DEBUG_STRIPPED) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_DEBUG_STRIPPED", NULL });
		m_mask ^= IMAGE_FILE_DEBUG_STRIPPED;
	}
	if (m_mask & IMAGE_FILE_32BIT_MACHINE) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_32BIT_MACHINE", NULL });
		m_mask ^= IMAGE_FILE_32BIT_MACHINE;
	}
	if (m_mask & IMAGE_FILE_BYTES_REVERSED_LO) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_BYTES_REVERSED_LO", NULL });
		m_mask ^= IMAGE_FILE_BYTES_REVERSED_LO;
	}
	if (m_mask & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_LARGE_ADDRESS_AWARE", NULL });
		m_mask ^= IMAGE_FILE_LARGE_ADDRESS_AWARE;
	}
	if (m_mask & IMAGE_FILE_AGGRESIVE_WS_TRIM) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_AGGRESIVE_WS_TRIM", NULL });
		m_mask ^= IMAGE_FILE_AGGRESIVE_WS_TRIM;
	}
	if (m_mask & IMAGE_FILE_LOCAL_SYMS_STRIPPED) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_LOCAL_SYMS_STRIPPED", NULL });
		m_mask ^= IMAGE_FILE_LOCAL_SYMS_STRIPPED;
	}
	if (m_mask & IMAGE_FILE_LINE_NUMS_STRIPPED) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_LINE_NUMS_STRIPPED", NULL });
		m_mask ^= IMAGE_FILE_LINE_NUMS_STRIPPED;
	}
	if (m_mask & IMAGE_FILE_EXECUTABLE_IMAGE) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_EXECUTABLE_IMAGE", NULL });
		m_mask ^= IMAGE_FILE_EXECUTABLE_IMAGE;
	}
	if (m_mask & IMAGE_FILE_RELOCS_STRIPPED) {
		fileStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_FILE_RELOCS_STRIPPED", NULL });
		m_mask ^= IMAGE_FILE_RELOCS_STRIPPED;
	}

	if (m_mask != 0) {
		MessageBoxW (NULL, L"Missing definition of PIMAGE_FILE_HEADER->Characteristics.\r\n\
Please notify the developer by opening an issue on the project's GitHub.",
savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
	}

	return;
}

VOID
PE::m_MakeOptionalStrings32 (VOID) {

	// Optional Header 32 

	swprintf_s (m_Magic, L"PE32 (%X)", optHdr32->Magic);

	_itow_s (optHdr32->MajorLinkerVersion, 			m_MajorLinkerVersion, 			32, 16);
	_itow_s (optHdr32->MinorLinkerVersion, 			m_MinorLinkerVersion, 			32, 16);
	_itow_s (optHdr32->SizeOfCode, 					m_SizeOfCode, 					32, 16);
	_itow_s (optHdr32->SizeOfInitializedData, 		m_SizeOfInitializedData, 		32, 16);
	_itow_s (optHdr32->SizeOfUninitializedData, 	m_SizeOfUninitializedData, 		32, 16);
	_itow_s (optHdr32->AddressOfEntryPoint, 		m_AddressOfEntryPoint, 			32, 16);
	_itow_s (optHdr32->BaseOfCode, 					m_BaseOfCode, 					32, 16);
	_itow_s (optHdr32->BaseOfData,					m_BaseOfData,					32, 16);
	_itow_s (optHdr32->ImageBase, 					m_ImageBase, 					32, 16);
	_itow_s (optHdr32->SectionAlignment, 			m_SectionAlignment, 			32, 16);
	_itow_s (optHdr32->FileAlignment, 				m_FileAlignment, 				32, 16);
	_itow_s (optHdr32->MajorOperatingSystemVersion,	m_MajorOperatingSystemVersion, 	32, 16);
	_itow_s (optHdr32->MinorOperatingSystemVersion,	m_MinorOperatingSystemVersion, 	32, 16);
	_itow_s (optHdr32->MajorImageVersion, 			m_MajorImageVersion, 			32, 16);
	_itow_s (optHdr32->MinorImageVersion, 			m_MinorImageVersion, 			32, 16);
	_itow_s (optHdr32->MajorSubsystemVersion, 		m_MajorSubsystemVersion, 		32, 16);
	_itow_s (optHdr32->MinorSubsystemVersion, 		m_MinorSubsystemVersion, 		32, 16);
	_itow_s (optHdr32->Win32VersionValue, 			m_Win32VersionValue, 			32, 16);
	_itow_s (optHdr32->SizeOfImage, 				m_SizeOfImage, 					32, 16);
	_itow_s (optHdr32->SizeOfHeaders, 				m_SizeOfHeaders, 				32, 16);
	_itow_s (optHdr32->CheckSum, 					m_CheckSum, 					32, 16);
	_itow_s (optHdr32->DllCharacteristics, 			m_DllCharacteristics, 			32, 16);
	_itow_s (optHdr32->SizeOfStackReserve, 			m_SizeOfStackReserve, 			32, 16);
	_itow_s (optHdr32->SizeOfStackCommit, 			m_SizeOfStackCommit, 			32, 16);
	_itow_s (optHdr32->SizeOfHeapReserve, 			m_SizeOfHeapReserve, 			32, 16);
	_itow_s (optHdr32->SizeOfHeapCommit, 			m_SizeOfHeapCommit,				32, 16);
	_itow_s (optHdr32->LoaderFlags, 				m_LoaderFlags, 					32, 16);
	_itow_s (optHdr32->NumberOfRvaAndSizes, 		m_NumberOfRvaAndSizes, 			32, 16);
	
	switch (optHdr32->Subsystem) {

	case IMAGE_SUBSYSTEM_UNKNOWN:
		swprintf_s (m_Subsystem, L"UNKNOWN (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		swprintf_s (m_Subsystem, L"Subsystem Not Required (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		swprintf_s (m_Subsystem, L"GUI Application (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		swprintf_s (m_Subsystem, L"Windows Character Subsystem (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		swprintf_s (m_Subsystem, L"OS/2 Character Subsystem (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		swprintf_s (m_Subsystem, L"Posix Character Subsystem (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		swprintf_s (m_Subsystem, L"Windows 9X Driver (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		swprintf_s (m_Subsystem, L"Windows CE GUI (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		swprintf_s (m_Subsystem, L"EFI Application (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		swprintf_s (m_Subsystem, L"EFI Boot Service Driver (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		swprintf_s (m_Subsystem, L"EFI Runtime Driver (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		swprintf_s (m_Subsystem, L"EFI ROM (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		swprintf_s (m_Subsystem, L"XBOX (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		swprintf_s (m_Subsystem, L"Windows Boot Application (%X)", optHdr32->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
		swprintf_s (m_Subsystem, L"XBOX code catalog (%X)", optHdr32->Subsystem);
		break;
	default:
		swprintf_s (m_Subsystem, L"NOT IMPLEMENTED (value: %X)", optHdr32->Subsystem);
	}

	_wcsupr_s (m_MajorLinkerVersion,			32);
	_wcsupr_s (m_MinorLinkerVersion,			32);
	_wcsupr_s (m_SizeOfCode,					32);
	_wcsupr_s (m_SizeOfInitializedData,			32);
	_wcsupr_s (m_SizeOfUninitializedData,		32);
	_wcsupr_s (m_AddressOfEntryPoint,			32);
	_wcsupr_s (m_BaseOfCode,					32);
	_wcsupr_s (m_ImageBase,						32);
	_wcsupr_s (m_BaseOfData,					32);
	_wcsupr_s (m_SectionAlignment,				32);
	_wcsupr_s (m_FileAlignment,					32);
	_wcsupr_s (m_MajorOperatingSystemVersion,	32);
	_wcsupr_s (m_MinorOperatingSystemVersion,	32);
	_wcsupr_s (m_MajorImageVersion,				32);
	_wcsupr_s (m_MinorImageVersion,				32);
	_wcsupr_s (m_MajorSubsystemVersion,			32);
	_wcsupr_s (m_MinorSubsystemVersion,			32);
	_wcsupr_s (m_Win32VersionValue,				32);
	_wcsupr_s (m_SizeOfImage,					32);
	_wcsupr_s (m_SizeOfHeaders,					32);
	_wcsupr_s (m_CheckSum,						32);
	_wcsupr_s (m_DllCharacteristics,			32);
	_wcsupr_s (m_SizeOfStackReserve,			32);
	_wcsupr_s (m_SizeOfStackCommit,				32);
	_wcsupr_s (m_SizeOfHeapReserve,				32);
	_wcsupr_s (m_SizeOfHeapCommit,				32);
	_wcsupr_s (m_LoaderFlags,					32);
	_wcsupr_s (m_NumberOfRvaAndSizes,			32);

	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Magic",								(LPWSTR)L"Magic",						m_Magic,						(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Linker Version",				(LPWSTR)L"MajorLinkerVersion",			m_MajorLinkerVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Linker Version",				(LPWSTR)L"MinorLinkerVersion",			m_MinorLinkerVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Code",						(LPWSTR)L"SizeOfCode",					m_SizeOfCode,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Initialized Data",			(LPWSTR)L"SizeOfInitializedData",		m_SizeOfInitializedData,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Uninitialized Data",			(LPWSTR)L"SizeOfUninitializedData",		m_SizeOfUninitializedData,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Address Of EntryPoint",				(LPWSTR)L"AddressOfEntryPoint",			m_AddressOfEntryPoint,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Base Of Code",						(LPWSTR)L"BaseOfCode",					m_BaseOfCode,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"BaseOfData",							(LPWSTR)L"BaseOfData",					m_BaseOfData,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Image Base",							(LPWSTR)L"ImageBase",					m_ImageBase,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Section Alignment",					(LPWSTR)L"SectionAlignment",			m_SectionAlignment,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"File Alignment",						(LPWSTR)L"FileAlignment",				m_FileAlignment,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Operating System Version",		(LPWSTR)L"MajorOperatingSystemVersion",	m_MajorOperatingSystemVersion,	(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Operating System Version",		(LPWSTR)L"MinorOperatingSystemVersion",	m_MinorOperatingSystemVersion,	(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Image Version",				(LPWSTR)L"MajorImageVersion",			m_MajorImageVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Image Version",				(LPWSTR)L"MinorImageVersion",			m_MinorImageVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Subsystem Version",			(LPWSTR)L"MajorSubsystemVersion",		m_MajorSubsystemVersion,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Subsystem Version",			(LPWSTR)L"MinorSubsystemVersion",		m_MinorSubsystemVersion,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Win32 Version Value",				(LPWSTR)L"Win32VersionValue",			m_Win32VersionValue,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Image",						(LPWSTR)L"SizeOfImage",					m_SizeOfImage,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Headers",					(LPWSTR)L"SizeOfHeaders",				m_SizeOfHeaders,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"CheckSum",							(LPWSTR)L"CheckSum",					m_CheckSum,						(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Subsystem",							(LPWSTR)L"Subsystem",					m_Subsystem,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Dll Characteristics",				(LPWSTR)L"DllCharacteristics",			m_DllCharacteristics,			(LPWSTR)L"TODO" });
	
	m_mask = optHdr32->DllCharacteristics;

	if (m_mask & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_GUARD_CF", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_GUARD_CF;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_WDM_DRIVER;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_APPCONTAINER", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_APPCONTAINER;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NO_BIND) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NO_BIND", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NO_BIND;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NO_SEH", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NO_SEH;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NO_ISOLATION;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NX_COMPAT", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
	}
	if (m_mask & 0x0008) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0008)", NULL });
		m_mask ^= 0x0008;
	}
	if (m_mask & 0x0004) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0004)", NULL });
		m_mask ^= 0x0004;
	}
	if (m_mask & 0x0002) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0002)", NULL });
		m_mask ^= 0x0002;
	}
	if (m_mask & 0x0001) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0001)", NULL });
		m_mask ^= 0x0001;
	}

	if (m_mask != 0) {
		MessageBoxW (NULL, L"Missing definition of PIMAGE_OPTIONAL_HEADER->DllCharacteristics.\r\n\
Please notify the developer by opening an issue on the project's GitHub.",
savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
	}

	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Stack Reserve",				(LPWSTR)L"SizeOfStackReserve",			m_SizeOfStackReserve,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Stack Commit",				(LPWSTR)L"SizeOfStackCommit",			m_SizeOfStackCommit,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Heap Reserve",				(LPWSTR)L"SizeOfHeapReserve",			m_SizeOfHeapReserve,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Heap Commit",				(LPWSTR)L"SizeOfHeapCommit",			m_SizeOfHeapCommit,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Loader Flags",						(LPWSTR)L"LoaderFlags",					m_LoaderFlags,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Number Of RVA And Sizes",			(LPWSTR)L"NumberOfRvaAndSizes",			m_NumberOfRvaAndSizes,			(LPWSTR)L"TODO" });

	m_isX64 = false;
	return;
}

VOID
PE::m_MakeOptionalStrings64 (VOID) {

	// Optional Header 64 

	swprintf_s (m_Magic, L"PE32+ (%x)", optHdr64->Magic);

	_i64tow_s (optHdr64->MajorLinkerVersion, 			m_MajorLinkerVersion, 			32, 16);
	_i64tow_s (optHdr64->MinorLinkerVersion, 			m_MinorLinkerVersion, 			32, 16);
	_i64tow_s (optHdr64->SizeOfCode, 					m_SizeOfCode, 					32, 16);
	_i64tow_s (optHdr64->SizeOfInitializedData, 		m_SizeOfInitializedData, 		32, 16);
	_i64tow_s (optHdr64->SizeOfUninitializedData, 		m_SizeOfUninitializedData, 		32, 16);
	_i64tow_s (optHdr64->AddressOfEntryPoint, 			m_AddressOfEntryPoint, 			32, 16);
	_i64tow_s (optHdr64->BaseOfCode, 					m_BaseOfCode, 					32, 16);
	_i64tow_s (optHdr64->ImageBase, 					m_ImageBase, 					32, 16);
	_i64tow_s (optHdr64->SectionAlignment, 				m_SectionAlignment, 			32, 16);
	_i64tow_s (optHdr64->FileAlignment, 				m_FileAlignment, 				32, 16);
	_i64tow_s (optHdr64->MajorOperatingSystemVersion,	m_MajorOperatingSystemVersion, 	32, 16);
	_i64tow_s (optHdr64->MinorOperatingSystemVersion,	m_MinorOperatingSystemVersion, 	32, 16);
	_i64tow_s (optHdr64->MajorImageVersion, 			m_MajorImageVersion, 			32, 16);
	_i64tow_s (optHdr64->MinorImageVersion, 			m_MinorImageVersion, 			32, 16);
	_i64tow_s (optHdr64->MajorSubsystemVersion, 		m_MajorSubsystemVersion, 		32, 16);
	_i64tow_s (optHdr64->MinorSubsystemVersion, 		m_MinorSubsystemVersion, 		32, 16);
	_i64tow_s (optHdr64->Win32VersionValue, 			m_Win32VersionValue, 			32, 16);
	_i64tow_s (optHdr64->SizeOfImage, 					m_SizeOfImage, 					32, 16);
	_i64tow_s (optHdr64->SizeOfHeaders, 				m_SizeOfHeaders, 				32, 16);
	_i64tow_s (optHdr64->CheckSum, 						m_CheckSum, 					32, 16);
	_i64tow_s (optHdr64->DllCharacteristics, 			m_DllCharacteristics, 			32, 16);
	_i64tow_s (optHdr64->SizeOfStackReserve, 			m_SizeOfStackReserve, 			32, 16);
	_i64tow_s (optHdr64->SizeOfStackCommit, 			m_SizeOfStackCommit, 			32, 16);
	_i64tow_s (optHdr64->SizeOfHeapReserve, 			m_SizeOfHeapReserve, 			32, 16);
	_i64tow_s (optHdr64->SizeOfHeapCommit, 				m_SizeOfHeapCommit,				32, 16);
	_i64tow_s (optHdr64->LoaderFlags, 					m_LoaderFlags, 					32, 16);
	_i64tow_s (optHdr64->NumberOfRvaAndSizes, 			m_NumberOfRvaAndSizes, 			32, 16);
	
	switch (optHdr64->Subsystem) {

	case IMAGE_SUBSYSTEM_UNKNOWN:
		swprintf_s (m_Subsystem, L"UNKNOWN (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		swprintf_s (m_Subsystem, L"Subsystem Not Required (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		swprintf_s (m_Subsystem, L"GUI Application (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		swprintf_s (m_Subsystem, L"Windows Character Subsystem (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		swprintf_s (m_Subsystem, L"OS/2 Character Subsystem (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		swprintf_s (m_Subsystem, L"Posix Character Subsystem (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		swprintf_s (m_Subsystem, L"Windows 9X Driver (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		swprintf_s (m_Subsystem, L"Windows CE GUI (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		swprintf_s (m_Subsystem, L"EFI Application (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		swprintf_s (m_Subsystem, L"EFI Boot Service Driver (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		swprintf_s (m_Subsystem, L"EFI Runtime Driver (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		swprintf_s (m_Subsystem, L"EFI ROM (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		swprintf_s (m_Subsystem, L"XBOX (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		swprintf_s (m_Subsystem, L"Windows Boot Application (%X)", optHdr64->Subsystem);
		break;
	case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
		swprintf_s (m_Subsystem, L"XBOX code catalog (%X)", optHdr64->Subsystem);
		break;
	default:
		swprintf_s (m_Subsystem, L"NOT IMPLEMENTED (value: %X)", optHdr64->Subsystem);
	}

	_wcsupr_s (m_MajorLinkerVersion,			32);
	_wcsupr_s (m_MinorLinkerVersion,			32);
	_wcsupr_s (m_SizeOfCode,					32);
	_wcsupr_s (m_SizeOfInitializedData,			32);
	_wcsupr_s (m_SizeOfUninitializedData,		32);
	_wcsupr_s (m_AddressOfEntryPoint,			32);
	_wcsupr_s (m_BaseOfCode,					32);
	_wcsupr_s (m_BaseOfData,					32);
	_wcsupr_s (m_SectionAlignment,				32);
	_wcsupr_s (m_FileAlignment,					32);
	_wcsupr_s (m_MajorOperatingSystemVersion,	32);
	_wcsupr_s (m_MinorOperatingSystemVersion,	32);
	_wcsupr_s (m_MajorImageVersion,				32);
	_wcsupr_s (m_MinorImageVersion,				32);
	_wcsupr_s (m_MajorSubsystemVersion,			32);
	_wcsupr_s (m_MinorSubsystemVersion,			32);
	_wcsupr_s (m_Win32VersionValue,				32);
	_wcsupr_s (m_SizeOfImage,					32);
	_wcsupr_s (m_SizeOfHeaders,					32);
	_wcsupr_s (m_CheckSum,						32);
	_wcsupr_s (m_DllCharacteristics,			32);
	_wcsupr_s (m_SizeOfStackReserve,			32);
	_wcsupr_s (m_SizeOfStackCommit,				32);
	_wcsupr_s (m_SizeOfHeapReserve,				32);
	_wcsupr_s (m_SizeOfHeapCommit,				32);
	_wcsupr_s (m_LoaderFlags,					32);
	_wcsupr_s (m_NumberOfRvaAndSizes,			32);

	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Magic",								(LPWSTR)L"Magic",						m_Magic,						(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Linker Version",				(LPWSTR)L"MajorLinkerVersion",			m_MajorLinkerVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Linker Version",				(LPWSTR)L"MinorLinkerVersion",			m_MinorLinkerVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Code",						(LPWSTR)L"SizeOfCode",					m_SizeOfCode,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Initialized Data",			(LPWSTR)L"SizeOfInitializedData",		m_SizeOfInitializedData,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Uninitialized Data",			(LPWSTR)L"SizeOfUninitializedData",		m_SizeOfUninitializedData,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Address Of EntryPoint",				(LPWSTR)L"AddressOfEntryPoint",			m_AddressOfEntryPoint,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Base Of Code",						(LPWSTR)L"BaseOfCode",					m_BaseOfCode,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Image Base",							(LPWSTR)L"ImageBase",					m_ImageBase,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Section Alignment",					(LPWSTR)L"SectionAlignment",			m_SectionAlignment,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"File Alignment",						(LPWSTR)L"FileAlignment",				m_FileAlignment,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Operating System Version",		(LPWSTR)L"MajorOperatingSystemVersion",	m_MajorOperatingSystemVersion,	(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Operating System Version",		(LPWSTR)L"MinorOperatingSystemVersion",	m_MinorOperatingSystemVersion,	(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Image Version",				(LPWSTR)L"MajorImageVersion",			m_MajorImageVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Image Version",				(LPWSTR)L"MinorImageVersion",			m_MinorImageVersion,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Major Subsystem Version",			(LPWSTR)L"MajorSubsystemVersion",		m_MajorSubsystemVersion,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Minor Subsystem Version",			(LPWSTR)L"MinorSubsystemVersion",		m_MinorSubsystemVersion,		(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Win32 Version Value",				(LPWSTR)L"Win32VersionValue",			m_Win32VersionValue,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Image",						(LPWSTR)L"SizeOfImage",					m_SizeOfImage,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Headers",					(LPWSTR)L"SizeOfHeaders",				m_SizeOfHeaders,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"CheckSum",							(LPWSTR)L"CheckSum",					m_CheckSum,						(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Subsystem",							(LPWSTR)L"Subsystem",					m_Subsystem,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Dll Characteristics",				(LPWSTR)L"DllCharacteristics",			m_DllCharacteristics,			(LPWSTR)L"TODO" });

	m_mask = optHdr64->DllCharacteristics;

	if (m_mask & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_GUARD_CF", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_GUARD_CF;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_WDM_DRIVER;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_APPCONTAINER", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_APPCONTAINER;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NO_BIND) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NO_BIND", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NO_BIND;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NO_SEH", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NO_SEH;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NO_ISOLATION;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_NX_COMPAT", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	}
	if (m_mask & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", NULL });
		m_mask ^= IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
	}
	if (m_mask & 0x0008) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0008)", NULL });
		m_mask ^= 0x0008;
	}
	if (m_mask & 0x0004) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0004)", NULL });
		m_mask ^= 0x0004;
	}
	if (m_mask & 0x0002) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0002)", NULL });
		m_mask ^= 0x0002;
	}
	if (m_mask & 0x0001) {
		optStr.emplace_back (HEADER_STRINGS{ NULL, NULL, (LPWSTR)L"RESERVED (0x0001)", NULL });
		m_mask ^= 0x0001;
	}

	if (m_mask != 0) {
		MessageBoxW (NULL, L"Missing definition of PIMAGE_OPTIONAL_HEADER->DllCharacteristics.\r\n\
Please notify the developer by opening an issue on the project's GitHub.",
savedBasename, MB_ICONEXCLAMATION | MB_OK | MB_TASKMODAL);
	}

	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Stack Reserve",				(LPWSTR)L"SizeOfStackReserve",			m_SizeOfStackReserve,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Stack Commit",				(LPWSTR)L"SizeOfStackCommit",			m_SizeOfStackCommit,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Heap Reserve",				(LPWSTR)L"SizeOfHeapReserve",			m_SizeOfHeapReserve,			(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size Of Heap Commit",				(LPWSTR)L"SizeOfHeapCommit",			m_SizeOfHeapCommit,				(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Loader Flags",						(LPWSTR)L"LoaderFlags",					m_LoaderFlags,					(LPWSTR)L"TODO" });
	optStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Number Of RVA And Sizes",			(LPWSTR)L"NumberOfRvaAndSizes",			m_NumberOfRvaAndSizes,			(LPWSTR)L"TODO" });

	m_isX64 = true;
	return;
}

VOID
PE::m_MakeSectionStrings (VOID) {

	size_t retval = 0;
	wchar_t tmpName[16]{};

	for (uint16_t i = 0; i < fileHdr->NumberOfSections &&
		 secHdr->PointerToRawData < m_fileSizeB; i++) {

		if (secHdr->Name[0])
			mbstowcs_s (&retval, m_Name, 16, (const char*)secHdr->Name, 8);
		else
			mbstowcs_s (&retval, tmpName, 8, "No name", 8);
	
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Name",		 			(LPWSTR)L"Name",		 			m_Name,						(LPWSTR)L"TODO"});

		_i64tow_s (secHdr->Misc.VirtualSize,		m_VirtualSize,				32, 16);
		_i64tow_s (secHdr->VirtualAddress,			m_VirtualAddress,			32, 16);
		_i64tow_s (secHdr->SizeOfRawData,			m_SizeOfRawData,			32, 16);
		_i64tow_s (secHdr->PointerToRawData,		m_PointerToRawData,			32, 16);
		_i64tow_s (secHdr->PointerToRelocations,	m_PointerToRelocations,		32, 16);
		_i64tow_s (secHdr->PointerToLinenumbers,	m_PointerToLinenumbers,		32, 16);
		_i64tow_s (secHdr->NumberOfRelocations,		m_NumberOfRelocations,		32, 16);
		_i64tow_s (secHdr->NumberOfLinenumbers,		m_NumberOfLinenumbers,		32, 16);
		_i64tow_s (secHdr->Characteristics,			m_SectionCharacteristics,	32, 16);

		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"VirtualSize", 			(LPWSTR)L"VirtualSize", 			m_VirtualSize,				(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"VirtualAddress", 		(LPWSTR)L"VirtualAddress", 			m_VirtualAddress,			(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"SizeOfRawData", 			(LPWSTR)L"SizeOfRawData", 			m_SizeOfRawData,			(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"PointerToRawData", 		(LPWSTR)L"PointerToRawData", 		m_PointerToRawData,			(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"PointerToRelocations", 	(LPWSTR)L"PointerToRelocations", 	m_PointerToRelocations,		(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"PointerToLinenumbers", 	(LPWSTR)L"PointerToLinenumbers", 	m_PointerToLinenumbers,		(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"NumberOfRelocations", 	(LPWSTR)L"NumberOfRelocations", 	m_NumberOfRelocations,		(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"NumberOfLinenumbers", 	(LPWSTR)L"NumberOfLinenumbers", 	m_NumberOfLinenumbers,		(LPWSTR)L"TODO"});
		secStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Characteristics", 		(LPWSTR)L"Characteristics", 		m_SectionCharacteristics,	(LPWSTR)L"TODO"});
		
		secStr.emplace_back (HEADER_STRINGS{ NULL, NULL, NULL, NULL });

		secHdr = (PIMAGE_SECTION_HEADER)((PBYTE)secHdr + sizeof (IMAGE_SECTION_HEADER));
	}

	return;
}

VOID 
PE::m_MakeSummary (VOID) {

	m_fileSizeKB = (float_t)m_fileSizeB / 1000;
	swprintf_s (m_fsizeW, L"%.2f KB", m_fileSizeKB);
	
	summaryStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Name",					savedBasename,			NULL, NULL });
	summaryStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Size",					m_fsizeW,				NULL, NULL });
	summaryStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Compilation Date",		m_TimeDateStamp,		NULL, NULL });
	summaryStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Address Format",			m_Magic,				NULL, NULL });
	summaryStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Target Architecture",	m_Machine,				NULL, NULL });
	summaryStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Entry Point",			m_AddressOfEntryPoint,	NULL, NULL });
	summaryStr.emplace_back (HEADER_STRINGS{ (LPWSTR)L"Application Type",		m_Subsystem,			NULL, NULL });

	return;
}

VOID
PE::CleanUp (VOID) {

	if (binary != NULL)
		CloseHandle (binary);

	if (mapped != NULL)
		CloseHandle (mapped);
	
	return;
}