#pragma once

class PE {

public:

	BOOL		LoadBinary (LPWSTR);
	VOID		MakeTreeView (HWND);
	HTREEITEM	MakeTreeRoot (HWND, LPWSTR);
	HTREEITEM	MakeTreeItem (HWND, HTREEITEM, LPWSTR, uint32_t);
	VOID		PopulateList (HWND, LPARAM);
	VOID		CleanUp (VOID);

private:

	VOID m_MakeDosStrings (VOID);
	VOID m_MakeFileStrings (VOID);
	VOID m_MakeOptionalStrings32 (VOID);
	VOID m_MakeOptionalStrings64 (VOID);
	VOID m_MakeSectionStrings (VOID);
	VOID m_MakeSummary (VOID);

public:

	wchar_t  savedPath[MAX_PATH]{};
	wchar_t  savedBasename[MAX_PATH]{};

	HANDLE	 binary =			nullptr;
	HANDLE	 mapped =			nullptr;
	HANDLE	 data =				nullptr;

	PIMAGE_DOS_HEADER			dosHdr;
	PIMAGE_NT_HEADERS32			ntHdr32;
	PIMAGE_NT_HEADERS64			ntHdr64;
	PIMAGE_FILE_HEADER			fileHdr;
	PIMAGE_OPTIONAL_HEADER32	optHdr32;
	PIMAGE_OPTIONAL_HEADER64	optHdr64;
	PIMAGE_SECTION_HEADER		secHdr;

	std::vector<HEADER_STRINGS> summaryStr;
	std::vector<HEADER_STRINGS> dosStr;
	std::vector<HEADER_STRINGS> fileStr;
	std::vector<HEADER_STRINGS> optStr;
	std::vector<HEADER_STRINGS> secStr;

private:

	uint16_t m_mask;
	BOOL	 m_isX64;
	uint64_t m_fileSizeB;
	float_t  m_fileSizeKB;
	wchar_t  m_fsizeW[32]{};
	
	// DOS Header 
	wchar_t m_magic[32]{};
	wchar_t m_cblp[32]{};
	wchar_t m_cp[32]{};
	wchar_t m_crlc[32]{};
	wchar_t m_cparhdr[32]{};
	wchar_t m_minalloc[32]{};
	wchar_t m_maxalloc[32]{};
	wchar_t m_ss[32]{};
	wchar_t m_sp[32]{};
	wchar_t m_csum[32]{};
	wchar_t m_ip[32]{};
	wchar_t m_cs[32]{};
	wchar_t m_lfarlc[32]{};
	wchar_t m_ovno[32]{};
	wchar_t m_res[32]{};
	wchar_t m_oemid[32]{};
	wchar_t m_oeminfo[32]{};
	wchar_t m_res2[64]{};
	wchar_t m_lfanew[32]{};

	// File Header
	wchar_t m_Machine[32]{};
	wchar_t m_NumberOfSections[32]{};
	wchar_t m_TimeDateStamp[64]{};
	wchar_t m_PointerToSymbolTable[32]{};
	wchar_t m_NumberOfSymbols[32]{};
	wchar_t m_SizeOfOptionalHeader[32]{};
	wchar_t m_Characteristics[32]{};
	struct tm m_timeinfo {};
	time_t m_timestamp;

	//Optional Header
	wchar_t m_Magic[32]{};
	wchar_t m_MajorLinkerVersion[32]{};
	wchar_t m_MinorLinkerVersion[32]{};
	wchar_t m_SizeOfCode[32]{};
	wchar_t m_SizeOfInitializedData[32]{};
	wchar_t m_SizeOfUninitializedData[32]{};
	wchar_t m_AddressOfEntryPoint[32]{};
	wchar_t m_BaseOfCode[32]{};
	wchar_t m_BaseOfData[32]{};
	wchar_t m_ImageBase[32]{};
	wchar_t m_SectionAlignment[32]{};
	wchar_t m_FileAlignment[32]{};
	wchar_t m_MajorOperatingSystemVersion[32]{};
	wchar_t m_MinorOperatingSystemVersion[32]{};
	wchar_t m_MajorImageVersion[32]{};
	wchar_t m_MinorImageVersion[32]{};
	wchar_t m_MajorSubsystemVersion[32]{};
	wchar_t m_MinorSubsystemVersion[32]{};
	wchar_t m_Win32VersionValue[32]{};
	wchar_t m_SizeOfImage[32]{};
	wchar_t m_SizeOfHeaders[32]{};
	wchar_t m_CheckSum[32]{};
	wchar_t m_Subsystem[32]{};
	wchar_t m_DllCharacteristics[32]{};
	wchar_t m_SizeOfStackReserve[32]{};
	wchar_t m_SizeOfStackCommit[32]{};
	wchar_t m_SizeOfHeapReserve[32]{};
	wchar_t m_SizeOfHeapCommit[32]{};
	wchar_t m_LoaderFlags[32]{};
	wchar_t m_NumberOfRvaAndSizes[32]{};

	// Sections
	
	wchar_t m_Name[8];
	wchar_t m_VirtualSize[32]{};
	wchar_t m_VirtualAddress[32]{};
	wchar_t m_SizeOfRawData[32]{};
	wchar_t m_PointerToRawData[32]{};
	wchar_t m_PointerToRelocations[32]{};
	wchar_t m_PointerToLinenumbers[32]{};
	wchar_t m_NumberOfRelocations[32]{};
	wchar_t m_NumberOfLinenumbers[32]{};
	wchar_t m_SectionCharacteristics[32]{};
};
