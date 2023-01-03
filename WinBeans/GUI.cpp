#include "stdafx.h"

#include "GUI.h"
#include <BeanLog/BeanLog.hpp>

extern std::vector<PE*> BinList;
extern std::atomic_uint32_t index;

VOID
LaunchGUI(HINSTANCE hInstance)
{
	MSG	msg;
	HACCEL accel;
	hInst = hInstance;

	InitCommonControls();

	// Setting up and creating root window
	WNDCLASSEXW wcRoot {};

	wcRoot.cbSize = sizeof(WNDCLASSEXW);
	wcRoot.lpfnWndProc = rootProc;
	wcRoot.hInstance = hInstance;
	wcRoot.lpszClassName = L"WinBeans";
	wcRoot.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_BEAN_ICO));
	wcRoot.hCursor = LoadCursorW(NULL, IDC_ARROW);
	wcRoot.lpszMenuName = MAKEINTRESOURCEW(IDR_MENU);

	if (!RegisterClassExW(&wcRoot))
	{
		bean_fail_a("{}", "Failed to register class.");
		return;
	}

	rootWnd = CreateWindowExW(WS_EX_WINDOWEDGE, wcRoot.lpszClassName, L"WinBeans", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
							  CW_USEDEFAULT, CW_USEDEFAULT, DEF_WIDTH, DEF_HEIGHT,
							  HWND_DESKTOP, NULL, hInstance, NULL);

	if (!rootWnd)
	{
		bean_fail_a("{}", "Failed to create window.");
		return;
	}

	// Enable Drag and drop, then snapshot window dimentions 
	DragAcceptFiles(rootWnd, true);
	GetClientRect(rootWnd, &rootRect);

	// Create left side subview as a tree view for navigation
	subWndLeft = CreateWindowExW(0, WC_TREEVIEW, NULL,
								 WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL | WS_CLIPCHILDREN |
								 TVS_HASBUTTONS | TVS_SHOWSELALWAYS | TVS_HASLINES | TVS_TRACKSELECT,
								 MS, MS, TW, rootRect.bottom - (MS * 2),
								 rootWnd, (HMENU) SUB_LEFT, hInstance, NULL);

	if (!subWndLeft)
	{
		bean_warn_a("{}", "Left Subview not created.");
		return;
	}

	// Get a modern look and feel
	if (SetWindowTheme(subWndLeft, L"Explorer", NULL) != S_OK)
	{
		bean_warn_a("{}", "Theme not applied to treeview.");
	}

	// Handle some custom drawing (e.g. look at LoaderProc)
	if (!SetWindowSubclass(subWndLeft, leftProc, SUB_LEFT, NULL))
	{
		bean_warn_a("{}", "Left subclass not registered");
	}

	ListView_SetExtendedListViewStyle(subWndLeft, TVS_EX_DOUBLEBUFFER | TVS_EX_FADEINOUTEXPANDOS);

	// Create right side subview as a list view for data display
	subWndRight = CreateWindowExW(0, WC_LISTVIEW, NULL,
								  WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE | WS_BORDER |
								  LVS_REPORT | LVS_SHOWSELALWAYS,
								  TW + (MS * 2), MS,
								  ((rootRect.right) - (MS * 3) - TW),
								  rootRect.bottom - (MS * 2),
								  rootWnd, (HMENU) SUB_RIGHT, hInstance, NULL);

	if (!subWndRight)
	{
		bean_warn_a("{}", "Right Subview not created.");
		return;
	}

	// Get a modern look and feel
	if (SetWindowTheme(subWndRight, L"Explorer", NULL) != S_OK)
	{
		bean_fail_a("{}", "Theme not applied to listview.");
	}

	// Handle some custom drawing (e.g. look at LoaderProc)
	if (!SetWindowSubclass(subWndRight, rightProc, SUB_RIGHT, NULL))
	{
		bean_warn_a("{}", "Right subclass not registered");
	}

	ListView_SetExtendedListViewStyle(subWndRight, LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP |
									  LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERINALLVIEWS);

	SendMessageW(subWndRight, WM_CHANGEUISTATE, MAKELONG(UIS_SET, UISF_HIDEFOCUS), 0);


	// load accelerator table for CTRL+KEY operations
	accel = LoadAcceleratorsW(hInstance, MAKEINTRESOURCEW(ID_CTRL_ACCEL));

	if (!accel)
	{
		bean_fail_a("{}", "Accelerator table not loaded.");
		return;
	}

	// Toggle visibility of all windows
	if (ShowWindow(rootWnd, true) == 0 &&
		UpdateWindow(rootWnd))
	{
		bean_info_a("{}", "Root Window is up");
	}

	if (ShowWindow(subWndLeft, SW_SHOWDEFAULT) &&
		UpdateWindow(subWndLeft))
	{
		bean_info_a("{}", "Left side subview is up.");
	}

	if (ShowWindow(subWndRight, SW_SHOWDEFAULT) &&
		UpdateWindow(subWndRight))
	{
		bean_info_a("{}", "Right side subview is up.");
	}

	// Start processing messages
	while (GetMessageW(&msg, NULL, 0, 0))
	{
		if (!TranslateAcceleratorW(rootWnd, accel, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
	}

	if (!IsAppThemed())
	{
		bean_warn_a("{}", "App not themed.");
	}

	return;
}

LPWSTR
GetBinPath(HWND oWner)
{
	OPENFILENAMEW file;
	LPWSTR path = new WCHAR[MAX_PATH] {};

	// I dare you to delete this line
	ZeroMemory(&file, sizeof(OPENFILENAMEW));

	file.lStructSize = sizeof(OPENFILENAMEW);
	file.hwndOwner = oWner;
	file.lpstrFile = path;
	file.nMaxFile = MAX_PATH;
	file.lpstrFilter = L"All Files (*.*)\0*.*\0Programs (*.exe)\0*.exe\0Libraries (*.dll)\0*.dll\0Drivers (*.sys)\0*.sys\0";
	file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	file.nFilterIndex = 1;

	// Open Dialog box in Explorer style
	if (!GetOpenFileNameW(&file))
	{
		bean_warn_a("{}", "No file path specified");
		return NULL;
	}

	return path;
}

VOID
MakeListViewCols(HWND subWnd)
{
	LVCOLUMNW	nameCol {}, membCol {}, valueCol {}, descCol {};

	ListView_DeleteAllItems(subWnd);

	nameCol.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_DEFAULTWIDTH;
	nameCol.fmt = LVCFMT_LEFT;
	nameCol.cxDefault = 250;
	nameCol.cx = nameCol.cxDefault;
	nameCol.pszText = (LPWSTR) L"Name";

	ListView_DeleteColumn(subWnd, 0);
	ListView_InsertColumn(subWnd, 0, &nameCol);

	membCol.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_DEFAULTWIDTH;
	membCol.fmt = LVCFMT_LEFT;
	membCol.cxDefault = 200;
	membCol.cx = membCol.cxDefault;
	membCol.pszText = (LPWSTR) L"Member";

	ListView_DeleteColumn(subWnd, 1);
	ListView_InsertColumn(subWnd, 1, &membCol);

	valueCol.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_DEFAULTWIDTH;
	valueCol.fmt = LVCFMT_LEFT;
	valueCol.cxDefault = 100;
	valueCol.cx = valueCol.cxDefault;
	valueCol.pszText = (LPWSTR) L"Value (hex)";

	ListView_DeleteColumn(subWnd, 2);
	ListView_InsertColumn(subWnd, 2, &valueCol);

	descCol.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_DEFAULTWIDTH;
	descCol.fmt = LVCFMT_LEFT;
	descCol.cxDefault = 200;
	descCol.cx = descCol.cxDefault;
	descCol.pszText = (LPWSTR) L"Description";

	ListView_DeleteColumn(subWnd, 3);
	ListView_InsertColumn(subWnd, 3, &descCol);

	return;
}

VOID
LoaderProc(WPARAM wParam, uint32_t nDrops)
{
	wchar_t		path[MAX_PATH] {};
	wchar_t		basename[MAX_PATH + 1] {};

	progBar = CreateWindowExW(0, PROGRESS_CLASS, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
							  rightRect.left + MS, rightRect.bottom - (15 + MS),
							  rightRect.right - (MS * 2), 15,
							  subWndRight, NULL, hInst, NULL);

	if (progBar == NULL)
	{
		bean_fail_a("{}", "ProgBar not created.");
		return;
	}

	SendMessageW(progBar, PBM_SETRANGE, NULL, MAKELPARAM(0, nDrops));
	SendMessageW(progBar, PBM_SETSTEP, 1, NULL);

	for (uint32_t i = 0; i < nDrops; i++)
	{

		DragQueryFileW((HDROP) wParam, i, path, MAX_PATH);
		BinList.emplace_back(new PE);

		// Skip invalid binaries and restore the vector to avoid empty slots
		if (!BinList[index]->LoadBinary(path))
		{

			BinList[index]->CleanUp();
			delete BinList[index];

			BinList.pop_back();
			continue;
		}

		BinList[index]->MakeTreeView(subWndLeft);

		SendMessageW(progBar, PBM_STEPIT, NULL, NULL);
		index++;
	}

	DragFinish((HDROP) wParam);
	DestroyWindow(progBar);
	return;
}

LRESULT
rootProc(HWND rootWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Root window

	static HBRUSH bckgrnd = NULL;

	switch (uMsg)
	{

		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			HDC hdc;

			hdc = BeginPaint(rootWnd, &ps);

			FillRect(hdc, &ps.rcPaint, (HBRUSH) COLOR_WINDOW);
			EndPaint(rootWnd, &ps);
			break;
		}

		case WM_COMMAND:
		{
			// Handle menu bar and popup messages
			switch (LOWORD(wParam))
			{

				case ID_ABOUT_MANUFACTURER:
					ShellExecuteW(NULL, L"open", L"https://google.com", NULL, NULL, SW_SHOW);
					break;

				case ID_ABOUT_LICENSE:
					break;

				case ID_CTRL_Q:
				case ID_FILE_QUIT:
					DestroyWindow(rootWnd);
					break;

				case ID_CTRL_O:
				case ID_FILE_OPEN:
				{
					LPWSTR path = NULL;
					WCHAR basename[MAX_PATH + 1] {};

					BinList.emplace_back(new PE);

					path = GetBinPath(rootWnd);

					if (!path || !BinList[index]->LoadBinary(path))
					{

						BinList[index]->CleanUp();
						delete BinList[index];
						BinList.pop_back();
						delete[] path;
						break;
					}

					BinList[index]->MakeTreeView(subWndLeft);

					index++;
					delete[] path;
					break;
				}

				case ID_CTRL_W:
				case ID_FILE_UNLOADSELECTION:
				{
					HTREEITEM selection;
					TVITEMEXW nodeItem {};

					if ((selection = TreeView_GetSelection(subWndLeft)) == NULL)
					{
						break;
					}

					while (selection != NULL)
					{

						nodeItem.hItem = selection;
						selection = TreeView_GetParent(subWndLeft, selection);
					}

					TreeView_DeleteItem(subWndLeft, nodeItem.hItem);
					ListView_DeleteAllItems(subWndRight);
					break;
				}

				case ID_CTRL_SHIFT_W:
				case ID_FILE_UNLOADALL:
				{
					deleting = true;

					for (int64_t i = (int64_t) (index - 1); i >= 0; i--)
					{
						BinList[i]->CleanUp();
						delete BinList[i];
					}

					BinList.clear();
					TreeView_DeleteAllItems(subWndLeft);
					ListView_DeleteAllItems(subWndRight);
					TreeView_SetHot(subWndLeft, NULL);

					for (uint32_t i = 0; i < 4; i++)
					{
						SendMessageW(subWndRight, LVM_DELETECOLUMN, 0, NULL);
					}

					firstSel = true;
					deleting = false;
					index = 0;
					break;
				}
				default:
					return DefWindowProcW(rootWnd, uMsg, wParam, lParam);
			}
			break;
		}

		case WM_SIZE:
		{
			// Record current size of root window and propagate changes to children
			GetClientRect(rootWnd, &rootRect);
			SendMessageW(subWndLeft, uMsg, wParam, lParam);
			SendMessageW(subWndRight, uMsg, wParam, lParam);
			break;
		}

		case WM_DROPFILES:
		{
			uint32_t nDrops;

			nDrops = DragQueryFileW((HDROP) wParam, 0xFFFFFFFF, NULL, NULL);
			std::thread loaderThread(LoaderProc, wParam, nDrops);

			// If for some reason the user decides to load thousands of binaries at once
			// this will make it so that the rest of the application isn't stuck waiting
			loaderThread.detach();

			break;
		}

		case WM_NOTIFY:
		{
			// Forward the message to the correct window procedure for processing
			if (((LPNMHDR) lParam)->idFrom == SUB_LEFT)
			{
				SendMessageW(subWndLeft, uMsg, wParam, lParam);
			}
			else if (((LPNMHDR) lParam)->idFrom == SUB_RIGHT)
			{
				SendMessageW(subWndRight, uMsg, wParam, lParam);
			}
			else
			{
				return DefWindowProcW(rootWnd, uMsg, wParam, lParam);
			}
			break;
		}

		case WM_DESTROY:
		{
			for (uint64_t i = 0; i < index; i++)
			{
				BinList[i]->CleanUp();
				delete BinList[i];
			}

			BinList.clear();
			PostQuitMessage(EXIT_SUCCESS);
			break;
		}

		default:
			return DefWindowProcW(rootWnd, uMsg, wParam, lParam);
	}
	return DefWindowProcW(rootWnd, uMsg, wParam, lParam);
}

LRESULT
leftProc(HWND subWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR subClassID, DWORD_PTR refData)
{
	switch (msg)
	{
		case WM_SIZE:
		{
			MoveWindow(subWnd, MS, MS,
					   TW, rootRect.bottom - (MS * 2),
					   true);
			GetClientRect(subWnd, &leftRect);
			break;
		}
		case WM_NOTIFY:
		{
			switch (((LPNMHDR) lParam)->code)
			{
				case TVN_SELCHANGED:
				{
					HTREEITEM selectedItem;
					TVITEMW item {};
					uint32_t i, id;

					if (deleting)
					{
						break;
					}

					selectedItem = TreeView_GetSelection(subWndLeft);

					if (!selectedItem)
						break;

					if (firstSel)
					{
						MakeListViewCols(subWndRight);
						firstSel = false;
					}

					item.hItem = selectedItem;
					item.mask = TVIF_PARAM;

					TreeView_GetItem(subWndLeft, &item);

					i = HIDWORD(item.lParam);
					id = LODWORD(item.lParam);

					ListView_DeleteAllItems(subWndRight);
					BinList[i]->PopulateList(subWndRight, id);
					break;
				}

				default:
					return DefSubclassProc(subWnd, msg, wParam, lParam);
			}
		}
		default:
			return DefSubclassProc(subWnd, msg, wParam, lParam);
	}
	return DefSubclassProc(subWnd, msg, wParam, lParam);
}

LRESULT
rightProc(HWND subWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR subClassID, DWORD_PTR refData)
{
	switch (msg)
	{
		case WM_SIZE:
		{
			MoveWindow(subWnd, TW + (MS * 2), MS,
					   rootRect.right - (TW + (MS * 3)),
					   rootRect.bottom - (MS * 2),
					   true);
			GetClientRect(subWnd, &rightRect);

			// Update the progress bar if there is one
			if (progBar)
			{
				// There's probably a better way of doing this performance wise
				GetClientRect(subWnd, &rightRect);
				MoveWindow(progBar, rightRect.left + MS, rightRect.bottom - (15 + MS),
						   rightRect.right - (MS * 2), 15, true);
			}
			break;
		}

		case WM_PAINT:
		{
			// Maybe GDI+ isn't the answer and if so remember to remove it from stdafx and the input libs
			break;
		}


		default:
			return DefSubclassProc(subWnd, msg, wParam, lParam);
	}

	return DefSubclassProc(subWnd, msg, wParam, lParam);
}