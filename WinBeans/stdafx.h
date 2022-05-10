#pragma once

#define WIN32_LEAN_AND_MEAN

// Link against ComCtrl32 version 6.0 for custom controls and (limited) theming 
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls'\
 version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <Windows.h>
#include <winnt.h>
#include <shellapi.h>
#include <commdlg.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <strsafe.h>
#include <vector>
#include <shlwapi.h>
#include <Uxtheme.h>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <thread>

// These changes rarely
#include "Logger.h"
#include "Types.h"