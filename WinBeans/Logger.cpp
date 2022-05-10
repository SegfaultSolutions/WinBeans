#include "stdafx.h"

#include "Logger.h"

#if DEBUG

// File object and the output stream associated with it.
// Both must survive until the end of the logging session.
FILE* DebugOut = NULL;
HANDLE Out = NULL;

// Needed to provide timing information about when the logs are 
// written to the console since the start of the application.
std::chrono::system_clock::time_point start;
std::chrono::system_clock::time_point now;
std::chrono::duration<double> timestamp;

BOOL
StartLogging (VOID) {

	start = std::chrono::system_clock::now ();

	if (!AllocConsole ())
		return false;

	freopen_s (&DebugOut, "CONOUT$", "w", stdout);

	if (!DebugOut) {
		FreeConsole ();
		return false;
	}

	// This is not strictly necessary but it is required if colored output matters to us
	// It does.
	if (!(Out = GetStdHandle (STD_OUTPUT_HANDLE))) {
		fclose (DebugOut);
		FreeConsole ();
		return false;
	}

	LogMeA (INFO, "Logger started.");
	return true;
}

VOID
StopLogging (VOID) {

	LogMeA (INFO, "End of log.");
	fclose (DebugOut);
	FreeConsole ();
}

VOID
LogMeA (int32_t lvl, const char* msg) {

	LPSTR reason = NULL;

	now = std::chrono::system_clock::now ();
	timestamp = now - start;

	SetConsoleTextAttribute (Out, lvl);
	std::cout << std::setprecision (8) << std::fixed
		<< "[ME " << timestamp.count () << "]: ";

	SetConsoleTextAttribute (Out, WHITE);
	std::cout << msg << std::endl;

	// Justify with error string from OS

	if (!(GetLastError ()) || (lvl == INFO))
		return;

	FormatMessageA (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, GetLastError (), MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&reason, 0, NULL);

	now = std::chrono::system_clock::now ();
	timestamp = now - start;

	SetConsoleTextAttribute (Out, lvl);
	std::cout << std::setprecision (8) << std::fixed
		<< "[OS " << timestamp.count () << "]: ";


	SetConsoleTextAttribute (Out, WHITE);
	std::cout << reason;

	SetLastError(EXIT_SUCCESS);
	LocalFree (reason);
	
	return;
}

VOID
LogMeW (int32_t lvl, const LPWSTR msg) {

	LPSTR reason = NULL;

	now = std::chrono::system_clock::now ();
	timestamp = now - start;

	SetConsoleTextAttribute (Out, lvl);
	std::cout << std::setprecision (8) << std::fixed
		<< "[ME " << timestamp.count () << "]: ";

	SetConsoleTextAttribute (Out, WHITE);
	std::wcout << msg << std::endl;

	// Justify with error string from OS

	if (!(GetLastError ()) || (lvl == INFO))
		return;

	FormatMessageA (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, GetLastError (), MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&reason, 0, NULL);

	now = std::chrono::system_clock::now ();
	timestamp = now - start;

	SetConsoleTextAttribute (Out, lvl);
	std::cout << std::setprecision (8) << std::fixed
		<< "[OS " << timestamp.count () << "]: ";


	SetConsoleTextAttribute (Out, WHITE);
	std::cout << reason;

	SetLastError(EXIT_SUCCESS);
	LocalFree (reason);
	
	return;
}
#else

// These functions have no effect in a release build and
// will likely be optimized out by the compiler.
BOOL StartLogging (VOID) { return true; }
VOID StopLogging (VOID) { return; }
VOID LogMeA (int32_t, const char*) { return; }
VOID LogMeW (int32_t, const LPWSTR) { return; }
#endif