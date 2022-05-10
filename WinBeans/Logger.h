#pragma once

// You shouldn't need this as a user.

#include "Constants.h"

// Allocate console and open STDOUT for writing
BOOL StartLogging(VOID);

// Deallocate console and close STDOUT
VOID StopLogging (VOID);

// Write log messages (LogMe!) to console
VOID LogMeA (int32_t, const char*);

VOID LogMeW (int32_t, const LPWSTR);