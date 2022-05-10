#pragma once

#define DEBUG _DEBUG

#define DEF_WIDTH	960			// Default width
#define DEF_HEIGHT	600			// and height
#define TW			200			// Tree Width
#define MS			4			// Margin Size
#define SUB_LEFT	0xDEAD		// Left subwindow ID
#define SUB_RIGHT	0xBEEF		// Right subwindow ID

// The `INFO`, `WARN` and `FAIL` constants hold two meanings:
// they're used by the programmer to generate info, warnings and error messages,
// but they also provide a simple way to set the color of the timestamp to match each case.
// The `WHITE` constant is used to reset colors and write a readable message in each case.
#define WHITE		(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)		// White timestamp
#define INFO		(FOREGROUND_GREEN | FOREGROUND_INTENSITY)											// Green timestamp
#define WARN		(FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY)							// Yellow timestamp
#define FAIL		(FOREGROUND_RED | FOREGROUND_INTENSITY)												// Red timestamp

#define HIDWORD(x) ((uint32_t)(x >> 32))
#define LODWORD(x) ((uint32_t)(x))