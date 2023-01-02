#pragma once

#define HIDWORD(x) ((uint32_t)(x >> 32))
#define LODWORD(x) ((uint32_t)(x))

#define DEF_WIDTH	960			// Default width
#define DEF_HEIGHT	600			// and height
#define TW			200			// Tree Width
#define MS			4			// Margin Size
#define SUB_LEFT	0xDEAD		// Left subwindow ID
#define SUB_RIGHT	0xBEEF		// Right subwindow ID