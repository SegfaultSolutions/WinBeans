#include "stdafx.h"
#include "GUI.h"

INT APIENTRY
WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
		_In_ LPSTR lpCmdLine, _In_ int32_t nCmdShow)
{
	bean_set_loglevel(BeanLogLevel::trace);
	LaunchGUI(hInstance);
	return EXIT_SUCCESS;
}