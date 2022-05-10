#include "stdafx.h"

#include "Logger.h"
#include "GUI.h"

INT APIENTRY
WinMain (_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
         _In_ LPSTR lpCmdLine, _In_ int32_t nCmdShow) {

    if (!StartLogging ())
        return EXIT_FAILURE;

    LaunchGUI (hInstance);

    StopLogging ();
    return EXIT_SUCCESS;
}