// test DLL entry: the interpreter starts the image as
// _DllMainCRTStartup(hinst, DLL_PROCESS_ATTACH, nullptr). DllMain returns
// FALSE unless the second parameter really is DLL_PROCESS_ATTACH (1), so a
// garbage reason cannot fake a pass. Exit code = the returned BOOL.
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    return reason == DLL_PROCESS_ATTACH ? TRUE : FALSE;
}
