// test DLL entry: the interpreter starts execution at the entry point with a
// sentinel return address and no argument contract, so the shellcode sets up
// its own DllMain arguments. The custom entry ignores whatever the caller
// left in the argument registers and derives the image base itself from
// __ImageBase; DllMain returns FALSE unless the image really is mapped there
// (MZ magic), so a garbage base cannot fake a pass. Exit code = the BOOL.
#include <windows.h>

extern "C" IMAGE_DOS_HEADER __ImageBase;

static BOOL WINAPI realMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return FALSE;
    return *reinterpret_cast<volatile WORD*>(hinst) == 0x5A4D ? TRUE : FALSE;
}

extern "C" BOOL __stdcall stubEntry(HINSTANCE, DWORD reason, LPVOID reserved) {
    (void)reason; (void)reserved;
    return realMain(reinterpret_cast<HINSTANCE>(&__ImageBase), DLL_PROCESS_ATTACH, nullptr);
}
