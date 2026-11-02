#include <stddef.h>

typedef void* HMODULE;
typedef void* FARPROC;

extern __declspec(dllimport) HMODULE __stdcall LoadLibraryA(const char* name);
extern __declspec(dllimport) FARPROC __stdcall GetProcAddress(HMODULE mod, const char* name);

typedef int (__stdcall *MessageBoxA_t)(unsigned, const char*, const char*, unsigned);

const char g_txt[] = "iter4a-body";
const char g_cap[] = "iter4a-caption";

int main(void)
{
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (user32 == 0) return 111;

    MessageBoxA_t mb = (MessageBoxA_t)GetProcAddress(user32, "MessageBoxA");
    if (mb == 0) return 222;

    if (GetProcAddress(user32, "Nope") != 0) return 333;
    if (LoadLibraryA("nonexistent.dll") != 0) return 444;
    HMODULE u32b = LoadLibraryA("USER32.DLL");
    if (u32b != user32) return 555;

    int r = mb(0, g_txt, g_cap, 0) + mb(0, g_txt, g_cap, 0);
    return 100 + r;
}
