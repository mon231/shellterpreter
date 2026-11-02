#include <stddef.h>

typedef void* HRSRC;
typedef unsigned long DWORD;

extern __declspec(dllimport) HRSRC __stdcall FindResourceA(void* hModule, const char* name, const char* type);
extern __declspec(dllimport) DWORD __stdcall SizeofResource(void* hModule, HRSRC hRes);

// RT_RCDATA = 10 (MAKEINTRESOURCE)
#define RT_RCDATA ((const char*)10)

int main(void)
{
    HRSRC r = FindResourceA(0, "TESTDATA", RT_RCDATA);
    if (r == 0) return 111;

    DWORD sz = SizeofResource(0, r);
    if (sz != 500) return 122;

    // missing resource -> NULL, and a bad handle yields size 0
    if (FindResourceA(0, "NOPE", RT_RCDATA) != 0) return 133;
    if (SizeofResource(0, (HRSRC)0) != 0) return 144;

    return (int)(100 + sz);
}
