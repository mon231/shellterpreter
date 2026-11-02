#include <stddef.h>

// explicit dllimport declarations: IgnoreAllDefaultLibraries + msvcrt.lib
// keeps the import table to exactly these three functions
extern __declspec(dllimport) int  __cdecl printf(const char* fmt, ...);
extern __declspec(dllimport) void __cdecl srand(unsigned seed);
extern __declspec(dllimport) int  __cdecl rand(void);

int main(void)
{
    printf("crt-lo|");
    printf("%d %d %d|", 42, -7, 12345);
    printf("%u %x|", 4000000000u, 48879);
    printf("%s %c|", "ok", 'Z');
    printf("%%");
    // stand-in contract: unsupported conversion -> -1, nothing printed
    if (printf("%q") != -1) return 121;

    srand(1234);
    unsigned sum = 0;
    for (int i = 0; i < 5; ++i) sum += (unsigned)rand();
    return (int)(100 + (sum % 1000));
}
