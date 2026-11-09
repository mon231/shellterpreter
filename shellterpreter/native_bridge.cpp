#include "native_bridge.hpp"
#include "vm.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

namespace stub {

// ---- module registry -------------------------------------------------

const char* const kNativeModuleNames[6] = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll",
    "user32.dll", "gdi32.dll", "advapi32.dll",
};

static void registerModules(Loaded& l) {
    for (const char* name : kNativeModuleNames) {
        if (l.realModCount >= 8) break;
        HMODULE h = GetModuleHandleA(name);
        if (!h) h = LoadLibraryA(name);
        if (!h) continue;
        // Loader-reported extent, not a hand-parsed PE header: a corrupt
        // header must cost a module, never the interpreter.
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) continue;
        const auto base = reinterpret_cast<uint64_t>(h);
        if (mi.SizeOfImage < 0x1000 || mi.SizeOfImage > 0x10000000) continue;
        l.realMods[l.realModCount] = ModuleRange{ base, base + mi.SizeOfImage };
        ++l.realModCount;
    }
}

bool isNativeModuleAddr(const Loaded& l, uint64_t addr) {
    for (uint32_t i = 0; i < l.realModCount; ++i)
        if (addr >= l.realMods[i].base && addr < l.realMods[i].end) return true;
    return false;
}

// ---- syscall table (x64 host): scan ntdll Nt* stub prologues ----------

struct SysEntry { uint32_t num; void* fn; };
static SysEntry gSys[2048];
static uint32_t gSysCount = 0;

bool isX64Host() { return sizeof(void*) == 8; }

void* syscallFnFor(uint32_t sysno) {
    for (uint32_t i = 0; i < gSysCount; ++i)
        if (gSys[i].num == sysno) return gSys[i].fn;
    return nullptr;
}

static void buildSyscallTable() {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return;
    const auto base = reinterpret_cast<uint64_t>(nt);
    const uint32_t lfanew = *reinterpret_cast<uint32_t*>(base + 0x3C);
    const uint8_t* nth = reinterpret_cast<const uint8_t*>(base) + lfanew;
    // DataDirectory[0] (exports) VirtualAddress: x64 at 0x88, x86 at 0x78
    const uint32_t expRva = sizeof(void*) == 8
        ? *reinterpret_cast<const uint32_t*>(nth + 0x88)
        : *reinterpret_cast<const uint32_t*>(nth + 0x78);
    if (!expRva) return;
    const uint8_t* exp = reinterpret_cast<const uint8_t*>(base) + expRva;
    const uint32_t nameCount = *reinterpret_cast<const uint32_t*>(exp + 0x18);
    const uint32_t namesRva = *reinterpret_cast<const uint32_t*>(exp + 0x20);
    const uint32_t funcsRva = *reinterpret_cast<const uint32_t*>(exp + 0x1C);
    const auto names = reinterpret_cast<const uint32_t*>(base + namesRva);
    const auto funcs = reinterpret_cast<const uint32_t*>(base + funcsRva);
    for (uint32_t i = 0; i < nameCount && gSysCount < 2048; ++i) {
        const char* nm = reinterpret_cast<const char*>(base + names[i]);
        if (nm[0] != 'N' || nm[1] != 't') continue;
        const uint8_t* code = reinterpret_cast<const uint8_t*>(base + funcs[i]);
        // standard stub: 4C 8B D1 (mov r10, rcx) ; B8 imm32 (mov eax, num)
        if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)
            gSys[gSysCount++] = SysEntry{
                *reinterpret_cast<const uint32_t*>(code + 4),
                reinterpret_cast<void*>(base + funcs[i]) };
    }
}

void initNativeBridge(Loaded& l) {
    registerModules(l);
    if (sizeof(void*) == 8) buildSyscallTable();
}

// ---- bridges ----------------------------------------------------------

// x64 host: plain C++ call; the compiler lays out shadow space and the
// 5..16 stack slots per MS x64 ABI, caller cleans.
bool callNativeWin64(uint64_t fn, const uint64_t args[16], uint64_t& out) {
    using Fn = uint64_t(__stdcall*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t, uint64_t);
    const Fn f = reinterpret_cast<Fn>(fn);
    __try {
        out = f(args[0], args[1], args[2], args[3],
                args[4], args[5], args[6], args[7],
                args[8], args[9], args[10], args[11],
                args[12], args[13], args[14], args[15]);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

#if defined(_M_IX86)
// x86 host: naked stdcall bridge. Pushes 16 dword args (arg1 ends up at
// [esp] before the call), calls the real function and measures how many
// dwords the callee cleaned so the emulated esp can be advanced identically.
__declspec(naked) static uint32_t nativeBridge86(uint32_t fn, const uint32_t* args, uint32_t* nargsOut) {
    __asm {
        push ebp
        mov ebp, esp
        mov eax, [ebp+8]        ; fn (save to local, loop needs eax)
        mov [ebp-12], eax
        sub esp, 12
        mov edx, [ebp+12]       ; args array (arg1..arg16)
        lea ecx, [edx+60]
        mov eax, 16
    pl: push dword ptr [ecx]
        sub ecx, 4
        dec eax
        jnz pl
        mov [ebp-4], esp        ; esp before the call
        call [ebp-12]
        mov [ebp-8], eax        ; return value
        mov eax, esp
        sub eax, [ebp-4]        ; = 4 * dwords popped by the callee
        mov ecx, [ebp+16]
        mov [ecx], eax
        mov eax, [ebp-8]
        mov esp, ebp
        pop ebp
        ret
    }
}

bool callNativeWin86(uint64_t fn, const uint32_t args[16], uint32_t& out, uint32_t& nargs) {
    uint32_t delta = 0;
    __try {
        out = nativeBridge86(static_cast<uint32_t>(fn), args, &delta);
        nargs = delta / 4;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
#else
bool callNativeWin86(uint64_t, const uint32_t[16], uint32_t&, uint32_t&) { return false; }
#endif

} // namespace stub
