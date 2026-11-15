#include "api_standins.hpp"
#include "guest_environment.hpp"
#include "native_bridge.hpp"
#include <cstdio>
#include <cstring>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace stub {

static char lowerAscii(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

static bool nameEq(const char* a, const char* b) {
    for (;; ++a, ++b) {
        if (lowerAscii(*a) != lowerAscii(*b)) return false;
        if (*a == '\0') return true;
    }
}

// ordinal import: stubs mask ordinals with 0xffff, so any value < 0x10000 is an
// ordinal; name pointers are absolute and >= img.base() (VirtualAlloc reserves start at 0x10000)
static const uint64_t kOrdinalMax = 0x10000ull;

static bool startsWithNoCase(const char* s, const char* prefix) {
    for (; *prefix; ++s, ++prefix)
        if (lowerAscii(*s) != lowerAscii(*prefix)) return false;
    return true;
}

// copy `size` bytes to a guest address when the bytes are mapped; pointers
// the guest obtained from native APIs (real HeapAlloc handles) land outside
// the guest regions and go through the host-page fallback instead
#define GUEST_WRITE(l, addr, from, size) do { \
        GuestMem m_ = guestMem((l), (addr)); \
        if (m_.p && m_.avail >= (size)) memcpy(m_.p, (from), (size)); \
        else if (hostPageAddr((addr), (size), true, m_.p)) memcpy(m_.p, (from), (size)); \
    } while (0)

static uint64_t apiLoadLibraryA(Loaded& l, const uint64_t* args) {
    char name[64];
    if (!guestStr(l, args[0], name)) return 0;
    fprintf(stderr, "TRC LDA name=%s", name);
    // TEMP batch G: log whitelist resolution result
    for (uint32_t i = 0; i < l.realModCount; ++i)
        if (nameEq(name, kNativeModuleNames[i])) {
            fprintf(stderr, " -> realMods[%u]=%llX", i, (unsigned long long)l.realMods[i].base);
            break;
        }
    fprintf(stderr, "\n");
    // batch D: whitelisted system modules now resolve to their real base;
    // calls into them go through the native bridge, everything else keeps
    // the interpreter's fake module layout
    for (uint32_t i = 0; i < l.realModCount; ++i) {
        // realMods are keyed by the same whitelist order as registerModules
        if (nameEq(name, kNativeModuleNames[i])) return l.realMods[i].base;
    }
    if (nameEq(name, "kernel32.dll") || nameEq(name, "kernelbase.dll")) {
        return l.env.base() + K32_RVA;
    }
    if (nameEq(name, "user32.dll")) return l.env.base() + USER32_RVA;
    if (nameEq(name, "msvcrt.dll")) return l.env.base() + MSVCRT_RVA;
    // hardening-batch-F+ real-binary support: the api-set shim names real
    // binaries import are forwarders to kernelbase (kernel32's implementation
    // surface); resolving them to the real kernelbase lets peor-converted
    // real programs bridge the actual functions instead of failing closed
    if (startsWithNoCase(name, "api-ms-win-core-") ||
        startsWithNoCase(name, "api-ms-win-shcore-") ||
        startsWithNoCase(name, "api-ms-win-security-") ||
        startsWithNoCase(name, "api-ms-win-service-")) return l.realKbase();
    return 0;
    // the CRT is split over ucrtbase/msvcp140/vcruntime140 and api-set stubs,
    // with a "d" suffix in Debug builds (msvcp140d, ucrtbased, ...)
    if (startsWithNoCase(name, "ucrtbase") || startsWithNoCase(name, "ucrtbased") ||
        startsWithNoCase(name, "msvcp140") ||
        startsWithNoCase(name, "vcruntime140") ||
        startsWithNoCase(name, "api-ms-win-crt-")) {
        return l.env.base() + CRTRT_RVA;
    }
    return 0;
}

static uint64_t apiGetProcAddress(Loaded& l, const uint64_t* args) {
    { // TEMP batch G
        char tname[64];
        if (guestStr(l, args[1], tname))
            fprintf(stderr, "TRC GP mod=%llX name=%s\n",
                    (unsigned long long)args[0], tname);
        else
            fprintf(stderr, "TRC GP mod=%llX name=?\n", (unsigned long long)args[0]);
    }
    if (args[1] < kOrdinalMax) {
        // ordinal imports carry no name; only resolvable against a real module
        for (uint32_t i = 0; i < l.realModCount; ++i) {
            if (args[0] != l.realMods[i].base) continue;
            const FARPROC p = ::GetProcAddress(reinterpret_cast<HMODULE>(args[0]),
                                               MAKEINTRESOURCEA(static_cast<int>(args[1])));
            return reinterpret_cast<uint64_t>(p);
        }
        return 0;
    }
    char name[64];
    if (!guestStr(l, args[1], name)) return 0;    if (nameEq(name, "LoadLibraryA"))  return l.env.base() + ST_LL_A;
    if (nameEq(name, "GetProcAddress")) return l.env.base() + ST_GP_A;
    if (nameEq(name, "MessageBoxA"))   return l.env.base() + ST_MB_A;
    if (nameEq(name, "printf"))        return l.env.base() + ST_PRINTF_A;
    if (nameEq(name, "srand"))         return l.env.base() + ST_SRAND_A;
    if (nameEq(name, "rand"))          return l.env.base() + ST_RAND_A;
    if (nameEq(name, "FindResourceA")) return l.env.base() + ST_FIND_RES_A;
    if (nameEq(name, "SizeofResource")) return l.env.base() + ST_SIZE_RES_A;
    if (nameEq(name, "_beginthreadex")) return l.env.base() + ST_BEGINT;
    if (nameEq(name, "_Thrd_join"))     return l.env.base() + ST_THRDJOIN;
    if (nameEq(name, "_Thrd_id"))       return l.env.base() + ST_THRDID;
    if (nameEq(name, "GetCurrentThreadId")) return l.env.base() + ST_THRDID;
    if (nameEq(name, "_Cnd_do_broadcast_at_thread_exit")) return l.env.base() + ST_CNDEXIT;
    if (nameEq(name, "malloc"))         return l.env.base() + ST_MALLOC;
    if (nameEq(name, "free"))           return l.env.base() + ST_FREE;
    if (nameEq(name, "_callnewh"))      return l.env.base() + ST_CALLNEWH;
    // throw helpers: the stand-ins record the throw and the interpreter walks
    // the guest frames itself (see dispatchThrow in cpu.hpp)
    if (nameEq(name, "_CxxThrowException")) return l.env.base() + ST_THROW;
    if (nameEq(name, "RaiseException")) return l.env.base() + ST_RAISE;
    if (nameEq(name, "__CxxFrameHandler4")) return l.env.base() + ST_CXXFRAME4;
    if (nameEq(name, "__CxxFrameHandler3")) return l.env.base() + ST_CXXFRAME3;
    if (nameEq(name, "_except_handler3")) return l.env.base() + ST_EH3;
    if (nameEq(name, "__std_exception_copy")) return l.env.base() + ST_CRTFAIL;
    if (nameEq(name, "__std_exception_destroy")) return l.env.base() + ST_CRTFAIL;
    if (nameEq(name, "?_Throw_Cpp_error@std@@YAXH@Z")) return l.env.base() + ST_CRTFAIL;
    if (nameEq(name, "terminate")) return l.env.base() + ST_CRTFAIL;
    if (nameEq(name, "GetSystemTimeAsFileTime")) return l.env.base() + ST_GSFT;
    if (nameEq(name, "QueryPerformanceCounter")) return l.env.base() + ST_QPC;
    if (nameEq(name, "GetCurrentProcessId")) return l.env.base() + ST_PID;
    if (nameEq(name, "InitializeSListHead")) return l.env.base() + ST_SLIST;
    if (nameEq(name, "UnhandledExceptionFilter")) return l.env.base() + ST_UEHF;
    if (nameEq(name, "SetUnhandledExceptionFilter")) return l.env.base() + ST_SUEH;
    if (nameEq(name, "IsProcessorFeaturePresent")) return l.env.base() + ST_IPP;
    // CRT startup pieces: iterations ran without them so far because the peor
    // stub chain takes EXE tests straight to main; a DLL entry runs the real
    // _DllMainCRTStartup flow and needs these
    if (nameEq(name, "__C_specific_handler")) return l.env.base() + ST_CSH;
    if (nameEq(name, "GetCurrentProcess")) return l.env.base() + ST_GCURPROC;
    // never legitimate mid-run: fail closed
    if (nameEq(name, "TerminateProcess")) return l.env.base() + ST_TERMPROC;
    if (nameEq(name, "_except_handler4_common")) return l.env.base() + ST_EH4;
    if (nameEq(name, "_getmainargs") || nameEq(name, "__getmainargs"))
        return l.env.base() + ST_ARGS;
    if (nameEq(name, "_wgetmainargs") || nameEq(name, "__wgetmainargs"))
        return l.env.base() + ST_WARGS;
    // _initterm gets a real table runner (see apiInitterm); _initterm_e and
    // the rest of the uCRT startup pieces stay no-ops until a test needs them
    if (nameEq(name, "_initterm")) return l.env.base() + ST_INITTERM;
    if (nameEq(name, "GetModuleHandleW") || nameEq(name, "GetModuleHandleA"))
        return l.env.base() + ST_MODH;
    if (nameEq(name, "FormatMessageW")) return l.env.base() + ST_FMT;
    if (nameEq(name, "GetModuleFileNameW")) return l.env.base() + ST_MODFNW;
    if (nameEq(name, "GetModuleFileNameA")) return l.env.base() + ST_MODFNA;
    // native CRT exit walks its atexit table and calls guest callbacks
    // natively (guest pages are not executable); halt the run instead
    if (nameEq(name, "exit") || nameEq(name, "_exit") || nameEq(name, "_amsg_exit"))
        return l.env.base() + ST_EXIT;
    // frees guest-heap pointers handed out by FormatMessageW; the native
    // LocalFree would see a bogus host handle
    if (nameEq(name, "LocalFree")) return l.env.base() + ST_SLIST;
    if (nameEq(name, "_initterm_e")) return l.env.base() + ST_CNOP;
    if (nameEq(name, "_cexit") ||
        nameEq(name, "_execute_onexit_table") ||
        nameEq(name, "_initialize_onexit_table") ||
        nameEq(name, "_initialize_narrow_environment") ||
        nameEq(name, "_configure_narrow_argv") ||
        nameEq(name, "_seh_filter_dll") ||
        nameEq(name, "__std_type_info_destroy_list") ||
        nameEq(name, "IsDebuggerPresent")) return l.env.base() + ST_CNOP;
    // Rtl unwind/context never legitimately run before exception support;
    // fail closed instead of silently returning zeros
    if (nameEq(name, "RtlCaptureContext") ||
        nameEq(name, "RtlLookupFunctionEntry") ||
        nameEq(name, "RtlVirtualUnwind")) return l.env.base() + ST_CRTFAIL;
    // batch D: names the interpreter does not intercept resolve against the
    // real module when the guest passed one; the returned address runs the
    // native bridge
    for (uint32_t i = 0; i < l.realModCount; ++i) {
        if (args[0] != l.realMods[i].base) continue;
        const FARPROC p = ::GetProcAddress(reinterpret_cast<HMODULE>(args[0]), name);
        if (!p) fprintf(stderr, "TRC GPA0 mod=%s name=%s\n", kNativeModuleNames[i], name);
        return reinterpret_cast<uint64_t>(p);
    }
    // mem* through guest-blob stand-ins only when no real module supplied
    // them: native alloc hands out host pointers the stand-ins cannot
    // address, and guest pointers are identity-mapped so native mem* is safe
    if (nameEq(name, "memcpy")) return l.env.base() + ST_MEMCPY;
    if (nameEq(name, "memset")) return l.env.base() + ST_MEMSET;
    fprintf(stderr, "TRC GPA nomatch mod=%llX name=%s\n", (unsigned long long)args[0], name);
    return 0;
}

static uint64_t apiMessageBoxA(Loaded&, const uint64_t*) { return 1; } // IDOK

static uint64_t apiRtlAdd(Loaded&, const uint64_t*) { return 1; } // handler registered

// CRT-startup time/counter stand-ins: deterministic zeros, so the GS cookie
// and any counters the guest mixes stay stable
static uint64_t apiGetSystemTimeAsFileTime(Loaded& l, const uint64_t* args) {
    const uint64_t zero = 0;
    GUEST_WRITE(l, args[0], &zero, 8);
    return 0; // void
}

static uint64_t apiQueryPerformanceCounter(Loaded& l, const uint64_t* args) {
    const uint64_t zero = 0;
    GUEST_WRITE(l, args[0], &zero, 8);
    return 1;
}

static uint64_t apiGetCurrentProcessId(Loaded&, const uint64_t*) { return 1; }

static uint64_t apiNoOp(Loaded&, const uint64_t*) { return 0; }

// CRT _initterm: the function-pointer table entries are guest code, which the
// native bridge cannot call, so the stand-in emits a guest-side loop into env
// scratch and tail-jumps into it; the loop calls every non-null entry and its
// final ret lands on the stand-in caller's return address
static uint64_t apiInitterm(Loaded& l, const uint64_t* args) {
    fprintf(stderr, "TRC INITERM enter rcx=%llX rdx=%llX\n",
            (unsigned long long)args[0], (unsigned long long)args[1]);
    {
        // TEMP batch G: early IAT dump (WSAStartup slot check)
        fprintf(stderr, "TRC IAT0E:");
        for (uint32_t rva = 0x4150; rva <= 0x4230; rva += 8) {
            GuestMem m = guestMem(l, l.img.base() + 0x320 + rva);
            uint64_t v = 0;
            if (m.p && m.avail >= 8) memcpy(&v, m.p, 8);
            fprintf(stderr, " %X:%llX", rva, (unsigned long long)v);
        }
        fprintf(stderr, "\n");
        // TEMP batch G: whoami IAT range
        fprintf(stderr, "TRC IATW:");
        for (uint32_t rva = 0x10D00; rva <= 0x11010; rva += 8) {
            GuestMem m = guestMem(l, l.img.base() + 0x320 + rva);
            uint64_t v = 0;
            if (m.p && m.avail >= 8) memcpy(&v, m.p, 8);
            fprintf(stderr, " %X:%llX", rva, (unsigned long long)v);
        }
        fprintf(stderr, "\n");
    }
    if (sizeof(void*) != 8) return 0; // 32-bit guests keep the no-op stand-in
    static const uint8_t tramp[] = {
        0x4C, 0x8B, 0xD1,             // 00 mov r10, rcx
        0x4C, 0x8B, 0xDA,             // 03 mov r11, rdx
        0x48, 0x83, 0xEC, 0x28,       // 06 sub rsp, 0x28 (own frame; guest
                                      //    callbacks clobber [rsp+8..0x28))
        0x4D, 0x39, 0xDA,             // 0A loop: cmp r10, r11
        0x73, 0x11,                   // 0D jae done (+0x11 -> 0x20)
        0x49, 0x8B, 0x02,             // 0F mov rax, [r10]
        0x48, 0x85, 0xC0,             // 12 test rax, rax
        0x74, 0x03,                   // 15 jz next (+0x03 -> 0x1A)
        0xFF, 0xD0,                   // 17 call rax
        0x90,                         // 19 nop
        0x49, 0x83, 0xC2, 0x08,       // 1A next: add r10, 8
        0xEB, 0xEA,                   // 1E jmp loop (0x1E+2-0x16 = 0x0A)
        0x31, 0xC0,                   // 20 done: xor eax, eax
        0x48, 0x83, 0xC4, 0x28,       // 22 add rsp, 0x28
        0xC3,                         // 26 ret
    };
    memcpy(l.env.data() + ST_TRAMP, tramp, sizeof(tramp));
    l.tailJump = l.env.base() + ST_TRAMP;
    return 0;
}

// __C_specific_handler: real SEH comes with iteration 6; the startup flow
// only needs a truthful "no exception happened" oracle here
static uint64_t apiCsh(Loaded&, const uint64_t*) { return 0; }

// CRT memcpy/memset through the guest address space: the uCRT DLL startup
// copies cookie/init data through these
static uint64_t apiMemcpy(Loaded& l, const uint64_t* args) {
    const size_t n = static_cast<size_t>(args[2]);
    if (!n) return args[0];
    GuestMem dst = guestMem(l, args[0]);
    GuestMem src = guestMem(l, args[1]);
    if (!dst.p || dst.avail < n || !src.p || src.avail < n) {
        fprintf(stderr, "TRC MCOPY fail dst=%llX src=%llX n=%llX\n",
                (unsigned long long)args[0], (unsigned long long)args[1],
                (unsigned long long)args[2]); // TEMP batch G
        l.fault = fault_code(Fault::OutsideMemory);
        return 0;
    }
    memmove(dst.p, src.p, n);
    return args[0];
}

static uint64_t apiMemset(Loaded& l, const uint64_t* args) {
    const size_t n = static_cast<size_t>(args[2]);
    if (!n) return args[0];
    GuestMem dst = guestMem(l, args[0]);
    if (!dst.p || dst.avail < n) {
        fprintf(stderr, "TRC MSET fail dst=%llX n=%llX\n",
                (unsigned long long)args[0], (unsigned long long)args[2]); // TEMP batch G
        l.fault = fault_code(Fault::OutsideMemory);
        return 0;
    }
    memset(dst.p, static_cast<int>(args[1] & 0xFF), n);
    return args[0];
}

// pseudo process handle, (HANDLE)-1
static uint64_t apiGetCurrentProcess(Loaded&, const uint64_t*) { return 0xFFFFFFFFFFFFFFFFull; }

// exit/_exit/_amsg_exit: the native CRT exit would walk its atexit table and
// call guest callbacks natively (guest pages are not executable); stop the
// run instead and surface the status as the process exit code
static uint64_t apiExit(Loaded& l, const uint64_t* args) {
    l.fault = fault_code(Fault::Halt);
    return args[0];
}

// rand/srand: classic MSVCRT LCG, shared static seed
static uint64_t gRandSeed = 0;

static uint64_t apiSrand(Loaded&, const uint64_t* args) {
    gRandSeed = args[0] & 0xFFFFFFFFull;
    return 0;
}

static uint64_t apiRand(Loaded&, const uint64_t*) {
    gRandSeed = gRandSeed * 214013ull + 2531011ull;
    return (gRandSeed >> 16) & 0x7FFF;
}

// minimal printf: %d %i %u %x %X %c %s %%. Buffered so an unsupported
// conversion aborts the call with -1 and prints nothing (fail closed).
static uint64_t apiPrintf(Loaded& l, const uint64_t* args) {
    char fmt[96];
    if (!guestStr(l, args[0], fmt)) return static_cast<uint64_t>(-1);
    char out[256];
    size_t n = 0;
    int argIdx = 1;
    for (const char* p = fmt; *p; ++p) {
        if (*p != '%') {
            if (n < sizeof(out)) out[n++] = *p;
            continue;
        }
        const char spec = *++p;
        if (spec == '%') {
            if (n < sizeof(out)) out[n++] = '%';
            continue;
        }
        // arguments at our call sites are 32-bit values; all guest pointers
        // fit below 4 GB (GuestRegion keeps every guest block under 0x80000000)
        const uint64_t v = args[argIdx++] & 0xFFFFFFFFull;
        if (spec == 's') {
            char s[64];
            if (!guestStr(l, v, s)) return static_cast<uint64_t>(-1);
            const size_t k = strlen(s);
            if (n + k >= sizeof(out)) return static_cast<uint64_t>(-1);
            memcpy(out + n, s, k);
            n += k;
            continue;
        }
        const size_t room = sizeof(out) - n - 1;
        if (room == 0) return static_cast<uint64_t>(-1);
        int k = -1;
        switch (spec) {
        case 'd': case 'i': k = snprintf(out + n, room, "%d", static_cast<int32_t>(static_cast<uint32_t>(v))); break;
        case 'u': k = snprintf(out + n, room, "%u", static_cast<uint32_t>(v)); break;
        case 'x': k = snprintf(out + n, room, "%x", static_cast<uint32_t>(v)); break;
        case 'X': k = snprintf(out + n, room, "%X", static_cast<uint32_t>(v)); break;
        case 'c': k = snprintf(out + n, room, "%c", static_cast<char>(v)); break;
        default:
            return static_cast<uint64_t>(-1); // unsupported conversion
        }
        if (k < 0) return static_cast<uint64_t>(-1);
        if (static_cast<size_t>(k) > room) k = static_cast<int>(room);
        n += static_cast<size_t>(k);
    }
    out[n] = '\0';
    fwrite(out, 1, n, stdout);
    return n;
}

// resource stand-ins: the guest declared its image base and resource
// directory RVA in the descriptor globals, so FindResourceA/SizeofResource
// walk the real resource directory without parsing any header
static bool descImage(const Loaded& l, uint64_t& imageBase, uint32_t& resRva) {
    if (l.env.size() < kDescRva + 0x20) return false;
    uint32_t magic;
    memcpy(&magic, l.env.data() + kDescRva, 4);
    if (magic != kDescMagic) return false;
    memcpy(&resRva, l.env.data() + kDescRva + 4, 4);
    memcpy(&imageBase, l.env.data() + kDescRva + 8, 8);
    return imageBase >= l.img.base() && imageBase < l.img.base() + l.img.size();
}

static bool imgRead(const Loaded& l, uint64_t imageBase, uint64_t off, void* dst, size_t n) {
    const uint64_t rel = imageBase - l.img.base();
    const uint64_t avail = l.img.size() - rel;
    if (off > avail || n > avail - off) return false;
    memcpy(dst, l.img.data() + rel + off, n);
    return true;
}

// directory entry offsets are relative to the resource section base
static bool resFind(const Loaded& l, uint64_t imageBase, uint32_t resRva, uint32_t rel, const char* name,
                    uint32_t id, uint32_t& childRel, bool& isDir) {
    uint16_t counts[2] = { 0, 0 };
    if (!imgRead(l, imageBase, resRva + rel + 12, counts, 4)) return false;
    const uint32_t total = static_cast<uint32_t>(counts[0]) + counts[1];
    for (uint32_t i = 0; i < total; ++i) {
        uint32_t e[2] = { 0, 0 };
        if (!imgRead(l, imageBase, resRva + rel + 16 + 8 * i, e, 8)) return false;
        bool match = false;
        if (e[0] & 0x80000000u) {
            if (name) {
                const uint32_t nr = resRva + (e[0] & 0x7FFFFFFFu);
                uint16_t len = 0;
                if (!imgRead(l, imageBase, nr, &len, 2)) continue;
                bool eq = name[len] == '\0';
                for (uint16_t k = 0; k < len && eq; ++k) {
                    uint16_t c = 0;
                    if (!imgRead(l, imageBase, nr + 2 + 2 * k, &c, 2)) { eq = false; break; }
                    eq = c == static_cast<uint8_t>(name[k]);
                }
                match = eq;
            }
        } else {
            match = !name && e[0] == id;
        }
        if (!match) continue;
        childRel = e[1] & 0x7FFFFFFFu;
        isDir = (e[1] & 0x80000000u) != 0;
        return true;
    }
    return false;
}

static bool resFirst(const Loaded& l, uint64_t imageBase, uint32_t resRva, uint32_t rel, uint32_t& childRel, bool& isDir) {
    uint16_t counts[2] = { 0, 0 };
    if (!imgRead(l, imageBase, resRva + rel + 12, counts, 4) || counts[0] + counts[1] == 0) return false;
    uint32_t e[2] = { 0, 0 };
    if (!imgRead(l, imageBase, resRva + rel + 16, e, 8)) return false;
    childRel = e[1] & 0x7FFFFFFFu;
    isDir = (e[1] & 0x80000000u) != 0;
    return true;
}

static uint64_t apiFindResourceA(Loaded& l, const uint64_t* args) {
    // the hosted module is the shellcode's own image; any handle is ignored
    uint64_t imageBase = 0;
    uint32_t res = 0;
    if (!descImage(l, imageBase, res) || res == 0) return 0;
    const uint64_t nameArg = args[1], typeArg = args[2];
    uint32_t typeRel = 0, nameRel = 0, langRel = 0;
    bool dir = false;
    if (typeArg < 0x10000u) {
        if (!resFind(l, imageBase, res, 0, nullptr, static_cast<uint32_t>(typeArg), typeRel, dir) || !dir) return 0;
    } else {
        char tb[64];
        if (!guestStr(l, typeArg, tb) || !resFind(l, imageBase, res, 0, tb, 0, typeRel, dir) || !dir) return 0;
    }
    if (nameArg < 0x10000u) {
        if (!resFind(l, imageBase, res, typeRel, nullptr, static_cast<uint32_t>(nameArg), nameRel, dir) || !dir) return 0;
    } else {
        char nb[64];
        if (!guestStr(l, nameArg, nb) || !resFind(l, imageBase, res, typeRel, nb, 0, nameRel, dir) || !dir) return 0;
    }
    if (!resFind(l, imageBase, res, nameRel, nullptr, 0x409, langRel, dir) || dir) {
        if (!resFirst(l, imageBase, res, nameRel, langRel, dir) || dir) return 0; // any language
    }
    // handle = guest address of the data entry, decoded again by SizeofResource
    return imageBase + res + langRel;
}

static uint64_t apiSizeofResource(Loaded& l, const uint64_t* args) {
    uint64_t imageBase = 0;
    uint32_t resRva = 0;
    if (!descImage(l, imageBase, resRva)) return 0;
    if (args[1] < imageBase) return 0;
    // IMAGE_RESOURCE_DATA_ENTRY: DataRVA, Size, CodePage, Reserved
    uint32_t size = 0;
    if (!imgRead(l, imageBase, args[1] - imageBase + 4, &size, 4)) return 0;
    return size;
}

// wide guest string reader: NUL-terminated, clipped to cap-1
static size_t guestWideStr(const Loaded& l, uint64_t addr, wchar_t out[], size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        GuestMem m = guestMem(l, addr + 2 * n);
        if (!m.p || m.avail < 2) break;
        uint16_t ch;
        memcpy(&ch, m.p, 2);
        if (!ch) break;
        out[n++] = static_cast<wchar_t>(ch);
    }
    out[n] = L'\0';
    return n;
}

// GetModuleHandleW/A: NULL means the shellcode's own image; names resolve to
// the same handles LoadLibraryA hands out (real bases for whitelisted system
// modules, fake stand-in bases otherwise). The native version would return
// host process handles the guest cannot use.
static uint64_t apiModuleHandle(Loaded& l, const uint64_t* args) {
    if (args[0] == 0) return l.img.base() + 0x320; // rva 0 of the guest image
    wchar_t wname[64];
    guestWideStr(l, args[0], wname, 64);
    char name[64];
    for (size_t j = 0; j < 64; ++j) name[j] = static_cast<char>(wname[j]);
    name[63] = '\0';
    for (uint32_t i = 0; i < l.realModCount; ++i)
        if (nameEq(name, kNativeModuleNames[i])) return l.realMods[i].base;
    if (nameEq(name, "kernel32.dll") || nameEq(name, "kernelbase.dll")) return l.env.base() + K32_RVA;
    if (nameEq(name, "user32.dll")) return l.env.base() + USER32_RVA;
    if (nameEq(name, "msvcrt.dll")) return l.env.base() + MSVCRT_RVA;
    return 0;
}

// GetModuleFileNameW/A: NULL/self handle means the emulated image; report
// C:\Windows\System32\<blob name>.exe so the guest's self-inspection (version
// checks, resource paths) reads genuine system data. Real module handles
// delegate to the native API.
static bool moduleFileNameSelf(Loaded& l, uint64_t h) {
    return h == 0 || h == l.img.base() || h == l.img.base() + 0x320;
}

static uint64_t apiModuleFileNameW(Loaded& l, const uint64_t* args) {
    wchar_t path[300];
    uint64_t chars;
    fprintf(stderr, "TRC MODFNW h=%llX buf=%llX cap=%llX name=%s\n",
            (unsigned long long)args[0], (unsigned long long)args[1],
            (unsigned long long)args[2], l.name); // TEMP batch G
    if (moduleFileNameSelf(l, args[0])) {
        if (!l.name[0]) return 0; // unnamed blob: fail closed
        chars = swprintf(path, 300, L"C:\\Windows\\System32\\%hs.exe", l.name);
    } else {
        chars = ::GetModuleFileNameW(reinterpret_cast<HMODULE>(args[0]), path, 300);
    }
    if (!chars || !args[1] || !args[2]) return chars;
    const uint64_t copy = chars < args[2] ? chars : args[2] - 1;
    GUEST_WRITE(l, args[1], path, static_cast<size_t>(copy) * sizeof(wchar_t));
    const wchar_t nul = 0;
    GUEST_WRITE(l, args[1] + copy * sizeof(wchar_t), &nul, sizeof(nul));
    return copy;
}

static uint64_t apiModuleFileNameA(Loaded& l, const uint64_t* args) {
    char path[300];
    uint64_t chars;
    if (moduleFileNameSelf(l, args[0])) {
        if (!l.name[0]) return 0;
        chars = _snprintf(path, 300, "C:\\Windows\\System32\\%s.exe", l.name);
        if (chars == static_cast<uint64_t>(-1) || chars >= 300) chars = 0;
    } else {
        chars = ::GetModuleFileNameA(reinterpret_cast<HMODULE>(args[0]), path, 300);
    }
    if (!chars || !args[1] || !args[2]) return chars;
    const uint64_t copy = chars < args[2] ? chars : args[2] - 1;
    GUEST_WRITE(l, args[1], path, static_cast<size_t>(copy));
    GUEST_WRITE(l, args[1] + copy, "", 1);
    return copy;
}

// FormatMessageW for the guest's own message table (FORMAT_MESSAGE_FROM_
// HMODULE). The native LdrFindResource would work on a real PE at a page-
// aligned module base, which the guest image is not, so parse RT_MES
// SAGETABLE here. Inserts read the caller's Arguments va_list (qword per
// insert); strings arrive as guest pointers. ALLOCATE_BUFFER hands back a
// guest-heap pointer so guest code can read the result.
static uint64_t heapAlloc(Loaded& l, uint64_t sz); // defined below
// FormatMessageW flags used by the stand-ins
constexpr uint64_t kIgnoreInserts = 0x200;

// MUI fallback: modern system binaries are MUI-split and carry no message
// table of their own; the text lives in <lang>\<binary>.mun next to the base
// file. Load it as a data file and let the native FormatMessageW do the
// lookup (guest stack pointers are host-identity-mapped, so its va_list
// reads the caller's inserts directly); copy the result into the guest heap.
static uint64_t muiFallback(Loaded& l, uint64_t flags, uint64_t msgId,
                            uint64_t bufferPtr, uint64_t vaArgs) {
    wchar_t lang[64] = L"en-US";
    GetUserDefaultLocaleName(lang, 64);
    wchar_t path[300];
    HMODULE h = nullptr;
    if (l.name[0]) {
        wchar_t wname[32];
        size_t j = 0;
        for (; j < 31 && l.name[j]; ++j) wname[j] = static_cast<wchar_t>(l.name[j]);
        wname[j] = 0;
        for (int pass = 0; pass < 4 && !h; ++pass) {
            // servicing-store (.mun) and classic MUI (.mui) both occur
            swprintf(path, 300,
                     pass & 1 ? L"C:\\Windows\\System32\\en-US\\%ls.exe.%ls"
                              : L"C:\\Windows\\System32\\%ls\\%ls.exe.%ls",
                     pass & 1 ? lang : wname, wname,
                     pass & 2 ? L"mui" : L"mun");
        h = LoadLibraryExW(path, nullptr,
                           LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        }
    }
    if (!h) return 0;
    wchar_t* hostBuf = nullptr;
    // Arguments is va_list*: the guest stores a pointer to its first vararg
    // slot; deref it so the native va_arg walks the real argument homes
    va_list ap = nullptr;
    if (vaArgs) {
        GuestMem mv = guestMem(l, vaArgs);
        if (mv.p && mv.avail >= 8) memcpy(&ap, mv.p, 8);
    }
    const DWORD n = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE |
            ((flags & kIgnoreInserts) || !ap ? FORMAT_MESSAGE_IGNORE_INSERTS : 0),
        h, static_cast<DWORD>(msgId), 0, reinterpret_cast<LPWSTR>(&hostBuf), 0,
        &ap);
    uint64_t result = 0;
    if (n) {
        const uint64_t addr = heapAlloc(l, (static_cast<uint64_t>(n) + 1) * 2);
        if (addr) {
            GUEST_WRITE(l, addr, hostBuf, static_cast<size_t>(n) * 2);
            const uint16_t nul = 0;
            GuestMem m = guestMem(l, addr + static_cast<uint64_t>(n) * 2);
            if (m.p && m.avail >= 2) memcpy(m.p, &nul, 2);
            GuestMem mb = guestMem(l, bufferPtr);
            if (mb.p && mb.avail >= 8) memcpy(mb.p, &addr, 8);
            result = n;
        }
        LocalFree(hostBuf);
    }
    FreeLibrary(h);
    return result;
}

static uint64_t apiFormatMessageW(Loaded& l, const uint64_t* args) {
    fprintf(stderr, "TRC FMT flags=%llX src=%llX msgid=%llX lang=%llX buf=%llX n=%llX va=%llX\n",
            (unsigned long long)args[0], (unsigned long long)args[1],
            (unsigned long long)args[2], (unsigned long long)args[3],
            (unsigned long long)args[4], (unsigned long long)args[5],
            (unsigned long long)args[6]);
    const uint64_t flags = args[0], src = args[1], msgId = args[2];
    const uint64_t bufferPtr = args[4], nSize = args[5], vaArgs = args[6];
    constexpr uint64_t kAllocate = 0x100, kFromString = 0x400, kFromHmodule = 0x800;
    if ((flags & kFromString) || !(flags & kFromHmodule)) return 0;

    uint64_t imageBase = src ? src : l.img.base() + 0x320;
    if (imageBase < l.img.base() || imageBase >= l.img.base() + l.img.size()) return 0;
    uint32_t resRva = 0;
    if (!descImage(l, imageBase, resRva) || resRva == 0) {
        // no descriptor: the blob carries a real PE header at rva 0
        imageBase = l.img.base() + 0x320;
        uint32_t peoff = 0;
        if (!imgRead(l, imageBase, 0x3C, &peoff, 4))
            return muiFallback(l, flags, msgId, bufferPtr, vaArgs);
        // PE32+: DataDirectory[2] (resource) at optional header + 0x70
        if (!imgRead(l, imageBase, peoff + 0x18 + 0x70 + 16, &resRva, 4) || resRva == 0)
            return muiFallback(l, flags, msgId, bufferPtr, vaArgs);
    }

    // locate RT_MESSAGETABLE (11) id 1, lang 0x409 then any
    uint32_t typeRel = 0, nameRel = 0, langRel = 0;
    bool dir = false;
    if (!resFind(l, imageBase, resRva, 0, nullptr, 11, typeRel, dir) || !dir)
        return muiFallback(l, flags, msgId, bufferPtr, vaArgs);
    if (!resFind(l, imageBase, resRva, typeRel, nullptr, 1, nameRel, dir) || !dir)
        return muiFallback(l, flags, msgId, bufferPtr, vaArgs);
    if (!resFind(l, imageBase, resRva, nameRel, nullptr, 0x409, langRel, dir) || dir)
        if (!resFirst(l, imageBase, resRva, nameRel, langRel, dir) || dir)
            return muiFallback(l, flags, msgId, bufferPtr, vaArgs);
    uint32_t dataRva = 0;
    if (!imgRead(l, imageBase, resRva + langRel, &dataRva, 4))
        return muiFallback(l, flags, msgId, bufferPtr, vaArgs);

    // MESSAGE_RESOURCE_DATA { DWORD nBlocks; BLOCK blocks[]; }
    // BLOCK { DWORD LowId, HighId, EntriesOffset; }
    // ENTRY { WORD Length, Flags; BYTE text[]; } Flags bit0: 1 = UTF-16
    uint32_t nBlocks = 0;
    if (!imgRead(l, imageBase, dataRva, &nBlocks, 4) || !nBlocks || nBlocks > 64)
        return muiFallback(l, flags, msgId, bufferPtr, vaArgs);
    uint64_t textOff = 0, textLen = 0;
    bool utf16 = false, found = false;
    for (uint32_t b = 0; b < nBlocks && !found; ++b) {
        uint32_t blk[3] = { 0, 0, 0 };
        if (!imgRead(l, imageBase, dataRva + 4 + 12 * b, blk, 12)) break;
        if (msgId < blk[0] || msgId > blk[1]) continue;
        uint64_t off = dataRva + blk[2];
        for (uint32_t id = blk[0]; id <= blk[1]; ++id) {
            uint16_t hdr[2] = { 0, 0 }; // Length, Flags
            if (!imgRead(l, imageBase, off, hdr, 4) || hdr[0] < 4) break;
            if (id == msgId) {
                textOff = off + 4;
                textLen = hdr[0] - 4;
                utf16 = (hdr[1] & 1) != 0;
                found = true;
                break;
            }
            off += hdr[0];
        }
    }
    if (!found) return muiFallback(l, flags, msgId, bufferPtr, vaArgs);

    uint8_t raw[2048];
    if (textLen > sizeof(raw)) textLen = sizeof(raw);
    if (!imgRead(l, imageBase, textOff, raw, textLen))
        return muiFallback(l, flags, msgId, bufferPtr, vaArgs);
    wchar_t msg[1024];
    size_t mlen = 0;
    if (utf16) {
        while (mlen < 1024 && 2 * mlen + 2 <= textLen) {
            uint16_t c;
            memcpy(&c, raw + 2 * mlen, 2);
            msg[mlen++] = static_cast<wchar_t>(c);
        }
    } else {
        for (; mlen < textLen; ++mlen) msg[mlen] = static_cast<wchar_t>(raw[mlen]);
    }

    // substitute inserts: %% -> %, %0 -> end, %N[!fmt!] -> Arguments[N-1]
    wchar_t out[2048];
    size_t olen = 0;
    const auto put = [&](wchar_t c) { if (olen < 2047) out[olen++] = c; };
    for (size_t p = 0; p < mlen;) {
        if (msg[p] != L'%') { put(msg[p++]); continue; }
        if (p + 1 < mlen && msg[p + 1] == L'%') { put(L'%'); p += 2; continue; }
        if (p + 1 < mlen && msg[p + 1] == L'0') break; // %0 terminates
        size_t q = p + 1;
        uint32_t num = 0;
        bool digit = false;
        while (q < mlen && msg[q] >= L'0' && msg[q] <= L'9' && num < 100) {
            num = num * 10 + static_cast<uint32_t>(msg[q] - L'0');
            ++q;
            digit = true;
        }
        if (!digit || num == 0) { put(L'%'); ++p; continue; }
        wchar_t spec = 0;
        if (q < mlen && msg[q] == L'!') {
            size_t r = q + 1;
            while (r < mlen && msg[r] != L'!') ++r;
            if (r < mlen) { spec = msg[q + 1]; q = r + 1; }
        }
        uint64_t val = 0;
        if (!(flags & kIgnoreInserts) && vaArgs) {
            GuestMem m = guestMem(l, vaArgs + 8 * (num - 1));
            if (m.p && m.avail >= 8) memcpy(&val, m.p, 8);
        }
        if (spec == L's' || spec == L'S') {
            if (val) {
                wchar_t s[128];
                const size_t n = guestWideStr(l, val, s, 128);
                for (size_t k = 0; k < n; ++k) put(s[k]);
            }
        } else if (spec == L'c' || spec == L'C') {
            put(static_cast<wchar_t>(val));
        } else if (spec == L'x' || spec == L'X') {
            char nb[16];
            snprintf(nb, sizeof nb, spec == L'x' ? "%x" : "%X",
                     static_cast<uint32_t>(val));
            for (const char* s = nb; *s; ++s) put(static_cast<wchar_t>(*s));
        } else {
            // no spec / d / i / u: decimal of the 32-bit value
            char nb[16];
            snprintf(nb, sizeof nb, "%u", static_cast<uint32_t>(val));
            for (const char* s = nb; *s; ++s) put(static_cast<wchar_t>(*s));
        }
        p = q;
    }

    const size_t chars = olen;
    if (flags & kAllocate) {
        const uint64_t addr = heapAlloc(l, (chars + 1) * sizeof(wchar_t));
        if (!addr) return 0;
        GUEST_WRITE(l, addr, out, chars * sizeof(wchar_t));
        const uint16_t nul = 0;
        GuestMem m = guestMem(l, addr + chars * sizeof(wchar_t));
        if (m.p && m.avail >= 2) memcpy(m.p, &nul, 2);
        GuestMem mb = guestMem(l, bufferPtr);
        if (mb.p && mb.avail >= 8) memcpy(mb.p, &addr, 8);
        return chars;
    }
    if (!bufferPtr || nSize < chars + 1) return 0;
    GUEST_WRITE(l, bufferPtr, out, chars * sizeof(wchar_t));
    const uint16_t nul = 0;
    GuestMem m = guestMem(l, bufferPtr + chars * sizeof(wchar_t));
    if (m.p && m.avail >= 2) memcpy(m.p, &nul, 2);
    return chars;
}

static uint64_t apiBeginThread(Loaded& l, const uint64_t* args) {
    // _beginthreadex(security, stackSize, start, arglist, initflag, thrdaddr).
    // The thread is not run here: runThread is triggered by the first join or
    // wait for it, which keeps the interpreter single-threaded internally.
    if (l.threadCount >= 8) return 0;
    uint64_t stackSize = static_cast<uint64_t>(args[1]);
    if (stackSize < 0x4000) stackSize = 0x40000; // default-ish, generous
    if (stackSize > 0x400000) stackSize = 0x400000;
    ThreadContext& t = l.threads[l.threadCount];
    t = ThreadContext{};
    if (!t.stack.allocate(stackSize, true)) return 0;
    t.handle = 0x400ull + l.threadCount;
    t.entry = args[2];
    t.arg = args[3];
    t.done = false;
    t.exitCode = 0;
    ++l.threadCount;
    if (args[5]) {
        uint32_t id = static_cast<uint32_t>(t.handle);
        GUEST_WRITE(l, args[5], &id, 4);
    }
    return t.handle;
}

static uint64_t apiThrdJoin(Loaded& l, const uint64_t* args) {
    // _Thrd_join(_Thrd_t thr, int* code). _Thrd_t differs per arch: x64 passes a
    // pointer to {Hnd,Id}, x86 passes the 8-byte struct by value on the stack.
    uint64_t handle = args[0];
    uint64_t codePtr = args[1];
    if (l.is64) {
        uint32_t hnd = 0;
        GuestMem m = guestMem(l, args[0]);
        if (m.p && m.avail >= sizeof(void*)) {
            if (sizeof(void*) == 4) memcpy(&hnd, m.p, 4);
            else { uint64_t h64 = 0; memcpy(&h64, m.p, 8); hnd = static_cast<uint32_t>(h64); }
        }
        handle = hnd;
    } else {
        codePtr = args[2];
    }

    // runThread is driven here to keep the interpreter single-threaded internally
    ThreadContext* tc = nullptr;
    for (uint32_t i = 0; i < l.threadCount; ++i)
        if (l.threads[i].handle == handle) { tc = &l.threads[i]; break; }
    if (!tc) return 1; // thrd_error
    if (!tc->done) {
        const uint32_t rc = runThread(l, *tc);
        tc->exitCode = rc;
        tc->done = true;
    }
    if (codePtr) {
        uint32_t code = tc->exitCode;
        GUEST_WRITE(l, codePtr, &code, 4);
    }
    return 0; // thrd_success
}

static uint64_t apiThrdId(Loaded&, const uint64_t*) {
    return 1; // main thread id
}

// stand-ins that hand out data (#argv/env) allocate from the real process
// heap, not the bump-heap: the guest frees these with the native free /
// operator delete (imports resolve natively), which only accepts native heap
// blocks; guest reads/writes on the returned host pointers go through the
// host-page fallback in memLd/memSt
static uint64_t heapAlloc(Loaded& l, uint64_t sz) {
    void* p = HeapAlloc(GetProcessHeap(), 0, static_cast<SIZE_T>(sz));
    return reinterpret_cast<uint64_t>(p);
}

static uint64_t apiCndExit(Loaded&, const uint64_t*) { return 0; }

static uint64_t apiMalloc(Loaded& l, const uint64_t* args) {
    const size_t sz = static_cast<size_t>(args[0]);
    if (!sz) return 0;
    return heapAlloc(l, sz);
}

static uint64_t apiFree(Loaded&, const uint64_t*) { return 0; }

static uint64_t apiCallNewh(Loaded&, const uint64_t*) { return 0; } // no new-handler

static uint64_t apiCrtFail(Loaded& l, const uint64_t*) {
    l.fault = fault_code(Fault::UnsupportedInstruction);
    return 0;
}

// _CxxThrowException(obj, throwInfo): record the throw; the run loop sees
// ehThrow after the call and walks the logged frames instead of returning.
static uint64_t apiEhThrow(Loaded& l, const uint64_t* args) {
    l.ehThrow.active = true;
    l.ehThrow.objEA = args[0];
    l.ehThrow.tiPtr = args[1];
    return 0;
}

// RaiseException(code, flags, nargs, args): SEH form, no ThrowInfo.
static uint64_t apiEhRaise(Loaded& l, const uint64_t* args) {
    l.ehThrow.active = true;
    l.ehThrow.objEA = 0;
    l.ehThrow.tiPtr = 0;
    l.ehThrow.code = args[0];
    l.ehThrow.flags = args[1];
    l.ehThrow.nargs = static_cast<uint32_t>(args[2]);
    l.ehThrow.argsEA = args[3];
    return 0;
}

// CRT startup argv stand-in: real porcelain binaries reach main through the
// full CRT startup, which needs _getmainargs/_wgetmainargs to hand out a
// truthful argv. Guest pointers are host pointers, so the guest writes the
// pointers through the same bumped heap the malloc stand-in uses.
template <class Char> struct ArgvEncoding;

template <> struct ArgvEncoding<char> {
    static constexpr bool kWide = false;
};

template <> struct ArgvEncoding<wchar_t> {
    static constexpr bool kWide = true;
};

// Writes one string into the guest heap, NUL-terminated; returns its guest
// address (0 = heap exhausted).
static uint64_t heapStoreString(Loaded& l, const char* text, bool wide) {
    const size_t rawLen = strlen(text) + 1;
    const size_t bytes = rawLen * (wide ? 2 : 1);
    const uint64_t addr = heapAlloc(l, bytes);
    if (!addr) return 0;
    if (!wide) {
        GUEST_WRITE(l, addr, text, rawLen);
        return addr;
    }
    wchar_t buf[16];
    for (size_t i = 0; i < rawLen && i < 15; ++i) buf[i] = static_cast<wchar_t>(text[i]);
    buf[15] = 0;
    GUEST_WRITE(l, addr, buf, bytes < 32 ? bytes : 32);
    return addr;
}

// Shared argv/env builder for the narrow/wide CRT variants: fills
// *(Argc)=1, *(Argv) = [name, NULL], *(Env) = [NULL] on the guest heap.
template <class Char>
static uint64_t apiGetMainArgsImpl(Loaded& l, const uint64_t* args) {
    fprintf(stderr, "TRC WGAENTER args=%llX,%llX,%llX,%llX\n",
            (unsigned long long)args[0], (unsigned long long)args[1],
            (unsigned long long)args[2], (unsigned long long)args[3]);
    constexpr bool wide = ArgvEncoding<Char>::kWide;
    const uint64_t nameAddr = heapStoreString(l, l.name[0] ? l.name : "ipconfig", wide);
    const uint64_t argvArray = heapAlloc(l, 2 * sizeof(uint64_t));
    const uint64_t envArray = heapAlloc(l, 1 * sizeof(uint64_t));
    if (!nameAddr || !argvArray || !envArray) {
        l.fault = fault_code(Fault::Allocation);
        return 0;
    }
    const uint64_t argcOne = 1;
    const uint64_t envNullTerminator = 0;          // env array already one NULL
    const uint64_t argvArrayEntry[2] = { nameAddr, 0 };
    GUEST_WRITE(l, args[0], &argcOne, sizeof(uint32_t));
    GUEST_WRITE(l, args[1], &argvArray, sizeof(uint64_t));
    GUEST_WRITE(l, args[2], &envArray, sizeof(uint64_t));
    GUEST_WRITE(l, argvArray, argvArrayEntry, sizeof(argvArrayEntry));
    GUEST_WRITE(l, envArray, &envNullTerminator, sizeof(uint64_t));
    fprintf(stderr, "TRC WGA args=%llX,%llX,%llX,%llX argv=%llX name=%llX\n",
            (unsigned long long)args[0], (unsigned long long)args[1],
            (unsigned long long)args[2], (unsigned long long)args[3],
            (unsigned long long)argvArray, (unsigned long long)nameAddr);
    uint32_t argcBack = 0xFFFFFFFF; uint64_t argvBack = 0;
    if (auto gm = guestMem(l, args[0]); gm.p && gm.avail >= 4)
        memcpy(&argcBack, gm.p, 4);
    if (auto gm = guestMem(l, args[1]); gm.p && gm.avail >= 8)
        memcpy(&argvBack, gm.p, 8);
    fprintf(stderr, "TRC WGA back argc=%u argvptr=%llX\n", argcBack, (unsigned long long)argvBack);
    return 0;
}

static uint64_t apiGetMainArgs(Loaded& l, const uint64_t* args) {
    return apiGetMainArgsImpl<char>(l, args);
}

static uint64_t apiWGetMainArgs(Loaded& l, const uint64_t* args) {
    return apiGetMainArgsImpl<wchar_t>(l, args);
}

void registerApiStandins(Loaded& l) {
    initNativeBridge(l);
    const uint32_t B = static_cast<uint32_t>(l.env.base());
    const ApiEntry apis[] = {
        { B + ST_NT_A, 2, false, apiRtlAdd },
        { B + ST_LL_A, 1, false, apiLoadLibraryA },
        { B + ST_GP_A, 2, false, apiGetProcAddress },
        { B + ST_MB_A, 4, false, apiMessageBoxA },
        { B + ST_PRINTF_A, 8, true, apiPrintf }, // cdecl: caller cleans
        { B + ST_SRAND_A, 1, true, apiSrand },
        { B + ST_RAND_A, 0, true, apiRand },
        { B + ST_FIND_RES_A, 3, false, apiFindResourceA },
        { B + ST_SIZE_RES_A, 2, false, apiSizeofResource },
        { B + ST_BEGINT,   6, true, apiBeginThread },
        { B + ST_THRDJOIN, 3, true, apiThrdJoin },
        { B + ST_THRDID,   0, true, apiThrdId },
        { B + ST_CNDEXIT,  0, true, apiCndExit },
        { B + ST_MALLOC,   1, true, apiMalloc },
        { B + ST_FREE,     1, true, apiFree },
        { B + ST_CALLNEWH, 1, true, apiCallNewh },
        { B + ST_CRTFAIL,  2, true, apiCrtFail },
        { B + ST_GSFT,     1, false, apiGetSystemTimeAsFileTime },
        { B + ST_QPC,      1, false, apiQueryPerformanceCounter },
        { B + ST_PID,      0, false, apiGetCurrentProcessId },
        { B + ST_SLIST,    1, false, apiNoOp },
        { B + ST_UEHF,     1, false, apiNoOp },
        { B + ST_SUEH,     1, false, apiNoOp },
        { B + ST_IPP,      1, false, apiNoOp },
        { B + ST_CSH,      4, true,  apiCsh },
        { B + ST_MEMCPY,   3, true,  apiMemcpy },
        { B + ST_CNOP,     0, true,  apiNoOp },
        { B + ST_INITTERM, 2, true,  apiInitterm },
        { B + ST_MEMSET,   3, true,  apiMemset },
        { B + ST_GCURPROC, 1, false, apiGetCurrentProcess },
        { B + ST_TERMPROC, 2, false, apiCrtFail },
        { B + ST_EH4,      4, false, apiCsh },
        { B + ST_THROW,    2, true,  apiEhThrow },
        { B + ST_RAISE,    4, true,  apiEhRaise },
        { B + ST_CXXFRAME4, 4, true, apiCsh },
        { B + ST_CXXFRAME3, 4, true, apiCsh },
        { B + ST_EH3,      4, true,  apiCsh },
        { B + ST_ARGS,     4, true,  apiGetMainArgs },
        { B + ST_WARGS,    4, true,  apiWGetMainArgs },
        { B + ST_MODH,     1, false, apiModuleHandle },
        { B + ST_FMT,      7, false, apiFormatMessageW },
        { B + ST_EXIT,     1, false, apiExit },
        { B + ST_MODFNW,   3, false, apiModuleFileNameW },
        { B + ST_MODFNA,   3, false, apiModuleFileNameA },
    };
    for (const ApiEntry& entry : apis) {
        if (!l.apis.add(entry)) {
            l.fault = fault_code(Fault::UnsupportedInstruction);
            return;
        }
    }
}

#undef GUEST_WRITE

} // namespace stub

