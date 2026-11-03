#include "api_standins.hpp"
#include "guest_environment.hpp"
#include <cstdio>
#include <cstring>

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

// copy `size` bytes to a guest address when the bytes are mapped
#define GUEST_WRITE(l, addr, from, size) do { \
        GuestMem m_ = guestMem((l), (addr)); \
        if (m_.p && m_.avail >= (size)) memcpy(m_.p, (from), (size)); \
    } while (0)

static uint64_t apiLoadLibraryA(Loaded& l, const uint64_t* args) {
    char name[64];
    if (!guestStr(l, args[0], name)) return 0;
    if (nameEq(name, "kernel32.dll") || nameEq(name, "kernelbase.dll")) {
        return l.env.base() + K32_RVA;
    }
    if (nameEq(name, "user32.dll")) return l.env.base() + USER32_RVA;
    if (nameEq(name, "msvcrt.dll")) return l.env.base() + MSVCRT_RVA;
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
    if (args[1] < kOrdinalMax) return 0; // ordinal imports not emulated
    char name[64];
    if (!guestStr(l, args[1], name)) return 0;
    if (nameEq(name, "LoadLibraryA"))  return l.env.base() + ST_LL_A;
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
    // throw helpers are resolved but only a guest raising an exception reaches
    // them; that is not emulated yet, so they fail closed instead of returning
    if (nameEq(name, "_CxxThrowException")) return l.env.base() + ST_CRTFAIL;
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
    if (nameEq(name, "memcpy")) return l.env.base() + ST_MEMCPY;
    if (nameEq(name, "memset")) return l.env.base() + ST_MEMSET;
    if (nameEq(name, "_cexit") ||
        nameEq(name, "_execute_onexit_table") ||
        nameEq(name, "_initialize_onexit_table") ||
        nameEq(name, "_initialize_narrow_environment") ||
        nameEq(name, "_configure_narrow_argv") ||
        nameEq(name, "_seh_filter_dll") ||
        nameEq(name, "__std_type_info_destroy_list") ||
        nameEq(name, "IsDebuggerPresent") ||
        // shortcut: _initterm/_initterm_e skip the paste tables; a test with
        // real C++ static initializers (ctors in __xc_a) will need a run-loop
        // driven version, upgrade in iteration 6 alongside exception tests
        nameEq(name, "_initterm") ||
        nameEq(name, "_initterm_e")) return l.env.base() + ST_CNOP;
    // Rtl unwind/context never legitimately run before exception support;
    // fail closed instead of silently returning zeros
    if (nameEq(name, "RtlCaptureContext") ||
        nameEq(name, "RtlLookupFunctionEntry") ||
        nameEq(name, "RtlVirtualUnwind")) return l.env.base() + ST_CRTFAIL;
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
        l.fault = fault_code(Fault::OutsideMemory);
        return 0;
    }
    memset(dst.p, static_cast<int>(args[1] & 0xFF), n);
    return args[0];
}

// pseudo process handle, (HANDLE)-1
static uint64_t apiGetCurrentProcess(Loaded&, const uint64_t*) { return 0xFFFFFFFFFFFFFFFFull; }

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

// resource stand-ins: the shellcode's own mapped PE image is in guest memory,
// so FindResourceA/SizeofResource walk its real resource directory
static bool imgRead(const Loaded& l, uint64_t off, void* dst, size_t n) {
    if (!l.hasImage) return false;
    const uint64_t avail = l.img.size() > l.pe.image_offset ? l.img.size() - l.pe.image_offset : 0;
    if (off > avail || n > avail - off) return false;
    memcpy(dst, l.img.data() + l.pe.image_offset + off, n);
    return true;
}

static bool resBase(const Loaded& l, uint32_t& out) {
    uint32_t lfanew = 0;
    if (!imgRead(l, 0x3C, &lfanew, 4)) return false;
    uint16_t magic = 0;
    if (!imgRead(l, lfanew + 0x18, &magic, 2)) return false;
    const uint32_t dd = lfanew + 0x18 + (magic == 0x20B ? 0x70 : 0x60);
    return imgRead(l, dd + 16, &out, 4) && out != 0;
}

// directory entry offsets are relative to the resource section base
static bool resFind(const Loaded& l, uint32_t resRva, uint32_t rel, const char* name,
                    uint32_t id, uint32_t& childRel, bool& isDir) {
    uint16_t counts[2] = { 0, 0 };
    if (!imgRead(l, resRva + rel + 12, counts, 4)) return false;
    const uint32_t total = static_cast<uint32_t>(counts[0]) + counts[1];
    for (uint32_t i = 0; i < total; ++i) {
        uint32_t e[2] = { 0, 0 };
        if (!imgRead(l, resRva + rel + 16 + 8 * i, e, 8)) return false;
        bool match = false;
        if (e[0] & 0x80000000u) {
            if (name) {
                const uint32_t nr = resRva + (e[0] & 0x7FFFFFFFu);
                uint16_t len = 0;
                if (!imgRead(l, nr, &len, 2)) continue;
                bool eq = name[len] == '\0';
                for (uint16_t k = 0; k < len && eq; ++k) {
                    uint16_t c = 0;
                    if (!imgRead(l, nr + 2 + 2 * k, &c, 2)) { eq = false; break; }
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

static bool resFirst(const Loaded& l, uint32_t resRva, uint32_t rel, uint32_t& childRel, bool& isDir) {
    uint16_t counts[2] = { 0, 0 };
    if (!imgRead(l, resRva + rel + 12, counts, 4) || counts[0] + counts[1] == 0) return false;
    uint32_t e[2] = { 0, 0 };
    if (!imgRead(l, resRva + rel + 16, e, 8)) return false;
    childRel = e[1] & 0x7FFFFFFFu;
    isDir = (e[1] & 0x80000000u) != 0;
    return true;
}

static uint64_t apiFindResourceA(Loaded& l, const uint64_t* args) {
    // the hosted module is the shellcode's own image; any handle is ignored
    uint32_t res = 0;
    if (!resBase(l, res)) return 0;
    const uint64_t nameArg = args[1], typeArg = args[2];
    uint32_t typeRel = 0, nameRel = 0, langRel = 0;
    bool dir = false;
    if (typeArg < 0x10000u) {
        if (!resFind(l, res, 0, nullptr, static_cast<uint32_t>(typeArg), typeRel, dir) || !dir) return 0;
    } else {
        char tb[64];
        if (!guestStr(l, typeArg, tb) || !resFind(l, res, 0, tb, 0, typeRel, dir) || !dir) return 0;
    }
    if (nameArg < 0x10000u) {
        if (!resFind(l, res, typeRel, nullptr, static_cast<uint32_t>(nameArg), nameRel, dir) || !dir) return 0;
    } else {
        char nb[64];
        if (!guestStr(l, nameArg, nb) || !resFind(l, res, typeRel, nb, 0, nameRel, dir) || !dir) return 0;
    }
    if (!resFind(l, res, nameRel, nullptr, 0x409, langRel, dir) || dir) {
        if (!resFirst(l, res, nameRel, langRel, dir) || dir) return 0; // any language
    }
    // handle = guest address of the data entry, decoded again by SizeofResource
    return l.img.base() + l.pe.image_offset + res + langRel;
}

static uint64_t apiSizeofResource(Loaded& l, const uint64_t* args) {
    const uint64_t imageGuest = l.img.base() + l.pe.image_offset;
    if (args[1] < imageGuest) return 0;
    // IMAGE_RESOURCE_DATA_ENTRY: DataRVA, Size, CodePage, Reserved
    uint32_t size = 0;
    if (!imgRead(l, args[1] - imageGuest + 4, &size, 4)) return 0;
    return size;
}

static uint64_t apiBeginThread(Loaded& l, const uint64_t* args) {
    // _beginthreadex(security, stackSize, start, arglist, initflag, thrdaddr).
    // The thread is not run here: runThread is triggered by the first join or
    // wait for it, which keeps the interpreter single-threaded internally.
    if (l.threadCount >= 8) return 0;
    uint64_t stackSize = static_cast<uint64_t>(args[1]);
    if (stackSize < 0x4000) stackSize = 0x40000; // default-ish, generous
    if (stackSize > 0x400000) stackSize = 0x400000;
    ThreadCtx& t = l.threads[l.threadCount];
    t = ThreadCtx{};
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
    ThreadCtx* tc = nullptr;
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

static uint64_t apiCndExit(Loaded&, const uint64_t*) { return 0; }

static uint64_t apiMalloc(Loaded& l, const uint64_t* args) {
    const size_t sz = static_cast<size_t>(args[0]);
    if (!sz) return 0;
    const uint64_t align = 16;
    const uint64_t base = l.heapNext;
    const uint64_t aligned = (base + align - 1) & ~(align - 1);
    const uint64_t end = aligned + sz;
    if (end > l.heapEnd) return 0;
    l.heapNext = end;
    return aligned;
}

static uint64_t apiFree(Loaded&, const uint64_t*) { return 0; }

static uint64_t apiCallNewh(Loaded&, const uint64_t*) { return 0; } // no new-handler

static uint64_t apiCrtFail(Loaded& l, const uint64_t*) {
    l.fault = fault_code(Fault::UnsupportedInstruction);
    return 0;
}

void registerApiStandins(Loaded& l) {
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
        { B + ST_MEMSET,   3, true,  apiMemset },
        { B + ST_GCURPROC, 1, false, apiGetCurrentProcess },
        { B + ST_TERMPROC, 2, false, apiCrtFail },
        { B + ST_EH4,      4, false, apiCsh },
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
