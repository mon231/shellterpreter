#include "export_resolver.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>

namespace stub {

// Env layout (RVAs from l.envBase). Nodes are 0x100 apart so both layouts
// overlap: x86 node.DllBase at +0x10, x64 at +0x20.
//   0x100  TEB   (fsBase/gsBase)          0x200  PEB
//   0x300  Ldr                            0x400  chain node1 (head)
//   0x500  chain node2 = ntdll            0x600  chain node3 = kernel32
//   0x800  fake kernel32 image            0x1000 fake ntdll image
//   0xA00  LoadLibraryA stand-in          0xA10  GetProcAddress stand-in
//   0x1010 RtlAdd* stand-in               0x1C00 MessageBoxA stand-in
//   0x1D00 printf stand-in                0x1D10 srand stand-in
//   0x1D20 rand stand-in                  0x1E00 fake msvcrt module handle (no image)
//   0x1800 fake user32 module handle (no image; GetProcAddress never walks it)
namespace {
constexpr uint32_t K32_RVA    = 0x800;
constexpr uint32_t USER32_RVA = 0x1800;
constexpr uint32_t NTDLL_RVA  = 0x1000;
constexpr uint32_t ST_LL_A    = 0xA00;
constexpr uint32_t ST_GP_A    = 0xA10;
constexpr uint32_t ST_MB_A    = 0x1C00;
constexpr uint32_t ST_NT_A    = 0x1010;
constexpr uint32_t ST_PRINTF_A = 0x1D00;
constexpr uint32_t ST_SRAND_A  = 0x1D10;
constexpr uint32_t ST_RAND_A   = 0x1D20;
constexpr uint32_t ST_FIND_RES_A = 0x1D30;
constexpr uint32_t ST_SIZE_RES_A = 0x1D40;
constexpr uint32_t MSVCRT_RVA  = 0x1E00;
}

void* allocLow(size_t sz) {
    // x86 core addresses everything through 32-bit registers/pointers; keep all
    // regions below 4 GB even in a 64-bit process
    for (uintptr_t a = 0x10000; a < 0x80000000ull; a += 0x10000) {
        void* p = VirtualAlloc(reinterpret_cast<void*>(a), sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p) return p;
    }
    return VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

// Guest string read: shellcode data may live in the image, stack or env; the
// first NUL ends the name. Returns false if addr is outside guest memory.
static bool guestStr(const Loaded& l, uint64_t addr, char out[64]) {
    uint64_t lo = 0, hi = 0;
    const uint8_t* src = nullptr;
    if (addr >= l.imgBase && addr < l.imgBase + l.imgLen) {
        src = l.img + (addr - l.imgBase); lo = l.imgBase; hi = l.imgBase + l.imgLen;
    } else if (addr >= l.envBase && addr < l.envBase + l.envLen) {
        src = l.env + (addr - l.envBase); lo = l.envBase; hi = l.envBase + l.envLen;
    } else if (addr >= l.stkBase && addr < l.stkBase + l.stkLen) {
        src = l.stk + (addr - l.stkBase); lo = l.stkBase; hi = l.stkBase + l.stkLen;
    } else {
        return false;
    }
    size_t n = 0;
    while (n < 63 && (addr + n) < hi) {
        const char c = static_cast<char>(src[n]);
        out[n] = c;
        if (c == '\0') return true;
        ++n;
    }
    out[63] = '\0';
    return true;
}

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
// ordinal; name pointers are absolute and >= imgBase (>= 0x10000 by allocLow)
static const uint64_t kOrdinalMax = 0x10000ull;

static uint64_t apiLoadLibraryA(Loaded& l, const uint64_t* args) {
    char name[64];
    if (!guestStr(l, args[0], name)) return 0;
    if (nameEq(name, "kernel32.dll") || nameEq(name, "kernelbase.dll")) {
        return l.envBase + K32_RVA;
    }
    if (nameEq(name, "user32.dll")) return l.envBase + USER32_RVA;
    if (nameEq(name, "msvcrt.dll")) return l.envBase + MSVCRT_RVA;
    return 0;
}

static uint64_t apiGetProcAddress(Loaded& l, const uint64_t* args) {
    if (args[1] < kOrdinalMax) return 0; // ordinal imports not emulated
    char name[64];
    if (!guestStr(l, args[1], name)) return 0;
    if (nameEq(name, "LoadLibraryA"))  return l.envBase + ST_LL_A;
    if (nameEq(name, "GetProcAddress")) return l.envBase + ST_GP_A;
    if (nameEq(name, "MessageBoxA"))   return l.envBase + ST_MB_A;
    if (nameEq(name, "printf"))        return l.envBase + ST_PRINTF_A;
    if (nameEq(name, "srand"))         return l.envBase + ST_SRAND_A;
    if (nameEq(name, "rand"))          return l.envBase + ST_RAND_A;
    if (nameEq(name, "FindResourceA")) return l.envBase + ST_FIND_RES_A;
    if (nameEq(name, "SizeofResource")) return l.envBase + ST_SIZE_RES_A;
    return 0;
}

static uint64_t apiMessageBoxA(Loaded&, const uint64_t*) { return 1; } // IDOK

static uint64_t apiRtlAdd(Loaded&, const uint64_t*) { return 1; } // handler registered

// rand/srand: classic MSVCRT LCG, shared static seed
namespace {
uint64_t gRandSeed = 0;
}

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
        // fit below 4 GB (allocLow keeps every region under 0x80000000)
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
    const uint64_t avail = l.imgLen > l.pe.imageOffset ? l.imgLen - l.pe.imageOffset : 0;
    if (off > avail || n > avail - off) return false;
    memcpy(dst, l.img + l.pe.imageOffset + off, n);
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
    return l.imgBase + l.pe.imageOffset + res + langRel;
}

static uint64_t apiSizeofResource(Loaded& l, const uint64_t* args) {
    const uint64_t imageGuest = l.imgBase + l.pe.imageOffset;
    if (args[1] < imageGuest) return 0;
    // IMAGE_RESOURCE_DATA_ENTRY: DataRVA, Size, CodePage, Reserved
    uint32_t size = 0;
    if (!imgRead(l, args[1] - imageGuest + 4, &size, 4)) return 0;
    return size;
}

uint32_t buildFakeEnv(Loaded& l) {
    constexpr size_t kEnv = 0x2000;
    void* p = allocLow(kEnv);
    if (!p) return FAULT_ALLOC;
    uint8_t* m = static_cast<uint8_t*>(p);
    l.env = m;
    l.envLen = kEnv;
    l.envBase = reinterpret_cast<uint64_t>(m);
    auto put32 = [m](uint32_t off, uint32_t v) { memcpy(m + off, &v, 4); };
    auto put16 = [m](uint32_t off, uint16_t v) { memcpy(m + off, &v, 2); };
    const uint32_t B = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m));
    l.fsBase = l.envBase + 0x100;
    l.gsBase = l.envBase + 0x100;

    // module chain: head -> ntdll (node2) -> kernel32 (node3)
    put32(0x400, B + 0x500);
    put32(0x500, B + 0x600);
    put32(0x510, B + NTDLL_RVA);  // node2 DllBase, x86 LDR entry
    put32(0x520, B + NTDLL_RVA);  // node2 DllBase, x64 LDR entry
    put32(0x610, B + K32_RVA);    // node3 DllBase, x86
    put32(0x620, B + K32_RVA);    // node3 DllBase, x64

    // fake kernel32 image: stubs read the export directory through the PE
    // header at [imgBase+0x3C]; x86 dir RVA at pehdr+0x78, x64 at +0x88
    m[K32_RVA] = 'M'; m[K32_RVA + 1] = 'Z';
    put32(K32_RVA + 0x3C, 0x40);
    m[K32_RVA + 0x40] = 'P'; m[K32_RVA + 0x41] = 'E'; m[K32_RVA + 0x42] = 0; m[K32_RVA + 0x43] = 0;
    put32(K32_RVA + 0x40 + 0x78, 0x100);    // x86 export dir RVA (PE hdr + 0x78)
    put32(K32_RVA + 0x40 + 0x88, 0x100);    // x64 export dir RVA (PE hdr + 0x88)
    // export directory at image RVA 0x100 -> env 0x900
    put32(0x918, 2);                        // NumberOfNames
    put32(0x91C, 0x140);                    // AddressOfFunctions
    put32(0x920, 0x150);                    // AddressOfNames
    put32(0x924, 0x160);                    // AddressOfNameOrdinals
    put32(0x940, 0x200);                    // function[0] = LoadLibraryA stand-in
    put32(0x944, 0x210);                    // function[1] = GetProcAddress stand-in
    put32(0x950, 0x1A0);                    // names[0] RVA
    put32(0x954, 0x1B0);                    // names[1] RVA
    put16(0x960, 0);                        // ordinal[0]
    put16(0x962, 1);                        // ordinal[1]
    memcpy(m + 0x9A0, "LoadLibraryA", 13);
    memcpy(m + 0x9B0, "GetProcAddress", 15);

    // fake ntdll image: one export, resolved by the registrar stubs
    m[NTDLL_RVA] = 'M'; m[NTDLL_RVA + 1] = 'Z';
    put32(NTDLL_RVA + 0x3C, 0x40);
    m[NTDLL_RVA + 0x40] = 'P'; m[NTDLL_RVA + 0x41] = 'E'; m[NTDLL_RVA + 0x42] = 0; m[NTDLL_RVA + 0x43] = 0;
    put32(NTDLL_RVA + 0x40 + 0x78, 0x200);  // x86 export dir RVA (PE hdr + 0x78)
    put32(NTDLL_RVA + 0x40 + 0x88, 0x200);  // x64 export dir RVA (PE hdr + 0x88)
    // export directory at image RVA 0x200 -> env 0x1200
    put32(0x1218, 1);                       // NumberOfNames
    put32(0x121C, 0x240);                   // AddressOfFunctions
    put32(0x1220, 0x250);                   // AddressOfNames
    put32(0x1224, 0x248);                   // AddressOfNameOrdinals
    put32(0x1240, 0x10);                    // function[0] RVA = RtlAdd* stand-in
    put16(0x1248, 0);                       // ordinal[0]
    put32(0x1250, 0x280);                   // names[0] RVA
    if (l.is64) {
        put32(0x160, B + 0x200);            // TEB+0x60 = PEB (x64 peb walk at gs:[0x60])
        put32(0x218, B + 0x300);            // PEB+0x18 = Ldr
        put32(0x320, B + 0x400);            // Ldr+0x20 = InMemoryOrderModuleList.Flink
        memcpy(m + 0x1280, "RtlAddFunctionTable", 20);
    } else {
        put32(0x130, B + 0x200);            // TEB+0x30 = PEB (x86 fs:[0x30])
        put32(0x20C, B + 0x300);            // PEB+0x0C = Ldr (absolute)
        put32(0x314, B + 0x400);            // Ldr+0x14 = InMemoryOrderModuleList.Flink
        memcpy(m + 0x1280, "RtlAddVectoredExceptionHandler", 31);
    }

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
    };
    l.apiCount = static_cast<uint32_t>(sizeof(apis) / sizeof(apis[0]));
    memcpy(l.apis, apis, sizeof(apis));
    return FAULT_NONE;
}

} // namespace stub
