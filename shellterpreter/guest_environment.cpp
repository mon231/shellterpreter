#include "guest_environment.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>

namespace stub {

static GuestMem guestMemHit(const GuestRegion& region, uint64_t addr, size_t n) {
    if (region.empty() || addr < region.base() || addr - region.base() >= region.size())
        return { nullptr, 0 };
    const size_t off = static_cast<size_t>(addr - region.base());
    if (off + n > region.size()) return { nullptr, 0 };
    return { region.data() + off, static_cast<size_t>(region.size() - off) };
}

GuestMem guestMem(const Loaded& l, uint64_t addr) {
    if (auto m = guestMemHit(l.img, addr, 1); m.p) return m;
    if (auto m = guestMemHit(l.stk, addr, 1); m.p) return m;
    if (auto m = guestMemHit(l.env, addr, 1); m.p) return m;
    if (auto m = guestMemHit(l.heap, addr, 1); m.p) return m;
    for (uint32_t i = 0; i < l.threadCount; ++i) {
        if (auto m = guestMemHit(l.threads[i].stack, addr, 1); m.p) return m;
    }
    return { nullptr, 0 };
}

bool guestStr(const Loaded& l, uint64_t addr, char out[64]) {
    GuestMem m = guestMem(l, addr);
    if (!m.p) return false;
    size_t n = 0;
    while (n < 63 && n < m.avail) {
        const char c = static_cast<char>(m.p[n]);
        out[n] = c;
        if (c == '\0') return true;
        ++n;
    }
    out[63] = '\0';
    return true;
}

uint32_t buildFakeEnv(Loaded& l) {
    constexpr uint64_t kEnvSize = 0x2000;
    if (!l.env.allocate(kEnvSize, true)) return fault_code(Fault::Allocation);
    uint8_t* m = l.env.data();
    auto put32 = [m](uint32_t off, uint32_t v) { memcpy(m + off, &v, 4); };
    auto put16 = [m](uint32_t off, uint16_t v) { memcpy(m + off, &v, 2); };
    const uint32_t B = static_cast<uint32_t>(l.env.base());
    l.fsBase = l.env.base() + 0x100;
    l.gsBase = l.env.base() + 0x100;

    // guest heap: bump allocator for std::thread's operator new (malloc) and
    // any other dynamic allocation; freed only on process exit
    if (!l.heap.allocate(0x100000, true)) return fault_code(Fault::Allocation);
    l.heapNext = l.heap.base();
    l.heapEnd = l.heapNext + 0x100000;
    l.threadCount = 0;
    l.fault = fault_code(Fault::None);

    // module chain: head -> ntdll (node2) -> kernel32 (node3)
    put32(0x400, B + 0x500);
    put32(0x500, B + 0x600);
    put32(0x510, B + NTDLL_RVA);  // node2 DllBase, x86 LDR entry
    put32(0x520, B + NTDLL_RVA);  // node2 DllBase, x64 LDR entry
    put32(0x610, B + K32_RVA);    // node3 DllBase, x86
    put32(0x620, B + K32_RVA);    // node3 DllBase, x64

    // fake kernel32 image: stubs read the export directory through the PE
    // header at [img.base()+0x3C]; x86 dir RVA at pehdr+0x78, x64 at +0x88
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
        put32(0x130, B + 0x100);            // TEB+0x30 = TEB Self (x64 gs:[0x30])
        put32(0x160, B + 0x200);            // TEB+0x60 = PEB (x64 peb walk at gs:[0x60])
        put32(0x218, B + 0x300);            // PEB+0x18 = Ldr
        put32(0x320, B + 0x400);            // Ldr+0x20 = InMemoryOrderModuleList.Flink
        memcpy(m + 0x1280, "RtlAddFunctionTable", 20);
    } else {
        put32(0x118, B + 0x100);            // TEB+0x18 = TEB Self (x86 fs:[0x18])
        put32(0x130, B + 0x200);            // TEB+0x30 = PEB (x86 fs:[0x30])
        put32(0x20C, B + 0x300);            // PEB+0x0C = Ldr (absolute)
        put32(0x314, B + 0x400);            // Ldr+0x14 = InMemoryOrderModuleList.Flink
        memcpy(m + 0x1280, "RtlAddVectoredExceptionHandler", 31);
    }

    return fault_code(Fault::None);
}

} // namespace stub
