#include "cpu.hpp"
#include <cstdlib>

namespace stub {

// Per-run instruction cap override. SHELLTERP_BUDGET names a decimal integer;
// anything unreadable, empty, or zero falls back to the built-in default.
uint64_t instructionBudget() {
    char buf[64] = {};
    const DWORD n = GetEnvironmentVariableA("SHELLTERP_BUDGET", buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf)) {
        char* end = nullptr;
        const unsigned long long v = strtoull(buf, &end, 10);
        if (end != buf && v != 0) return static_cast<uint64_t>(v);
    }
    return kInstrBudget;
}

// One CPU instance per architecture.
template class Cpu<Architecture::X64>;
template class Cpu<Architecture::X86>;

uint32_t run64(Loaded& l) { return Cpu<Architecture::X64>::runMain(l); }
uint32_t run86(Loaded& l) { return Cpu<Architecture::X86>::runMain(l); }

uint32_t runThread64(Loaded& l, ThreadCtx& t) { return Cpu<Architecture::X64>::runThread(l, t); }
uint32_t runThread86(Loaded& l, ThreadCtx& t) { return Cpu<Architecture::X86>::runThread(l, t); }

uint32_t runThread(Loaded& l, ThreadCtx& t) {
    if (l.is64) return runThread64(l, t);
    return runThread86(l, t);
}

} // namespace stub
