#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "fault.hpp"
#include "guest_region.hpp"
#include "api_table.hpp"

// Whole-memory helper (batch D): accepts any committed host page; reads on
// readable pages only, writes on writable pages only (code pages stay RO:
// every write outside the guest regions fails closed with 0xE0000002).
// Defined in native_bridge.cpp; stand-ins use it for pointers the guest
// obtained from native APIs (e.g. real HeapAlloc handles).
bool hostPageAddr(uint64_t addr, uint64_t size, bool forWrite, uint8_t*& p);

namespace stub {


constexpr uint32_t kEhLogMax = 128;


constexpr uint64_t kSentinel = 0x0000BAD0C0FFEE10ull;
// sub-run sentinel: address the EH dispatch pushes as the funclet's return
// address; runLoop resumes the pending catch when the funclet's ret pops it
constexpr uint64_t kSentinelSub = 0x0000BAD0C0FFEE20ull;

// One logged guest call for the EH unwinder: a return address pushed by a
// real call plus the rsp slot it lives in (est frame rsp = rspEntry + 8).
struct EhCallFrame {
    uint64_t ret;
    uint64_t rspEntry;
    uint64_t rbp;   // caller's rbp at the call site = frame rbp after unwind
};

// Native throw recorded by the _CxxThrowException/RaiseException stand-ins;
// the interpreter-driven EH dispatch walks the logged call frames instead of
// returning to the throw site.
struct EhThrow {
    bool active = false;
    uint64_t objEA = 0;   // guest ptr of the thrown object (rcx at throw)
    uint64_t tiPtr = 0;   // guest ptr of ThrowInfo (rdx at throw)
    // SEH form (tiPtr == 0): RaiseException parameters
    uint64_t code = 0;
    uint64_t flags = 0;
    uint32_t nargs = 0;
    uint64_t argsEA = 0;  // guest ptr of the exception args array
};

// Pending catch: state saved while the catch/except funclet runs. The
// funclet's ret pops kSentinelSub and the run loop resumes here.
struct EhPending {
    bool active = false;
    int  mode = 0;             // 1 = C++ catch resume, 2 = SEH filter result pending
    uint64_t estRsp = 0;       // establisher frame rsp the funclet returns to
    uint64_t contBase = 0;     // owner frame's function start (kind-1 conts are relative to it)
    uint64_t contVals[2] = {0, 0}; // continuation addresses (function-relative)
    int contKind = -1;         // HandlerTypeHeader::contAddr kind: 0 none, 1 one address
    uint32_t logMark = 0;      // ehLogCount at dispatch; restored when the funclet returns
    uint32_t walkFrame = 0;    // walk resume state for SEH filters
    uint32_t walkIdx = 0;
};


// One emulated guest thread. A stand-in creates it and the join stand-in runs
// the entry function on its own stack (see runThread).
struct ThreadContext {
    uint64_t handle;
    uint64_t entry;
    uint64_t arg;
    GuestRegion stack;
    uint32_t exitCode;
    bool     done;
};

// Batch D: whitelisted real system module (kernel32/user32/ntdll/...):
// guest call/jmp into the range runs a native bridge stub (native_bridge).
struct ModuleRange {
    uint64_t base = 0;
    uint64_t end = 0;
};

struct Loaded {
    // real system module helper: the module a name-based stand-in resolves to
    // when the imported DLL is an api-set shim. realMods are filled in the
    // kNativeModuleNames order: index 0 = kernel32, index 1 = kernelbase.
    // Kernelbase implements the core api-set share; falls back to kernel32.
    uint64_t realKbase() const {
        if (realModCount > 1) return realMods[1].base;
        if (realModCount > 0) return realMods[0].base;
        return 0;
    }

    GuestRegion img;   // the whole mapped blob: image bytes + header + slack
    GuestRegion stk;
    GuestRegion env;
    GuestRegion heap;
    ModuleRange realMods[32];
    uint32_t realModCount = 0;
    uint64_t fsBase;
    uint64_t gsBase;
    // blob name: filename stem, reported by the stand-ins as the guest's own
    // module name (argv[0], module file name, MUI paths)
    char name[32] = {};
    uint64_t heapNext;  // bump allocator cursor inside heap
    uint64_t heapEnd;
    ApiTable apis;
    ThreadContext threads[8];
    uint32_t threadCount;
    uint32_t fault; // stand-in sets this to fail closed
    // stand-in asks the dispatch loop to continue execution here instead of
    // returning (apiInitterm trampoline); cleared once consumed
    uint64_t tailJump = 0;
    // iteration 6: guest exception machinery state
    EhCallFrame ehLog[kEhLogMax];
    uint32_t ehLogCount = 0;
    EhThrow ehThrow;
    EhPending eh;
    bool     is64;
    // x64 host: ntdll Nt* syscall table, per-run (rebuilt by initNativeBridge);
    // was process-global gSys/gSysCount
    uint32_t sysNum[2048] = {};
    void*    sysFn[2048] = {};
    uint32_t sysCount = 0;
    // rand/srand LCG seed, per-run (was file-static gRandSeed)
    uint64_t randSeed = 0;
};

// Returns fault_code(Fault::BadFile) when the file cannot be read or is empty.
// The blob is opaque: it is mapped verbatim, execution starts at offset 0 and
// the architecture comes from the caller (--x86/--x64, default = this build).
uint32_t loadShellcode(const std::string& path, Loaded& out, bool force86);

uint32_t run64(Loaded& l);
uint32_t run86(Loaded& l);

// Run a thread's guest entry on its own stack until it returns.
// Semantics are join-driven: the thread runs at the first join/wait for it.
uint32_t runThread(Loaded& l, ThreadContext& t);
uint32_t runThread64(Loaded& l, ThreadContext& t);
uint32_t runThread86(Loaded& l, ThreadContext& t);

}

