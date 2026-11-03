#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "fault.hpp"
#include "pe_reader.hpp"
#include "guest_region.hpp"

namespace stub {


constexpr uint64_t kSentinel = 0x0000BAD0C0FFEE10ull;


// Native stand-in registered by the loader. nargs counts the call-site
// arguments (x64 keeps the first 4); the run loop intercepts ip == addr,
// gathers args via the calling convention and returns fn() in RAX/EAX.
// x86 uses stdcall (callee pops ret+nargs); x64 caller cleans.
struct Loaded;
struct ApiEntry {
    uint64_t addr;
    int      nargs;
    // false (default): x86 stdcall, callee pops ret+nargs
    bool     callerCleans; // x86 cdecl (printf etc): caller pops ret only
    uint64_t (*fn)(Loaded&, const uint64_t* args);
};

// One emulated guest thread. A stand-in creates it and the join stand-in runs
// the entry function on its own stack (see runThread).
struct ThreadCtx {
    uint64_t handle;
    uint64_t entry;
    uint64_t arg;
    GuestRegion stack;
    uint32_t exitCode;
    bool     done;
};

struct Loaded {
    GuestRegion img;   // the whole mapped blob: image bytes + header + slack
    GuestRegion stk;
    GuestRegion env;
    GuestRegion heap;
    uint64_t fsBase;
    uint64_t gsBase;
    uint64_t heapNext;  // bump allocator cursor inside heap
    uint64_t heapEnd;
    ApiEntry apis[32];
    uint32_t apiCount;
    ThreadCtx threads[8];
    uint32_t threadCount;
    uint32_t fault; // stand-in sets this to fail closed
    PeInfo   pe;
    bool     is64;
    bool     hasImage;
};

inline const ApiEntry* lookupApi(const Loaded& l, uint64_t ip) {
    for (uint32_t i = 0; i < l.apiCount; ++i)
        if (l.apis[i].addr == ip) return &l.apis[i];
    return nullptr;
}

// Returns fault_code(Fault::BadFile) when the file cannot be read or is empty. Detection
// of an embedded PE header is optional; when none is found the buffer starts
// at offset 0 and the caller picks the architecture explicitly.
uint32_t loadShellcode(const std::string& path, Loaded& out, bool force86);

uint32_t run64(Loaded& l);
uint32_t run86(Loaded& l);

// Run a thread's guest entry on its own stack until it returns.
// Semantics are join-driven: the thread runs at the first join/wait for it.
uint32_t runThread(Loaded& l, ThreadCtx& t);
uint32_t runThread64(Loaded& l, ThreadCtx& t);
uint32_t runThread86(Loaded& l, ThreadCtx& t);

}
