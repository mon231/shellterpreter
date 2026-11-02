#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace stub {

enum Fault : uint32_t {
    FAULT_NONE          = 0x00000000u,
    FAULT_UNSUPPORTED   = 0xE0000001u,
    FAULT_OOB           = 0xE0000002u,
    FAULT_BAD_FILE      = 0xE0000003u,
    FAULT_ALLOC         = 0xE0000004u,
    FAULT_AUDIT         = 0xE0000005u,
    FAULT_HALT          = 0xE0000006u,
    FAULT_ARCH          = 0xE0000007u,
    FAULT_ARG           = 0xE0000008u,
    FAULT_LIMIT         = 0xE0000009u,
};

constexpr uint64_t kSentinel = 0x0000BAD0C0FFEE10ull;

struct PeInfo {
    uint64_t imageOffset;
    uint32_t entryRva;
    uint32_t imageBase;
    uint32_t sizeOfImage;
};

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

struct Loaded {
    uint8_t* img;
    size_t   imgLen;
    uint64_t imgBase;
    uint8_t* stk;
    size_t   stkLen;
    uint64_t stkBase;
    uint64_t fsBase;
    uint64_t gsBase;
    uint8_t* env;
    size_t   envLen;
    uint64_t envBase;
    ApiEntry apis[8];
    uint32_t apiCount;
    PeInfo   pe;
    bool     is64;
    bool     hasImage;
};

inline const ApiEntry* lookupApi(const Loaded& l, uint64_t ip) {
    for (uint32_t i = 0; i < l.apiCount; ++i)
        if (l.apis[i].addr == ip) return &l.apis[i];
    return nullptr;
}

void freeLoaded(Loaded& l);

// Returns FAULT_BAD_FILE when the file cannot be read or is empty. Detection
// of an embedded PE header is optional; when none is found the buffer starts
// at offset 0 and the caller picks the architecture explicitly.
uint32_t loadShellcode(const std::string& path, Loaded& out, bool force86);

uint32_t run64(Loaded& l);
uint32_t run86(Loaded& l);

std::string faultMessage(uint32_t fault);

}
