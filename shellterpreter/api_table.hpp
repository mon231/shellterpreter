#pragma once
#include <cstdint>

namespace stub {

struct Loaded;

// Native stand-in registered for one guest import. nargs counts the call-site
// arguments (x64 keeps the first 4); the run loop intercepts ip == addr,
// gathers args via the calling convention and returns fn() in RAX/EAX.
// x86 uses stdcall (callee pops ret+nargs); x64 caller cleans.
struct ApiEntry {
    uint64_t addr;
    int      nargs;
    // false (default): x86 stdcall, callee pops ret+nargs
    bool     callerCleans; // x86 cdecl (printf etc): caller pops ret only
    uint64_t (*fn)(Loaded&, const uint64_t* args);
};

// Checked registry of the compiled-in API stand-ins. add keeps the count
// real and refuses entries past the fixed capacity; find is the point the
// run loops call before every guest step.
class ApiTable {
public:
    static constexpr uint32_t max_entries = 32;

    bool add(const ApiEntry& entry);
    const ApiEntry* find(uint64_t addr) const;

private:
    ApiEntry _entries[max_entries] = {};
    uint32_t _count = 0;
};

} // namespace stub
