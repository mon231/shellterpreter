#pragma once
#include <cstdint>

namespace stub {

struct Loaded;

// Batch D: emulated code may call REAL functions of the resident system
// modules (kernel32/user32/ntdll/...). The registry records base/size of
// whitelisted modules; a guest call/jmp/sycall into that range runs a bridge
// stub that marshals the emulated registers to the native ABI and writes
// the return value back. Whole-memory guest access covers the real pages.

// Whitelisted real system modules; registerModules fills realMods in this
// order. The first six are the interpreter's candidates — everything after
// them is what real porcelain binaries import for their working set
// (ipconfig needs iphlpapi/ws2_32/dnsapi/nsi/dhcpcsvc*, and its static CRT
// surface resolves through the real msvcrt export table); preloading them
// before the exec-audit snapshot keeps the audit from seeing new exec pages.
// The trailing winsock namespace/transport providers load inside real
// WSAStartup (socket calls enumerate the Winsock catalog), which would create
// new exec regions after the snapshot; preloading them keeps hostname-type
// binaries audit-clean (batch H task 5b).
extern const char* const kNativeModuleNames[24];

// True when addr lies inside one of the whitelisted native modules.
bool isNativeModuleAddr(const Loaded& l, uint64_t addr);

// x64 host only: call the native function with MS x64 ABI; args 1..16.
// Returns false when a structured exception escaped the callee.
bool callNativeWin64(uint64_t fn, const uint64_t args[16], uint64_t& out);

// x86 host only: stdcall bridge; nargsOut gets the callee's own cleanup
// count (measured from the stack delta, in dwords).
bool callNativeWin86(uint64_t fn, const uint32_t args[16], uint32_t& out, uint32_t& nargs);

// One-time init: register system modules in Loaded and build the x64
// syscall-number table (ntdll Nt* stub prologues). Safe to skip pieces.
void initNativeBridge(Loaded& l);

// x64 host only: the native Nt* function for a syscall number, nullptr if unknown.
void* syscallFnFor(const Loaded& l, uint32_t sysno);

} // namespace stub
