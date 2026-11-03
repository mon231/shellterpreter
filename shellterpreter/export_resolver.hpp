#pragma once
#include "vm.hpp"

namespace stub {

// Builds the fake TEB/PEB/Ldr/module environment, the fake kernel32/ntdll
// images and the registry of compiled-in API stand-ins (LoadLibraryA,
// GetProcAddress, MessageBoxA, RtlAdd{VectoredExceptionHandler,FunctionTable}).
uint32_t buildFakeEnv(Loaded& l);

} // namespace stub
