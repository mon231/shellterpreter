#pragma once
#include <cstdint>
#include <cstddef>
#include "vm.hpp"

namespace stub {

// Env layout (RVAs from l.env.base()). Nodes are 0x100 apart so both layouts
// overlap: x86 node.DllBase at +0x10, x64 at +0x20.
//   0x100  TEB   (fsBase/gsBase)          0x200  PEB
//   0x300  Ldr                            0x400  chain node1 (head)
//   0x500  chain node2 = ntdll            0x600  chain node3 = kernel32
//   0x800  fake kernel32 image            0x1000 fake ntdll image
//   0xA00  LoadLibraryA stand-in          0xA10  GetProcAddress stand-in
//   0x1010 RtlAdd* stand-in               0x1C00 MessageBoxA stand-in
//   0x1D00 printf stand-in                0x1D10 srand stand-in
//   0x1D20 rand stand-in                  0x1E00 fake msvcrt module handle (no image)
//   0x1D30 FindResourceA stand-in         0x1D40 SizeofResource stand-in
//   0x1D50 _beginthreadex stand-in        0x1D60 _Thrd_join stand-in
//   0x1D70 _Thrd_id stand-in              0x1D80 _Cnd_do_broadcast_at_thread_exit
//   0x1D90 malloc stand-in                0x1DA0 free stand-in
//   0x1DB0 _callnewh stand-in             0x1DC0 fail-closed CRT helper
//   0x1F00 fake CRT/MSVC module handle (ucrt/msvcp/vcruntime/api-set, no image)
//   0x1800 fake user32 module handle (no image; GetProcAddress never walks it)
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
constexpr uint32_t ST_BEGINT   = 0x1D50;
constexpr uint32_t ST_THRDJOIN = 0x1D60;
constexpr uint32_t ST_THRDID   = 0x1D70;
constexpr uint32_t ST_CNDEXIT  = 0x1D80;
constexpr uint32_t ST_MALLOC   = 0x1D90;
constexpr uint32_t ST_FREE     = 0x1DA0;
constexpr uint32_t ST_CALLNEWH = 0x1DB0;
constexpr uint32_t ST_CRTFAIL  = 0x1DC0;
constexpr uint32_t ST_CSH      = 0x1DD0; // __C_specific_handler stub
constexpr uint32_t ST_MEMCPY   = 0x1DE0;
constexpr uint32_t ST_CNOP     = 0x1DF0; // shared cdecl no-op (uCRT startup)
constexpr uint32_t ST_MEMSET   = 0x1DF8;
constexpr uint32_t ST_GCURPROC = 0x1E00; // GetCurrentProcess
constexpr uint32_t ST_TERMPROC = 0x1E08; // TerminateProcess
constexpr uint32_t ST_EH4      = 0x1E10; // _except_handler4_common
// kernel32 slack (no export data below 0x1000): CRT-startup API stand-ins
constexpr uint32_t ST_GSFT   = 0xC00; // GetSystemTimeAsFileTime
constexpr uint32_t ST_QPC    = 0xC10; // QueryPerformanceCounter
constexpr uint32_t ST_PID    = 0xC20; // GetCurrentProcessId
constexpr uint32_t ST_SLIST  = 0xC30; // InitializeSListHead
constexpr uint32_t ST_UEHF   = 0xC40; // UnhandledExceptionFilter
constexpr uint32_t ST_SUEH   = 0xC50; // SetUnhandledExceptionFilter
constexpr uint32_t ST_IPP    = 0xC60; // IsProcessorFeaturePresent
constexpr uint32_t MSVCRT_RVA  = 0x1E00;
constexpr uint32_t CRTRT_RVA   = 0x1F00;

// Guest memory view over any mapped guest region (image, stack, env, heap and
// each thread's own stack). Returns a host pointer and the bytes remaining
// from addr to the end of that region; null if addr is outside guest memory.
struct GuestMem { uint8_t* p; size_t avail; };

GuestMem guestMem(const Loaded& l, uint64_t addr);
bool guestStr(const Loaded& l, uint64_t addr, char out[64]);

// Fake TEB/PEB/Ldr/module environment, fake kernel32/ntdll images, env+heap
// region allocation. The stand-in registry itself lives in ApiTable
// (api_standins.cpp registers the entries).
uint32_t buildFakeEnv(Loaded& l);

} // namespace stub
