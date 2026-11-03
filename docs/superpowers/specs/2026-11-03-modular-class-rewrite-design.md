# Modular class rewrite - design

Approved by user in chat: incremental, pytest green each step; module map
chosen from the proposal (below).

## Intent

Rewrite shellterpreter to the conventions in CONTRIBUTING.md (no
namespaces, no inline, RAII classes with private fields `_`-prefixed,
snake_case full names, std::variant/std::unique_ptr, template core,
least duplication) without changing behavior: the pytest suite (26
tests, Release AND Debug) stays green after every step, and each step
is one commit.

## Module map (one class per file, files snake_case)

- `fault.hpp/cpp` - Fault enum, fault_message()
- `shellcode_file.hpp/cpp` - class ShellcodeFile: RAII file read
  (replaces raw fread path in main), full buffer + size
- `pe_reader.hpp/cpp` - class PeReader/PeInfo: MZ/PE scan, is_dll,
  image_offset, entry_rva (replaces the loader scan inside loadShellcode)
- `guest_region.hpp/cpp` - class GuestRegion: RAII VirtualAlloc/
  VirtualFree (rules of 3/5), used by image/stack/env/heap
- `guest_environment.hpp/cpp` - TEB/PEB/Ldr/mock-kernel32 layout writer
- `api_table.hpp/cpp` + `api_standins.hpp/cpp` - ApiEntry/ApiTable,
  stand-in functions grouped by topic
- `cpu_state.hpp` - Emu state class (registers, flags class Flags,
  xmm store)
- `operand.hpp/cpp` - Operand as std::variant (replaces OpRm) +
  InstructionDecoder
- `cpu.hpp/cpp` - template class Cpu<Architecture> running the loop;
  Architecture64 / Architecture86 config classes replace vm64/vm86
  (per-arch fetch/regs ea rules are config, shared logic once)
- `thread.hpp/cpp` - ThreadContext
- `audit.hpp/cpp` - RAII page snapshot + verify_no_new_exec
- `main.cpp` - CLI entry only

## Steps (each ends: builds all 4 configs, pytest Release+Debug, commit)

1. fault module 2. ShellcodeFile + PeReader 3. GuestRegion +
   GuestEnvironment 4. ApiTable/ApiStandins 5. Operand/decoder via
   std::variant 6. Cpu<Architecture> template absorbing vm64/vm86
   (sub-steps: decode first, then execute) 7. thread/audit/main sweep,
   old files deleted.

Behavior never changes: fault codes, exit = low32(RAX), RW-only audit,
fail-closed stand-ins.
