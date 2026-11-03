# shellterpreter — PLAN (single file: implemented / to implement / keynotes)

C++ Windows shellcode interpreter. Reads shellcode from a file into one
`PAGE_READWRITE` allocation, emulates it instruction by instruction, sets the
process exit code to low 32 bits of RAX/EAX. Scope: position-independent raw
binary starting at offset 0 with a return address on the stack; peor output is
only the test corpus. An embedded `MZ`/`PE` header is used for architecture
detection (and DllMain entry shape), never required.

## User decisions

- ISA/ABI: Windows, x86 + x64; the x64 interpreter runs both, the x86 build runs x86 only (`0xE0000007` otherwise).
- Coverage: growable common subset; unknown instruction → fail closed, never guessed.
- Toolchain: VS solution + vcxproj all 4 configs (Release/Debug x x64/Win32), pytest gate, peor is test-pipeline-only.
- Threads (`std::thread`) and multiple exception types are hard requirements; stand-ins take parameters from interpreter-owned state, not guest register shuffling.
- Development proceeds test-first, iteration by iteration, each feature with tests + commit.

## Exit-code contract

| Code | Meaning |
|---|---|
| `0x00000000..0xDFFFFFFF` | low 32 bits of returned RAX/EAX |
| `0xE0000001..0xE0000009` | faults: unsupported opcode, outside memory, bad file, allocation, audit violation, `hlt` (stub-chain end: exit = EAX low32), wrong arch path, bad command line, instruction budget |

## Part 1 — Implemented

Iterations 1-5 complete (pytest 26 green, Release AND Debug):

- Iterations 1-4 (commits c29c0c5 … 6168e74): x64 core, x86 core, base
  relocations, fake env + WinAPI/CRT/resources stand-ins;
  `03_winapi_messagebox`, `04_crt_printf_rand` green x64+x86.
- Iteration 5 (5a `std::thread` commit 5cf2b1b; 5b DLL entry commit ef0fff8):
  `05_dll_entry` (full CRT startup through DllMain, exit 1) and
  `08_cpp_thread` (join-driven threads) green x64+x86, Release+Debug; 40/40
  repeat runs stable. Root fixes of 5: imm64 8-byte, CPUID both cores
  (SSE2-only), BT/CMPXCHG/lock both cores, xorps/movlpd x86, TEB Self
  pointers, memcpy/memset/CRT stand-ins, `hlt` ends stub chain with exit =
  EAX low32.
- Stand-in architecture so far: x64 MS ABI RCX/RDX/R8/R9 + shadow space; x86 stdcall callee-pops (`ApiEntry.callerCleans` marks cdecl); buffered `printf` (%d %i %u %x %X %c %s %%), MSVCRT LCG `rand`/`srand`, real import enumeration from the built exe.
- Core fixes landed this era: `doSubF` → `flagsNZP` (cmp+ja was broken), ordinal threshold `kOrdinalMax = 0x10000` (stub ordinals masked 0xffff), `pusha`/`popa` x86, `div`/`idiv` 8/16/32 signed+unsigned x86, stand-in arg array `args[8]` (was OOB at indices 4..7), rsp/esp starts 0x100 below stack end so vararg peeks stay inside the region.
- Module rewrite tasks 1-2 done: `Fault` enum + `fault_code`/`fault_message` in `fault.hpp/.cpp` (commit 380c4b3), `ShellcodeFile`+`File` RAII read (03f552f), `PeReader` MZ/PE scan class with `PeInfo` snake_case fields + truncated-header bounds fix (ebee2cb).
- Module rewrite task 3 (commit 4a15cd7): `GuestRegion` RAII VirtualAlloc/VirtualFree class (rule of 5, below-4GiB mode for x86 guests) absorbing image/stack/env/heap/thread stacks; `freeLoaded` deleted (regions free themselves); `allocLow` moved into `GuestRegion::allocate`.
- Module rewrite task 4 (commit 2ad6d79): export_resolver split into `api_table` (ApiEntry + checked ApiTable, `add`/`find`, max 32 entries fails closed), `guest_environment` (env layout constants, TEB/PEB/Ldr/fake images, `GuestMem`/`guestMem`/`guestStr`, `buildFakeEnv`) and `api_standins` (all stand-ins + `registerApiStandins`); `GUEST_WRITE` guard macro (local, `#undef` after) replaces 4 repeated guest-copy guards; `Loaded.apis` is `ApiTable`, cores call `l.apis.find(e.ip)`.
- Module rewrite task 5 (commit 973b1fc): `operand.hpp` (`OperandRegister`/`OperandMemory` tag structs, `Operand` = std::variant) and `instruction_decoder.hpp/.cpp` (Fetch, MR, arch-tagged `decodeMR<Architecture>` via `if constexpr` for the rm==5/mod==0 and SIB base-5 displacement asymmetries, `cond<EmuT>` + `operandRead`/`operandWrite<EmuT>` bound to the core memLd/memSt through ADL, `maskSz`/`bitsSz`/`sext`/`popcnt8` out of line). Both cores' local decode/operand machinery deleted; `Ctx.o`/`Ctx.g` are `Operand`s with `oIsReg`/`oRegIdx`/`oAddr`/`gRegIdx` helpers; `oSet`/`oVal`/`o8Read`/`o8Write` resolve the address then delegate.

## Part 2 — To implement

Module rewrite tasks 6-7 (conventions = CONTRIBUTING.md; each task: all 4
msbuild configs built, pytest green in Release AND Debug, one commit).

- Task 6: `Cpu<Architecture>` template absorbs vm64/vm86 stepwise (a: state/run loop; b: ALU+jcc/call/ret; c: remaining opcodes; d: delete old cores). Lands: rep-string budget fix, `SHELLTERP_BUDGET` env var + budget-fault pytest pin (20-byte `jmp $` → `0xE0000009`), O(1) stand-in lookup.
- Task 7: `ThreadContext` + RAII audit + `main` sweep; vcxproj updated, old files deleted; README exit/fault code table.

Feature track after the rewrite:

- Iteration 6 exceptions (tests 07/11/12/15): x64 table-based first —
  `RtlAddFunctionTable`/`RtlUnwind*`/`__C_specific_handler`/
  `_except_handler4_common` stand-ins currently fail closed (`ST_CRTFAIL`),
  move them from no-op to real; then x86 VEH model. Tests:
  `07_cpp_exceptions`, `11_cpp_exceptions`, `12_seh_exceptions`,
  `15_nested_exceptions`. Do not weaken invariants to make exceptions work;
  if impossible, stop and report.
- Iteration 7 hardening + docs: fuzz-ish tests, README, final audit;
  `_initterm`/`_initterm_e` upgrade path from paste-table skip to driven
  version if tests add C++ static initializers.

## Part 3 — Keynotes

Hard invariants (never weaken, never bypass):

1. Shellcode/stack/env/heap pages: one `VirtualAlloc(..., PAGE_READWRITE)`; protection never changes; never RX/RWX (runtime self-audit, build-time PE check). No executable page may appear after process start; the audit snapshots committed exec regions before/after and fails on difference.
2. `unknown instruction = Fault::UnsupportedInstruction` (`0xE0000001`); all stand-ins fail closed.
3. All emulated OS-facing services (fake PEB/TEB/module environment, import/WinAPI stand-ins, syscall/ROP-relevant paths) are compiled into the binary at build time.
4. Exit code = low 32 bits of RAX (x64) / EAX (x86); fault codes `0xE0000001..0xE0000009`.
5. Threads stay join-driven, single-threaded inside the interpreter; stand-ins take parameters from interpreter-owned state, with arch-specific `_Thrd_t` handling (x64 by ref, x86 by value) preserved in `apiThrdJoin`.

Build/test cycle (required before every commit):

```bat
msbuild shellterpreter.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64  (and x86, and Debug for both)
python -m pytest tests\pytest -q
set SHELLTERP_CONFIG=Debug & python -m pytest tests\pytest -q
```

Notable facts:

- Debug builds: isolated `Debug_x64`/`Debug_Win32` OutDirs, `/INCREMENTAL:NO` global property (otherwise `.textbss` RWX trips the audit); `conftest.py` reads `SHELLTERP_CONFIG=Debug`.
- 32-bit build refuses x64 shellcode with `0xE0000007`; 64-bit build runs both.
- Test PEs: `tests/test_projects/{02_relocs,03_winapi_messagebox,…}`; `04` needs the hand-generated `msvcrt.mini.def` import lib because no shipped lib exports `__imp_printf`.
- Known root causes live in the commit messages and `.sdd/ledger.md`; keep new findings there, keep this file the plan only.
- Do not leave temp debug prints (`dbg0`) in committed code. Code comments: why only.
