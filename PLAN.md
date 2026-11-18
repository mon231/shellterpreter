# shellterpreter — PLAN (single file: implemented / to implement / keynotes)

C++ Windows shellcode interpreter. Loads a shellcode binary from a file into a
single `PAGE_READWRITE` allocation, emulates it instruction-by-instruction,
and sets the process exit code to the low 32 bits of the emulated return value
(RAX on x64, EAX on x86). Scope: position-independent raw binary starting at
offset 0 with a return address on the stack. The blob is mapped opaque — no
MZ/PE parsing, no header assumptions; peor output is only the test corpus. A
shellcode that needs image-relative services (x64 table-based exception
handling, resources) registers itself by writing a descriptor block into the
emulated environment; unregistered blobs still run, those services fail
closed.

## User decisions

- ISA/ABI: Windows, x86 + x64; the x64 interpreter runs both, the x86 build
  runs x86 only (`0xE0000007` otherwise).
- Coverage: growable common subset; unknown instruction → fail closed, never
  guessed.
- Toolchain: VS solution + vcxproj all 4 configs (Release/Debug x x64/Win32),
  pytest gate, peor is test-pipeline-only.
- Threads (`std::thread`) and multiple exception types are hard requirements;
  stand-ins take parameters from interpreter-owned state, not guest register
  shuffling.
- Development proceeds test-first, batch by batch (see `.sdd/ledger.md`), the
  pytest suite is the correctness gate.

## Architecture

- The blob is mapped opaque into a `GuestRegion` image allocation, verbatim,
  execution starts at offset 0; architecture comes only from the caller
  (`--x86`/`--x64`, default = the build's own). No PE parsing anywhere: a
  blob without any header works fully.
- Fake PEB/TEB/LDR environment built at load; image-relative services are
  driven by a guest-declared descriptor (magic `'RDSH'`, `kDescRva`) that the
  shellcode's own prologue writes.
- WinAPI/CRT stand-ins are compiled in and registered in a checked `ApiTable`
  (`O(1)` address lookup); whitelisted real system modules resolve to their
  real bases and calls into them run natively through the native bridge;
  `syscall` (x64) dispatches to the real ntdll `Nt*` stub via a runtime
  prologue-scanned table. Everything else fails closed.
- Threads are join-driven: emulated threads run on the first `_Thrd_join`/
  `WaitForSingleObject` stand-in, so the interpreter itself stays
  single-threaded.
- Exceptions are interpreter-walked, not delegated: x64 FH4 `.pdata`/`.xdata`
  tables, x86 `FS:[0]` chain with EH3/SEH3 scope tables; handlers run as
  funclets on a sentinel return address.

## Exit-code contract

| Code | Meaning |
|---|---|
| `0x00000000..0xDFFFFFFF` | low 32 bits of returned RAX/EAX |
| `0xE0000001` | unimplemented opcode (fail closed) |
| `0xE0000002` | access outside emulated memory |
| `0xE0000003` | bad shellcode file |
| `0xE0000004` | memory allocation failed |
| `0xE0000005` | runtime self-audit violation |
| `0xE0000006` | `hlt` executed (also ends a stub chain; exit is then EAX) |
| `0xE0000007` | architecture mismatch (32-bit build + x64 shellcode, wrong `--x86`/`--x64` flag) |
| `0xE0000008` | bad command line |
| `0xE0000009` | instruction budget exhausted |
| `0xE000000A` | native bridged call escaped via exception (fail closed) |

## Part 1 — Implemented

Iterations 1-7 and the modular-class rewrite are complete (pytest green,
Release AND Debug, both archs); the iterations and their commits live in the
git history and `.sdd/ledger.md`. The rewrite landed `Fault` +
`fault_code`/`fault_message`, `ShellcodeFile` RAII read, `GuestRegion` RAII
VirtualAlloc regions, the `api_table`/`guest_environment`/`api_standins`
split, `operand.hpp` + the arch-tagged decoder, and the single
`Cpu<Architecture>` template absorbing the two per-arch cores (budget-charged
rep loops, `SHELLTERP_BUDGET`, `O(1)` ApiTable::find), then `ExecAudit` RAII
snapshot + verify, guest exceptions (interpreter-walked FH4 / FS:[0]-chain
unwind), and the iteration-7 hardening fuzz tests.

Batches A-H (`.sdd/ledger.md` batch headers, summary):

- **Batch A — user-mode integer opcodes**: rotates, 64-bit mul/imul,
  shld/shrd, bsf/bsr, popcnt, crc32 (Castagnoli), xadd, lahf/sahf, fs/gs
  moves, sreg moves, scas/movs/stos lifted to x86, cwd/cbw family,
  int3/pause/endbr. Driven by the keystone-assembled opcode corpus
  (`tests/pytest/_opcode_corpus.py`); iteration 11 value tests. Corpus after
  A/B/C: full user-mode opcode coverage, no gaps.
- **Batch B — SSE/SSE2**: 0F escape subset + legacy MMX via NP forms —
  packed/scalar ALU, conversions (integer indefinite on out-of-range),
  compare predicates, shuffles, unpacks, pshifts, movd/movq, pinsr*/pexr*.
  Iteration 12 value tests.
- **Batch C — x87**: full D8-DF memory and register forms, fcmovcc, fsincos,
  fprem, fild/fistp all widths, fldcw/fnstcw/fnstsw/fninit; DC/DE sub/div
  direction table measured on real hardware. Iteration 13 value tests.
- **Batch D — whole-memory access + native bridge + syscall**: memLd/memSt
  region whitelist fast path with a `hostPageAddr` VirtualQuery fallback
  (reads on committed readable pages, writes on writable pages only);
  call/jmp into whitelisted real modules runs the real function through the
  native bridge (x64 C ABI, x86 naked-asm stdcall bridge on an x86 host);
  x64-only `0F 05` syscall dispatches the guest's NT number to the real ntdll
  stub; new fault `NativeFault` `0xE000000A`. Iteration 14 value tests.
- **Batch E — shared guest test kit**: `tests/pytest/guestkit.py` migrates
  iterations 11-14 onto one arch-explicit kit (blob/exit_code/run_case,
  x86call/stdcall builders, ntdll syscall-number parse).
- **Batch F — hardening**: registerModules switched to the loader API
  (GetModuleInformation, per-module failure costs only that module);
  PAGE_GUARD/noaccess pages fail closed into `0xE0000002`;
  CONTRIBUTING.md gains the mandatory RAII/small-function/small-module rules.
- **Batch G — real x64 binaries end-to-end**: whoami/hostname/ipconfig-class
  real porcelain blobs run through full CRT startup; GetModuleFileNameW
  stand-in, GUEST_WRITE host fallback, SSE bitwise full-width fix, 16-bit FF
  inc/dec. TEMP debug prints from this batch were removed in Batch H Task 6.
- **Batch H — audit fixes + stub-state into Loaded + realbin tests** (plan:
  `docs/superpowers/plans/2026-11-16-batch-h-stubs-and-hardening.md`): decoder
  fetch bounds at all six fetch sites; syscall table + rand seed moved into
  per-run `Loaded` state; stub hardening (memory-safety, thread lifecycle,
  argv/env CRT stand-ins, native-delete heap-identity routing, heapAlloc
  x64-native/x86-bump split); module whitelist 19→24 (winsock catalog
  providers preloaded); audit TEMP dumpDiff diagnostics (removed by this
  cleanup); `test_realbin.py` runs the real whoami/hostname/ipconfig blobs
  (exit 0, stdout asserted); exit-path fixes. pytest 77/77 Release AND Debug.

## Part 2 — To implement

- **x86 native bridge on x86 host only** — under an x64 build the x86 core
  fails closed (`0xE000000A`). Float/xmm returns and varargs `AL` are not
  modeled across a bridge.
- **More user-mode instruction families** as real-world corpora demand them
  (fuzzing continues to surface gaps; everything else already fails closed).
- Tracked product issues (ledger Batch H): whoami teardown fault variance
  (0xC0000374/0xE000000A — native-heap delete mystery); native operator
  new/delete[] asymmetry (silent leak, fails closed); no dedicated test for
  the native-forward WAIT_FAILED path; rep cmps missing the rcx==0 early
  guard.

## Part 3 — Keynotes

Hard invariants (never weaken, never bypass):

1. Shellcode/stack/env/heap pages: one `VirtualAlloc(..., PAGE_READWRITE)`;
   protection never changes; never RX/RWX. No executable page may appear
   after process start; the runtime self-audit snapshots committed exec
   regions before/after and fails `0xE0000005` on any difference.
2. `unknown instruction = Fault::UnsupportedInstruction` (`0xE0000001`);
   all stand-ins fail closed.
3. All emulated OS-facing services (fake PEB/TEB/module environment,
   import/WinAPI stand-ins, syscall/ROP-relevant paths) are compiled into
   the binary at build time.
4. Exit code = low 32 bits of RAX (x64) / EAX (x86); fault codes
   `0xE0000000..0xE000000A` reserved (see table above).
5. Threads stay join-driven, single-threaded inside the interpreter; stand-ins
   take parameters from interpreter-owned state.

Build/test cycle (required before every commit):

```bat
msbuild shellterpreter.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64  (and x86, and Debug for both)
python -m pytest tests\pytest -q
set SHELLTERP_CONFIG=Debug & python -m pytest tests\pytest -q
```

Notable facts:

- Debug builds: isolated `Debug_x64`/`Debug_Win32` OutDirs, `/INCREMENTAL:NO`
  global property (otherwise `.textbss` RWX trips the audit); conftest.py
  reads `SHELLTERP_CONFIG=Debug`. REBUILD all 4 configs before the Debug
  pytest run when product code changed — a stale exe reports pre-fix
  behavior.
- Test PEs: `tests/test_projects/{02_relocs,03_winapi_messagebox,…}`; `04`
  needs the hand-generated `msvcrt.mini.def` import lib because no shipped
  lib exports `__imp_printf`.
- Real binary blobs for `test_realbin.py` live in
  `C:\Users\avart\AppData\Local\Temp\opencode\` (whoami/hostname/ipconfig).
- Known root causes live in the commit messages and `.sdd/ledger.md`; keep
  new findings there, keep this file the plan only.
- Do not leave temp debug prints in committed code. Code comments: why only.
