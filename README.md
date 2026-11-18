# shellterpreter

C++ Windows shellcode interpreter. Loads a shellcode binary from a file into a
single `PAGE_READWRITE` allocation, emulates it instruction-by-instruction,
and sets the process exit code to the low 32 bits of the emulated return value
(RAX on x64, EAX on x86).

## What a shellcode is (contract)

Position-independent raw binary. Execution starts at offset 0. A return
address is on the stack when the first instruction runs; emulation ends when
execution returns to it. That is the full interface: shellterpreter does not
require [peor](https://pypi.org/project/peor/). Our test corpus uses peor (it
correctly produces this format), but any hand-crafted or tool-generated
shellcode following the contract works. The architecture comes only from the
caller: `--x86` or `--x64`, defaulting to the interpreter build's own
architecture. Embedded `MZ`/`PE` headers in the shellcode are never parsed —
a blob without any header works fully.

A shellcode that needs image-relative services (x64 table-based exception
handling, `FindResourceA`/`SizeofResource`) registers itself: it writes a
small descriptor block into the emulated environment at a fixed offset
(magic `'RDSH'`, image base, `.pdata` address/size, resource directory RVA —
see `kDescRva` in `guest_environment.hpp`), usually by reading its own
headers and deriving the runtime image base from a linker-provided symbol.
`tests/test_projects/common/selfreg.h` is a worked example. The interpreter
never parses any header — the shellcode owns its bytes, so only it touches
them. A blob that registers nothing still runs: those services fail closed.

## Invariants

- Shellcode memory is never executable: one RW allocation (image + stack),
  protection never changed afterwards; pages never become RX/RWX.
- The process never gains an executable page after start: a runtime
  self-audit snapshots all committed executable regions before and after
  emulation and fails with a reserved code on any difference.
- All emulated OS-facing services (fake PEB/TEB/module environment, WinAPI
  stand-ins, syscall and ROP-relevant paths) are compiled into the binary.
- Unknown instructions fail closed with a reserved diagnostic exit code.

See `PLAN.md` for the roadmap and the user decisions behind these choices.

## Feature status

Implemented (verified by the pytest corpus and value tests, Release + Debug,
both archs):

- **Core**: x64 and x86 user-mode integer instruction set to full opcode
  coverage — rotates (rol/ror/rcl/rcr), 64-bit mul/imul, shld/shrd,
  bsf/bsr, popcnt, crc32, xadd, lahf/sahf, fs/gs moves, scas and the other
  string ops (movs/stos/...), cwd/cbw family, int3/pause/endbr/nop forms.
- **SSE/SSE2**: packed and scalar float ALU, conversions (with integer
  indefinite on out-of-range), compare predicates, shuffles, unpacks,
  pshifts, movd/movq, pinsr*/pexr* family (per-lane semantics validated
  against real hardware).
- **x87**: D8–DF all memory and register forms — arith/compare, fcmovcc,
  fxch, fsincos, fprem, fild/fistp all widths, fldcw/fnstcw/fnstsw/fninit,
  DC/DE sub/div direction table measured on real hardware.
- **Memory / environment**: fake PEB/TEB/LDR environment with self-pointer
  TEB, opcode-driven memory access with an emulated image+stack layout,
  guest-declared descriptor for image-relative services.
- **OS-facing services**: WinAPI/CRT stand-in table (LoadLibraryA-style
  imports, MessageBox, CRT printf/rand/srand, thread creation, resource
  APIs, RaiseException) — compiled in, never real API calls; guest
  pointers stay emulated.
- **Native bridge**: `LoadLibraryA`/`GetProcAddress` stand-ins can hand
  out real kernel32/user32/ntdll/gdi32/advapi32 addresses (whitelisted
  modules resolve to their real bases) and a guest `call`/`jmp` into any
  whitelisted module range runs the real function through a native
  bridge — x64 through the C ABI, x86 through a naked-asm stdcall bridge
  (x86 host only) — with only `RAX`/`EAX` carrying the return value back.
  Whole-memory data access: reads on any committed readable page (via
  VirtualQuery fallback), writes on writable pages; code pages stay
  read-only. `syscall` (x64) dispatches the guest's NT number to the real
  ntdll stub through the bridge, table built by scanning ntdll `Nt*`
  export prologues; anything else fails closed.
- **Exceptions**: guest C++ throw/catch and SEH with real unwind metadata
  (x64 FH4 tables, x86 FS:[0] chain + scope tables), handlers run as
  funclets; uncovered constructs fail closed.
- **Threads**: emulated join-driven worker threads, single-threaded host.
- **Fail-closed discipline**: unknown opcode, out-of-range access,
  malformed metadata, missing state — all reserved faults, never a crash;
  instruction budget (`SHELLTERP_BUDGET`) with `0xE0000009` on exhaustion;
  executable-region audit before/after every run.

Remaining top-down (largest first):

- **x86 native bridge on x86 host only** — the naked-asm x86 bridge runs
  a real function only under a 32-bit interpreter build; under an x64
  build the x86 core fails closed (`0xE000000A`). x64 bridges and the
  x64 syscall dispatch run natively on an x64 build. Float/xmm returns
  and varargs `AL` are not modeled across a bridge; `jmp` into a bridge
  pops a garbage return address (accepted, fetch-outside fails closed
  after the return).
- **More user-mode instruction families** as real-world corpora demand
  them (fuzzing continues to surface gaps; everything else already fails
  closed).

## Exit and fault codes

The process exit code is the outcome of the run: for a shellcode that
returns normally it is the low 32 bits of `RAX`/`EAX`; the range
`0xE0000000..0xE000000A` is reserved for the interpreter's own diagnostics.

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

## Design and choices

- **Fail closed, never guessed.** An unknown or partial instruction is a
  fault, not a best-effort decode. Stand-ins return faults on missing
  state instead of writing zeros; import tables that overflow fail the
  run; the audit compares executable regions before and after the run and
  fails on any change.
- **W^X by construction.** All guest memory lives in dedicated
  `VirtualAlloc` regions created `PAGE_READWRITE` once and never
  re-protected, so there is no JIT, no self-modification surface, and no
  way for guest writes (including writes through emulated `memcpy`) to
  create code that later runs.
- **One CPU, one decoder.** The x64 and x86 cores are a single
  `Cpu<Architecture>` template around one arch-tagged decoder. The two
  instruction sets differ in real, known places (REX bytes vs 40–4F
  inc/dec, RIP-relative vs absolute disp32, register-file widths, div/pusha
  forms); every such place is resolved at compile time with `if constexpr`,
  and the two cores cannot drift apart again.
- **Interpreter-visible OS services are compiled in.** The fake
  PEB/TEB/LDR environment, the WinAPI/CRT stand-in table (checked into an
  `ApiTable`, O(1) address lookup) and CRT startup helpers are binary-resident
  code, approved ahead of time — the guest never calls a real API.
- **RAII for every system resource.** Guest regions, file handles, and the
  executable-region audit are classes with destructors; the kernel handles
  and allocations cannot leak on an early-out (the interpreter takes a
  fault on almost any malformed input).
- **Threads are emulated, join-driven.** `_beginthreadex`/`std::thread`
  stand-ins create emulated threads that run on the first `_Thrd_join`
  stand-in, keeping the interpreter itself single-threaded.
- **Exceptions are interpreted, not delegated.** Guest C++ (`throw`/`catch`)
  and SEH (`__try`/`__except`) unwind through metadata the interpreter walks
  itself: x64 FH4 `.pdata`/`.xdata` tables, x86 `FS:[0]` registration chain
  with EH3/SEH3 scope tables. Catch handlers and filters run as funclets on a
  sentinel return address; anything the metadata does not cover (destructor
  unwind actions, multi-continuation handlers, rethrow) fails closed with a
  reserved fault code instead of guessing.
- **A budget instead of a crash.** Instruction execution is bounded;
  default 5,000,000,000, overridable via `SHELLTERP_BUDGET`. A runaway
  guest exits with `0xE0000009` instead of hanging the host process.
- **Test-first, both configs.** The pytest suite is the correctness gate
  for every commit, run in Release AND Debug, on both x64 and x86 builds.

## Build

pytest builds the solution itself. To build by hand from a *Developer
Command Prompt* (Visual Studio 2022 or 18):

```bat
msbuild shellterpreter.sln /p:Configuration=Release /p:Platform=x64
msbuild shellterpreter.sln /p:Configuration=Release /p:Platform=x86
```

`Win_x64\shellterpreter.exe` is a dual-arch interpreter: it contains both the
x64 and x86 cores and selects them via the `--x86`/`--x64` flag (default =
the build's own architecture). `Win_x86\shellterpreter.exe` runs x86
shellcode only.
GitHub Actions builds both and publishes them as artifacts
(`shellterpreter-x64`, `shellterpreter-x86`); see
`.github/workflows/ci.yml`.

## Test

```bat
pip install peor pytest
pytest tests\pytest -v
```

## Layout

| Path                   | What                                              |
|------------------------|---------------------------------------------------|
| `shellterpreter/`     | interpreter sources                               |
| `tests/test_projects/` | companion C++ test PEs (one per feature)          |
| `tests/pytest/`        | pytest harness                                    |
| `tests/audit_pe.py`    | PE-structure checks used by the tests             |
| `.github/workflows/`   | CI: builds both configs, runs pytest, uploads exe |
| `PLAN.md`              | roadmap, iteration log, user decisions            |
