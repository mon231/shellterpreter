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

## Exit and fault codes

The process exit code is the outcome of the run: for a shellcode that
returns normally it is the low 32 bits of `RAX`/`EAX`; the range
`0xE0000000..0xE0000009` is reserved for the interpreter's own diagnostics.

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
