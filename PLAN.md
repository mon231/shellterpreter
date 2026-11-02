# shellterpreter — PLAN

C++ Windows shellcode interpreter. Reads a shellcode binary from a file into a
single `PAGE_READWRITE` allocation, emulates it instruction-by-instruction,
and sets the process exit code to the low 32 bits of the emulated return value
(RAX on x64, EAX on x86).

Scope of the shellcode format: **position-independent raw binary whose
execution starts at offset 0 with a return address on the stack**. That is the
only contract. The [
peor](https://pypi.org/project/peor/) output happens to satisfy this contract and
is what our test corpus uses, but shellterpreter does not require peor, its
stubs, or its layout. A shellcode without an embedded PE header is valid: in
that case the image base is the buffer start and the architecture must be
selected explicitly (`--x86` / `--x64`). When an `MZ`/`PE` header is present,
shellterpreter uses it for architecture detection only.

## User decisions (goal crafting)

- **ISA / ABI**: Windows, both x86 and x64, one interpreter core.
- **Instruction coverage**: common growable subset; fail closed with a
  reserved diagnostic code on anything unimplemented; the test suite drives
  what gets added.
- **Toolchain**: Visual Studio solution (`sln` + `vcxproj`); comprehensive
  pytest harness. The solution contains the `shellterpreter` executable
  project and many companion C++ projects that get compiled to EXE and then to
  shellcode for test execution. peor (PyPI) is a **test-pipeline-only**
  dependency: tests convert the built test PEs into shellcode binaries. peor
  is never required to run or build shellterpreter itself.
- **Iterations**: development proceeds iteration by iteration. First tests are
  simple (calculations / importless PEs like peor's own test style), then more
  and more gets implemented. Whenever a new feature is implemented it must land
  with tests that cover it and a commit.
- **Final delivered state**: threads and multiple types of exceptions must be
  supported; support for simple things (calculations, relocation) comes first.
- **Termination**: interpreter pushes a sentinel return address; emulation
  ends when RIP reaches it; process exit code = low 32 bits of RAX/EAX.
- **Safety evidence**: self-audit (VirtualQuery) at runtime plus a
  build-time PE-structure check.

## Hard invariants (never weakened, never bypassed)

1. Shellcode image pages: one `VirtualAlloc(..., PAGE_READWRITE)`; protection
   is never changed after allocation. Stack pages: same policy. Pages never
   become RX/RWX.
2. The shellterpreter process must not gain any executable page after process
   start. Runtime self-audit: snapshot all committed executable regions at
   startup, re-snapshot before exit, fail on any difference.
3. All emulated OS-facing services (fake PEB/TEB/module environment,
   import/WinAPI stand-ins, syscall/ROP-relevant paths) are compiled into the
   binary at build time.
4. Instruction coverage is a growable common subset. Unknown instruction =
   fail closed with a reserved fault code, never guessed semantics.

## Exit-code contract

| Code | Meaning |
|---|---|
| `0x00000000..0xDFFFFFFF` | emulator-set exit code = low 32 bits of returned RAX/EAX |
| `0xE0000001` | unsupported opcode (fail-closed) |
| `0xE0000002` | out-of-bounds memory access |
| `0xE0000003` | bad shellcode file |
| `0xE0000004` | memory allocation failure |
| `0xE0000005` | runtime self-audit violation |
| `0xE0000006` | `hlt` executed |
| `0xE0000007` | architecture path present in file, core not built yet |
| `0xE0000008` | bad command line |
| `0xE0000009` | instruction budget exhausted |

Sentinel return address is a fixed unmapped value; the first `ret` of the
shellcode (its own contract, or peor's stub chain for our test corpus) falls
there.

## Iterations (each lands with its tests and a commit)

### Iteration 1 — x64 positional-independent importless shellcode
- Solution, CLI, loader (arch detect with optional embedded PE header),
  x64 core (stubs need call/pop/lea/mov/cmp/test/add/sub/push/pop/jcc/jmp/
  call/ret/movzx/lodsw/hlt ModRM/SIB/rip-relative), sentinel return, fault
  codes, runtime self-audit, test PE `01_simple_calc` (importless, custom
  entry, x64), pytest (shellcode runs, audit, fail-closed unknown opcode),
  `tests/audit_pe.py`, `tests/build_tests.py`.

### Iteration 2 - x86 importless shellcode
- 32-bit core, same contract. Tests: 01_simple_calc Win32.
- Status: complete. peor's x86 stub does fs:[0x30] PEB walk and resolves
  AddVectoredExceptionHandler from an ntdll export table; fake TEB/PEB/Ldr/
  ntdll stand-ins built by the loader (one extra RW region, never
  executable), NT-function calls intercepted by the interpreter loop.
  x64 exe runs x86 shellcode via --x86 flag (all memory kept below 4 GB).

### Iteration 3 — base relocations (complete)
- Test project `02_relocs` (static globals + .reloc), expected exit 542.
- x64 core: `rexUsed` flag fixed; byte-reg REX ops now decode correctly.
- x86 core: `decodeMR` `rm=5/mod=0` fixed to absolute disp32 (`absDisp`).
- x86 reloc stub patches verified POS-space (delta = vmInnerFileBase − ImageBase).
- Debug builds isolated; `/INCREMENTAL:NO`; `conftest` supports `SHELLTERP_CONFIG=Debug`.
- pytest: 13 passed (Release + Debug).
- Next: iteration 4 (import stand-ins).

### Iteration 4 — fake PEB/TEB/environment + import stand-ins
- Compiled-in module table; emulated `LoadLibraryA`/`GetProcAddress`/...
  stand-ins executed natively inside shellterpreter.
- Tests: `03_winapi_messagebox`, `04_crt_printf_rand`, `09_resources`.

### Iteration 5 — CRT basics
- Tests: `05_dll_entry`, `08_cpp_thread` (threads as interpreter-driven
  contexts), CRT startup pieces.

### Iteration 6 — exceptions
- x64 table-based first, then x86 VEH-model. Multiple exception types must be
  supported by the end.
- Tests: `07_cpp_exceptions`, `11_cpp_exceptions`, `12_seh_exceptions`,
  `15_nested_exceptions`.

### Iteration 7 — hardening + docs
- Fuzz-ish tests, README architecture section, final audit.

## Evidence standard per feature

- `pytest tests\pytest` green, including audit tests.
- Both platforms build: `python tests\build_tests.py Release x64` and
  `... Release Win32`.
- `tests/audit_pe.py` passes on shellterpreter.exe (both arch) and on all
  test PEs: no RWX sections; no executable sections beyond the compile-time
  image's own (`.text` for shellterpreter; also allows the known test-PE
  sections).
- Every feature PR lands with its tests and a commit.

## Stop honesty

If a feature cannot be delivered inside the invariants (e.g. an exception
mechanism that would require executable pages), stop and report: attempted
paths, exact missing capability, evidence. Never fix it by weakening an
invariant.
