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

- **ISA / ABI**: Windows, both x86 and x64. The 32-bit interpreter build runs
  32-bit shellcode only; the 64-bit interpreter build runs x64 and x86
  shellcode.
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
- Status: `03_winapi_messagebox` complete (x64 + x86, exit 102; negative
  checks covered). `export_resolver.{hpp,cpp}` build the fake env (TEB/PEB/Ldr
  chain, fake kernel32 + ntdll PE headers with export dirs, user32 module
  token) and register compiled-in stand-ins
  (LoadLibraryA/GetProcAddress/MessageBoxA/RtlAdd*). vm64/vm86 run loops
  intercept calls at stand-in addresses; x64 = SysV-free MS x64 ABI via
  RCX/RDX/R8/R9 + shadow space, x86 = stdcall with callee-cleaned args.
- vm64 `ApiEntry/Loaded/lookupApi` replaced iteration-2's per-call ntdll hook.
- Root fixes: vm64 stands-in args read RCX not RAX; both cores' `doSubF`
  used `flagsLogic` (clears CF — broke `cmp`+`ja` in the MZ-scan stubs) now
  uses `flagsNZP`; ordinal/import-name threshold `kOrdinalMax = 0x10000`
  (stub ordinals are masked 0xffff, name pointers >= imgBase >= 0x10000);
  vm86 added `pusha`/`popa` (IMPORTS_32 opens with `pushal`).
- Liberation: env layout documented in `export_resolver.cpp` header comment.
- pytest: 18 passed in Release and Debug (incl. audit tests).
- `04_crt_printf_rand` complete (x64 + x86): real PE imports enumerated from
  the built exe = one module `msvcrt.dll` with `printf`, `rand`, `srand`
  (by name, no ordinals). A hand-generated import lib
  (`tests/test_projects/04_crt_printf_rand/msvcrt.mini.def` +
  `msvcrt_mini_x64.lib` / `msvcrt_mini_Win32.lib`) supplies them because the
  UCRT headers model `printf` as an inline wrapper over
  `__stdio_common_vfprintf`; no shipped lib exports `__imp_printf`.
  Stand-ins: minimal `printf` (%d %i %u %x %X %c %s %%, buffered, unsupported
  conversion -> -1, writes guest text to interpreter stdout), MSVCRT LCG
  `rand`/`srand` (shared seed, caller's 5 draws match a Python model).
  `ApiEntry.callerCleans` marks x86 cdecl stand-ins (caller pops args).
- Arch dispatch: x64 interpreter runs x64 and x86 shellcode; the 32-bit
  interpreter runs x86 only and fails closed with `0xE0000007` on x64
  shellcode (`test_arch_dispatch`).
- `09_resources` complete (x64 + x86, exit 600): real PE imports
  enumerated from the built exe = one module `KERNEL32.dll` with
  `FindResourceA`, `SizeofResource` (by name). Stand-ins parse the
  shellcode's own mapped PE image: the resource directory entry is read
  from the PE data directory, and every directory offset is relative to
  the resource section RVA (name strings, subdirectory offsets, data
  entries). `FindResourceA` matches type -> name -> language (any language
  fallback) and returns the guest address of the leaf
  `IMAGE_RESOURCE_DATA_ENTRY`; `SizeofResource` reads that entry's `Size`.
  Missing resources return NULL, a bad handle returns 0.
- Iteration 4 complete: pytest 20 passed in Release and Debug.

### Iteration 5 — CRT basics
- Tests: `05_dll_entry`, `08_cpp_thread` (threads as interpreter-driven
  contexts), CRT startup pieces.
- Threads are a hard requirement (`std::thread` in the test corpus too): the
  interpreter must run the shellcode's thread entry points itself, as
  emulated contexts on separate interpreter stacks. Stand-in/syscall
  entry points must take their parameters from interpreter-owned globals
  rather than shuffling them through guest registers.

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
