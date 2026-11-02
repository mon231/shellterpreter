# Next-Agent Prompt: continue shellterpreter

You are continuing work on `shellterpreter`, a C++ Windows shellcode interpreter (x86 + x64). Read `PLAN.md`, `README.md`, `.sdd/ledger.md`, and this file before acting. Follow repo invariants and TDD.

## Goal
Implement iterations 4-7 from `PLAN.md`: fake PEB/TEB/environment + import stand-ins (iteration 4), CRT basics (iteration 5), exceptions (iteration 6), hardening/docs (iteration 7). Each feature lands with tests and a commit. Run relevant tests in **both Release and Debug** before every commit.

## Current State (committed in this handoff)
- Restructure complete: project code at root `shellterpreter/`; PE audit at `tests/audit_pe.py`.
- Iteration 1 (x64 core), iteration 2 (x86 core), iteration 3 (base relocations) implemented.
- Iteration 4 partially implemented, `03_winapi_messagebox` green (x64 + x86, exit 102):
  - `shellterpreter/export_resolver.{hpp,cpp}`: `buildFakeEnv` (fake TEB/PEB/Ldr
    chain + fake kernel32/ntdll images with export dirs + user32 module token)
    and compiled-in stand-ins (LoadLibraryA / GetProcAddress / MessageBoxA /
    RtlAdd*). Env layout documented in the file header comment.
  - `shellterpreter/vm.hpp`: `ApiEntry {addr, nargs, fn}`, `Loaded.apis[8]`,
    `lookupApi(l, ip)`; replaces iteration-2's per-call `ntEntry` hook.
  - `shellterpreter/main.cpp`: loader now calls `stub::buildFakeEnv(out)`;
    `allocLow` moved to export_resolver.cpp.
  - `shellterpreter/vm64.cpp` / `vm86.cpp`: run loops intercept stand-in calls
    (x64: MS x64 ABI RCX/RDX/R8/R9 + shadow space arg5+; x86: stdcall, callee
    pops ret + args, EAX result).
  - New files: `tests/test_projects/03_winapi_messagebox/{main.c,vcxproj}`
    (imported user32.dll, LoadLibraryA/GetProcAddress, MessageBoxA x2,
    negative checks), `tests/pytest/test_iteration4.py`.
  - Root causes fixed this round:
    - export-dir RVA was written at imgBase+0x78/0x88 instead of
      pehdr(e_lfanew=0x40)+0x78/0x88 (both fake images).
    - vm64 stand-in args read RAX as arg0; arg0 is RCX.
    - `doSubF` (both cores) called `flagsLogic` after computing borrow — CF
      cleared, `cmp`+`ja` broken (MZ scan in peor IMPORTS stubs). Now
      `flagsNZP` (same as adc/sbb).
    - ordinal threshold `kOrdinalMax = 0x10000`: stub ordinals are masked
      0xffff; name pointers are absolute >= imgBase >= 0x10000.
    - vm86 `pusha`/`popa` implemented (IMPORTS_32 opens with `pushal`).
- Test suite: 15 passed in Release and Debug (`SHELLTERP_CONFIG=Debug`).
- Debug builds use isolated `Debug_x64`/`Debug_Win32` OutDirs and `/INCREMENTAL:NO`.
- `tests/pytest/conftest.py` supports `SHELLTERP_CONFIG=Debug`.

## Architecture Invariants (never weaken)
1. Shellcode image pages: one `VirtualAlloc(..., PAGE_READWRITE)`; protection never changed. Stack pages same policy. No RX/RWX pages.
2. Process never gains an executable page after start; runtime self-audit snapshots committed executable regions before/after and fails on difference.
3. All emulated OS services compiled into binary at build time.
4. Unknown instruction = fail closed (`0xE0000001`), never guessed semantics.
5. Exit code = low 32 bits of RAX (x64) / EAX (x86). Fault codes `0xE0000001..0xE0000009`.

## Key Files
- `shellterpreter/vm64.cpp`, `shellterpreter/vm86.cpp`: instruction cores.
- `shellterpreter/export_resolver.cpp/.hpp`: fake env builder + API stand-ins.
- `shellterpreter/vm.hpp`: ApiEntry/Loaded/lookupApi, loadShellcode decl.
- `shellterpreter/main.cpp`: loader (calls buildFakeEnv; allocLow lives in export_resolver).
- `shellterpreter/shellterpreter.vcxproj`: build config.
- `tests/test_projects/02_relocs/`, `tests/test_projects/03_winapi_messagebox/`: test PEs.
- `tests/pytest/test_iteration3.py`, `test_iteration4.py`: iteration tests.
- `tests/pytest/conftest.py`: build/run helpers.
- `tests/audit_pe.py`: PE audit.

## Build/Test Commands
```bat
msbuild shellterpreter.sln /p:Configuration=Release /p:Platform=x64
msbuild shellterpreter.sln /p:Configuration=Release /p:Platform=x86
pytest tests\pytest -v
set SHELLTERP_CONFIG=Debug
pytest tests\pytest -v
```

## Remaining Work (next iterations)
- Iteration 4 remainder: `04_crt_printf_rand` (CRT pieces — enumerate its real
  PE imports before coding handlers) and `09_resources`
  (FindResourceA/SizeofResource stand-ins). Both then run in Release + Debug.
- Iteration 5: CRT basics. Tests: `05_dll_entry`, `08_cpp_thread`.
- Iteration 6: exceptions (x64 table-based first, then x86 VEH). Tests: `07_cpp_exceptions`, `11_cpp_exceptions`, `12_seh_exceptions`, `15_nested_exceptions`.
- Iteration 7: hardening + docs.

## Limits / Known Issues
- Do not weaken invariants to make exceptions work; if impossible, stop and report.
- Debug exes must be built with `/INCREMENTAL:NO` (global property) to avoid `.textbss` RWX audit failures.
- `conftest.build` defaults to Release; use env for Debug.
- Do not leave temp debug prints (`dbg0`) in code.
- Keep code comments minimal (why only).

## Immediate Next Step
Finish iteration 4: build test PE `04_crt_printf_rand` first, dump its import
table (dumpbin or python pefile) and add the needed CRT stand-ins to
`export_resolver.cpp` (printf/rand/srand/exit family — each needs real
emulation, e.g. printf writes to stdout, rand is deterministic); extend
`test_iteration4.py`. Then `09_resources` (FindResourceA + SizeofResource
stand-ins validate RT_RCDATA/test-resource bytes exit). Run Release + Debug
pytest (15 -> more), then commit each.
