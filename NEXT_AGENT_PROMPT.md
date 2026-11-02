# Next-Agent Prompt: continue shellterpreter

You are continuing work on `shellterpreter`, a C++ Windows shellcode interpreter (x86 + x64). Read `PLAN.md`, `README.md`, `.sdd/ledger.md`, and this file before acting. Follow repo invariants and TDD.

## Goal
Implement iterations 4-7 from `PLAN.md`: fake PEB/TEB/environment + import stand-ins (iteration 4), CRT basics (iteration 5), exceptions (iteration 6), hardening/docs (iteration 7). Each feature lands with tests and a commit. Run relevant tests in **both Release and Debug** before every commit.

## Current State (committed in this handoff)
- Restructure complete: project code at root `shellterpreter/`; PE audit at `tests/audit_pe.py`.
- Iteration 1 (x64 core), iteration 2 (x86 core), iteration 3 (base relocations) implemented.
- Iteration 3 root causes fixed:
  - `shellterpreter/vm64.cpp`: `rexUsed` flag now set in REX prefix case.
  - `shellterpreter/vm86.cpp`: `decodeMR` treats `rm=5/mod=0` as absolute disp32 (`absDisp`), not RIP-relative.
- Test suite: 13 passed in Release and Debug (`SHELLTERP_CONFIG=Debug`).
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
- `shellterpreter/main.cpp`: loader, PEB/TEB/env stand-ins, allocLow.
- `shellterpreter/shellterpreter.vcxproj`: build config.
- `tests/test_projects/02_relocs/`: relocation test PE.
- `tests/pytest/test_iteration3.py`: iteration 3 tests.
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
- Iteration 4: fake PEB/TEB/environment + import stand-ins. Compiled-in module table; emulated `LoadLibraryA`/`GetProcAddress` stand-ins. Tests: `03_winapi_messagebox`, `04_crt_printf_rand`, `09_resources`.
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
Start iteration 4: inspect how import stand-ins should be added, create test PE `03_winapi_messagebox`, implement emulated `LoadLibraryA`/`GetProcAddress`, add tests, run Release + Debug pytest, commit.
