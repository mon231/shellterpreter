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
shellcode following the contract works. If the binary contains an embedded
`MZ`/`PE` header, it is used for architecture detection only; without one, the
caller must pass `--x86` or `--x64`.

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

## Build

From a *Developer Command Prompt* (Visual Studio 2022 or 18):

```bat
python tests\build_tests.py Release x64
python tests\build_tests.py Release Win32
```

## Test

```bat
pip install peor pytest
pytest tests\pytest -v
```

## Layout

| Path                   | What                                              |
|------------------------|---------------------------------------------------|
| `src/shellterpreter/`  | interpreter sources                               |
| `tests/test_projects/` | companion C++ test PEs (one per feature)          |
| `tests/pytest/`        | pytest harness                                    |
| `scripts/audit_pe.py`  | PE-structure checks used by the tests             |
| `tests/build_tests.py` | msbuild driver (x64 + Win32)                      |
| `PLAN.md`              | roadmap, iteration log, user decisions            |
