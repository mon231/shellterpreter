# shellterpreter — PLAN (single file: goal, status, redesign, audit, follow-ups)

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

## Hard invariants (never weaken)

1. Shellcode/stack/env/heap pages: one `VirtualAlloc(..., PAGE_READWRITE)`; protection never changes; never RX/RWX (runtime self-audit, build-time PE check).
2. `unknown instruction = Fault::Unsupported` (`0xE0000001`); all stand-ins fail closed.
3. All OS-facing fake services compiled into the binary at build time.

## Exit-code contract

| Code | Meaning |
|---|---|
| `0x00000000..0xDFFFFFFF` | low 32 bits of returned RAX/EAX |
| `0xE0000001..0xE0000009` | faults: unsupported opcode, outside memory, bad file, allocation, audit violation, `hlt` (stub-chain end: exit = EAX low32), wrong arch path, bad command line, instruction budget |

## Status ledger (details live in .sdd/ledger.md)

- Iterations 1-4 complete (commits c29c0c5 … 6168e74): x64 core, x86 core, relocations, fake env + WinAPI/CRT/resources stand-ins; pytest 20 green Release+Debug.
- Iteration 5 complete (5a `std::thread` commit 5cf2b1b; 5b DLL entry commit ef0fff8): `05_dll_entry` (full CRT startup through DllMain, exit 1) and `08_cpp_thread` (join-driven threads) green x64+x86, Release+Debug; pytest 26 green; 40/40 repeat runs stable. Root fixes of 5: imm64 8-byte, CPUID both cores (SSE2-only), BT/CMPXCHG/lock both cores, xorps/movlpd x86, TEB Self pointers, memcpy/memset/CRT stand-ins, `hlt` ends stub chain with exit = EAX low32.
- Next feature work: iteration 6 — exceptions (x64 table-based → x86 VEH; tests 07/11/12/15).

## Module rewrite (in progress; conventions = CONTRIBUTING.md)

Behavior-preserving refactor to RAII classes, one class per file, snake_case
full names, no namespaces / no `inline` / no raw owning pointers, shared
templated CPU core. Each task: all 4 msbuild configs built, pytest green in
Release AND Debug, one commit.

1. `fault` module (Fault enum, fault_message).
2. `ShellcodeFile` (RAII read) + `PeReader` (MZ/PE scan incl. decoys, arch, is_dll).
3. `GuestRegion` (RAII VirtualAlloc/VirtualFree, rule of 5) absorbs image/stack/env/heap/thread stacks.
4. `GuestEnvironment` + `ApiTable` + `ApiStandins` (replaces export_resolver; arch-parameterized layout constants).
5. `Operand` (std::variant) + `InstructionDecoder` (shared, arch-tagged) — replaces the malformed `OpRm` clusters.
6. `Cpu<Architecture>` template absorbs vm64/vm86 stepwise (sub-commit a: state/run loop; b: ALU+jcc/call/ret; c: remaining opcodes; d: delete old cores).
7. `ThreadContext` + RAII audit + `main` sweep; vcxproj updated, old files deleted.

## Audit findings (2026-11-03; full report in session log; fix in this order)

1. `rep movs/stos` bypasses the instruction budget (one emulated instruction = up to RCX guest iterations; worst case minutes of apparent hang; budget path untestable). Fix: count/cap iterations inside the string-op loops in both cores — land with the Cpu template.
2. No test pins the instruction budget fault `0xE0000009` (budget = 5e9 makes such a test slow). Fix before/with task 6: expose a test-only budget (env var `SHELLTERP_BUDGET`, read once at startup, default unchanged; pytest asserts 20-byte `jmp $` → 0xE0000009.
3. PE header fields read past file end into the 64 KB slack for truncated PEs (`main.cpp:88-98`). Fix: `imgOff + eLfanew + 0x400 <= data.size()` else `Fault::BadFile` (land with task 2).
4. `ApiEntry apis[32]` / `ThreadCtx threads[8]` raw arrays with overflow risk (9th `_beginthreadex` = out-of-bounds host write). Fix: checked registry in task 4/7.
5. `lookupApi` linear scan per guest step. Fix opportunistically in task 6 (range check over stand-in span → O(1)).
6. `loadShellcode` raw `CreateFileA`/`CloseHandle` early-return plumbing → task 2's RAII.
7. Housekeeping to do with first commit: commit `CONTRIBUTING.md` + `docs/` plan/spec, add `.superpowers/` to `.gitignore`.
8. README addition (task 7): exit/fault code table.

## Follow-ups (feature track after the rewrite)

- Iteration 6 exceptions: x64 RtlAddFunctionTable/unwind stand-ins currently fail closed (`ST_CRTFAIL`); x86 VEH model next; `_except_handler4_common`/`__C_specific_handler` move from no-op to real.
- Iteration 7: fuzz-ish tests, README, final audit. `_initterm`/`_initterm_e` upgrade path from paste-table skip to driven version if tests add C++ static initializers.
