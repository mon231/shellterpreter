# Guest Test Kit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One shared guest-test kit (`tests/pytest/guestkit.py`) replaces the four drifted private helper copies in test_iteration11-14, with arch-explicit case semantics that would have caught today's x86-fallback bug.

**Architecture:** New module owns keystone assembly + prologue/tail, both-arch running and exit-code conversion, string puts, syscall numbers, and an x86 stdcall call builder. Test files keep their case bodies exactly, import the kit, lose their private helpers. `asm86=None` now means skip (never silently generate an x86 asm).

**Tech Stack:** pytest + keystone (existing), no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-09-guest-test-kit-design.md`

## Global Constraints

- Test-only: no product code in `shellterpreter/` may change.
- Same case names, same expectations, same pass counts: 74 tests, green
  under `python -m pytest tests\pytest -q` (Release) and with
  `SHELLTERP_CONFIG=Debug` + `SHELLTERP_BUDGET=5000000` env (Debug).
- Kit module name: `tests/pytest/guestkit.py`.
- Pipelines env needs local peor editable install + `C:\Python313\Scripts` on PATH (ledger note).

## Review Focus

1. **`asm86=None` skip semantics** — an x64-only case must never assemble
   an x86 blob; pinned by keeping `test_iteration14.test_cases` green
   (yield/marshal/unknown skip x86 silently).
2. **x86 stdcall args** — every x86 `call <reg>` to a stand-in/bridge must
   be preceded by push-looped args; pinned by the existing lstrlen/
   user32/VirtualAlloc cases.
3. **Exit-code conversion** — `win_code(rc)` mapping negative → +2^32;
   pinned by existing suite pass counts.
4. **Budget env for Debug fuzz** — `test_iteration7.py` ENV must survive
   import-order moved helpers; pinned by Debug full-suite run.

---

### Task 1: guestkit.py

**Files:**
- Create: `tests/pytest/guestkit.py`

**Interfaces:**
- Produces:
  - `blob(asm: str, is64: bool) -> bytes` — keystone assemble, prepends
    the standard prologue (`sub rsp/esp, 0x40` + `cld`), appends `hlt`.
  - `run(code: bytes, is64: bool, tag: str, tmp_path) -> (exit_code: int, stderr: str)`
    — writes blob, runs the right exe (conftest dirs), converts exit via
    `win_code`.
  - `run_case(name, asm64, asm86, expect, tmp_path)` — `asm86=None`
    means skip x86; no fallback, ever.
  - `x86call(reg_fn: str, args: list[str]) -> str` — emits
    `push <arg>` lines reverse + `call <reg_fn>` so x86 stdcall arg order
    is a helper decision, not per-case fingers.
  - `puts(base: str, off: int, value: str) -> str` — dword-store string
    writer (NUL-padded, one extra zero dword), same shape as
    test_iteration14._puts.
  - `syscall_num(func: str) -> int` — ntdll stub-prologue parse, asserts
    the `4C 8B D1 B8` shape.
  - `X64_PRE / X86_PRE` — TEB-self-pointer preludes (env base register).

- [ ] **Step 1: Write `guestkit.py`** with the exact interfaces above,
  bodies borrowed from `test_iteration14.py` (today's passing versions).
- [ ] **Step 2: Smoke assert** — `python -c` import + `syscall_num
  ("NtYieldExecution")` returns 0x46 and `blob('hlt\ncall', ...)`
  assembles. Run: `python -c "import sys; sys.path.insert(0,
  r'tests\pytest'); import guestkit"` then call `syscall_num`.

### Task 2: Migrate test_iteration14.py

**Files:**
- Modify: `tests/pytest/test_iteration14.py`

- [ ] **Step 1:** Replace `_blob/_exit_code/_run_case/_x86asm/_puts/
  _syscall_num/preludes` with kit imports; rewire `_load_gpa` to use
  `x86call` for its two x86 stand-in calls.
- [ ] **Step 2:** Run `pytest tests\pytest\test_iteration14.py -q`.
  Expected: PASS (same cases).
- [ ] **Step 3:** Delete `_NONE` sentinel remnants if any; keep case text
  identical otherwise.

### Task 3: Migrate test_iteration11-13, delete private copies

**Files:**
- Modify: `tests/pytest/test_iteration11.py`, `test_iteration12.py`,
  `test_iteration13.py`

- [ ] **Step 1:** Same migration per file; where a file's `_run_case`
  differs (iteration11 has no tag param), choose the kit's signature and
  adjust call sites. Preserve iteration12's conditional-fallback only
  where a case genuinely needs it — otherwise `None`-means-skip.
- [ ] **Step 2:** Run all three files: `pytest tests\pytest\test_iteration11.py
  tests\pytest\test_iteration12.py tests\pytest\test_iteration13.py -q`.
  Expected: PASS.

### Task 4: Gate + commit

- [ ] **Step 1:** Full gate — `pytest tests\pytest -q` Release, then
  `SHELLTERP_CONFIG=Debug` env variant. Expected: 74 passed both.
- [ ] **Step 2:** Ledger entry in `.sdd/ledger.md` (gitignored, never
  `git add`).
- [ ] **Step 3:** Commit: `git add tests/pytest/guestkit.py
  tests/pytest/test_iteration1{1,2,3,4}.py docs/superpowers && git commit
  -m "test: shared guest kit - arch-explicit cases, helper dedup across iteration11-14"`.
