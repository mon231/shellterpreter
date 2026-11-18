# Batch H: hardening + stub-state + real-binary tests — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the audit's guest-controllable bugs, move process-global stub state into `Loaded` (per-run object), add the missing thread/exit stubs, pin the real binaries (ipconfig/hostname/whoami) with pytest smoke tests, strip all batch-G TEMP prints, regenerate PLAN.md, pass the full 4-config gate.

**Architecture:** No new subsystems. The audit (2026-11-16, 20 findings) drives fixes in place. Stub state migration follows the existing pattern: everything a stand-in needs already lives in `Loaded` (`vm.hpp`); only `gRandSeed` and `gSys/gSysCount` remain process-global, and those move into `Loaded`. New thread stubs register through the existing `registerApiStandins` + `ST_*` RVA table in `guest_environment.hpp`.

**Tech Stack:** C++/MSVC (4 configs), pytest harness (`tests/pytest`, `conftest.py` reads `SHELLTERP_CONFIG`), peor-converted real binaries as smoke blobs (external, path-skipped).

**Spec:** `.sdd/ledger.md` (batch history), README.md invariants section, audit findings 1-20 (this conversation, 2026-11-16).

## Global Constraints

- Fail closed: every stub with missing state returns a fault, never guessed zeros (PLAN.md:66).
- Exit/fault codes: `0xE0000000..0xE000000A` reserved; table in README.md:105-117 is the contract.
- All guest pointers land below 4 GiB; x86 stand-ins truncate to 32 bits.
- No temp debug prints in committed code (PLAN.md:85). The 5 fault-diagnostic prints in `cpu.hpp` (fetch-outside-image, access-outside-memory, unimplemented-opcode, native-bridge-escaped) are legit and stay.
- Gate before every commit: 4-config Rebuild + pytest green Release AND Debug (`$env:SHELLTERP_CONFIG="Debug"`); ledger entry in `.sdd/ledger.md` (gitignored, never `git add`); one commit per batch.
- Threads stay join-driven, single-threaded host (PLAN.md:69).

## Review Focus

1. Malformed/truncated blob (guest u16 lengths, fetch past image end) — expected: reserved fault, never host crash. Pinned by: test_iteration7 fuzz + new bounds tests (Task 1, Step 4).
2. `printf` format that fills the 256-byte buffer exactly — expected: clean truncation or `-1`, no stack overflow. Pinned by: Task 1 Step 1 unit test via tiny shellcode in `_opcode_corpus` style.
3. Two shellcodes in one process (repeat runs) — expected: identical rand/syscall behavior per run. Pinned by: Task 2 Step 2 repeat-run test.
4. Guest `free()` of a native heap pointer after Task 2 — expected: freed without 0xC0000374; garbage pointer → ignored, no crash. Pinned by: whoami smoke test exit=0 (Task 5).
5. CMPSD/Q + repne on real code — expected: correct step size and direction. Pinned by: existing opcode corpus + real-binary run (Task 5).

---

### Task 1: Memory-safety fixes (audit #1 #2 #3 #8 #10 #11)

**Files:**
- Modify: `shellterpreter/api_standins.cpp` (resFind ~417, apiPrintf ~340, va_list ~607)
- Modify: `shellterpreter/cpu.hpp` (addrPtr ~36-48, fetch bound ~1234)
- Modify: `shellterpreter/guest_region.cpp:46-50` (below4 fallthrough)
- Modify: `shellterpreter/shellcode_file.cpp:5-15` (handle guard)
- Test: `tests/pytest/test_iteration7.py` (fuzz already covers; must stay green)

**Interfaces:**
- Produces: `addrPtr` fails closed (`nullptr` → `Fault::Access` path unchanged); `File` destructor no-ops on `INVALID_HANDLE_VALUE`.

- [ ] **Step 1: resFind clamp** — `len = min(len, 63)` before indexing `char name[64]` (both sites ~417, ~421).
- [ ] **Step 2: addrPtr bounds** — reject `addr > end` (and any `addr + size` wrap) before the `img.data() + (addr - base)` branch; fall through to fail-closed `Fault::Access`.
- [ ] **Step 3: fetch bounds** — `stepOne`/`Fetch::u8/u16/u32/u64` check `pos < len`; out of bounds → existing fetch-outside-image fault path (cpu.hpp:3477).
- [ ] **Step 4: apiPrintf buffer** — change the two plain-char appends (~340, ~345) to `if (n < sizeof(out) - 1)`; then `out[n]='\0'` at ~376 cannot hit `out[256]`.
- [ ] **Step 5: x86 va_list** — guard the `memcpy(&ap, mv.p, 8)` at ~607 with `sizeof(va_list)` length.
- [ ] **Step 5b: va_list convention (audit #4)** — `muiFallback` (~606) derefs `vaArgs` as a pointer, `apiFormatMessageW` (~740) indexes it directly: pick the call-site convention that matches how the guest passes the array (verify against a real blob run), fix the other, note the decision in a comment.
- [ ] **Step 6: below4 fail-closed** — if every below-4 probe fails, return `false` from `GuestRegion::allocate` (caller already maps to `Fault::Allocation`); delete the fall-through `VirtualAlloc`.
- [ ] **Step 7: shellcode_file** — destructor: `if (_handle != INVALID_HANDLE_VALUE) CloseHandle(_handle);`
- [ ] **Step 8: Verify** — `python -m pytest tests/pytest -q` (Release) and `$env:SHELLTERP_CONFIG="Debug"; python -m pytest tests/pytest -q`. Expected: 74/74 both.

### Task 2: Bridge lifecycle + RVA collision (audit #9 #12 #13)

**Files:**
- Modify: `shellterpreter/native_bridge.cpp/hpp` (gSys → Loaded)
- Modify: `shellterpreter/vm.hpp` (Loaded gains syscall-table fields)
- Modify: `shellterpreter/cpu.hpp:2379` (syscallFnFor call site)
- Modify: `shellterpreter/api_standins.cpp` (apiFree ~865, gRandSeed ~318)
- Modify: `shellterpreter/guest_environment.hpp` (ST_GCURPROC move; new ST_* for Task 4)

**Interfaces:**
- Produces (later tasks + cpu.hpp rely on):
  - `Loaded.sysNum[2048] : uint32_t`, `Loaded.sysFn[2048] : void*`, `Loaded.sysCount : uint32_t = 0` — reset per run.
  - `void* syscallFnFor(const Loaded& l, uint32_t sysno)` (old global-table signature deleted).
  - `Loaded.randSeed : uint64_t = 0` (was `gRandSeed`).
  - `ST_GCURPROC = 0xC70` (kernel32 slack, was 0x1E00 == MSVCRT_RVA).

- [ ] **Step 1: move syscall table** — fields into `Loaded` (init `= 0`); `buildSyscallTable(Loaded&)` appends into `l.sysNum/l.sysFn/l.sysCount` starting at `l.sysCount = 0`; `syscallFnFor(const Loaded& l, uint32_t)` loops `l.sysCount`; update cpu.hpp:2379.
- [ ] **Step 2: apiFree** — `if (p && HeapValidate(GetProcessHeap(), 0, p)) HeapFree(GetProcessHeap(), 0, p); return 0;` — garbage pointers are ignored, never crashed on.
- [ ] **Step 3: randSeed** — `gRandSeed` → `l.randSeed` in apiSrand/apiRand; delete the global.
- [ ] **Step 4: ST_GCURPROC** — `0x1E00` → `0xC70` in `guest_environment.hpp`; update registration in api_standins.cpp.
- [ ] **Step 5: Verify** — full pytest Release + Debug, 74/74. Repeat-run check: run `08_cpp_thread` twice in one process? (not possible in one process via CLI; instead verify via test_iteration4 rand determinism — srand+rand sequence unchanged).

### Task 3: cpu string-op + arith fixes (audit #5 #6 #7)

**Files:**
- Modify: `shellterpreter/cpu.hpp:1723,1740` (cmps step size), `:1736,1753` (repne direction), `:881-882` (pextrd store width), `:2067-2077` (idiv overflow)

**Interfaces:**
- Produces: cmps steps by operand size (like movs at :1625); `repF2` cmps breaks when `zf` (opposite of rep); pextrd/pextrb mem store writes 1/4 bytes; idiv r64 checks `hi >= divisor` and `INT64_MIN / -1` → `Fault::UnsupportedInstruction`? No — real CPU raises #DE → fail closed with the div fault path the unsigned branch already uses (:2065).

- [ ] **Step 1: cmps step** — replace `stepv = ±1` with the operand-size step (mirror movs).
- [ ] **Step 2: repne cmps** — break condition: `repF2 ? zf : !zf`.
- [ ] **Step 3: pextrd** — `memSt<uint64_t>` → `memSt<uint32_t>` for the 32-bit form (881-882); check the pextrb neighbor too.
- [ ] **Step 4: idiv** — add the signed overflow check mirroring :2065.
- [ ] **Step 5: Verify** — pytest Release + Debug 74/74; run whoami blob (whose option-table parser exercises string ops) → correct stdout.

### Task 4: Thread/exit stubs on `Loaded` state (audit #14 follow-up; user request)

**Files:**
- Modify: `shellterpreter/guest_environment.hpp` (new ST_* constants, see below)
- Modify: `shellterpreter/api_standins.cpp` (new stand-ins + registration)
- Modify: `shellterpreter/vm.hpp` (ThreadContext gains `joinable` only if needed — prefer reusing `done`)

**Interfaces:**
- Produces (RVA table additions, all in free env range ≥ 0x1E58):
  - `ST_W4SO = 0x1E58` — WaitForSingleObject(handle, ms): handle ∈ `l.threads[0..threadCount)` → run join-driven `runThread`, return `WAIT_OBJECT_0 (0)`; unknown handle → `0xFFFFFFFF` (WAIT_FAILED), never a fault (Windows semantics).
  - `ST_EXITTHREAD = 0x1E60` — ExitThread(code): current thread's ThreadContext `exitCode = code`, `done = true`, halt thread execution.
  - `ST_GCTHREAD = 0x1E68` — GetCurrentThread → `(HANDLE)-2`.
  - `ST_SLEEP = 0x1E70` — Sleep(ms) → 0 (deterministic no-op).
- Consumes: `runThread(l, t)` existing signature (vm.hpp:135).

- [ ] **Step 1: ST_* constants + registration** in `registerApiStandins`.
- [ ] **Step 2: WaitForSingleObject** — match `_Thrd_join` join-driven semantics: look up handle in `l.threads`, `runThread`, return 0; unknown → WAIT_FAILED.
- [ ] **Step 3: ExitThread/Sleep/GetCurrentThread** — per signatures above.
- [ ] **Step 4: Verify** — pytest Release + Debug 74/74 (no behavior change on existing tests).

### Task 5: Real-binary + fault-coverage tests (audit #18)

**Files:**
- Create: `tests/pytest/test_realbin.py`
- Modify: `tests/pytest/test_iteration7.py:18` (TMP path → `tempfile.mkdtemp()`)
- Modify: `tests/pytest/test_build.py:16` (x86 test asserts x86 artifact)

**Interfaces:**
- Consumes: env var `SHELLTERP_BLOBS` (directory holding `ipconfig.shellcode`, `hostname.shellcode`, `whoami.shellcode`); tests `pytest.skip` when unset (CI-safe).
- Produces: `run_blob(name, args)` helper: subprocess `shellterpreter.exe <blob>`, returns (exitcode, stdout).

- [ ] **Step 1: TMP path fix** — `test_iteration7.py` uses `tempfile.TemporaryDirectory()` per session.
- [ ] **Step 2: test_build fix** — x86 test asserts `Win_x86/01_simple_calc.shellcode` exists.
- [ ] **Step 3: test_realbin.py** — `test_ipconfig_exit0`, `test_hostname_stdout` (regex `^[A-Za-z0-9\-]+$`), `test_whoami_stdout` (regex `^.+[\\\\/].+` or non-empty), each skipping without `SHELLTERP_BLOBS`; all assert exit == 0.
- [ ] **Step 4: Verify** — with `SHELLTERP_BLOBS` pointing at the temp opencode dir: 3 pass; without: 3 skip. Full suite green.

### Task 6: TEMP print removal + docs (audit #16 #19)

**Files:**
- Modify: `shellterpreter/cpu.hpp` (delete ~47 watch blocks lines 58-3535: TBLW/LDF/EHRES/STKRSP/STKARG/TJPUSH/APIFLT/DISPFLT/TRAMP/WRAP/WRAPMEM/SLOT444/WRAP2/GLUE/BA4C/BYTES9278/WHO/DESC/SCRT/WATCH1933/NATRSP/NAT/NATR/IAT0/FAULTRING/state-dump/ring; delete `iatDumped`, `stkEnd`, static `traceRing`)
- Modify: `shellterpreter/api_standins.cpp` (delete LDA/GP/GPA0/GPA/INITERM/IAT0E/IATW/MCOPY/MSET/MODFNW/FMT/WGA*/dead ucrtbase branch ~75-81)
- Modify: `shellterpreter/native_bridge.cpp:34` (TRC REG)
- Modify: `shellterpreter/main.cpp:14-26,81` (delete vehTriage + AddVectoredExceptionHandler)
- Modify: `shellterpreter/vm.hpp:114-116` (delete ipRing/ipRingIdx)
- Rewrite: `PLAN.md` (iterations 8-14 + batch G, current architecture, exit table with 0xE000000A; drop PeReader/MZ-scan claims)
- Modify: `README.md:103` (range sentence includes 0xE000000A)

- [ ] **Step 1: delete all TEMP prints** — keep exactly the 5 fault diagnostics; verify with `grep -c TRC shellterpreter/*.cpp shellterpreter/*.hpp` → 0.
- [ ] **Step 2: regenerate PLAN.md** to match code + README.
- [ ] **Step 3: Verify** — pytest Release + Debug 74/74 + real-binary smoke (whoami/ipconfig/hostname exit 0, correct stdout).

### Task 7: Gate + commit

- [ ] **Step 1:** 4-config Rebuild: `msbuild shellterpreter.sln -t:Rebuild -p:Configuration=Release -p:Platform=x64` (repeat x86, Debug x64, Debug Win32) — zero errors.
- [ ] **Step 2:** pytest Release AND Debug: 74/74 + new tests.
- [ ] **Step 3:** ledger entry in `.sdd/ledger.md` (Batch H: fixes, stubs, tests, print removal).
- [ ] **Step 4:** one commit, push.
- [ ] **Step 5:** delete stray root artifacts `x87test.obj`, `d.obj` (untracked, disk-only).

**Skipped on purpose (recorded, not in this batch):**
- Audit #15: ntdll-header validation in `buildSyscallTable` + narrower `__except` — host-controlled input, low risk.
- Audit #17: runLoop/step()/dispatchFrom structural splits — no behavior change, high diff cost.
- `apiBeginThread` CREATE_SUSPENDED + 8-thread-cap silent 0 — no real binary needs it yet.
- README/PLAN drift items beyond the exit-table line (full PLAN.md rewrite covers #19).
