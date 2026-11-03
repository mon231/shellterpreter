# Modular Class Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite shellterpreter to the CON­TRIBUTING.md conventions (RAII
classes, no namespaces, template CPU core, snake_case full names) without
any behavior change.

**Architecture:** Extract one module from the current 4 .cpp / 4 .hpp layout
per task, keep the remaining code working, and move the two CPU cores into a
shared `Cpu<Architecture>` template last (sub-steps: decoder first, then
execute). Every task ends with all 4 msbuild configs built and pytest green
in Release AND Debug, then one commit.

**Tech Stack:** C++23 (MSVC 18, x64+x86), Win32, pytest.

**Spec:** `docs/superpowers/specs/2026-11-03-modular-class-rewrite-design.md`
plus `CONTRIBUTING.md` (naming/style rules are constraints, not suggestions).

## Global Constraints

- Conventions (CONTRIBUTING.md): no namespaces, no `inline` functions, RAII
  everywhere, rule of 3/5, `std::unique_ptr`, fields `_`-prefixed, snake_case,
  full names (`index`, `instruction`, `context`), one class per file,
  declarations in headers, least duplication, `std::variant` instead of the
  malformed `OpRm`.
- Behavior never changes: fault codes 0xE0000001..0xE0000009, exit = low32
  of RAX/EAX, `hlt` ends the stub chain, RW-only memory audit, fail-closed
  stand-ins.
- Every task: build all 4 configs (Release/Debug x x64/x86, msbuild sln
  `/t:Rebuild` or per-config), run `python -m pytest tests\pytest -q` with
  and without `SHELLTERP_CONFIG=Debug`; only then commit.
- Debug builds need `/INCREMENTAL:NO`; msbuild lives at
  `C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe`.

## Review Focus

- The two decoders share ~90% logic but differ in REX/segment/size rules;
  any copy-paste between them must land in the shared template instead.
  Test: full pytest suite after each decode step.
- `std::variant` operand must preserve the exact `ea` evaluation order and
  `fault` propagation the hand-rolled `OpRm` had. Test: 01/03/04/05 tests.
- Stand-in ABI (x86 stdcall ret+N vs x64 caller-cleans, `nargs` counting)
  must survive the ApiTable rewrite. Test: 04, 05, 08 tests.
- File/PE loader rewrite must keep detecting the peor blob MZ at file 0x320
  with decoys at 0xC5/0x192/0xD9/0x19F. Test: 02, 03, 05 dual-arch tests.
- RAII regions must free in the same order/paths `freeLoaded` did (image,
  stack, env, heap, thread stacks). Test: build + audit test in
  test_iteration1.py and leak-free repeat runs of 08.

## Tasks

### Task 1: fault module

**Files:** Create `shellterpreter/fault.hpp`, `shellterpreter/fault.cpp`;
Delete the Fault enum + faultMessage from `vm.hpp`/`main.cpp` (moved).

**Interfaces:** Produces `enum class Fault : uint32_t` with the same
constant values, `uint32_t fault_code(Fault)`, `std::string fault_message
(uint32_t)`. Existing call sites switch to it. No test change expected.

Steps: move enum (rename constants to kUnsupported/kOob/... snake_case k
prefix; keep values) - build 4 configs - pytest both configs - commit
`refactor: fault module`.

### Task 2: ShellcodeFile + PeReader

**Files:** Create `shellterpreter/shellcode_file.hpp/.cpp` (class
ShellcodeFile: RAII HANDLE, ReadFile into std::vector<uint8_t>), `shellterpreter/pe_reader.hpp/.cpp` (class PeReader scanning MZ/PE with decoy rules,
fields `_image_offset`, `_entry_rva`, `_image_base`, `_size_of_image`,
`_is_dll`, `_is_64`); Modify `main.cpp` (loadShellcode uses the classes).

Interfaces: `ShellcodeFile::open(const std::string& path)` returning
`std::unique_ptr<ShellcodeFile>` or bool + `data()/size()`; `bool
PeReader::scan(const std::vector<uint8_t>&, bool force86)`. Kill
`loadShellcode`'s C-file open. Test: pytest both configs (02/03/05 prove
the decoy scan and arch pick).

### Task 3: GuestRegion (RAII memory)

**Files:** Create `shellterpreter/guest_region.hpp/.cpp` (class GuestRegion
with static functions for Reserved/Commit, rules of 3/5 deleted copy;
`base()`, `length()`); Modify loader + vm64/vm86 region plumbing to hold
regions instead of raw pointers (temporary bridging fields in Loaded).

Test: pytest both configs + leak check `!heapinfo`. Commit
`refactor: RAII guest regions`.

### Task 4: GuestEnvironment + ApiTable stand-ins

**Files:** Create `shellterpreter/guest_environment.hpp/.cpp` (build_teb/
peb/ldr/mock_kernel32 layout writer from export_resolver.cpp),
`shellterpreter/api_table.hpp/.cpp` (ApiEntry class, ApiTable::resolve),
`shellterpreter/api_standins.hpp/.cpp` (stand-in functions grouped:
thread/memory/crt/startup); Delete `export_resolver.*`.

Interfaces: `ApiTable::resolve(address) -> const ApiEntry*` mimics
lookupApi; stand-in signature stays `uint64_t name(Interpreter& context,
const uint64_t* arguments)` with the Interpreter owning regions.

Test: pytest both configs (04/05/08 cover stdcall/cdecl ABI).

### Task 5: Operand via std::variant + InstructionDecoder split

**Files:** Create `shellterpreter/operand.hpp/.cpp` (class Operand:
`std::variant<RegisterRef, MemoryRef, Immediate>`; replaces OpRm), `shellterpreter/instruction_decoder.hpp/.cpp` (prefix scan + modrm under
decodeRm); vm64/vm86 include and use.

Decoder stays arch-tagged (template constructor parameter) so both cores
dedupe. Test: pytest both configs after each core migrates.

### Task 6: Cpu<Architecture> template absorbs the cores

**Files:** Create `shellterpreter/cpu.hpp/.cpp` template class Cpu with
static Architecture64/Architecture86 config classes (register count,
fetch/ea rules, hlt/exit path, CPUID), files `cpu64.cpp`/`cpu86.cpp` only
holding config instantiations; Delete `vm64.cpp`/`vm86.cpp` contents into
the shared core (op groups move in order: ALU, mov, jcc/call/ret, strings,
SSE, bit ops, misc). Sub-steps, each pytest green and a commit:
a. state/flags/run-loop shared, execute dispatch still per-arch copies;
b. ALU+jcc/call/ret deduped; c. remaining opcode groups deduped; d. old
files deleted.

### Task 7: Thread + Audit + main sweep

**Files:** Create `shellterpreter/thread.hpp/.cpp` (ThreadContext class),
`shellterpreter/audit_ray/audit.hpp/.cpp` (RAII snapshot class), rewrite
`main.cpp` to use ShellcodeFile/PeReader/Cpu; update vcxproj file lists;
Delete leftovers; final: pytest both configs, 20x repeat runs of 08/05, commit `refactor: modular class layout`.

Self-review note: plan is interface-level on purpose; exact bodies come
from the moved code so behavior does not drift.
