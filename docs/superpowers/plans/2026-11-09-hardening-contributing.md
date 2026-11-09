# Hardening + CONTRIBUTING force rules — plan

**Spec:** `docs/superpowers/specs/2026-11-09-hardening-contributing-design.md`

## Task 1: native_bridge.cpp fail-closed init

- Register modules via `PSAPI_VERSION 1` `GetModuleInformation` (kernel32
  export, no psapi.lib dependency), wrapped so a failure path skips the
  module instead of crashing init.
- Range sanity: `sizeOfImage >= 0x1000 && <= 0x10000000` (256 MB) else skip.
- Guard/NOACCESS rejected in `cpu.hpp:hostPageAddr` (no more `~PAGE_GUARD`).

## Task 2: value tests (test_iteration14.py, kit)

- `wholememory_guardpage_faults`: guest `VirtualAlloc(PAGE_GUARD)` then a
  guest read of that page must exit `0xE0000002` (pre-fix: process abort).
- `wholememory_reserve_read_faults`: `VirtualAlloc(MEM_RESERVE)` then a guest
  read of the reserved page must exit `0xE0000002`.

## Task 3: CONTRIBUTING.md mandatory rules

New section "Mandatory structure (non-negotiable)": RAII forced (every
resource in a class with a destructor; no raw owning pointers, no manual
delete in main flow), one job per function (one screen max, split when a
second concept appears), one responsibility per file pair (split when a
file needs two reasons to exist or outgrows a screen of scroll), helper
structs + their functions become classes.

## Gate + commit

- pytest Release + Debug (74 + 2 new), 4-config Rebuild, ledger entry,
  `git add` the touched files + docs, commit.
