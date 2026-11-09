# Hardening: native-bridge fail-closed surface + CONTRIBUTING force rules

## Intent

Two deliverables, one batch:

1. **Hardening of the native-bridge / whole-memory surface** — the audit found
   three spots where untrusted or edge memory lay under a raw trust path:
   - `registerModules` parses each module's PE header with raw derefs
     (`base + 0x3C`, `nt + 0x50`), unbounded and unguarded; a corrupt header
     crashes the interpreter at init instead of skipping the module.
   - Module `SizeOfImage` is copied into `ModuleRange.end` unchecked; an
     absurd value widens the bridge-eligible range beyond the actual module.
   - `hostPageAddr` strips `PAGE_GUARD` (`prot & ~PAGE_GUARD`) and then classifies
     the page — a guest touch of a guard page then raises an uncaught
     STATUS_GUARD_PAGE_VIOLATION (process abort), not the fail-closed fault.
2. **CONTRIBUTING.md gains non-optional structure rules**: RAII forced, small
   functions, small modules, split to classes and files. These become review
   gates, not style preferences.

## Goals

- Use `GetModuleInformation` for module base/size instead of hand-parsed PE
  headers (root cause of #1 and #2; the loader hands the numbers over).
- Fail closed on guard pages and no-access pages in `hostPageAddr`.
- Guest-visible behavior otherwise unchanged; new faults stay within the
  existing code set (`0xE0000002` outside-memory / `0xE000000A` NativeFault).
- Value tests pin the guard-page fix and the reserve-only fallback
  (test_iteration14 kit cases).

## Non-goals

- No new fault codes; no bridge ABI changes; no x86 bridge rework.
- No CONTRIBUTING reorganization beyond the new mandatory section (the
  existing text stays).
- No repo-wide compliance sweep in this batch (a later, optional batch).

## Approaches considered

1. **Loader API + fail-closed guard pages** (chosen): smallest, removes the
   entire hand-parse path; guard/page-protect fixes are two conditions in one
   helper.
2. Wrap the PE parse in `__try` and keep it: keeps dead code and still trusts
   hand-made offsets.
3. Whitelist only module "image + entry header check": narrower but rejects
   valid odd modules without naming why.
