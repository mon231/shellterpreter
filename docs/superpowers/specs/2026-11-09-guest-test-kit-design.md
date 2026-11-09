# Guest test kit redesign (tests)

## Intent

Today's debugging of `test_iteration14` started with a helper bug, not a
product bug: each keystone test file carries a private copy of
`_blob`/`_run_case`/`_exit_code`/`_x86asm`, and the copies have drifted —
iteration14 silently generated an x86 blob for an x64-only case, ran the
known-unsupported `syscall` on x86, and the failure read like a broken
native bridge. The gotchas that keep biting (x86 stdcall needs an explicit
`push <arg>`, `asm86=None` meaning "skip" vs "fallback", TEB-handshake
prelude, descriptor/scratch placement) live only as prose in
`.sdd/ledger.md`.

## Goals

- One shared guest-test kit, `tests/pytest/guestkit.py`, owning:
  assembly (keystone), prepended prologue + `hlt` tail, both-arch running,
  Win exit-code conversion, string-puts helper, syscall-number helper.
- Cases declare arch coverage explicitly: `asm86=None` means **skip x86**;
  the old write-x86-asm-for-me fallback disappears (every current fallback
  in iteration11-14 either mirrors trivial reg renames or is the bug).
- The stdcall gotcha becomes code: a helper builds x86 calls that always
  push args in reverse before `call`, so a case cannot assemble a
  register-passed stdcall call by accident.
- History keeps reading as iterations: `test_iterationN.py` files stay,
  only their private helpers go.

## Non-goals / Anti-goals

- No product-code changes; test-only batch.
- No pytest restructure into new suite names or parametrized fixtures in
  this batch (a later, optional step) — churn stays proportional to the
  hurt.
- No behavior change to what is asserted; the suite must stay exactly as
  strict as before (74 cases, Release + Debug green).

## Approaches considered

1. **Shared guest kit** (chosen): one module, migrate the four files,
   delete private copies. Fixes the drift at the root; medium, test-only.
2. Minimal unification: align skip semantics per file, copy gotcha
   comments. Cheapest; drift returns with the next new test file.
3. Full restructure: feature-named suites + `parametrize` over arch.
   Cleanest long-term, too much churn mid-stream before the shellcode
   corpus work lands.

## Left to the builder

- Migrate `test_iteration11/12/13/14.py` onto the kit; behavior-preserving,
  same case names, same expectations.
- `test_iteration12` keeps its own conditional-fallback block only if a
  case genuinely depends on it — otherwise mirror `None`-means-skip.
- Keep `pytest Release` and `pytest SHELLTERP_CONFIG=Debug` both fully
  green; Suite must reach the same pass counts as before the change.
