# CONTRIBUTING.md - C++ conventions for shellterpreter

The compiler must not see namespaces and lazy shortcuts. The reviewer sees
classes, RAII and honest names. Read this before you touch any source file.

## Structure

- Split the project into modules and files so each file has one reason to
  exist. One class per file is the default; group only tightly coupled
  small classes.
- Declarations belong in header files. Implementations belong in .cpp files.
- Every file carries `#pragma once` guards.

## Style

- **No namespaces.** Flat global scope, class scope only.
- **No `inline` on functions.** Let the linker do its job.
- **Classes with public/private/protected.** Private members are the
  default; expose only what a caller needs. Static member functions where
  the logic does not need an instance.
- **Fields start with `_`.** Example: `_image_base`, `_exit_code`. Function
  parameters and locals do not get the prefix.
- **snake_case everywhere**: fields, variables, arguments, function names,
  file names. Types/FileName stay PascalCase (`VirtualMemory`, `OpcodeDecoder`).

## Naming

- Use full, honest names: `index` not `idx`, `zero_flag` not `zf`,
  `register_index` not `reg`, `instruction` not `instr`,
  `context` not `ctx`. A short loop counter `i` is fine.
- Never use meaningless names such as `v`. Name the thing what it is.

## Resources

- RAII everywhere. Every handle, allocation and mapping lives in a class
  with a destructor that releases it (`CloseHandle` in the destructor of a
  `Handle` class, `ReadFile` behind a `File` class, ...). Rule of 3 / rule
  of 5: deleting, copying or moving one of them means define all of them.
- `std::unique_ptr` for ownership. No unsafe raw owning pointers.
- Templates are allowed where they remove duplication (for example one CPU
  core class parameterized by architecture).

## Macros

- Repetitive guard patterns become macros. Examples from this codebase:
  - `RETURN_ON_FAULT(field)` for `if (_fault != Fault::None) { return _fault; }`
  - per-opcode decode boilerplate inside the CPU cores.
- Keep each macro local to the file that needs it, `#undef` after use unless
  it is a deliberate cross-file utility.

## Refactoring rules (learned from this codebase)

- Behavior-preserving refactors run the full pytest gate (Release AND Debug)
  before commit; the suite is the correctness proof, not eyeballing the diff.
- No temp debug prints (`dbg0`, `[dbg]`, `DBG64`, `DBG86-value`, ...)
  in committed code.
- A deliberate simplification gets a `shortcut: <limit>, <when to upgrade>`
  comment naming the ceiling and the upgrade path.
- Fix root causes once in shared code: a bug fixed on one CPU core gets
  checked for the same root cause on the other before the fix is merged
  into one implementation.
- Fail closed: missing API resolution, unwinding or unknown state returns a
  fault code, never a silent zero.

## C++

- Use the language: `std::variant` instead of a malformed non-union struct
  (the old `OpRm`), `std::vector`, `std::string_view`, `std::optional`,
  `enum class` for code constants, no new-then-delete by hand.
- Repetitive or parsing logic becomes a function. If the repetition is
  textual (per-opcode boilerplate), a macro is acceptable - keep it local
  and `#undef` it after use.
- Aim for the least possible code duplication. Two CPU cores are one
  template, not two copies.

## Process

- Tests first where practical: the pytest suite (`tests/pytest`) must pass
  in Release AND Debug before every commit.
- No temp debug prints (`dbg0`, `[dbg]`, `DBG64`, ...) in committed code.
- Comments explain why, not what.
