# Provenance Draft: noscope-s9i
## Thread Message (for requirement )
Implemented hygiene cleanup for module boundaries and test placement.

- `ci_checks` is no longer publicly exported from crate root in non-test builds; `src/lib.rs` now wires it as `#[cfg(test)] mod ci_checks;`.
- Signal policy unit tests were moved from `tests/signal_handling_policy.rs` into `src/signal_policy.rs` under a `#[cfg(test)] mod tests` block to align with unit-test conventions.
- Added guard tests in `src/lib.rs` (`module_hygiene_tests`) to enforce both constraints and prevent regressions.

## New Artifacts (if any)
- type: rule
  content: Test-only helper modules must not be exported as public modules from crate root in release builds.
- type: rule
  content: Unit tests that exercise module internals without integration boundaries must live alongside the module under `#[cfg(test)]`.
