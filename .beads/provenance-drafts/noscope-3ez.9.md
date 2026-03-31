# Provenance Draft: noscope-3ez.9

## Thread Message (for requirement noscope-3ez.9)

Implemented `validate` command wiring so CLI validation now performs provider command readiness checks instead of only config resolution.

- Updated `cmd_validate` in `src/main.rs` to call `noscope::provider::validate_provider(&resolved)?` after `resolve_provider(...)`.
- Added wiring tests in `src/main.rs` that prove command-level behavior:
  - `validate_command_performs_provider_executable_validation` ensures `noscope validate` fails when `NOSCOPE_MINT_CMD` points to a non-executable file.
  - `validate_command_error_is_actionable_for_operator` ensures the surfaced error mentions both the failing command type (`mint`) and concrete command path.
- Tests were written first and failed before production changes (RED), then passed after minimal implementation (GREEN).
- Verified full quality gates: `cargo test -q` and `cargo clippy --all-targets -- -D warnings` both pass.

Operator impact: `noscope validate` now reports real provider executable readiness and returns actionable failures before runtime use.
