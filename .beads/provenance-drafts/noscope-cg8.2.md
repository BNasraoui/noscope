# Provenance Draft: noscope-cg8.2

## Thread Message (for requirement noscope-cg8.2)

Implemented the separation of CLI argument concerns from the core library.

### Changes Made

1. **New module `src/cli_adapter.rs`**: Dedicated adapter layer containing:
   - `validate_revoke_argv()`: Scans raw argv for `--token` flags (NS-012). Moved from `Client::validate_revoke_args()`.
   - `validate_mint_flags()`: Bridges CLI flags (`Option<u64>` for `--ttl`) to domain `MintRequest`. Wraps `mint::validate_mint_args()`.
   - `check_profile_flag_exclusion()`: NS-053 mutual exclusion check between `--profile` and credential flags. Wraps `profile::check_profile_flag_exclusion()`.

2. **Removed `Client::validate_revoke_args(&self, args: &[String])`**: This method accepted raw argv slices — a CLI concern that doesn't belong on the core `Client` type. Library consumers use `RevokeRequest::from_token_id()` or `RevokeRequest::from_mint_json()` (domain types) instead.

3. **Added `#[derive(Debug)]` to `MintRequest`**: Domain types should be debuggable for diagnostics.

4. **Updated existing tests**: The `client.rs` tests that used the removed method now delegate to `cli_adapter::validate_revoke_argv()`.

### Acceptance Criteria Coverage

- **Core crate APIs accept domain inputs, not raw argv slices**: `Client` no longer has `validate_revoke_args(&[String])`. Library consumers use `MintRequest`, `RevokeRequest`, `Profile` — domain types.
- **CLI-specific parsing/validation lives in a dedicated adapter layer**: `cli_adapter` module provides `validate_revoke_argv`, `validate_mint_flags`, and `check_profile_flag_exclusion`.
- **Backward-compatible migration path documented**: Module header documents the migration from old call sites to new adapter functions. The underlying `mint::validate_revoke_args` and `profile::check_profile_flag_exclusion` remain available for callers who already have parsed values.

### Test Coverage

- 26 new tests in `cli_adapter::tests` covering all three acceptance criteria
- 558 total tests passing (3 net new after test consolidation)
- Zero clippy warnings
