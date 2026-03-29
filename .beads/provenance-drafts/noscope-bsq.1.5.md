# Provenance Draft: noscope-bsq.1.5

## Thread Message (for requirement noscope-bsq.1.5)

Converged on `error::Error` as the single canonical public error type.

The crate previously exported two overlapping error types:
- `client::NoscopeError` — a simple enum with string-only variants (Usage, Config, MintFailed, Security, Profile)
- `error::Error` + `ErrorKind` — a richer typed error with kind(), provider_name(), errors() (multi-error), source chaining, and From conversions from all module errors

Resolution: `error::Error` is now the sole canonical type. `NoscopeError` is retained as a `pub type NoscopeError = Error` alias for backward compatibility.

Changes made:
1. Removed the `NoscopeError` enum and all its `From` impls from `client.rs`
2. Updated `Client` methods to return `error::Error` instead of `NoscopeError`
3. Updated `cli_adapter` functions to return `error::Error` instead of `NoscopeError`
4. Added `pub type NoscopeError = Error` in `lib.rs` with migration documentation
5. Updated all existing tests to use the canonical error API
6. Added 31 convergence tests proving:
   - No split-brain: NoscopeError is an alias for Error
   - Facade layer (Client) uses Error consistently
   - Adapter layer (cli_adapter) uses Error consistently
   - All exit codes remain stable
   - All From conversions still work
   - Backward compatibility maintained

Exit-code behavior is fully preserved:
- Usage → 64, Config → 78, Provider → 65, Security → 64, Profile → 66, Internal → 70

## New Artifacts (if any)
- type: resolution
  content: Canonical error type is error::Error. NoscopeError is a backward-compatible type alias. Old NoscopeError::MintFailed maps to ErrorKind::Provider (same exit code 65).
