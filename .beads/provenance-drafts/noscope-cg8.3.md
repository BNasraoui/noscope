# Provenance Draft: noscope-cg8.3

## Thread Message (for requirement jn79b26tr04yrxt7bt2hna1j4h83vnes)

Implemented NS-078 (centralized token conversion boundaries) via new
`token_convert` module. The module defines the canonical conversion pipeline:
ProviderOutput -> ScopedToken -> MintEnvelope.

Three conversion functions centralize all cross-type secret transitions:
- `provider_output_to_scoped_token`: consumes ProviderOutput, clones raw
  token into SecretString. Both copies independently zeroized (NS-019).
- `provider_output_to_scoped_token_with_metadata`: same as above but
  preserves `expires_at_provided` flag for NS-034 warning emission.
- `scoped_token_to_mint_envelope`: borrows ScopedToken, calls
  expose_secret() explicitly (NS-064), delegates to MintEnvelope::from_scoped_token.

Acceptance verified with 20 tests covering:
1. Centralized conversions (7 tests): field preservation through pipeline
2. Unified serialization (2 tests): single/multi envelope field set identity
3. Secret boundary guarantees (8 tests): ownership semantics, zeroization,
   non-Serialize/non-Clone invariants, redacted Debug output
4. Metadata preservation (3 tests): expires_at_provided flag, ConversionResult access

## New Artifacts (if any)
- type: resolution
  content: NS-078 implemented in src/token_convert.rs. All three acceptance
  criteria satisfied. No existing module interfaces changed (backward compatible).
  Re-exported from crate root for ergonomic access.
