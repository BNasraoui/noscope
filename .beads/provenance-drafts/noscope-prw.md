# Provenance Draft: noscope-prw

## Thread Message (for requirement NS-058)
Addressed a credential redaction leak in `ProviderOutput` debug formatting. Replaced derived `Debug` with a manual `fmt::Debug` implementation that wraps `token` with `RedactedToken`, preserving visibility for non-secret fields (`expires_at`, `expires_at_provided`) while preventing raw token disclosure. Added NS-058-focused tests proving raw tokens are never present in debug output, including a short-token edge case, and validated with `cargo test ns_058_provider_output_debug`.

## New Artifacts (if any)
- none
