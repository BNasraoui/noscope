# Provenance Draft: noscope-bsq.1.4

## Thread Message (for requirement NS-020)

Resolved the API bug where `Client::new` silently swallowed `disable_core_dumps()` failures via `let _ =`.

Changes made:
- `Client::new()` now returns `Result<Self, NoscopeError>`, propagating
  `SecurityError::CoreDumpDisableFailed` through the existing `From` conversion.
- Added `Client::new_best_effort()` as a backwards-compatible migration path
  that preserves the old silent-ignore behavior.
- 11 new tests covering: fallible constructor, success path, error variant
  mapping, exit code, backwards-compatible constructor, Linux success,
  programmatic detection via pattern match, and human-readable Display.
- Public API docs updated on both constructors with `# Errors` section.

The `?` operator on `security::disable_core_dumps()` works naturally because
`From<SecurityError> for NoscopeError` already existed (maps to
`NoscopeError::Security`). No new error types were needed.

## New Artifacts (if any)
- type: resolution
  content: NS-020 hardening failures are now surfaced to callers via Client::new() returning Result. Backwards compatibility preserved via Client::new_best_effort().
