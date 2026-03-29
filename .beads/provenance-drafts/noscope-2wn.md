# Provenance Draft: noscope-2wn

## Thread Message (for requirement jn78wxpmbj1kegw5c8qv05nmzn83tbgd)

Implemented multi-credential minting infrastructure in `src/credential_set.rs`.

All 7 rules covered with dedicated tests (57 total tests in the module):

- **NS-006**: `resolve_mint_results()` — atomic all-or-nothing semantics. On any failure, returns succeeded tokens for rollback.
- **NS-045**: `validate_env_key_uniqueness()` — rejects duplicate env_keys, identifies all conflicting providers. Called by `validate_credential_specs()` before minting.
- **NS-046**: `MintConfig` with configurable `per_provider_timeout` (default 30s). `format_timeout_error()` for error reporting.
- **NS-047**: `RollbackBudget` with timeout/retry policy. `RollbackLogEntry` with credential ID + TTL in log output. Error messages escaped.
- **NS-048**: `compute_refresh_at()` — per-credential refresh based on individual expires_at. `CredentialSet::refresh_schedules()` returns independent schedules. No batching.
- **NS-049**: `ExpiryPolicy::on_credential_expired()` — always returns `LogWarning`, never `TerminateChild` or `ReMint`.
- **NS-050**: `MintConfig::max_concurrent` (default 8, configurable, rejects 0).

Design decisions:
- `CredentialSet` is not Clone, not Serialize (secrets inside)
- Debug impl redacts secrets (NS-005 compliance)
- `MintResult` enum with Success/Failure variants for clean result collection
- `ExpiryAction::TerminateChild` and `ReMint` exist as negative constraints only (same pattern as `RefreshAction::KillChild`)
- `CredentialSetError::MintFailed` carries `succeeded_tokens: Vec<ScopedToken>` so caller can revoke during rollback
