# Provenance Draft: noscope-ydn

## Thread Message (for requirement jn7dcw8ce9gxw6v4p9p1k44jex83vgsn)

Implemented the provider command execution contract in `src/provider_exec.rs`.

All 11 rules are covered with 78 tests:

- **NS-009**: `parse_provider_output()` extracts JSON `token` (required, string) and `expires_at` (optional, ISO 8601). Invalid JSON, missing token, non-string token, empty token, and invalid ISO 8601 dates are all rejected with actionable error messages.

- **NS-033**: `validate_role()` enforces alphanumeric+hyphens+underscores+dots only. `substitute_template_vars()` performs pure argv array string replacement — no shell involved. Tests verify shell metacharacters, backticks, command substitution, pipes, spaces, slashes, and non-ASCII are all rejected.

- **NS-034**: When `expires_at` is absent (including JSON null), `parse_provider_output()` computes `now() + requested_ttl` and sets `expires_at_provided = false` so the caller can emit a warning.

- **NS-035**: `ExecConfig` defaults to 30s timeout and 5s SIGTERM-to-SIGKILL grace period. `ProviderExecError::Timeout` maps to exit code 4 (Unavailable).

- **NS-036**: `check_stdout_size_limit()` rejects output exceeding `MAX_STDOUT_BYTES` (1 MiB = 1,048,576 bytes). Boundary tested at exactly 1 MiB and 1 MiB + 1.

- **NS-037**: `substitute_template_vars()` formats TTL as integer seconds string. Tests verify no human-duration suffixes.

- **NS-038**: `build_revoke_env()` sets NOSCOPE_TOKEN and NOSCOPE_TOKEN_ID. Does NOT set NOSCOPE_TTL. `is_revoke_success()` treats exit 0 as success (including already-revoked).

- **NS-039**: `build_refresh_env()` sets NOSCOPE_TOKEN, NOSCOPE_TOKEN_ID, and NOSCOPE_TTL (integer seconds). Refresh output uses same JSON contract as mint.

- **NS-040**: `capture_stderr()` truncates to 4096 bytes at safe UTF-8 boundary. `redact_stderr()` replaces known token values with `[redacted]`. `StderrPolicy` encodes discard-on-success/keep-on-failure/keep-on-verbose logic.

- **NS-041**: `ProviderCapabilities` struct with `supports_refresh`/`supports_revoke` booleans. `parse_capabilities_from_toml()` defaults absent values to false. `validate_capabilities()` rejects supports_X=true without corresponding command.

- **NS-068**: `build_sandboxed_env()` creates a HashMap with exactly PATH, HOME, LANG from current env with fallback defaults. Tests verify no other env vars leak through.

Security note: `ProviderOutput` implements `Drop` to zeroize the token string, matching the `MintEnvelope` pattern from `mint.rs`.
