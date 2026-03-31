# Provenance Draft: noscope-4mw

## Thread Message (for requirement jn72kkrbwj1gk2k10zxsqz13d583vws2)

Implemented provider discovery and configuration module (`src/provider.rs`) covering all 7 rules:

- **NS-007** (Strict config precedence): Three-layer resolution — flags > env vars > config files. No merging across layers; the highest-precedence layer with any value wins entirely. Tested with 4 dedicated precedence tests including no-merging scenarios.

- **NS-042** (XDG Base Directory): Config paths resolve under `XDG_CONFIG_HOME/noscope/providers/<name>.toml` with fallback to `~/.config/noscope/providers/<name>.toml`. Extracted `provider_toml_under()` helper to eliminate path-building duplication.

- **NS-043** (Malformed config is hard error): TOML syntax errors and missing required fields (`commands.mint`) return `ProviderConfigError::MalformedConfig`. Empty mint_cmd is also rejected. Missing file returns `Ok(None)` — layer absent, not error.

- **NS-044** (Provider not found enumerates locations): When no layer provides config, the error lists all checked locations: flag name (`--mint-cmd`), env var name (`NOSCOPE_MINT_CMD`), and file path. Sufficient for user self-diagnosis.

- **NS-069** (Config file permission enforcement): Rejects files with any "other" permission bits set (world-readable/writable/executable). Allows 0600, 0640, 0400, etc. Integrated into `load_provider_file()` pipeline.

- **NS-071** (Dry-run mode): `dry_run_output()` produces structured output showing provider name, config source, mint/refresh/revoke commands, role, TTL, and environment variables — without executing anything.

- **NS-073** (Provider validation command): `validate_provider()` checks that all configured commands (mint, refresh, revoke) exist on disk and have execute permission. Does NOT execute commands — verified by marker-file test.

38 tests total (29 rule-dedicated + 9 edge-case tests from self-review). Zero clippy warnings. TDD workflow followed strictly: tests written first, all 29 failed (RED), minimal code to pass (GREEN), refactored, self-reviewed as Linus Torvalds.

Design note: `resolve_provider_config()` takes pre-parsed layers rather than reading env/filesystem directly, making it fully testable without process-global side effects.
