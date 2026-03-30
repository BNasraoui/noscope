# Provenance Draft: noscope-4in
## Thread Message (for requirement )
Implemented CLI wiring for `noscope mint` end-to-end through the orchestrator path.

Key changes:
- `cmd_mint` now validates terminal safety (NS-065) via `Client::check_stdout_not_terminal` before writing tokens.
- Provider configs are resolved through the existing facade for all requested `--provider` values.
- Mint operations execute via `orchestrator::mint_all` and return `MintResult` per provider.
- Successful results are rendered through `format_orchestrator_output` and written to stdout as JSON envelope array output.
- Failure path preserves atomic behavior: provider failure yields non-zero exit and no partial stdout.
- Added role/ttl template substitution for provider argv (`{role}`, `{ttl}`) before command execution.

TDD notes:
- Added integration tests in `tests/cmd_mint_wiring.rs` for JSON stdout wiring, multi-provider resolution, atomic failure behavior, NS-065 tty rejection, NS-065 force override, and template substitution.
- Confirmed red -> green cycle for the new tests.

## New Artifacts (if any)
- type: rule
  content: CLI mint must route through orchestrator and emit `format_orchestrator_output` JSON to stdout (no placeholder output).
