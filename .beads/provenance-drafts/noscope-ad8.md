# Provenance Draft: noscope-ad8
## Thread Message (for requirement )
Implemented end-to-end `cmd_run` wiring in `src/main.rs` so `noscope run` now executes the real runtime path instead of placeholder behavior.

Key changes:
- Resolve providers from either explicit CLI args or a selected profile (`--profile`) using existing facade/config loading flows.
- Build credential specs and mint through `orchestrator::mint_all` with provider command execution and token conversion.
- Inject minted credential environment variables into the child process and execute child through `integration_runtime::run_child_and_pass_exit`.
- Wait for child termination and return the exact child exit code.
- Revoke all minted credentials after child completion, and also revoke on child spawn failure to avoid leaked credentials.
- Preserve existing revoke wiring by delegating revoke calls through `execute_revoke`.

TDD notes:
- Added dedicated `run_wiring_tests` in `src/main.rs` for each required rule: provider resolution (CLI and profile), mint-before-spawn ordering, env injection, child exit passthrough, and revoke-all behavior.
- Added a self-review follow-up test for child spawn failure (`run_revokes_credentials_if_child_fails_to_spawn`) and fixed implementation to revoke in that path.
- Confirmed red -> green progression for run wiring tests.

## New Artifacts (if any)
- type: rule
  content: `cmd_run` must revoke all minted credentials even if child spawn fails after minting.
