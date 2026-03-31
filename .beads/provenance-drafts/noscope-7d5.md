# noscope-7d5 provenance notes

## Scope

Implemented NS-070 runtime event emission wiring so structured events are emitted from real execution paths, not just formatted in isolation.

## What changed

- Added runtime emitter installation in `cmd_run` using `--log-format` (`text` default, `json` optional).
- Added event emission for mint lifecycle in `orchestrator::mint_all`:
  - `mint_start`, `mint_success`, `mint_fail`
- Added event emission for refresh lifecycle in `refresh::RefreshRuntimeLoop::run_once`:
  - `refresh_start`, `refresh_success`, `refresh_fail`
- Added event emission for revoke lifecycle in both revoke paths:
  - `main::execute_revoke`
  - `integration_runtime::revoke_token`
  - emits `revoke_start`, `revoke_success`, `revoke_fail`
  - includes fail events for early failures (missing/empty revoke command, spawn errors, non-zero exits)
- Added child process events in `agent_process`:
  - `child_spawn`, `child_exit`
- Added signal events in `run_signal_wiring`:
  - `signal_received`, `signal_forwarded`
- Added runtime emitter plumbing in `event.rs`:
  - global install/clear guard
  - `emit_runtime_event`
  - test collector helpers

## Tests added/updated

- Added `src/event_emission_wiring_tests.rs` with dedicated NS-070 wiring tests:
  - CLI accepts `--log-format`
  - mint start/success/fail emission
  - refresh start/success/fail emission
  - revoke start/success/fail emission
  - child spawn/exit emission
  - signal received/forwarded emission
  - stderr event sink behavior
- Updated tests to avoid cross-test interference from shared runtime emitter state by serializing these event-emitter tests with an async-aware lock.

## Validation

- `cargo fmt --all`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

All above commands pass.
