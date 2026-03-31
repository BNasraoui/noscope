## noscope-f75 progress

- Added run-mode OS signal registration for `SIGTERM`, `SIGINT`, and `SIGHUP` in `cmd_run` via `signal_hook::iterator::Signals`.
- Added `src/run_signal_wiring.rs` to connect parent signals to `SignalHandlingPolicy::on_shutdown_signal`, including:
  - forwarding shutdown signals to child process handling,
  - NS-028 double-signal escalation to `SIGKILL`,
  - NS-029 revocation trigger on first shutdown signal,
  - NS-003 revoke-at-exit guard tracking.
- Updated `AgentProcess::spawn` run-mode child setup to call `process_group::configure_child_for_mode(Run)` in `pre_exec`, so group signaling works as intended.
- Updated `AgentProcess::forward_signal` to target child process group first, then fallback to child pid, tolerating `ESRCH`.
- Added nonblocking `AgentProcess::try_wait_exit_code()` and used it in run-mode signal loop.
- Integrated revocation callback in run mode (`revoke_on_shutdown_signal`) using `SignalHandlingPolicy::revoke_all_on_signal` and `RevocationBudget::default()`.
- Fixed regression: when child spawn fails in run mode, minted credentials are now revoked before returning the spawn error.
- Added/kept tests for NS-003, NS-026, NS-028, and NS-029 in `src/run_signal_wiring.rs` and verified wiring behavior.

## verification

- `cargo clippy --all-targets -- -D warnings` passes.
- `cargo test --quiet` passes.
