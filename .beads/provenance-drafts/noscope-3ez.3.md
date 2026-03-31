# Provenance Draft: noscope-3ez.3

## Thread Message (for requirement )
Implemented signal-loop parity coverage between `src/main.rs` run-mode wiring and `src/integration_runtime.rs` integration wiring for identical signal sequences.

- Added parity tests in `src/main.rs` (`signal_loop_parity_tests`) covering `SIGTERM`, `SIGINT -> SIGTERM`, and `SIGHUP` parent signal sequences, asserting equivalence for forwarding and escalation outcomes.
- Expanded `SignalHandlingReport` in `src/integration_runtime.rs` to report `forwarded_sigint` and `forwarded_sighup` in addition to `forwarded_sigterm` and `double_signal_escalated`, enabling full parity assertions.
- Updated integration signal adapter forwarding bookkeeping so parity checks observe the same forwarding surface (`SIGTERM`, `SIGINT`, `SIGHUP`, and escalation to `SIGKILL`).
- Hardened integration signal processing by tracking expected parent-signal counts and consuming only intended injected signals, preventing stray process-wide pending signals from polluting parity outcomes.
- Prevented cross-test signal interference by using a shared global signal lock for OS-signal tests and parity tests in `src/main.rs`.
- Verified quality gates with `cargo test --quiet` and `cargo clippy --all-targets --all-features -- -D warnings`.

## New Artifacts (if any)
- type: rule
  content: Run-mode and integration signal loops must produce equivalent forwarding and escalation outcomes for the same parent signal sequence.
- type: rule
  content: Parity reporting must include SIGTERM, SIGINT, and SIGHUP forwarding state plus double-signal escalation state.
