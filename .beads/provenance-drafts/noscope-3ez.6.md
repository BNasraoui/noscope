# Provenance Draft: noscope-3ez.6

## Thread Message (for requirement noscope-f75)

Corrected the provenance draft for noscope-f75 to precisely attribute OS signal
registration to `run_child_with_os_signals` (main.rs:348) rather than `cmd_run`
directly. The call chain is: `cmd_run` (main.rs:209) invokes
`run_child_with_os_signals`, which registers `SIGTERM`/`SIGINT`/`SIGHUP` handlers
via `signal_hook::iterator::Signals::new()` (main.rs:374-377) and then runs the
dispatch loop using `dispatch_pending_parent_signals` from `run_signal_wiring.rs`.
This wording change ensures the provenance record accurately reflects the code
architecture.
