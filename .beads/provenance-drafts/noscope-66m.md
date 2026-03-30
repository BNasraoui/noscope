# Provenance Draft: noscope-66m

## Thread Message (for requirement NS-024)

Implemented Linux run-mode process group management and parent-death signaling in `src/process_group.rs`.

- Added `configure_child_for_mode(ProcessGroupMode::Run)` to apply run-mode behavior before exec:
  - `setpgid(0, 0)` to create a new process group for the child.
  - `prctl(PR_SET_PDEATHSIG, SIGTERM)` so child receives `SIGTERM` if noscope dies.
- Added `terminate_group_for_mode(ProcessGroupMode::Run, pgid)` to terminate the full group with `kill(-pgid, SIGTERM)`.
- Added explicit mode-gating so mint mode is a no-op for process-group/PDEATHSIG behavior.

NS-024 coverage tests (Linux):

- `process_group_management_in_run_mode_sets_pdeathsig_on_child_before_exec`
- `process_group_management_in_run_mode_creates_new_process_group`
- `process_group_management_in_run_mode_kills_entire_group_on_exit`
- `process_group_management_does_not_apply_to_mint_mode`

Post-review hardening (edge case):

- Guarded `terminate_process_group` against invalid `pgid <= 0` to prevent accidental signal targeting with special pid semantics.
- Added tests:
  - `process_group_management_in_run_mode_rejects_invalid_process_group_id`
  - `process_group_management_in_mint_mode_ignores_invalid_process_group_id`

Validation:

- `cargo test` passes (793 tests).
- `cargo clippy --all-targets --all-features -- -D warnings` passes.
