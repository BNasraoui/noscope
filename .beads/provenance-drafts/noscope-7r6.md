# Provenance Draft: noscope-7r6
## Thread Message (for requirement NS-047)
Implemented NS-047 wiring in the run rollback path by adding budget-aware revocation retries for tokens minted before a partial failure. The new rollback flow now enforces a shared wall-clock timeout (`RollbackBudget.revoke_timeout`) across all retries, applies exponential backoff between attempts, logs every attempt using `RollbackLogEntry`, and disables retry execution when budget is zero. Added focused TDD coverage in `src/main.rs` for retry behavior, wall-clock budget enforcement, exponential backoff sequence, per-attempt rollback logging, zero-budget disable semantics, and timed-out attempt logging.

## New Artifacts (if any)
- type: rule
  content: No new rule created; implementation wires existing NS-047 policy into run rollback execution.
