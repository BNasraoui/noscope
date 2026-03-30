# Provenance Draft: noscope-5dw

## Thread Message (for requirement: Async runtime and concurrent minting orchestration)

Implemented the async orchestrator module (`src/orchestrator.rs`) as a thin spine
that wires together existing credential_set, mint, and token_convert modules with
tokio-based async parallelism.

Key design decisions:
- Used `tokio::sync::Semaphore` for bounded parallelism (NS-050) rather than
  a task pool or manual channel-based approach. The semaphore is acquired before
  spawning each task, ensuring at most `max_concurrent` tasks are active at any time.
- Per-provider timeout (NS-046) uses `tokio::time::timeout` wrapping each provider
  future. On timeout, a `MintResult::Failure` is synthesized with the provider name
  and timeout duration in the error message.
- Atomic rollback (NS-006, NS-047) is delegated entirely to the existing
  `resolve_mint_results()` function — no new rollback logic was needed.
- JSON array output (NS-063) is wired via `format_orchestrator_output()` which
  iterates `CredentialSet::tokens()` (new accessor method) and pipes through
  `scoped_token_to_mint_envelope()` and `format_mint_output()`.

The `mint_all` function takes a generic closure `Fn(&CredentialSpec) -> Fut` for
provider execution, enabling both production subprocess execution and test mocking.

Rules covered: NS-006, NS-046, NS-047, NS-050, NS-063

## New Artifacts (if any)
- type: rule
  content: NS-050 enforcement via tokio::sync::Semaphore in orchestrator::mint_all
- type: rule
  content: NS-046 enforcement via tokio::time::timeout per spawned provider task
