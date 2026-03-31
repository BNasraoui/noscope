# Provenance Draft: noscope-3ez.7

## Thread Message (for requirement )
Implemented documentation hardening for first-use onboarding.

- Expanded `README.md` with concrete install paths (`cargo build --release`, `cargo install --path .`), provider config examples, and a concise command sequence for dry-run, mint, revoke, and run workflows.
- Added `docs/QUICKSTART.md` with an end-to-end setup flow: install, provider config, validate, dry-run, mint, revoke, and run.
- Added test coverage in `tests/noscope_3ez_7_docs.rs` to enforce all bead rules: install guidance, provider config examples, first-run workflows, and implemented-vs-planned safety-layer guidance.
- Verified red/green workflow: tests initially failed against old docs, then passed after doc updates; `cargo clippy --all-targets --all-features -- -D warnings` is clean.

## New Artifacts (if any)
- type: rule
  content: README must include explicit install guidance for local build and cargo install workflows.
- type: rule
  content: QUICKSTART must include runnable dry-run, mint, revoke, and run examples for first-time setup.
- type: rule
  content: Documentation must explicitly distinguish currently implemented safety behaviors from planned hardening work.
