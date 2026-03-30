# Provenance Draft: noscope-3ed

## Thread Message (for requirement )
Updated `Cargo.toml` to `edition = "2021"` so the crate builds on stable Rust toolchains. Added a dedicated integration test that asserts the manifest uses edition 2021, then verified full suite health with `cargo test` and `cargo clippy --all-targets -- -D warnings`.

## New Artifacts (if any)
- type: rule
  content: Cargo manifest must use a stable Rust edition (`2021`) so default stable toolchains can compile the project.
