# Provenance Draft: noscope-9l0

## Thread Message (for requirement: Binary entrypoint and CLI framework)

Implemented the binary entrypoint and CLI framework using clap with derive feature.

### What was done:
- Added `clap` (v4, derive feature) and `clap_complete` (v4) to Cargo.toml
- Added `[[bin]]` target to Cargo.toml pointing to src/main.rs
- Created `src/cli.rs` as a testable library module containing:
  - Clap-derived CLI struct with 6 subcommands: run, mint, revoke, validate, dry-run, completions
  - `parse_from_args()` for testable CLI parsing
  - `error_to_exit_code()` for NS-054 exit code mapping
  - `SUCCESS_EXIT_CODE` constant
- Created `src/main.rs` as a thin binary wrapper that:
  - Dispatches all subcommands through the Client facade (NS-074)
  - Maps errors to process exit codes (NS-054)
  - Generates shell completions for bash/zsh/fish

### Rules covered:
- **NS-054** (exit codes become real): `error_to_exit_code()` maps Error::exit_code() to process exit codes. 8 tests verify every ErrorKind produces the correct sysexits.h code.
- **NS-071** (dry-run usable): `dry-run` subcommand parses provider/role/ttl and invokes Client::dry_run(). 4 tests verify parsing and field extraction.
- **NS-074** (facade for workflows): All subcommands route through Client. main.rs dispatches to cmd_run/cmd_mint/cmd_revoke/cmd_validate/cmd_dry_run, each constructing a Client. 8 tests verify all 5 workflow subcommands parse correctly.
- **NS-075** (CLI parsing in adapter layer): Clap types live in cli.rs (adapter layer), not in lib.rs core types. Client and Cli are distinct types. 3 tests verify separation.

### Test coverage: 36 new tests added, all named after the rule they verify.

### Remaining work:
- cmd_run, cmd_mint, cmd_revoke are stubs (print "not yet fully implemented") — blocked on integration test suite (noscope-lgb)
- cmd_validate works end-to-end (resolves provider config)
- cmd_dry_run works end-to-end (prints dry-run output)

## New Artifacts (if any)
- type: rule
  content: NS-075 - CLI parsing types (Cli, Command, RunArgs, etc.) must live in the adapter layer (cli.rs), separate from core domain types (Client, MintRequest, etc.)
