# Provenance Draft: noscope-6a9

## Thread Message (for requirement noscope-6a9)

Implemented the provider command execution engine (`execute_provider_command`)
that bridges all existing policy building blocks in `provider_exec.rs` to actual
subprocess execution via `std::process::Command`.

The engine:
- Spawns provider commands with `build_sandboxed_env()` as base environment (NS-068)
- Reads stdout/stderr concurrently to avoid pipe buffer deadlock
- Enforces timeout via SIGTERM then SIGKILL escalation (NS-035)
- Checks stdout size limit via `check_stdout_size_limit()` (NS-036)
- Captures and truncates stderr via `capture_stderr()`, redacts tokens via `redact_stderr()` (NS-040)
- Parses successful output through `parse_provider_output()` (NS-009)
- Maps exit codes through `interpret_provider_exit()` (NS-010)

Key design decisions:
- Uses `tokio::spawn` for concurrent stdout/stderr reading to prevent deadlock
  when child writes more than the pipe buffer (64KB on Linux)
- Returns `Result<ProviderExecResult, io::Error>` where io::Error covers spawn
  failures and ProviderExecResult covers all execution outcomes including timeout,
  oversized stdout, parse failures, and non-zero exit codes
- Added `io-util` feature to tokio dependency for `AsyncReadExt`
- Token redaction in stderr uses NOSCOPE_TOKEN* prefix matching to capture both
  NOSCOPE_TOKEN and NOSCOPE_TOKEN_ID values

## New Artifacts (if any)
- type: rule
  content: NS-068+NS-036+NS-040+NS-035+NS-009+NS-010 are now consumed by
  execute_provider_command() which is the single entry point for running provider
  subprocesses. All future provider invocations should use this function.
