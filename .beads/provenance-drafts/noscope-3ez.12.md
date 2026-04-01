# Provenance Draft: noscope-3ez.12

## Thread Message (for requirement noscope-3ez.12)

Implemented `noscope doctor` and `noscope init` guided setup/health commands.

### Doctor (`noscope doctor`)

Validates local prerequisites and provider configuration:

1. **Config directory** (NS-080): Checks `<XDG_CONFIG_HOME>/noscope/` exists
2. **Provider TOML** (NS-081): For each `.toml` in `providers/`, checks:
   - File permissions are secure (reuses existing `check_config_permissions`)
   - TOML is parseable and satisfies schema (reuses existing `parse_provider_toml`)
3. **Command executability** (NS-082): For each configured command (mint, refresh, revoke), checks the binary exists and has execute bits
4. **Structured report** (NS-083): Returns `DoctorReport` with `Vec<Check>`, each having name/status/message
5. **Exit codes** (NS-084): 0 = all pass, 1 = warnings only, 78 = failures (sysexits.h ConfigError)

### Init (`noscope init`)

Creates the config directory tree with secure permissions:

1. **Directory structure** (NS-085): Creates `noscope/`, `noscope/providers/`, `noscope/profiles/`
2. **Secure permissions** (NS-086): All directories created with mode 0700 (owner-only)
3. **Idempotent** (NS-087): Existing directories are left unchanged; second run reports no new dirs

### CLI Integration

Both commands are wired into the CLI as `noscope doctor` and `noscope init` subcommands, with `--output text|json` support.

### Design decisions

- **Doctor is infallible**: `run_doctor()` returns `DoctorReport`, never `Result`. Diagnostic commands should always produce output, even when things are broken.
- **Missing commands are warnings, not failures**: A valid config file referencing a not-yet-installed binary is a warning (config is correct, system setup isn't). Malformed config or insecure permissions are failures.
- **Reuses existing validation**: Delegates to `provider::check_config_permissions` and `provider::parse_provider_toml` for consistency with the rest of the codebase.

## New Artifacts

- type: rule
  content: NS-080 — doctor checks config directory exists and is accessible
- type: rule
  content: NS-081 — doctor checks each configured provider's TOML is parseable and permissions are secure
- type: rule
  content: NS-082 — doctor checks each provider's mint command exists and is executable
- type: rule
  content: NS-083 — doctor produces a structured report with pass/warn/fail per check
- type: rule
  content: NS-084 — doctor exit code reflects worst status (0=all pass, 1=warnings, 78=failures)
- type: rule
  content: NS-085 — init creates the config directory structure under XDG_CONFIG_HOME
- type: rule
  content: NS-086 — init sets secure permissions (0700) on created directories
- type: rule
  content: NS-087 — init is idempotent — running twice does not error or change permissions
