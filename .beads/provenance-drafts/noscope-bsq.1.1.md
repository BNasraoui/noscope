# Provenance Draft: noscope-bsq.1.1

## Thread Message (for requirement noscope-bsq.1.1)

Implemented config-name path traversal blocking in `config_path.rs`.

### What was done

- Added `ConfigPathError` typed error struct with `name()` and `reason()` accessors
- Added `validate_config_name()` function with strict allowlist:
  - Allowed: ASCII alphanumeric, hyphen, underscore, dot
  - Rejected: empty, `.`, `..`, any character outside allowlist (path separators, NUL, whitespace, control chars, colons, tildes, non-ASCII)
- Changed `named_config_toml_path()` from `-> PathBuf` to `-> Result<PathBuf, ConfigPathError>`
- Updated all callers: `provider_config_path`, `provider_config_path_with_home`, `profile_config_path`, `profile_config_path_with_home`, `resolve_provider_config`, `Client::resolve_provider`
- Added `From<ConfigPathError> for Error` mapping to `ErrorKind::Security` (path traversal is a security violation)
- 38 tests covering positive names, negative names, typed error properties, end-to-end provider/profile paths, and edge cases

### Design decisions

- **Allowlist over denylist**: Instead of rejecting known-bad characters, we allow only known-safe ones. This is defense-in-depth — future OS/filesystem tricks can't bypass it.
- **Security error kind**: Path traversal maps to `ErrorKind::Security` (not `Config`) because it's a security invariant violation, matching the existing pattern for `SecurityError::TokenInArgs`.
- **`..hidden` is allowed**: Names that start with `..` but are not exactly `..` are valid filesystem components and pose no traversal risk.
- **No length limit**: The filesystem will reject overly long names; adding an artificial limit would be YAGNI.

## New Artifacts (if any)

- type: rule
  content: Config names (provider and profile) must pass validate_config_name() before being used as path components. Only ASCII alphanumeric, hyphen, underscore, and dot are allowed. Empty, ".", and ".." are rejected.
