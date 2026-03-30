// NS-004: Profile flatness constraint
// NS-051: Profile schema
// NS-052: Profile validation before minting
// NS-053: Profile and CLI flag mutual exclusion

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config_path::named_config_toml_path;
use crate::exit_code::NoscopeExitCode;
use crate::provider::check_config_permissions;

/// Known fields in a [[credentials]] entry.
/// NS-051: provider (required), role (required), ttl (required), env_key (optional).
/// NS-004/NS-051: Any field not in this set is an error.
const KNOWN_CREDENTIAL_FIELDS: &[&str] = &["provider", "role", "ttl", "env_key"];

/// A single credential entry from a profile.
///
/// NS-004: Flat tuple of (provider, role, ttl) with optional env_key.
/// No nesting, no inheritance, no composition.
#[derive(Debug)]
pub struct ProfileCredential {
    pub provider: String,
    pub role: String,
    pub ttl: u64,
    pub env_key: Option<String>,
}

/// A parsed profile: a flat list of credential entries.
///
/// NS-004: This is deliberately flat — no extends, no overrides,
/// no merge strategy. Just a Vec of credentials.
#[derive(Debug)]
pub struct Profile {
    pub credentials: Vec<ProfileCredential>,
}

/// Error type for profile operations.
#[derive(Debug)]
pub enum ProfileError {
    /// NS-051: Malformed profile TOML or schema violation.
    MalformedProfile { message: String },
    /// NS-052: Profile validation failed (provider existence, env_key
    /// uniqueness). Contains all problems found in a single pass.
    ValidationFailed { problems: Vec<String> },
    /// NS-053: --profile used with forbidden credential flags.
    FlagConflict { message: String },
    /// Profile file not found.
    NotFound { path: PathBuf },
    /// Insecure file permissions.
    InsecurePermissions { path: PathBuf, mode: u32 },
}

impl ProfileError {
    /// Get the noscope exit code for this error.
    pub fn exit_code(&self) -> NoscopeExitCode {
        match self {
            Self::MalformedProfile { .. } => NoscopeExitCode::ConfigError,
            Self::ValidationFailed { .. } => NoscopeExitCode::ProfileValidation,
            Self::FlagConflict { .. } => NoscopeExitCode::Usage,
            Self::NotFound { .. } => NoscopeExitCode::ConfigNotFound,
            Self::InsecurePermissions { .. } => NoscopeExitCode::Permission,
        }
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedProfile { message } => {
                write!(f, "malformed profile: {}", message)
            }
            Self::ValidationFailed { problems } => {
                write!(f, "profile validation failed: ")?;
                for (i, p) in problems.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{}", p)?;
                }
                Ok(())
            }
            Self::FlagConflict { message } => {
                write!(f, "{}", message)
            }
            Self::NotFound { path } => {
                write!(f, "profile not found: {}", path.display())
            }
            Self::InsecurePermissions { path, mode } => {
                write!(
                    f,
                    "profile {:?} has insecure permissions {:04o}; \
                     group-writable and world-accessible bits must be 0 (e.g. 0600, 0640)",
                    path, mode
                )
            }
        }
    }
}

impl std::error::Error for ProfileError {}

/// Compute the config file path for a named profile.
///
/// Uses XDG_CONFIG_HOME if provided, otherwise falls back to
/// `$HOME/.config`.
///
/// Returns `Err` if the name contains path traversal characters.
pub fn profile_config_path(
    name: &str,
    xdg_config_home: Option<&Path>,
) -> Result<PathBuf, crate::config_path::ConfigPathError> {
    named_config_toml_path(xdg_config_home, None, "profiles", name)
}

/// Same as `profile_config_path` but with explicit HOME fallback.
///
/// Returns `Err` if the name contains path traversal characters.
pub fn profile_config_path_with_home(
    name: &str,
    xdg_config_home: Option<&Path>,
    home: &Path,
) -> Result<PathBuf, crate::config_path::ConfigPathError> {
    named_config_toml_path(xdg_config_home, Some(home), "profiles", name)
}

/// NS-051: Parse profile TOML content into a Profile.
///
/// Validates schema: required fields, unknown credential fields = error,
/// empty credentials = error. Unknown top-level fields are ignored.
pub fn parse_profile_toml(content: &str) -> Result<Profile, ProfileError> {
    let table: toml::Table =
        content
            .parse()
            .map_err(|e: toml::de::Error| ProfileError::MalformedProfile {
                message: e.to_string(),
            })?;

    // Extract the credentials array.
    let creds_value = table
        .get("credentials")
        .ok_or(ProfileError::MalformedProfile {
            message: "missing required [[credentials]] section".to_string(),
        })?;

    let creds_array = creds_value
        .as_array()
        .ok_or(ProfileError::MalformedProfile {
            message: "'credentials' must be an array of tables".to_string(),
        })?;

    // NS-051: empty array = error.
    if creds_array.is_empty() {
        return Err(ProfileError::MalformedProfile {
            message: "credentials array must not be empty".to_string(),
        });
    }

    let mut credentials = Vec::new();
    let mut problems = Vec::new();

    for (i, entry) in creds_array.iter().enumerate() {
        let entry_table = match entry.as_table() {
            Some(t) => t,
            None => {
                problems.push(format!(
                    "credentials[{}]: expected a table, got a non-table value",
                    i
                ));
                continue;
            }
        };

        // NS-004/NS-051: Check for unknown credential fields.
        for key in entry_table.keys() {
            if !KNOWN_CREDENTIAL_FIELDS.contains(&key.as_str()) {
                problems.push(format!("credentials[{}]: unknown field '{}'", i, key));
            }
        }

        // Extract required fields with proper type checking.
        let provider = match entry_table.get("provider") {
            Some(v) => match v.as_str() {
                Some(s) if !s.is_empty() => Some(s.to_string()),
                Some(_) => {
                    problems.push(format!("credentials[{}]: provider must not be empty", i));
                    None
                }
                None => {
                    problems.push(format!("credentials[{}]: provider must be a string", i));
                    None
                }
            },
            None => {
                problems.push(format!(
                    "credentials[{}]: missing required field 'provider'",
                    i
                ));
                None
            }
        };

        let role = match entry_table.get("role") {
            Some(v) => match v.as_str() {
                Some(s) if !s.is_empty() => Some(s.to_string()),
                Some(_) => {
                    problems.push(format!("credentials[{}]: role must not be empty", i));
                    None
                }
                None => {
                    problems.push(format!("credentials[{}]: role must be a string", i));
                    None
                }
            },
            None => {
                problems.push(format!("credentials[{}]: missing required field 'role'", i));
                None
            }
        };

        let ttl_value = entry_table.get("ttl");

        let env_key = match entry_table.get("env_key") {
            Some(v) => match v.as_str() {
                Some(s) => Some(s.to_string()),
                None => {
                    problems.push(format!("credentials[{}]: env_key must be a string", i));
                    None
                }
            },
            None => None,
        };

        let ttl = match ttl_value {
            Some(v) => match v.as_integer() {
                Some(n) if n > 0 => Some(n as u64),
                Some(n) => {
                    problems.push(format!(
                        "credentials[{}]: ttl must be a positive integer, got {}",
                        i, n
                    ));
                    None
                }
                None => {
                    problems.push(format!("credentials[{}]: ttl must be an integer", i));
                    None
                }
            },
            None => {
                problems.push(format!("credentials[{}]: missing required field 'ttl'", i));
                None
            }
        };

        // Only build the credential if all required fields are present.
        if let (Some(provider), Some(role), Some(ttl)) = (provider, role, ttl) {
            credentials.push(ProfileCredential {
                provider,
                role,
                ttl,
                env_key,
            });
        }
    }

    if !problems.is_empty() {
        return Err(ProfileError::MalformedProfile {
            message: problems.join("; "),
        });
    }

    Ok(Profile { credentials })
}

/// NS-052: Validate a parsed profile before minting.
///
/// Checks:
/// - env_key uniqueness across all credentials
/// - Provider existence (via the `provider_exists` callback)
///
/// All errors are collected and returned together (no fail-fast).
/// Returns an empty Vec on success.
pub fn validate_profile(profile: &Profile, provider_exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut errors = Vec::new();

    // Check provider existence.
    for cred in &profile.credentials {
        if !provider_exists(&cred.provider) {
            errors.push(format!("provider '{}' not found", cred.provider));
        }
    }

    // Check env_key uniqueness.
    let mut seen_env_keys = HashSet::new();
    for cred in &profile.credentials {
        if let Some(ref key) = cred.env_key
            && !seen_env_keys.insert(key.clone())
        {
            errors.push(format!("duplicate env_key '{}'", key));
        }
    }

    errors
}

/// NS-053: Check mutual exclusion between --profile and credential flags.
///
/// --profile forbids --provider, --role, and --ttl.
/// Returns Ok(()) if no conflict, Err with usage error if violated.
pub fn check_profile_flag_exclusion(
    profile: Option<&str>,
    provider: Option<&str>,
    role: Option<&str>,
    ttl: Option<u64>,
) -> Result<(), ProfileError> {
    let profile_name = match profile {
        Some(name) => name,
        None => return Ok(()), // No --profile, no conflict possible.
    };

    let mut conflicts = Vec::new();
    if provider.is_some() {
        conflicts.push("--provider");
    }
    if role.is_some() {
        conflicts.push("--role");
    }
    if ttl.is_some() {
        conflicts.push("--ttl");
    }

    if conflicts.is_empty() {
        return Ok(());
    }

    Err(ProfileError::FlagConflict {
        message: format!(
            "--profile '{}' cannot be used with {}",
            profile_name,
            conflicts.join(", ")
        ),
    })
}

/// Load a profile from disk.
///
/// Unlike provider config (which returns Ok(None) for missing files),
/// an explicitly requested profile must exist. Returns an error if
/// the file is missing or has insecure permissions.
pub fn load_profile(path: &Path) -> Result<Profile, ProfileError> {
    if !path.exists() {
        return Err(ProfileError::NotFound {
            path: path.to_path_buf(),
        });
    }

    // Reuse the provider permission check.
    check_config_permissions(path).map_err(|e| match e {
        crate::provider::ProviderConfigError::InsecurePermissions { path, mode } => {
            ProfileError::InsecurePermissions { path, mode }
        }
        other => ProfileError::MalformedProfile {
            message: format!("{}", other),
        },
    })?;

    let content = fs::read_to_string(path).map_err(|e| ProfileError::MalformedProfile {
        message: format!("failed to read {}: {}", path.display(), e),
    })?;

    parse_profile_toml(&content)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    // =========================================================================
    // NS-004: Profile flatness constraint — flat lists of (provider, role, ttl)
    // tuples only; no inheritance/extends/overrides/composition.
    // =========================================================================

    #[test]
    fn profile_flatness_constraint_is_flat_list_of_tuples() {
        // A valid profile is a flat array of credential entries.
        // Each entry is a (provider, role, ttl) tuple. No nesting.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600

[[credentials]]
provider = "gcp"
role = "viewer"
ttl = 1800
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        assert_eq!(profile.credentials.len(), 2);
        assert_eq!(profile.credentials[0].provider, "aws");
        assert_eq!(profile.credentials[0].role, "admin");
        assert_eq!(profile.credentials[0].ttl, 3600);
        assert_eq!(profile.credentials[1].provider, "gcp");
        assert_eq!(profile.credentials[1].role, "viewer");
        assert_eq!(profile.credentials[1].ttl, 1800);
    }

    #[test]
    fn profile_flatness_constraint_no_extends_field() {
        // NS-004: no inheritance — "extends" field in a credential is
        // an unknown field and must be rejected.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
extends = "base-profile"
"#;
        let result = super::parse_profile_toml(toml);
        assert!(
            result.is_err(),
            "NS-004: 'extends' field must be rejected as unknown credential field"
        );
    }

    #[test]
    fn profile_flatness_constraint_no_overrides_field() {
        // NS-004: no overrides — "overrides" is an unknown credential field.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
overrides = "something"
"#;
        let result = super::parse_profile_toml(toml);
        assert!(
            result.is_err(),
            "NS-004: 'overrides' field must be rejected as unknown credential field"
        );
    }

    #[test]
    fn profile_flatness_constraint_no_nested_profiles() {
        // NS-004: no composition — credentials cannot contain nested credentials.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600

[[credentials.nested]]
provider = "gcp"
role = "viewer"
ttl = 1800
"#;
        let result = super::parse_profile_toml(toml);
        assert!(
            result.is_err(),
            "NS-004: nested credential structures must be rejected"
        );
    }

    // =========================================================================
    // NS-051: Profile schema — [[credentials]] entries with provider (required),
    // role (required), ttl (required), env_key (optional); unknown top-level
    // fields ignored; unknown credential fields = error; empty array = error.
    // =========================================================================

    #[test]
    fn profile_schema_requires_provider() {
        let toml = r#"
[[credentials]]
role = "admin"
ttl = 3600
"#;
        let result = super::parse_profile_toml(toml);
        assert!(
            result.is_err(),
            "NS-051: missing 'provider' must be an error"
        );
    }

    #[test]
    fn profile_schema_requires_role() {
        let toml = r#"
[[credentials]]
provider = "aws"
ttl = 3600
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err(), "NS-051: missing 'role' must be an error");
    }

    #[test]
    fn profile_schema_requires_ttl() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err(), "NS-051: missing 'ttl' must be an error");
    }

    #[test]
    fn profile_schema_env_key_is_optional() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        assert!(
            profile.credentials[0].env_key.is_none(),
            "NS-051: env_key should be None when not specified"
        );
    }

    #[test]
    fn profile_schema_env_key_can_be_set() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
env_key = "AWS_SESSION_TOKEN"
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        assert_eq!(
            profile.credentials[0].env_key.as_deref(),
            Some("AWS_SESSION_TOKEN"),
            "NS-051: env_key should be set when specified"
        );
    }

    #[test]
    fn profile_schema_unknown_top_level_fields_ignored() {
        // NS-051: unknown top-level fields are ignored (forward-compat).
        let toml = r#"
description = "my dev profile"
version = 2

[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        assert_eq!(
            profile.credentials.len(),
            1,
            "NS-051: unknown top-level fields must be ignored"
        );
    }

    #[test]
    fn profile_schema_unknown_credential_field_is_error() {
        // NS-051: unknown fields in [[credentials]] entries = error.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
region = "us-east-1"
"#;
        let result = super::parse_profile_toml(toml);
        assert!(
            result.is_err(),
            "NS-051: unknown credential field 'region' must be an error"
        );
    }

    #[test]
    fn profile_schema_empty_credentials_array_is_error() {
        // NS-051: empty credentials array = error.
        let toml = r#"
credentials = []
"#;
        let result = super::parse_profile_toml(toml);
        assert!(
            result.is_err(),
            "NS-051: empty credentials array must be an error"
        );
    }

    #[test]
    fn profile_schema_no_credentials_key_is_error() {
        // A profile without any [[credentials]] section is empty => error.
        let toml = r#"
description = "empty profile"
"#;
        let result = super::parse_profile_toml(toml);
        assert!(
            result.is_err(),
            "NS-051: profile without credentials must be an error"
        );
    }

    #[test]
    fn profile_schema_ttl_must_be_positive_integer() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 0
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err(), "NS-051: ttl=0 must be an error");
    }

    #[test]
    fn profile_schema_ttl_must_not_be_negative() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = -100
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err(), "NS-051: negative ttl must be an error");
    }

    #[test]
    fn profile_schema_multiple_unknown_credential_fields_all_reported() {
        // When multiple credential entries have unknown fields, all should
        // be reported in the error.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
region = "us-east-1"

[[credentials]]
provider = "gcp"
role = "viewer"
ttl = 1800
project = "my-project"
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("region"),
            "Error must mention 'region': {}",
            msg
        );
        assert!(
            msg.contains("project"),
            "Error must mention 'project': {}",
            msg
        );
    }

    // =========================================================================
    // NS-052: Profile validation before minting — schema + env_key uniqueness
    // + provider existence validated before any minting; all errors reported
    // together; distinct exit code.
    // =========================================================================

    #[test]
    fn profile_validation_env_key_uniqueness() {
        // Two credentials with the same env_key must be rejected.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
env_key = "TOKEN"

[[credentials]]
provider = "gcp"
role = "viewer"
ttl = 1800
env_key = "TOKEN"
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        let errors = super::validate_profile(&profile, &|_name| true);
        assert!(
            !errors.is_empty(),
            "NS-052: duplicate env_key must be reported"
        );
        let all_msgs: String = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            all_msgs.contains("TOKEN"),
            "NS-052: error must mention the duplicated env_key: {}",
            all_msgs
        );
    }

    #[test]
    fn profile_validation_provider_existence() {
        // Validation checks that all referenced providers exist.
        let toml = r#"
[[credentials]]
provider = "nonexistent-provider"
role = "admin"
ttl = 3600
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        // Provider lookup returns false for the nonexistent provider.
        let errors = super::validate_profile(&profile, &|_name| false);
        assert!(
            !errors.is_empty(),
            "NS-052: nonexistent provider must be reported"
        );
        let all_msgs: String = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            all_msgs.contains("nonexistent-provider"),
            "NS-052: error must name the missing provider: {}",
            all_msgs
        );
    }

    #[test]
    fn profile_validation_all_errors_reported_together() {
        // Multiple problems must all be reported in one pass, not fail-fast.
        let toml = r#"
[[credentials]]
provider = "missing-a"
role = "admin"
ttl = 3600
env_key = "DUPE"

[[credentials]]
provider = "missing-b"
role = "viewer"
ttl = 1800
env_key = "DUPE"
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        let errors = super::validate_profile(&profile, &|_name| false);
        // Should have: missing-a provider, missing-b provider, duplicate env_key
        assert!(
            errors.len() >= 3,
            "NS-052: all errors must be reported together, got {} errors: {:?}",
            errors.len(),
            errors
        );
    }

    #[test]
    fn profile_validation_distinct_exit_code() {
        // NS-052: profile validation errors use a distinct exit code.
        let exit_code = super::ProfileError::ValidationFailed {
            problems: vec!["test".to_string()],
        };
        let noscope_exit = exit_code.exit_code();
        // Must not be 64 (usage), 65 (mint), 66 (not found), 78 (config) etc.
        // It should be a distinct code. Let's check it's 79 or similar —
        // the exact value will be determined by implementation, but it must
        // be different from other NoscopeExitCode variants.
        let raw = noscope_exit.as_raw();
        assert_ne!(raw, 64, "Must not be Usage (64)");
        assert_ne!(raw, 65, "Must not be MintFailure (65)");
        assert_ne!(raw, 66, "Must not be ConfigNotFound (66)");
        assert_ne!(raw, 70, "Must not be Internal (70)");
        assert_ne!(raw, 78, "Must not be ConfigError (78)");
        // Should be some distinct sysexits-adjacent code
        assert!(
            (64..=113).contains(&raw),
            "Exit code should be in sysexits range, got: {}",
            raw
        );
    }

    #[test]
    fn profile_validation_passes_for_valid_profile() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
env_key = "AWS_TOKEN"

[[credentials]]
provider = "gcp"
role = "viewer"
ttl = 1800
env_key = "GCP_TOKEN"
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        let errors = super::validate_profile(&profile, &|_name| true);
        assert!(
            errors.is_empty(),
            "Valid profile should produce no errors, got: {:?}",
            errors
        );
    }

    #[test]
    fn profile_validation_env_key_uniqueness_none_does_not_conflict() {
        // Two credentials without env_key should not conflict with each other.
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600

[[credentials]]
provider = "gcp"
role = "viewer"
ttl = 1800
"#;
        let profile = super::parse_profile_toml(toml).unwrap();
        let errors = super::validate_profile(&profile, &|_name| true);
        assert!(
            errors.is_empty(),
            "Credentials without env_key should not conflict: {:?}",
            errors
        );
    }

    // =========================================================================
    // NS-053: Profile and CLI flag mutual exclusion — --profile forbids
    // --provider/--role/--ttl; global flags remain valid.
    // =========================================================================

    #[test]
    fn profile_cli_mutual_exclusion_profile_forbids_provider() {
        let result =
            super::check_profile_flag_exclusion(Some("my-profile"), Some("aws"), None, None);
        assert!(
            result.is_err(),
            "NS-053: --profile with --provider must be rejected"
        );
    }

    #[test]
    fn profile_cli_mutual_exclusion_profile_forbids_role() {
        let result =
            super::check_profile_flag_exclusion(Some("my-profile"), None, Some("admin"), None);
        assert!(
            result.is_err(),
            "NS-053: --profile with --role must be rejected"
        );
    }

    #[test]
    fn profile_cli_mutual_exclusion_profile_forbids_ttl() {
        let result =
            super::check_profile_flag_exclusion(Some("my-profile"), None, None, Some(3600));
        assert!(
            result.is_err(),
            "NS-053: --profile with --ttl must be rejected"
        );
    }

    #[test]
    fn profile_cli_mutual_exclusion_profile_forbids_all_three() {
        let result = super::check_profile_flag_exclusion(
            Some("my-profile"),
            Some("aws"),
            Some("admin"),
            Some(3600),
        );
        assert!(
            result.is_err(),
            "NS-053: --profile with all credential flags must be rejected"
        );
    }

    #[test]
    fn profile_cli_mutual_exclusion_profile_alone_is_valid() {
        let result = super::check_profile_flag_exclusion(Some("my-profile"), None, None, None);
        assert!(result.is_ok(), "NS-053: --profile alone must be valid");
    }

    #[test]
    fn profile_cli_mutual_exclusion_no_profile_allows_flags() {
        // When --profile is not set, --provider/--role/--ttl are fine.
        let result =
            super::check_profile_flag_exclusion(None, Some("aws"), Some("admin"), Some(3600));
        assert!(
            result.is_ok(),
            "NS-053: without --profile, credential flags are allowed"
        );
    }

    #[test]
    fn profile_cli_mutual_exclusion_error_names_conflicting_flags() {
        let result =
            super::check_profile_flag_exclusion(Some("my-profile"), Some("aws"), None, Some(3600));
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("--provider") || msg.contains("--ttl"),
            "NS-053: error must name the conflicting flags, got: {}",
            msg
        );
        assert!(
            msg.contains("--profile"),
            "NS-053: error must mention --profile, got: {}",
            msg
        );
    }

    #[test]
    fn profile_cli_mutual_exclusion_exit_code_is_usage() {
        // --profile with --provider is a usage error.
        let err = super::check_profile_flag_exclusion(Some("my-profile"), Some("aws"), None, None)
            .unwrap_err();
        assert_eq!(
            err.exit_code().as_raw(),
            64,
            "NS-053: mutual exclusion violation must be usage error (64)"
        );
    }

    // =========================================================================
    // Profile path resolution (XDG Base Directory, like provider.rs)
    // =========================================================================

    #[test]
    fn profile_path_under_xdg_config() {
        let xdg = PathBuf::from("/home/user/.config");
        let path = super::profile_config_path("dev", Some(&xdg)).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/.config/noscope/profiles/dev.toml")
        );
    }

    #[test]
    fn profile_path_default_home() {
        let home = PathBuf::from("/home/user");
        let path = super::profile_config_path_with_home("staging", None, &home).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/.config/noscope/profiles/staging.toml")
        );
    }

    // =========================================================================
    // Profile loading (permission checks, missing file)
    // =========================================================================

    #[test]
    fn profile_load_missing_file_is_error() {
        // Unlike provider config (Ok(None) for missing), a profile that
        // was explicitly requested must exist.
        let result = super::load_profile(Path::new("/nonexistent/profile.toml"));
        assert!(
            result.is_err(),
            "NS-051: explicitly requested profile must exist"
        );
    }

    #[test]
    fn profile_load_insecure_permissions_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("insecure.toml");
        std::fs::write(
            &file_path,
            r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
"#,
        )
        .unwrap();
        std::fs::set_permissions(
            &file_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();

        let result = super::load_profile(&file_path);
        assert!(
            result.is_err(),
            "Profile with world-readable permissions must be rejected"
        );
    }

    #[test]
    fn profile_load_secure_permissions_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("secure.toml");
        std::fs::write(
            &file_path,
            r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
"#,
        )
        .unwrap();
        std::fs::set_permissions(
            &file_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let profile = super::load_profile(&file_path).unwrap();
        assert_eq!(profile.credentials.len(), 1);
    }

    // =========================================================================
    // noscope-bsq.1.3: Profile permission checks must match provider policy —
    // group-writable and world-accessible bits both rejected.
    // =========================================================================

    fn valid_profile_toml() -> &'static str {
        r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
"#
    }

    #[test]
    fn profile_permissions_rejects_group_writable_0660() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("profile.toml");
        std::fs::write(&file_path, valid_profile_toml()).unwrap();
        std::fs::set_permissions(
            &file_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o660),
        )
        .unwrap();

        let result = super::load_profile(&file_path);
        assert!(
            result.is_err(),
            "Profile with 0660 (group-writable) must be rejected"
        );
    }

    #[test]
    fn profile_permissions_rejects_group_writable_0620() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("profile.toml");
        std::fs::write(&file_path, valid_profile_toml()).unwrap();
        std::fs::set_permissions(
            &file_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o620),
        )
        .unwrap();

        let result = super::load_profile(&file_path);
        assert!(
            result.is_err(),
            "Profile with 0620 (group-write-only) must be rejected"
        );
    }

    #[test]
    fn profile_permissions_allows_0640() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("profile.toml");
        std::fs::write(&file_path, valid_profile_toml()).unwrap();
        std::fs::set_permissions(
            &file_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o640),
        )
        .unwrap();

        let result = super::load_profile(&file_path);
        assert!(
            result.is_ok(),
            "Profile with 0640 (owner rw, group read) should be allowed"
        );
    }

    #[test]
    fn profile_permissions_allows_0400() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("profile.toml");
        std::fs::write(&file_path, valid_profile_toml()).unwrap();
        std::fs::set_permissions(
            &file_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o400),
        )
        .unwrap();

        let result = super::load_profile(&file_path);
        assert!(
            result.is_ok(),
            "Profile with 0400 (owner read-only) should be allowed"
        );
    }

    #[test]
    fn profile_permissions_error_message_mentions_group_writable() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("profile.toml");
        std::fs::write(&file_path, valid_profile_toml()).unwrap();
        std::fs::set_permissions(
            &file_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o660),
        )
        .unwrap();

        let result = super::load_profile(&file_path);
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("0660"),
            "Error must show the actual mode: {}",
            msg
        );
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn profile_schema_provider_wrong_type_is_error() {
        // provider = 42 should say "must be a string", not "missing field"
        let toml = r#"
[[credentials]]
provider = 42
role = "admin"
ttl = 3600
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("string"),
            "Error must mention wrong type, got: {}",
            msg
        );
    }

    #[test]
    fn profile_schema_role_wrong_type_is_error() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = true
ttl = 3600
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("string"),
            "Error must mention wrong type, got: {}",
            msg
        );
    }

    #[test]
    fn profile_schema_env_key_wrong_type_is_error() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
env_key = 42
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("string"),
            "Error must mention wrong type, got: {}",
            msg
        );
    }

    #[test]
    fn profile_schema_ttl_as_string_is_error() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = "3600"
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("integer"),
            "Error must mention wrong type, got: {}",
            msg
        );
    }

    #[test]
    fn profile_schema_empty_provider_is_error() {
        let toml = r#"
[[credentials]]
provider = ""
role = "admin"
ttl = 3600
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err(), "Empty provider must be rejected");
    }

    #[test]
    fn profile_schema_empty_role_is_error() {
        let toml = r#"
[[credentials]]
provider = "aws"
role = ""
ttl = 3600
"#;
        let result = super::parse_profile_toml(toml);
        assert!(result.is_err(), "Empty role must be rejected");
    }

    #[test]
    fn profile_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<super::ProfileError>();
    }

    #[test]
    fn profile_error_not_found_display() {
        let err = super::ProfileError::NotFound {
            path: PathBuf::from("/etc/noscope/profiles/missing.toml"),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("missing.toml"),
            "Display must contain the path: {}",
            msg
        );
    }

    #[test]
    fn profile_error_insecure_permissions_display() {
        let err = super::ProfileError::InsecurePermissions {
            path: PathBuf::from("/etc/noscope/profiles/bad.toml"),
            mode: 0o644,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("644"), "Display must show mode: {}", msg);
        assert!(msg.contains("bad.toml"), "Display must show path: {}", msg);
    }

    #[test]
    fn profile_error_validation_failed_display_all_problems() {
        let err = super::ProfileError::ValidationFailed {
            problems: vec![
                "provider 'aws' not found".to_string(),
                "duplicate env_key 'TOKEN'".to_string(),
            ],
        };
        let msg = format!("{}", err);
        assert!(msg.contains("aws"), "Must list aws problem: {}", msg);
        assert!(msg.contains("TOKEN"), "Must list TOKEN problem: {}", msg);
    }

    #[test]
    fn profile_cli_mutual_exclusion_error_includes_profile_name() {
        let result = super::check_profile_flag_exclusion(Some("staging"), Some("aws"), None, None);
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("staging"),
            "Error must include profile name: {}",
            msg
        );
    }

    #[test]
    fn profile_cli_mutual_exclusion_neither_set() {
        // Both None — should be valid.
        let result = super::check_profile_flag_exclusion(None, None, None, None);
        assert!(result.is_ok(), "Neither set should be valid");
    }
}
