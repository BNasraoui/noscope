// Profile flatness constraint
// Profile schema
// Profile validation before minting
// Profile and CLI flag mutual exclusion

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::exit_code::NoscopeExitCode;
use crate::ports::config_path::named_config_toml_path;
use crate::ports::provider::check_config_permissions;
use provenance_macros::rule;

/// Known fields in a [[credentials]] entry.
/// provider (required), role (required), ttl (required), env_key (optional).
/// Any field not in this set is an error.
const KNOWN_CREDENTIAL_FIELDS: &[&str] = &["provider", "role", "ttl", "env_key"];

/// A single credential entry from a profile.
/// Flat tuple of (provider, role, ttl) with optional env_key.
/// No nesting, no inheritance, no composition.
#[derive(Debug)]
pub struct ProfileCredential {
    pub provider: String,
    pub role: String,
    pub ttl: u64,
    pub env_key: Option<String>,
}

/// A parsed profile: a flat list of credential entries.
/// This is deliberately flat — no extends, no overrides,
/// no merge strategy. Just a Vec of credentials.
#[derive(Debug)]
pub struct Profile {
    pub credentials: Vec<ProfileCredential>,
}

/// Error type for profile operations.
#[derive(Debug)]
pub enum ProfileError {
    /// Malformed profile TOML or schema violation.
    MalformedProfile { message: String },
    /// Profile validation failed (provider existence, env_key
    /// uniqueness). Contains all problems found in a single pass.
    ValidationFailed { problems: Vec<String> },
    /// --profile used with forbidden credential flags.
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
/// Uses XDG_CONFIG_HOME if provided, otherwise falls back to
/// `$HOME/.config`.
/// Returns `Err` if the name contains path traversal characters.
pub fn profile_config_path(
    name: &str,
    xdg_config_home: Option<&Path>,
) -> Result<PathBuf, crate::ports::config_path::ConfigPathError> {
    named_config_toml_path(xdg_config_home, None, "profiles", name)
}

/// Same as `profile_config_path` but with explicit HOME fallback.
/// Returns `Err` if the name contains path traversal characters.
pub fn profile_config_path_with_home(
    name: &str,
    xdg_config_home: Option<&Path>,
    home: &Path,
) -> Result<PathBuf, crate::ports::config_path::ConfigPathError> {
    named_config_toml_path(xdg_config_home, Some(home), "profiles", name)
}

/// Parse profile TOML content into a Profile.
/// Validates schema: required fields, unknown credential fields = error,
/// empty credentials = error. Unknown top-level fields are ignored.
#[rule("rule_profile_schema")]
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

    // empty array = error.
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

        // Check for unknown credential fields.
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

/// Validate a parsed profile before minting.
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
        if let Some(ref key) = cred.env_key {
            if !seen_env_keys.insert(key.clone()) {
                errors.push(format!("duplicate env_key '{}'", key));
            }
        }
    }

    errors
}

/// Check mutual exclusion between --profile and credential flags.
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
/// Unlike provider config (which returns Ok(None) for missing files),
/// an explicitly requested profile must exist. Returns an error if
/// the file is missing or has insecure permissions.
#[rule("rule_profile_named_must_exist")]
pub fn load_profile(path: &Path) -> Result<Profile, ProfileError> {
    if !path.exists() {
        return Err(ProfileError::NotFound {
            path: path.to_path_buf(),
        });
    }

    // Reuse the provider permission check.
    check_config_permissions(path).map_err(|e| match e {
        crate::ports::provider::ProviderConfigError::InsecurePermissions { path, mode } => {
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
mod tests;
