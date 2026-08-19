use provenance_macros::rule;
use std::fmt;
use std::path::{Path, PathBuf};

/// Error type for config name validation failures.
/// Returned when a provider or profile name contains path traversal
/// characters (`/`, `\`, `..`) or is otherwise unsafe for use as a
/// filesystem path component.
#[derive(Debug)]
pub struct ConfigPathError {
    name: String,
    reason: &'static str,
}

impl ConfigPathError {
    /// The rejected name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Why the name was rejected.
    pub fn reason(&self) -> &str {
        self.reason
    }
}

impl fmt::Display for ConfigPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid config name '{}': {}", self.name, self.reason)
    }
}

impl std::error::Error for ConfigPathError {}

/// Validate that a config name is safe for use as a single path component.
/// **Allowed characters:** ASCII alphanumeric (`a-z`, `A-Z`, `0-9`),
/// hyphen (`-`), underscore (`_`), and dot (`.`).
/// **Rejected:**
/// - Empty string
/// - `.` or `..` (current/parent directory)
/// - Any character outside the allowed set (path separators, NUL,
///   whitespace, control characters, colons, tildes, etc.)
///
/// This is a strict allowlist — only characters known to be safe as
/// filesystem path components on all supported platforms are permitted.
#[rule("rule_config_name_allowlist")]
pub(crate) fn validate_config_name(name: &str) -> Result<(), ConfigPathError> {
    if name.is_empty() {
        return Err(ConfigPathError {
            name: name.to_string(),
            reason: "name must not be empty",
        });
    }

    if name == "." || name == ".." {
        return Err(ConfigPathError {
            name: name.to_string(),
            reason: "name must not be '.' or '..'",
        });
    }

    for ch in name.chars() {
        let allowed = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.';
        if !allowed {
            return Err(ConfigPathError {
                name: name.to_string(),
                reason: "name contains invalid characters; \
                         only ASCII alphanumeric, hyphen, underscore, and dot are allowed",
            });
        }
    }

    Ok(())
}

fn config_base_dir(xdg_config_home: Option<&Path>, home: Option<&Path>) -> PathBuf {
    match xdg_config_home {
        Some(base) => base.to_path_buf(),
        None => {
            let home_dir = match home {
                Some(path) => path.to_path_buf(),
                None => {
                    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
                }
            };
            home_dir.join(".config")
        }
    }
}

pub(crate) fn named_config_toml_path(
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
    domain: &str,
    name: &str,
) -> Result<PathBuf, ConfigPathError> {
    validate_config_name(name)?;
    Ok(config_base_dir(xdg_config_home, home)
        .join("noscope")
        .join(domain)
        .join(format!("{}.toml", name)))
}

#[cfg(test)]
mod tests;
