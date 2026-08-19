// Strict config precedence
// Config follows XDG Base Directory
// Malformed config is hard error
// Provider not found enumerates checked locations
// Config file permission enforcement
// Dry-run mode
// Provider contract version
// Provider validation command

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::ports::config_path::named_config_toml_path;
use provenance_macros::rule;

/// The current provider contract version.
/// When mint output format, exit code protocol, or input contracts change,
/// this version increments. noscope must support the current version and the
/// immediately previous version for backward compatibility.
pub const CURRENT_CONTRACT_VERSION: u32 = 1;

/// Return the list of supported contract versions.
/// Always includes the current version and the previous version (if one exists).
/// Since version 1 is the first, there is no version 0 — only [1] is returned.
pub fn supported_contract_versions() -> Vec<u32> {
    let mut versions = vec![CURRENT_CONTRACT_VERSION];
    if CURRENT_CONTRACT_VERSION > 1 {
        versions.push(CURRENT_CONTRACT_VERSION - 1);
    }
    versions
}

/// Validate that a contract version is supported.
/// Rejects versions not in the supported set.
#[rule("rule_config_contract_version_gate")]
pub fn validate_contract_version(version: u32) -> Result<(), ProviderConfigError> {
    let supported = supported_contract_versions();
    if supported.contains(&version) {
        Ok(())
    } else {
        Err(ProviderConfigError::UnsupportedContractVersion { version, supported })
    }
}

/// Error type for provider configuration failures.
#[derive(Debug)]
pub enum ProviderConfigError {
    /// Syntactically invalid TOML or missing required fields.
    MalformedConfig { message: String },
    /// Provider not found at any layer.
    ProviderNotFound {
        provider: String,
        checked_locations: Vec<String>,
    },
    /// Config file has insecure permissions.
    InsecurePermissions { path: PathBuf, mode: u32 },
    /// Unsupported provider contract version.
    UnsupportedContractVersion { version: u32, supported: Vec<u32> },
    /// Provider validation found problems.
    ValidationFailed { problems: Vec<String> },
}

impl fmt::Display for ProviderConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedConfig { message } => {
                write!(f, "malformed provider config: {}", message)
            }
            Self::ProviderNotFound {
                provider,
                checked_locations,
            } => {
                write!(f, "provider '{}' not found; checked: ", provider)?;
                for (i, loc) in checked_locations.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", loc)?;
                }
                Ok(())
            }
            Self::InsecurePermissions { path, mode } => {
                write!(
                    f,
                    "config file {:?} has insecure permissions {:04o}; \
                     group-writable and world-accessible bits must be 0 (e.g. 0600, 0640)",
                    path, mode
                )
            }
            Self::UnsupportedContractVersion { version, supported } => {
                write!(
                    f,
                    "unsupported provider contract_version {}; supported versions: {:?}",
                    version, supported
                )
            }
            Self::ValidationFailed { problems } => {
                write!(f, "provider validation failed: ")?;
                for (i, p) in problems.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{}", p)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ProviderConfigError {}

/// Where the winning config layer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    Flags,
    EnvVars,
    File,
}

/// Shared command override input used by flags/env layers.
#[derive(Debug, Default, Clone)]
pub struct ProviderCommandInput {
    pub mint_cmd: Option<String>,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
}

impl ProviderCommandInput {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns true if any flag is set.
    pub fn has_any(&self) -> bool {
        self.mint_cmd.is_some() || self.refresh_cmd.is_some() || self.revoke_cmd.is_some()
    }
}

/// CLI flags for provider configuration (highest precedence).
pub type ProviderFlags = ProviderCommandInput;

/// Environment variable layer for provider configuration (middle precedence).
pub type ProviderEnv = ProviderCommandInput;

/// Read provider env overrides from the process environment.
/// Looks for `NOSCOPE_MINT_CMD`, `NOSCOPE_REFRESH_CMD`, and
/// `NOSCOPE_REVOKE_CMD`. Missing or empty vars yield `None`.
/// This is a standalone function (not a method on `ProviderEnv`) because
/// `ProviderEnv` is a type alias for `ProviderCommandInput`. An `impl`
/// block on a type alias would leak the method onto `ProviderFlags` too,
/// which is semantically wrong — flags don't come from env vars.
#[rule("rule_config_env_override_vars")]
pub fn provider_env_from_process() -> ProviderEnv {
    fn read_var(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.is_empty())
    }
    ProviderEnv {
        mint_cmd: read_var("NOSCOPE_MINT_CMD"),
        refresh_cmd: read_var("NOSCOPE_REFRESH_CMD"),
        revoke_cmd: read_var("NOSCOPE_REVOKE_CMD"),
    }
}

/// Provider capability declaration.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapabilities {
    /// Whether this provider supports token refresh.
    pub supports_refresh: bool,
    /// Whether this provider supports token revocation.
    pub supports_revoke: bool,
}

/// Parsed provider config from a TOML file (lowest precedence).
#[derive(Debug)]
pub struct FileProviderConfig {
    /// Provider contract version from the config file.
    pub contract_version: u32,
    pub mint_cmd: String,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
    pub env: HashMap<String, String>,
    pub capabilities: ProviderCapabilities,
}

/// Typed intermediate state for precedence selection.
#[derive(Debug)]
pub enum SelectedProviderConfigLayer {
    Flags(ProviderCommandInput),
    EnvVars(ProviderCommandInput),
    File(FileProviderConfig),
}

/// Fully resolved provider configuration after precedence resolution.
#[derive(Debug, Clone)]
pub struct ResolvedProvider {
    pub name: String,
    /// Contract version from the file config layer.
    /// `None` when the config came from flags or env (which don't carry
    /// a contract version — they're overrides, not full configs).
    pub contract_version: Option<u32>,
    pub mint_cmd: String,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
    pub env: HashMap<String, String>,
    pub source: ConfigSource,
}

/// Compute the config file path for a named provider.
/// Uses XDG_CONFIG_HOME if provided, otherwise falls back to
/// `$HOME/.config`.
/// Returns `Err` if the name contains path traversal characters.
pub fn provider_config_path(
    name: &str,
    xdg_config_home: Option<&Path>,
) -> Result<PathBuf, crate::ports::config_path::ConfigPathError> {
    named_config_toml_path(xdg_config_home, None, "providers", name)
}

/// Same as `provider_config_path` but with explicit HOME fallback.
/// Used when XDG_CONFIG_HOME is not set.
/// Returns `Err` if the name contains path traversal characters.
pub fn provider_config_path_with_home(
    name: &str,
    xdg_config_home: Option<&Path>,
    home: &Path,
) -> Result<PathBuf, crate::ports::config_path::ConfigPathError> {
    named_config_toml_path(xdg_config_home, Some(home), "providers", name)
}

/// Parse provider TOML content into a FileProviderConfig.
/// Returns MalformedConfig error for syntax errors or missing required fields.
/// Returns UnsupportedContractVersion for versions outside the supported set.
#[rule("rule_config_provider_toml_schema")]
pub fn parse_provider_toml(content: &str) -> Result<FileProviderConfig, ProviderConfigError> {
    let table: toml::Table =
        content
            .parse()
            .map_err(|e: toml::de::Error| ProviderConfigError::MalformedConfig {
                message: e.to_string(),
            })?;

    // Parse and validate contract_version (required).
    let contract_version = match table.get("contract_version") {
        Some(v) => match v.as_integer() {
            Some(n) if n > 0 => {
                let version = n as u32;
                validate_contract_version(version)?;
                version
            }
            Some(_) => {
                return Err(ProviderConfigError::MalformedConfig {
                    message: "contract_version must be a positive integer".to_string(),
                });
            }
            None => {
                return Err(ProviderConfigError::MalformedConfig {
                    message: "contract_version must be an integer".to_string(),
                });
            }
        },
        None => {
            return Err(ProviderConfigError::MalformedConfig {
                message: "missing required field: contract_version".to_string(),
            });
        }
    };

    let commands = table.get("commands").and_then(|v| v.as_table()).ok_or(
        ProviderConfigError::MalformedConfig {
            message: "missing required [commands] section".to_string(),
        },
    )?;

    let mint_cmd = commands.get("mint").and_then(|v| v.as_str()).ok_or(
        ProviderConfigError::MalformedConfig {
            message: "missing required field: commands.mint".to_string(),
        },
    )?;

    if mint_cmd.is_empty() {
        return Err(ProviderConfigError::MalformedConfig {
            message: "commands.mint must not be empty".to_string(),
        });
    }

    let refresh_cmd = commands
        .get("refresh")
        .and_then(|v| v.as_str())
        .map(String::from);
    let revoke_cmd = commands
        .get("revoke")
        .and_then(|v| v.as_str())
        .map(String::from);

    let env = commands
        .get("env")
        .and_then(|v| v.as_table())
        .map(|t| {
            t.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let supports_refresh = parse_optional_bool(&table, "supports_refresh")?;
    let supports_revoke = parse_optional_bool(&table, "supports_revoke")?;

    let capabilities = ProviderCapabilities {
        supports_refresh,
        supports_revoke,
    };

    validate_declared_capabilities(&capabilities, refresh_cmd.is_some(), revoke_cmd.is_some())?;

    Ok(FileProviderConfig {
        contract_version,
        mint_cmd: mint_cmd.to_string(),
        refresh_cmd,
        revoke_cmd,
        env,
        capabilities,
    })
}

fn parse_optional_bool(table: &toml::Table, key: &str) -> Result<bool, ProviderConfigError> {
    match table.get(key) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| ProviderConfigError::MalformedConfig {
                message: format!("{} must be a boolean", key),
            }),
        None => Ok(false),
    }
}

/// Validate capability declarations against configured commands.
#[rule("rule_cross_capability_consistency")]
pub fn validate_declared_capabilities(
    caps: &ProviderCapabilities,
    has_refresh_cmd: bool,
    has_revoke_cmd: bool,
) -> Result<(), ProviderConfigError> {
    if caps.supports_refresh && !has_refresh_cmd {
        return Err(ProviderConfigError::MalformedConfig {
            message: "supports_refresh=true but no refresh command configured".to_string(),
        });
    }

    if caps.supports_revoke && !has_revoke_cmd {
        return Err(ProviderConfigError::MalformedConfig {
            message: "supports_revoke=true but no revoke command configured".to_string(),
        });
    }

    Ok(())
}

/// Load a provider config file from disk.
/// Returns `Ok(None)` if the file does not exist (missing file = layer absent).
/// Returns `Err` for permission issues, malformed TOML, or missing required fields.
pub fn load_provider_file(path: &Path) -> Result<Option<FileProviderConfig>, ProviderConfigError> {
    if !path.exists() {
        return Ok(None);
    }

    check_config_permissions(path)?;

    let content = fs::read_to_string(path).map_err(|e| ProviderConfigError::MalformedConfig {
        message: format!("failed to read {}: {}", path.display(), e),
    })?;

    parse_provider_toml(&content).map(Some)
}

/// Bitmask of permission bits that are insecure for secret-bearing config files.
/// - `0o020`: group-write — another user in the same group could modify secrets.
/// - `0o007`: world (other) read/write/execute — anyone on the system could access.
///
/// Allowed: owner-only (0600, 0700, 0400) or owner+group-read (0640, 0750, 0440).
/// Rejected: group-writable (0660, 0620) or world-accessible (0644, 0666, 0604).
const INSECURE_MODE_BITS: u32 = 0o020 | 0o007;

/// Check that a config file has secure permissions.
/// Secret-bearing config files must not be group-writable or world-accessible.
/// See [`INSECURE_MODE_BITS`] for the exact policy.
#[rule("rule_cross_config_file_permissions")]
pub fn check_config_permissions(path: &Path) -> Result<(), ProviderConfigError> {
    let metadata = fs::metadata(path).map_err(|e| ProviderConfigError::MalformedConfig {
        message: format!("cannot stat {}: {}", path.display(), e),
    })?;

    let mode = metadata.permissions().mode();

    if mode & INSECURE_MODE_BITS != 0 {
        return Err(ProviderConfigError::InsecurePermissions {
            path: path.to_path_buf(),
            mode: mode & 0o777,
        });
    }

    Ok(())
}

/// Resolve provider configuration with strict precedence.
/// Precedence: flags > env vars > config file. No merging across layers.
/// The highest-precedence layer that has ANY value wins entirely.
/// Returns ProviderNotFound with checked locations if no layer provides config.
#[rule("rule_config_not_found_lists_locations")]
pub fn resolve_provider_config(
    name: &str,
    flags: &ProviderFlags,
    env: &ProviderEnv,
    file_config: Option<FileProviderConfig>,
) -> Result<ResolvedProvider, ProviderConfigError> {
    let config_path =
        provider_config_path(name, None).map_err(|e| ProviderConfigError::MalformedConfig {
            message: format!("{}", e),
        })?;
    resolve_provider_config_at(name, flags, env, file_config, &config_path)
}

/// Same as [`resolve_provider_config`], but names the config file location
/// that was actually checked instead of recomputing it from the
/// process environment.
pub fn resolve_provider_config_at(
    name: &str,
    flags: &ProviderFlags,
    env: &ProviderEnv,
    file_config: Option<FileProviderConfig>,
    config_path: &Path,
) -> Result<ResolvedProvider, ProviderConfigError> {
    if let Some(selected) = select_provider_config_layer(flags, env, file_config) {
        return Ok(match selected {
            SelectedProviderConfigLayer::Flags(input) => ResolvedProvider {
                name: name.to_string(),
                contract_version: None,
                mint_cmd: input.mint_cmd.unwrap_or_default(),
                refresh_cmd: input.refresh_cmd,
                revoke_cmd: input.revoke_cmd,
                env: HashMap::new(),
                source: ConfigSource::Flags,
            },
            SelectedProviderConfigLayer::EnvVars(input) => ResolvedProvider {
                name: name.to_string(),
                contract_version: None,
                mint_cmd: input.mint_cmd.unwrap_or_default(),
                refresh_cmd: input.refresh_cmd,
                revoke_cmd: input.revoke_cmd,
                env: HashMap::new(),
                source: ConfigSource::EnvVars,
            },
            SelectedProviderConfigLayer::File(fc) => ResolvedProvider {
                name: name.to_string(),
                contract_version: Some(fc.contract_version),
                mint_cmd: fc.mint_cmd,
                refresh_cmd: fc.refresh_cmd,
                revoke_cmd: fc.revoke_cmd,
                env: fc.env,
                source: ConfigSource::File,
            },
        });
    }

    // No layer provided config — enumerate checked locations.
    Err(ProviderConfigError::ProviderNotFound {
        provider: name.to_string(),
        checked_locations: vec![
            "flag --mint-cmd (not set)".to_string(),
            "env NOSCOPE_MINT_CMD (not set)".to_string(),
            format!("file {} (not found)", config_path.display()),
        ],
    })
}

/// Select the highest-precedence provider config layer with any values.
#[rule("rule_config_precedence_no_merge")]
pub fn select_provider_config_layer(
    flags: &ProviderFlags,
    env: &ProviderEnv,
    file_config: Option<FileProviderConfig>,
) -> Option<SelectedProviderConfigLayer> {
    if flags.has_any() {
        return Some(SelectedProviderConfigLayer::Flags(flags.clone()));
    }

    if env.has_any() {
        return Some(SelectedProviderConfigLayer::EnvVars(env.clone()));
    }

    file_config.map(SelectedProviderConfigLayer::File)
}

/// Generate dry-run output for a resolved provider.
/// Shows the mint command, role, TTL, and config source without executing anything.
pub fn dry_run_output(config: &ResolvedProvider, role: &str, ttl_secs: u64) -> String {
    let source_label = match config.source {
        ConfigSource::Flags => "flags",
        ConfigSource::EnvVars => "environment variables",
        ConfigSource::File => "config file",
    };

    let mut out = format!(
        "dry-run: provider '{}' (from {})\n\
         dry-run: mint command: {}\n\
         dry-run: role: {}\n\
         dry-run: ttl: {}s",
        config.name, source_label, config.mint_cmd, role, ttl_secs
    );

    if let Some(ref refresh) = config.refresh_cmd {
        out.push_str(&format!("\ndry-run: refresh command: {}", refresh));
    }
    if let Some(ref revoke) = config.revoke_cmd {
        out.push_str(&format!("\ndry-run: revoke command: {}", revoke));
    }
    if !config.env.is_empty() {
        out.push_str("\ndry-run: environment:");
        for (k, v) in &config.env {
            out.push_str(&format!("\n  {}={}", k, v));
        }
    }

    out
}

/// Validate a resolved provider configuration.
/// Checks that all configured commands exist and are executable.
/// Does NOT execute any commands.
#[rule("rule_validate_checks_without_running")]
pub fn validate_provider(config: &ResolvedProvider) -> Result<(), ProviderConfigError> {
    let mut problems = Vec::new();

    check_command_executable(&config.mint_cmd, "mint", &mut problems);

    if let Some(ref cmd) = config.refresh_cmd {
        check_command_executable(cmd, "refresh", &mut problems);
    }

    if let Some(ref cmd) = config.revoke_cmd {
        check_command_executable(cmd, "revoke", &mut problems);
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(ProviderConfigError::ValidationFailed { problems })
    }
}

/// Check that a command path exists and is executable.
/// Appends problems to the list without executing the command.
fn check_command_executable(cmd: &str, label: &str, problems: &mut Vec<String>) {
    let path = Path::new(cmd);

    if !path.exists() {
        problems.push(format!("{} command not found: {}", label, cmd));
        return;
    }

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            problems.push(format!("{} command not accessible: {}: {}", label, cmd, e));
            return;
        }
    };

    let mode = metadata.permissions().mode();
    // Check if any execute bit is set (owner, group, or other).
    if mode & 0o111 == 0 {
        problems.push(format!(
            "{} command is not executable: {} (mode {:04o})",
            label,
            cmd,
            mode & 0o777
        ));
    }
}

#[cfg(test)]
mod tests;
