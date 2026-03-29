// NS-007: Strict config precedence
// NS-042: Config follows XDG Base Directory
// NS-043: Malformed config is hard error
// NS-044: Provider not found enumerates checked locations
// NS-069: Config file permission enforcement
// NS-071: Dry-run mode
// NS-072: Provider contract version
// NS-073: Provider validation command

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// NS-072: The current provider contract version.
///
/// When mint output format, exit code protocol, or input contracts change,
/// this version increments. noscope must support the current version and the
/// immediately previous version for backward compatibility.
pub const CURRENT_CONTRACT_VERSION: u32 = 1;

/// NS-072: Return the list of supported contract versions.
///
/// Always includes the current version and the previous version (if one exists).
/// Since version 1 is the first, there is no version 0 — only [1] is returned.
pub fn supported_contract_versions() -> Vec<u32> {
    let mut versions = vec![CURRENT_CONTRACT_VERSION];
    if CURRENT_CONTRACT_VERSION > 1 {
        versions.push(CURRENT_CONTRACT_VERSION - 1);
    }
    versions
}

/// NS-072: Validate that a contract version is supported.
///
/// Rejects versions not in the supported set.
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
    /// NS-043: Syntactically invalid TOML or missing required fields.
    MalformedConfig { message: String },
    /// NS-044: Provider not found at any layer.
    ProviderNotFound {
        provider: String,
        checked_locations: Vec<String>,
    },
    /// NS-069: Config file has insecure permissions.
    InsecurePermissions { path: PathBuf, mode: u32 },
    /// NS-072: Unsupported provider contract version.
    UnsupportedContractVersion { version: u32, supported: Vec<u32> },
    /// NS-073: Provider validation found problems.
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
                     world-accessible bits must be 0 (e.g. 0600, 0640)",
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

/// CLI flags for provider configuration (highest precedence).
#[derive(Debug, Default)]
pub struct ProviderFlags {
    pub mint_cmd: Option<String>,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
}

impl ProviderFlags {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns true if any flag is set.
    pub fn has_any(&self) -> bool {
        self.mint_cmd.is_some() || self.refresh_cmd.is_some() || self.revoke_cmd.is_some()
    }
}

/// Environment variable layer for provider configuration (middle precedence).
#[derive(Debug, Default)]
pub struct ProviderEnv {
    pub mint_cmd: Option<String>,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
}

impl ProviderEnv {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns true if any env var is set.
    pub fn has_any(&self) -> bool {
        self.mint_cmd.is_some() || self.refresh_cmd.is_some() || self.revoke_cmd.is_some()
    }
}

/// Parsed provider config from a TOML file (lowest precedence).
#[derive(Debug)]
pub struct FileProviderConfig {
    /// NS-072: Provider contract version from the config file.
    pub contract_version: u32,
    pub mint_cmd: String,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
    pub env: HashMap<String, String>,
}

/// Fully resolved provider configuration after precedence resolution.
#[derive(Debug)]
pub struct ResolvedProvider {
    pub name: String,
    /// NS-072: Contract version from the file config layer.
    /// `None` when the config came from flags or env (which don't carry
    /// a contract version — they're overrides, not full configs).
    pub contract_version: Option<u32>,
    pub mint_cmd: String,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
    pub env: HashMap<String, String>,
    pub source: ConfigSource,
}

/// Build the provider TOML path under a given config base directory.
fn provider_toml_under(base: &Path, name: &str) -> PathBuf {
    base.join("noscope")
        .join("providers")
        .join(format!("{}.toml", name))
}

/// NS-042: Compute the config file path for a named provider.
///
/// Uses XDG_CONFIG_HOME if provided, otherwise falls back to
/// `$HOME/.config`.
pub fn provider_config_path(name: &str, xdg_config_home: Option<&Path>) -> PathBuf {
    match xdg_config_home {
        Some(base) => provider_toml_under(base, name),
        None => {
            // Fall back to $HOME/.config when XDG_CONFIG_HOME is absent.
            // In production, HOME comes from the environment; tests use
            // provider_config_path_with_home() to control it explicitly.
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            provider_toml_under(&PathBuf::from(home).join(".config"), name)
        }
    }
}

/// NS-042: Same as `provider_config_path` but with explicit HOME fallback.
/// Used when XDG_CONFIG_HOME is not set.
pub fn provider_config_path_with_home(
    name: &str,
    xdg_config_home: Option<&Path>,
    home: &Path,
) -> PathBuf {
    match xdg_config_home {
        Some(base) => provider_toml_under(base, name),
        None => provider_toml_under(&home.join(".config"), name),
    }
}

/// NS-043 + NS-072: Parse provider TOML content into a FileProviderConfig.
///
/// Returns MalformedConfig error for syntax errors or missing required fields.
/// Returns UnsupportedContractVersion for versions outside the supported set.
pub fn parse_provider_toml(content: &str) -> Result<FileProviderConfig, ProviderConfigError> {
    let table: toml::Table =
        content
            .parse()
            .map_err(|e: toml::de::Error| ProviderConfigError::MalformedConfig {
                message: e.to_string(),
            })?;

    // NS-072: Parse and validate contract_version (required).
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

    Ok(FileProviderConfig {
        contract_version,
        mint_cmd: mint_cmd.to_string(),
        refresh_cmd,
        revoke_cmd,
        env,
    })
}

/// NS-043 + NS-069: Load a provider config file from disk.
///
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

/// NS-069: Check that a config file has secure permissions.
///
/// Rejects world-readable files. The "other" permission bits (lowest 3 bits
/// of the mode) must be zero. This allows 0600, 0640, 0400, etc. but
/// rejects 0644, 0604, 0666, etc.
pub fn check_config_permissions(path: &Path) -> Result<(), ProviderConfigError> {
    let metadata = fs::metadata(path).map_err(|e| ProviderConfigError::MalformedConfig {
        message: format!("cannot stat {}: {}", path.display(), e),
    })?;

    let mode = metadata.permissions().mode();
    let other_bits = mode & 0o007;

    if other_bits != 0 {
        return Err(ProviderConfigError::InsecurePermissions {
            path: path.to_path_buf(),
            mode: mode & 0o777,
        });
    }

    Ok(())
}

/// NS-007 + NS-044: Resolve provider configuration with strict precedence.
///
/// Precedence: flags > env vars > config file. No merging across layers.
/// The highest-precedence layer that has ANY value wins entirely.
///
/// Returns ProviderNotFound with checked locations if no layer provides config.
pub fn resolve_provider_config(
    name: &str,
    flags: &ProviderFlags,
    env: &ProviderEnv,
    file_config: Option<FileProviderConfig>,
) -> Result<ResolvedProvider, ProviderConfigError> {
    // NS-007: Strict precedence — highest layer with ANY value wins entirely.
    // No merging across layers.

    // Layer 1 (highest): CLI flags
    if flags.has_any() {
        // Flags must provide mint_cmd to be a valid layer.
        let mint_cmd = flags.mint_cmd.clone().unwrap_or_default();
        return Ok(ResolvedProvider {
            name: name.to_string(),
            contract_version: None,
            mint_cmd,
            refresh_cmd: flags.refresh_cmd.clone(),
            revoke_cmd: flags.revoke_cmd.clone(),
            env: HashMap::new(),
            source: ConfigSource::Flags,
        });
    }

    // Layer 2: Environment variables
    if env.has_any() {
        let mint_cmd = env.mint_cmd.clone().unwrap_or_default();
        return Ok(ResolvedProvider {
            name: name.to_string(),
            contract_version: None,
            mint_cmd,
            refresh_cmd: env.refresh_cmd.clone(),
            revoke_cmd: env.revoke_cmd.clone(),
            env: HashMap::new(),
            source: ConfigSource::EnvVars,
        });
    }

    // Layer 3 (lowest): Config file
    if let Some(fc) = file_config {
        return Ok(ResolvedProvider {
            name: name.to_string(),
            contract_version: Some(fc.contract_version),
            mint_cmd: fc.mint_cmd,
            refresh_cmd: fc.refresh_cmd,
            revoke_cmd: fc.revoke_cmd,
            env: fc.env,
            source: ConfigSource::File,
        });
    }

    // NS-044: No layer provided config — enumerate checked locations.
    let config_path = provider_config_path(name, None);
    Err(ProviderConfigError::ProviderNotFound {
        provider: name.to_string(),
        checked_locations: vec![
            "flag --mint-cmd (not set)".to_string(),
            "env NOSCOPE_MINT_CMD (not set)".to_string(),
            format!("file {} (not found)", config_path.display()),
        ],
    })
}

/// NS-071: Generate dry-run output for a resolved provider.
///
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

/// NS-073: Validate a resolved provider configuration.
///
/// Checks that all configured commands exist and are executable.
/// Does NOT execute any commands.
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
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Helper: create a temporary directory with a provider TOML file.
    fn write_provider_toml(dir: &std::path::Path, name: &str, contents: &str) {
        let providers_dir = dir.join("noscope").join("providers");
        fs::create_dir_all(&providers_dir).unwrap();
        let file_path = providers_dir.join(format!("{}.toml", name));
        fs::write(&file_path, contents).unwrap();
        // Set secure permissions (0600)
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Helper: minimal valid provider TOML content.
    fn valid_provider_toml() -> &'static str {
        r#"
contract_version = 1

[commands]
mint = "/usr/bin/vault-mint"

[commands.env]
VAULT_ADDR = "https://vault.example.com"
"#
    }

    /// Helper: create ProviderFlags with just a mint_cmd override.
    fn flags_with_mint_cmd(cmd: &str) -> ProviderFlags {
        ProviderFlags {
            mint_cmd: Some(cmd.to_string()),
            refresh_cmd: None,
            revoke_cmd: None,
        }
    }

    // =========================================================================
    // NS-007: Strict config precedence — flags > env vars > config files;
    // no merging across layers; highest-precedence wins entirely.
    // =========================================================================

    #[test]
    fn strict_config_precedence_flags_win_over_env() {
        let flags = flags_with_mint_cmd("/from/flags/mint");
        let env = ProviderEnv {
            mint_cmd: Some("/from/env/mint".to_string()),
            refresh_cmd: Some("/from/env/refresh".to_string()),
            revoke_cmd: None,
        };

        let resolved = resolve_provider_config("test-provider", &flags, &env, None).unwrap();

        assert_eq!(resolved.mint_cmd, "/from/flags/mint");
        // NS-007: "no merging" — env's refresh_cmd must NOT leak through
        assert!(
            resolved.refresh_cmd.is_none(),
            "flags layer wins entirely — env refresh_cmd must not merge in"
        );
    }

    #[test]
    fn strict_config_precedence_env_wins_over_file() {
        let tmp = tempfile::tempdir().unwrap();
        write_provider_toml(tmp.path(), "mycloud", valid_provider_toml());

        let flags = ProviderFlags::empty();
        let env = ProviderEnv {
            mint_cmd: Some("/from/env/mint".to_string()),
            refresh_cmd: None,
            revoke_cmd: None,
        };
        let file_config = FileProviderConfig {
            contract_version: 1,
            mint_cmd: "/from/file/mint".to_string(),
            refresh_cmd: Some("/from/file/refresh".to_string()),
            revoke_cmd: None,
            env: Default::default(),
        };

        let resolved = resolve_provider_config("mycloud", &flags, &env, Some(file_config)).unwrap();

        assert_eq!(resolved.mint_cmd, "/from/env/mint");
        // NS-007: no merging — file's refresh_cmd must not leak through
        assert!(
            resolved.refresh_cmd.is_none(),
            "env layer wins entirely — file refresh_cmd must not merge in"
        );
    }

    #[test]
    fn strict_config_precedence_file_used_when_no_flags_or_env() {
        let file_config = FileProviderConfig {
            contract_version: 1,
            mint_cmd: "/from/file/mint".to_string(),
            refresh_cmd: Some("/from/file/refresh".to_string()),
            revoke_cmd: None,
            env: Default::default(),
        };

        let resolved = resolve_provider_config(
            "mycloud",
            &ProviderFlags::empty(),
            &ProviderEnv::empty(),
            Some(file_config),
        )
        .unwrap();

        assert_eq!(resolved.mint_cmd, "/from/file/mint");
        assert_eq!(resolved.refresh_cmd.as_deref(), Some("/from/file/refresh"));
    }

    #[test]
    fn strict_config_precedence_no_merging_across_layers() {
        let flags = flags_with_mint_cmd("/from/flags/mint");
        let env = ProviderEnv {
            mint_cmd: None,
            refresh_cmd: Some("/from/env/refresh".to_string()),
            revoke_cmd: Some("/from/env/revoke".to_string()),
        };
        let file_config = FileProviderConfig {
            contract_version: 1,
            mint_cmd: "/from/file/mint".to_string(),
            refresh_cmd: Some("/from/file/refresh".to_string()),
            revoke_cmd: Some("/from/file/revoke".to_string()),
            env: Default::default(),
        };

        let resolved = resolve_provider_config("test", &flags, &env, Some(file_config)).unwrap();

        assert_eq!(resolved.mint_cmd, "/from/flags/mint");
        assert!(resolved.refresh_cmd.is_none());
        assert!(resolved.revoke_cmd.is_none());
    }

    // =========================================================================
    // NS-042: Config follows XDG Base Directory
    // =========================================================================

    #[test]
    fn config_follows_xdg_base_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let xdg_config = tmp.path().to_path_buf();

        let path = provider_config_path("aws", Some(&xdg_config));
        assert_eq!(
            path,
            xdg_config
                .join("noscope")
                .join("providers")
                .join("aws.toml")
        );
    }

    #[test]
    fn config_xdg_defaults_to_home_dot_config() {
        let tmp = tempfile::tempdir().unwrap();
        let path = provider_config_path_with_home("aws", None, tmp.path());
        assert_eq!(
            path,
            tmp.path()
                .join(".config")
                .join("noscope")
                .join("providers")
                .join("aws.toml")
        );
    }

    #[test]
    fn config_xdg_custom_overrides_default() {
        let custom_xdg = PathBuf::from("/custom/xdg");
        let path = provider_config_path("gcp", Some(&custom_xdg));
        assert_eq!(
            path,
            PathBuf::from("/custom/xdg/noscope/providers/gcp.toml")
        );
    }

    // =========================================================================
    // NS-043: Malformed config is hard error
    // =========================================================================

    #[test]
    fn malformed_config_is_hard_error_syntax() {
        let bad_toml = "this is not [valid toml {{{}";
        let result = parse_provider_toml(bad_toml);
        assert!(result.is_err(), "Syntactically invalid TOML must be error");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProviderConfigError::MalformedConfig { .. }),
            "Error must be MalformedConfig variant, got: {:?}",
            err
        );
    }

    #[test]
    fn malformed_config_is_hard_error_missing_required_field() {
        let incomplete_toml = r#"
[commands]
refresh = "/usr/bin/refresh"
"#;
        let result = parse_provider_toml(incomplete_toml);
        assert!(result.is_err(), "Missing required field must be hard error");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProviderConfigError::MalformedConfig { .. }),
            "Missing required field must be MalformedConfig, got: {:?}",
            err
        );
    }

    #[test]
    fn malformed_config_missing_file_is_not_error() {
        let result = load_provider_file(&PathBuf::from("/nonexistent/path/provider.toml"));
        assert!(
            matches!(result, Ok(None)),
            "Missing file should return Ok(None), got: {:?}",
            result
        );
    }

    #[test]
    fn malformed_config_empty_mint_cmd_is_error() {
        let toml_with_empty_mint = r#"
contract_version = 1

[commands]
mint = ""
"#;
        let result = parse_provider_toml(toml_with_empty_mint);
        assert!(result.is_err(), "Empty mint command must be error");
    }

    // =========================================================================
    // NS-044: Provider not found enumerates checked locations
    // =========================================================================

    #[test]
    fn provider_not_found_enumerates_checked_locations() {
        let result = resolve_provider_config(
            "nonexistent",
            &ProviderFlags::empty(),
            &ProviderEnv::empty(),
            None,
        );

        assert!(result.is_err(), "Missing provider must be error");
        let err = result.unwrap_err();
        match err {
            ProviderConfigError::ProviderNotFound {
                checked_locations, ..
            } => {
                let has_file_path = checked_locations
                    .iter()
                    .any(|loc| loc.contains("providers/nonexistent.toml"));
                assert!(
                    has_file_path,
                    "Must enumerate file path, got: {:?}",
                    checked_locations
                );

                let has_env_var = checked_locations
                    .iter()
                    .any(|loc| loc.contains("NOSCOPE_MINT_CMD"));
                assert!(
                    has_env_var,
                    "Must enumerate env var name, got: {:?}",
                    checked_locations
                );

                let has_flag = checked_locations
                    .iter()
                    .any(|loc| loc.contains("--mint-cmd"));
                assert!(
                    has_flag,
                    "Must enumerate flag name, got: {:?}",
                    checked_locations
                );
            }
            other => panic!("Expected ProviderNotFound error, got: {:?}", other),
        }
    }

    #[test]
    fn provider_not_found_message_is_user_actionable() {
        let result = resolve_provider_config(
            "mycloud",
            &ProviderFlags::empty(),
            &ProviderEnv::empty(),
            None,
        );
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("mycloud"),
            "Error should name the provider: {}",
            msg
        );
    }

    // =========================================================================
    // NS-069: Config file permission enforcement
    // =========================================================================

    #[test]
    fn config_file_permission_enforcement_rejects_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("provider.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

        let result = check_config_permissions(&file_path);
        assert!(result.is_err(), "World-readable config must be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProviderConfigError::InsecurePermissions { .. }),
            "Error must be InsecurePermissions, got: {:?}",
            err
        );
    }

    #[test]
    fn config_file_permission_enforcement_allows_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("provider.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

        let result = check_config_permissions(&file_path);
        assert!(result.is_ok(), "0600 should be allowed");
    }

    #[test]
    fn config_file_permission_enforcement_allows_0640() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("provider.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o640)).unwrap();

        let result = check_config_permissions(&file_path);
        assert!(result.is_ok(), "0640 should be allowed");
    }

    #[test]
    fn config_file_permission_enforcement_rejects_0666() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("provider.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o666)).unwrap();

        let result = check_config_permissions(&file_path);
        assert!(result.is_err(), "0666 must be rejected");
    }

    #[test]
    fn config_file_permission_enforcement_rejects_0604() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("provider.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o604)).unwrap();

        let result = check_config_permissions(&file_path);
        assert!(result.is_err(), "0604 (other-read) must be rejected");
    }

    #[test]
    fn config_file_permission_enforcement_allows_0400() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("provider.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o400)).unwrap();

        let result = check_config_permissions(&file_path);
        assert!(result.is_ok(), "0400 (owner-read-only) should be allowed");
    }

    // =========================================================================
    // NS-071: Dry-run mode
    // =========================================================================

    #[test]
    fn dry_run_mode_produces_output() {
        let config = ResolvedProvider {
            name: "aws".to_string(),
            contract_version: Some(1),
            mint_cmd: "/usr/bin/aws-mint".to_string(),
            refresh_cmd: None,
            revoke_cmd: Some("/usr/bin/aws-revoke".to_string()),
            env: Default::default(),
            source: ConfigSource::File,
        };

        let output = dry_run_output(&config, "admin", 3600);
        assert!(!output.is_empty(), "Dry-run must produce output");
    }

    #[test]
    fn dry_run_mode_shows_mint_command() {
        let config = ResolvedProvider {
            name: "aws".to_string(),
            contract_version: Some(1),
            mint_cmd: "/usr/bin/aws-mint".to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::File,
        };

        let output = dry_run_output(&config, "admin", 3600);
        assert!(
            output.contains("/usr/bin/aws-mint"),
            "Dry-run must show the mint command, got: {}",
            output
        );
    }

    #[test]
    fn dry_run_mode_shows_role_and_ttl() {
        let config = ResolvedProvider {
            name: "vault".to_string(),
            contract_version: Some(1),
            mint_cmd: "/usr/bin/vault-mint".to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::File,
        };

        let output = dry_run_output(&config, "deployer", 7200);
        assert!(
            output.contains("deployer"),
            "Dry-run must show role: {}",
            output
        );
        assert!(output.contains("7200"), "Dry-run must show ttl: {}", output);
    }

    #[test]
    fn dry_run_mode_shows_config_source() {
        let config = ResolvedProvider {
            name: "aws".to_string(),
            contract_version: None,
            mint_cmd: "/usr/bin/aws-mint".to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::Flags,
        };

        let output = dry_run_output(&config, "admin", 3600);
        assert!(
            output.to_lowercase().contains("flag"),
            "Dry-run must show config source, got: {}",
            output
        );
    }

    // =========================================================================
    // NS-073: Provider validation command
    // =========================================================================

    #[test]
    fn validate_provider_checks_mint_cmd_exists() {
        let config = ResolvedProvider {
            name: "test".to_string(),
            contract_version: Some(1),
            mint_cmd: "/nonexistent/path/to/mint".to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::File,
        };

        let result = validate_provider(&config);
        assert!(
            result.is_err(),
            "Validation must fail when mint command does not exist"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProviderConfigError::ValidationFailed { .. }),
            "Error must be ValidationFailed, got: {:?}",
            err
        );
    }

    #[test]
    fn validate_provider_checks_mint_cmd_is_executable() {
        let tmp = tempfile::tempdir().unwrap();
        let mint_path = tmp.path().join("mint-script");
        fs::write(&mint_path, "#!/bin/sh\necho ok").unwrap();
        fs::set_permissions(&mint_path, fs::Permissions::from_mode(0o644)).unwrap();

        let config = ResolvedProvider {
            name: "test".to_string(),
            contract_version: Some(1),
            mint_cmd: mint_path.to_str().unwrap().to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::File,
        };

        let result = validate_provider(&config);
        assert!(
            result.is_err(),
            "Validation must fail when mint command is not executable"
        );
    }

    #[test]
    fn validate_provider_succeeds_for_valid_config() {
        let tmp = tempfile::tempdir().unwrap();
        let mint_path = tmp.path().join("mint-script");
        fs::write(&mint_path, "#!/bin/sh\necho ok").unwrap();
        fs::set_permissions(&mint_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = ResolvedProvider {
            name: "test".to_string(),
            contract_version: Some(1),
            mint_cmd: mint_path.to_str().unwrap().to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::File,
        };

        let result = validate_provider(&config);
        assert!(
            result.is_ok(),
            "Validation must pass for valid config, got: {:?}",
            result
        );
    }

    #[test]
    fn validate_provider_does_not_execute_mint_cmd() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("was-executed");
        let mint_path = tmp.path().join("mint-script");
        fs::write(&mint_path, format!("#!/bin/sh\ntouch {}", marker.display())).unwrap();
        fs::set_permissions(&mint_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = ResolvedProvider {
            name: "test".to_string(),
            contract_version: Some(1),
            mint_cmd: mint_path.to_str().unwrap().to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::File,
        };

        let _ = validate_provider(&config);
        assert!(
            !marker.exists(),
            "validate must NOT execute the mint command"
        );
    }

    #[test]
    fn validate_provider_checks_refresh_cmd_if_present() {
        let tmp = tempfile::tempdir().unwrap();
        let mint_path = tmp.path().join("mint-script");
        fs::write(&mint_path, "#!/bin/sh\necho ok").unwrap();
        fs::set_permissions(&mint_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = ResolvedProvider {
            name: "test".to_string(),
            contract_version: Some(1),
            mint_cmd: mint_path.to_str().unwrap().to_string(),
            refresh_cmd: Some("/nonexistent/refresh".to_string()),
            revoke_cmd: None,
            env: Default::default(),
            source: ConfigSource::File,
        };

        let result = validate_provider(&config);
        assert!(result.is_err(), "Validation must check refresh_cmd too");
    }

    #[test]
    fn validate_provider_checks_revoke_cmd_if_present() {
        let tmp = tempfile::tempdir().unwrap();
        let mint_path = tmp.path().join("mint-script");
        fs::write(&mint_path, "#!/bin/sh\necho ok").unwrap();
        fs::set_permissions(&mint_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = ResolvedProvider {
            name: "test".to_string(),
            contract_version: Some(1),
            mint_cmd: mint_path.to_str().unwrap().to_string(),
            refresh_cmd: None,
            revoke_cmd: Some("/nonexistent/revoke".to_string()),
            env: Default::default(),
            source: ConfigSource::File,
        };

        let result = validate_provider(&config);
        assert!(result.is_err(), "Validation must check revoke_cmd too");
    }

    // =========================================================================
    // Edge cases discovered during review
    // =========================================================================

    #[test]
    fn config_precedence_flags_without_mint_cmd_still_wins() {
        // If flags layer sets refresh_cmd but not mint_cmd, the flags layer
        // still wins (no merging) — mint_cmd comes from flags as empty.
        let flags = ProviderFlags {
            mint_cmd: None,
            refresh_cmd: Some("/from/flags/refresh".to_string()),
            revoke_cmd: None,
        };
        let env = ProviderEnv {
            mint_cmd: Some("/from/env/mint".to_string()),
            refresh_cmd: None,
            revoke_cmd: None,
        };

        let resolved = resolve_provider_config("test", &flags, &env, None).unwrap();
        // Flags layer wins entirely — even though mint_cmd is absent from flags
        assert_eq!(resolved.source, ConfigSource::Flags);
        assert_eq!(resolved.refresh_cmd.as_deref(), Some("/from/flags/refresh"));
        // mint_cmd is empty because flags layer didn't set it
        assert!(
            resolved.mint_cmd.is_empty(),
            "mint_cmd should be empty since flags layer didn't set it"
        );
    }

    #[test]
    fn parse_provider_toml_rejects_non_string_mint() {
        // commands.mint is an integer, not a string
        let toml = r#"
contract_version = 1

[commands]
mint = 42
"#;
        let result = parse_provider_toml(toml);
        assert!(result.is_err(), "Non-string mint value must be rejected");
    }

    #[test]
    fn parse_provider_toml_valid_with_all_commands() {
        let toml = r#"
contract_version = 1

[commands]
mint = "/usr/bin/mint"
refresh = "/usr/bin/refresh"
revoke = "/usr/bin/revoke"

[commands.env]
API_URL = "https://api.example.com"
API_KEY_FILE = "/etc/secrets/key"
"#;
        let config = parse_provider_toml(toml).unwrap();
        assert_eq!(config.mint_cmd, "/usr/bin/mint");
        assert_eq!(config.refresh_cmd.as_deref(), Some("/usr/bin/refresh"));
        assert_eq!(config.revoke_cmd.as_deref(), Some("/usr/bin/revoke"));
        assert_eq!(
            config.env.get("API_URL").unwrap(),
            "https://api.example.com"
        );
        assert_eq!(config.env.get("API_KEY_FILE").unwrap(), "/etc/secrets/key");
    }

    #[test]
    fn load_provider_file_rejects_insecure_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("insecure.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

        let result = load_provider_file(&file_path);
        assert!(
            result.is_err(),
            "load_provider_file must reject world-readable config"
        );
    }

    #[test]
    fn load_provider_file_reads_secure_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("secure.toml");
        fs::write(&file_path, valid_provider_toml()).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

        let result = load_provider_file(&file_path);
        assert!(result.is_ok(), "load_provider_file should read secure file");
        let config = result.unwrap();
        assert!(config.is_some());
        assert_eq!(config.unwrap().mint_cmd, "/usr/bin/vault-mint");
    }

    #[test]
    fn provider_not_found_display_contains_provider_name() {
        let err = ProviderConfigError::ProviderNotFound {
            provider: "my-cloud".to_string(),
            checked_locations: vec!["test location".to_string()],
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("my-cloud"),
            "Display must contain provider name: {}",
            msg
        );
    }

    // =========================================================================
    // NS-072: Provider contract version — config must include
    // contract_version=1, reject unsupported versions, support current
    // and previous version.
    // =========================================================================

    #[test]
    fn provider_contract_version_must_be_present_in_config() {
        // NS-072: A provider TOML config MUST include contract_version.
        // Omitting it is a hard error.
        let toml_without_version = r#"
[commands]
mint = "/usr/bin/mint"
"#;
        let result = parse_provider_toml(toml_without_version);
        assert!(
            result.is_err(),
            "NS-072: config without contract_version must be rejected"
        );
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.to_lowercase().contains("contract_version"),
            "NS-072: error must mention contract_version, got: {}",
            msg
        );
    }

    #[test]
    fn provider_contract_version_accepts_current_version() {
        // NS-072: contract_version = 1 (the current version) must be accepted.
        let toml = r#"
contract_version = 1

[commands]
mint = "/usr/bin/mint"
"#;
        let config = parse_provider_toml(toml).unwrap();
        assert_eq!(
            config.contract_version, 1,
            "NS-072: current version (1) must be accepted"
        );
    }

    #[test]
    fn provider_contract_version_rejects_unsupported_future_version() {
        // NS-072: A version far beyond current must be rejected.
        let toml = r#"
contract_version = 99

[commands]
mint = "/usr/bin/mint"
"#;
        let result = parse_provider_toml(toml);
        assert!(
            result.is_err(),
            "NS-072: unsupported future version must be rejected"
        );
        let err = result.unwrap_err();
        match err {
            ProviderConfigError::UnsupportedContractVersion { version, .. } => {
                assert_eq!(version, 99);
            }
            other => panic!(
                "NS-072: expected UnsupportedContractVersion, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn provider_contract_version_rejects_version_zero() {
        // NS-072: Version 0 is not a valid contract version.
        let toml = r#"
contract_version = 0

[commands]
mint = "/usr/bin/mint"
"#;
        let result = parse_provider_toml(toml);
        assert!(result.is_err(), "NS-072: version 0 must be rejected");
    }

    #[test]
    fn provider_contract_version_rejects_negative_version() {
        // NS-072: Negative versions are not valid.
        let toml = r#"
contract_version = -1

[commands]
mint = "/usr/bin/mint"
"#;
        let result = parse_provider_toml(toml);
        assert!(result.is_err(), "NS-072: negative version must be rejected");
    }

    #[test]
    fn provider_contract_version_rejects_non_integer_type() {
        // NS-072: contract_version must be an integer, not a string.
        let toml = r#"
contract_version = "1"

[commands]
mint = "/usr/bin/mint"
"#;
        let result = parse_provider_toml(toml);
        assert!(
            result.is_err(),
            "NS-072: non-integer contract_version must be rejected"
        );
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.to_lowercase().contains("integer"),
            "NS-072: error must mention expected type, got: {}",
            msg
        );
    }

    #[test]
    fn provider_contract_version_stored_in_file_provider_config() {
        // NS-072: The parsed FileProviderConfig must expose the contract_version.
        let toml = r#"
contract_version = 1

[commands]
mint = "/usr/bin/mint"
"#;
        let config = parse_provider_toml(toml).unwrap();
        assert_eq!(config.contract_version, 1);
    }

    #[test]
    fn provider_contract_version_propagated_to_resolved_provider() {
        // NS-072: The resolved provider must carry the contract_version
        // from the file config layer.
        let file_config = FileProviderConfig {
            contract_version: 1,
            mint_cmd: "/usr/bin/mint".to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
        };

        let resolved = resolve_provider_config(
            "test",
            &ProviderFlags::empty(),
            &ProviderEnv::empty(),
            Some(file_config),
        )
        .unwrap();

        assert_eq!(
            resolved.contract_version,
            Some(1),
            "NS-072: resolved provider must carry contract_version from file layer"
        );
    }

    #[test]
    fn provider_contract_version_none_for_flags_and_env_layers() {
        // NS-072: Flags and env layers don't specify contract_version
        // (they're overrides, not full configs). contract_version is None.
        let flags = flags_with_mint_cmd("/from/flags/mint");
        let resolved =
            resolve_provider_config("test", &flags, &ProviderEnv::empty(), None).unwrap();
        assert_eq!(
            resolved.contract_version, None,
            "NS-072: flags layer should not have contract_version"
        );
    }

    #[test]
    fn provider_contract_version_unsupported_error_display() {
        // NS-072: Error message for unsupported version must be actionable.
        let err = ProviderConfigError::UnsupportedContractVersion {
            version: 42,
            supported: vec![1],
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("42"),
            "NS-072: error must mention the unsupported version, got: {}",
            msg
        );
        assert!(
            msg.contains("1"),
            "NS-072: error must mention supported versions, got: {}",
            msg
        );
    }

    #[test]
    fn provider_contract_version_current_version_constant_is_one() {
        // NS-072: The current contract version must be 1.
        assert_eq!(
            CURRENT_CONTRACT_VERSION, 1,
            "NS-072: current contract version must be 1"
        );
    }

    #[test]
    fn provider_contract_version_supported_versions_includes_current() {
        // NS-072: The supported versions list must include the current version.
        let supported = supported_contract_versions();
        assert!(
            supported.contains(&CURRENT_CONTRACT_VERSION),
            "NS-072: supported versions must include current version {}",
            CURRENT_CONTRACT_VERSION
        );
    }

    #[test]
    fn provider_contract_version_backward_compat_supports_previous() {
        // NS-072: Must support current and previous version.
        // Since current = 1 and there's no version 0, only version 1 is valid now.
        // But the mechanism must be in place: when version 2 becomes current,
        // version 1 must remain supported.
        let supported = supported_contract_versions();
        // For now, at version 1, only 1 is supported (no version 0 existed).
        assert_eq!(
            supported,
            vec![1],
            "NS-072: at version 1, only version 1 should be supported (no v0 existed)"
        );
    }

    #[test]
    fn provider_contract_version_validate_version_rejects_unsupported() {
        // NS-072: validate_contract_version must reject unsupported versions.
        let result = validate_contract_version(99);
        assert!(
            result.is_err(),
            "NS-072: validate_contract_version must reject unsupported versions"
        );
    }

    #[test]
    fn provider_contract_version_validate_version_accepts_current() {
        // NS-072: validate_contract_version must accept the current version.
        let result = validate_contract_version(CURRENT_CONTRACT_VERSION);
        assert!(
            result.is_ok(),
            "NS-072: validate_contract_version must accept current version"
        );
    }

    #[test]
    fn provider_contract_version_rejects_float_type() {
        // NS-072: contract_version must be an integer; TOML floats are rejected.
        let toml = r#"
contract_version = 1.0

[commands]
mint = "/usr/bin/mint"
"#;
        let result = parse_provider_toml(toml);
        assert!(
            result.is_err(),
            "NS-072: float contract_version must be rejected"
        );
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.to_lowercase().contains("integer"),
            "NS-072: error must mention expected type, got: {}",
            msg
        );
    }

    #[test]
    fn provider_contract_version_validate_rejects_zero_directly() {
        // NS-072: validate_contract_version(0) must reject — version 0 never existed.
        // In practice the parser catches this first, but the public API must be safe.
        let result = validate_contract_version(0);
        assert!(
            result.is_err(),
            "NS-072: validate_contract_version(0) must reject"
        );
    }

    #[test]
    fn config_source_eq_works() {
        assert_eq!(ConfigSource::Flags, ConfigSource::Flags);
        assert_ne!(ConfigSource::Flags, ConfigSource::EnvVars);
        assert_ne!(ConfigSource::EnvVars, ConfigSource::File);
    }

    #[test]
    fn insecure_permissions_display_contains_path_and_mode() {
        let err = ProviderConfigError::InsecurePermissions {
            path: PathBuf::from("/etc/noscope/providers/aws.toml"),
            mode: 0o644,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("644"), "Display must show mode: {}", msg);
        assert!(msg.contains("aws.toml"), "Display must show path: {}", msg);
    }

    #[test]
    fn validation_failed_display_lists_all_problems() {
        let err = ProviderConfigError::ValidationFailed {
            problems: vec![
                "mint command not found: /bad/path".to_string(),
                "revoke command not executable: /other/path".to_string(),
            ],
        };
        let msg = format!("{}", err);
        assert!(msg.contains("mint"), "Must list mint problem: {}", msg);
        assert!(msg.contains("revoke"), "Must list revoke problem: {}", msg);
    }
}
