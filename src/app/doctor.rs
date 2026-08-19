// Doctor and init confidence commands.
// Rules:

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::ports::provider;
use provenance_macros::rule;

/// Status of a single doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// Check passed — no issues found.
    Pass,
    /// Check found a non-critical issue (e.g. missing binary that might
    /// be installed later).
    Warn,
    /// Check found a critical issue (e.g. malformed config, insecure
    /// permissions).
    Fail,
}

/// A single check result from `noscope doctor`.
#[derive(Debug, Clone)]
pub struct Check {
    /// Machine-readable check name (e.g. "config_directory", "provider:aws").
    pub name: String,
    /// Pass, Warn, or Fail.
    pub status: CheckStatus,
    /// Human-readable explanation.
    pub message: String,
}

/// Full report from `noscope doctor`.
#[derive(Debug)]
#[rule("rule_doctor_exit_codes")]
pub struct DoctorReport {
    /// All check results, in the order they were performed.
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// Count checks that passed.
    pub fn pass_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == CheckStatus::Pass)
            .count()
    }

    /// Count checks that warned.
    pub fn warn_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == CheckStatus::Warn)
            .count()
    }

    /// Count checks that failed.
    pub fn fail_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .count()
    }

    /// Determine the exit code for the doctor report.
    /// - 0: all checks passed
    /// - 1: at least one warning (no failures)
    /// - 78: at least one failure (config error, sysexits.h)
    pub fn exit_code(&self) -> i32 {
        if self.checks.iter().any(|c| c.status == CheckStatus::Fail) {
            78
        } else if self.checks.iter().any(|c| c.status == CheckStatus::Warn) {
            1
        } else {
            0
        }
    }
}

/// Result from `noscope init`.
#[derive(Debug)]
pub struct InitResult {
    /// Directories that were newly created (empty on idempotent re-runs).
    pub created_dirs: Vec<PathBuf>,
}

/// Run all doctor checks against the config tree rooted at `xdg_config_home`.
/// The `xdg_config_home` parameter is the XDG_CONFIG_HOME directory (or
/// `$HOME/.config` if unset). Provider configs are expected at
/// `<xdg_config_home>/noscope/providers/<name>.toml`.
#[rule("rule_doctor_checks")]
pub fn run_doctor(xdg_config_home: &Path) -> DoctorReport {
    let mut checks = Vec::new();
    let noscope_dir = xdg_config_home.join("noscope");

    // Check config directory exists.
    if noscope_dir.is_dir() {
        checks.push(Check {
            name: "config_directory".to_string(),
            status: CheckStatus::Pass,
            message: format!("{} exists", noscope_dir.display()),
        });
    } else {
        checks.push(Check {
            name: "config_directory".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "{} not found; run 'noscope init' to create it",
                noscope_dir.display()
            ),
        });
        // If the root config dir is missing, no further checks are useful.
        return DoctorReport { checks };
    }

    // Check providers directory.
    let providers_dir = noscope_dir.join("providers");
    if !providers_dir.is_dir() {
        checks.push(Check {
            name: "providers_directory".to_string(),
            status: CheckStatus::Warn,
            message: format!(
                "{} not found; no providers configured yet",
                providers_dir.display()
            ),
        });
    } else {
        // Check each provider .toml file.
        check_providers(&providers_dir, &mut checks);
    }

    DoctorReport { checks }
}

/// Scan the providers directory and check each `.toml` file.
fn check_providers(providers_dir: &Path, checks: &mut Vec<Check>) {
    let entries = match fs::read_dir(providers_dir) {
        Ok(entries) => entries,
        Err(e) => {
            checks.push(Check {
                name: "providers_directory".to_string(),
                status: CheckStatus::Fail,
                message: format!("cannot read {}: {}", providers_dir.display(), e),
            });
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if ext != Some("toml") {
            continue;
        }

        let provider_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let check_name = format!("provider:{}", provider_name);

        // Check permissions first.
        if let Err(e) = provider::check_config_permissions(&path) {
            checks.push(Check {
                name: check_name,
                status: CheckStatus::Fail,
                message: format!("{}", e),
            });
            continue;
        }

        // Parse the TOML.
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                checks.push(Check {
                    name: check_name,
                    status: CheckStatus::Fail,
                    message: format!("cannot read {}: {}", path.display(), e),
                });
                continue;
            }
        };

        let config = match provider::parse_provider_toml(&content) {
            Ok(config) => config,
            Err(e) => {
                checks.push(Check {
                    name: check_name,
                    status: CheckStatus::Fail,
                    message: format!("{}", e),
                });
                continue;
            }
        };

        checks.push(Check {
            name: check_name,
            status: CheckStatus::Pass,
            message: format!("{} is valid", path.display()),
        });

        // Check mint command exists and is executable.
        check_command_health(
            &config.mint_cmd,
            &format!("provider:{}:mint_cmd", provider_name),
            checks,
        );

        // Also check optional commands if configured.
        if let Some(ref refresh_cmd) = config.refresh_cmd {
            check_command_health(
                refresh_cmd,
                &format!("provider:{}:refresh_cmd", provider_name),
                checks,
            );
        }
        if let Some(ref revoke_cmd) = config.revoke_cmd {
            check_command_health(
                revoke_cmd,
                &format!("provider:{}:revoke_cmd", provider_name),
                checks,
            );
        }
    }
}

/// Check whether a command path exists and is executable.
/// - Pass: exists and has execute bits
/// - Warn: missing or not executable (config is valid but command can't run)
fn check_command_health(cmd: &str, check_name: &str, checks: &mut Vec<Check>) {
    let path = Path::new(cmd);

    if !path.exists() {
        checks.push(Check {
            name: check_name.to_string(),
            status: CheckStatus::Warn,
            message: format!("command not found: {}", cmd),
        });
        return;
    }

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            checks.push(Check {
                name: check_name.to_string(),
                status: CheckStatus::Warn,
                message: format!("cannot stat {}: {}", cmd, e),
            });
            return;
        }
    };

    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        checks.push(Check {
            name: check_name.to_string(),
            status: CheckStatus::Warn,
            message: format!("{} is not executable (mode {:04o})", cmd, mode & 0o777),
        });
        return;
    }

    checks.push(Check {
        name: check_name.to_string(),
        status: CheckStatus::Pass,
        message: format!("{} exists and is executable", cmd),
    });
}

/// Create the noscope config directory tree.
/// Creates:
/// - `<xdg_config_home>/noscope/`
/// - `<xdg_config_home>/noscope/providers/`
/// - `<xdg_config_home>/noscope/profiles/`
///
/// All directories are created with mode 0700 (owner-only).
/// Idempotent: existing directories are left unchanged.
#[rule("rule_init_creates_0700")]
#[rule("rule_init_idempotent")]
pub fn run_init(xdg_config_home: &Path) -> Result<InitResult, std::io::Error> {
    let dirs = [
        xdg_config_home.join("noscope"),
        xdg_config_home.join("noscope").join("providers"),
        xdg_config_home.join("noscope").join("profiles"),
    ];

    let mut created = Vec::new();

    for dir in &dirs {
        if dir.is_dir() {
            continue;
        }
        fs::create_dir_all(dir)?;
        // Secure permissions.
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        created.push(dir.clone());
    }

    Ok(InitResult {
        created_dirs: created,
    })
}

#[cfg(test)]
mod tests;
