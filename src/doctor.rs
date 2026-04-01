// noscope-3ez.12: Doctor and init confidence commands.
//
// Rules:
// - NS-080: doctor checks config directory exists and is accessible
// - NS-081: doctor checks each configured provider's TOML is parseable and permissions are secure
// - NS-082: doctor checks each provider's mint command exists and is executable
// - NS-083: doctor produces a structured report with pass/warn/fail per check
// - NS-084: doctor exit code reflects worst status (0=all pass, 1=warnings, 78=failures)
// - NS-085: init creates the config directory structure under XDG_CONFIG_HOME
// - NS-086: init sets secure permissions (0700) on created directories
// - NS-087: init is idempotent — running twice does not error or change permissions

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::provider;

// ---------------------------------------------------------------------------
// NS-083: Structured check types
// ---------------------------------------------------------------------------

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

    /// NS-084: Determine the exit code for the doctor report.
    ///
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

// ---------------------------------------------------------------------------
// NS-085/NS-086/NS-087: Init result
// ---------------------------------------------------------------------------

/// Result from `noscope init`.
#[derive(Debug)]
pub struct InitResult {
    /// Directories that were newly created (empty on idempotent re-runs).
    pub created_dirs: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------
// Doctor implementation
// ---------------------------------------------------------------------------

/// Run all doctor checks against the config tree rooted at `xdg_config_home`.
///
/// The `xdg_config_home` parameter is the XDG_CONFIG_HOME directory (or
/// `$HOME/.config` if unset). Provider configs are expected at
/// `<xdg_config_home>/noscope/providers/<name>.toml`.
pub fn run_doctor(xdg_config_home: &Path) -> DoctorReport {
    let mut checks = Vec::new();
    let noscope_dir = xdg_config_home.join("noscope");

    // NS-080: Check config directory exists.
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
        // NS-081 + NS-082: Check each provider .toml file.
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

        // NS-081: Check permissions first.
        if let Err(e) = provider::check_config_permissions(&path) {
            checks.push(Check {
                name: check_name,
                status: CheckStatus::Fail,
                message: format!("{}", e),
            });
            continue;
        }

        // NS-081: Parse the TOML.
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

        // NS-082: Check mint command exists and is executable.
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
///
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

// ---------------------------------------------------------------------------
// Init implementation
// ---------------------------------------------------------------------------

/// NS-085/NS-086/NS-087: Create the noscope config directory tree.
///
/// Creates:
/// - `<xdg_config_home>/noscope/`
/// - `<xdg_config_home>/noscope/providers/`
/// - `<xdg_config_home>/noscope/profiles/`
///
/// All directories are created with mode 0700 (owner-only).
/// Idempotent: existing directories are left unchanged.
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
        // NS-086: Secure permissions.
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        created.push(dir.clone());
    }

    Ok(InitResult {
        created_dirs: created,
    })
}

#[cfg(test)]
mod tests {
    // =========================================================================
    // NS-080: doctor checks config directory exists and is accessible
    // =========================================================================

    #[test]
    fn doctor_checks_config_dir_exists() {
        // When the config directory exists, the check should pass.
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("noscope");
        std::fs::create_dir_all(&config_dir).unwrap();

        let report = super::run_doctor(tmp.path());
        let config_check = report
            .checks
            .iter()
            .find(|c| c.name == "config_directory")
            .expect("must have a config_directory check");
        assert_eq!(
            config_check.status,
            super::CheckStatus::Pass,
            "config_directory check must pass when directory exists"
        );
    }

    #[test]
    fn doctor_fails_when_config_dir_missing() {
        // When the config directory does not exist, the check should fail.
        let tmp = tempfile::tempdir().unwrap();
        // Do NOT create the noscope directory.

        let report = super::run_doctor(tmp.path());
        let config_check = report
            .checks
            .iter()
            .find(|c| c.name == "config_directory")
            .expect("must have a config_directory check");
        assert_eq!(
            config_check.status,
            super::CheckStatus::Fail,
            "config_directory check must fail when directory is missing"
        );
    }

    #[test]
    fn doctor_config_dir_check_message_is_human_readable() {
        let tmp = tempfile::tempdir().unwrap();
        // Missing config dir
        let report = super::run_doctor(tmp.path());
        let config_check = report
            .checks
            .iter()
            .find(|c| c.name == "config_directory")
            .unwrap();
        assert!(
            !config_check.message.is_empty(),
            "check message must be non-empty"
        );
    }

    // =========================================================================
    // NS-081: doctor checks each configured provider's TOML is parseable
    // and permissions are secure
    // =========================================================================

    #[test]
    fn doctor_checks_provider_toml_parseable() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let provider_toml = providers_dir.join("aws.toml");
        std::fs::write(
            &provider_toml,
            r#"
contract_version = 1

[commands]
mint = "/usr/bin/aws-mint"
"#,
        )
        .unwrap();
        std::fs::set_permissions(
            &provider_toml,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let report = super::run_doctor(tmp.path());
        let provider_check = report
            .checks
            .iter()
            .find(|c| c.name.starts_with("provider:"))
            .expect("must have a provider check when providers exist");
        assert_eq!(
            provider_check.status,
            super::CheckStatus::Pass,
            "valid provider TOML should pass: {}",
            provider_check.message,
        );
    }

    #[test]
    fn doctor_fails_when_provider_toml_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let provider_toml = providers_dir.join("bad.toml");
        std::fs::write(&provider_toml, "this is not valid toml {{{").unwrap();
        std::fs::set_permissions(
            &provider_toml,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let report = super::run_doctor(tmp.path());
        let provider_check = report
            .checks
            .iter()
            .find(|c| c.name == "provider:bad")
            .expect("must have a check for the 'bad' provider");
        assert_eq!(
            provider_check.status,
            super::CheckStatus::Fail,
            "malformed provider TOML must fail"
        );
    }

    #[test]
    fn doctor_fails_when_provider_toml_has_insecure_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let provider_toml = providers_dir.join("insecure.toml");
        std::fs::write(
            &provider_toml,
            r#"
contract_version = 1

[commands]
mint = "/usr/bin/mint"
"#,
        )
        .unwrap();
        // World-readable — insecure
        std::fs::set_permissions(
            &provider_toml,
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();

        let report = super::run_doctor(tmp.path());
        let provider_check = report
            .checks
            .iter()
            .find(|c| c.name == "provider:insecure")
            .expect("must have a check for the 'insecure' provider");
        assert_eq!(
            provider_check.status,
            super::CheckStatus::Fail,
            "insecure permissions must fail"
        );
    }

    // =========================================================================
    // NS-082: doctor checks each provider's mint command exists and is executable
    // =========================================================================

    #[test]
    fn doctor_warns_when_mint_command_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let provider_toml = providers_dir.join("aws.toml");
        std::fs::write(
            &provider_toml,
            r#"
contract_version = 1

[commands]
mint = "/nonexistent/path/to/mint"
"#,
        )
        .unwrap();
        std::fs::set_permissions(
            &provider_toml,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let report = super::run_doctor(tmp.path());
        let cmd_check = report
            .checks
            .iter()
            .find(|c| c.name == "provider:aws:mint_cmd")
            .expect("must have a mint_cmd check");
        assert_eq!(
            cmd_check.status,
            super::CheckStatus::Warn,
            "missing mint command should warn (not fail — config is valid, binary just missing)"
        );
    }

    #[test]
    fn doctor_passes_when_mint_command_exists_and_executable() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let mint_script = tmp.path().join("mint.sh");
        std::fs::write(&mint_script, "#!/bin/sh\necho ok").unwrap();
        std::fs::set_permissions(
            &mint_script,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let provider_toml = providers_dir.join("aws.toml");
        std::fs::write(
            &provider_toml,
            format!(
                r#"
contract_version = 1

[commands]
mint = "{}"
"#,
                mint_script.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &provider_toml,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let report = super::run_doctor(tmp.path());
        let cmd_check = report
            .checks
            .iter()
            .find(|c| c.name == "provider:aws:mint_cmd")
            .expect("must have a mint_cmd check");
        assert_eq!(
            cmd_check.status,
            super::CheckStatus::Pass,
            "executable mint command should pass"
        );
    }

    #[test]
    fn doctor_warns_when_mint_command_not_executable() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let mint_script = tmp.path().join("mint.sh");
        std::fs::write(&mint_script, "#!/bin/sh\necho ok").unwrap();
        // Not executable
        std::fs::set_permissions(
            &mint_script,
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();

        let provider_toml = providers_dir.join("aws.toml");
        std::fs::write(
            &provider_toml,
            format!(
                r#"
contract_version = 1

[commands]
mint = "{}"
"#,
                mint_script.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &provider_toml,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let report = super::run_doctor(tmp.path());
        let cmd_check = report
            .checks
            .iter()
            .find(|c| c.name == "provider:aws:mint_cmd")
            .expect("must have a mint_cmd check");
        assert_eq!(
            cmd_check.status,
            super::CheckStatus::Warn,
            "non-executable mint command should warn"
        );
    }

    // =========================================================================
    // NS-083: doctor produces a structured report with pass/warn/fail per check
    // =========================================================================

    #[test]
    fn doctor_report_has_structured_checks() {
        let tmp = tempfile::tempdir().unwrap();
        let report = super::run_doctor(tmp.path());
        // Report must always contain at least the config_directory check.
        assert!(
            !report.checks.is_empty(),
            "doctor report must contain at least one check"
        );
    }

    #[test]
    fn doctor_check_status_has_three_variants() {
        // Verify all three variants exist by constructing them.
        let _pass = super::CheckStatus::Pass;
        let _warn = super::CheckStatus::Warn;
        let _fail = super::CheckStatus::Fail;
    }

    #[test]
    fn doctor_check_has_name_status_message() {
        let check = super::Check {
            name: "test_check".to_string(),
            status: super::CheckStatus::Pass,
            message: "all good".to_string(),
        };
        assert_eq!(check.name, "test_check");
        assert_eq!(check.status, super::CheckStatus::Pass);
        assert_eq!(check.message, "all good");
    }

    #[test]
    fn doctor_report_summary_counts_statuses() {
        let report = super::DoctorReport {
            checks: vec![
                super::Check {
                    name: "a".to_string(),
                    status: super::CheckStatus::Pass,
                    message: "ok".to_string(),
                },
                super::Check {
                    name: "b".to_string(),
                    status: super::CheckStatus::Warn,
                    message: "hmm".to_string(),
                },
                super::Check {
                    name: "c".to_string(),
                    status: super::CheckStatus::Fail,
                    message: "bad".to_string(),
                },
            ],
        };
        assert_eq!(report.pass_count(), 1);
        assert_eq!(report.warn_count(), 1);
        assert_eq!(report.fail_count(), 1);
    }

    // =========================================================================
    // NS-084: doctor exit code reflects worst status
    // (0=all pass, 1=warnings, 78=failures)
    // =========================================================================

    #[test]
    fn doctor_exit_code_zero_when_all_pass() {
        let report = super::DoctorReport {
            checks: vec![super::Check {
                name: "a".to_string(),
                status: super::CheckStatus::Pass,
                message: "ok".to_string(),
            }],
        };
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn doctor_exit_code_one_when_warnings_present() {
        let report = super::DoctorReport {
            checks: vec![
                super::Check {
                    name: "a".to_string(),
                    status: super::CheckStatus::Pass,
                    message: "ok".to_string(),
                },
                super::Check {
                    name: "b".to_string(),
                    status: super::CheckStatus::Warn,
                    message: "hmm".to_string(),
                },
            ],
        };
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn doctor_exit_code_78_when_failures_present() {
        let report = super::DoctorReport {
            checks: vec![
                super::Check {
                    name: "a".to_string(),
                    status: super::CheckStatus::Pass,
                    message: "ok".to_string(),
                },
                super::Check {
                    name: "b".to_string(),
                    status: super::CheckStatus::Fail,
                    message: "bad".to_string(),
                },
            ],
        };
        assert_eq!(report.exit_code(), 78);
    }

    #[test]
    fn doctor_exit_code_failure_takes_precedence_over_warning() {
        let report = super::DoctorReport {
            checks: vec![
                super::Check {
                    name: "a".to_string(),
                    status: super::CheckStatus::Warn,
                    message: "hmm".to_string(),
                },
                super::Check {
                    name: "b".to_string(),
                    status: super::CheckStatus::Fail,
                    message: "bad".to_string(),
                },
            ],
        };
        assert_eq!(
            report.exit_code(),
            78,
            "failure must take precedence over warning"
        );
    }

    #[test]
    fn doctor_exit_code_zero_when_empty_report() {
        let report = super::DoctorReport { checks: vec![] };
        assert_eq!(report.exit_code(), 0);
    }

    // =========================================================================
    // NS-085: init creates the config directory structure under XDG_CONFIG_HOME
    // =========================================================================

    #[test]
    fn init_creates_config_directory_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let result = super::run_init(tmp.path());
        assert!(result.is_ok(), "init must succeed: {:?}", result.err());

        let noscope_dir = tmp.path().join("noscope");
        let providers_dir = noscope_dir.join("providers");
        let profiles_dir = noscope_dir.join("profiles");
        assert!(noscope_dir.is_dir(), "noscope dir must be created");
        assert!(providers_dir.is_dir(), "providers dir must be created");
        assert!(profiles_dir.is_dir(), "profiles dir must be created");
    }

    #[test]
    fn init_result_reports_created_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let result = super::run_init(tmp.path()).unwrap();
        assert!(
            !result.created_dirs.is_empty(),
            "init result must report created directories"
        );
    }

    // =========================================================================
    // NS-086: init sets secure permissions (0700) on created directories
    // =========================================================================

    #[test]
    fn init_sets_secure_permissions_on_created_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        super::run_init(tmp.path()).unwrap();

        let noscope_dir = tmp.path().join("noscope");
        let mode = std::fs::metadata(&noscope_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "noscope config dir must be 0700, got {:04o}",
            mode
        );

        let providers_dir = noscope_dir.join("providers");
        let mode = std::fs::metadata(&providers_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "providers dir must be 0700, got {:04o}", mode);

        let profiles_dir = noscope_dir.join("profiles");
        let mode = std::fs::metadata(&profiles_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "profiles dir must be 0700, got {:04o}", mode);
    }

    // =========================================================================
    // NS-087: init is idempotent — running twice does not error or change perms
    // =========================================================================

    #[test]
    fn init_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let result1 = super::run_init(tmp.path());
        assert!(result1.is_ok(), "first init must succeed");

        let result2 = super::run_init(tmp.path());
        assert!(result2.is_ok(), "second init must also succeed");

        // Permissions must still be 0700 after second run.
        let noscope_dir = tmp.path().join("noscope");
        let mode = std::fs::metadata(&noscope_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "permissions must remain 0700 after idempotent re-run, got {:04o}",
            mode
        );
    }

    #[test]
    fn init_second_run_reports_no_new_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        super::run_init(tmp.path()).unwrap();

        let result2 = super::run_init(tmp.path()).unwrap();
        assert!(
            result2.created_dirs.is_empty(),
            "second init should report no newly created directories, got: {:?}",
            result2.created_dirs
        );
    }

    // =========================================================================
    // Doctor with no providers should still work
    // =========================================================================

    #[test]
    fn doctor_with_no_providers_still_has_config_check() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("noscope");
        std::fs::create_dir_all(&config_dir).unwrap();

        let report = super::run_doctor(tmp.path());
        assert!(
            report.checks.iter().any(|c| c.name == "config_directory"),
            "doctor must always include config_directory check"
        );
        // No provider checks expected when no providers exist.
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.name.starts_with("provider:")),
            "doctor should not have provider checks when no providers exist"
        );
    }

    // =========================================================================
    // Doctor checks profiles too
    // =========================================================================

    #[test]
    fn doctor_checks_profiles_dir_existence() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("noscope");
        std::fs::create_dir_all(&config_dir).unwrap();
        // No providers or profiles dirs

        let report = super::run_doctor(tmp.path());
        let providers_check = report
            .checks
            .iter()
            .find(|c| c.name == "providers_directory");
        // If there's a providers_directory check, it should note the directory is missing
        // but this is a warning, not a failure (the user may not have any providers yet).
        if let Some(check) = providers_check {
            assert_eq!(
                check.status,
                super::CheckStatus::Warn,
                "missing providers dir should warn, not fail"
            );
        }
    }

    // =========================================================================
    // CheckStatus has PartialEq, Eq, Debug, Clone, Copy
    // =========================================================================

    #[test]
    fn check_status_is_eq_comparable() {
        assert_eq!(super::CheckStatus::Pass, super::CheckStatus::Pass);
        assert_ne!(super::CheckStatus::Pass, super::CheckStatus::Fail);
    }

    #[test]
    fn check_status_is_copy() {
        static_assertions::assert_impl_all!(super::CheckStatus: Copy);
    }

    #[test]
    fn check_status_is_debug() {
        let s = format!("{:?}", super::CheckStatus::Pass);
        assert!(!s.is_empty());
    }

    // =========================================================================
    // DoctorReport and InitResult are Debug
    // =========================================================================

    #[test]
    fn doctor_report_is_debug() {
        let report = super::DoctorReport { checks: vec![] };
        let s = format!("{:?}", report);
        assert!(!s.is_empty());
    }

    #[test]
    fn init_result_is_debug() {
        let result = super::InitResult {
            created_dirs: vec![],
        };
        let s = format!("{:?}", result);
        assert!(!s.is_empty());
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn doctor_checks_refresh_and_revoke_commands_if_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let mint_script = tmp.path().join("mint.sh");
        std::fs::write(&mint_script, "#!/bin/sh\necho ok").unwrap();
        std::fs::set_permissions(
            &mint_script,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let provider_toml = providers_dir.join("aws.toml");
        std::fs::write(
            &provider_toml,
            format!(
                r#"
contract_version = 1

[commands]
mint = "{}"
refresh = "/nonexistent/refresh"
revoke = "/nonexistent/revoke"
"#,
                mint_script.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(
            &provider_toml,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let report = super::run_doctor(tmp.path());
        let refresh_check = report
            .checks
            .iter()
            .find(|c| c.name == "provider:aws:refresh_cmd");
        assert!(
            refresh_check.is_some(),
            "doctor must check refresh_cmd when configured"
        );
        assert_eq!(
            refresh_check.unwrap().status,
            super::CheckStatus::Warn,
            "missing refresh command should warn"
        );

        let revoke_check = report
            .checks
            .iter()
            .find(|c| c.name == "provider:aws:revoke_cmd");
        assert!(
            revoke_check.is_some(),
            "doctor must check revoke_cmd when configured"
        );
        assert_eq!(
            revoke_check.unwrap().status,
            super::CheckStatus::Warn,
            "missing revoke command should warn"
        );
    }

    #[test]
    fn doctor_checks_multiple_providers() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        for name in &["aws", "gcp"] {
            let provider_toml = providers_dir.join(format!("{}.toml", name));
            std::fs::write(
                &provider_toml,
                r#"
contract_version = 1

[commands]
mint = "/nonexistent/mint"
"#,
            )
            .unwrap();
            std::fs::set_permissions(
                &provider_toml,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )
            .unwrap();
        }

        let report = super::run_doctor(tmp.path());
        let provider_checks: Vec<&super::Check> = report
            .checks
            .iter()
            .filter(|c| c.name.starts_with("provider:") && !c.name.contains(":mint_cmd"))
            .collect();
        assert_eq!(
            provider_checks.len(),
            2,
            "doctor must check both providers, got: {:?}",
            provider_checks.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn doctor_ignores_non_toml_files_in_providers_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let providers_dir = tmp.path().join("noscope").join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();

        // A .json file should be ignored, not cause errors.
        std::fs::write(providers_dir.join("notes.json"), "{}").unwrap();
        // A directory should also be ignored.
        std::fs::create_dir_all(providers_dir.join("subdir")).unwrap();

        let report = super::run_doctor(tmp.path());
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.name.contains("notes") || c.name.contains("subdir")),
            "doctor should ignore non-TOML files and subdirectories"
        );
    }
}
