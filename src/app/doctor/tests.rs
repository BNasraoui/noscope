use provenance_macros::verifies;

#[test]
#[verifies("rule_doctor_checks", examples)]
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
#[verifies("rule_doctor_exit_codes", examples)]
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

#[test]
#[verifies("rule_init_creates_0700", examples)]
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

#[test]
#[verifies("rule_init_idempotent", examples)]
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
