use super::*;
use provenance_macros::verifies;
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
    // "no merging" — env's refresh_cmd must NOT leak through
    assert!(
        resolved.refresh_cmd.is_none(),
        "flags layer wins entirely — env refresh_cmd must not merge in"
    );
}

#[test]
#[verifies("rule_config_env_override_vars", examples)]
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
        capabilities: ProviderCapabilities::default(),
    };

    let resolved = resolve_provider_config("mycloud", &flags, &env, Some(file_config)).unwrap();

    assert_eq!(resolved.mint_cmd, "/from/env/mint");
    // no merging — file's refresh_cmd must not leak through
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
        capabilities: ProviderCapabilities::default(),
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
#[verifies("rule_config_precedence_no_merge", examples)]
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
        capabilities: ProviderCapabilities::default(),
    };

    let resolved = resolve_provider_config("test", &flags, &env, Some(file_config)).unwrap();

    assert_eq!(resolved.mint_cmd, "/from/flags/mint");
    assert!(resolved.refresh_cmd.is_none());
    assert!(resolved.revoke_cmd.is_none());
}

#[test]
fn config_follows_xdg_base_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg_config = tmp.path().to_path_buf();

    let path = provider_config_path("aws", Some(&xdg_config)).unwrap();
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
    let path = provider_config_path_with_home("aws", None, tmp.path()).unwrap();
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
    let path = provider_config_path("gcp", Some(&custom_xdg)).unwrap();
    assert_eq!(
        path,
        PathBuf::from("/custom/xdg/noscope/providers/gcp.toml")
    );
}

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
#[verifies("rule_config_provider_toml_schema", examples)]
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

#[test]
#[verifies("rule_config_not_found_lists_locations", examples)]
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

#[test]
#[verifies("rule_cross_config_file_permissions", examples)]
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

#[test]
fn config_permissions_rejects_group_writable_0660() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o660)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(
        result.is_err(),
        "0660 (group-writable) must be rejected for secret-bearing config"
    );
}

#[test]
fn config_permissions_rejects_group_writable_0620() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o620)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(
        result.is_err(),
        "0620 (group-write-only) must be rejected for secret-bearing config"
    );
}

#[test]
fn config_permissions_rejects_group_writable_0670() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o670)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(
        result.is_err(),
        "0670 (group-rwx) must be rejected for secret-bearing config"
    );
}

#[test]
fn config_permissions_rejects_world_writable_0602() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o602)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(result.is_err(), "0602 (world-writable) must be rejected");
}

#[test]
fn config_permissions_rejects_group_and_world_writable_0662() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o662)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(
        result.is_err(),
        "0662 (group+world writable) must be rejected"
    );
}

#[test]
fn config_permissions_allows_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o700)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(result.is_ok(), "0700 (owner-only rwx) should be allowed");
}

#[test]
fn config_permissions_allows_0500() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o500)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(result.is_ok(), "0500 (owner rx) should be allowed");
}

#[test]
fn config_permissions_allows_0440() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o440)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(
        result.is_ok(),
        "0440 (owner+group read-only) should be allowed"
    );
}

#[test]
fn config_permissions_allows_0750() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o750)).unwrap();

    let result = check_config_permissions(&file_path);
    assert!(
        result.is_ok(),
        "0750 (owner rwx, group rx) should be allowed"
    );
}

#[test]
fn config_permissions_error_message_is_actionable() {
    // The error message must mention the rejected mode, suggest acceptable
    // modes, and reference group-writable rejection (not just world bits).
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o660)).unwrap();

    let result = check_config_permissions(&file_path);
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("0660"),
        "Error must show the actual mode: {}",
        msg
    );
    assert!(
        msg.contains("group") || msg.contains("writable"),
        "Error must mention group-writable rejection, got: {}",
        msg
    );
}

#[test]
fn config_permissions_load_provider_file_rejects_group_writable() {
    // Integration: load_provider_file must reject group-writable files too,
    // not just world-accessible.
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("provider.toml");
    fs::write(&file_path, valid_provider_toml()).unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o660)).unwrap();

    let result = load_provider_file(&file_path);
    assert!(
        result.is_err(),
        "load_provider_file must reject group-writable config"
    );
}

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

#[test]
#[verifies("rule_validate_checks_without_running", examples)]
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

#[test]
fn provider_contract_version_must_be_present_in_config() {
    // A provider TOML config MUST include contract_version.
    // Omitting it is a hard error.
    let toml_without_version = r#"
[commands]
mint = "/usr/bin/mint"
"#;
    let result = parse_provider_toml(toml_without_version);
    assert!(
        result.is_err(),
        "config without contract_version must be rejected"
    );
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("contract_version"),
        "error must mention contract_version, got: {}",
        msg
    );
}

#[test]
fn provider_contract_version_accepts_current_version() {
    // contract_version = 1 (the current version) must be accepted.
    let toml = r#"
contract_version = 1

[commands]
mint = "/usr/bin/mint"
"#;
    let config = parse_provider_toml(toml).unwrap();
    assert_eq!(
        config.contract_version, 1,
        "current version (1) must be accepted"
    );
}

#[test]
#[verifies("rule_config_contract_version_gate", examples)]
fn provider_contract_version_rejects_unsupported_future_version() {
    // A version far beyond current must be rejected.
    let toml = r#"
contract_version = 99

[commands]
mint = "/usr/bin/mint"
"#;
    let result = parse_provider_toml(toml);
    assert!(
        result.is_err(),
        "unsupported future version must be rejected"
    );
    let err = result.unwrap_err();
    match err {
        ProviderConfigError::UnsupportedContractVersion { version, .. } => {
            assert_eq!(version, 99);
        }
        other => panic!("expected UnsupportedContractVersion, got: {:?}", other),
    }
}

#[test]
fn provider_contract_version_rejects_version_zero() {
    // Version 0 is not a valid contract version.
    let toml = r#"
contract_version = 0

[commands]
mint = "/usr/bin/mint"
"#;
    let result = parse_provider_toml(toml);
    assert!(result.is_err(), "version 0 must be rejected");
}

#[test]
fn provider_contract_version_rejects_negative_version() {
    // Negative versions are not valid.
    let toml = r#"
contract_version = -1

[commands]
mint = "/usr/bin/mint"
"#;
    let result = parse_provider_toml(toml);
    assert!(result.is_err(), "negative version must be rejected");
}

#[test]
fn provider_contract_version_rejects_non_integer_type() {
    // contract_version must be an integer, not a string.
    let toml = r#"
contract_version = "1"

[commands]
mint = "/usr/bin/mint"
"#;
    let result = parse_provider_toml(toml);
    assert!(
        result.is_err(),
        "non-integer contract_version must be rejected"
    );
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("integer"),
        "error must mention expected type, got: {}",
        msg
    );
}

#[test]
fn provider_contract_version_stored_in_file_provider_config() {
    // The parsed FileProviderConfig must expose the contract_version.
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
    // The resolved provider must carry the contract_version
    // from the file config layer.
    let file_config = FileProviderConfig {
        contract_version: 1,
        mint_cmd: "/usr/bin/mint".to_string(),
        refresh_cmd: None,
        revoke_cmd: None,
        env: Default::default(),
        capabilities: ProviderCapabilities::default(),
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
        "resolved provider must carry contract_version from file layer"
    );
}

#[test]
fn provider_contract_version_none_for_flags_and_env_layers() {
    // Flags and env layers don't specify contract_version
    // (they're overrides, not full configs). contract_version is None.
    let flags = flags_with_mint_cmd("/from/flags/mint");
    let resolved = resolve_provider_config("test", &flags, &ProviderEnv::empty(), None).unwrap();
    assert_eq!(
        resolved.contract_version, None,
        "flags layer should not have contract_version"
    );
}

#[test]
fn provider_contract_version_unsupported_error_display() {
    // Error message for unsupported version must be actionable.
    let err = ProviderConfigError::UnsupportedContractVersion {
        version: 42,
        supported: vec![1],
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("42"),
        "error must mention the unsupported version, got: {}",
        msg
    );
    assert!(
        msg.contains("1"),
        "error must mention supported versions, got: {}",
        msg
    );
}

#[test]
fn provider_contract_version_current_version_constant_is_one() {
    // The current contract version must be 1.
    assert_eq!(
        CURRENT_CONTRACT_VERSION, 1,
        "current contract version must be 1"
    );
}

#[test]
fn provider_contract_version_supported_versions_includes_current() {
    // The supported versions list must include the current version.
    let supported = supported_contract_versions();
    assert!(
        supported.contains(&CURRENT_CONTRACT_VERSION),
        "supported versions must include current version {}",
        CURRENT_CONTRACT_VERSION
    );
}

#[test]
fn provider_contract_version_backward_compat_supports_previous() {
    // Must support current and previous version.
    // Since current = 1 and there's no version 0, only version 1 is valid now.
    // But the mechanism must be in place: when version 2 becomes current,
    // version 1 must remain supported.
    let supported = supported_contract_versions();
    // For now, at version 1, only 1 is supported (no version 0 existed).
    assert_eq!(
        supported,
        vec![1],
        "at version 1, only version 1 should be supported (no v0 existed)"
    );
}

#[test]
fn provider_contract_version_validate_version_rejects_unsupported() {
    // validate_contract_version must reject unsupported versions.
    let result = validate_contract_version(99);
    assert!(
        result.is_err(),
        "validate_contract_version must reject unsupported versions"
    );
}

#[test]
fn provider_contract_version_validate_version_accepts_current() {
    // validate_contract_version must accept the current version.
    let result = validate_contract_version(CURRENT_CONTRACT_VERSION);
    assert!(
        result.is_ok(),
        "validate_contract_version must accept current version"
    );
}

#[test]
fn provider_contract_version_rejects_float_type() {
    // contract_version must be an integer; TOML floats are rejected.
    let toml = r#"
contract_version = 1.0

[commands]
mint = "/usr/bin/mint"
"#;
    let result = parse_provider_toml(toml);
    assert!(result.is_err(), "float contract_version must be rejected");
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("integer"),
        "error must mention expected type, got: {}",
        msg
    );
}

#[test]
fn provider_contract_version_validate_rejects_zero_directly() {
    // validate_contract_version(0) must reject — version 0 never existed.
    // In practice the parser catches this first, but the public API must be safe.
    let result = validate_contract_version(0);
    assert!(result.is_err(), "validate_contract_version(0) must reject");
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

#[test]
fn consolidate_provider_config_single_authoritative_domain_model() {
    let toml = r#"
contract_version = 1
supports_refresh = true
supports_revoke = false

[commands]
mint = "/usr/bin/mint"
refresh = "/usr/bin/refresh"
"#;

    let parsed = parse_provider_toml(toml).unwrap();
    assert_eq!(parsed.mint_cmd, "/usr/bin/mint");
    assert_eq!(parsed.refresh_cmd.as_deref(), Some("/usr/bin/refresh"));
    assert!(parsed.capabilities.supports_refresh);
    assert!(!parsed.capabilities.supports_revoke);
}

#[test]
fn consolidate_provider_config_capability_validation_owned_by_provider_parser() {
    let toml = r#"
contract_version = 1
supports_refresh = true

[commands]
mint = "/usr/bin/mint"
"#;

    let parsed = parse_provider_toml(toml);
    assert!(
        parsed.is_err(),
        "supports_refresh=true without commands.refresh must be rejected during provider parse"
    );
}

#[test]
fn consolidate_provider_config_capability_validation_revoke_requires_command() {
    let toml = r#"
contract_version = 1
supports_revoke = true

[commands]
mint = "/usr/bin/mint"
"#;

    let parsed = parse_provider_toml(toml);
    assert!(
        parsed.is_err(),
        "supports_revoke=true without commands.revoke must be rejected during provider parse"
    );
}

#[test]
fn consolidate_provider_config_capability_fields_require_bool_values() {
    let toml = r#"
contract_version = 1
supports_refresh = "yes"

[commands]
mint = "/usr/bin/mint"
refresh = "/usr/bin/refresh"
"#;

    let parsed = parse_provider_toml(toml);
    assert!(
        parsed.is_err(),
        "non-boolean supports_refresh must be rejected"
    );
}

#[test]
fn consolidate_provider_config_typed_precedence_pipeline() {
    let selected = select_provider_config_layer(
        &ProviderFlags {
            mint_cmd: Some("/flags/mint".to_string()),
            refresh_cmd: None,
            revoke_cmd: None,
        },
        &ProviderEnv {
            mint_cmd: Some("/env/mint".to_string()),
            refresh_cmd: None,
            revoke_cmd: None,
        },
        Some(FileProviderConfig {
            contract_version: 1,
            mint_cmd: "/file/mint".to_string(),
            refresh_cmd: None,
            revoke_cmd: None,
            env: Default::default(),
            capabilities: ProviderCapabilities::default(),
        }),
    )
    .unwrap();

    assert!(matches!(selected, SelectedProviderConfigLayer::Flags(_)));
}

#[test]
fn provider_env_from_process_returns_valid_struct() {
    // provider_env_from_process must return a valid ProviderEnv.
    // NOTE: we can't guarantee env var state, but we verify the
    // function is callable and returns the right type.
    let env = provider_env_from_process();
    let _ = env.has_any(); // must compile and not panic
}

#[test]
fn provider_env_from_process_empty_env_contract() {
    // Empty env vars should be treated as absent (None), not Some("").
    // We verify the ProviderEnv::empty() contract matches expectations.
    let empty = ProviderEnv::empty();
    assert!(!empty.has_any(), "empty ProviderEnv must have no values");
    assert!(empty.mint_cmd.is_none());
    assert!(empty.refresh_cmd.is_none());
    assert!(empty.revoke_cmd.is_none());
}
