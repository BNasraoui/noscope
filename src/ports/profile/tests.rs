use provenance_macros::verifies;
use std::path::{Path, PathBuf};

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
    // no inheritance — "extends" field in a credential is
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
        "'extends' field must be rejected as unknown credential field"
    );
}

#[test]
fn profile_flatness_constraint_no_overrides_field() {
    // no overrides — "overrides" is an unknown credential field.
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
        "'overrides' field must be rejected as unknown credential field"
    );
}

#[test]
fn profile_flatness_constraint_no_nested_profiles() {
    // no composition — credentials cannot contain nested credentials.
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
        "nested credential structures must be rejected"
    );
}

#[test]
#[verifies("rule_profile_schema", examples)]
fn profile_schema_requires_provider() {
    let toml = r#"
[[credentials]]
role = "admin"
ttl = 3600
"#;
    let result = super::parse_profile_toml(toml);
    assert!(result.is_err(), "missing 'provider' must be an error");
}

#[test]
fn profile_schema_requires_role() {
    let toml = r#"
[[credentials]]
provider = "aws"
ttl = 3600
"#;
    let result = super::parse_profile_toml(toml);
    assert!(result.is_err(), "missing 'role' must be an error");
}

#[test]
fn profile_schema_requires_ttl() {
    let toml = r#"
[[credentials]]
provider = "aws"
role = "admin"
"#;
    let result = super::parse_profile_toml(toml);
    assert!(result.is_err(), "missing 'ttl' must be an error");
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
        "env_key should be None when not specified"
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
        "env_key should be set when specified"
    );
}

#[test]
fn profile_schema_unknown_top_level_fields_ignored() {
    // unknown top-level fields are ignored (forward-compat).
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
        "unknown top-level fields must be ignored"
    );
}

#[test]
fn profile_schema_unknown_credential_field_is_error() {
    // unknown fields in [[credentials]] entries = error.
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
        "unknown credential field 'region' must be an error"
    );
}

#[test]
fn profile_schema_empty_credentials_array_is_error() {
    // empty credentials array = error.
    let toml = r#"
credentials = []
"#;
    let result = super::parse_profile_toml(toml);
    assert!(result.is_err(), "empty credentials array must be an error");
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
        "profile without credentials must be an error"
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
    assert!(result.is_err(), "ttl=0 must be an error");
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
    assert!(result.is_err(), "negative ttl must be an error");
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
    assert!(!errors.is_empty(), "duplicate env_key must be reported");
    let all_msgs: String = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        all_msgs.contains("TOKEN"),
        "error must mention the duplicated env_key: {}",
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
    assert!(!errors.is_empty(), "nonexistent provider must be reported");
    let all_msgs: String = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        all_msgs.contains("nonexistent-provider"),
        "error must name the missing provider: {}",
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
        "all errors must be reported together, got {} errors: {:?}",
        errors.len(),
        errors
    );
}

#[test]
fn profile_validation_distinct_exit_code() {
    // profile validation errors use a distinct exit code.
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

#[test]
fn profile_cli_mutual_exclusion_profile_forbids_provider() {
    let result = super::check_profile_flag_exclusion(Some("my-profile"), Some("aws"), None, None);
    assert!(
        result.is_err(),
        "--profile with --provider must be rejected"
    );
}

#[test]
fn profile_cli_mutual_exclusion_profile_forbids_role() {
    let result = super::check_profile_flag_exclusion(Some("my-profile"), None, Some("admin"), None);
    assert!(result.is_err(), "--profile with --role must be rejected");
}

#[test]
fn profile_cli_mutual_exclusion_profile_forbids_ttl() {
    let result = super::check_profile_flag_exclusion(Some("my-profile"), None, None, Some(3600));
    assert!(result.is_err(), "--profile with --ttl must be rejected");
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
        "--profile with all credential flags must be rejected"
    );
}

#[test]
fn profile_cli_mutual_exclusion_profile_alone_is_valid() {
    let result = super::check_profile_flag_exclusion(Some("my-profile"), None, None, None);
    assert!(result.is_ok(), "--profile alone must be valid");
}

#[test]
fn profile_cli_mutual_exclusion_no_profile_allows_flags() {
    // When --profile is not set, --provider/--role/--ttl are fine.
    let result = super::check_profile_flag_exclusion(None, Some("aws"), Some("admin"), Some(3600));
    assert!(
        result.is_ok(),
        "without --profile, credential flags are allowed"
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
        "error must name the conflicting flags, got: {}",
        msg
    );
    assert!(
        msg.contains("--profile"),
        "error must mention --profile, got: {}",
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
        "mutual exclusion violation must be usage error (64)"
    );
}

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

#[test]
#[verifies("rule_profile_named_must_exist", examples)]
fn profile_load_missing_file_is_error() {
    // Unlike provider config (Ok(None) for missing), a profile that
    // was explicitly requested must exist.
    let result = super::load_profile(Path::new("/nonexistent/profile.toml"));
    assert!(result.is_err(), "explicitly requested profile must exist");
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
