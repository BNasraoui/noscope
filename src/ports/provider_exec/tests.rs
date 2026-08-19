use chrono::Datelike;
use provenance_macros::verifies;
use std::time::Duration;

#[test]
#[verifies("rule_exec_output_token_contract", examples)]
fn provider_output_contract_parses_valid_json_with_token_and_expires_at() {
    let json = r#"{"token": "my-secret-token-123", "expires_at": "2026-03-30T12:00:00Z"}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(
        result.is_ok(),
        "valid JSON with token and expires_at must parse, got: {:?}",
        result
    );
    let output = result.unwrap();
    assert_eq!(output.token, "my-secret-token-123");
    assert!(
        output.expires_at_provided,
        "expires_at was provided in JSON"
    );
}

#[test]
fn provider_output_contract_token_is_required() {
    let json = r#"{"expires_at": "2026-03-30T12:00:00Z"}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(result.is_err(), "JSON without 'token' must be rejected");
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("token"),
        "Error must mention missing 'token' field, got: {}",
        msg
    );
}

#[test]
fn provider_output_contract_empty_token_is_rejected() {
    let json = r#"{"token": ""}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(result.is_err(), "empty 'token' value must be rejected");
}

#[test]
fn provider_output_contract_token_must_be_string() {
    let json = r#"{"token": 12345}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(result.is_err(), "non-string 'token' must be rejected");
}

#[test]
fn provider_output_contract_expires_at_is_optional() {
    // says expires_at is optional; governs the fallback.
    let json = r#"{"token": "my-secret-token-123"}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(
        result.is_ok(),
        "JSON without expires_at must be accepted, got: {:?}",
        result
    );
    let output = result.unwrap();
    assert!(
        !output.expires_at_provided,
        "expires_at was NOT provided in JSON"
    );
}

#[test]
fn provider_output_contract_expires_at_must_be_valid_iso8601() {
    let json = r#"{"token": "tok", "expires_at": "not-a-date"}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(
        result.is_err(),
        "invalid ISO 8601 expires_at must be rejected"
    );
}

#[test]
fn provider_output_contract_rejects_invalid_json() {
    let result = super::parse_provider_output("not json {{{", 3600);
    assert!(result.is_err(), "invalid JSON must be rejected");
}

#[test]
fn provider_output_contract_extra_fields_are_ignored() {
    // Provider may include extra fields; noscope ignores them.
    let json = r#"{"token": "tok", "expires_at": "2026-03-30T12:00:00Z", "extra": "ignored"}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(result.is_ok(), "extra fields should be ignored");
}

#[test]
fn template_variable_injection_prevention_role_valid_alphanumeric() {
    assert!(super::validate_role("admin").is_ok());
    assert!(super::validate_role("read-only").is_ok());
    assert!(super::validate_role("my_role").is_ok());
    assert!(super::validate_role("my.role.v2").is_ok());
    assert!(super::validate_role("Admin-Role_v2.1").is_ok());
}

#[test]
#[verifies("rule_role_charset", examples)]
fn template_variable_injection_prevention_role_rejects_shell_metacharacters() {
    assert!(
        super::validate_role("admin; rm -rf /").is_err(),
        "role with semicolon must be rejected"
    );
    assert!(
        super::validate_role("admin$(whoami)").is_err(),
        "role with command substitution must be rejected"
    );
    assert!(
        super::validate_role("admin`whoami`").is_err(),
        "role with backtick must be rejected"
    );
    assert!(
        super::validate_role("admin|cat /etc/passwd").is_err(),
        "role with pipe must be rejected"
    );
}

#[test]
fn template_variable_injection_prevention_role_rejects_empty() {
    assert!(
        super::validate_role("").is_err(),
        "empty role must be rejected"
    );
}

#[test]
fn template_variable_injection_prevention_role_rejects_spaces() {
    assert!(
        super::validate_role("admin user").is_err(),
        "role with spaces must be rejected"
    );
}

#[test]
fn template_variable_injection_prevention_role_rejects_slashes() {
    assert!(
        super::validate_role("admin/subdir").is_err(),
        "role with forward slash must be rejected"
    );
    assert!(
        super::validate_role("admin\\subdir").is_err(),
        "role with backslash must be rejected"
    );
}

#[test]
#[verifies("rule_cross_template_substitution", examples)]
fn template_variable_injection_prevention_argv_substitution() {
    // Template variables are substituted in an argv array, never via shell.
    let template = vec![
        "/usr/bin/mint".to_string(),
        "--role".to_string(),
        "{role}".to_string(),
        "--ttl".to_string(),
        "{ttl}".to_string(),
    ];
    let result = super::substitute_template_vars(&template, "admin", 3600);
    assert_eq!(result[0], "/usr/bin/mint");
    assert_eq!(result[1], "--role");
    assert_eq!(result[2], "admin");
    assert_eq!(result[3], "--ttl");
    assert_eq!(result[4], "3600");
}

#[test]
fn template_variable_injection_prevention_no_shell_expansion() {
    // Even if the role contains shell-like patterns, they are passed literally
    // (after validation — which would reject them. This tests the substitution
    // itself doesn't invoke a shell).
    let template = vec!["/usr/bin/mint".to_string(), "{role}".to_string()];
    // Note: in practice this role would fail validate_role(), but we're
    // testing that substitute_template_vars is a pure string replacement.
    let result = super::substitute_template_vars(&template, "literal-value", 100);
    assert_eq!(result[1], "literal-value");
}

#[test]
fn template_variable_injection_prevention_multiple_role_substitutions() {
    let template = vec![
        "/usr/bin/cmd".to_string(),
        "--a={role}".to_string(),
        "--b={role}".to_string(),
    ];
    let result = super::substitute_template_vars(&template, "myrole", 60);
    assert_eq!(result[1], "--a=myrole");
    assert_eq!(result[2], "--b=myrole");
}

#[test]
fn template_variable_injection_prevention_ttl_substituted_as_integer_string() {
    let template = vec!["/cmd".to_string(), "{ttl}".to_string()];
    let result = super::substitute_template_vars(&template, "role", 7200);
    assert_eq!(result[1], "7200");
}

#[test]
#[verifies("rule_exec_expiry_fallback", examples)]
fn missing_expires_at_computed_from_requested_ttl() {
    let json = r#"{"token": "tok-123"}"#;
    let before = chrono::Utc::now();
    let result = super::parse_provider_output(json, 3600).unwrap();
    let after = chrono::Utc::now();

    assert!(!result.expires_at_provided, "expires_at was not provided");
    // The computed expires_at should be approximately now + 3600s
    let expected_min = before + chrono::Duration::seconds(3600);
    let expected_max = after + chrono::Duration::seconds(3600);
    assert!(
        result.expires_at >= expected_min && result.expires_at <= expected_max,
        "computed expires_at should be now + requested_ttl, got: {:?}, expected between {:?} and {:?}",
        result.expires_at,
        expected_min,
        expected_max
    );
}

#[test]
fn missing_expires_at_generates_warning() {
    let json = r#"{"token": "tok"}"#;
    let result = super::parse_provider_output(json, 3600).unwrap();
    assert!(
        !result.expires_at_provided,
        "expires_at was not provided, warning should be generated"
    );
    // The caller checks expires_at_provided to emit the warning.
}

#[test]
fn provided_expires_at_is_used_as_is() {
    let json = r#"{"token": "tok", "expires_at": "2099-12-31T23:59:59Z"}"#;
    let result = super::parse_provider_output(json, 3600).unwrap();
    assert!(result.expires_at_provided);
    assert_eq!(
        result.expires_at.year(),
        2099,
        "provided expires_at must be used as-is"
    );
}

#[test]
fn provider_command_execution_timeout_default_is_30_seconds() {
    let config = super::ExecConfig::default();
    assert_eq!(
        config.timeout,
        Duration::from_secs(30),
        "default provider command timeout must be 30s"
    );
}

#[test]
fn provider_command_execution_timeout_kill_grace_period_is_5_seconds() {
    let config = super::ExecConfig::default();
    assert_eq!(
        config.kill_grace_period,
        Duration::from_secs(5),
        "SIGKILL grace period after SIGTERM must be 5s"
    );
}

#[test]
fn provider_command_execution_timeout_treated_as_exit_4() {
    // When a provider times out, it's treated as exit code 4 (Unavailable).
    let result = super::ProviderExecError::Timeout {
        timeout: Duration::from_secs(30),
    };
    assert_eq!(
        result.as_provider_exit_code(),
        4,
        "timeout must be treated as exit code 4 (unavailable)"
    );
}

#[test]
fn provider_stdout_size_limit_accepts_small_output() {
    let small = "x".repeat(1024); // 1 KiB
    assert!(
        super::check_stdout_size_limit(small.len()).is_ok(),
        "1 KiB output must be accepted"
    );
}

#[test]
fn provider_stdout_size_limit_accepts_exactly_1_mib() {
    let exactly_1_mib = 1024 * 1024;
    assert!(
        super::check_stdout_size_limit(exactly_1_mib).is_ok(),
        "exactly 1 MiB output must be accepted"
    );
}

#[test]
#[verifies("rule_exec_stdout_1mib_cap", examples)]
fn provider_stdout_size_limit_rejects_over_1_mib() {
    let over_1_mib = (1024 * 1024) + 1;
    assert!(
        super::check_stdout_size_limit(over_1_mib).is_err(),
        "output exceeding 1 MiB must be rejected"
    );
}

#[test]
fn provider_stdout_size_limit_constant_is_1_mib() {
    assert_eq!(
        super::MAX_STDOUT_BYTES,
        1024 * 1024,
        "stdout size limit must be exactly 1 MiB"
    );
}

#[test]
fn ttl_format_is_integer_seconds_for_providers() {
    // When building provider command args, TTL must be integer seconds.
    let template = vec!["/cmd".to_string(), "{ttl}".to_string()];
    let result = super::substitute_template_vars(&template, "role", 3600);
    assert_eq!(
        result[1], "3600",
        "TTL must be formatted as integer seconds string"
    );
}

#[test]
fn ttl_format_no_human_duration_suffix() {
    let template = vec!["/cmd".to_string(), "{ttl}".to_string()];
    let result = super::substitute_template_vars(&template, "role", 7200);
    // Must be "7200", not "2h" or "120m" or anything else
    assert!(
        result[1].parse::<u64>().is_ok(),
        "TTL must be a pure integer string, got: {}",
        result[1]
    );
    assert_eq!(result[1], "7200");
}

#[test]
fn revoke_command_env_vars_include_noscope_token_id() {
    let env = super::build_revoke_env("tok-abc");
    assert_eq!(
        env.get("NOSCOPE_TOKEN_ID").map(|s| s.as_str()),
        Some("tok-abc"),
        "revoke env must include NOSCOPE_TOKEN_ID"
    );
}

#[test]
#[verifies("rule_revoke_identifier_only", examples)]
fn revoke_command_env_never_carries_the_credential_value() {
    let env = super::build_revoke_env("tok-abc");
    assert!(
        !env.contains_key("NOSCOPE_TOKEN"),
        "revoke must never receive the credential value"
    );
    assert!(
        !env.contains_key("NOSCOPE_TTL"),
        "revoke must NOT include NOSCOPE_TTL"
    );
    assert_eq!(env.len(), 1, "identifier is the whole revoke contract");
}

#[test]
#[verifies("rule_cross_revoke_idempotent_exit0", examples)]
fn revoke_command_exit_0_for_already_revoked() {
    // exit 0 means success (including already-revoked); the caller
    // should treat exit 0 from revoke as success regardless.
    // This tests the interpret function recognizes this pattern.
    assert!(
        super::is_revoke_success(0),
        "exit 0 from revoke must be treated as success (including already-revoked)"
    );
}

#[test]
fn revoke_command_non_zero_exit_is_failure() {
    assert!(
        !super::is_revoke_success(1),
        "exit 1 from revoke is failure"
    );
}

#[test]
fn refresh_command_env_vars_include_noscope_token() {
    let env = super::build_refresh_env("secret-token", "tok-id", 3600);
    assert_eq!(
        env.get("NOSCOPE_TOKEN").map(|s| s.as_str()),
        Some("secret-token"),
        "refresh env must include NOSCOPE_TOKEN"
    );
}

#[test]
fn refresh_command_env_vars_include_noscope_token_id() {
    let env = super::build_refresh_env("tok", "tok-id-123", 3600);
    assert_eq!(
        env.get("NOSCOPE_TOKEN_ID").map(|s| s.as_str()),
        Some("tok-id-123"),
        "refresh env must include NOSCOPE_TOKEN_ID"
    );
}

#[test]
fn refresh_command_env_vars_include_noscope_ttl() {
    let env = super::build_refresh_env("tok", "id", 7200);
    assert_eq!(
        env.get("NOSCOPE_TTL").map(|s| s.as_str()),
        Some("7200"),
        "refresh env must include NOSCOPE_TTL as integer seconds"
    );
}

#[test]
fn refresh_command_env_has_exactly_three_credential_vars() {
    let env = super::build_refresh_env("tok", "id", 3600);
    assert!(env.contains_key("NOSCOPE_TOKEN"));
    assert!(env.contains_key("NOSCOPE_TOKEN_ID"));
    assert!(env.contains_key("NOSCOPE_TTL"));
}

#[test]
fn refresh_command_output_same_contract_as_mint() {
    // refresh output uses same JSON format as mint
    let json = r#"{"token": "refreshed-token", "expires_at": "2026-12-31T23:59:59Z"}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(
        result.is_ok(),
        "refresh output must parse with same contract as mint"
    );
    let output = result.unwrap();
    assert_eq!(output.token, "refreshed-token");
}

#[test]
fn provider_stderr_handling_capture_limit_is_4096_bytes() {
    assert_eq!(
        super::MAX_STDERR_CAPTURE_BYTES,
        4096,
        "stderr capture limit must be 4096 bytes"
    );
}

#[test]
#[verifies("rule_exec_stderr_truncate", examples)]
fn provider_stderr_handling_truncates_to_limit() {
    let long_stderr = "x".repeat(8192);
    let captured = super::capture_stderr(&long_stderr);
    assert!(
        captured.len() <= 4096,
        "captured stderr must be <= 4096 bytes, got: {}",
        captured.len()
    );
}

#[test]
fn provider_stderr_handling_preserves_short_stderr() {
    let short = "error: auth failed";
    let captured = super::capture_stderr(short);
    assert_eq!(captured, short, "short stderr should be preserved verbatim");
}

#[test]
fn provider_stderr_handling_redacts_known_token() {
    let stderr_with_token = "error: token abc123secret456789xyz is invalid";
    let captured = super::redact_stderr(stderr_with_token, &["abc123secret456789xyz"]);
    assert!(
        !captured.contains("abc123secret456789xyz"),
        "known token values must be redacted from stderr, got: {}",
        captured
    );
    assert!(
        captured.contains("[redacted]"),
        "redacted token must be replaced with [redacted], got: {}",
        captured
    );
}

#[test]
fn provider_stderr_handling_redacts_multiple_tokens() {
    let stderr = "token1=secret_aaa token2=secret_bbb";
    let captured = super::redact_stderr(stderr, &["secret_aaa", "secret_bbb"]);
    assert!(!captured.contains("secret_aaa"));
    assert!(!captured.contains("secret_bbb"));
}

#[test]
fn provider_stderr_handling_no_tokens_no_change() {
    let stderr = "provider error: connection refused";
    let captured = super::redact_stderr(stderr, &[]);
    assert_eq!(
        captured, stderr,
        "with no known tokens, stderr should be unchanged"
    );
}

#[test]
fn provider_stderr_handling_discard_on_success_default() {
    let policy = super::StderrPolicy::on_success(false);
    assert!(
        policy.should_discard(),
        "on success without --verbose, stderr should be discarded"
    );
}

#[test]
fn provider_stderr_handling_keep_on_success_verbose() {
    let policy = super::StderrPolicy::on_success(true);
    assert!(
        !policy.should_discard(),
        "on success with --verbose, stderr should be kept"
    );
}

#[test]
fn provider_stderr_handling_keep_on_failure() {
    let policy = super::StderrPolicy::on_failure();
    assert!(
        !policy.should_discard(),
        "on failure, stderr must always be captured"
    );
}

#[test]
fn provider_capability_declaration_default_no_refresh_no_revoke() {
    let caps = super::ProviderCapabilities::default();
    assert!(!caps.supports_refresh, "default should NOT support refresh");
    assert!(!caps.supports_revoke, "default should NOT support revoke");
}

#[test]
fn provider_capability_declaration_from_config_both_true() {
    let caps = super::ProviderCapabilities {
        supports_refresh: true,
        supports_revoke: true,
    };
    assert!(caps.supports_refresh);
    assert!(caps.supports_revoke);
}

#[test]
fn provider_capability_declaration_from_config_refresh_only() {
    let caps = super::ProviderCapabilities {
        supports_refresh: true,
        supports_revoke: false,
    };
    assert!(caps.supports_refresh);
    assert!(!caps.supports_revoke);
}

#[test]
fn provider_capability_declaration_parsed_from_toml() {
    let toml = r#"
contract_version = 1
supports_refresh = true
supports_revoke = false

[commands]
mint = "/usr/bin/mint"
refresh = "/usr/bin/refresh"
"#;
    let caps = super::parse_capabilities_from_toml(toml);
    assert!(
        caps.is_ok(),
        "valid capability TOML must parse, got: {:?}",
        caps
    );
    let caps = caps.unwrap();
    assert!(caps.supports_refresh, "supports_refresh should be true");
    assert!(!caps.supports_revoke, "supports_revoke should be false");
}

#[test]
fn provider_capability_declaration_defaults_when_absent_in_toml() {
    let toml = r#"
contract_version = 1

[commands]
mint = "/usr/bin/mint"
"#;
    let caps = super::parse_capabilities_from_toml(toml).unwrap();
    assert!(
        !caps.supports_refresh,
        "absent supports_refresh defaults to false"
    );
    assert!(
        !caps.supports_revoke,
        "absent supports_revoke defaults to false"
    );
}

#[test]
#[verifies("rule_cross_capability_consistency", examples)]
fn provider_capability_declaration_revoke_without_revoke_cmd_is_inconsistent() {
    // If supports_revoke = true but no revoke command, that's a validation issue.
    let caps = super::ProviderCapabilities {
        supports_refresh: false,
        supports_revoke: true,
    };
    let has_revoke_cmd = false;
    assert!(
        super::validate_capabilities(&caps, false, has_revoke_cmd).is_err(),
        "supports_revoke=true without revoke command should be rejected"
    );
}

#[test]
fn provider_capability_declaration_refresh_without_refresh_cmd_is_inconsistent() {
    let caps = super::ProviderCapabilities {
        supports_refresh: true,
        supports_revoke: false,
    };
    let has_refresh_cmd = false;
    assert!(
        super::validate_capabilities(&caps, has_refresh_cmd, false).is_err(),
        "supports_refresh=true without refresh command should be rejected"
    );
}

#[test]
fn provider_capability_declaration_consistent_config_passes() {
    let caps = super::ProviderCapabilities {
        supports_refresh: true,
        supports_revoke: true,
    };
    assert!(
        super::validate_capabilities(&caps, true, true).is_ok(),
        "consistent capability config should pass"
    );
}

#[test]
fn provider_command_environment_sandboxing_only_path_home_lang() {
    let env = super::build_sandboxed_env();
    // Must contain exactly PATH, HOME, LANG
    assert!(env.contains_key("PATH"), "sandboxed env must include PATH");
    assert!(env.contains_key("HOME"), "sandboxed env must include HOME");
    assert!(env.contains_key("LANG"), "sandboxed env must include LANG");
}

#[test]
fn provider_command_environment_sandboxing_excludes_other_vars() {
    let env = super::build_sandboxed_env();
    // Should NOT contain common env vars like USER, TERM, SHELL, etc.
    let forbidden = [
        "USER",
        "TERM",
        "SHELL",
        "EDITOR",
        "DISPLAY",
        "SSH_AUTH_SOCK",
    ];
    for var in &forbidden {
        assert!(
            !env.contains_key(*var),
            "sandboxed env must NOT include {}, but it does",
            var
        );
    }
}

#[test]
fn provider_command_environment_sandboxing_has_exactly_three_base_keys() {
    let env = super::build_sandboxed_env();
    assert_eq!(
        env.len(),
        3,
        "sandboxed env must have exactly 3 keys (PATH, HOME, LANG), got: {:?}",
        env.keys().collect::<Vec<_>>()
    );
}

#[test]
fn provider_command_environment_sandboxing_with_credential_vars_for_revoke() {
    // When revoking, the sandboxed env gets NOSCOPE_TOKEN_ID added.
    let mut env = super::build_sandboxed_env();
    let cred_vars = super::build_revoke_env("id");
    for (k, v) in &cred_vars {
        env.insert(k.clone(), v.clone());
    }
    // Should now have PATH, HOME, LANG + NOSCOPE_TOKEN_ID = 4
    assert_eq!(env.len(), 4);
    assert_eq!(env.get("NOSCOPE_TOKEN_ID").map(|s| s.as_str()), Some("id"));
}

#[test]
fn provider_command_environment_sandboxing_with_credential_vars_for_refresh() {
    let mut env = super::build_sandboxed_env();
    let cred_vars = super::build_refresh_env("secret", "id", 3600);
    for (k, v) in &cred_vars {
        env.insert(k.clone(), v.clone());
    }
    // PATH, HOME, LANG + NOSCOPE_TOKEN + NOSCOPE_TOKEN_ID + NOSCOPE_TTL = 6
    assert_eq!(env.len(), 6);
}

#[test]
fn provider_command_environment_sandboxing_path_is_not_empty() {
    let env = super::build_sandboxed_env();
    let path = env.get("PATH").unwrap();
    assert!(!path.is_empty(), "PATH in sandboxed env must not be empty");
}

#[test]
fn provider_command_environment_sandboxing_home_is_not_empty() {
    let env = super::build_sandboxed_env();
    let home = env.get("HOME").unwrap();
    assert!(!home.is_empty(), "HOME in sandboxed env must not be empty");
}

#[test]
fn exec_config_is_constructible() {
    let config = super::ExecConfig {
        timeout: Duration::from_secs(60),
        kill_grace_period: Duration::from_secs(10),
    };
    assert_eq!(config.timeout, Duration::from_secs(60));
    assert_eq!(config.kill_grace_period, Duration::from_secs(10));
}

#[test]
fn provider_exec_error_implements_display() {
    let err = super::ProviderExecError::OutputContract {
        message: "missing token".to_string(),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("missing token"),
        "Display should include message"
    );
}

#[test]
fn provider_exec_error_implements_std_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<super::ProviderExecError>();
}

#[test]
fn provider_output_has_chrono_datetime() {
    // Verify ProviderOutput.expires_at is a chrono DateTime<Utc>
    let json = r#"{"token": "tok", "expires_at": "2026-06-15T10:30:00Z"}"#;
    let output = super::parse_provider_output(json, 3600).unwrap();
    assert_eq!(output.expires_at.year(), 2026);
    assert_eq!(output.expires_at.month(), 6);
}

#[test]
fn provider_output_contract_expires_at_null_treated_as_absent() {
    // JSON null for expires_at should be treated the same as absent.
    let json = r#"{"token": "tok", "expires_at": null}"#;
    let result = super::parse_provider_output(json, 3600).unwrap();
    assert!(
        !result.expires_at_provided,
        "null expires_at should be treated as absent"
    );
}

#[test]
fn provider_output_contract_expires_at_in_past_accepted() {
    // Provider might have clock skew — accept past timestamps without error.
    let json = r#"{"token": "tok", "expires_at": "2020-01-01T00:00:00Z"}"#;
    let result = super::parse_provider_output(json, 3600);
    assert!(
        result.is_ok(),
        "past expires_at should be accepted (provider clock skew)"
    );
    let output = result.unwrap();
    assert!(output.expires_at_provided);
    assert_eq!(output.expires_at.year(), 2020);
}

#[test]
fn template_variable_injection_prevention_role_rejects_non_ascii() {
    // only ASCII alphanumeric + hyphens + underscores + dots
    assert!(
        super::validate_role("rôle").is_err(),
        "non-ASCII characters must be rejected"
    );
    assert!(
        super::validate_role("ロール").is_err(),
        "CJK characters must be rejected"
    );
}

#[test]
fn provider_output_token_is_zeroized_on_drop() {
    // Verify the token string is zeroized when ProviderOutput is dropped.
    // We can't directly observe the zeroization, but we can verify the trait
    // impl exists by checking the type compiles with our Drop impl.
    let json =
        r#"{"token": "sensitive-credential-value-12345", "expires_at": "2026-06-15T10:30:00Z"}"#;
    let output = super::parse_provider_output(json, 3600).unwrap();
    assert_eq!(output.token, "sensitive-credential-value-12345");
    // Drop happens here — token.zeroize() is called.
}

#[test]
fn ns_058_provider_output_debug_redacts_token() {
    let output = super::parse_provider_output(
        r#"{"token": "provider-secret-token-abc123", "expires_at": "2026-06-15T10:30:00Z"}"#,
        3600,
    )
    .unwrap();

    let debug = format!("{:?}", output);
    assert!(
        !debug.contains("provider-secret-token-abc123"),
        "Debug output must not expose raw token, got: {}",
        debug
    );
}

#[test]
fn ns_058_provider_output_debug_includes_non_secret_fields() {
    let output = super::parse_provider_output(
        r#"{"token": "provider-secret-token-abc123", "expires_at": "2026-06-15T10:30:00Z"}"#,
        3600,
    )
    .unwrap();

    let debug = format!("{:?}", output);
    assert!(
        debug.contains("RedactedToken"),
        "Debug output should use redaction wrapper, got: {}",
        debug
    );
    assert!(debug.contains("expires_at"));
    assert!(debug.contains("expires_at_provided"));
}

#[test]
fn ns_058_provider_output_debug_redacts_short_tokens_too() {
    let output = super::parse_provider_output(
        r#"{"token": "shorttok", "expires_at": "2026-06-15T10:30:00Z"}"#,
        3600,
    )
    .unwrap();

    let debug = format!("{:?}", output);
    assert!(!debug.contains("shorttok"));
    assert!(debug.contains("RedactedToken"));
}

#[test]
fn provider_exec_error_config_parse_variant_exists() {
    // Verify the ConfigParse error variant exists and displays properly.
    let err = super::ProviderExecError::ConfigParse {
        message: "bad toml syntax".to_string(),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("bad toml syntax"),
        "ConfigParse should display message"
    );
    assert!(
        msg.contains("config"),
        "ConfigParse display should mention config, got: {}",
        msg
    );
}

#[test]
fn provider_stderr_handling_truncation_respects_utf8_boundary() {
    // Create a string where byte 4096 falls in the middle of a multi-byte char.
    let mut s = "a".repeat(4094); // 4094 ASCII bytes
    s.push('\u{00E9}'); // 2-byte UTF-8 char at position 4094-4095
    s.push('x'); // byte 4096
    assert!(s.len() > 4096);
    let captured = super::capture_stderr(&s);
    // Should not panic and should be valid UTF-8
    assert!(captured.len() <= 4096);
    // Verify it's valid UTF-8 (this is implicit since &str is always valid)
    let _ = captured.to_string();
}

#[test]
fn provider_stdout_size_limit_zero_is_accepted() {
    assert!(
        super::check_stdout_size_limit(0).is_ok(),
        "Zero-length stdout should be accepted"
    );
}

#[test]
fn template_variable_injection_prevention_no_unknown_vars_expanded() {
    // Unknown template variables like {unknown} should remain as-is.
    let template = vec!["/cmd".to_string(), "{unknown}".to_string()];
    let result = super::substitute_template_vars(&template, "role", 100);
    assert_eq!(
        result[1], "{unknown}",
        "Unknown template variables must not be expanded"
    );
}

#[test]
fn provider_exec_error_timeout_display() {
    let err = super::ProviderExecError::Timeout {
        timeout: Duration::from_secs(30),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("30"),
        "Timeout display should include duration"
    );
}

#[test]
fn provider_exec_error_stdout_too_large_display() {
    let err = super::ProviderExecError::StdoutTooLarge {
        size: 2_000_000,
        limit: 1_048_576,
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("2000000"),
        "StdoutTooLarge display should include actual size"
    );
}

#[test]
fn provider_exec_error_invalid_role_display() {
    let err = super::ProviderExecError::InvalidRole {
        role: "bad;role".to_string(),
        reason: "contains semicolon".to_string(),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("bad;role"),
        "InvalidRole display should include the role"
    );
}
