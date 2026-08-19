use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

#[test]
fn facade_client_type_exists() {
    // The facade type `Client` must exist and be constructible.
    let _client: super::Client = super::Client::new(super::ClientOptions::default()).unwrap();
}

#[test]
fn facade_client_options_has_default() {
    // ClientOptions must have sensible defaults.
    let opts = super::ClientOptions::default();
    // Default timeout should be 30s (matching ExecConfig default)
    assert_eq!(opts.provider_timeout, Duration::from_secs(30));
    // Default max concurrent should be 8 (matching MintConfig default)
    assert_eq!(opts.max_concurrent, 8);
}

#[test]
fn facade_client_options_customizable() {
    // All options must be settable.
    let opts = super::ClientOptions {
        provider_timeout: Duration::from_secs(60),
        max_concurrent: 4,
        xdg_config_home: Some(std::path::PathBuf::from("/custom/config")),
        home: Some(std::path::PathBuf::from("/custom/home")),
        force_terminal: false,
        verbose: false,
        provider_env: None,
    };
    assert_eq!(opts.provider_timeout, Duration::from_secs(60));
    assert_eq!(opts.max_concurrent, 4);
}

#[test]
fn facade_error_type_exists_and_is_std_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<crate::Error>();
}

#[test]
fn facade_error_has_exit_code() {
    // Every error kind must map to an exit code for automation.
    let err = crate::Error::usage("bad flag");
    let code = err.exit_code();
    assert_eq!(code, 64);
}

#[test]
fn facade_error_variants_cover_core_failure_modes() {
    // Usage errors
    let usage = crate::Error::usage("missing --ttl");
    assert_eq!(usage.exit_code(), 64);

    // Provider config errors
    let config = crate::Error::config("malformed TOML");
    assert_eq!(config.exit_code(), 78);

    // Provider failure (replaces MintFailed)
    let provider = crate::Error::provider("aws", "auth expired");
    assert_eq!(provider.exit_code(), 65);

    // Security violation
    let sec = crate::Error::security("token in args");
    // Security violations are usage errors — must not be 0
    assert_ne!(sec.exit_code(), 0);
}

#[test]
fn facade_error_display_is_informative() {
    let err = crate::Error::usage("missing --ttl flag");
    let msg = format!("{}", err);
    assert!(
        msg.contains("missing --ttl flag"),
        "Display must include the message: {}",
        msg
    );
}

#[test]
fn facade_error_debug_does_not_contain_secrets() {
    // Error type must not carry or leak secret values in Debug.
    let err = crate::Error::provider("aws", "provider failed");
    let debug = format!("{:?}", err);
    assert!(
        !debug.contains("secret"),
        "Debug must not contain secrets: {}",
        debug
    );
}

#[test]
fn facade_mint_request_validates_providers_required() {
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let req = super::MintRequest {
        providers: vec![],
        role: "admin".to_string(),
        ttl_secs: 3600,
    };
    let result = client.validate_mint(&req);
    assert!(result.is_err(), "Empty providers must be rejected");
}

#[test]
fn facade_mint_request_validates_role_required() {
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let req = super::MintRequest {
        providers: vec!["aws".to_string()],
        role: "".to_string(),
        ttl_secs: 3600,
    };
    let result = client.validate_mint(&req);
    assert!(result.is_err(), "Empty role must be rejected");
}

#[test]
fn facade_mint_request_validates_ttl_required() {
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let req = super::MintRequest {
        providers: vec!["aws".to_string()],
        role: "admin".to_string(),
        ttl_secs: 0,
    };
    let result = client.validate_mint(&req);
    assert!(result.is_err(), "Zero TTL must be rejected");
}

#[test]
fn facade_mint_request_validates_role_safe_characters() {
    // Role must be validated for safe characters.
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let req = super::MintRequest {
        providers: vec!["aws".to_string()],
        role: "admin; rm -rf /".to_string(),
        ttl_secs: 3600,
    };
    let result = client.validate_mint(&req);
    assert!(
        result.is_err(),
        "Role with shell metacharacters must be rejected"
    );
}

#[test]
fn facade_mint_request_valid_passes() {
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let req = super::MintRequest {
        providers: vec!["aws".to_string()],
        role: "admin".to_string(),
        ttl_secs: 3600,
    };
    let result = client.validate_mint(&req);
    assert!(result.is_ok(), "Valid request must pass validation");
}

// Core dump prevention at client construction.
#[test]
fn facade_client_disables_core_dumps() {
    // After Client construction, core dumps must be disabled.
    let _client = super::Client::new(super::ClientOptions::default()).unwrap();
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let ret = libc::getrlimit(libc::RLIMIT_CORE, &mut rlim);
        assert_eq!(ret, 0);
        assert_eq!(
            rlim.rlim_cur, 0,
            "core dumps must be disabled after Client construction"
        );
        assert_eq!(rlim.rlim_max, 0);
    }
}

// Terminal detection for mint stdout.
#[test]
fn facade_check_stdout_terminal_rejects_tty() {
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let result = client.check_stdout_not_terminal(true);
    assert!(result.is_err(), "Mint to terminal stdout must be rejected");
}

#[test]
fn facade_check_stdout_terminal_allows_pipe() {
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let result = client.check_stdout_not_terminal(false);
    assert!(result.is_ok(), "Pipe stdout must be allowed");
}

#[test]
fn facade_check_stdout_terminal_force_overrides() {
    let client = super::Client::new(super::ClientOptions {
        force_terminal: true,
        ..super::ClientOptions::default()
    })
    .unwrap();
    let result = client.check_stdout_not_terminal(true);
    assert!(result.is_ok(), "force_terminal must override TTY check");
}

#[test]
fn facade_client_is_not_clone() {
    // Client may hold state that should not be cloned carelessly.
    static_assertions::assert_not_impl_any!(super::Client: Clone);
}

#[test]
fn facade_client_is_send() {
    static_assertions::assert_impl_all!(super::Client: Send);
}

#[test]
fn facade_client_is_sync() {
    static_assertions::assert_impl_all!(super::Client: Sync);
}

#[test]
fn facade_error_is_send() {
    static_assertions::assert_impl_all!(crate::Error: Send);
}

#[test]
fn facade_error_is_sync() {
    static_assertions::assert_impl_all!(crate::Error: Sync);
}

#[test]
fn facade_error_is_not_clone() {
    // Error types should not be Clone — they may carry heap-allocated
    // context and cloning errors is rarely the right pattern.
    static_assertions::assert_not_impl_any!(crate::Error: Clone);
}

#[test]
fn facade_mint_request_is_not_clone() {
    static_assertions::assert_not_impl_any!(super::MintRequest: Clone);
}

#[test]
fn facade_resolve_provider_delegates_to_provider_module() {
    // Client exposes provider resolution without requiring the consumer
    // to manually import provider module types.
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let result = client.resolve_provider("nonexistent", &super::ProviderOverrides::default());
    assert!(result.is_err(), "Nonexistent provider must return an error");
    // Error message must enumerate checked locations
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("nonexistent"),
        "Error must name the provider: {}",
        msg
    );
}

#[test]
fn facade_provider_overrides_default_is_empty() {
    let overrides = super::ProviderOverrides::default();
    assert!(overrides.mint_cmd.is_none());
    assert!(overrides.refresh_cmd.is_none());
    assert!(overrides.revoke_cmd.is_none());
    assert!(!overrides.has_any());
}

#[test]
fn facade_provider_overrides_has_any_detects_set_fields() {
    let overrides = super::ProviderOverrides {
        mint_cmd: Some("/usr/bin/mint".to_string()),
        ..super::ProviderOverrides::default()
    };
    assert!(overrides.has_any());
}

#[test]
fn facade_dry_run_produces_output() {
    // Dry-run mode must work through the facade without requiring
    // the consumer to construct ResolvedProvider manually.
    let client = super::Client::new(super::ClientOptions::default()).unwrap();
    let overrides = super::ProviderOverrides {
        mint_cmd: Some("/usr/bin/mint".to_string()),
        ..super::ProviderOverrides::default()
    };
    let resolved = client
        .resolve_provider("test-provider", &overrides)
        .unwrap();
    let output = client.dry_run(&resolved, "admin", 3600);
    assert!(!output.is_empty(), "Dry-run must produce output");
    assert!(
        output.contains("/usr/bin/mint"),
        "Dry-run must show mint command: {}",
        output
    );
}

#[test]
fn facade_reexports_scoped_token_type() {
    // ScopedToken should be re-exported so consumers don't need
    // `use noscope::core::token::ScopedToken`.
    fn _accepts_scoped_token(_t: &crate::core::token::ScopedToken) {}
    // This test existing verifies the type is accessible.
}

#[test]
fn facade_reexports_mint_envelope() {
    fn _accepts_envelope(_e: &crate::core::mint::MintEnvelope) {}
}

#[test]
fn facade_reexports_event_types() {
    fn _accepts_event(_e: &crate::ports::event::Event) {}
    fn _accepts_event_type(_t: &crate::ports::event::EventType) {}
}

#[test]
fn facade_error_from_mint_error() {
    let mint_err = crate::core::mint::MintError::InvalidInput {
        message: "bad input".to_string(),
    };
    let err: crate::Error = mint_err.into();
    let msg = format!("{}", err);
    assert!(msg.contains("bad input"), "Must carry the message: {}", msg);
}

#[test]
fn facade_error_from_provider_config_error() {
    let prov_err = crate::ports::provider::ProviderConfigError::MalformedConfig {
        message: "syntax error".to_string(),
    };
    let err: crate::Error = prov_err.into();
    let msg = format!("{}", err);
    assert!(
        msg.contains("syntax error"),
        "Must carry the message: {}",
        msg
    );
}

#[test]
fn facade_error_from_security_error() {
    let sec_err = crate::ports::security::SecurityError::TokenInArgs { arg_index: 2 };
    let err: crate::Error = sec_err.into();
    assert_ne!(err.exit_code(), 0, "Security error must not be success");
}

#[test]
fn facade_error_from_profile_error() {
    let prof_err = crate::ports::profile::ProfileError::NotFound {
        path: std::path::PathBuf::from("/missing/profile.toml"),
    };
    let err: crate::Error = prof_err.into();
    let msg = format!("{}", err);
    assert!(msg.contains("profile"), "Must mention profile: {}", msg);
}

// Rule: env overrides are observed end-to-end from Client (mint_cmd).
#[test]
fn env_override_mint_cmd_observed_from_client() {
    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
        provider_env: Some(crate::ports::provider::ProviderEnv {
            mint_cmd: Some("/from/env/mint".to_string()),
            refresh_cmd: None,
            revoke_cmd: None,
        }),
        ..super::ClientOptions::default()
    })
    .unwrap();
    let resolved = client
        .resolve_provider("test-provider", &super::ProviderOverrides::default())
        .expect("NOSCOPE_MINT_CMD should satisfy provider resolution");
    assert_eq!(
        resolved.mint_cmd, "/from/env/mint",
        "mint_cmd must come from env override"
    );
    assert_eq!(
        resolved.source,
        crate::ports::provider::ConfigSource::EnvVars,
        "source must be EnvVars"
    );
}

// Rule: env overrides are observed end-to-end (refresh_cmd).
#[test]
fn env_override_refresh_cmd_observed_from_client() {
    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
        provider_env: Some(crate::ports::provider::ProviderEnv {
            mint_cmd: Some("/env/mint".to_string()),
            refresh_cmd: Some("/env/refresh".to_string()),
            revoke_cmd: None,
        }),
        ..super::ClientOptions::default()
    })
    .unwrap();
    let resolved = client
        .resolve_provider("test-provider", &super::ProviderOverrides::default())
        .unwrap();
    assert_eq!(
        resolved.refresh_cmd.as_deref(),
        Some("/env/refresh"),
        "refresh_cmd must come from env override"
    );
}

// Rule: env overrides are observed end-to-end (revoke_cmd).
#[test]
fn env_override_revoke_cmd_observed_from_client() {
    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
        provider_env: Some(crate::ports::provider::ProviderEnv {
            mint_cmd: Some("/env/mint".to_string()),
            refresh_cmd: None,
            revoke_cmd: Some("/env/revoke".to_string()),
        }),
        ..super::ClientOptions::default()
    })
    .unwrap();
    let resolved = client
        .resolve_provider("test-provider", &super::ProviderOverrides::default())
        .unwrap();
    assert_eq!(
        resolved.revoke_cmd.as_deref(),
        Some("/env/revoke"),
        "revoke_cmd must come from env override"
    );
}

// Rule: precedence — flags > env > file. Flags must beat env.
#[test]
fn env_override_precedence_flags_beat_env() {
    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
        provider_env: Some(crate::ports::provider::ProviderEnv {
            mint_cmd: Some("/from/env/mint".to_string()),
            refresh_cmd: Some("/from/env/refresh".to_string()),
            revoke_cmd: None,
        }),
        ..super::ClientOptions::default()
    })
    .unwrap();
    let overrides = super::ProviderOverrides {
        mint_cmd: Some("/from/flags/mint".to_string()),
        refresh_cmd: None,
        revoke_cmd: None,
    };
    let resolved = client
        .resolve_provider("test-provider", &overrides)
        .unwrap();
    assert_eq!(resolved.mint_cmd, "/from/flags/mint", "flags must beat env");
    assert_eq!(
        resolved.source,
        crate::ports::provider::ConfigSource::Flags,
        "source must be Flags when flags are set"
    );
    // no merging — env's refresh_cmd must NOT leak through
    assert!(
        resolved.refresh_cmd.is_none(),
        "flags layer wins entirely — env refresh_cmd must not merge"
    );
}

// Rule: precedence — env > file. Env must beat file config.
#[test]
fn env_override_precedence_env_beats_file() {
    let tmp = tempfile::tempdir().unwrap();

    let providers_dir = tmp.path().join("noscope").join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    let file_path = providers_dir.join("mycloud.toml");
    std::fs::write(
        &file_path,
        r#"
contract_version = 1

[commands]
mint = "/from/file/mint"
refresh = "/from/file/refresh"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(tmp.path().to_path_buf()),
        provider_env: Some(crate::ports::provider::ProviderEnv {
            mint_cmd: Some("/from/env/mint".to_string()),
            refresh_cmd: None,
            revoke_cmd: None,
        }),
        ..super::ClientOptions::default()
    })
    .unwrap();
    let resolved = client
        .resolve_provider("mycloud", &super::ProviderOverrides::default())
        .unwrap();
    assert_eq!(
        resolved.mint_cmd, "/from/env/mint",
        "env must beat file config"
    );
    assert_eq!(
        resolved.source,
        crate::ports::provider::ConfigSource::EnvVars,
        "source must be EnvVars"
    );
    // no merging — file's refresh_cmd must NOT leak through
    assert!(
        resolved.refresh_cmd.is_none(),
        "env layer wins entirely — file refresh_cmd must not merge"
    );
}

// Rule: when no env vars set and no flags, file layer still works.
#[test]
fn env_override_absent_env_falls_through_to_file() {
    let tmp = tempfile::tempdir().unwrap();

    let providers_dir = tmp.path().join("noscope").join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    let file_path = providers_dir.join("mycloud.toml");
    std::fs::write(
        &file_path,
        r#"
contract_version = 1

[commands]
mint = "/from/file/mint"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(tmp.path().to_path_buf()),
        // provider_env = None → uses process env (which won't have
        // NOSCOPE_* set in normal test environment)
        ..super::ClientOptions::default()
    })
    .unwrap();
    let resolved = client
        .resolve_provider("mycloud", &super::ProviderOverrides::default())
        .unwrap();
    assert_eq!(
        resolved.mint_cmd, "/from/file/mint",
        "with no env vars, file config must be used"
    );
    assert_eq!(
        resolved.source,
        crate::ports::provider::ConfigSource::File,
        "source must be File when no env/flags set"
    );
}

// Rule: env override only needs one var set to activate env layer.
#[test]
fn env_override_single_var_activates_env_layer() {
    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
        provider_env: Some(crate::ports::provider::ProviderEnv {
            mint_cmd: None,
            refresh_cmd: None,
            revoke_cmd: Some("/env/revoke".to_string()),
        }),
        ..super::ClientOptions::default()
    })
    .unwrap();
    let resolved = client
        .resolve_provider("test-provider", &super::ProviderOverrides::default())
        .unwrap();
    assert_eq!(
        resolved.source,
        crate::ports::provider::ConfigSource::EnvVars,
        "setting any env var must activate the env layer"
    );
    assert_eq!(resolved.revoke_cmd.as_deref(), Some("/env/revoke"));
    assert!(
        resolved.mint_cmd.is_empty(),
        "mint_cmd should be empty when env layer wins but mint env var not set"
    );
}

// Rule: default ClientOptions has no provider_env override (reads process env).
#[test]
fn env_override_default_client_options_reads_process_env() {
    let opts = super::ClientOptions::default();
    assert!(
        opts.provider_env.is_none(),
        "default ClientOptions must not override provider_env (reads from process env)"
    );
}

// Rule 1: Client::new must return Result<Client, Error>.
#[test]
fn hardening_client_new_returns_result() {
    // Client::new must be fallible — returns Result, not bare Client.
    let result: Result<super::Client, crate::Error> =
        super::Client::new(super::ClientOptions::default());
    // On Linux, hardening should succeed.
    assert!(result.is_ok(), "Client::new must succeed on Linux");
}

// Rule 1: Client::new success produces a usable Client.
#[test]
fn hardening_client_new_success_produces_usable_client() {
    let client = super::Client::new(super::ClientOptions::default())
        .expect("Client::new should succeed on Linux");
    // The client must be fully functional.
    let req = super::MintRequest {
        providers: vec!["aws".to_string()],
        role: "admin".to_string(),
        ttl_secs: 3600,
    };
    let result = client.validate_mint(&req);
    assert!(result.is_ok(), "Client from new() must be fully functional");
}

// Rule 1: Client::new error is an Error with SecurityKind.
#[test]
fn hardening_failure_is_security_error() {
    // A hardening failure must surface as Error with ErrorKind::Security.
    // We can't easily force setrlimit to fail, so we verify the error
    // type conversion: SecurityError::CoreDumpDisableFailed → Error::Security.
    let sec_err = crate::ports::security::SecurityError::CoreDumpDisableFailed(
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "mock failure"),
    );
    let err: crate::Error = sec_err.into();
    assert_eq!(
        err.kind(),
        crate::ErrorKind::Security,
        "CoreDumpDisableFailed must map to ErrorKind::Security"
    );
    assert!(
        err.message().contains("core dump"),
        "Security error message must mention core dumps: {}",
        err.message()
    );
}

// Rule 1: Hardening error has a non-zero exit code.
#[test]
fn hardening_failure_has_nonzero_exit_code() {
    let sec_err = crate::ports::security::SecurityError::CoreDumpDisableFailed(
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "mock"),
    );
    let err: crate::Error = sec_err.into();
    assert_ne!(
        err.exit_code(),
        0,
        "Hardening failure exit code must be non-zero"
    );
}

// Rule 2: Backwards-compatible best-effort constructor exists.
#[test]
fn hardening_best_effort_constructor_exists() {
    // new_best_effort must return Client (infallible), preserving old behavior.
    let _client: super::Client = super::Client::new_best_effort(super::ClientOptions::default());
}

// Rule 2: Best-effort constructor produces a usable client.
#[test]
fn hardening_best_effort_client_is_functional() {
    let client = super::Client::new_best_effort(super::ClientOptions::default());
    let req = super::MintRequest {
        providers: vec!["aws".to_string()],
        role: "admin".to_string(),
        ttl_secs: 3600,
    };
    let result = client.validate_mint(&req);
    assert!(
        result.is_ok(),
        "Best-effort client must be fully functional"
    );
}

// Rule 2: Best-effort constructor still calls disable_core_dumps.
#[test]
fn hardening_best_effort_still_disables_core_dumps() {
    let _client = super::Client::new_best_effort(super::ClientOptions::default());
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let ret = libc::getrlimit(libc::RLIMIT_CORE, &mut rlim);
        assert_eq!(ret, 0);
        assert_eq!(
            rlim.rlim_cur, 0,
            "Best-effort constructor must still disable core dumps"
        );
    }
}

// Rule 3: On Linux, Client::new succeeds (setrlimit works).
#[test]
fn hardening_succeeds_on_linux() {
    let result = super::Client::new(super::ClientOptions::default());
    assert!(
        result.is_ok(),
        "On Linux, Client::new must succeed (setrlimit works)"
    );
}

// Rule 4: Callers can programmatically detect hardening failure.
#[test]
fn hardening_failure_is_detectable_via_pattern_match() {
    // Prove that callers can match on ErrorKind::Security to detect
    // hardening failures specifically.
    let sec_err = crate::ports::security::SecurityError::CoreDumpDisableFailed(
        std::io::Error::other("simulated"),
    );
    let err: crate::Error = sec_err.into();
    let detected = err.kind() == crate::ErrorKind::Security && err.message().contains("core dump");
    assert!(
        detected,
        "Callers must be able to detect hardening failure via kind + message"
    );
}

// Rule 4: Hardening failure Display message is human-readable.
#[test]
fn hardening_failure_display_is_informative() {
    let sec_err = crate::ports::security::SecurityError::CoreDumpDisableFailed(
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
    );
    let err: crate::Error = sec_err.into();
    let msg = format!("{}", err);
    assert!(
        msg.contains("core dump"),
        "Display must mention 'core dump': {}",
        msg
    );
    assert!(
        msg.contains("security"),
        "Display must indicate security category: {}",
        msg
    );
}

// Edge case: Client::new on Linux should leave core dumps disabled.
#[test]
fn hardening_client_new_leaves_core_dumps_disabled() {
    let _client =
        super::Client::new(super::ClientOptions::default()).expect("should succeed on Linux");
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let ret = libc::getrlimit(libc::RLIMIT_CORE, &mut rlim);
        assert_eq!(ret, 0);
        assert_eq!(
            rlim.rlim_cur, 0,
            "After Client::new, core dumps must be disabled"
        );
        assert_eq!(rlim.rlim_max, 0);
    }
}

// Edge case: explicit empty ProviderEnv should not activate env layer.
#[test]
fn env_override_explicit_empty_env_does_not_activate_layer() {
    let tmp = tempfile::tempdir().unwrap();

    let providers_dir = tmp.path().join("noscope").join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    let file_path = providers_dir.join("mycloud.toml");
    std::fs::write(
        &file_path,
        r#"
contract_version = 1

[commands]
mint = "/from/file/mint"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let client = super::Client::new(super::ClientOptions {
        xdg_config_home: Some(tmp.path().to_path_buf()),
        // Explicit empty env — should fall through to file layer.
        provider_env: Some(crate::ports::provider::ProviderEnv::empty()),
        ..super::ClientOptions::default()
    })
    .unwrap();
    let resolved = client
        .resolve_provider("mycloud", &super::ProviderOverrides::default())
        .unwrap();
    assert_eq!(
        resolved.source,
        crate::ports::provider::ConfigSource::File,
        "explicit empty ProviderEnv must not activate env layer"
    );
    assert_eq!(resolved.mint_cmd, "/from/file/mint");
}
