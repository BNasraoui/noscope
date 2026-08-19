use provenance_macros::verifies;

#[test]
fn typed_error_taxonomy_has_usage_variant() {
    // Usage errors (bad flags, missing args) are a distinct category.
    let err = super::Error::usage("missing --ttl flag");
    assert!(matches!(err.kind(), super::ErrorKind::Usage));
}

#[test]
fn typed_error_taxonomy_has_config_variant() {
    // Configuration errors (malformed TOML, missing provider) are distinct.
    let err = super::Error::config("malformed TOML");
    assert!(matches!(err.kind(), super::ErrorKind::Config));
}

#[test]
fn typed_error_taxonomy_has_provider_variant() {
    // Provider errors carry the provider name for programmatic access.
    let err = super::Error::provider("aws", "auth expired");
    assert!(matches!(err.kind(), super::ErrorKind::Provider));
}

#[test]
fn typed_error_taxonomy_has_security_variant() {
    // Security violations (token in args, etc.) are distinct.
    let err = super::Error::security("credential value in CLI args");
    assert!(matches!(err.kind(), super::ErrorKind::Security));
}

#[test]
fn typed_error_taxonomy_has_profile_variant() {
    // Profile errors (not found, validation) are distinct.
    let err = super::Error::profile("profile not found");
    assert!(matches!(err.kind(), super::ErrorKind::Profile));
}

#[test]
fn typed_error_taxonomy_has_internal_variant() {
    // Internal/unexpected errors for bug scenarios.
    let err = super::Error::internal("unexpected state");
    assert!(matches!(err.kind(), super::ErrorKind::Internal));
}

#[test]
#[verifies("rule_errors_six_kinds", examples)]
fn typed_error_taxonomy_kind_is_machine_readable() {
    // ErrorKind can be matched exhaustively by machine consumers.
    let err = super::Error::usage("test");
    let kind = err.kind();
    // This match must compile — proves ErrorKind is a closed enum.
    let _label = match kind {
        super::ErrorKind::Usage => "usage",
        super::ErrorKind::Config => "config",
        super::ErrorKind::Provider => "provider",
        super::ErrorKind::Security => "security",
        super::ErrorKind::Profile => "profile",
        super::ErrorKind::Internal => "internal",
    };
}

#[test]
fn typed_error_taxonomy_provider_error_carries_provider_name() {
    // Machine consumers can extract the provider name without parsing text.
    let err = super::Error::provider("aws", "auth expired");
    assert_eq!(err.provider_name(), Some("aws"));
}

#[test]
fn typed_error_taxonomy_non_provider_error_has_no_provider() {
    let err = super::Error::usage("bad flag");
    assert_eq!(err.provider_name(), None);
}

#[test]
fn typed_error_taxonomy_message_is_accessible() {
    // The human-readable message is always accessible.
    let err = super::Error::usage("missing --ttl flag");
    assert_eq!(err.message(), "missing --ttl flag");
}

#[test]
fn typed_error_taxonomy_multi_error_holds_multiple_errors() {
    let errors = vec![
        super::Error::provider("aws", "auth expired"),
        super::Error::provider("gcp", "timeout"),
    ];
    let multi = super::Error::multi(errors);
    assert_eq!(multi.errors().len(), 2);
}

#[test]
fn typed_error_taxonomy_multi_error_preserves_individual_kinds() {
    let errors = vec![
        super::Error::provider("aws", "auth expired"),
        super::Error::config("missing field"),
    ];
    let multi = super::Error::multi(errors);
    let inner = multi.errors();
    assert!(matches!(inner[0].kind(), super::ErrorKind::Provider));
    assert!(matches!(inner[1].kind(), super::ErrorKind::Config));
}

#[test]
fn typed_error_taxonomy_multi_error_provider_names_accessible() {
    let errors = vec![
        super::Error::provider("aws", "auth expired"),
        super::Error::provider("gcp", "timeout"),
    ];
    let multi = super::Error::multi(errors);
    let providers: Vec<&str> = multi
        .errors()
        .iter()
        .filter_map(|e| e.provider_name())
        .collect();
    assert_eq!(providers, vec!["aws", "gcp"]);
}

#[test]
fn typed_error_taxonomy_multi_error_display_includes_all() {
    let errors = vec![
        super::Error::provider("aws", "auth expired"),
        super::Error::provider("gcp", "timeout"),
    ];
    let multi = super::Error::multi(errors);
    let display = format!("{}", multi);
    assert!(
        display.contains("aws"),
        "Display must mention aws: {}",
        display
    );
    assert!(
        display.contains("gcp"),
        "Display must mention gcp: {}",
        display
    );
}

#[test]
fn typed_error_taxonomy_multi_error_single_item_still_works() {
    // Multi with one error is valid (degenerate case).
    let errors = vec![super::Error::provider("aws", "auth expired")];
    let multi = super::Error::multi(errors);
    assert_eq!(multi.errors().len(), 1);
}

#[test]
fn typed_error_taxonomy_multi_error_empty_is_representable() {
    // Edge case: empty multi-error (e.g. from empty provider list).
    let multi = super::Error::multi(vec![]);
    assert!(multi.errors().is_empty());
}

#[test]
fn typed_error_taxonomy_multi_error_empty_display_is_empty() {
    // Edge case: Display on an empty multi-error produces an empty string.
    let multi = super::Error::multi(vec![]);
    let display = format!("{}", multi);
    assert!(
        display.is_empty(),
        "Empty multi-error display should be empty, got: {:?}",
        display
    );
}

#[test]
fn typed_error_taxonomy_usage_exit_code_is_64() {
    let err = super::Error::usage("bad flag");
    assert_eq!(err.exit_code(), 64);
}

#[test]
fn typed_error_taxonomy_config_exit_code_is_78() {
    let err = super::Error::config("malformed");
    assert_eq!(err.exit_code(), 78);
}

#[test]
fn typed_error_taxonomy_provider_exit_code_is_65() {
    // Provider failures map to exit 65 (mint failure).
    let err = super::Error::provider("aws", "auth expired");
    assert_eq!(err.exit_code(), 65);
}

#[test]
fn typed_error_taxonomy_security_exit_code_is_64() {
    // Security violations are usage errors (exit 64) per existing behavior.
    let err = super::Error::security("token in args");
    assert_eq!(err.exit_code(), 64);
}

#[test]
fn typed_error_taxonomy_profile_exit_code_is_66() {
    // Profile errors map to exit 66 (config not found) per existing behavior.
    let err = super::Error::profile("not found");
    assert_eq!(err.exit_code(), 66);
}

#[test]
fn typed_error_taxonomy_internal_exit_code_is_70() {
    let err = super::Error::internal("bug");
    assert_eq!(err.exit_code(), 70);
}

#[test]
fn typed_error_taxonomy_multi_error_exit_code_is_65() {
    // Multi-error (typically multi-provider failure) maps to exit 65.
    let errors = vec![
        super::Error::provider("aws", "expired"),
        super::Error::provider("gcp", "timeout"),
    ];
    let multi = super::Error::multi(errors);
    assert_eq!(multi.exit_code(), 65);
}

#[test]
fn typed_error_taxonomy_display_is_human_readable() {
    let err = super::Error::usage("missing --ttl flag");
    let display = format!("{}", err);
    assert!(
        display.contains("missing --ttl flag"),
        "Display must include the message: {}",
        display
    );
}

#[test]
fn typed_error_taxonomy_display_includes_category_prefix() {
    // Display should indicate the error category for humans.
    let err = super::Error::config("malformed TOML");
    let display = format!("{}", err);
    assert!(
        display.contains("config"),
        "Display must include category: {}",
        display
    );
}

#[test]
fn typed_error_taxonomy_provider_display_includes_provider_name() {
    let err = super::Error::provider("aws", "auth expired");
    let display = format!("{}", err);
    assert!(
        display.contains("aws"),
        "Display must include provider name: {}",
        display
    );
}

#[test]
fn typed_error_taxonomy_debug_does_not_leak_secrets() {
    // No error variant should carry or leak credential material.
    let err = super::Error::provider("aws", "auth expired");
    let debug = format!("{:?}", err);
    assert!(
        !debug.contains("secret"),
        "Debug must not contain secrets: {}",
        debug
    );
}

#[test]
fn typed_error_taxonomy_implements_std_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<super::Error>();
}

#[test]
fn typed_error_taxonomy_is_send() {
    static_assertions::assert_impl_all!(super::Error: Send);
}

#[test]
fn typed_error_taxonomy_is_sync() {
    static_assertions::assert_impl_all!(super::Error: Sync);
}

#[test]
fn typed_error_taxonomy_from_mint_error() {
    let mint_err = crate::core::mint::MintError::InvalidInput {
        message: "bad input".to_string(),
    };
    let err: super::Error = mint_err.into();
    assert!(matches!(err.kind(), super::ErrorKind::Usage));
    assert!(err.message().contains("bad input"));
}

#[test]
fn typed_error_taxonomy_from_mint_error_terminal() {
    let mint_err = crate::core::mint::MintError::TerminalDetected;
    let err: super::Error = mint_err.into();
    assert!(matches!(err.kind(), super::ErrorKind::Usage));
}

#[test]
fn typed_error_taxonomy_from_provider_config_error_malformed() {
    let prov_err = crate::ports::provider::ProviderConfigError::MalformedConfig {
        message: "syntax error".to_string(),
    };
    let err: super::Error = prov_err.into();
    assert!(matches!(err.kind(), super::ErrorKind::Config));
    assert!(err.message().contains("syntax error"));
}

#[test]
fn typed_error_taxonomy_from_provider_config_error_not_found() {
    let prov_err = crate::ports::provider::ProviderConfigError::ProviderNotFound {
        provider: "mycloud".to_string(),
        checked_locations: vec!["loc1".to_string()],
    };
    let err: super::Error = prov_err.into();
    assert!(matches!(err.kind(), super::ErrorKind::Config));
    assert!(err.message().contains("mycloud"));
}

#[test]
fn typed_error_taxonomy_from_security_error() {
    let sec_err = crate::ports::security::SecurityError::TokenInArgs { arg_index: 2 };
    let err: super::Error = sec_err.into();
    assert!(matches!(err.kind(), super::ErrorKind::Security));
}

#[test]
fn typed_error_taxonomy_from_profile_error() {
    let prof_err = crate::ports::profile::ProfileError::NotFound {
        path: std::path::PathBuf::from("/missing/profile.toml"),
    };
    let err: super::Error = prof_err.into();
    assert!(matches!(err.kind(), super::ErrorKind::Profile));
}

#[test]
fn typed_error_taxonomy_from_credential_set_error() {
    let cred_err = crate::core::credential_set::CredentialSetError::InvalidConfig {
        message: "max_concurrent must be > 0".to_string(),
    };
    let err: super::Error = cred_err.into();
    assert!(err.message().contains("max_concurrent"));
}

#[test]
fn typed_error_taxonomy_from_provider_exec_error() {
    let exec_err = crate::ports::provider_exec::ProviderExecError::Timeout {
        timeout: std::time::Duration::from_secs(30),
    };
    let err: super::Error = exec_err.into();
    assert!(matches!(err.kind(), super::ErrorKind::Provider));
}

#[test]
fn typed_error_taxonomy_kind_as_str() {
    // Machine consumers should be able to get a stable string tag.
    assert_eq!(super::ErrorKind::Usage.as_str(), "usage");
    assert_eq!(super::ErrorKind::Config.as_str(), "config");
    assert_eq!(super::ErrorKind::Provider.as_str(), "provider");
    assert_eq!(super::ErrorKind::Security.as_str(), "security");
    assert_eq!(super::ErrorKind::Profile.as_str(), "profile");
    assert_eq!(super::ErrorKind::Internal.as_str(), "internal");
}

#[test]
fn typed_error_taxonomy_kind_is_eq_comparable() {
    assert_eq!(super::ErrorKind::Usage, super::ErrorKind::Usage);
    assert_ne!(super::ErrorKind::Usage, super::ErrorKind::Config);
}

#[test]
fn typed_error_taxonomy_kind_is_copy() {
    static_assertions::assert_impl_all!(super::ErrorKind: Copy);
}

#[test]
fn typed_error_taxonomy_source_chaining() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let err = super::Error::config("config not found").with_source(io_err);
    // std::error::Error::source() should return Some
    use std::error::Error as _;
    assert!(err.source().is_some());
}

#[test]
fn typed_error_taxonomy_no_source_by_default() {
    let err = super::Error::usage("bad flag");
    use std::error::Error as _;
    assert!(err.source().is_none());
}
