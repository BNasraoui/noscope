mod config_path;
pub mod cli_adapter;
pub mod client;
pub mod credential_set;
pub mod error;
pub mod event;
pub mod exit_code;
pub mod mint;
pub mod profile;
pub mod provider;
pub mod provider_exec;
pub mod redaction;
pub mod refresh;
pub mod security;
pub mod token;
pub mod token_convert;

// ---------------------------------------------------------------------------
// Re-exports: stable, ergonomic types from crate root (noscope-cg8.1).
//
// Consumers can write `use noscope::{Client, MintRequest, Error, ErrorKind}`
// instead of importing from individual modules.
//
// NoscopeError is a backward-compatible type alias for Error
// (noscope-bsq.1.5).
// ---------------------------------------------------------------------------

pub use client::{Client, ClientOptions, MintRequest, ProviderOverrides, RevokeRequest};
pub use error::{Error, ErrorKind};

/// Backward-compatible type alias for the canonical error type.
///
/// noscope-bsq.1.5: The crate previously exported both `NoscopeError`
/// (a simple enum in `client.rs`) and `error::Error`/`ErrorKind` (a richer
/// typed error). This alias converges on `error::Error` as the single
/// canonical public error surface.
///
/// **Migration guide:**
/// - Old: `match err { NoscopeError::Usage { message } => ... }`
///   New: `match err.kind() { ErrorKind::Usage => { let msg = err.message(); ... } }`
/// - Old: `NoscopeError::Usage { message: "bad".to_string() }`
///   New: `Error::usage("bad")`
/// - `exit_code()` and `Display` work unchanged.
/// - `error::Error` adds `kind()`, `provider_name()`, `errors()` (multi-error),
///   and `with_source()` for error chaining.
pub type NoscopeError = Error;
pub use event::{Event, EventType, LogFormat};
pub use exit_code::{NoscopeExitCode, ProviderExitCode};
pub use mint::MintEnvelope;
pub use token::ScopedToken;
pub use token_convert::{
    provider_output_to_scoped_token, provider_output_to_scoped_token_with_metadata,
    scoped_token_to_mint_envelope, ConversionResult,
};

#[cfg(test)]
mod convergence_tests {
    // =========================================================================
    // noscope-bsq.1.5: Converge on a single public top-level error type.
    //
    // Acceptance criteria:
    // 1. No split-brain error API for new consumers.
    // 2. Exit-code behavior remains stable and covered by tests.
    //
    // Rules tested:
    // - Choose one canonical public error surface.
    // - Make facade and adapter layers use that canonical type consistently.
    // - Provide migration notes/tests for compatibility.
    // =========================================================================

    // -------------------------------------------------------------------------
    // Rule: Choose one canonical public error surface.
    //
    // error::Error must be the single canonical error type. NoscopeError
    // must be a type alias for backward compatibility, not a separate type.
    // -------------------------------------------------------------------------

    #[test]
    fn canonical_error_type_is_error_error() {
        // The canonical public error type is error::Error.
        // It must be re-exported from the crate root.
        let err: crate::Error = crate::error::Error::usage("test");
        assert_eq!(err.kind(), crate::ErrorKind::Usage);
    }

    #[test]
    fn noscope_error_is_alias_for_canonical_type() {
        // NoscopeError must be a type alias for error::Error, not a separate enum.
        // This proves they are the same type by assigning one to the other.
        let err: crate::NoscopeError = crate::error::Error::usage("test");
        let _back: crate::Error = err;
    }

    #[test]
    fn noscope_error_alias_has_kind_method() {
        // NoscopeError (alias) must expose the kind() method from error::Error.
        let err: crate::NoscopeError = crate::error::Error::config("malformed");
        assert_eq!(err.kind(), crate::ErrorKind::Config);
    }

    #[test]
    fn noscope_error_alias_has_provider_name_method() {
        // NoscopeError (alias) must expose provider_name() from error::Error.
        let err: crate::NoscopeError = crate::error::Error::provider("aws", "expired");
        assert_eq!(err.provider_name(), Some("aws"));
    }

    #[test]
    fn noscope_error_alias_has_errors_method() {
        // NoscopeError (alias) must expose multi-error support from error::Error.
        let multi: crate::NoscopeError = crate::error::Error::multi(vec![
            crate::error::Error::provider("aws", "expired"),
            crate::error::Error::provider("gcp", "timeout"),
        ]);
        assert_eq!(multi.errors().len(), 2);
    }

    #[test]
    fn noscope_error_alias_has_exit_code_method() {
        // NoscopeError (alias) must expose exit_code() from error::Error.
        let err: crate::NoscopeError = crate::error::Error::usage("bad flag");
        assert_eq!(err.exit_code(), 64);
    }

    #[test]
    fn no_duplicate_error_type_in_crate_root() {
        // Both crate::NoscopeError and crate::Error must refer to the same type.
        // Prove this by creating one and consuming it as the other.
        fn accepts_error(_e: crate::Error) {}
        let err: crate::NoscopeError = crate::error::Error::usage("test");
        accepts_error(err);
    }

    // -------------------------------------------------------------------------
    // Rule: Make facade layer (Client) use that canonical type consistently.
    // -------------------------------------------------------------------------

    #[test]
    fn client_new_returns_canonical_error() {
        // Client::new must return Result<Client, error::Error>.
        let result: Result<crate::Client, crate::Error> =
            crate::Client::new(crate::ClientOptions::default());
        assert!(result.is_ok());
    }

    #[test]
    fn client_validate_mint_returns_canonical_error() {
        let client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        let req = crate::MintRequest {
            providers: vec![],
            role: "admin".to_string(),
            ttl_secs: 3600,
        };
        let result: Result<(), crate::Error> = client.validate_mint(&req);
        assert!(result.is_err());
        // The error must have a kind — proving it's the canonical type.
        let err = result.unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Usage);
    }

    #[test]
    fn client_check_stdout_returns_canonical_error() {
        let client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        let result: Result<(), crate::Error> = client.check_stdout_not_terminal(true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Usage);
    }

    #[test]
    fn client_resolve_provider_returns_canonical_error() {
        let client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        let result: Result<crate::provider::ResolvedProvider, crate::Error> =
            client.resolve_provider("nonexistent", &crate::ProviderOverrides::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Config);
    }

    #[test]
    fn revoke_request_from_mint_json_returns_canonical_error() {
        let result: Result<crate::RevokeRequest, crate::Error> =
            crate::RevokeRequest::from_mint_json("not json {{{");
        match result {
            Ok(_) => panic!("Expected error for invalid JSON"),
            Err(err) => assert_eq!(err.kind(), crate::ErrorKind::Usage),
        }
    }

    // -------------------------------------------------------------------------
    // Rule: Make adapter layer (cli_adapter) use that canonical type consistently.
    // -------------------------------------------------------------------------

    #[test]
    fn cli_adapter_validate_revoke_argv_returns_canonical_error() {
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token".to_string(),
            "secret".to_string(),
        ];
        let result: Result<(), crate::Error> = crate::cli_adapter::validate_revoke_argv(&args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Usage);
    }

    #[test]
    fn cli_adapter_validate_mint_flags_returns_canonical_error() {
        let result: Result<crate::MintRequest, crate::Error> =
            crate::cli_adapter::validate_mint_flags(None, &["aws".to_string()], "admin");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Usage);
    }

    #[test]
    fn cli_adapter_check_profile_flag_exclusion_returns_canonical_error() {
        let result: Result<(), crate::Error> =
            crate::cli_adapter::check_profile_flag_exclusion(Some("dev"), Some("aws"), None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Profile);
    }

    // -------------------------------------------------------------------------
    // Rule: Exit-code behavior remains stable.
    //
    // All existing exit codes must be preserved through the canonical type.
    // -------------------------------------------------------------------------

    #[test]
    fn exit_code_usage_is_64_through_canonical() {
        let err = crate::Error::usage("bad flag");
        assert_eq!(err.exit_code(), 64);
    }

    #[test]
    fn exit_code_config_is_78_through_canonical() {
        let err = crate::Error::config("malformed");
        assert_eq!(err.exit_code(), 78);
    }

    #[test]
    fn exit_code_provider_is_65_through_canonical() {
        let err = crate::Error::provider("aws", "expired");
        assert_eq!(err.exit_code(), 65);
    }

    #[test]
    fn exit_code_security_is_64_through_canonical() {
        let err = crate::Error::security("token in args");
        assert_eq!(err.exit_code(), 64);
    }

    #[test]
    fn exit_code_profile_is_66_through_canonical() {
        let err = crate::Error::profile("not found");
        assert_eq!(err.exit_code(), 66);
    }

    #[test]
    fn exit_code_internal_is_70_through_canonical() {
        let err = crate::Error::internal("bug");
        assert_eq!(err.exit_code(), 70);
    }

    #[test]
    fn exit_code_multi_is_65_through_canonical() {
        let multi = crate::Error::multi(vec![
            crate::Error::provider("aws", "expired"),
            crate::Error::provider("gcp", "timeout"),
        ]);
        assert_eq!(multi.exit_code(), 65);
    }

    // -------------------------------------------------------------------------
    // Rule: Facade error conversions from module errors preserve exit codes.
    //
    // After convergence, Client returns error::Error which has From impls
    // for all module errors. The exit codes must match previous NoscopeError
    // behavior.
    // -------------------------------------------------------------------------

    #[test]
    fn facade_mint_error_exit_code_preserved() {
        // MintError → error::Error, usage exit code (64).
        let client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        let req = crate::MintRequest {
            providers: vec!["aws".to_string()],
            role: "admin".to_string(),
            ttl_secs: 0, // triggers mint validation error
        };
        let err = client.validate_mint(&req).unwrap_err();
        assert_eq!(err.exit_code(), 64, "MintError must map to usage (64)");
    }

    #[test]
    fn facade_provider_error_exit_code_preserved() {
        // ProviderConfigError → error::Error, config exit code (78).
        let client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        let err = client
            .resolve_provider("nonexistent", &crate::ProviderOverrides::default())
            .unwrap_err();
        assert_eq!(
            err.exit_code(),
            78,
            "ProviderConfigError must map to config error (78)"
        );
    }

    #[test]
    fn facade_security_error_exit_code_preserved() {
        // SecurityError → error::Error, security/usage exit code (64).
        let sec_err = crate::security::SecurityError::CoreDumpDisableFailed(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "mock"),
        );
        let err: crate::Error = sec_err.into();
        assert_eq!(
            err.exit_code(),
            64,
            "SecurityError must map to usage (64)"
        );
    }

    #[test]
    fn facade_profile_error_exit_code_preserved() {
        // ProfileError → error::Error, profile exit code (66).
        let prof_err = crate::profile::ProfileError::NotFound {
            path: std::path::PathBuf::from("/missing.toml"),
        };
        let err: crate::Error = prof_err.into();
        assert_eq!(
            err.exit_code(),
            66,
            "ProfileError must map to config not found (66)"
        );
    }

    // -------------------------------------------------------------------------
    // Rule: Provide migration notes/tests for compatibility.
    //
    // Existing code using NoscopeError must continue to compile.
    // The type alias ensures backward compatibility.
    // -------------------------------------------------------------------------

    #[test]
    fn migration_noscope_error_pattern_match_still_works() {
        // Existing code that matches on NoscopeError variants must still work.
        // With the type alias, matching uses error::Error's kind() instead.
        let err: crate::NoscopeError = crate::error::Error::usage("test");
        // New consumer pattern: use kind() for programmatic matching.
        match err.kind() {
            crate::ErrorKind::Usage => {} // ok
            _ => panic!("Expected Usage kind"),
        }
    }

    #[test]
    fn migration_noscope_error_display_still_works() {
        // Display must still produce human-readable output.
        let err: crate::NoscopeError = crate::error::Error::usage("missing --ttl flag");
        let display = format!("{}", err);
        assert!(display.contains("missing --ttl flag"));
    }

    #[test]
    fn migration_noscope_error_exit_code_still_works() {
        // exit_code() method must still be available on NoscopeError.
        let err: crate::NoscopeError = crate::error::Error::config("malformed");
        assert_eq!(err.exit_code(), 78);
    }

    #[test]
    fn migration_noscope_error_is_std_error() {
        // NoscopeError must still implement std::error::Error.
        fn assert_error<T: std::error::Error>() {}
        assert_error::<crate::NoscopeError>();
    }

    #[test]
    fn migration_noscope_error_is_send_sync() {
        static_assertions::assert_impl_all!(crate::NoscopeError: Send, Sync);
    }
}
