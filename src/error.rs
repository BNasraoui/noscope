// NS-077: Typed machine-readable public error taxonomy
//
// Replace stringly, ad-hoc error aggregation with a typed top-level
// error hierarchy that is ergonomic for humans and machine consumers (agents).

use std::fmt;

use crate::exit_code::NoscopeExitCode;

// ---------------------------------------------------------------------------
// ErrorKind — machine-readable error category
// ---------------------------------------------------------------------------

/// Machine-readable error category for programmatic consumers.
///
/// Each variant maps to a stable string tag via [`ErrorKind::as_str`] and
/// a noscope exit code via the parent [`Error::exit_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Command-line usage error (bad flags, missing args). Exit 64.
    Usage,
    /// Configuration error (malformed config, missing provider). Exit 78.
    Config,
    /// Provider operation failed (mint, refresh, revoke). Exit 65.
    Provider,
    /// Security invariant violated (token in args, etc.). Exit 64.
    Security,
    /// Profile error (not found, validation failed). Exit 66.
    Profile,
    /// Internal software error (bug in noscope). Exit 70.
    Internal,
}

impl ErrorKind {
    /// Stable string tag for machine consumers (e.g. JSON error responses).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Config => "config",
            Self::Provider => "provider",
            Self::Security => "security",
            Self::Profile => "profile",
            Self::Internal => "internal",
        }
    }

    /// Map this kind to a noscope exit code.
    fn exit_code(self) -> i32 {
        match self {
            Self::Usage => NoscopeExitCode::Usage.as_raw(),
            Self::Config => NoscopeExitCode::ConfigError.as_raw(),
            Self::Provider => NoscopeExitCode::MintFailure.as_raw(),
            Self::Security => NoscopeExitCode::Usage.as_raw(),
            Self::Profile => NoscopeExitCode::ConfigNotFound.as_raw(),
            Self::Internal => NoscopeExitCode::Internal.as_raw(),
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Error — typed top-level error
// ---------------------------------------------------------------------------

/// Typed top-level error for the noscope public API.
///
/// Designed for both human and machine consumers:
/// - [`Error::kind`] returns a machine-readable [`ErrorKind`].
/// - [`Error::message`] returns the human-readable detail string.
/// - [`Error::provider_name`] returns the provider name (if applicable).
/// - [`Error::errors`] returns inner errors for multi-error cases.
/// - [`Error::exit_code`] maps to a noscope exit code (NS-054).
///
/// Multi-error cases (e.g. multiple provider failures) are represented
/// via [`Error::multi`] without flattening into brittle strings.
pub struct Error {
    kind: ErrorKind,
    message: String,
    /// Provider name, if this error is associated with a specific provider.
    provider_name: Option<String>,
    /// Inner errors for multi-error aggregation.
    inner: Vec<Error>,
    /// Optional source error for chaining.
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    // -- Private helper ------------------------------------------------------

    fn new(kind: ErrorKind, message: &str) -> Self {
        Self {
            kind,
            message: message.to_string(),
            provider_name: None,
            inner: Vec::new(),
            source: None,
        }
    }

    // -- Constructors --------------------------------------------------------

    /// Create a usage error (bad flags, missing args).
    pub fn usage(message: &str) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    /// Create a configuration error (malformed config, missing provider).
    pub fn config(message: &str) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    /// Create a provider error with the provider name for programmatic access.
    pub fn provider(provider: &str, message: &str) -> Self {
        let mut err = Self::new(ErrorKind::Provider, message);
        err.provider_name = Some(provider.to_string());
        err
    }

    /// Create a security error (token in args, etc.).
    pub fn security(message: &str) -> Self {
        Self::new(ErrorKind::Security, message)
    }

    /// Create a profile error (not found, validation failed).
    pub fn profile(message: &str) -> Self {
        Self::new(ErrorKind::Profile, message)
    }

    /// Create an internal error (bug in noscope).
    pub fn internal(message: &str) -> Self {
        Self::new(ErrorKind::Internal, message)
    }

    /// Create a multi-error aggregating multiple failures.
    ///
    /// Multi-errors preserve individual error kinds, provider names, and
    /// messages — no flattening into a single string.
    pub fn multi(errors: Vec<Error>) -> Self {
        Self {
            kind: ErrorKind::Provider,
            message: String::new(),
            provider_name: None,
            inner: errors,
            source: None,
        }
    }

    /// Attach a source error for chaining.
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    // -- Accessors -----------------------------------------------------------

    /// Machine-readable error category.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Human-readable detail message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Provider name, if this error is associated with a specific provider.
    pub fn provider_name(&self) -> Option<&str> {
        self.provider_name.as_deref()
    }

    /// Inner errors for multi-error cases. Empty for single errors.
    pub fn errors(&self) -> &[Error] {
        &self.inner
    }

    /// Map this error to a process exit code (NS-054).
    pub fn exit_code(&self) -> i32 {
        // Multi-error: use MintFailure (65) since multi-errors represent
        // multi-provider failures.
        if !self.inner.is_empty() {
            return NoscopeExitCode::MintFailure.as_raw();
        }
        self.kind.exit_code()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Multi-error: display all inner errors (may be empty).
        if self.message.is_empty() && self.provider_name.is_none() {
            for (i, err) in self.inner.iter().enumerate() {
                if i > 0 {
                    write!(f, "; ")?;
                }
                write!(f, "{}", err)?;
            }
            return Ok(());
        }

        match self.kind {
            ErrorKind::Provider => {
                if let Some(ref name) = self.provider_name {
                    write!(f, "provider '{}' error: {}", name, self.message)
                } else {
                    write!(f, "provider error: {}", self.message)
                }
            }
            _ => write!(f, "{} error: {}", self.kind, self.message),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Error");
        s.field("kind", &self.kind);
        s.field("message", &self.message);
        if let Some(ref name) = self.provider_name {
            s.field("provider", name);
        }
        if !self.inner.is_empty() {
            s.field("errors", &self.inner);
        }
        if self.source.is_some() {
            s.field("source", &"<error>");
        }
        s.finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

// ---------------------------------------------------------------------------
// From conversions for internal error types
// ---------------------------------------------------------------------------

impl From<crate::mint::MintError> for Error {
    fn from(e: crate::mint::MintError) -> Self {
        Self::usage(&format!("{}", e))
    }
}

impl From<crate::provider::ProviderConfigError> for Error {
    fn from(e: crate::provider::ProviderConfigError) -> Self {
        Self::config(&format!("{}", e))
    }
}

impl From<crate::security::SecurityError> for Error {
    fn from(e: crate::security::SecurityError) -> Self {
        Self::security(&format!("{}", e))
    }
}

impl From<crate::profile::ProfileError> for Error {
    fn from(e: crate::profile::ProfileError) -> Self {
        Self::profile(&format!("{}", e))
    }
}

impl From<crate::credential_set::CredentialSetError> for Error {
    fn from(e: crate::credential_set::CredentialSetError) -> Self {
        // Credential set errors are configuration/usage errors depending
        // on variant, but map to provider-level failures for consistency.
        Self::config(&format!("{}", e))
    }
}

impl From<crate::provider_exec::ProviderExecError> for Error {
    fn from(e: crate::provider_exec::ProviderExecError) -> Self {
        Self::new(ErrorKind::Provider, &format!("{}", e))
    }
}

#[cfg(test)]
mod tests {
    // =========================================================================
    // NS-077: Typed machine-readable public error taxonomy.
    //
    // Acceptance criteria:
    // 1. Public API returns typed errors with actionable categories.
    // 2. Multi-error cases are representable without flattening into
    //    brittle strings.
    // 3. Existing exit-code mapping and logging behavior remains consistent.
    // =========================================================================

    // -------------------------------------------------------------------------
    // Acceptance 1: Typed errors with actionable categories.
    //
    // Each variant carries structured fields (not just a String) so machine
    // consumers can programmatically inspect the error without parsing text.
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Acceptance 2: Multi-error cases are representable.
    //
    // When multiple providers fail, the errors are collected in a Vec,
    // not flattened into a single string.
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Acceptance 3: Existing exit-code mapping remains consistent.
    //
    // Each error kind maps to the same exit codes as the old NoscopeError.
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Display and Debug safety.
    //
    // Display messages must be stable for humans.
    // Debug must not leak secrets.
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // std::error::Error impl.
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // From conversions from existing error types.
    //
    // The new Error type must accept conversions from all existing module
    // error types so callers can use `?` seamlessly.
    // -------------------------------------------------------------------------

    #[test]
    fn typed_error_taxonomy_from_mint_error() {
        let mint_err = crate::mint::MintError::InvalidInput {
            message: "bad input".to_string(),
        };
        let err: super::Error = mint_err.into();
        assert!(matches!(err.kind(), super::ErrorKind::Usage));
        assert!(err.message().contains("bad input"));
    }

    #[test]
    fn typed_error_taxonomy_from_mint_error_terminal() {
        let mint_err = crate::mint::MintError::TerminalDetected;
        let err: super::Error = mint_err.into();
        assert!(matches!(err.kind(), super::ErrorKind::Usage));
    }

    #[test]
    fn typed_error_taxonomy_from_provider_config_error_malformed() {
        let prov_err = crate::provider::ProviderConfigError::MalformedConfig {
            message: "syntax error".to_string(),
        };
        let err: super::Error = prov_err.into();
        assert!(matches!(err.kind(), super::ErrorKind::Config));
        assert!(err.message().contains("syntax error"));
    }

    #[test]
    fn typed_error_taxonomy_from_provider_config_error_not_found() {
        let prov_err = crate::provider::ProviderConfigError::ProviderNotFound {
            provider: "mycloud".to_string(),
            checked_locations: vec!["loc1".to_string()],
        };
        let err: super::Error = prov_err.into();
        assert!(matches!(err.kind(), super::ErrorKind::Config));
        assert!(err.message().contains("mycloud"));
    }

    #[test]
    fn typed_error_taxonomy_from_security_error() {
        let sec_err = crate::security::SecurityError::TokenInArgs { arg_index: 2 };
        let err: super::Error = sec_err.into();
        assert!(matches!(err.kind(), super::ErrorKind::Security));
    }

    #[test]
    fn typed_error_taxonomy_from_profile_error() {
        let prof_err = crate::profile::ProfileError::NotFound {
            path: std::path::PathBuf::from("/missing/profile.toml"),
        };
        let err: super::Error = prof_err.into();
        assert!(matches!(err.kind(), super::ErrorKind::Profile));
    }

    #[test]
    fn typed_error_taxonomy_from_credential_set_error() {
        let cred_err = crate::credential_set::CredentialSetError::InvalidConfig {
            message: "max_concurrent must be > 0".to_string(),
        };
        let err: super::Error = cred_err.into();
        assert!(err.message().contains("max_concurrent"));
    }

    #[test]
    fn typed_error_taxonomy_from_provider_exec_error() {
        let exec_err = crate::provider_exec::ProviderExecError::Timeout {
            timeout: std::time::Duration::from_secs(30),
        };
        let err: super::Error = exec_err.into();
        assert!(matches!(err.kind(), super::ErrorKind::Provider));
    }

    // -------------------------------------------------------------------------
    // ErrorKind string representation for machine consumers.
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // ErrorKind: PartialEq, Eq, Clone, Copy for convenience.
    // -------------------------------------------------------------------------

    #[test]
    fn typed_error_taxonomy_kind_is_eq_comparable() {
        assert_eq!(super::ErrorKind::Usage, super::ErrorKind::Usage);
        assert_ne!(super::ErrorKind::Usage, super::ErrorKind::Config);
    }

    #[test]
    fn typed_error_taxonomy_kind_is_copy() {
        static_assertions::assert_impl_all!(super::ErrorKind: Copy);
    }

    // -------------------------------------------------------------------------
    // Source chaining: Error can carry a source error.
    // -------------------------------------------------------------------------

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
}
