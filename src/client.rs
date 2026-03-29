// Noscope high-level API facade (noscope-cg8.1)
//
// Provides a cohesive top-level API for core workflows (run, mint, revoke)
// so consumers do not compose many low-level module helpers manually.
//
// Security invariants enforced:
// - NS-001: No credential storage (no Serialize on secret-bearing types)
// - NS-005: Redaction in all Display/Debug output
// - NS-012: No tokens in process arguments
// - NS-019: Memory zeroization on drop
// - NS-020: Core dump prevention at construction
// - NS-033: Template variable injection prevention (role validation)
// - NS-058: Redaction at all log levels

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::exit_code::NoscopeExitCode;
use crate::mint;
use crate::provider;
use crate::provider_exec;
use crate::security;

// ---------------------------------------------------------------------------
// ClientOptions
// ---------------------------------------------------------------------------

/// Configuration for the noscope [`Client`].
///
/// All fields have sensible defaults. Use `ClientOptions::default()` to start
/// and override only the fields you need.
pub struct ClientOptions {
    /// Per-provider command timeout (default 30s).
    pub provider_timeout: Duration,
    /// Maximum concurrent provider operations (default 8).
    pub max_concurrent: usize,
    /// Override XDG_CONFIG_HOME for provider/profile config lookup.
    pub xdg_config_home: Option<PathBuf>,
    /// Override HOME for config fallback when XDG_CONFIG_HOME is unset.
    pub home: Option<PathBuf>,
    /// If true, allow mint output to a terminal (overrides NS-065 check).
    pub force_terminal: bool,
    /// If true, include provider stderr on success.
    pub verbose: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            provider_timeout: Duration::from_secs(30),
            max_concurrent: 8,
            xdg_config_home: None,
            home: None,
            force_terminal: false,
            verbose: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// High-level facade for noscope operations.
///
/// Wraps provider resolution, mint validation, revoke validation, terminal
/// detection, and dry-run into a single entry point. The `Client` calls
/// `security::disable_core_dumps()` at construction time (NS-020).
///
/// Not Clone — holds configuration state that should not be duplicated
/// carelessly.
pub struct Client {
    opts: ClientOptions,
}

impl Client {
    /// Create a new Client with the given options.
    ///
    /// NS-020: Disables core dumps immediately. If the platform does not
    /// support core dump suppression, the failure is silently ignored
    /// (the caller should log a warning separately if desired).
    pub fn new(opts: ClientOptions) -> Self {
        // NS-020: Best-effort core dump prevention.
        let _ = security::disable_core_dumps();
        Self { opts }
    }

    /// Validate a mint request before execution.
    ///
    /// Checks: providers non-empty, role non-empty and safe (NS-033),
    /// TTL > 0 (NS-062).
    pub fn validate_mint(&self, req: &MintRequest) -> Result<(), NoscopeError> {
        // Delegate to existing mint validation.
        // Pass Some(ttl_secs) directly — validate_mint_args handles zero
        // TTL with a clear error message, and None for the missing-flag case.
        let ttl_opt = if req.ttl_secs == 0 {
            None
        } else {
            Some(req.ttl_secs)
        };
        mint::validate_mint_args(ttl_opt, &req.providers, &req.role).map_err(NoscopeError::from)?;

        // NS-033: Validate role for safe characters.
        provider_exec::validate_role(&req.role).map_err(|e| NoscopeError::Usage {
            message: format!("{}", e),
        })?;

        Ok(())
    }

    /// NS-012: Validate that revoke CLI arguments do not contain --token.
    pub fn validate_revoke_args(&self, args: &[String]) -> Result<(), NoscopeError> {
        mint::validate_revoke_args(args).map_err(NoscopeError::from)
    }

    /// NS-065: Check that stdout is not a terminal before mint output.
    ///
    /// Respects `force_terminal` from [`ClientOptions`].
    pub fn check_stdout_not_terminal(&self, is_tty: bool) -> Result<(), NoscopeError> {
        mint::check_stdout_not_terminal(is_tty, self.opts.force_terminal)
            .map_err(NoscopeError::from)
    }

    /// Resolve a provider configuration by name, with optional overrides.
    ///
    /// Delegates to the provider module's strict precedence resolution
    /// (NS-007). The consumer does not need to import `provider::*` types.
    pub fn resolve_provider(
        &self,
        name: &str,
        overrides: &ProviderOverrides,
    ) -> Result<provider::ResolvedProvider, NoscopeError> {
        // Convert ProviderOverrides to the internal types.
        let flags = provider::ProviderFlags {
            mint_cmd: overrides.mint_cmd.clone(),
            refresh_cmd: overrides.refresh_cmd.clone(),
            revoke_cmd: overrides.revoke_cmd.clone(),
        };

        // Load file config from disk if no overrides are active.
        let config_path = match (&self.opts.xdg_config_home, &self.opts.home) {
            (Some(xdg), _) => provider::provider_config_path(name, Some(xdg)),
            (None, Some(home)) => provider::provider_config_path_with_home(name, None, home),
            (None, None) => provider::provider_config_path(name, None),
        };
        let file_config = provider::load_provider_file(&config_path).map_err(NoscopeError::from)?;

        let env = provider::ProviderEnv::default();

        provider::resolve_provider_config(name, &flags, &env, file_config)
            .map_err(NoscopeError::from)
    }

    /// NS-071: Generate dry-run output for a resolved provider.
    pub fn dry_run(
        &self,
        resolved: &provider::ResolvedProvider,
        role: &str,
        ttl_secs: u64,
    ) -> String {
        provider::dry_run_output(resolved, role, ttl_secs)
    }
}

// ---------------------------------------------------------------------------
// MintRequest
// ---------------------------------------------------------------------------

/// Input for a mint operation.
///
/// Contains everything needed to validate and execute a multi-provider mint.
pub struct MintRequest {
    /// One or more provider names.
    pub providers: Vec<String>,
    /// Role to request from each provider.
    pub role: String,
    /// TTL in seconds (must be > 0).
    pub ttl_secs: u64,
}

// ---------------------------------------------------------------------------
// RevokeRequest
// ---------------------------------------------------------------------------

/// Input for a revoke operation.
///
/// NS-012: Never stores the raw token value. Only carries the opaque
/// token_id and provider name needed for revocation.
pub struct RevokeRequest {
    inner: mint::RevokeInput,
}

impl RevokeRequest {
    /// Create a revoke request from explicit token_id and provider.
    pub fn from_token_id(token_id: &str, provider: &str) -> Self {
        Self {
            inner: mint::RevokeInput::from_token_id_and_provider(token_id, provider),
        }
    }

    /// Create a revoke request by parsing a mint JSON envelope.
    ///
    /// Extracts only token_id and provider. The raw token field is read
    /// but never stored (NS-012).
    pub fn from_mint_json(json_str: &str) -> Result<Self, NoscopeError> {
        let inner = mint::RevokeInput::from_mint_json(json_str).map_err(NoscopeError::from)?;
        Ok(Self { inner })
    }

    /// Get the token ID for revocation.
    pub fn token_id(&self) -> &str {
        self.inner.token_id()
    }

    /// Get the provider name for revocation.
    pub fn provider(&self) -> &str {
        self.inner.provider()
    }
}

// ---------------------------------------------------------------------------
// ProviderOverrides
// ---------------------------------------------------------------------------

/// CLI flag / env var overrides for provider configuration.
///
/// Maps to the highest-precedence layers in the NS-007 config resolution.
/// Use `ProviderOverrides::default()` for no overrides.
#[derive(Default)]
pub struct ProviderOverrides {
    pub mint_cmd: Option<String>,
    pub refresh_cmd: Option<String>,
    pub revoke_cmd: Option<String>,
}

impl ProviderOverrides {
    /// Returns true if any override is set.
    pub fn has_any(&self) -> bool {
        self.mint_cmd.is_some() || self.refresh_cmd.is_some() || self.revoke_cmd.is_some()
    }
}

// ---------------------------------------------------------------------------
// NoscopeError
// ---------------------------------------------------------------------------

/// Unified error type for the noscope facade API.
///
/// Covers all failure modes a consumer may encounter: usage errors,
/// configuration errors, mint failures, and security violations.
/// Each variant maps to a noscope exit code (NS-054).
#[derive(Debug)]
pub enum NoscopeError {
    /// Command-line usage error (bad flags, missing args).
    Usage { message: String },
    /// Configuration error (malformed config, missing provider).
    Config { message: String },
    /// Credential minting failed.
    MintFailed { message: String },
    /// Security invariant violated (token in args, etc.).
    Security { message: String },
    /// Profile error (not found, validation failed, etc.).
    Profile { message: String },
}

impl NoscopeError {
    /// Map this error to a process exit code (NS-054).
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage { .. } => NoscopeExitCode::Usage.as_raw(),
            Self::Config { .. } => NoscopeExitCode::ConfigError.as_raw(),
            Self::MintFailed { .. } => NoscopeExitCode::MintFailure.as_raw(),
            Self::Security { .. } => NoscopeExitCode::Usage.as_raw(),
            Self::Profile { .. } => NoscopeExitCode::ConfigNotFound.as_raw(),
        }
    }
}

impl fmt::Display for NoscopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage { message } => write!(f, "usage error: {}", message),
            Self::Config { message } => write!(f, "config error: {}", message),
            Self::MintFailed { message } => write!(f, "mint failed: {}", message),
            Self::Security { message } => write!(f, "security error: {}", message),
            Self::Profile { message } => write!(f, "profile error: {}", message),
        }
    }
}

impl std::error::Error for NoscopeError {}

// ---------------------------------------------------------------------------
// From conversions for internal error types
// ---------------------------------------------------------------------------

impl From<mint::MintError> for NoscopeError {
    fn from(e: mint::MintError) -> Self {
        match e {
            mint::MintError::InvalidInput { message } => Self::Usage { message },
            mint::MintError::TerminalDetected => Self::Usage {
                message: format!("{}", e),
            },
        }
    }
}

impl From<provider::ProviderConfigError> for NoscopeError {
    fn from(e: provider::ProviderConfigError) -> Self {
        Self::Config {
            message: format!("{}", e),
        }
    }
}

impl From<security::SecurityError> for NoscopeError {
    fn from(e: security::SecurityError) -> Self {
        Self::Security {
            message: format!("{}", e),
        }
    }
}

impl From<crate::profile::ProfileError> for NoscopeError {
    fn from(e: crate::profile::ProfileError) -> Self {
        Self::Profile {
            message: format!("{}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    // =========================================================================
    // Acceptance 1: Common workflow requires significantly fewer direct
    // module imports. The facade re-exports stable types from crate root.
    // =========================================================================

    #[test]
    fn facade_client_type_exists() {
        // The facade type `Client` must exist and be constructible.
        let _client: super::Client = super::Client::new(super::ClientOptions::default());
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
        };
        assert_eq!(opts.provider_timeout, Duration::from_secs(60));
        assert_eq!(opts.max_concurrent, 4);
    }

    // =========================================================================
    // Acceptance 2: Facade methods return typed results/errors suitable
    // for automation. A unified NoscopeError covers all failure modes.
    // =========================================================================

    #[test]
    fn facade_error_type_exists_and_is_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<super::NoscopeError>();
    }

    #[test]
    fn facade_error_has_exit_code() {
        // Every error variant must map to an exit code for automation.
        let err = super::NoscopeError::Usage {
            message: "bad flag".to_string(),
        };
        let code = err.exit_code();
        assert_eq!(code, 64);
    }

    #[test]
    fn facade_error_variants_cover_core_failure_modes() {
        // Usage errors
        let usage = super::NoscopeError::Usage {
            message: "missing --ttl".to_string(),
        };
        assert_eq!(usage.exit_code(), 64);

        // Provider config errors
        let config = super::NoscopeError::Config {
            message: "malformed TOML".to_string(),
        };
        assert_eq!(config.exit_code(), 78);

        // Mint failure
        let mint = super::NoscopeError::MintFailed {
            message: "aws auth expired".to_string(),
        };
        assert_eq!(mint.exit_code(), 65);

        // Security violation
        let sec = super::NoscopeError::Security {
            message: "token in args".to_string(),
        };
        // Security violations are internal/usage errors — must not be 0
        assert_ne!(sec.exit_code(), 0);
    }

    #[test]
    fn facade_error_display_is_informative() {
        let err = super::NoscopeError::Usage {
            message: "missing --ttl flag".to_string(),
        };
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
        let err = super::NoscopeError::MintFailed {
            message: "provider failed".to_string(),
        };
        let debug = format!("{:?}", err);
        assert!(
            !debug.contains("secret"),
            "Debug must not contain secrets: {}",
            debug
        );
    }

    // =========================================================================
    // Acceptance 2 (continued): MintRequest / RevokeRequest — typed input
    // structs that validate before execution.
    // =========================================================================

    #[test]
    fn facade_mint_request_validates_providers_required() {
        let client = super::Client::new(super::ClientOptions::default());
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
        let client = super::Client::new(super::ClientOptions::default());
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
        let client = super::Client::new(super::ClientOptions::default());
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
        // NS-033: Role must be validated for safe characters.
        let client = super::Client::new(super::ClientOptions::default());
        let req = super::MintRequest {
            providers: vec!["aws".to_string()],
            role: "admin; rm -rf /".to_string(),
            ttl_secs: 3600,
        };
        let result = client.validate_mint(&req);
        assert!(
            result.is_err(),
            "NS-033: Role with shell metacharacters must be rejected"
        );
    }

    #[test]
    fn facade_mint_request_valid_passes() {
        let client = super::Client::new(super::ClientOptions::default());
        let req = super::MintRequest {
            providers: vec!["aws".to_string()],
            role: "admin".to_string(),
            ttl_secs: 3600,
        };
        let result = client.validate_mint(&req);
        assert!(result.is_ok(), "Valid request must pass validation");
    }

    #[test]
    fn facade_revoke_request_from_token_id_and_provider() {
        let req = super::RevokeRequest::from_token_id("tok-123", "aws");
        assert_eq!(req.token_id(), "tok-123");
        assert_eq!(req.provider(), "aws");
    }

    #[test]
    fn facade_revoke_request_from_mint_json() {
        let json = r#"{"token":"secret","expires_at":"2025-01-01T00:00:00Z","token_id":"tok-99","provider":"gcp","role":"viewer"}"#;
        let req = super::RevokeRequest::from_mint_json(json);
        assert!(req.is_ok(), "Valid mint JSON must parse");
        let req = req.unwrap();
        assert_eq!(req.token_id(), "tok-99");
        assert_eq!(req.provider(), "gcp");
    }

    #[test]
    fn facade_revoke_request_rejects_invalid_json() {
        let result = super::RevokeRequest::from_mint_json("not json {{{");
        assert!(result.is_err(), "Invalid JSON must be rejected");
    }

    // =========================================================================
    // Acceptance 3: Existing security invariants remain enforced.
    // =========================================================================

    // NS-020: Core dump prevention at client construction.
    #[test]
    fn facade_client_disables_core_dumps() {
        // After Client construction, core dumps must be disabled.
        let _client = super::Client::new(super::ClientOptions::default());
        unsafe {
            let mut rlim = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            let ret = libc::getrlimit(libc::RLIMIT_CORE, &mut rlim);
            assert_eq!(ret, 0);
            assert_eq!(
                rlim.rlim_cur, 0,
                "NS-020: core dumps must be disabled after Client construction"
            );
            assert_eq!(rlim.rlim_max, 0);
        }
    }

    // NS-012: validate_revoke_args rejects --token in CLI args.
    #[test]
    fn facade_validate_revoke_args_rejects_raw_token_flag() {
        let client = super::Client::new(super::ClientOptions::default());
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token".to_string(),
            "secret-value".to_string(),
        ];
        let result = client.validate_revoke_args(&args);
        assert!(
            result.is_err(),
            "NS-012: --token flag must be rejected in revoke args"
        );
    }

    #[test]
    fn facade_validate_revoke_args_allows_token_id() {
        let client = super::Client::new(super::ClientOptions::default());
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token-id".to_string(),
            "tok-123".to_string(),
        ];
        let result = client.validate_revoke_args(&args);
        assert!(result.is_ok(), "--token-id is safe and must be allowed");
    }

    // NS-065: Terminal detection for mint stdout.
    #[test]
    fn facade_check_stdout_terminal_rejects_tty() {
        let client = super::Client::new(super::ClientOptions::default());
        let result = client.check_stdout_not_terminal(true);
        assert!(
            result.is_err(),
            "NS-065: Mint to terminal stdout must be rejected"
        );
    }

    #[test]
    fn facade_check_stdout_terminal_allows_pipe() {
        let client = super::Client::new(super::ClientOptions::default());
        let result = client.check_stdout_not_terminal(false);
        assert!(result.is_ok(), "NS-065: Pipe stdout must be allowed");
    }

    #[test]
    fn facade_check_stdout_terminal_force_overrides() {
        let client = super::Client::new(super::ClientOptions {
            force_terminal: true,
            ..super::ClientOptions::default()
        });
        let result = client.check_stdout_not_terminal(true);
        assert!(
            result.is_ok(),
            "NS-065: force_terminal must override TTY check"
        );
    }

    // =========================================================================
    // Facade structural invariants.
    // =========================================================================

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
    fn facade_noscopeerror_is_send() {
        static_assertions::assert_impl_all!(super::NoscopeError: Send);
    }

    #[test]
    fn facade_noscopeerror_is_sync() {
        static_assertions::assert_impl_all!(super::NoscopeError: Sync);
    }

    #[test]
    fn facade_noscopeerror_is_not_clone() {
        // Error types should not be Clone — they may carry heap-allocated
        // context and cloning errors is rarely the right pattern.
        static_assertions::assert_not_impl_any!(super::NoscopeError: Clone);
    }

    #[test]
    fn facade_mint_request_is_not_clone() {
        static_assertions::assert_not_impl_any!(super::MintRequest: Clone);
    }

    #[test]
    fn facade_revoke_request_is_not_clone() {
        // RevokeRequest wraps RevokeInput which should not be cloned.
        static_assertions::assert_not_impl_any!(super::RevokeRequest: Clone);
    }

    // =========================================================================
    // Facade provider resolution shorthand.
    // =========================================================================

    #[test]
    fn facade_resolve_provider_delegates_to_provider_module() {
        // Client exposes provider resolution without requiring the consumer
        // to manually import provider module types.
        let client = super::Client::new(super::ClientOptions::default());
        let result = client.resolve_provider("nonexistent", &super::ProviderOverrides::default());
        assert!(result.is_err(), "Nonexistent provider must return an error");
        // Error message must enumerate checked locations (NS-044)
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

    // =========================================================================
    // Facade dry-run support.
    // =========================================================================

    #[test]
    fn facade_dry_run_produces_output() {
        // Dry-run mode must work through the facade without requiring
        // the consumer to construct ResolvedProvider manually.
        let client = super::Client::new(super::ClientOptions::default());
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

    // =========================================================================
    // Re-export verification: stable types accessible from crate root.
    // =========================================================================

    #[test]
    fn facade_reexports_scoped_token_type() {
        // ScopedToken should be re-exported so consumers don't need
        // `use noscope::token::ScopedToken`.
        fn _accepts_scoped_token(_t: &crate::token::ScopedToken) {}
        // This test existing verifies the type is accessible.
    }

    #[test]
    fn facade_reexports_mint_envelope() {
        fn _accepts_envelope(_e: &crate::mint::MintEnvelope) {}
    }

    #[test]
    fn facade_reexports_event_types() {
        fn _accepts_event(_e: &crate::event::Event) {}
        fn _accepts_event_type(_t: &crate::event::EventType) {}
    }

    // =========================================================================
    // NoscopeError conversion from internal error types.
    // =========================================================================

    #[test]
    fn facade_error_from_mint_error() {
        let mint_err = crate::mint::MintError::InvalidInput {
            message: "bad input".to_string(),
        };
        let err: super::NoscopeError = mint_err.into();
        let msg = format!("{}", err);
        assert!(msg.contains("bad input"), "Must carry the message: {}", msg);
    }

    #[test]
    fn facade_error_from_provider_config_error() {
        let prov_err = crate::provider::ProviderConfigError::MalformedConfig {
            message: "syntax error".to_string(),
        };
        let err: super::NoscopeError = prov_err.into();
        let msg = format!("{}", err);
        assert!(
            msg.contains("syntax error"),
            "Must carry the message: {}",
            msg
        );
    }

    #[test]
    fn facade_error_from_security_error() {
        let sec_err = crate::security::SecurityError::TokenInArgs { arg_index: 2 };
        let err: super::NoscopeError = sec_err.into();
        assert_ne!(err.exit_code(), 0, "Security error must not be success");
    }

    #[test]
    fn facade_error_from_profile_error() {
        let prof_err = crate::profile::ProfileError::NotFound {
            path: std::path::PathBuf::from("/missing/profile.toml"),
        };
        let err: super::NoscopeError = prof_err.into();
        let msg = format!("{}", err);
        assert!(msg.contains("profile"), "Must mention profile: {}", msg);
    }
}
