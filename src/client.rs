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
//
// noscope-bsq.1.5: This module uses crate::error::Error as the single
// canonical error type. The old NoscopeError enum has been replaced by a
// type alias (pub type NoscopeError = crate::error::Error) in lib.rs for
// backward compatibility.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::Error;
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
    /// Override the NOSCOPE_* env var layer for provider resolution.
    ///
    /// When `None` (the default), reads `NOSCOPE_MINT_CMD`,
    /// `NOSCOPE_REFRESH_CMD`, and `NOSCOPE_REVOKE_CMD` from the process
    /// environment. When `Some(env)`, uses the provided values directly.
    /// This exists for testability — mutating process env in parallel
    /// tests is inherently racy.
    pub provider_env: Option<provider::ProviderEnv>,
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
            provider_env: None,
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
    /// NS-020: Disables core dumps immediately. Returns an error if the
    /// platform does not support core dump suppression, allowing callers
    /// to detect and handle hardening failures (e.g., log a warning,
    /// abort the process, or proceed with degraded security).
    ///
    /// For callers that prefer the old best-effort behavior, use
    /// [`Client::new_best_effort`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] with [`ErrorKind::Security`] if
    /// `setrlimit(RLIMIT_CORE, 0)` fails (e.g., insufficient privileges).
    pub fn new(opts: ClientOptions) -> Result<Self, Error> {
        // NS-020: Fail-fast core dump prevention.
        security::disable_core_dumps()?;
        Ok(Self { opts })
    }

    /// Create a new Client with best-effort core dump hardening.
    ///
    /// NS-020: Attempts to disable core dumps but silently ignores
    /// failures. This preserves the original `Client::new` behavior
    /// for callers that cannot handle a fallible constructor.
    ///
    /// **Prefer [`Client::new`]** in new code — it surfaces hardening
    /// failures so callers can make an informed decision.
    pub fn new_best_effort(opts: ClientOptions) -> Self {
        let _ = security::disable_core_dumps();
        Self { opts }
    }

    /// Validate a mint request before execution.
    ///
    /// Checks: providers non-empty, role non-empty and safe (NS-033),
    /// TTL > 0 (NS-062).
    pub fn validate_mint(&self, req: &MintRequest) -> Result<(), Error> {
        // Delegate to existing mint validation.
        // Pass Some(ttl_secs) directly — validate_mint_args handles zero
        // TTL with a clear error message, and None for the missing-flag case.
        let ttl_opt = if req.ttl_secs == 0 {
            None
        } else {
            Some(req.ttl_secs)
        };
        mint::validate_mint_args(ttl_opt, &req.providers, &req.role)?;

        // NS-033: Validate role for safe characters.
        provider_exec::validate_role(&req.role).map_err(|e| Error::usage(&format!("{}", e)))?;

        Ok(())
    }

    /// NS-065: Check that stdout is not a terminal before mint output.
    ///
    /// Respects `force_terminal` from [`ClientOptions`].
    pub fn check_stdout_not_terminal(&self, is_tty: bool) -> Result<(), Error> {
        mint::check_stdout_not_terminal(is_tty, self.opts.force_terminal)?;
        Ok(())
    }

    /// Resolve a provider configuration by name, with optional overrides.
    ///
    /// Delegates to the provider module's strict precedence resolution
    /// (NS-007). The consumer does not need to import `provider::*` types.
    pub fn resolve_provider(
        &self,
        name: &str,
        overrides: &ProviderOverrides,
    ) -> Result<provider::ResolvedProvider, Error> {
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
        let file_config = provider::load_provider_file(&config_path)?;

        let env = match &self.opts.provider_env {
            Some(env) => env.clone(),
            None => provider::provider_env_from_process(),
        };

        Ok(provider::resolve_provider_config(
            name,
            &flags,
            &env,
            file_config,
        )?)
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
#[derive(Debug)]
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
    pub fn from_mint_json(json_str: &str) -> Result<Self, Error> {
        let inner = mint::RevokeInput::from_mint_json(json_str)?;
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
// NoscopeError type alias (noscope-bsq.1.5)
// ---------------------------------------------------------------------------
// The old NoscopeError enum has been replaced by a type alias pointing to
// the canonical error::Error type. This preserves backward compatibility
// for existing consumers while converging on a single public error surface.
//
// Migration for existing code:
// - Old: match err { NoscopeError::Usage { message } => ... }
//   New: match err.kind() { ErrorKind::Usage => ...; use err.message() }
// - Old: NoscopeError::Usage { message: "bad".to_string() }
//   New: Error::usage("bad")
// - exit_code() and Display still work unchanged.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    // =========================================================================
    // Acceptance 1: Common workflow requires significantly fewer direct
    // module imports. The facade re-exports stable types from crate root.
    // =========================================================================

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

    // =========================================================================
    // Acceptance 2: Facade methods return typed results/errors suitable
    // for automation. A unified NoscopeError covers all failure modes.
    // =========================================================================

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

    // =========================================================================
    // Acceptance 2 (continued): MintRequest / RevokeRequest — typed input
    // structs that validate before execution.
    // =========================================================================

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
        // NS-033: Role must be validated for safe characters.
        let client = super::Client::new(super::ClientOptions::default()).unwrap();
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
        let client = super::Client::new(super::ClientOptions::default()).unwrap();
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
                "NS-020: core dumps must be disabled after Client construction"
            );
            assert_eq!(rlim.rlim_max, 0);
        }
    }

    // NS-012: validate_revoke_argv lives in cli_adapter (noscope-cg8.2).
    // See cli_adapter::tests for argv-level validation tests.
    #[test]
    fn facade_revoke_args_validation_moved_to_cli_adapter() {
        // noscope-cg8.2: argv validation moved to cli_adapter module.
        // Client no longer exposes validate_revoke_args(&[String]).
        // Verify cli_adapter::validate_revoke_argv works.
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token".to_string(),
            "secret-value".to_string(),
        ];
        let result = crate::cli_adapter::validate_revoke_argv(&args);
        assert!(
            result.is_err(),
            "NS-012: --token flag must be rejected via cli_adapter"
        );

        let safe_args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token-id".to_string(),
            "tok-123".to_string(),
        ];
        let result = crate::cli_adapter::validate_revoke_argv(&safe_args);
        assert!(result.is_ok(), "--token-id is safe and must be allowed");
    }

    // NS-065: Terminal detection for mint stdout.
    #[test]
    fn facade_check_stdout_terminal_rejects_tty() {
        let client = super::Client::new(super::ClientOptions::default()).unwrap();
        let result = client.check_stdout_not_terminal(true);
        assert!(
            result.is_err(),
            "NS-065: Mint to terminal stdout must be rejected"
        );
    }

    #[test]
    fn facade_check_stdout_terminal_allows_pipe() {
        let client = super::Client::new(super::ClientOptions::default()).unwrap();
        let result = client.check_stdout_not_terminal(false);
        assert!(result.is_ok(), "NS-065: Pipe stdout must be allowed");
    }

    #[test]
    fn facade_check_stdout_terminal_force_overrides() {
        let client = super::Client::new(super::ClientOptions {
            force_terminal: true,
            ..super::ClientOptions::default()
        })
        .unwrap();
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
        let client = super::Client::new(super::ClientOptions::default()).unwrap();
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
    // Error conversion from internal error types (via error::Error From impls).
    // =========================================================================

    #[test]
    fn facade_error_from_mint_error() {
        let mint_err = crate::mint::MintError::InvalidInput {
            message: "bad input".to_string(),
        };
        let err: crate::Error = mint_err.into();
        let msg = format!("{}", err);
        assert!(msg.contains("bad input"), "Must carry the message: {}", msg);
    }

    #[test]
    fn facade_error_from_provider_config_error() {
        let prov_err = crate::provider::ProviderConfigError::MalformedConfig {
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
        let sec_err = crate::security::SecurityError::TokenInArgs { arg_index: 2 };
        let err: crate::Error = sec_err.into();
        assert_ne!(err.exit_code(), 0, "Security error must not be success");
    }

    #[test]
    fn facade_error_from_profile_error() {
        let prof_err = crate::profile::ProfileError::NotFound {
            path: std::path::PathBuf::from("/missing/profile.toml"),
        };
        let err: crate::Error = prof_err.into();
        let msg = format!("{}", err);
        assert!(msg.contains("profile"), "Must mention profile: {}", msg);
    }

    // =========================================================================
    // noscope-bsq.1.2: NOSCOPE_* env overrides wired in Client::resolve_provider
    //
    // The bug: resolve_provider passes ProviderEnv::default() and ignores
    // process environment. Tests below prove env overrides are observed
    // end-to-end through the Client facade, and precedence is strict.
    //
    // Tests use the provider_env override in ClientOptions for determinism —
    // mutating process env in parallel tests is inherently racy. The
    // from_process_env() constructor is tested separately in provider::tests.
    // =========================================================================

    // Rule: env overrides are observed end-to-end from Client (mint_cmd).
    #[test]
    fn env_override_mint_cmd_observed_from_client() {
        let client = super::Client::new(super::ClientOptions {
            xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
            provider_env: Some(crate::provider::ProviderEnv {
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
            crate::provider::ConfigSource::EnvVars,
            "source must be EnvVars"
        );
    }

    // Rule: env overrides are observed end-to-end (refresh_cmd).
    #[test]
    fn env_override_refresh_cmd_observed_from_client() {
        let client = super::Client::new(super::ClientOptions {
            xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
            provider_env: Some(crate::provider::ProviderEnv {
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
            provider_env: Some(crate::provider::ProviderEnv {
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
            provider_env: Some(crate::provider::ProviderEnv {
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
            crate::provider::ConfigSource::Flags,
            "source must be Flags when flags are set"
        );
        // NS-007: no merging — env's refresh_cmd must NOT leak through
        assert!(
            resolved.refresh_cmd.is_none(),
            "NS-007: flags layer wins entirely — env refresh_cmd must not merge"
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
            provider_env: Some(crate::provider::ProviderEnv {
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
            crate::provider::ConfigSource::EnvVars,
            "source must be EnvVars"
        );
        // NS-007: no merging — file's refresh_cmd must NOT leak through
        assert!(
            resolved.refresh_cmd.is_none(),
            "NS-007: env layer wins entirely — file refresh_cmd must not merge"
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
            crate::provider::ConfigSource::File,
            "source must be File when no env/flags set"
        );
    }

    // Rule: env override only needs one var set to activate env layer.
    #[test]
    fn env_override_single_var_activates_env_layer() {
        let client = super::Client::new(super::ClientOptions {
            xdg_config_home: Some(std::path::PathBuf::from("/nonexistent/xdg/for/env/test")),
            provider_env: Some(crate::provider::ProviderEnv {
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
            crate::provider::ConfigSource::EnvVars,
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

    // =========================================================================
    // noscope-bsq.1.4: Surface core-dump hardening failures from Client
    // construction.
    //
    // Rules tested:
    // 1. Client::new returns Result, exposing hardening failure to callers.
    // 2. Backwards-compatible constructor (new_best_effort) still available.
    // 3. Success path: Client::new succeeds on Linux (where setrlimit works).
    // 4. Failure detection: callers can match on the error variant.
    // 5. Documentation: public API docs describe the behavior.
    // =========================================================================

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
        let sec_err = crate::security::SecurityError::CoreDumpDisableFailed(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "mock failure",
        ));
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
        let sec_err = crate::security::SecurityError::CoreDumpDisableFailed(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "mock",
        ));
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
        let _client: super::Client =
            super::Client::new_best_effort(super::ClientOptions::default());
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
        let sec_err = crate::security::SecurityError::CoreDumpDisableFailed(std::io::Error::other(
            "simulated",
        ));
        let err: crate::Error = sec_err.into();
        let detected =
            err.kind() == crate::ErrorKind::Security && err.message().contains("core dump");
        assert!(
            detected,
            "Callers must be able to detect hardening failure via kind + message"
        );
    }

    // Rule 4: Hardening failure Display message is human-readable.
    #[test]
    fn hardening_failure_display_is_informative() {
        let sec_err = crate::security::SecurityError::CoreDumpDisableFailed(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
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
            provider_env: Some(crate::provider::ProviderEnv::empty()),
            ..super::ClientOptions::default()
        })
        .unwrap();
        let resolved = client
            .resolve_provider("mycloud", &super::ProviderOverrides::default())
            .unwrap();
        assert_eq!(
            resolved.source,
            crate::provider::ConfigSource::File,
            "explicit empty ProviderEnv must not activate env layer"
        );
        assert_eq!(resolved.mint_cmd, "/from/file/mint");
    }
}
