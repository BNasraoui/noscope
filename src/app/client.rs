// High-level facade: provider resolution, mint validation, terminal
// detection, and dry-run behind one entry point. Disables core dumps
// at construction.

use std::path::PathBuf;
use std::time::Duration;

use crate::core::error::Error;
use crate::core::mint;
use crate::ports::provider;
use crate::ports::provider_exec;
use crate::ports::security;

/// Configuration for the noscope [`Client`].
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
    /// If true, allow mint output to a terminal (overrides check).
    pub force_terminal: bool,
    /// If true, include provider stderr on success.
    pub verbose: bool,
    /// Override the NOSCOPE_* env var layer for provider resolution.
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

/// High-level facade for noscope operations.
/// Wraps provider resolution, mint validation, revoke validation, terminal
/// detection, and dry-run into a single entry point. The `Client` calls
/// `security::disable_core_dumps()` at construction time.
/// Not Clone — holds configuration state that should not be duplicated
/// carelessly.
pub struct Client {
    opts: ClientOptions,
}

impl Client {
    /// Create a new Client with the given options.
    /// Disables core dumps immediately. Returns an error if the
    /// platform does not support core dump suppression, allowing callers
    /// to detect and handle hardening failures (e.g., log a warning,
    /// abort the process, or proceed with degraded security).
    /// For callers that prefer the old best-effort behavior, use
    /// [`Client::new_best_effort`] instead.
    /// # Errors
    /// Returns [`Error`] with [`ErrorKind::Security`] if
    /// `setrlimit(RLIMIT_CORE, 0)` fails (e.g., insufficient privileges).
    pub fn new(opts: ClientOptions) -> Result<Self, Error> {
        // Fail-fast core dump prevention.
        security::disable_core_dumps()?;
        Ok(Self { opts })
    }

    /// Create a new Client with best-effort core dump hardening.
    /// Attempts to disable core dumps but silently ignores
    /// failures. This preserves the original `Client::new` behavior
    /// for callers that cannot handle a fallible constructor.
    /// **Prefer [`Client::new`]** in new code — it surfaces hardening
    /// failures so callers can make an informed decision.
    pub fn new_best_effort(opts: ClientOptions) -> Self {
        let _ = security::disable_core_dumps();
        Self { opts }
    }

    /// Validate a mint request before execution.
    /// Checks: providers non-empty, role non-empty and safe,
    /// TTL > 0.
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

        // Validate role for safe characters.
        provider_exec::validate_role(&req.role).map_err(|e| Error::usage(&format!("{}", e)))?;

        Ok(())
    }

    /// Check that stdout is not a terminal before mint output.
    /// Respects `force_terminal` from [`ClientOptions`].
    pub fn check_stdout_not_terminal(&self, is_tty: bool) -> Result<(), Error> {
        mint::check_stdout_not_terminal(is_tty, self.opts.force_terminal)?;
        Ok(())
    }

    /// Resolve a provider configuration by name, with optional overrides.
    /// Delegates to the provider module's strict precedence resolution
    ///. The consumer does not need to import `provider::*` types.
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
            (Some(xdg), _) => provider::provider_config_path(name, Some(xdg))?,
            (None, Some(home)) => provider::provider_config_path_with_home(name, None, home)?,
            (None, None) => provider::provider_config_path(name, None)?,
        };
        let file_config = provider::load_provider_file(&config_path)?;

        let env = match &self.opts.provider_env {
            Some(env) => env.clone(),
            None => provider::provider_env_from_process(),
        };

        Ok(provider::resolve_provider_config_at(
            name,
            &flags,
            &env,
            file_config,
            &config_path,
        )?)
    }

    /// Generate dry-run output for a resolved provider.
    pub fn dry_run(
        &self,
        resolved: &provider::ResolvedProvider,
        role: &str,
        ttl_secs: u64,
    ) -> String {
        provider::dry_run_output(resolved, role, ttl_secs)
    }
}

/// Input for a mint operation.
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

/// CLI flag / env var overrides for provider configuration.
/// Maps to the highest-precedence layers in config resolution.
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

#[cfg(test)]
mod tests;
