// Atomic multi-credential minting
// Env key uniqueness
// Parallel minting timeout
// Atomic rollback follows revocation budget
// Independent refresh scheduling
// Single credential expiry preserves child
// Bounded parallelism for provider operations

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::core::token::ScopedToken;
use provenance_macros::rule;

/// A specification for a single credential to mint.
/// Each spec corresponds to one provider invocation. The `env_key` is the
/// environment variable name under which the minted credential will be
/// injected into the child process.
#[derive(Debug)]
pub struct CredentialSpec {
    pub provider: String,
    pub role: String,
    pub ttl_secs: u64,
    pub env_key: String,
}

impl CredentialSpec {
    pub fn new(provider: &str, role: &str, ttl_secs: u64, env_key: &str) -> Self {
        Self {
            provider: provider.to_string(),
            role: role.to_string(),
            ttl_secs,
            env_key: env_key.to_string(),
        }
    }
}

/// The result of a single provider mint operation.
pub enum MintResult {
    Success {
        spec: CredentialSpec,
        token: ScopedToken,
    },
    Failure {
        spec: CredentialSpec,
        error: String,
    },
}

/// A single provider failure record (for error reporting).
#[derive(Debug, Clone)]
pub struct MintFailure {
    pub provider: String,
    pub error: String,
}

/// Error type for credential set operations.
#[derive(Debug)]
pub enum CredentialSetError {
    /// Duplicate env_key across providers.
    DuplicateEnvKey {
        env_key: String,
        providers: Vec<String>,
    },
    /// One or more providers failed during minting.
    /// Contains both the failures and the successfully minted tokens
    /// (which must be revoked for atomic rollback).
    MintFailed {
        failed_providers: Vec<MintFailure>,
        succeeded_tokens: Vec<ScopedToken>,
    },
    /// Invalid configuration (e.g. max_concurrent = 0).
    InvalidConfig { message: String },
}

impl fmt::Display for CredentialSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateEnvKey { env_key, providers } => {
                write!(
                    f,
                    "duplicate env_key '{}' across providers: {}",
                    env_key,
                    providers.join(", ")
                )
            }
            Self::MintFailed {
                failed_providers, ..
            } => {
                write!(f, "credential minting failed: ")?;
                for (i, failure) in failed_providers.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "provider '{}': {}", failure.provider, failure.error)?;
                }
                Ok(())
            }
            Self::InvalidConfig { message } => {
                write!(f, "invalid credential set config: {}", message)
            }
        }
    }
}

impl std::error::Error for CredentialSetError {}

/// Configuration for multi-credential minting.
pub struct MintConfig {
    /// Per-provider timeout.
    pub per_provider_timeout: Duration,
    /// Maximum concurrent provider operations.
    pub max_concurrent: usize,
}

impl Default for MintConfig {
    fn default() -> Self {
        Self {
            per_provider_timeout: Duration::from_secs(30),
            max_concurrent: 8,
        }
    }
}

impl MintConfig {
    /// Create a new MintConfig, rejecting invalid values.
    pub fn new(
        per_provider_timeout: Duration,
        max_concurrent: usize,
    ) -> Result<Self, CredentialSetError> {
        if max_concurrent == 0 {
            return Err(CredentialSetError::InvalidConfig {
                message: "max_concurrent must be > 0".to_string(),
            });
        }
        Ok(Self {
            per_provider_timeout,
            max_concurrent,
        })
    }
}

/// Budget for atomic rollback revocation attempts.
pub struct RollbackBudget {
    /// Timeout per revocation attempt.
    pub revoke_timeout: Duration,
    /// Maximum number of retry attempts per token.
    pub max_retries: u32,
}

impl Default for RollbackBudget {
    fn default() -> Self {
        // Same timeout/retry policy as signal-triggered revocation.
        // Reasonable defaults: 5s per attempt, 3 retries.
        Self {
            revoke_timeout: Duration::from_secs(5),
            max_retries: 3,
        }
    }
}

/// Log entry for rollback operations (success or failure).
pub struct RollbackLogEntry {
    credential_id: String,
    provider: String,
    expires_at: DateTime<Utc>,
    error: Option<String>,
}

impl RollbackLogEntry {
    /// Create a log entry for a successful revocation during rollback.
    pub fn new(credential_id: &str, provider: &str, expires_at: DateTime<Utc>) -> Self {
        Self {
            credential_id: credential_id.to_string(),
            provider: provider.to_string(),
            expires_at,
            error: None,
        }
    }

    /// Create a log entry for a failed revocation during rollback.
    pub fn revocation_failed(
        credential_id: &str,
        provider: &str,
        expires_at: DateTime<Utc>,
        error: &str,
    ) -> Self {
        Self {
            credential_id: credential_id.to_string(),
            provider: provider.to_string(),
            expires_at,
            error: Some(error.to_string()),
        }
    }

    /// Format this entry as a log message.
    /// Log failure with credential ID + TTL.
    pub fn format_log(&self) -> String {
        let base = format!(
            "rollback: provider={} credential_id={} expires={}",
            self.provider,
            self.credential_id,
            self.expires_at.to_rfc3339()
        );
        match &self.error {
            Some(err) => {
                // Escape embedded quotes to keep the log format parseable.
                let escaped = err.replace('\\', "\\\\").replace('"', "\\\"");
                format!("{} error=\"{}\"", base, escaped)
            }
            None => format!("{} status=revoked", base),
        }
    }
}

/// What to do when a credential expires.
#[derive(Debug)]
pub enum ExpiryAction {
    /// Log a warning but do not terminate the child.
    LogWarning { message: String },
    /// Terminate the child process. **Must never be used.**
    TerminateChild,
    /// Re-mint the credential. **Must never be used.**
    ReMint { provider: String },
}

/// Policy for handling credential expiry.
pub struct ExpiryPolicy;

impl Default for ExpiryPolicy {
    fn default() -> Self {
        Self
    }
}

impl ExpiryPolicy {
    /// Determine the action for a single expired credential.
    /// Always returns LogWarning — never terminates child or re-mints.
    #[rule("rule_expiry_log_only")]
    pub fn on_credential_expired(&self, provider: &str, token_id: &str) -> ExpiryAction {
        ExpiryAction::LogWarning {
            message: format!(
                "credential expired: provider={} token_id={}; \
                 child process preserved; credential will not be re-minted",
                provider, token_id
            ),
        }
    }
}

/// A refresh schedule entry for one credential.
#[derive(Debug)]
pub struct RefreshSchedule {
    pub provider: String,
    pub env_key: String,
    pub refresh_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A set of minted credentials, ready for child process injection.
/// Not Clone — contains secrets via ScopedToken.
/// Debug does not expose secret values.
pub struct CredentialSet {
    entries: Vec<(CredentialSpec, ScopedToken)>,
}

impl fmt::Debug for CredentialSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSet")
            .field("len", &self.entries.len())
            .finish()
    }
}

impl CredentialSet {
    /// Create a new credential set from paired specs and tokens.
    pub fn new(entries: Vec<(CredentialSpec, ScopedToken)>) -> Self {
        Self { entries }
    }

    /// Number of credentials in the set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the set contains no credentials.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build an environment variable map for child process injection.
    /// Maps env_key -> raw secret value. The caller is responsible for
    /// injecting these into the child process environment.
    pub fn env_map(&self) -> HashMap<&str, &str> {
        self.entries
            .iter()
            .map(|(spec, token)| (spec.env_key.as_str(), token.expose_secret()))
            .collect()
    }

    /// Iterate over the tokens in this credential set.
    /// Returns references to the `ScopedToken` values only (not the specs).
    /// Used by the orchestrator to convert tokens to mint envelopes for
    /// JSON output.
    pub fn tokens(&self) -> impl Iterator<Item = &ScopedToken> {
        self.entries.iter().map(|(_, token)| token)
    }

    /// Iterate over (spec, token) pairs.
    pub fn entries(&self) -> impl Iterator<Item = (&CredentialSpec, &ScopedToken)> {
        self.entries.iter().map(|(spec, token)| (spec, token))
    }

    /// Compute independent refresh schedules for all credentials.
    /// Each credential gets its own schedule based on its own expires_at.
    /// No batching or synchronization across credentials.
    pub fn refresh_schedules(&self) -> Vec<RefreshSchedule> {
        self.entries
            .iter()
            .map(|(spec, token)| {
                let refresh_at = compute_refresh_at(token);
                RefreshSchedule {
                    provider: spec.provider.clone(),
                    env_key: spec.env_key.clone(),
                    refresh_at,
                    expires_at: token.expires_at(),
                }
            })
            .collect()
    }
}

/// Resolve a collection of mint results into a credential set or error.
/// If all results are Success, returns a CredentialSet.
/// If any result is Failure, returns a CredentialSetError::MintFailed
/// containing both the failures and the successfully minted tokens
/// (for atomic rollback).
pub fn resolve_mint_results(results: Vec<MintResult>) -> Result<CredentialSet, CredentialSetError> {
    let mut succeeded: Vec<(CredentialSpec, ScopedToken)> = Vec::new();
    let mut failed: Vec<MintFailure> = Vec::new();

    for result in results {
        match result {
            MintResult::Success { spec, token } => {
                succeeded.push((spec, token));
            }
            MintResult::Failure { spec, error } => {
                failed.push(MintFailure {
                    provider: spec.provider,
                    error,
                });
            }
        }
    }

    if failed.is_empty() {
        Ok(CredentialSet::new(succeeded))
    } else {
        // Atomic rollback — return succeeded tokens so caller can revoke.
        let succeeded_tokens: Vec<ScopedToken> =
            succeeded.into_iter().map(|(_, token)| token).collect();
        Err(CredentialSetError::MintFailed {
            failed_providers: failed,
            succeeded_tokens,
        })
    }
}

/// Validate that all credential specs have unique env_keys.
/// If a duplicate is found, identifies ALL providers that share the same env_key.
pub fn validate_env_key_uniqueness(specs: &[CredentialSpec]) -> Result<(), CredentialSetError> {
    // Build a map from env_key -> list of providers that use it.
    let mut key_to_providers: HashMap<&str, Vec<&str>> = HashMap::new();
    for spec in specs {
        key_to_providers
            .entry(spec.env_key.as_str())
            .or_default()
            .push(spec.provider.as_str());
    }

    // Find the first env_key with multiple providers.
    for (key, providers) in &key_to_providers {
        if providers.len() > 1 {
            return Err(CredentialSetError::DuplicateEnvKey {
                env_key: (*key).to_string(),
                providers: providers.iter().map(|p| p.to_string()).collect(),
            });
        }
    }

    Ok(())
}

/// Validate credential specs before minting (includes env_key check).
/// Checks:
/// - Non-empty spec list
pub fn validate_credential_specs(specs: &[CredentialSpec]) -> Result<(), CredentialSetError> {
    if specs.is_empty() {
        return Err(CredentialSetError::InvalidConfig {
            message: "at least one credential spec is required".to_string(),
        });
    }
    validate_env_key_uniqueness(specs)?;
    Ok(())
}

/// Compute the refresh time for a single credential.
/// The refresh time is based on the credential's own expires_at,
/// not any shared timer. Refreshes at 75% of the token's lifetime
/// (i.e., when 75% of the time between now and expiry has elapsed).
#[rule("rule_refresh_schedule_75pct")]
pub fn compute_refresh_at(token: &ScopedToken) -> DateTime<Utc> {
    let now = Utc::now();
    let expires = token.expires_at();
    let total_secs = (expires - now).num_seconds();
    // Refresh at 75% of lifetime elapsed = 25% remaining
    let refresh_offset_secs = (total_secs as f64 * 0.75) as i64;
    now + chrono::Duration::seconds(refresh_offset_secs)
}

/// Format a timeout error message for a provider.
#[rule("rule_orchestration_timeout_error_names_provider")]
pub fn format_timeout_error(provider: &str, timeout: Duration) -> String {
    format!(
        "provider '{}' timed out after {}s",
        provider,
        timeout.as_secs()
    )
}

#[cfg(test)]
mod tests;
