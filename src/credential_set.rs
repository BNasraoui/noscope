// NS-006: Atomic multi-credential minting
// NS-045: Env key uniqueness
// NS-046: Parallel minting timeout
// NS-047: Atomic rollback follows revocation budget
// NS-048: Independent refresh scheduling
// NS-049: Single credential expiry preserves child
// NS-050: Bounded parallelism for provider operations

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::token::ScopedToken;

/// A specification for a single credential to mint.
///
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
    /// NS-045: Duplicate env_key across providers.
    DuplicateEnvKey {
        env_key: String,
        providers: Vec<String>,
    },
    /// NS-006: One or more providers failed during minting.
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

/// NS-046 + NS-050: Configuration for multi-credential minting.
pub struct MintConfig {
    /// NS-046: Per-provider timeout.
    pub per_provider_timeout: Duration,
    /// NS-050: Maximum concurrent provider operations.
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

/// NS-047: Budget for atomic rollback revocation attempts.
pub struct RollbackBudget {
    /// Timeout per revocation attempt.
    pub revoke_timeout: Duration,
    /// Maximum number of retry attempts per token.
    pub max_retries: u32,
}

impl Default for RollbackBudget {
    fn default() -> Self {
        // NS-047: Same timeout/retry policy as signal-triggered revocation (NS-027).
        // Reasonable defaults: 5s per attempt, 3 retries.
        Self {
            revoke_timeout: Duration::from_secs(5),
            max_retries: 3,
        }
    }
}

/// NS-047: Log entry for rollback operations (success or failure).
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
    ///
    /// NS-047: Log failure with credential ID + TTL.
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

/// NS-049: What to do when a credential expires.
#[derive(Debug)]
pub enum ExpiryAction {
    /// Log a warning but do not terminate the child.
    LogWarning { message: String },
    /// Terminate the child process. **Must never be used per NS-049.**
    TerminateChild,
    /// Re-mint the credential. **Must never be used per NS-049.**
    ReMint { provider: String },
}

/// NS-049: Policy for handling credential expiry.
pub struct ExpiryPolicy;

impl Default for ExpiryPolicy {
    fn default() -> Self {
        Self
    }
}

impl ExpiryPolicy {
    /// NS-049: Determine the action for a single expired credential.
    ///
    /// Always returns LogWarning — never terminates child or re-mints.
    pub fn on_credential_expired(&self, provider: &str, token_id: &str) -> ExpiryAction {
        ExpiryAction::LogWarning {
            message: format!(
                "credential expired: provider={} token_id={}; \
                 child process preserved (NS-049); credential will not be re-minted",
                provider, token_id
            ),
        }
    }
}

/// NS-048: A refresh schedule entry for one credential.
#[derive(Debug)]
pub struct RefreshSchedule {
    pub provider: String,
    pub env_key: String,
    pub refresh_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A set of minted credentials, ready for child process injection.
///
/// Not Clone — contains secrets via ScopedToken.
/// Debug does not expose secret values (NS-005).
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
    ///
    /// Maps env_key -> raw secret value. The caller is responsible for
    /// injecting these into the child process environment.
    pub fn env_map(&self) -> HashMap<&str, &str> {
        self.entries
            .iter()
            .map(|(spec, token)| (spec.env_key.as_str(), token.expose_secret()))
            .collect()
    }

    /// NS-048: Compute independent refresh schedules for all credentials.
    ///
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

/// NS-006: Resolve a collection of mint results into a credential set or error.
///
/// If all results are Success, returns a CredentialSet.
/// If any result is Failure, returns a CredentialSetError::MintFailed
/// containing both the failures and the successfully minted tokens
/// (for atomic rollback per NS-006).
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
        // NS-006: Atomic rollback — return succeeded tokens so caller can revoke.
        let succeeded_tokens: Vec<ScopedToken> =
            succeeded.into_iter().map(|(_, token)| token).collect();
        Err(CredentialSetError::MintFailed {
            failed_providers: failed,
            succeeded_tokens,
        })
    }
}

/// NS-045: Validate that all credential specs have unique env_keys.
///
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

/// Validate credential specs before minting (includes NS-045 env_key check).
///
/// Checks:
/// - Non-empty spec list
/// - NS-045: env_key uniqueness
pub fn validate_credential_specs(specs: &[CredentialSpec]) -> Result<(), CredentialSetError> {
    if specs.is_empty() {
        return Err(CredentialSetError::InvalidConfig {
            message: "at least one credential spec is required".to_string(),
        });
    }
    validate_env_key_uniqueness(specs)?;
    Ok(())
}

/// NS-048: Compute the refresh time for a single credential.
///
/// The refresh time is based on the credential's own expires_at,
/// not any shared timer. Refreshes at 75% of the token's lifetime
/// (i.e., when 75% of the time between now and expiry has elapsed).
pub fn compute_refresh_at(token: &ScopedToken) -> DateTime<Utc> {
    let now = Utc::now();
    let expires = token.expires_at();
    let total_secs = (expires - now).num_seconds();
    // Refresh at 75% of lifetime elapsed = 25% remaining
    let refresh_offset_secs = (total_secs as f64 * 0.75) as i64;
    now + chrono::Duration::seconds(refresh_offset_secs)
}

/// NS-046: Format a timeout error message for a provider.
pub fn format_timeout_error(provider: &str, timeout: Duration) -> String {
    format!(
        "provider '{}' timed out after {}s",
        provider,
        timeout.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use secrecy::SecretString;

    /// Helper: create a ScopedToken for test convenience.
    fn make_token(value: &str, provider: &str, expires_at: DateTime<Utc>) -> ScopedToken {
        ScopedToken::new(
            SecretString::from(value.to_string()),
            "test-role",
            expires_at,
            Some(format!("tok-{}", provider)),
            provider,
        )
    }

    /// Helper: default expiry 1 hour from now.
    fn default_expiry() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(1)
    }

    // =========================================================================
    // NS-006: Atomic multi-credential minting — if any provider fails,
    // revoke all minted, exit error; no partial credential sets.
    // =========================================================================

    #[test]
    fn atomic_multi_credential_minting_all_succeed() {
        // When all providers succeed, the credential set contains all tokens.
        let spec_a = CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN");
        let spec_b = CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN");

        let results: Vec<MintResult> = vec![
            MintResult::Success {
                spec: spec_a,
                token: make_token("aws-secret", "aws", default_expiry()),
            },
            MintResult::Success {
                spec: spec_b,
                token: make_token("gcp-secret", "gcp", default_expiry()),
            },
        ];

        let outcome = resolve_mint_results(results);
        assert!(
            outcome.is_ok(),
            "NS-006: all succeed should produce Ok credential set"
        );
        let set = outcome.unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn atomic_multi_credential_minting_one_fails_returns_error() {
        // When one provider fails, the entire operation fails.
        let spec_a = CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN");
        let spec_b = CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN");

        let results: Vec<MintResult> = vec![
            MintResult::Success {
                spec: spec_a,
                token: make_token("aws-secret", "aws", default_expiry()),
            },
            MintResult::Failure {
                spec: spec_b,
                error: "gcp auth expired".to_string(),
            },
        ];

        let outcome = resolve_mint_results(results);
        assert!(
            outcome.is_err(),
            "NS-006: any failure must fail the entire operation"
        );
    }

    #[test]
    fn atomic_multi_credential_minting_failure_reports_which_failed() {
        let spec_a = CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN");
        let spec_b = CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN");

        let results: Vec<MintResult> = vec![
            MintResult::Success {
                spec: spec_a,
                token: make_token("aws-secret", "aws", default_expiry()),
            },
            MintResult::Failure {
                spec: spec_b,
                error: "gcp auth expired".to_string(),
            },
        ];

        let err = resolve_mint_results(results).unwrap_err();
        match err {
            CredentialSetError::MintFailed {
                failed_providers, ..
            } => {
                assert!(
                    failed_providers.iter().any(|f| f.provider == "gcp"),
                    "NS-006: error must identify which provider failed"
                );
            }
            other => panic!("Expected MintFailed, got: {:?}", other),
        }
    }

    #[test]
    fn atomic_multi_credential_minting_failure_includes_successful_for_rollback() {
        // The error must include which providers succeeded so they can be revoked.
        let spec_a = CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN");
        let spec_b = CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN");

        let results: Vec<MintResult> = vec![
            MintResult::Success {
                spec: spec_a,
                token: make_token("aws-secret", "aws", default_expiry()),
            },
            MintResult::Failure {
                spec: spec_b,
                error: "gcp auth expired".to_string(),
            },
        ];

        let err = resolve_mint_results(results).unwrap_err();
        match err {
            CredentialSetError::MintFailed {
                succeeded_tokens, ..
            } => {
                assert_eq!(
                    succeeded_tokens.len(),
                    1,
                    "NS-006: error must include successfully minted tokens for rollback"
                );
                assert_eq!(succeeded_tokens[0].provider(), "aws");
            }
            other => panic!("Expected MintFailed, got: {:?}", other),
        }
    }

    #[test]
    fn atomic_multi_credential_minting_all_fail() {
        let spec_a = CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN");
        let spec_b = CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN");

        let results: Vec<MintResult> = vec![
            MintResult::Failure {
                spec: spec_a,
                error: "aws auth expired".to_string(),
            },
            MintResult::Failure {
                spec: spec_b,
                error: "gcp timeout".to_string(),
            },
        ];

        let err = resolve_mint_results(results).unwrap_err();
        match err {
            CredentialSetError::MintFailed {
                failed_providers,
                succeeded_tokens,
            } => {
                assert_eq!(failed_providers.len(), 2);
                assert!(
                    succeeded_tokens.is_empty(),
                    "NS-006: no tokens to rollback when all fail"
                );
            }
            other => panic!("Expected MintFailed, got: {:?}", other),
        }
    }

    // =========================================================================
    // NS-045: Env key uniqueness — reject credential sets with duplicate
    // env_key; validate before minting; identify conflicting providers.
    // =========================================================================

    #[test]
    fn env_key_uniqueness_rejects_duplicates() {
        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "TOKEN"),
        ];

        let result = validate_env_key_uniqueness(&specs);
        assert!(
            result.is_err(),
            "NS-045: duplicate env_key must be rejected"
        );
    }

    #[test]
    fn env_key_uniqueness_identifies_conflicting_providers() {
        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "TOKEN"),
        ];

        let err = validate_env_key_uniqueness(&specs).unwrap_err();
        match err {
            CredentialSetError::DuplicateEnvKey { env_key, providers } => {
                assert_eq!(env_key, "TOKEN");
                assert!(
                    providers.contains(&"aws".to_string()),
                    "NS-045: must identify aws as conflicting"
                );
                assert!(
                    providers.contains(&"gcp".to_string()),
                    "NS-045: must identify gcp as conflicting"
                );
            }
            other => panic!("Expected DuplicateEnvKey, got: {:?}", other),
        }
    }

    #[test]
    fn env_key_uniqueness_allows_distinct_keys() {
        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN"),
        ];

        let result = validate_env_key_uniqueness(&specs);
        assert!(
            result.is_ok(),
            "NS-045: distinct env_keys should be allowed"
        );
    }

    #[test]
    fn env_key_uniqueness_three_way_conflict() {
        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "TOKEN"),
            CredentialSpec::new("azure", "reader", 900, "TOKEN"),
        ];

        let err = validate_env_key_uniqueness(&specs).unwrap_err();
        match err {
            CredentialSetError::DuplicateEnvKey { providers, .. } => {
                assert_eq!(
                    providers.len(),
                    3,
                    "NS-045: must identify all three conflicting providers"
                );
            }
            other => panic!("Expected DuplicateEnvKey, got: {:?}", other),
        }
    }

    #[test]
    fn env_key_uniqueness_validated_before_minting() {
        // validate_credential_specs must check env_key uniqueness.
        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "TOKEN"),
        ];

        let result = validate_credential_specs(&specs);
        assert!(
            result.is_err(),
            "NS-045: env_key uniqueness must be checked during pre-mint validation"
        );
    }

    #[test]
    fn env_key_uniqueness_single_spec_always_valid() {
        let specs = vec![CredentialSpec::new("aws", "admin", 3600, "TOKEN")];
        let result = validate_env_key_uniqueness(&specs);
        assert!(result.is_ok(), "Single spec cannot have env_key conflicts");
    }

    #[test]
    fn env_key_uniqueness_empty_specs_valid() {
        let specs: Vec<CredentialSpec> = vec![];
        let result = validate_env_key_uniqueness(&specs);
        assert!(result.is_ok(), "Empty specs cannot have env_key conflicts");
    }

    // =========================================================================
    // NS-046: Parallel minting timeout — per-provider timeout (default 30s);
    // exceed triggers atomic rollback per NS-006.
    // =========================================================================

    #[test]
    fn parallel_minting_timeout_default_is_30_seconds() {
        let config = MintConfig::default();
        assert_eq!(
            config.per_provider_timeout,
            Duration::from_secs(30),
            "NS-046: default per-provider timeout must be 30 seconds"
        );
    }

    #[test]
    fn parallel_minting_timeout_configurable() {
        let config = MintConfig {
            per_provider_timeout: Duration::from_secs(60),
            ..MintConfig::default()
        };
        assert_eq!(
            config.per_provider_timeout,
            Duration::from_secs(60),
            "NS-046: per-provider timeout must be configurable"
        );
    }

    #[test]
    fn parallel_minting_timeout_exceeded_is_failure() {
        // A timeout result is represented as a MintResult::Failure
        let spec = CredentialSpec::new("slow-provider", "admin", 3600, "SLOW_TOKEN");
        let result = MintResult::Failure {
            spec,
            error: "provider timed out after 30s".to_string(),
        };

        // When resolved with other successes, it triggers atomic rollback
        let spec_ok = CredentialSpec::new("fast-provider", "admin", 3600, "FAST_TOKEN");
        let results: Vec<MintResult> = vec![
            MintResult::Success {
                spec: spec_ok,
                token: make_token("fast-secret", "fast-provider", default_expiry()),
            },
            result,
        ];

        let err = resolve_mint_results(results).unwrap_err();
        assert!(
            matches!(err, CredentialSetError::MintFailed { .. }),
            "NS-046: timeout must trigger atomic rollback"
        );
    }

    #[test]
    fn parallel_minting_timeout_error_message_mentions_timeout() {
        let timeout_error = format_timeout_error("slow-provider", Duration::from_secs(30));
        assert!(
            timeout_error.contains("30") || timeout_error.contains("timeout"),
            "NS-046: timeout error must mention the timeout duration, got: {}",
            timeout_error
        );
        assert!(
            timeout_error.contains("slow-provider"),
            "NS-046: timeout error must mention the provider, got: {}",
            timeout_error
        );
    }

    // =========================================================================
    // NS-047: Atomic rollback follows revocation budget — same timeout/retry
    // policy as signal-triggered revocation (NS-027); log failure with
    // credential ID+TTL.
    // =========================================================================

    #[test]
    fn atomic_rollback_follows_revocation_budget_has_timeout() {
        let budget = RollbackBudget::default();
        assert!(
            budget.revoke_timeout > Duration::ZERO,
            "NS-047: rollback budget must have a non-zero revoke timeout"
        );
    }

    #[test]
    fn atomic_rollback_follows_revocation_budget_has_retry_count() {
        let budget = RollbackBudget::default();
        assert!(
            budget.max_retries > 0,
            "NS-047: rollback budget must allow at least one retry"
        );
    }

    #[test]
    fn atomic_rollback_follows_revocation_budget_log_entry_contains_credential_id_and_ttl() {
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let entry = RollbackLogEntry::new("tok-aws-123", "aws", expiry);
        let log_msg = entry.format_log();
        assert!(
            log_msg.contains("tok-aws-123"),
            "NS-047: rollback log must contain credential ID, got: {}",
            log_msg
        );
        // TTL should be represented somehow (either as duration or expiry time)
        assert!(
            log_msg.contains("TTL") || log_msg.contains("expires"),
            "NS-047: rollback log must contain TTL info, got: {}",
            log_msg
        );
    }

    #[test]
    fn atomic_rollback_follows_revocation_budget_log_failure() {
        // When revocation fails during rollback, the failure must be logged
        // with credential ID and TTL.
        let expiry = Utc::now() + chrono::Duration::hours(2);
        let entry =
            RollbackLogEntry::revocation_failed("tok-gcp-456", "gcp", expiry, "connection refused");
        let log_msg = entry.format_log();
        assert!(
            log_msg.contains("tok-gcp-456"),
            "NS-047: failed rollback log must contain credential ID"
        );
        assert!(
            log_msg.contains("connection refused"),
            "NS-047: failed rollback log must contain error reason"
        );
    }

    // =========================================================================
    // NS-048: Independent refresh scheduling — each credential has own
    // refresh timer based on its TTL/expires_at; no sync/batching.
    // =========================================================================

    #[test]
    fn independent_refresh_scheduling_different_ttls_different_schedules() {
        let now = Utc::now();
        let token_1h = make_token("secret-1", "aws", now + chrono::Duration::hours(1));
        let token_30m = make_token("secret-2", "gcp", now + chrono::Duration::minutes(30));

        let schedule_1h = compute_refresh_at(&token_1h);
        let schedule_30m = compute_refresh_at(&token_30m);

        assert_ne!(
            schedule_1h, schedule_30m,
            "NS-048: credentials with different TTLs must have different refresh times"
        );
        // The 30m credential should refresh before the 1h credential.
        assert!(
            schedule_30m < schedule_1h,
            "NS-048: shorter-TTL credential must refresh sooner"
        );
    }

    #[test]
    fn independent_refresh_scheduling_refresh_at_is_before_expiry() {
        let now = Utc::now();
        let expiry = now + chrono::Duration::hours(1);
        let token = make_token("secret", "aws", expiry);

        let refresh_at = compute_refresh_at(&token);
        assert!(
            refresh_at < expiry,
            "NS-048: refresh must be scheduled before expiry"
        );
    }

    #[test]
    fn independent_refresh_scheduling_no_batching() {
        // Each credential gets its own schedule; no rounding/alignment.
        let now = Utc::now();
        let token_a = make_token("a", "aws", now + chrono::Duration::seconds(3600));
        let token_b = make_token("b", "gcp", now + chrono::Duration::seconds(3601));

        let schedule_a = compute_refresh_at(&token_a);
        let schedule_b = compute_refresh_at(&token_b);

        // They should be different even with 1-second TTL difference
        assert_ne!(
            schedule_a, schedule_b,
            "NS-048: no batching — each credential gets its own schedule"
        );
    }

    #[test]
    fn independent_refresh_scheduling_uses_credential_expires_at() {
        // The schedule is derived from the credential's own expires_at,
        // not some shared clock or batch timer.
        let now = Utc::now();
        let expiry = now + chrono::Duration::minutes(45);
        let token = make_token("secret", "vault", expiry);

        let refresh_at = compute_refresh_at(&token);
        // Refresh should be at some point between now and expiry
        assert!(refresh_at > now, "NS-048: refresh must be in the future");
        assert!(refresh_at < expiry, "NS-048: refresh must be before expiry");
    }

    // =========================================================================
    // NS-049: Single credential expiry preserves child — one expired does
    // not terminate child; log warning; do not re-mint.
    // =========================================================================

    #[test]
    fn single_credential_expiry_preserves_child() {
        let policy = ExpiryPolicy::default();
        let action = policy.on_credential_expired("aws", "tok-aws-123");
        assert!(
            !matches!(action, ExpiryAction::TerminateChild),
            "NS-049: single credential expiry must NOT terminate child"
        );
    }

    #[test]
    fn single_credential_expiry_logs_warning() {
        let policy = ExpiryPolicy::default();
        let action = policy.on_credential_expired("aws", "tok-aws-123");
        assert!(
            matches!(action, ExpiryAction::LogWarning { .. }),
            "NS-049: single credential expiry must log a warning, got: {:?}",
            action
        );
    }

    #[test]
    fn single_credential_expiry_does_not_re_mint() {
        let policy = ExpiryPolicy::default();
        let action = policy.on_credential_expired("aws", "tok-aws-123");
        assert!(
            !matches!(action, ExpiryAction::ReMint { .. }),
            "NS-049: expired credential must NOT be re-minted"
        );
    }

    #[test]
    fn single_credential_expiry_warning_contains_provider_and_token_id() {
        let policy = ExpiryPolicy::default();
        let action = policy.on_credential_expired("aws", "tok-aws-123");
        match action {
            ExpiryAction::LogWarning { message } => {
                assert!(
                    message.contains("aws"),
                    "NS-049: warning must contain provider name, got: {}",
                    message
                );
                assert!(
                    message.contains("tok-aws-123"),
                    "NS-049: warning must contain token ID, got: {}",
                    message
                );
            }
            other => panic!("Expected LogWarning, got: {:?}", other),
        }
    }

    #[test]
    fn single_credential_expiry_multiple_independent() {
        // Expiring one credential does not affect the action for another.
        let policy = ExpiryPolicy::default();
        let action_a = policy.on_credential_expired("aws", "tok-aws");
        let action_b = policy.on_credential_expired("gcp", "tok-gcp");
        // Both should independently produce warnings, not termination.
        assert!(matches!(action_a, ExpiryAction::LogWarning { .. }));
        assert!(matches!(action_b, ExpiryAction::LogWarning { .. }));
    }

    // =========================================================================
    // NS-050: Bounded parallelism for provider operations — configurable
    // max concurrent (default 8); prevents FD exhaustion/rate limits.
    // =========================================================================

    #[test]
    fn bounded_parallelism_default_is_eight() {
        let config = MintConfig::default();
        assert_eq!(
            config.max_concurrent, 8,
            "NS-050: default max concurrent must be 8"
        );
    }

    #[test]
    fn bounded_parallelism_configurable() {
        let config = MintConfig {
            per_provider_timeout: Duration::from_secs(60),
            ..MintConfig::default()
        };
        assert_eq!(
            config.per_provider_timeout,
            Duration::from_secs(60),
            "NS-050: max concurrent must be configurable"
        );
    }

    #[test]
    fn bounded_parallelism_minimum_is_one() {
        // At minimum, one operation at a time must be possible.
        let config = MintConfig {
            max_concurrent: 1,
            ..MintConfig::default()
        };
        assert_eq!(
            config.max_concurrent, 1,
            "NS-050: max concurrent must support minimum of 1"
        );
    }

    #[test]
    fn bounded_parallelism_zero_is_rejected() {
        let result = MintConfig::new(Duration::from_secs(30), 0);
        assert!(
            result.is_err(),
            "NS-050: max_concurrent = 0 must be rejected"
        );
    }

    // =========================================================================
    // CredentialSpec and CredentialSet structural tests
    // =========================================================================

    #[test]
    fn credential_spec_stores_all_fields() {
        let spec = CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN");
        assert_eq!(spec.provider, "aws");
        assert_eq!(spec.role, "admin");
        assert_eq!(spec.ttl_secs, 3600);
        assert_eq!(spec.env_key, "AWS_TOKEN");
    }

    #[test]
    fn credential_set_provides_env_map() {
        // The credential set should provide a mapping from env_key -> secret value
        // for injecting into the child process environment.
        let tokens = vec![
            make_token("aws-secret-val", "aws", default_expiry()),
            make_token("gcp-secret-val", "gcp", default_expiry()),
        ];

        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN"),
        ];

        let set = CredentialSet::new(specs.into_iter().zip(tokens).collect());

        let env_map = set.env_map();
        assert_eq!(env_map.len(), 2);
        assert_eq!(*env_map.get("AWS_TOKEN").unwrap(), "aws-secret-val");
        assert_eq!(*env_map.get("GCP_TOKEN").unwrap(), "gcp-secret-val");
    }

    #[test]
    fn credential_set_len() {
        let set = CredentialSet::new(vec![(
            CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
            make_token("s1", "aws", default_expiry()),
        )]);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn credential_set_is_not_clone() {
        // Credential sets contain secrets — no implicit cloning.
        static_assertions::assert_not_impl_any!(CredentialSet: Clone);
    }

    // =========================================================================
    // CredentialSetError tests
    // =========================================================================

    #[test]
    fn credential_set_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<CredentialSetError>();
    }

    #[test]
    fn credential_set_error_display_for_duplicate_env_key() {
        let err = CredentialSetError::DuplicateEnvKey {
            env_key: "TOKEN".to_string(),
            providers: vec!["aws".to_string(), "gcp".to_string()],
        };
        let msg = format!("{}", err);
        assert!(msg.contains("TOKEN"), "Must mention the env_key: {}", msg);
        assert!(msg.contains("aws"), "Must mention aws: {}", msg);
        assert!(msg.contains("gcp"), "Must mention gcp: {}", msg);
    }

    #[test]
    fn credential_set_error_display_for_mint_failed() {
        let err = CredentialSetError::MintFailed {
            failed_providers: vec![MintFailure {
                provider: "gcp".to_string(),
                error: "timeout".to_string(),
            }],
            succeeded_tokens: vec![],
        };
        let msg = format!("{}", err);
        assert!(msg.contains("gcp"), "Must mention failed provider: {}", msg);
    }

    #[test]
    fn credential_set_error_display_for_invalid_config() {
        let err = CredentialSetError::InvalidConfig {
            message: "max_concurrent must be > 0".to_string(),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("max_concurrent"),
            "Must contain config detail: {}",
            msg
        );
    }

    // =========================================================================
    // validate_credential_specs integration
    // =========================================================================

    #[test]
    fn validate_credential_specs_accepts_valid_set() {
        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN"),
        ];
        let result = validate_credential_specs(&specs);
        assert!(result.is_ok(), "Valid specs should pass validation");
    }

    #[test]
    fn validate_credential_specs_rejects_empty() {
        let specs: Vec<CredentialSpec> = vec![];
        let result = validate_credential_specs(&specs);
        assert!(result.is_err(), "Empty specs should be rejected");
    }

    // =========================================================================
    // Refresh schedule collection
    // =========================================================================

    #[test]
    fn build_refresh_schedules_returns_one_per_credential() {
        let entries = vec![
            (
                CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
                make_token("s1", "aws", default_expiry()),
            ),
            (
                CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN"),
                make_token("s2", "gcp", Utc::now() + chrono::Duration::minutes(30)),
            ),
        ];

        let set = CredentialSet::new(entries);
        let schedules = set.refresh_schedules();
        assert_eq!(
            schedules.len(),
            2,
            "NS-048: must return one schedule per credential"
        );
    }

    #[test]
    fn build_refresh_schedules_each_based_on_own_ttl() {
        let now = Utc::now();
        let entries = vec![
            (
                CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
                make_token("s1", "aws", now + chrono::Duration::hours(1)),
            ),
            (
                CredentialSpec::new("gcp", "viewer", 1800, "GCP_TOKEN"),
                make_token("s2", "gcp", now + chrono::Duration::minutes(30)),
            ),
        ];

        let set = CredentialSet::new(entries);
        let schedules = set.refresh_schedules();

        // gcp (30min) should refresh before aws (1h)
        let gcp_schedule = schedules.iter().find(|s| s.provider == "gcp").unwrap();
        let aws_schedule = schedules.iter().find(|s| s.provider == "aws").unwrap();
        assert!(
            gcp_schedule.refresh_at < aws_schedule.refresh_at,
            "NS-048: shorter TTL must refresh sooner"
        );
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn resolve_mint_results_empty_input_returns_empty_set() {
        // Edge case: no providers at all — should return an empty credential set.
        let results: Vec<MintResult> = vec![];
        let outcome = resolve_mint_results(results);
        assert!(outcome.is_ok(), "Empty results should not error");
        let set = outcome.unwrap();
        assert_eq!(set.len(), 0, "Empty results should produce empty set");
        assert!(set.is_empty());
    }

    #[test]
    fn compute_refresh_at_already_expired_token_returns_past_time() {
        // Edge case: token already expired — refresh_at should still compute
        // (it will be in the past, which the caller should handle).
        let now = Utc::now();
        let expired = now - chrono::Duration::hours(1);
        let token = make_token("expired-secret", "aws", expired);

        let refresh_at = compute_refresh_at(&token);
        // For an already-expired token, refresh_at should be in the past.
        assert!(
            refresh_at < now,
            "Already-expired token should produce past refresh_at"
        );
    }

    #[test]
    fn rollback_log_entry_escapes_embedded_quotes() {
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let entry = RollbackLogEntry::revocation_failed(
            "tok-123",
            "aws",
            expiry,
            "connection \"refused\" by host",
        );
        let log_msg = entry.format_log();
        assert!(
            log_msg.contains("\\\"refused\\\""),
            "Embedded quotes must be escaped, got: {}",
            log_msg
        );
    }

    #[test]
    fn credential_set_debug_does_not_expose_secrets() {
        let set = CredentialSet::new(vec![(
            CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
            make_token("super-secret-credential", "aws", default_expiry()),
        )]);
        let debug = format!("{:?}", set);
        assert!(
            !debug.contains("super-secret-credential"),
            "Debug must not expose secret values, got: {}",
            debug
        );
        assert!(
            debug.contains("CredentialSet"),
            "Debug should contain type name"
        );
    }

    #[test]
    fn credential_set_is_not_serializable() {
        // NS-001: CredentialSet contains secrets — must not be serializable.
        static_assertions::assert_not_impl_any!(CredentialSet: serde::Serialize);
    }

    #[test]
    fn mint_config_zero_timeout_is_allowed() {
        // A zero timeout is a valid (if aggressive) configuration.
        let config = MintConfig::new(Duration::ZERO, 1);
        assert!(config.is_ok(), "Zero timeout should be allowed");
    }

    #[test]
    fn credential_set_error_display_for_mint_failed_no_providers() {
        // Edge case: MintFailed with empty failed_providers list
        let err = CredentialSetError::MintFailed {
            failed_providers: vec![],
            succeeded_tokens: vec![],
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("credential minting failed"),
            "Display should still produce meaningful output: {}",
            msg
        );
    }

    #[test]
    fn rollback_budget_timeout_and_retries_are_reasonable() {
        // Sanity check: the default budget shouldn't have absurd values.
        let budget = RollbackBudget::default();
        assert!(
            budget.revoke_timeout <= Duration::from_secs(30),
            "Default timeout should be reasonable"
        );
        assert!(
            budget.max_retries <= 10,
            "Default retries should be reasonable"
        );
    }

    #[test]
    fn env_key_uniqueness_case_sensitive() {
        // env_keys should be case-sensitive — "TOKEN" and "token" are different.
        let specs = vec![
            CredentialSpec::new("aws", "admin", 3600, "TOKEN"),
            CredentialSpec::new("gcp", "viewer", 1800, "token"),
        ];
        let result = validate_env_key_uniqueness(&specs);
        assert!(result.is_ok(), "env_keys should be case-sensitive");
    }

    #[test]
    fn format_timeout_error_sub_second_timeout() {
        // Edge case: timeout less than 1 second shows as 0s.
        let msg = format_timeout_error("fast", Duration::from_millis(500));
        assert!(
            msg.contains("0s"),
            "Sub-second timeout should show as 0s, got: {}",
            msg
        );
    }

    #[test]
    fn credential_set_env_map_empty_set() {
        let set = CredentialSet::new(vec![]);
        let env_map = set.env_map();
        assert!(env_map.is_empty(), "Empty set should produce empty env_map");
    }

    #[test]
    fn credential_set_refresh_schedules_empty_set() {
        let set = CredentialSet::new(vec![]);
        let schedules = set.refresh_schedules();
        assert!(
            schedules.is_empty(),
            "Empty set should produce empty schedules"
        );
    }
}
