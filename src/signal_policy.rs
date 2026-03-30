// NS-003: Revoke on exit guarantee
// NS-011: TTL as safety net
// NS-014: Revocation idempotency
// NS-026: Signal forwarding policy
// NS-027: Revocation timeout and retry budget
// NS-028: Double-signal escalation
// NS-029: Multi-credential revocation on signal
// NS-066: Minimum TTL enforcement
// NS-067: Maximum TTL enforcement

use std::future::Future;
use std::time::{Duration, Instant};

/// NS-066: Minimum allowed TTL in seconds.
pub const MIN_TTL_SECS: u64 = 60;

/// NS-067: Default maximum allowed TTL in seconds (12 hours).
pub const DEFAULT_MAX_TTL_SECS: u64 = 12 * 60 * 60;

/// NS-026: Parent signal values relevant to policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentSignal {
    Sigterm,
    Sighup,
    Sigint,
    Sigpipe,
}

/// NS-003: Why the child process exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExitReason {
    ExitCode(i32),
    Signaled(i32),
}

/// NS-066 + NS-067: TTL bounds used by mint validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlBounds {
    pub minimum_secs: u64,
    pub maximum_secs: u64,
}

impl Default for TtlBounds {
    fn default() -> Self {
        Self {
            minimum_secs: MIN_TTL_SECS,
            maximum_secs: DEFAULT_MAX_TTL_SECS,
        }
    }
}

/// NS-011 + NS-066 + NS-067: TTL validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlError {
    Missing,
    BelowMinimum { minimum: u64, actual: u64 },
    AboveMaximum { maximum: u64, actual: u64 },
}

impl std::fmt::Display for TtlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "--ttl is required"),
            Self::BelowMinimum { minimum, actual } => write!(
                f,
                "--ttl must be at least {} seconds (got {})",
                minimum, actual
            ),
            Self::AboveMaximum { maximum, actual } => write!(
                f,
                "--ttl must be at most {} seconds (got {})",
                maximum, actual
            ),
        }
    }
}

impl std::error::Error for TtlError {}

/// NS-027: Revocation budget (wall clock + retry parameters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationBudget {
    pub wall_clock_budget: Duration,
    pub base_backoff: Duration,
    pub max_retries: u32,
}

impl Default for RevocationBudget {
    fn default() -> Self {
        Self {
            wall_clock_budget: Duration::from_secs(10),
            base_backoff: Duration::from_millis(500),
            max_retries: 3,
        }
    }
}

impl RevocationBudget {
    pub fn disabled() -> Self {
        Self {
            wall_clock_budget: Duration::ZERO,
            ..Self::default()
        }
    }

    pub fn is_disabled(&self) -> bool {
        self.wall_clock_budget.is_zero()
    }

    pub fn backoff_for_retry(&self, retry: u32) -> Duration {
        let factor = 2u32.saturating_pow(retry);
        self.base_backoff.saturating_mul(factor)
    }
}

/// NS-029: Minimal descriptor for a credential that should be revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCredential {
    pub credential_id: String,
    pub provider: String,
}

impl ActiveCredential {
    pub fn new(credential_id: &str, provider: &str) -> Self {
        Self {
            credential_id: credential_id.to_string(),
            provider: provider.to_string(),
        }
    }
}

/// Result classification for a single revocation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationResultKind {
    Revoked,
    AlreadyRevoked,
    Expired,
    Failed(String),
}

impl RevocationResultKind {
    /// NS-014: already-revoked/expired are treated as success.
    pub fn treated_as_success(&self) -> bool {
        matches!(self, Self::Revoked | Self::AlreadyRevoked | Self::Expired)
    }
}

/// NS-029: Per-credential revocation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationResult {
    pub credential_id: String,
    pub provider: String,
    pub kind: RevocationResultKind,
}

/// NS-028: What to do after receiving a shutdown signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownDecision {
    pub started_graceful_shutdown: bool,
    pub immediate_sigkill: bool,
    pub abandon_revocation: bool,
}

/// NS-026 + NS-028: Signal handling policy and shutdown state.
pub struct SignalHandlingPolicy {
    grace_period: Duration,
    shutdown_started: bool,
}

impl Default for SignalHandlingPolicy {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_secs(30),
            shutdown_started: false,
        }
    }
}

impl SignalHandlingPolicy {
    /// NS-003: Attempt revocation on child exit regardless of reason.
    pub fn should_attempt_revoke_on_exit(&self, _reason: ChildExitReason) -> bool {
        true
    }

    /// NS-011 + NS-066 + NS-067: Never allow mint without bounded TTL.
    pub fn validate_ttl(ttl_secs: Option<u64>, bounds: &TtlBounds) -> Result<u64, TtlError> {
        let ttl = ttl_secs.ok_or(TtlError::Missing)?;

        if ttl < bounds.minimum_secs {
            return Err(TtlError::BelowMinimum {
                minimum: bounds.minimum_secs,
                actual: ttl,
            });
        }

        if ttl > bounds.maximum_secs {
            return Err(TtlError::AboveMaximum {
                maximum: bounds.maximum_secs,
                actual: ttl,
            });
        }

        Ok(ttl)
    }

    /// NS-014: Idempotent revocation classification.
    pub fn classify_revocation_result(&self, exit_code: i32, stderr: &str) -> RevocationResultKind {
        if exit_code == 0 {
            return RevocationResultKind::Revoked;
        }

        let lower = stderr.to_ascii_lowercase();
        if lower.contains("already revoked") || lower.contains("already-revoked") {
            return RevocationResultKind::AlreadyRevoked;
        }
        if lower.contains("expired") {
            return RevocationResultKind::Expired;
        }

        RevocationResultKind::Failed(stderr.to_string())
    }

    /// NS-026: Forward TERM/HUP/INT to child process group; ignore PIPE.
    pub fn should_forward_to_child_group(&self, signal: ParentSignal) -> bool {
        matches!(
            signal,
            ParentSignal::Sigterm | ParentSignal::Sighup | ParentSignal::Sigint
        )
    }

    /// NS-026: Configurable grace period before SIGKILL (default 30s).
    pub fn shutdown_grace_period(&self) -> Duration {
        self.grace_period
    }

    /// NS-028: Second TERM/INT during shutdown escalates immediately.
    pub fn on_shutdown_signal(&mut self, signal: ParentSignal) -> ShutdownDecision {
        if matches!(signal, ParentSignal::Sigpipe) {
            return ShutdownDecision {
                started_graceful_shutdown: false,
                immediate_sigkill: false,
                abandon_revocation: false,
            };
        }

        let escalation_signal = matches!(signal, ParentSignal::Sigterm | ParentSignal::Sigint);
        if self.shutdown_started && escalation_signal {
            return ShutdownDecision {
                started_graceful_shutdown: false,
                immediate_sigkill: true,
                abandon_revocation: true,
            };
        }

        self.shutdown_started = true;
        ShutdownDecision {
            started_graceful_shutdown: true,
            immediate_sigkill: false,
            abandon_revocation: false,
        }
    }

    /// NS-029: Revoke all active credentials in parallel; isolate failures.
    pub async fn revoke_all_on_signal<F, Fut>(
        &self,
        credentials: Vec<ActiveCredential>,
        budget: RevocationBudget,
        revoke_fn: F,
    ) -> Vec<RevocationResult>
    where
        F: Fn(ActiveCredential) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = RevocationResultKind> + Send + 'static,
    {
        let mut set = tokio::task::JoinSet::new();

        for cred in credentials {
            let revoke = revoke_fn.clone();
            let budget = budget;
            set.spawn(async move {
                let kind = revoke_with_budget(cred.clone(), budget, revoke).await;
                RevocationResult {
                    credential_id: cred.credential_id,
                    provider: cred.provider,
                    kind,
                }
            });
        }

        let mut out = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(result) = joined {
                out.push(result);
            }
        }

        out
    }
}

async fn revoke_with_budget<F, Fut>(
    credential: ActiveCredential,
    budget: RevocationBudget,
    revoke_fn: F,
) -> RevocationResultKind
where
    F: Fn(ActiveCredential) -> Fut,
    Fut: Future<Output = RevocationResultKind>,
{
    if budget.is_disabled() {
        return RevocationResultKind::Failed(
            "revocation disabled by zero budget; relying on TTL safety net".to_string(),
        );
    }

    let started = Instant::now();
    let mut last_failure = RevocationResultKind::Failed("revocation not attempted".to_string());

    for attempt in 0..=budget.max_retries {
        if started.elapsed() >= budget.wall_clock_budget {
            return RevocationResultKind::Failed(
                "revocation budget exhausted; relying on TTL safety net".to_string(),
            );
        }

        let result = revoke_fn(credential.clone()).await;
        if result.treated_as_success() {
            return result;
        }
        last_failure = result;

        if attempt == budget.max_retries {
            return last_failure;
        }

        let backoff = budget.backoff_for_retry(attempt);
        if started.elapsed().saturating_add(backoff) >= budget.wall_clock_budget {
            return RevocationResultKind::Failed(
                "revocation budget exhausted; relying on TTL safety net".to_string(),
            );
        }

        tokio::time::sleep(backoff).await;
    }

    last_failure
}
