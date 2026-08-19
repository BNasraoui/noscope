// Refresh failure preserves child
// Refresh limitation documentation
// Refresh retry parameters
// Refresh failure independence
// Continuous refresh after failure

use std::time::Duration;

use chrono::{DateTime, Utc};
use std::future::Future;
use std::time::Instant;

use crate::ports::event::{emit_runtime_event, Event, EventType};
use provenance_macros::rule;

/// What to do after a refresh failure.
/// `KillChild` exists only to be explicitly rejected — no code path
/// should ever produce it. The enum carries it so tests can assert
/// the invariant `!matches!(action, KillChild)`.
#[derive(Debug)]
pub enum RefreshAction {
    /// Schedule a retry after `delay`.
    Retry { delay: Duration },
    /// All retries exhausted or no time left — let the token expire naturally.
    /// The child process is NOT terminated.
    AllowExpiry,
    /// Terminate the child process. **Must never be used.** Exists only so
    /// that can be asserted as a negative constraint.
    KillChild,
}

/// The outcome of evaluating a refresh failure against the policy.
#[derive(Debug)]
pub struct RefreshOutcome {
    /// The recommended action.
    pub action: RefreshAction,
    /// Whether a warning should be logged.
    pub log_warning: bool,
}

/// Retry parameters for refresh exponential backoff.
/// - base 1s, 2x multiplier, max 4 retries, +/-25% jitter
/// - total retry window <= 50% remaining token lifetime
#[derive(Debug)]
#[rule("rule_refresh_retry_params")]
pub struct RetryParams {
    /// Base delay before the first retry.
    pub base_delay: Duration,
    /// Multiplicative factor per attempt.
    pub multiplier: u32,
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Jitter fraction (0.25 means +/-25%).
    pub jitter_fraction: f64,
}

impl Default for RetryParams {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_secs(1),
            multiplier: 2,
            max_retries: 4,
            jitter_fraction: 0.25,
        }
    }
}

impl RetryParams {
    /// Compute the base delay (without jitter) for a given attempt number.
    /// attempt 0 → base_delay, attempt 1 → base_delay * multiplier, etc.
    /// Saturates at `u32::MAX` multiplier to avoid overflow on large attempt values.
    pub fn base_delay_for_attempt(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.checked_pow(attempt).unwrap_or(u32::MAX);
        self.base_delay * factor
    }

    /// Compute a jittered delay for a given attempt.
    /// The delay is `base_delay * multiplier^attempt * (1 +/- jitter_fraction)`.
    /// Jitter is uniformly distributed in [-jitter_fraction, +jitter_fraction].
    pub fn jittered_delay_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.base_delay_for_attempt(attempt);
        let base_ms = base.as_millis() as f64;

        // Simple deterministic-enough jitter using a cheap source.
        // In production this would use a proper RNG; for the policy layer
        // we just need something that varies per call.
        let jitter_range = base_ms * self.jitter_fraction;
        let raw: f64 = pseudo_random_fraction();
        // Map [0, 1) to [-1, 1)
        let jitter_factor = (raw * 2.0) - 1.0;
        let jittered_ms = base_ms + (jitter_range * jitter_factor);

        // Clamp to at least 1ms to avoid zero-duration retries.
        let clamped_ms = jittered_ms.max(1.0);
        Duration::from_millis(clamped_ms as u64)
    }

    /// Compute the worst-case (max jitter) total retry window across all attempts.
    /// This must be <= 50% of `remaining_lifetime`.
    pub fn max_retry_window(&self, remaining_lifetime: Duration) -> Duration {
        let mut total_ms: f64 = 0.0;
        for attempt in 0..self.max_retries {
            let base = self.base_delay_for_attempt(attempt);
            let base_ms = base.as_millis() as f64;
            // Worst case: maximum positive jitter
            total_ms += base_ms * (1.0 + self.jitter_fraction);
        }

        let half_remaining_ms = remaining_lifetime.as_millis() as f64 / 2.0;
        let capped_ms = total_ms.min(half_remaining_ms);
        Duration::from_millis(capped_ms as u64)
    }
}

/// Refresh failure policy.
/// Determines what to do when a credential refresh attempt fails.
/// Never kills the child. Uses exponential backoff with jitter.
#[derive(Default)]
pub struct RefreshPolicy {
    params: RetryParams,
}

impl RefreshPolicy {
    /// Get a reference to the retry parameters.
    pub fn retry_params(&self) -> &RetryParams {
        &self.params
    }

    /// Evaluate a refresh failure and return the recommended outcome.
    /// - `attempt`: zero-based attempt index within the current retry window.
    /// - `remaining_lifetime`: time until the current token expires.
    ///
    /// Never returns `KillChild`. Always returns `log_warning: true`.
    /// Respects max_retries and 50%-of-remaining-lifetime cap.
    #[rule("rule_refresh_never_kills_child")]
    pub fn on_refresh_failure(&self, attempt: u32, remaining_lifetime: Duration) -> RefreshOutcome {
        // No retries if there's no remaining lifetime.
        if remaining_lifetime.is_zero() {
            return RefreshOutcome {
                action: RefreshAction::AllowExpiry,
                log_warning: true,
            };
        }

        // Past max retries → allow natural expiry.
        if attempt >= self.params.max_retries {
            return RefreshOutcome {
                action: RefreshAction::AllowExpiry,
                log_warning: true,
            };
        }

        let delay = self.params.jittered_delay_for_attempt(attempt);

        // Total retry window must fit within 50% of remaining lifetime.
        // This is a per-attempt check — the caller drives attempts sequentially,
        // so each check guarantees the individual delay fits in the remaining budget.
        // The worst-case cumulative window is validated by RetryParams::max_retry_window().
        let half_remaining = remaining_lifetime / 2;
        if delay > half_remaining {
            return RefreshOutcome {
                action: RefreshAction::AllowExpiry,
                log_warning: true,
            };
        }

        RefreshOutcome {
            action: RefreshAction::Retry { delay },
            log_warning: true,
        }
    }
}

/// Generate the startup warning for rotate/refresh mode.
/// Environment variable injection is point-in-time: the child process
/// receives the env vars at spawn time and cannot see updates. This
/// warning must be emitted at startup when rotate mode is enabled.
#[rule("rule_refresh_rotate_mode_warning")]
pub fn rotate_mode_startup_warning() -> &'static str {
    "warning: environment variable injection is point-in-time; \
     the child process will not see refreshed credentials unless \
     it re-reads its environment. Rotate mode updates the credential \
     but the running child retains the original environment values."
}

/// Per-credential refresh state tracker.
/// Each credential in multi-credential mode gets its own `RefreshTracker`.
/// One tracker's failures never affect another's state.
#[derive(Debug)]
#[rule("rule_refresh_per_credential_isolation")]
pub struct RefreshTracker {
    credential_id: String,
    consecutive_failures: u32,
}

/// Result of comparing pre/post-refresh lease values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRefreshKind {
    /// Same token value after refresh command.
    Renewal,
    /// Different token value after refresh command.
    Rotation,
}

/// Runtime state for one independently refreshed credential.
pub struct RuntimeCredential {
    credential_id: String,
    provider: String,
    env_key: String,
    token: crate::core::token::ScopedToken,
    tracker: RefreshTracker,
    next_refresh_at: DateTime<Utc>,
}

impl RuntimeCredential {
    pub fn new(
        credential_id: &str,
        provider: &str,
        env_key: &str,
        token: crate::core::token::ScopedToken,
    ) -> Self {
        let next_refresh_at = crate::core::credential_set::compute_refresh_at(&token);
        Self {
            credential_id: credential_id.to_string(),
            provider: provider.to_string(),
            env_key: env_key.to_string(),
            token,
            tracker: RefreshTracker::new(credential_id),
            next_refresh_at,
        }
    }
}

/// Snapshot of upcoming refresh schedule for one credential.
#[derive(Debug)]
pub struct RuntimeScheduleEntry {
    pub credential_id: String,
    pub provider: String,
    pub env_key: String,
    pub refresh_at: DateTime<Utc>,
}

/// Input for invoking a provider refresh command.
#[derive(Debug, Clone)]
pub struct RefreshExecutionRequest {
    pub credential_id: String,
    pub provider: String,
    pub env_key: String,
    pub token_id: Option<String>,
    pub token_value: String,
    pub expires_at: DateTime<Utc>,
}

/// Result of processing one credential during a runtime refresh tick.
#[derive(Debug)]
pub struct RuntimeRefreshEvent {
    pub credential_id: String,
    pub outcome: Result<LeaseRefreshKind, RefreshOutcome>,
}

/// Runtime loop state that drives per-credential refresh timers.
pub struct RefreshRuntimeLoop {
    policy: RefreshPolicy,
    credentials: Vec<RuntimeCredential>,
    startup_done: bool,
}

impl RefreshRuntimeLoop {
    pub fn new(credentials: Vec<RuntimeCredential>) -> Self {
        Self {
            policy: RefreshPolicy::default(),
            credentials,
            startup_done: false,
        }
    }

    /// Emit rotate-mode startup warning once when rotate mode is enabled.
    pub fn startup(&mut self, rotate_mode: bool, warnings: &mut Vec<&'static str>) {
        if rotate_mode && !self.startup_done {
            warnings.push(rotate_mode_startup_warning());
        }
        self.startup_done = true;
    }

    /// Return a read-only schedule snapshot for all credentials.
    pub fn schedule_snapshot(&self) -> Vec<RuntimeScheduleEntry> {
        self.credentials
            .iter()
            .map(|c| RuntimeScheduleEntry {
                credential_id: c.credential_id.clone(),
                provider: c.provider.clone(),
                env_key: c.env_key.clone(),
                refresh_at: c.next_refresh_at,
            })
            .collect()
    }

    /// Compute delay until the next credential refresh timer fires.
    pub fn next_wake_delay(&self, now: DateTime<Utc>) -> Option<Duration> {
        self.credentials
            .iter()
            .map(|c| {
                c.next_refresh_at
                    .signed_duration_since(now)
                    .to_std()
                    .unwrap_or(Duration::ZERO)
            })
            .min()
    }

    /// Run one refresh tick for all credentials due at `now`.
    /// Uses `child_alive` as the AgentProcess lifecycle guard: once the child
    /// exits, no further refresh commands are executed.
    #[rule("rule_refresh_due_only_child_alive")]
    pub async fn run_once<F, Fut>(
        &mut self,
        now: DateTime<Utc>,
        child_alive: bool,
        mut execute_refresh: F,
    ) -> Vec<RuntimeRefreshEvent>
    where
        F: FnMut(RefreshExecutionRequest) -> Fut,
        Fut: Future<Output = Result<crate::core::token::ScopedToken, String>>,
    {
        if !child_alive {
            return Vec::new();
        }

        let due_ids: Vec<String> = self
            .credentials
            .iter()
            .filter(|c| c.next_refresh_at <= now)
            .map(|c| c.credential_id.clone())
            .collect();

        let mut events = Vec::with_capacity(due_ids.len());
        for credential_id in due_ids {
            let request = {
                let c = self
                    .credentials
                    .iter()
                    .find(|c| c.credential_id == credential_id)
                    .unwrap_or_else(|| panic!("unknown credential_id: {}", credential_id));
                RefreshExecutionRequest {
                    credential_id: c.credential_id.clone(),
                    provider: c.provider.clone(),
                    env_key: c.env_key.clone(),
                    token_id: c.token.token_id().map(|v| v.to_string()),
                    token_value: c.token.expose_secret().to_string(),
                    expires_at: c.token.expires_at(),
                }
            };

            emit_runtime_event(Event::new(EventType::RefreshStart, &request.provider));
            let started = Instant::now();
            let provider = request.provider.clone();

            let event = match execute_refresh(request).await {
                Ok(new_token) => {
                    let mut emitted = Event::new(EventType::RefreshSuccess, &provider);
                    if let Some(token_id) = new_token.token_id() {
                        emitted.set_token_id(token_id);
                    }
                    emitted.set_duration(started.elapsed());
                    emit_runtime_event(emitted);

                    RuntimeRefreshEvent {
                        credential_id: credential_id.clone(),
                        outcome: Ok(self.record_refresh_success(&credential_id, new_token)),
                    }
                }
                Err(err) => {
                    let mut emitted = Event::new(EventType::RefreshFail, &provider);
                    emitted.set_error(&err);
                    emitted.set_duration(started.elapsed());
                    emit_runtime_event(emitted);

                    RuntimeRefreshEvent {
                        credential_id: credential_id.clone(),
                        outcome: Err(self.record_refresh_failure(&credential_id, now)),
                    }
                }
            };
            events.push(event);
        }

        events
    }

    /// Record a refresh failure and compute next action via RefreshPolicy.
    #[rule("rule_refresh_never_disabled_for_good")]
    pub fn record_refresh_failure(
        &mut self,
        credential_id: &str,
        now: DateTime<Utc>,
    ) -> RefreshOutcome {
        let (attempt, remaining_lifetime) = {
            let credential = self.credential_mut(credential_id);
            credential.tracker.record_failure();
            let attempt = credential.tracker.consecutive_failures().saturating_sub(1);
            let remaining_lifetime = credential
                .token
                .expires_at()
                .signed_duration_since(now)
                .to_std()
                .unwrap_or(Duration::ZERO);
            (attempt, remaining_lifetime)
        };

        let outcome = self.policy.on_refresh_failure(attempt, remaining_lifetime);
        let credential = self.credential_mut(credential_id);
        match outcome.action {
            RefreshAction::Retry { delay } => {
                credential.next_refresh_at =
                    now + chrono::Duration::from_std(delay).unwrap_or_default();
            }
            RefreshAction::AllowExpiry => {
                // Keep participating in normal refresh cadence.
                credential.next_refresh_at = normal_refresh_at(&credential.token, now);
            }
            RefreshAction::KillChild => {
                // Defensive invariant; policy should never return this.
                credential.next_refresh_at = normal_refresh_at(&credential.token, now);
            }
        }

        outcome
    }

    /// Record a refresh success and classify as renewal or rotation.
    pub fn record_refresh_success(
        &mut self,
        credential_id: &str,
        token: crate::core::token::ScopedToken,
    ) -> LeaseRefreshKind {
        let credential = self.credential_mut(credential_id);

        let kind = if credential.token.expose_secret() == token.expose_secret() {
            LeaseRefreshKind::Renewal
        } else {
            LeaseRefreshKind::Rotation
        };

        credential.token = token;
        credential.tracker.record_success();
        credential.next_refresh_at = normal_refresh_at(&credential.token, Utc::now());

        kind
    }

    pub fn failure_count(&self, credential_id: &str) -> u32 {
        self.credential(credential_id)
            .tracker
            .consecutive_failures()
    }

    fn credential_mut(&mut self, credential_id: &str) -> &mut RuntimeCredential {
        self.credentials
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
            .unwrap_or_else(|| panic!("unknown credential_id: {}", credential_id))
    }

    fn credential(&self, credential_id: &str) -> &RuntimeCredential {
        self.credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
            .unwrap_or_else(|| panic!("unknown credential_id: {}", credential_id))
    }
}

fn normal_refresh_at(token: &crate::core::token::ScopedToken, now: DateTime<Utc>) -> DateTime<Utc> {
    let computed = crate::core::credential_set::compute_refresh_at(token);
    if computed <= now {
        now + chrono::Duration::seconds(1)
    } else {
        computed
    }
}

impl RefreshTracker {
    /// Create a new tracker for the given credential.
    pub fn new(credential_id: &str) -> Self {
        Self {
            credential_id: credential_id.to_string(),
            consecutive_failures: 0,
        }
    }

    /// Get the credential ID this tracker is associated with.
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// Record a refresh failure for this credential.
    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Record a refresh success — resets failure count.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    /// Current number of consecutive failures.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Whether refresh should still be attempted.
    /// Always returns `true` — a failure window never permanently disables
    /// refresh. The caller is responsible for scheduling the next attempt
    /// at the normal interval.
    pub fn should_attempt_refresh(&self) -> bool {
        true
    }

    /// Reset the retry window after the normal refresh interval
    /// has elapsed. This allows a fresh set of retries.
    pub fn reset_retry_window(&mut self) {
        self.consecutive_failures = 0;
    }
}

/// Cheap pseudo-random fraction in [0, 1) for jitter.
/// Uses thread-local state seeded from the system clock. This is NOT
/// cryptographically secure — it's only used for retry jitter timing.
fn pseudo_random_fraction() -> f64 {
    use std::cell::Cell;
    use std::time::SystemTime;

    thread_local! {
        static STATE: Cell<u64> = Cell::new(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        );
    }

    STATE.with(|s| {
        let mut x = s.get();
        // xorshift64 produces 0 forever if seeded with 0; fix up.
        if x == 0 {
            x = 0xdeadbeefcafe1234;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        (x as f64) / (u64::MAX as f64)
    })
}

#[cfg(test)]
mod tests;
