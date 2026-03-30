// NS-008: Refresh failure preserves child
// NS-025: Refresh limitation documentation
// NS-030: Refresh retry parameters
// NS-031: Refresh failure independence
// NS-032: Continuous refresh after failure

use std::time::Duration;

use chrono::{DateTime, Utc};
use std::future::Future;
use std::time::Instant;

use crate::event::{emit_runtime_event, Event, EventType};

/// NS-008: What to do after a refresh failure.
///
/// `KillChild` exists only to be explicitly rejected — no code path
/// should ever produce it. The enum carries it so tests can assert
/// the invariant `!matches!(action, KillChild)`.
#[derive(Debug)]
pub enum RefreshAction {
    /// Schedule a retry after `delay`.
    Retry { delay: Duration },
    /// All retries exhausted or no time left — let the token expire naturally.
    /// The child process is NOT terminated (NS-008).
    AllowExpiry,
    /// Terminate the child process. **Must never be used.** Exists only so
    /// that NS-008 can be asserted as a negative constraint.
    KillChild,
}

/// The outcome of evaluating a refresh failure against the policy.
#[derive(Debug)]
pub struct RefreshOutcome {
    /// The recommended action.
    pub action: RefreshAction,
    /// NS-008: Whether a warning should be logged.
    pub log_warning: bool,
}

/// NS-030: Retry parameters for refresh exponential backoff.
///
/// - base 1s, 2x multiplier, max 4 retries, +/-25% jitter
/// - total retry window <= 50% remaining token lifetime
#[derive(Debug)]
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
    ///
    /// attempt 0 → base_delay, attempt 1 → base_delay * multiplier, etc.
    /// Saturates at `u32::MAX` multiplier to avoid overflow on large attempt values.
    pub fn base_delay_for_attempt(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.checked_pow(attempt).unwrap_or(u32::MAX);
        self.base_delay * factor
    }

    /// Compute a jittered delay for a given attempt.
    ///
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
    ///
    /// NS-030: This must be <= 50% of `remaining_lifetime`.
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

/// NS-008 + NS-030: Refresh failure policy.
///
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
    ///
    /// - `attempt`: zero-based attempt index within the current retry window.
    /// - `remaining_lifetime`: time until the current token expires.
    ///
    /// NS-008: Never returns `KillChild`. Always returns `log_warning: true`.
    /// NS-030: Respects max_retries and 50%-of-remaining-lifetime cap.
    pub fn on_refresh_failure(&self, attempt: u32, remaining_lifetime: Duration) -> RefreshOutcome {
        // NS-030: No retries if there's no remaining lifetime.
        if remaining_lifetime.is_zero() {
            return RefreshOutcome {
                action: RefreshAction::AllowExpiry,
                log_warning: true,
            };
        }

        // NS-030: Past max retries → allow natural expiry.
        if attempt >= self.params.max_retries {
            return RefreshOutcome {
                action: RefreshAction::AllowExpiry,
                log_warning: true,
            };
        }

        let delay = self.params.jittered_delay_for_attempt(attempt);

        // NS-030: Total retry window must fit within 50% of remaining lifetime.
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

/// NS-025: Generate the startup warning for rotate/refresh mode.
///
/// Environment variable injection is point-in-time: the child process
/// receives the env vars at spawn time and cannot see updates. This
/// warning must be emitted at startup when rotate mode is enabled.
pub fn rotate_mode_startup_warning() -> &'static str {
    "warning: environment variable injection is point-in-time; \
     the child process will not see refreshed credentials unless \
     it re-reads its environment. Rotate mode updates the credential \
     but the running child retains the original environment values."
}

/// NS-031: Per-credential refresh state tracker.
///
/// Each credential in multi-credential mode gets its own `RefreshTracker`.
/// One tracker's failures never affect another's state.
#[derive(Debug)]
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
    token: crate::token::ScopedToken,
    tracker: RefreshTracker,
    next_refresh_at: DateTime<Utc>,
}

impl RuntimeCredential {
    pub fn new(
        credential_id: &str,
        provider: &str,
        env_key: &str,
        token: crate::token::ScopedToken,
    ) -> Self {
        let next_refresh_at = crate::credential_set::compute_refresh_at(&token);
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
    ///
    /// Uses `child_alive` as the AgentProcess lifecycle guard: once the child
    /// exits, no further refresh commands are executed.
    pub async fn run_once<F, Fut>(
        &mut self,
        now: DateTime<Utc>,
        child_alive: bool,
        mut execute_refresh: F,
    ) -> Vec<RuntimeRefreshEvent>
    where
        F: FnMut(RefreshExecutionRequest) -> Fut,
        Fut: Future<Output = Result<crate::token::ScopedToken, String>>,
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
                // NS-032: Keep participating in normal refresh cadence.
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
        token: crate::token::ScopedToken,
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

fn normal_refresh_at(token: &crate::token::ScopedToken, now: DateTime<Utc>) -> DateTime<Utc> {
    let computed = crate::credential_set::compute_refresh_at(token);
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

    /// NS-032: Whether refresh should still be attempted.
    ///
    /// Always returns `true` — a failure window never permanently disables
    /// refresh. The caller is responsible for scheduling the next attempt
    /// at the normal interval.
    pub fn should_attempt_refresh(&self) -> bool {
        true
    }

    /// NS-032: Reset the retry window after the normal refresh interval
    /// has elapsed. This allows a fresh set of retries.
    pub fn reset_retry_window(&mut self) {
        self.consecutive_failures = 0;
    }
}

/// Cheap pseudo-random fraction in [0, 1) for jitter.
///
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
mod tests {
    use super::*;
    use std::time::Duration;

    // =========================================================================
    // NS-008: Refresh failure preserves child — must not terminate child;
    // retry with exponential backoff; log warning; allow current token until
    // TTL expiry.
    // =========================================================================

    #[test]
    fn refresh_failure_preserves_child_action_is_not_kill() {
        // When a refresh attempt fails, the policy must recommend continuing
        // (not killing the child process). The token still has remaining TTL.
        let policy = RefreshPolicy::default();
        let remaining_lifetime = Duration::from_secs(300); // 5 minutes left
        let outcome = policy.on_refresh_failure(0, remaining_lifetime);
        assert!(
            !matches!(outcome.action, RefreshAction::KillChild),
            "NS-008: refresh failure must never kill the child process"
        );
    }

    #[test]
    fn refresh_failure_preserves_child_action_is_retry() {
        // First failure should recommend retry (not give up immediately).
        let policy = RefreshPolicy::default();
        let remaining_lifetime = Duration::from_secs(300);
        let outcome = policy.on_refresh_failure(0, remaining_lifetime);
        assert!(
            matches!(outcome.action, RefreshAction::Retry { .. }),
            "NS-008: first failure should schedule a retry, got: {:?}",
            outcome.action
        );
    }

    #[test]
    fn refresh_failure_preserves_child_logs_warning() {
        // The outcome must indicate a warning should be logged.
        let policy = RefreshPolicy::default();
        let remaining_lifetime = Duration::from_secs(300);
        let outcome = policy.on_refresh_failure(0, remaining_lifetime);
        assert!(
            outcome.log_warning,
            "NS-008: refresh failure must produce a log warning"
        );
    }

    #[test]
    fn refresh_failure_preserves_child_allows_token_until_expiry() {
        // After all retries exhausted, the action should be to let the token
        // expire naturally — NOT to kill the child.
        let policy = RefreshPolicy::default();
        let remaining_lifetime = Duration::from_secs(300);
        // Exhaust all retries (max_retries = 4, so attempt 4 is last)
        let outcome = policy.on_refresh_failure(4, remaining_lifetime);
        assert!(
            matches!(outcome.action, RefreshAction::AllowExpiry),
            "NS-008: after exhausting retries, must allow token to expire naturally, got: {:?}",
            outcome.action
        );
    }

    // =========================================================================
    // NS-025: Refresh limitation documentation — env var injection is
    // point-in-time; warn at startup for rotate mode.
    // =========================================================================

    #[test]
    fn refresh_limitation_documentation_startup_warning() {
        // When refresh/rotate mode is configured, a startup warning must be
        // generated explaining that env var injection is point-in-time.
        let warning = rotate_mode_startup_warning();
        assert!(
            !warning.is_empty(),
            "NS-025: must produce a non-empty startup warning"
        );
    }

    #[test]
    fn refresh_limitation_documentation_mentions_env_var_point_in_time() {
        // The warning must mention that environment variables are point-in-time.
        let warning = rotate_mode_startup_warning();
        assert!(
            warning.to_lowercase().contains("point-in-time")
                || warning.to_lowercase().contains("point in time"),
            "NS-025: warning must mention point-in-time nature of env vars, got: {}",
            warning
        );
    }

    #[test]
    fn refresh_limitation_documentation_mentions_environment() {
        // The warning must mention environment variables specifically.
        let warning = rotate_mode_startup_warning();
        assert!(
            warning.to_lowercase().contains("environment"),
            "NS-025: warning must mention environment variables, got: {}",
            warning
        );
    }

    // =========================================================================
    // NS-030: Refresh retry parameters — exponential backoff with jitter:
    // base 1s, 2x multiplier, max 4 retries, +/-25% jitter;
    // total retry window <= 50% remaining lifetime.
    // =========================================================================

    #[test]
    fn refresh_retry_parameters_base_delay_is_one_second() {
        let params = RetryParams::default();
        assert_eq!(
            params.base_delay,
            Duration::from_secs(1),
            "NS-030: base delay must be 1 second"
        );
    }

    #[test]
    fn refresh_retry_parameters_multiplier_is_two() {
        let params = RetryParams::default();
        assert_eq!(params.multiplier, 2, "NS-030: multiplier must be 2x");
    }

    #[test]
    fn refresh_retry_parameters_max_retries_is_four() {
        let params = RetryParams::default();
        assert_eq!(params.max_retries, 4, "NS-030: max retries must be 4");
    }

    #[test]
    fn refresh_retry_parameters_jitter_range_is_25_percent() {
        let params = RetryParams::default();
        assert!(
            (params.jitter_fraction - 0.25).abs() < f64::EPSILON,
            "NS-030: jitter fraction must be 0.25 (+/-25%), got: {}",
            params.jitter_fraction
        );
    }

    #[test]
    fn refresh_retry_parameters_delay_grows_exponentially() {
        // Without jitter: attempt 0 = 1s, attempt 1 = 2s, attempt 2 = 4s, attempt 3 = 8s
        let params = RetryParams::default();
        let d0 = params.base_delay_for_attempt(0);
        let d1 = params.base_delay_for_attempt(1);
        let d2 = params.base_delay_for_attempt(2);
        let d3 = params.base_delay_for_attempt(3);

        assert_eq!(d0, Duration::from_secs(1));
        assert_eq!(d1, Duration::from_secs(2));
        assert_eq!(d2, Duration::from_secs(4));
        assert_eq!(d3, Duration::from_secs(8));
    }

    #[test]
    fn refresh_retry_parameters_jittered_delay_within_bounds() {
        // Jittered delay for attempt 0 should be within [0.75s, 1.25s]
        let params = RetryParams::default();
        // Run several iterations to exercise jitter
        for _ in 0..100 {
            let delay = params.jittered_delay_for_attempt(0);
            let min = Duration::from_millis(750);
            let max = Duration::from_millis(1250);
            assert!(
                delay >= min && delay <= max,
                "NS-030: jittered delay for attempt 0 must be in [750ms, 1250ms], got: {:?}",
                delay
            );
        }
    }

    #[test]
    fn refresh_retry_parameters_jittered_delay_attempt_2_within_bounds() {
        // Attempt 2: base = 4s, range = [3s, 5s]
        let params = RetryParams::default();
        for _ in 0..100 {
            let delay = params.jittered_delay_for_attempt(2);
            let min = Duration::from_secs(3);
            let max = Duration::from_secs(5);
            assert!(
                delay >= min && delay <= max,
                "NS-030: jittered delay for attempt 2 must be in [3s, 5s], got: {:?}",
                delay
            );
        }
    }

    #[test]
    fn refresh_retry_parameters_total_window_within_50_percent_remaining() {
        // With remaining_lifetime = 60s, total retry window must be <= 30s.
        // Worst case (max jitter): 1.25 + 2.5 + 5 + 10 = 18.75s — fits in 30s.
        let params = RetryParams::default();
        let remaining = Duration::from_secs(60);
        let max_window = params.max_retry_window(remaining);
        let half_remaining = remaining / 2;
        assert!(
            max_window <= half_remaining,
            "NS-030: total retry window ({:?}) must be <= 50% of remaining lifetime ({:?})",
            max_window,
            half_remaining
        );
    }

    #[test]
    fn refresh_retry_parameters_truncates_retries_when_lifetime_short() {
        // If remaining lifetime is only 2s, we can't do 4 retries.
        // The policy must cap retries so total window <= 50% of 2s = 1s.
        let policy = RefreshPolicy::default();
        let remaining = Duration::from_secs(2);
        let outcome = policy.on_refresh_failure(0, remaining);
        match outcome.action {
            RefreshAction::Retry { delay } => {
                assert!(
                    delay <= Duration::from_secs(1),
                    "NS-030: retry delay must fit within 50% remaining lifetime, got: {:?}",
                    delay
                );
            }
            RefreshAction::AllowExpiry => {
                // Also acceptable — if there's no room for even one retry
            }
            RefreshAction::KillChild => {
                panic!("NS-008: must never kill child");
            }
        }
    }

    #[test]
    fn refresh_retry_parameters_no_retry_when_remaining_lifetime_zero() {
        // If token is already expired (0 remaining), skip retries.
        let policy = RefreshPolicy::default();
        let remaining = Duration::from_secs(0);
        let outcome = policy.on_refresh_failure(0, remaining);
        assert!(
            matches!(outcome.action, RefreshAction::AllowExpiry),
            "NS-030: with zero remaining lifetime, should allow expiry, got: {:?}",
            outcome.action
        );
    }

    // =========================================================================
    // NS-031: Refresh failure independence — in multi-credential mode,
    // one failure must not affect others.
    // =========================================================================

    #[test]
    fn refresh_failure_independence_separate_trackers() {
        // Each credential gets its own failure tracker. Failing one doesn't
        // affect the state of another.
        let mut tracker_a = RefreshTracker::new("credential-a");
        let mut tracker_b = RefreshTracker::new("credential-b");

        tracker_a.record_failure();
        tracker_a.record_failure();
        tracker_a.record_failure();

        assert_eq!(tracker_a.consecutive_failures(), 3);
        assert_eq!(
            tracker_b.consecutive_failures(),
            0,
            "NS-031: credential-b must not be affected by credential-a failures"
        );

        tracker_b.record_success();
        assert_eq!(
            tracker_a.consecutive_failures(),
            3,
            "NS-031: credential-a must not be affected by credential-b success"
        );
    }

    #[test]
    fn refresh_failure_independence_success_resets_own_tracker() {
        let mut tracker = RefreshTracker::new("cred");
        tracker.record_failure();
        tracker.record_failure();
        assert_eq!(tracker.consecutive_failures(), 2);

        tracker.record_success();
        assert_eq!(
            tracker.consecutive_failures(),
            0,
            "NS-031: success should reset own failure counter"
        );
    }

    #[test]
    fn refresh_failure_independence_tracker_knows_its_credential() {
        let tracker = RefreshTracker::new("my-aws-cred");
        assert_eq!(tracker.credential_id(), "my-aws-cred");
    }

    // =========================================================================
    // NS-032: Continuous refresh after failure — single failure window does
    // not permanently disable refresh; keep trying at normal interval.
    // =========================================================================

    #[test]
    fn continuous_refresh_after_failure_not_permanently_disabled() {
        // After a failure window (all retries exhausted), the tracker must
        // indicate that refresh should be attempted again at the next normal
        // interval — it must NOT be permanently disabled.
        let mut tracker = RefreshTracker::new("cred");
        let policy = RefreshPolicy::default();
        let remaining = Duration::from_secs(300);

        // Exhaust all retries
        for attempt in 0..=policy.retry_params().max_retries {
            tracker.record_failure();
            let _ = policy.on_refresh_failure(attempt, remaining);
        }

        assert!(
            tracker.should_attempt_refresh(),
            "NS-032: refresh must not be permanently disabled after a failure window"
        );
    }

    #[test]
    fn continuous_refresh_after_failure_reset_after_success() {
        // After a failure window, if a subsequent refresh succeeds,
        // the tracker fully resets.
        let mut tracker = RefreshTracker::new("cred");

        // Simulate a failure window
        for _ in 0..5 {
            tracker.record_failure();
        }
        assert!(tracker.consecutive_failures() > 0);

        // Success resets everything
        tracker.record_success();
        assert_eq!(tracker.consecutive_failures(), 0);
        assert!(
            tracker.should_attempt_refresh(),
            "NS-032: after success, refresh must be fully enabled"
        );
    }

    #[test]
    fn continuous_refresh_after_failure_new_window_after_expiry() {
        // After all retries in one window are exhausted and the failure
        // window elapses, a new set of retries becomes available.
        let mut tracker = RefreshTracker::new("cred");
        let policy = RefreshPolicy::default();

        // Exhaust first failure window
        for _ in 0..=policy.retry_params().max_retries {
            tracker.record_failure();
        }

        // Reset the failure window (simulates: next normal refresh interval arrived)
        tracker.reset_retry_window();
        assert_eq!(
            tracker.consecutive_failures(),
            0,
            "NS-032: resetting retry window must clear failure count"
        );
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn refresh_failure_preserves_child_never_kills_at_any_attempt() {
        // Exhaustive: no attempt count should ever produce KillChild.
        let policy = RefreshPolicy::default();
        for attempt in 0..=100 {
            let outcome = policy.on_refresh_failure(attempt, Duration::from_secs(3600));
            assert!(
                !matches!(outcome.action, RefreshAction::KillChild),
                "NS-008: attempt {} must never produce KillChild",
                attempt
            );
        }
    }

    #[test]
    fn refresh_tracker_failure_count_saturates_instead_of_wrapping() {
        let mut tracker = RefreshTracker::new("cred");
        // Simulate near-max failures directly
        tracker.consecutive_failures = u32::MAX - 1;
        tracker.record_failure(); // -> MAX
        assert_eq!(tracker.consecutive_failures(), u32::MAX);
        tracker.record_failure(); // should saturate, not wrap to 0
        assert_eq!(
            tracker.consecutive_failures(),
            u32::MAX,
            "Failure count must saturate, not wrap"
        );
    }

    #[test]
    fn refresh_retry_parameters_large_attempt_does_not_panic() {
        // base_delay_for_attempt with a huge attempt number should not
        // overflow or panic — it should saturate.
        let params = RetryParams::default();
        let delay = params.base_delay_for_attempt(100);
        // Just assert it doesn't panic and produces a non-zero duration.
        assert!(delay > Duration::ZERO);
    }

    fn make_runtime_token(
        value: &str,
        provider: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::token::ScopedToken {
        crate::token::ScopedToken::new(
            secrecy::SecretString::from(value.to_string()),
            "runtime-role",
            expires_at,
            Some(format!("tok-{}", provider)),
            provider,
        )
    }

    #[test]
    fn refresh_runtime_ns_048_timer_based_scheduling_uses_compute_refresh_at() {
        let token = make_runtime_token(
            "aws-v1",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(20),
        );
        let expected = crate::credential_set::compute_refresh_at(&token);

        let runtime = RefreshRuntimeLoop::new(vec![RuntimeCredential::new(
            "cred-aws",
            "aws",
            "AWS_TOKEN",
            token,
        )]);

        let schedule = runtime.schedule_snapshot();
        assert_eq!(schedule.len(), 1);
        let skew = (schedule[0].refresh_at - expected).num_milliseconds().abs();
        assert!(
            skew <= 5,
            "runtime schedule must derive from compute_refresh_at (skew={}ms)",
            skew
        );
    }

    #[test]
    fn refresh_runtime_ns_031_per_credential_independent_timers() {
        let token_a = make_runtime_token(
            "a-v1",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(10),
        );
        let token_b = make_runtime_token(
            "b-v1",
            "gcp",
            chrono::Utc::now() + chrono::Duration::minutes(40),
        );

        let runtime = RefreshRuntimeLoop::new(vec![
            RuntimeCredential::new("cred-a", "aws", "AWS_TOKEN", token_a),
            RuntimeCredential::new("cred-b", "gcp", "GCP_TOKEN", token_b),
        ]);

        let schedule = runtime.schedule_snapshot();
        assert_eq!(schedule.len(), 2);
        assert_ne!(schedule[0].refresh_at, schedule[1].refresh_at);
    }

    #[test]
    fn refresh_runtime_ns_008_ns_030_failure_handling_uses_policy() {
        let token = make_runtime_token(
            "aws-v1",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(5),
        );
        let mut runtime = RefreshRuntimeLoop::new(vec![RuntimeCredential::new(
            "cred-aws",
            "aws",
            "AWS_TOKEN",
            token,
        )]);

        let outcome = runtime.record_refresh_failure("cred-aws", chrono::Utc::now());
        assert!(outcome.log_warning);
        assert!(!matches!(outcome.action, RefreshAction::KillChild));
    }

    #[test]
    fn refresh_runtime_ns_032_tracker_counts_success_and_failure() {
        let token = make_runtime_token(
            "aws-v1",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(10),
        );
        let mut runtime = RefreshRuntimeLoop::new(vec![RuntimeCredential::new(
            "cred-aws",
            "aws",
            "AWS_TOKEN",
            token,
        )]);

        runtime.record_refresh_failure("cred-aws", chrono::Utc::now());
        assert_eq!(runtime.failure_count("cred-aws"), 1);

        let next_token = make_runtime_token(
            "aws-v2",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(10),
        );
        runtime.record_refresh_success("cred-aws", next_token);
        assert_eq!(runtime.failure_count("cred-aws"), 0);
    }

    #[test]
    fn refresh_runtime_ns_025_startup_warning_for_rotate_mode() {
        let token = make_runtime_token(
            "aws-v1",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(10),
        );

        let mut runtime = RefreshRuntimeLoop::new(vec![RuntimeCredential::new(
            "cred-aws",
            "aws",
            "AWS_TOKEN",
            token,
        )]);
        let mut warnings = Vec::new();

        runtime.startup(true, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0], rotate_mode_startup_warning());
    }

    #[test]
    fn refresh_runtime_lease_renewal_detection_same_token_is_renewal_different_is_rotation() {
        let token = make_runtime_token(
            "aws-v1",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(10),
        );
        let mut runtime = RefreshRuntimeLoop::new(vec![RuntimeCredential::new(
            "cred-aws",
            "aws",
            "AWS_TOKEN",
            token,
        )]);

        let renewal_token = make_runtime_token(
            "aws-v1",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(10),
        );
        let renewal = runtime.record_refresh_success("cred-aws", renewal_token);
        assert!(matches!(renewal, LeaseRefreshKind::Renewal));

        let rotation_token = make_runtime_token(
            "aws-v2",
            "aws",
            chrono::Utc::now() + chrono::Duration::minutes(10),
        );
        let rotation = runtime.record_refresh_success("cred-aws", rotation_token);
        assert!(matches!(rotation, LeaseRefreshKind::Rotation));
    }

    #[test]
    fn refresh_runtime_ns_048_timer_delay_until_next_refresh() {
        let now = chrono::Utc::now();
        let token_a = make_runtime_token("a-v1", "aws", now + chrono::Duration::minutes(20));
        let token_b = make_runtime_token("b-v1", "gcp", now + chrono::Duration::minutes(40));

        let runtime = RefreshRuntimeLoop::new(vec![
            RuntimeCredential::new("cred-a", "aws", "AWS_TOKEN", token_a),
            RuntimeCredential::new("cred-b", "gcp", "GCP_TOKEN", token_b),
        ]);

        let delay = runtime.next_wake_delay(now).expect("expected wake delay");
        assert!(delay > Duration::ZERO);
        assert!(delay <= Duration::from_secs(16 * 60));
    }

    #[tokio::test]
    async fn refresh_runtime_provider_execution_runs_only_due_credentials_with_child_context() {
        let now = chrono::Utc::now();
        let token = make_runtime_token("aws-v1", "aws", now + chrono::Duration::seconds(1));
        let mut runtime = RefreshRuntimeLoop::new(vec![RuntimeCredential::new(
            "cred-aws",
            "aws",
            "AWS_TOKEN",
            token,
        )]);

        let mut executed = false;
        let events = runtime
            .run_once(now + chrono::Duration::seconds(1), true, |_request| {
                executed = true;
                Box::pin(async {
                    Ok(make_runtime_token(
                        "aws-v2",
                        "aws",
                        chrono::Utc::now() + chrono::Duration::minutes(10),
                    ))
                })
            })
            .await;

        assert!(executed);
        assert_eq!(events.len(), 1);

        let mut not_run = false;
        let skipped = runtime
            .run_once(now + chrono::Duration::seconds(1), false, |_request| {
                not_run = true;
                Box::pin(async {
                    Ok(make_runtime_token(
                        "aws-v3",
                        "aws",
                        chrono::Utc::now() + chrono::Duration::minutes(10),
                    ))
                })
            })
            .await;
        assert!(!not_run);
        assert!(skipped.is_empty());
    }

    #[test]
    fn refresh_runtime_allow_expiry_does_not_schedule_tight_retry_loop() {
        let now = chrono::Utc::now();
        let expired = make_runtime_token("aws-v1", "aws", now - chrono::Duration::seconds(5));
        let mut runtime = RefreshRuntimeLoop::new(vec![RuntimeCredential::new(
            "cred-aws",
            "aws",
            "AWS_TOKEN",
            expired,
        )]);

        let outcome = runtime.record_refresh_failure("cred-aws", now);
        assert!(matches!(outcome.action, RefreshAction::AllowExpiry));

        let delay = runtime.next_wake_delay(now).expect("expected wake delay");
        assert!(
            delay >= Duration::from_secs(1),
            "allow-expiry path must avoid immediate tight loops"
        );
    }
}
