use super::*;
use provenance_macros::verifies;
use std::time::Duration;

#[test]
#[verifies("rule_refresh_never_kills_child", examples)]
fn refresh_failure_preserves_child_action_is_not_kill() {
    // When a refresh attempt fails, the policy must recommend continuing
    // (not killing the child process). The token still has remaining TTL.
    let policy = RefreshPolicy::default();
    let remaining_lifetime = Duration::from_secs(300); // 5 minutes left
    let outcome = policy.on_refresh_failure(0, remaining_lifetime);
    assert!(
        !matches!(outcome.action, RefreshAction::KillChild),
        "refresh failure must never kill the child process"
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
        "first failure should schedule a retry, got: {:?}",
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
        "refresh failure must produce a log warning"
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
        "after exhausting retries, must allow token to expire naturally, got: {:?}",
        outcome.action
    );
}

#[test]
fn refresh_limitation_documentation_startup_warning() {
    // When refresh/rotate mode is configured, a startup warning must be
    // generated explaining that env var injection is point-in-time.
    let warning = rotate_mode_startup_warning();
    assert!(
        !warning.is_empty(),
        "must produce a non-empty startup warning"
    );
}

#[test]
fn refresh_limitation_documentation_mentions_env_var_point_in_time() {
    // The warning must mention that environment variables are point-in-time.
    let warning = rotate_mode_startup_warning();
    assert!(
        warning.to_lowercase().contains("point-in-time")
            || warning.to_lowercase().contains("point in time"),
        "warning must mention point-in-time nature of env vars, got: {}",
        warning
    );
}

#[test]
fn refresh_limitation_documentation_mentions_environment() {
    // The warning must mention environment variables specifically.
    let warning = rotate_mode_startup_warning();
    assert!(
        warning.to_lowercase().contains("environment"),
        "warning must mention environment variables, got: {}",
        warning
    );
}

#[test]
fn refresh_retry_parameters_base_delay_is_one_second() {
    let params = RetryParams::default();
    assert_eq!(
        params.base_delay,
        Duration::from_secs(1),
        "base delay must be 1 second"
    );
}

#[test]
fn refresh_retry_parameters_multiplier_is_two() {
    let params = RetryParams::default();
    assert_eq!(params.multiplier, 2, "multiplier must be 2x");
}

#[test]
fn refresh_retry_parameters_max_retries_is_four() {
    let params = RetryParams::default();
    assert_eq!(params.max_retries, 4, "max retries must be 4");
}

#[test]
fn refresh_retry_parameters_jitter_range_is_25_percent() {
    let params = RetryParams::default();
    assert!(
        (params.jitter_fraction - 0.25).abs() < f64::EPSILON,
        "jitter fraction must be 0.25 (+/-25%), got: {}",
        params.jitter_fraction
    );
}

#[test]
#[verifies("rule_refresh_retry_params", examples)]
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
            "jittered delay for attempt 0 must be in [750ms, 1250ms], got: {:?}",
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
            "jittered delay for attempt 2 must be in [3s, 5s], got: {:?}",
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
        "total retry window ({:?}) must be <= 50% of remaining lifetime ({:?})",
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
                "retry delay must fit within 50% remaining lifetime, got: {:?}",
                delay
            );
        }
        RefreshAction::AllowExpiry => {
            // Also acceptable — if there's no room for even one retry
        }
        RefreshAction::KillChild => {
            panic!("must never kill child");
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
        "with zero remaining lifetime, should allow expiry, got: {:?}",
        outcome.action
    );
}

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
        "credential-b must not be affected by credential-a failures"
    );

    tracker_b.record_success();
    assert_eq!(
        tracker_a.consecutive_failures(),
        3,
        "credential-a must not be affected by credential-b success"
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
        "success should reset own failure counter"
    );
}

#[test]
fn refresh_failure_independence_tracker_knows_its_credential() {
    let tracker = RefreshTracker::new("my-aws-cred");
    assert_eq!(tracker.credential_id(), "my-aws-cred");
}

#[test]
#[verifies("rule_refresh_never_disabled_for_good", examples)]
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
        "refresh must not be permanently disabled after a failure window"
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
        "after success, refresh must be fully enabled"
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
        "resetting retry window must clear failure count"
    );
}

#[test]
fn refresh_failure_preserves_child_never_kills_at_any_attempt() {
    // Exhaustive: no attempt count should ever produce KillChild.
    let policy = RefreshPolicy::default();
    for attempt in 0..=100 {
        let outcome = policy.on_refresh_failure(attempt, Duration::from_secs(3600));
        assert!(
            !matches!(outcome.action, RefreshAction::KillChild),
            "attempt {} must never produce KillChild",
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
) -> crate::core::token::ScopedToken {
    crate::core::token::ScopedToken::new(
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
    let expected = crate::core::credential_set::compute_refresh_at(&token);

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
#[verifies("rule_refresh_per_credential_isolation", examples)]
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
#[verifies("rule_refresh_rotate_mode_warning", examples)]
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
#[verifies("rule_refresh_due_only_child_alive", examples)]
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
