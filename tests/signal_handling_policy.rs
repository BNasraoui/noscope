use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use noscope::signal_policy::{
    ActiveCredential, ChildExitReason, ParentSignal, RevocationBudget, RevocationResultKind,
    SignalHandlingPolicy, TtlBounds, TtlError,
};

#[test]
fn ns_003_revoke_on_exit_guarantee_attempts_revocation_regardless_of_exit_reason() {
    let policy = SignalHandlingPolicy::default();

    assert!(policy.should_attempt_revoke_on_exit(ChildExitReason::ExitCode(0)));
    assert!(policy.should_attempt_revoke_on_exit(ChildExitReason::ExitCode(42)));
    assert!(policy.should_attempt_revoke_on_exit(ChildExitReason::Signaled(15)));
}

#[test]
fn ns_011_ttl_as_safety_net_never_allows_missing_ttl() {
    let bounds = TtlBounds::default();
    let err = SignalHandlingPolicy::validate_ttl(None, &bounds).unwrap_err();

    assert!(matches!(err, TtlError::Missing));
}

#[test]
fn ns_014_revocation_must_be_idempotent_already_revoked_and_expired_are_success() {
    let policy = SignalHandlingPolicy::default();

    assert!(
        policy
            .classify_revocation_result(1, "already revoked")
            .treated_as_success()
    );
    assert!(
        policy
            .classify_revocation_result(1, "token expired")
            .treated_as_success()
    );
}

#[test]
fn ns_026_signal_forwarding_policy_forwards_supported_signals_and_ignores_sigpipe() {
    let policy = SignalHandlingPolicy::default();

    assert!(policy.should_forward_to_child_group(ParentSignal::Sigterm));
    assert!(policy.should_forward_to_child_group(ParentSignal::Sighup));
    assert!(policy.should_forward_to_child_group(ParentSignal::Sigint));
    assert!(!policy.should_forward_to_child_group(ParentSignal::Sigpipe));

    assert_eq!(policy.shutdown_grace_period(), Duration::from_secs(30));
}

#[test]
fn ns_027_revocation_timeout_and_retry_budget_defaults_and_budget_zero_disable() {
    let default_budget = RevocationBudget::default();
    assert_eq!(default_budget.wall_clock_budget, Duration::from_secs(10));
    assert_eq!(default_budget.base_backoff, Duration::from_millis(500));
    assert_eq!(default_budget.max_retries, 3);

    let disabled = RevocationBudget::disabled();
    assert!(disabled.is_disabled());
}

#[test]
fn ns_028_double_signal_escalation_second_term_or_int_abandons_revocation() {
    let mut policy = SignalHandlingPolicy::default();

    let first = policy.on_shutdown_signal(ParentSignal::Sigterm);
    assert!(first.started_graceful_shutdown);

    let second = policy.on_shutdown_signal(ParentSignal::Sigint);
    assert!(second.immediate_sigkill);
    assert!(second.abandon_revocation);
}

#[test]
fn ns_026_signal_forwarding_policy_sigpipe_does_not_start_shutdown() {
    let mut policy = SignalHandlingPolicy::default();
    let decision = policy.on_shutdown_signal(ParentSignal::Sigpipe);

    assert!(!decision.started_graceful_shutdown);
    assert!(!decision.immediate_sigkill);
    assert!(!decision.abandon_revocation);
}

#[tokio::test]
async fn ns_029_multi_credential_revocation_on_signal_runs_in_parallel_and_is_failure_isolated() {
    let policy = SignalHandlingPolicy::default();
    let budget = RevocationBudget {
        max_retries: 0,
        ..RevocationBudget::default()
    };

    let credentials = vec![
        ActiveCredential::new("c1", "aws"),
        ActiveCredential::new("c2", "gcp"),
        ActiveCredential::new("c3", "vault"),
    ];

    let started = Instant::now();
    let results = policy
        .revoke_all_on_signal(credentials, budget, |cred| async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if cred.provider == "gcp" {
                RevocationResultKind::Failed("network down".to_string())
            } else {
                RevocationResultKind::Revoked
            }
        })
        .await;

    assert_eq!(results.len(), 3);
    assert!(
        results
            .iter()
            .any(|r| matches!(r.kind, RevocationResultKind::Revoked))
    );
    assert!(
        results
            .iter()
            .any(|r| matches!(r.kind, RevocationResultKind::Failed(_)))
    );

    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(450),
        "expected parallel revocation; elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn ns_027_revocation_timeout_and_retry_budget_retries_with_backoff_until_success() {
    let policy = SignalHandlingPolicy::default();
    let attempts = Arc::new(AtomicUsize::new(0));

    let attempts_for_closure = Arc::clone(&attempts);
    let results = policy
        .revoke_all_on_signal(
            vec![ActiveCredential::new("cred-1", "aws")],
            RevocationBudget::default(),
            move |_cred| {
                let attempts = Arc::clone(&attempts_for_closure);
                async move {
                    let n = attempts.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        RevocationResultKind::Failed("network down".to_string())
                    } else {
                        RevocationResultKind::Revoked
                    }
                }
            },
        )
        .await;

    assert_eq!(results.len(), 1);
    assert!(matches!(results[0].kind, RevocationResultKind::Revoked));
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn ns_027_revocation_timeout_and_retry_budget_budget_zero_disables_attempts() {
    let policy = SignalHandlingPolicy::default();
    let attempts = Arc::new(AtomicUsize::new(0));

    let attempts_for_closure = Arc::clone(&attempts);
    let results = policy
        .revoke_all_on_signal(
            vec![ActiveCredential::new("cred-1", "aws")],
            RevocationBudget::disabled(),
            move |_cred| {
                let attempts = Arc::clone(&attempts_for_closure);
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    RevocationResultKind::Revoked
                }
            },
        )
        .await;

    assert_eq!(results.len(), 1);
    assert!(matches!(results[0].kind, RevocationResultKind::Failed(_)));
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
}

#[test]
fn ns_066_minimum_ttl_enforcement_rejects_ttl_below_60_seconds() {
    let bounds = TtlBounds::default();
    let err = SignalHandlingPolicy::validate_ttl(Some(59), &bounds).unwrap_err();

    assert!(matches!(
        err,
        TtlError::BelowMinimum {
            minimum: 60,
            actual: 59
        }
    ));
}

#[test]
fn ns_067_maximum_ttl_enforcement_rejects_ttl_above_default_12_hours() {
    let bounds = TtlBounds::default();
    let err = SignalHandlingPolicy::validate_ttl(Some(43_201), &bounds).unwrap_err();

    assert!(matches!(
        err,
        TtlError::AboveMaximum {
            maximum: 43_200,
            actual: 43_201
        }
    ));
}
