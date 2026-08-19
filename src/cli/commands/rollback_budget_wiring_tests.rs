use crate::app::revoke::revoke_token_with_budget;
use chrono::Utc;
use provenance_macros::verifies;
use secrecy::SecretString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn make_token(provider: &str, token_id: &str) -> crate::core::token::ScopedToken {
    crate::core::token::ScopedToken::new(
        SecretString::from("rollback-secret".to_string()),
        "admin",
        Utc::now() + chrono::Duration::minutes(5),
        Some(token_id.to_string()),
        provider,
    )
}

#[tokio::test]
async fn atomic_rollback_follows_revocation_budget_retries_failed_revocations() {
    let token = make_token("aws", "tok-aws");
    let budget = crate::core::credential_set::RollbackBudget::default();
    let attempts = Arc::new(AtomicUsize::new(0));

    let attempts_for_revoke = Arc::clone(&attempts);
    let mut noop_logs = Vec::new();
    revoke_token_with_budget(
        &token,
        &budget,
        move || {
            let attempts_for_revoke = Arc::clone(&attempts_for_revoke);
            async move {
                let current = attempts_for_revoke.fetch_add(1, Ordering::SeqCst) + 1;
                if current < 3 {
                    Err("transient revoke failure".to_string())
                } else {
                    Ok(())
                }
            }
        },
        |_delay| async {},
        |line| noop_logs.push(line),
    )
    .await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        3,
        "failed revokes must retry"
    );
}

#[tokio::test]
async fn atomic_rollback_follows_revocation_budget_enforces_wall_clock_budget() {
    let token = make_token("aws", "tok-aws");
    let budget = crate::core::credential_set::RollbackBudget {
        revoke_timeout: Duration::from_millis(15),
        max_retries: 8,
    };
    let attempts = Arc::new(AtomicUsize::new(0));

    let attempts_for_revoke = Arc::clone(&attempts);
    let mut noop_logs = Vec::new();
    revoke_token_with_budget(
        &token,
        &budget,
        move || {
            let attempts_for_revoke = Arc::clone(&attempts_for_revoke);
            async move {
                attempts_for_revoke.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Err("slow revoke failure".to_string())
            }
        },
        |_delay| async {},
        |line| noop_logs.push(line),
    )
    .await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "wall clock budget must cap total retry attempts"
    );
}

#[tokio::test]
#[verifies("rule_cross_rollback_budget", examples)]
async fn atomic_rollback_follows_revocation_budget_applies_exponential_backoff() {
    let token = make_token("aws", "tok-aws");
    let budget = crate::core::credential_set::RollbackBudget {
        revoke_timeout: Duration::from_secs(2),
        max_retries: 3,
    };

    let sleeps = Arc::new(Mutex::new(Vec::new()));
    let sleeps_for_sleep = Arc::clone(&sleeps);

    let mut noop_logs = Vec::new();
    revoke_token_with_budget(
        &token,
        &budget,
        || async { Err("always fails".to_string()) },
        move |delay| {
            let sleeps_for_sleep = Arc::clone(&sleeps_for_sleep);
            async move {
                sleeps_for_sleep.lock().unwrap().push(delay);
            }
        },
        |line| noop_logs.push(line),
    )
    .await;

    let delays = sleeps.lock().unwrap().clone();
    assert_eq!(
        delays,
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400)
        ],
        "rollback retries must use exponential backoff"
    );
}

#[tokio::test]
async fn atomic_rollback_follows_revocation_budget_logs_each_attempt() {
    let token = make_token("aws", "tok-aws");
    let budget = crate::core::credential_set::RollbackBudget::default();

    let logs = Arc::new(Mutex::new(Vec::new()));
    let logs_for_log = Arc::clone(&logs);
    let attempts = Arc::new(AtomicUsize::new(0));

    let attempts_for_revoke = Arc::clone(&attempts);
    revoke_token_with_budget(
        &token,
        &budget,
        move || {
            let attempts_for_revoke = Arc::clone(&attempts_for_revoke);
            async move {
                let current = attempts_for_revoke.fetch_add(1, Ordering::SeqCst) + 1;
                if current == 1 {
                    Err("first failure".to_string())
                } else {
                    Ok(())
                }
            }
        },
        |_delay| async {},
        move |line| {
            logs_for_log.lock().unwrap().push(line);
        },
    )
    .await;

    let lines = logs.lock().unwrap().clone();
    assert_eq!(
        lines.len(),
        2,
        "every rollback attempt must emit a rollback log entry"
    );
    assert!(
        lines.iter().all(|line| {
            line.contains("rollback:")
                && line.contains("provider=aws")
                && line.contains("credential_id=tok-aws")
        }),
        "logs must use RollbackLogEntry format"
    );
}

#[tokio::test]
async fn atomic_rollback_follows_revocation_budget_zero_disables_retries() {
    let token = make_token("aws", "tok-aws");
    let budget = crate::core::credential_set::RollbackBudget {
        revoke_timeout: Duration::ZERO,
        max_retries: 3,
    };
    let attempts = Arc::new(AtomicUsize::new(0));

    let attempts_for_revoke = Arc::clone(&attempts);
    let mut noop_logs = Vec::new();
    revoke_token_with_budget(
        &token,
        &budget,
        move || {
            let attempts_for_revoke = Arc::clone(&attempts_for_revoke);
            async move {
                attempts_for_revoke.fetch_add(1, Ordering::SeqCst);
                Err("should not run when budget=0".to_string())
            }
        },
        |_delay| async {},
        |line| noop_logs.push(line),
    )
    .await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "budget=0 must disable rollback retries"
    );
}

#[tokio::test]
async fn atomic_rollback_follows_revocation_budget_attempt_timeout_logs_failure() {
    let token = make_token("aws", "tok-aws");
    let budget = crate::core::credential_set::RollbackBudget {
        revoke_timeout: Duration::from_millis(10),
        max_retries: 3,
    };

    let attempts = Arc::new(AtomicUsize::new(0));
    let logs = Arc::new(Mutex::new(Vec::new()));

    let attempts_for_revoke = Arc::clone(&attempts);
    let logs_for_log = Arc::clone(&logs);

    revoke_token_with_budget(
        &token,
        &budget,
        move || {
            let attempts_for_revoke = Arc::clone(&attempts_for_revoke);
            async move {
                attempts_for_revoke.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(())
            }
        },
        |_delay| async {},
        move |line| logs_for_log.lock().unwrap().push(line),
    )
    .await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a timed-out attempt should consume budget and stop further retries"
    );
    let lines = logs.lock().unwrap().clone();
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("timed out"),
        "timed-out rollback attempts should be logged as failures"
    );
}
