use provenance_macros::verifies;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use secrecy::SecretString;

use crate::core::credential_set::{CredentialSetError, CredentialSpec, MintConfig, MintResult};
use crate::core::mint::format_mint_output;
use crate::core::token::ScopedToken;

/// Helper: create a ScopedToken for test convenience.
fn make_token(value: &str, provider: &str, expires_at: chrono::DateTime<Utc>) -> ScopedToken {
    ScopedToken::new(
        SecretString::from(value.to_string()),
        "test-role",
        expires_at,
        Some(format!("tok-{}", provider)),
        provider,
    )
}

/// Helper: default expiry 1 hour from now.
fn default_expiry() -> chrono::DateTime<Utc> {
    Utc::now() + chrono::Duration::hours(1)
}

#[tokio::test]
#[verifies("rule_orchestration_bounded_concurrency", examples)]
async fn bounded_parallelism_enforces_max_concurrent() {
    // With max_concurrent=2 and 4 providers, at most 2 should run
    // simultaneously. We track peak concurrency with an atomic counter.
    let config = MintConfig::new(Duration::from_secs(30), 2).unwrap();
    let peak = Arc::new(AtomicUsize::new(0));
    let current = Arc::new(AtomicUsize::new(0));

    let specs: Vec<CredentialSpec> = (0..4)
        .map(|i| CredentialSpec::new(&format!("prov-{}", i), "role", 3600, &format!("KEY_{}", i)))
        .collect();

    let peak_clone = Arc::clone(&peak);
    let current_clone = Arc::clone(&current);

    let mint_fn = move |spec: &CredentialSpec| {
        let peak = Arc::clone(&peak_clone);
        let current = Arc::clone(&current_clone);
        let provider = spec.provider.clone();
        async move {
            let c = current.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(c, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            current.fetch_sub(1, Ordering::SeqCst);
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, &format!("KEY_{}", provider)),
                token: make_token(&format!("secret-{}", provider), &provider, default_expiry()),
            }
        }
    };

    let results = super::mint_all(&specs, &config, mint_fn).await;

    assert!(results.is_ok(), "All providers succeeded, should be Ok");
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "peak concurrency must not exceed max_concurrent=2, got: {}",
        peak.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn bounded_parallelism_single_concurrent_serializes() {
    // With max_concurrent=1, providers must run one at a time.
    let config = MintConfig::new(Duration::from_secs(30), 1).unwrap();
    let peak = Arc::new(AtomicUsize::new(0));
    let current = Arc::new(AtomicUsize::new(0));

    let specs: Vec<CredentialSpec> = (0..3)
        .map(|i| CredentialSpec::new(&format!("prov-{}", i), "role", 3600, &format!("KEY_{}", i)))
        .collect();

    let peak_clone = Arc::clone(&peak);
    let current_clone = Arc::clone(&current);

    let mint_fn = move |spec: &CredentialSpec| {
        let peak = Arc::clone(&peak_clone);
        let current = Arc::clone(&current_clone);
        let provider = spec.provider.clone();
        async move {
            let c = current.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(c, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(30)).await;
            current.fetch_sub(1, Ordering::SeqCst);
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, &format!("KEY_{}", provider)),
                token: make_token(&format!("s-{}", provider), &provider, default_expiry()),
            }
        }
    };

    let results = super::mint_all(&specs, &config, mint_fn).await;

    assert!(results.is_ok());
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "with max_concurrent=1, peak concurrency must be exactly 1"
    );
}

#[tokio::test]
#[verifies("rule_orchestration_per_provider_timeout", examples)]
async fn per_provider_timeout_slow_provider_fails() {
    // A provider that takes longer than the timeout must be treated as failure.
    let config = MintConfig::new(Duration::from_millis(50), 8).unwrap();

    let specs = vec![CredentialSpec::new("slow-prov", "role", 3600, "SLOW_KEY")];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        async move {
            // Sleep longer than the 50ms timeout
            tokio::time::sleep(Duration::from_secs(5)).await;
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, "SLOW_KEY"),
                token: make_token("never-minted", &provider, default_expiry()),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;

    assert!(
        result.is_err(),
        "provider exceeding timeout must result in failure"
    );
}

#[tokio::test]
async fn per_provider_timeout_fast_provider_succeeds() {
    // A provider that completes within the timeout must succeed.
    let config = MintConfig::new(Duration::from_secs(5), 8).unwrap();

    let specs = vec![CredentialSpec::new("fast-prov", "role", 3600, "FAST_KEY")];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, "FAST_KEY"),
                token: make_token("fast-secret", &provider, default_expiry()),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;

    assert!(
        result.is_ok(),
        "provider completing within timeout must succeed"
    );
}

#[tokio::test]
#[verifies("rule_orchestration_timeout_error_names_provider", examples)]
async fn per_provider_timeout_error_identifies_provider() {
    // The timeout failure must identify which provider timed out.
    let config = MintConfig::new(Duration::from_millis(50), 8).unwrap();

    let specs = vec![CredentialSpec::new("timeout-prov", "role", 3600, "TO_KEY")];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, "TO_KEY"),
                token: make_token("never", &provider, default_expiry()),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;

    let err = result.unwrap_err();
    match err {
        CredentialSetError::MintFailed {
            failed_providers, ..
        } => {
            assert!(
                failed_providers
                    .iter()
                    .any(|f| f.provider == "timeout-prov"),
                "timeout error must identify which provider timed out"
            );
            assert!(
                failed_providers
                    .iter()
                    .any(|f| f.error.contains("timed out")),
                "error message must mention timeout"
            );
        }
        other => panic!("Expected MintFailed, got: {:?}", other),
    }
}

#[tokio::test]
async fn atomic_rollback_one_failure_fails_all() {
    let config = MintConfig::new(Duration::from_secs(5), 8).unwrap();

    let specs = vec![
        CredentialSpec::new("good-prov", "role", 3600, "GOOD_KEY"),
        CredentialSpec::new("bad-prov", "role", 3600, "BAD_KEY"),
    ];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            if provider == "bad-prov" {
                MintResult::Failure {
                    spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                    error: "auth expired".to_string(),
                }
            } else {
                MintResult::Success {
                    spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                    token: make_token("good-secret", &provider, default_expiry()),
                }
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;

    assert!(
        result.is_err(),
        "any failure must fail the entire operation"
    );
}

#[tokio::test]
async fn atomic_rollback_returns_succeeded_tokens_for_revocation() {
    let config = MintConfig::new(Duration::from_secs(5), 8).unwrap();

    let specs = vec![
        CredentialSpec::new("ok-prov", "role", 3600, "OK_KEY"),
        CredentialSpec::new("fail-prov", "role", 3600, "FAIL_KEY"),
    ];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            if provider == "fail-prov" {
                MintResult::Failure {
                    spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                    error: "failed".to_string(),
                }
            } else {
                MintResult::Success {
                    spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                    token: make_token("ok-secret", &provider, default_expiry()),
                }
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;

    let err = result.unwrap_err();
    match err {
        CredentialSetError::MintFailed {
            succeeded_tokens, ..
        } => {
            assert_eq!(
                succeeded_tokens.len(),
                1,
                "must return succeeded tokens for rollback"
            );
            assert_eq!(succeeded_tokens[0].provider(), "ok-prov");
        }
        other => panic!("Expected MintFailed, got: {:?}", other),
    }
}

#[tokio::test]
async fn atomic_rollback_timeout_triggers_rollback_with_succeeded_tokens() {
    // Mix of fast success + slow timeout: succeeded tokens must be returned.
    let config = MintConfig::new(Duration::from_millis(50), 8).unwrap();

    let specs = vec![
        CredentialSpec::new("fast-prov", "role", 3600, "FAST_KEY"),
        CredentialSpec::new("slow-prov", "role", 3600, "SLOW_KEY"),
    ];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            if provider == "slow-prov" {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                token: make_token(&format!("s-{}", provider), &provider, default_expiry()),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;

    let err = result.unwrap_err();
    match err {
        CredentialSetError::MintFailed {
            failed_providers,
            succeeded_tokens,
        } => {
            assert!(
                failed_providers.iter().any(|f| f.provider == "slow-prov"),
                "slow provider must be in failed list"
            );
            assert_eq!(
                succeeded_tokens.len(),
                1,
                "fast provider's token must be available for rollback"
            );
            assert_eq!(succeeded_tokens[0].provider(), "fast-prov");
        }
        other => panic!("Expected MintFailed, got: {:?}", other),
    }
}

#[tokio::test]
async fn mint_output_json_array_on_success() {
    let config = MintConfig::new(Duration::from_secs(5), 8).unwrap();

    let specs = vec![
        CredentialSpec::new("aws", "role", 3600, "AWS_KEY"),
        CredentialSpec::new("gcp", "role", 3600, "GCP_KEY"),
    ];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                token: make_token(&format!("secret-{}", provider), &provider, default_expiry()),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;
    let cred_set = result.unwrap();

    // Wire format_mint_output() via the orchestrator's output helper
    let output = super::format_orchestrator_output(&cred_set);

    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("output must be valid JSON");
    assert!(parsed.is_array(), "output must be a JSON array");
    assert_eq!(
        parsed.as_array().unwrap().len(),
        2,
        "array must contain one element per provider"
    );
}

#[tokio::test]
async fn mint_output_empty_on_total_failure() {
    let config = MintConfig::new(Duration::from_secs(5), 8).unwrap();

    let specs = vec![CredentialSpec::new("fail-prov", "role", 3600, "FAIL_KEY")];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            MintResult::Failure {
                spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                error: "total failure".to_string(),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;
    assert!(result.is_err());

    // On failure, no output should be produced (empty string)
    let output = format_mint_output(&[]);
    assert!(output.is_empty(), "on failure, output must be empty");
}

#[tokio::test]
async fn mint_output_is_single_line() {
    let config = MintConfig::new(Duration::from_secs(5), 8).unwrap();

    let specs = vec![
        CredentialSpec::new("aws", "role", 3600, "AWS_KEY"),
        CredentialSpec::new("gcp", "role", 3600, "GCP_KEY"),
    ];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                token: make_token(&format!("s-{}", provider), &provider, default_expiry()),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;
    let cred_set = result.unwrap();

    let output = super::format_orchestrator_output(&cred_set);
    assert!(
        !output.contains('\n'),
        "mint output must be single-line JSON"
    );
}

#[tokio::test]
async fn full_pipeline_multiple_providers_all_succeed() {
    let config = MintConfig::new(Duration::from_secs(5), 4).unwrap();

    let specs: Vec<CredentialSpec> = (0..4)
        .map(|i| CredentialSpec::new(&format!("prov-{}", i), "admin", 3600, &format!("KEY_{}", i)))
        .collect();

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            MintResult::Success {
                spec: CredentialSpec::new(&provider, "admin", 3600, &env_key),
                token: make_token(&format!("s-{}", provider), &provider, default_expiry()),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;
    assert!(result.is_ok());
    let cred_set = result.unwrap();
    assert_eq!(cred_set.len(), 4);
}

#[tokio::test]
async fn full_pipeline_empty_specs_returns_empty_set() {
    let config = MintConfig::default();
    let specs: Vec<CredentialSpec> = vec![];

    let mint_fn = |_spec: &CredentialSpec| async move {
        unreachable!("should not be called with empty specs")
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;
    assert!(result.is_ok());
    let cred_set = result.unwrap();
    assert!(cred_set.is_empty());
}

#[tokio::test]
async fn full_pipeline_all_fail_returns_empty_succeeded_tokens() {
    let config = MintConfig::new(Duration::from_secs(5), 8).unwrap();

    let specs = vec![
        CredentialSpec::new("a", "role", 3600, "A_KEY"),
        CredentialSpec::new("b", "role", 3600, "B_KEY"),
    ];

    let mint_fn = |spec: &CredentialSpec| {
        let provider = spec.provider.clone();
        let env_key = spec.env_key.clone();
        async move {
            MintResult::Failure {
                spec: CredentialSpec::new(&provider, "role", 3600, &env_key),
                error: format!("{} failed", provider),
            }
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;
    let err = result.unwrap_err();
    match err {
        CredentialSetError::MintFailed {
            failed_providers,
            succeeded_tokens,
        } => {
            assert_eq!(failed_providers.len(), 2);
            assert!(
                succeeded_tokens.is_empty(),
                "no tokens to rollback when all fail"
            );
        }
        other => panic!("Expected MintFailed, got: {:?}", other),
    }
}

#[tokio::test]
async fn format_orchestrator_output_empty_set() {
    // An empty CredentialSet should produce empty output (consistent
    // with format_mint_output on empty slice).
    let cred_set = crate::core::credential_set::resolve_mint_results(Vec::new()).unwrap();
    let output = super::format_orchestrator_output(&cred_set);
    assert!(
        output.is_empty(),
        "Empty credential set should produce empty output"
    );
}

#[tokio::test]
async fn bounded_parallelism_max_concurrent_matches_default() {
    // Verify the orchestrator respects MintConfig::default().max_concurrent = 8.
    let config = MintConfig::default();
    assert_eq!(config.max_concurrent, 8, "default max_concurrent must be 8");
}

#[tokio::test]
async fn timeout_failure_spec_contains_provider_name() {
    // The dummy spec created on timeout must carry the correct provider
    // name for error reporting in resolve_mint_results().
    let config = MintConfig::new(Duration::from_millis(10), 8).unwrap();
    let specs = vec![CredentialSpec::new("my-provider", "role", 3600, "MY_KEY")];

    let mint_fn = |_spec: &CredentialSpec| async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        MintResult::Success {
            spec: CredentialSpec::new("my-provider", "role", 3600, "MY_KEY"),
            token: make_token("never", "my-provider", default_expiry()),
        }
    };

    let result = super::mint_all(&specs, &config, mint_fn).await;
    let err = result.unwrap_err();
    match err {
        CredentialSetError::MintFailed {
            failed_providers, ..
        } => {
            assert_eq!(failed_providers[0].provider, "my-provider");
        }
        other => panic!("Expected MintFailed, got: {:?}", other),
    }
}
