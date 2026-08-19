// Atomic multi-credential minting (orchestrator integration)
// Parallel minting timeout (per-provider, via ExecConfig)
// Atomic rollback follows revocation budget
// Bounded parallelism for provider operations
// Mint mode JSON array output (format_mint_output wiring)

use std::future::Future;
use std::time::Instant;

use tokio::sync::Semaphore;

use crate::core::credential_set::{
    format_timeout_error, resolve_mint_results, CredentialSet, CredentialSetError, CredentialSpec,
    MintConfig, MintResult,
};
use crate::core::mint::{format_mint_output, MintEnvelope};
use crate::core::token_convert::scoped_token_to_mint_envelope;
use crate::ports::event::{emit_runtime_event, Event, EventType};
use provenance_macros::rule;

/// Execute provider mint operations in parallel
/// with bounded concurrency and per-provider timeouts.
///   using a tokio semaphore.
///   `config.per_provider_timeout`. Exceeding the timeout produces a
///   `MintResult::Failure`.
///   enforces atomic all-or-nothing semantics — any failure causes the
///   entire operation to fail, returning succeeded tokens for rollback.
/// The `mint_fn` closure takes a `&CredentialSpec` and returns a future
/// that resolves to a `MintResult`. This allows the caller to inject
/// arbitrary provider execution logic (subprocess, mock, etc.).
#[rule("rule_orchestration_bounded_concurrency")]
#[rule("rule_orchestration_per_provider_timeout")]
pub async fn mint_all<F, Fut>(
    specs: &[CredentialSpec],
    config: &MintConfig,
    mint_fn: F,
) -> Result<CredentialSet, CredentialSetError>
where
    F: Fn(&CredentialSpec) -> Fut,
    Fut: Future<Output = MintResult> + Send + 'static,
{
    if specs.is_empty() {
        return resolve_mint_results(Vec::new());
    }

    // Semaphore limits concurrency to max_concurrent.
    let semaphore = std::sync::Arc::new(Semaphore::new(config.max_concurrent));
    let timeout = config.per_provider_timeout;

    let mut handles = Vec::with_capacity(specs.len());

    for spec in specs {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore should never be closed during mint_all");

        let provider_name = spec.provider.clone();
        let env_key = spec.env_key.clone();
        let fut = mint_fn(spec);

        let handle = tokio::spawn(async move {
            emit_runtime_event(Event::new(EventType::MintStart, &provider_name));
            let started = Instant::now();

            // Per-provider timeout.
            let result = tokio::time::timeout(timeout, fut).await;

            // Drop the permit to free the semaphore slot.
            drop(permit);

            match result {
                Ok(mint_result) => {
                    let mut event = match &mint_result {
                        MintResult::Success { token, .. } => {
                            let mut event = Event::new(EventType::MintSuccess, &provider_name);
                            if let Some(token_id) = token.token_id() {
                                event.set_token_id(token_id);
                            }
                            event
                        }
                        MintResult::Failure { error, .. } => {
                            let mut event = Event::new(EventType::MintFail, &provider_name);
                            event.set_error(error);
                            event
                        }
                    };
                    event.set_duration(started.elapsed());
                    emit_runtime_event(event);
                    mint_result
                }
                Err(_elapsed) => {
                    // Timeout produces a failure result.
                    // The spec is reconstructed with minimal fields — only
                    // `provider` and `env_key` are used by resolve_mint_results()
                    // for error reporting. Role and TTL are not relevant here.
                    let timeout_error = format_timeout_error(&provider_name, timeout);
                    let mut event = Event::new(EventType::MintFail, &provider_name);
                    event.set_error(&timeout_error);
                    event.set_duration(started.elapsed());
                    emit_runtime_event(event);

                    MintResult::Failure {
                        spec: CredentialSpec::new(&provider_name, "", 0, &env_key),
                        error: timeout_error,
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Collect all results.
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        let result = handle.await.expect("mint task should not panic");
        results.push(result);
    }

    // Atomic resolution — any failure fails the entire operation
    // and returns succeeded tokens for rollback.
    resolve_mint_results(results)
}

/// Format orchestrator output as a JSON array for stdout.
/// Converts a successful `CredentialSet` into a JSON array of mint envelopes
/// via `format_mint_output()`. Each credential becomes one envelope in the
/// array.
pub fn format_orchestrator_output(cred_set: &CredentialSet) -> String {
    let envelopes: Vec<MintEnvelope> = cred_set
        .tokens()
        .map(scoped_token_to_mint_envelope)
        .collect();

    format_mint_output(&envelopes)
}

#[cfg(test)]
mod tests;
