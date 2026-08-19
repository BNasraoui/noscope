// The single revoke execution path.
//
// Revocation addresses a lease by identifier: the provider receives
// NOSCOPE_TOKEN_ID and never the credential value
// (res_revoke_contract_identifier_only). Used by `noscope revoke`, by
// rollback after a failed atomic mint (NS-047), and by shutdown-signal
// revocation in run mode (NS-003).

use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, Instant};

use crate::command_parse::parse_command;
use crate::credential_set::{CredentialSet, RollbackBudget, RollbackLogEntry};
use crate::error::Error;
use crate::event::{emit_runtime_event, Event, EventType};
use crate::mint::RevokeInput;
use crate::provider::ResolvedProvider;
use crate::provider_exec::{self, ExecConfig};
use crate::signal_policy::{
    ActiveCredential, RevocationBudget, RevocationResultKind, SignalHandlingPolicy,
};
use crate::token::ScopedToken;

/// Build a RevokeInput from CLI arguments.
pub fn revoke_input_from_cli(
    from_stdin: bool,
    stdin_payload: &str,
    token_id: Option<&str>,
    provider: Option<&str>,
) -> Result<RevokeInput, Error> {
    if from_stdin {
        return RevokeInput::from_mint_json(stdin_payload).map_err(Error::from);
    }

    let token_id = token_id
        .ok_or_else(|| Error::usage("--token-id is required unless --from-stdin is set"))?;
    let provider = provider
        .ok_or_else(|| Error::usage("--provider is required unless --from-stdin is set"))?;

    Ok(RevokeInput::from_token_id_and_provider(token_id, provider))
}

/// Execute a provider's revoke command for one lease.
pub async fn execute_revoke(resolved: &ResolvedProvider, input: &RevokeInput) -> Result<(), Error> {
    let emit_revoke_fail = |message: &str, started: Instant| {
        let mut event = Event::new(EventType::RevokeFail, &resolved.name);
        event.set_token_id(input.token_id());
        event.set_error(message);
        event.set_duration(started.elapsed());
        emit_runtime_event(event);
    };

    let started = Instant::now();
    let mut revoke_start = Event::new(EventType::RevokeStart, &resolved.name);
    revoke_start.set_token_id(input.token_id());
    emit_runtime_event(revoke_start);

    let revoke_cmd = match resolved.revoke_cmd.as_deref() {
        Some(cmd) => cmd,
        None => {
            let message = "provider does not define a revoke command";
            emit_revoke_fail(message, started);
            return Err(Error::provider(&resolved.name, message));
        }
    };
    let argv = parse_command(revoke_cmd);
    if argv.is_empty() {
        let message = "empty revoke command";
        emit_revoke_fail(message, started);
        return Err(Error::provider(&resolved.name, message));
    }

    let mut env = resolved.env.clone();
    env.extend(provider_exec::build_revoke_env(input.token_id()));

    let exec_result = provider_exec::execute_provider_command(
        &argv,
        &env,
        &ExecConfig {
            timeout: Duration::from_secs(30),
            kill_grace_period: Duration::from_secs(5),
        },
        0,
    )
    .await
    .map_err(|e| {
        let message = format!("spawn failed: {}", e);
        emit_revoke_fail(&message, started);
        Error::provider(&resolved.name, &message)
    })?;

    if provider_exec::is_revoke_success(exec_result.exit_result.exit_code.as_raw()) {
        let mut event = Event::new(EventType::RevokeSuccess, &resolved.name);
        event.set_token_id(input.token_id());
        event.set_duration(started.elapsed());
        emit_runtime_event(event);
        Ok(())
    } else {
        let stderr = if exec_result.stderr.is_empty() {
            exec_result.exit_result.stderr_message()
        } else {
            exec_result.stderr
        };
        let mut event = Event::new(EventType::RevokeFail, &resolved.name);
        event.set_token_id(input.token_id());
        event.set_error(&stderr);
        event.set_duration(started.elapsed());
        emit_runtime_event(event);
        Err(Error::provider(
            &resolved.name,
            &format!("revoke failed for token {}: {}", input.token_id(), stderr),
        ))
    }
}

/// Format the operator-facing success line for `noscope revoke`.
pub fn format_revoke_result(provider: &str, token_id: &str) -> String {
    format!(
        "noscope: revoked token {} for provider {}",
        token_id, provider
    )
}

fn rollback_backoff_for_retry(retry: u32) -> Duration {
    const ROLLBACK_BASE_BACKOFF: Duration = Duration::from_millis(100);
    let factor = 2u32.saturating_pow(retry);
    ROLLBACK_BASE_BACKOFF.saturating_mul(factor)
}

/// NS-047: Revoke one token within the rollback budget, with retries and
/// exponential backoff. Injectable revoke/sleep/log for testability.
pub async fn revoke_token_with_budget<RevokeFn, RevokeFut, SleepFn, SleepFut, LogFn>(
    token: &ScopedToken,
    budget: &RollbackBudget,
    mut revoke_once: RevokeFn,
    mut sleep_fn: SleepFn,
    mut log_line: LogFn,
) where
    RevokeFn: FnMut() -> RevokeFut,
    RevokeFut: Future<Output = Result<(), String>>,
    SleepFn: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
    LogFn: FnMut(String),
{
    if budget.revoke_timeout.is_zero() {
        return;
    }

    let started = Instant::now();
    let provider = token.provider();
    let credential_id = token.token_id().unwrap_or("unknown");
    let expires_at = token.expires_at();

    for attempt in 0..=budget.max_retries {
        let elapsed = started.elapsed();
        if elapsed >= budget.revoke_timeout {
            return;
        }

        let remaining = budget.revoke_timeout.saturating_sub(elapsed);

        match tokio::time::timeout(remaining, revoke_once()).await {
            Err(_) => {
                let entry = RollbackLogEntry::revocation_failed(
                    credential_id,
                    provider,
                    expires_at,
                    "rollback revocation attempt timed out",
                );
                log_line(format!("{} attempt={}", entry.format_log(), attempt + 1));
                return;
            }
            Ok(Ok(())) => {
                let entry = RollbackLogEntry::new(credential_id, provider, expires_at);
                log_line(format!("{} attempt={}", entry.format_log(), attempt + 1));
                return;
            }
            Ok(Err(err)) => {
                let entry =
                    RollbackLogEntry::revocation_failed(credential_id, provider, expires_at, &err);
                log_line(format!("{} attempt={}", entry.format_log(), attempt + 1));
            }
        }

        if attempt == budget.max_retries {
            return;
        }

        let backoff = rollback_backoff_for_retry(attempt);
        if started.elapsed().saturating_add(backoff) >= budget.revoke_timeout {
            return;
        }
        sleep_fn(backoff).await;
    }
}

/// NS-047: Roll back already-minted tokens after a failed atomic mint.
pub async fn revoke_minted_tokens(
    resolved_by_name: &HashMap<String, ResolvedProvider>,
    succeeded_tokens: &[ScopedToken],
    budget: RollbackBudget,
) {
    for token in succeeded_tokens {
        let provider = token.provider().to_string();
        let credential_id = token.token_id().unwrap_or("unknown").to_string();

        let Some(resolved) = resolved_by_name.get(provider.as_str()) else {
            let entry = RollbackLogEntry::revocation_failed(
                &credential_id,
                &provider,
                token.expires_at(),
                "provider missing during rollback",
            );
            eprintln!("{} attempt=1", entry.format_log());
            continue;
        };

        revoke_token_with_budget(
            token,
            &budget,
            || {
                let input = RevokeInput::from_token_id_and_provider(&credential_id, &provider);
                async move {
                    execute_revoke(resolved, &input)
                        .await
                        .map_err(|err| err.to_string())
                }
            },
            |delay| async move {
                tokio::time::sleep(delay).await;
            },
            |line| eprintln!("{}", line),
        )
        .await;
    }
}

/// NS-003: Revoke every credential in the set on a shutdown signal.
pub fn revoke_on_shutdown_signal(
    runtime: &tokio::runtime::Runtime,
    resolved_by_name: &HashMap<String, ResolvedProvider>,
    cred_set: &CredentialSet,
) {
    let credentials: Vec<ActiveCredential> = cred_set
        .tokens()
        .map(|token| {
            let provider = token.provider();
            let credential_id = token
                .token_id()
                .map(str::to_string)
                .unwrap_or_else(|| format!("tok-{}", provider));
            ActiveCredential::new(&credential_id, provider)
        })
        .collect();

    let resolved_by_name = resolved_by_name.clone();

    runtime.block_on(async {
        let policy = SignalHandlingPolicy::default();
        let results = policy
            .revoke_all_on_signal(credentials, RevocationBudget::default(), move |cred| {
                let resolved_by_name = resolved_by_name.clone();
                async move {
                    let Some(resolved) = resolved_by_name.get(&cred.provider) else {
                        return RevocationResultKind::Failed(format!(
                            "provider '{}' missing during signal revocation",
                            cred.provider
                        ));
                    };

                    let input = RevokeInput::from_token_id_and_provider(
                        &cred.credential_id,
                        &cred.provider,
                    );

                    match execute_revoke(resolved, &input).await {
                        Ok(()) => RevocationResultKind::Revoked,
                        Err(err) => RevocationResultKind::Failed(err.to_string()),
                    }
                }
            })
            .await;

        for result in results {
            if let RevocationResultKind::Failed(err) = result.kind {
                eprintln!(
                    "noscope: revoke failed for provider {}: {}",
                    result.provider, err
                );
            }
        }
    });
}
