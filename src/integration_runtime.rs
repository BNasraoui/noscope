use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use tokio::time::sleep;

use crate::agent_process::{AgentMode, AgentProcess, AgentProcessConfig};
use crate::client::{Client, ClientOptions, MintRequest, ProviderOverrides};
use crate::credential_set::{CredentialSet, CredentialSpec, validate_env_key_uniqueness};
use crate::error::Error;
use crate::event::EventType;
use crate::profile;
use crate::provider;
use crate::provider_exec::{self, ExecConfig, ProviderExecResult};
use crate::refresh::{RefreshOutcome, RefreshPolicy};
use crate::signal_policy::{ParentSignal, SignalHandlingPolicy};
use crate::token::ScopedToken;
use crate::token_convert::provider_output_to_scoped_token;

pub struct IntegrationRuntimeConfig {
    pub xdg_config_home: PathBuf,
    pub exec_timeout: Duration,
    pub kill_grace_period: Duration,
}

pub struct MintRefreshRevokeReport {
    pub minted: usize,
    pub refreshed: usize,
    pub revoked: usize,
    pub event_types: Vec<EventType>,
}

pub struct AtomicMintReport {
    pub rollback_attempts: usize,
}

pub struct SignalHandlingReport {
    pub forwarded_sigterm: bool,
    pub double_signal_escalated: bool,
}

fn parse_command(command: &str) -> Vec<String> {
    match shlex::split(command) {
        Some(parts) => parts,
        None => command
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
    }
}

fn make_exec_config(cfg: &IntegrationRuntimeConfig) -> ExecConfig {
    ExecConfig {
        timeout: cfg.exec_timeout,
        kill_grace_period: cfg.kill_grace_period,
    }
}

fn make_client(cfg: &IntegrationRuntimeConfig) -> Client {
    Client::new_best_effort(ClientOptions {
        xdg_config_home: Some(cfg.xdg_config_home.clone()),
        ..ClientOptions::default()
    })
}

fn resolve_provider_for(
    cfg: &IntegrationRuntimeConfig,
    provider_name: &str,
    overrides: &ProviderOverrides,
) -> Result<provider::ResolvedProvider, Error> {
    let client = make_client(cfg);
    client.resolve_provider(provider_name, overrides)
}

async fn mint_one(
    resolved: &provider::ResolvedProvider,
    role: &str,
    ttl_secs: u64,
    exec_config: &ExecConfig,
) -> Result<ScopedToken, Error> {
    let argv = parse_command(&resolved.mint_cmd);
    if argv.is_empty() {
        return Err(Error::provider(&resolved.name, "empty mint command"));
    }

    let mut env = resolved.env.clone();
    env.insert("NOSCOPE_PROVIDER".to_string(), resolved.name.clone());
    env.insert("NOSCOPE_ROLE".to_string(), role.to_string());

    let result = provider_exec::execute_provider_command(&argv, &env, exec_config, ttl_secs)
        .await
        .map_err(|e| Error::provider(&resolved.name, &format!("spawn failed: {}", e)))?;

    let output = result
        .parsed_output
        .map_err(|e| Error::provider(&resolved.name, &format!("{}", e)))?;

    let token_id = format!("tok-{}", resolved.name);
    Ok(provider_output_to_scoped_token(
        output,
        role,
        Some(token_id),
        &resolved.name,
    ))
}

async fn revoke_token(
    resolved: &provider::ResolvedProvider,
    token: &ScopedToken,
    exec_config: &ExecConfig,
) {
    let Some(revoke_cmd) = &resolved.revoke_cmd else {
        return;
    };
    let argv = parse_command(revoke_cmd);
    if argv.is_empty() {
        return;
    }
    let token_id = token.token_id().unwrap_or("unknown");
    let mut env = resolved.env.clone();
    env.extend(provider_exec::build_revoke_env(
        token.expose_secret(),
        token_id,
    ));
    let _ = provider_exec::execute_provider_command(&argv, &env, exec_config, 0).await;
}

pub async fn mint_refresh_revoke_cycle(
    cfg: &IntegrationRuntimeConfig,
    provider_name: &str,
    role: &str,
    ttl_secs: u64,
) -> Result<MintRefreshRevokeReport, Error> {
    let exec_config = make_exec_config(cfg);
    let resolved = resolve_provider_for(cfg, provider_name, &ProviderOverrides::default())?;
    let mut event_types = Vec::new();

    event_types.push(EventType::MintStart);
    let mut minted = 0usize;
    let mut refreshed = 0usize;
    let mut revoked = 0usize;

    let token = match mint_one(&resolved, role, ttl_secs, &exec_config).await {
        Ok(token) => {
            minted += 1;
            event_types.push(EventType::MintSuccess);
            token
        }
        Err(err) => {
            event_types.push(EventType::MintFail);
            return Err(err);
        }
    };

    if let Some(refresh_cmd) = &resolved.refresh_cmd {
        event_types.push(EventType::RefreshStart);
        let argv = parse_command(refresh_cmd);
        let mut env = resolved.env.clone();
        env.extend(provider_exec::build_refresh_env(
            token.expose_secret(),
            token.token_id().unwrap_or("unknown"),
            ttl_secs,
        ));
        env.insert("NOSCOPE_PROVIDER".to_string(), resolved.name.clone());

        let refresh_result =
            provider_exec::execute_provider_command(&argv, &env, &exec_config, ttl_secs)
                .await
                .map_err(|e| Error::provider(&resolved.name, &format!("spawn failed: {}", e)))?;

        match refresh_result.parsed_output {
            Ok(_) => {
                refreshed += 1;
                event_types.push(EventType::RefreshSuccess);
            }
            Err(e) => {
                event_types.push(EventType::RefreshFail);
                return Err(Error::provider(&resolved.name, &format!("{}", e)));
            }
        }
    }

    if resolved.revoke_cmd.is_some() {
        event_types.push(EventType::RevokeStart);
        revoke_token(&resolved, &token, &exec_config).await;
        revoked += 1;
        event_types.push(EventType::RevokeSuccess);
    }

    Ok(MintRefreshRevokeReport {
        minted,
        refreshed,
        revoked,
        event_types,
    })
}

pub async fn atomic_mint(
    cfg: &IntegrationRuntimeConfig,
    req: &MintRequest,
    overrides: &ProviderOverrides,
) -> Result<CredentialSet, Error> {
    let exec_config = make_exec_config(cfg);
    let mut succeeded: Vec<(provider::ResolvedProvider, CredentialSpec, ScopedToken)> = Vec::new();

    for provider_name in &req.providers {
        let resolved = resolve_provider_for(cfg, provider_name, overrides)?;
        let env_key = format!("{}_TOKEN", provider_name.to_uppercase());
        let spec = CredentialSpec::new(provider_name, &req.role, req.ttl_secs, &env_key);

        match mint_one(&resolved, &req.role, req.ttl_secs, &exec_config).await {
            Ok(token) => succeeded.push((resolved, spec, token)),
            Err(err) => {
                for (ok_resolved, _, ok_token) in &succeeded {
                    revoke_token(ok_resolved, ok_token, &exec_config).await;
                }
                return Err(err);
            }
        }
    }

    let entries: Vec<(CredentialSpec, ScopedToken)> = succeeded
        .into_iter()
        .map(|(_, spec, token)| (spec, token))
        .collect();

    let specs: Vec<CredentialSpec> = entries
        .iter()
        .map(|(spec, _)| {
            CredentialSpec::new(&spec.provider, &spec.role, spec.ttl_secs, &spec.env_key)
        })
        .collect();
    validate_env_key_uniqueness(&specs).map_err(|e| Error::config(&format!("{}", e)))?;

    Ok(CredentialSet::new(entries))
}

pub async fn atomic_mint_with_report(
    cfg: &IntegrationRuntimeConfig,
    req: &MintRequest,
    overrides: &ProviderOverrides,
) -> Result<AtomicMintReport, Error> {
    let exec_config = make_exec_config(cfg);
    let mut rollback_attempts = 0usize;
    let mut succeeded: Vec<(provider::ResolvedProvider, ScopedToken)> = Vec::new();

    for provider_name in &req.providers {
        let resolved = resolve_provider_for(cfg, provider_name, overrides)?;
        match mint_one(&resolved, &req.role, req.ttl_secs, &exec_config).await {
            Ok(token) => succeeded.push((resolved, token)),
            Err(_) => {
                for (ok_resolved, ok_token) in &succeeded {
                    rollback_attempts += 1;
                    revoke_token(ok_resolved, ok_token, &exec_config).await;
                }
                return Ok(AtomicMintReport { rollback_attempts });
            }
        }
    }

    Ok(AtomicMintReport { rollback_attempts })
}

pub async fn mint_profile(
    cfg: &IntegrationRuntimeConfig,
    profile_name: &str,
) -> Result<CredentialSet, Error> {
    let path = profile::profile_config_path(profile_name, Some(&cfg.xdg_config_home))?;
    let prof = profile::load_profile(&path)?;
    let exec_config = make_exec_config(cfg);

    let mut entries = Vec::new();
    for (idx, cred) in prof.credentials.iter().enumerate() {
        let resolved = resolve_provider_for(cfg, &cred.provider, &ProviderOverrides::default())?;
        let env_key = cred
            .env_key
            .clone()
            .unwrap_or_else(|| format!("{}_TOKEN_{}", cred.provider.to_uppercase(), idx));
        let spec = CredentialSpec::new(&cred.provider, &cred.role, cred.ttl, &env_key);
        let token = mint_one(&resolved, &cred.role, cred.ttl, &exec_config).await?;
        entries.push((spec, token));
    }

    Ok(CredentialSet::new(entries))
}

pub fn refresh_schedule_outcomes(
    set: &CredentialSet,
    remaining_lifetime: Duration,
) -> Vec<RefreshOutcome> {
    let schedules = set.refresh_schedules();
    let policy = RefreshPolicy::default();
    schedules
        .iter()
        .map(|_s| policy.on_refresh_failure(0, remaining_lifetime))
        .collect()
}

pub fn run_child_and_pass_exit(
    command: &str,
    args: &[String],
    env: HashMap<String, String>,
) -> Result<i32, Error> {
    let mut process = AgentProcess::spawn(AgentProcessConfig {
        command: command.to_string(),
        args: args.to_vec(),
        mode: AgentMode::Run,
        injected_env: env,
        force_env: true,
        timeout: None,
    })
    .map_err(|e| Error::internal(&format!("{}", e)))?;

    process
        .wait_with_revoke(|| Ok(()))
        .map_err(|e| Error::internal(&format!("{}", e)))
}

pub fn forward_sigterm_then_escalate(
    command: &str,
    args: &[String],
) -> Result<SignalHandlingReport, Error> {
    let mut process = AgentProcess::spawn(AgentProcessConfig {
        command: command.to_string(),
        args: args.to_vec(),
        mode: AgentMode::Run,
        injected_env: HashMap::new(),
        force_env: true,
        timeout: Some(Duration::from_secs(2)),
    })
    .map_err(|e| Error::internal(&format!("{}", e)))?;

    process
        .forward_signal(libc::SIGTERM)
        .map_err(|e| Error::internal(&format!("{}", e)))?;

    let mut policy = SignalHandlingPolicy::default();
    let _ = policy.on_shutdown_signal(ParentSignal::Sigterm);
    let decision = policy.on_shutdown_signal(ParentSignal::Sigint);
    if decision.immediate_sigkill {
        let _ = process.forward_signal(libc::SIGKILL);
    }

    let _ = process.wait_with_revoke(|| Ok(()));

    Ok(SignalHandlingReport {
        forwarded_sigterm: true,
        double_signal_escalated: decision.immediate_sigkill,
    })
}

pub async fn execute_provider_with_timeout(
    argv: &[String],
    timeout: Duration,
    kill_grace_period: Duration,
) -> Result<ProviderExecResult, std::io::Error> {
    let config = ExecConfig {
        timeout,
        kill_grace_period,
    };
    let result =
        provider_exec::execute_provider_command(argv, &HashMap::new(), &config, 3600).await?;

    // Give the OS a moment to reap process-group state in slow CI environments.
    sleep(Duration::from_millis(5)).await;
    let _ = Utc::now();

    Ok(result)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_command_preserves_quoted_segments() {
        let argv = super::parse_command("/bin/sh -c 'printf hello world'");
        assert_eq!(argv[0], "/bin/sh");
        assert_eq!(argv[1], "-c");
        assert_eq!(argv[2], "printf hello world");
    }
}
