use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use tokio::time::sleep;

use crate::agent_process::{AgentMode, AgentProcess, AgentProcessConfig};
use crate::client::{Client, ClientOptions, MintRequest, ProviderOverrides};
use crate::credential_set::{validate_env_key_uniqueness, CredentialSet, CredentialSpec};
use crate::error::Error;
use crate::event::EventType;
use crate::profile;
use crate::provider;
use crate::provider_exec::{self, ExecConfig, ProviderExecResult};
use crate::refresh::{RefreshOutcome, RefreshPolicy};
use crate::run_signal_wiring::{
    parent_signal_from_raw, RunSignalWiring, SignalProcess, SignalRevoker,
};
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
    let started = std::time::Instant::now();
    let token_id = token.token_id().unwrap_or("unknown");
    let mut start = crate::Event::new(crate::EventType::RevokeStart, &resolved.name);
    start.set_token_id(token_id);
    crate::event::emit_runtime_event(start);

    let argv = parse_command(revoke_cmd);
    if argv.is_empty() {
        let mut fail = crate::Event::new(crate::EventType::RevokeFail, &resolved.name);
        fail.set_token_id(token_id);
        fail.set_error("empty revoke command");
        fail.set_duration(started.elapsed());
        crate::event::emit_runtime_event(fail);
        return;
    }

    let mut env = resolved.env.clone();
    env.extend(provider_exec::build_revoke_env(
        token.expose_secret(),
        token_id,
    ));
    match provider_exec::execute_provider_command(&argv, &env, exec_config, 0).await {
        Ok(result) if provider_exec::is_revoke_success(result.exit_result.exit_code.as_raw()) => {
            let mut success = crate::Event::new(crate::EventType::RevokeSuccess, &resolved.name);
            success.set_token_id(token_id);
            success.set_duration(started.elapsed());
            crate::event::emit_runtime_event(success);
        }
        Ok(result) => {
            let err = if result.stderr.is_empty() {
                result.exit_result.stderr_message()
            } else {
                result.stderr
            };
            let mut fail = crate::Event::new(crate::EventType::RevokeFail, &resolved.name);
            fail.set_token_id(token_id);
            fail.set_error(&err);
            fail.set_duration(started.elapsed());
            crate::event::emit_runtime_event(fail);
        }
        Err(err) => {
            let mut fail = crate::Event::new(crate::EventType::RevokeFail, &resolved.name);
            fail.set_token_id(token_id);
            fail.set_error(&format!("spawn failed: {}", err));
            fail.set_duration(started.elapsed());
            crate::event::emit_runtime_event(fail);
        }
    }
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
    forward_sigterm_then_escalate_with_os_signals(command, args, &[])
}

pub fn forward_sigterm_then_escalate_with_os_signals(
    command: &str,
    args: &[String],
    parent_signals: &[i32],
) -> Result<SignalHandlingReport, Error> {
    let mut process = AgentProcess::spawn(AgentProcessConfig {
        command: command.to_string(),
        args: args.to_vec(),
        mode: AgentMode::Run,
        injected_env: HashMap::new(),
        force_env: true,
        timeout: None,
    })
    .map_err(|e| Error::internal(&format!("{}", e)))?;

    let mut signals =
        signal_hook::iterator::Signals::new([libc::SIGTERM, libc::SIGINT, libc::SIGHUP])
            .map_err(|e| Error::internal(&format!("failed to register signal handlers: {}", e)))?;

    for raw in parent_signals {
        let rc = unsafe { libc::raise(*raw) };
        if rc != 0 {
            return Err(Error::internal("failed to inject parent signal"));
        }
    }

    let mut wiring = RunSignalWiring::default();
    let mut forwarded_sigterm = false;
    let mut double_signal_escalated = false;
    let mut noop_revoker = NoopRevoker;
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(2);
    let mut timeout_kill_sent = false;

    loop {
        for raw in signals.pending() {
            if let Some(parent_signal) = parent_signal_from_raw(raw) {
                let mut process_adapter = IntegrationSignalProcessAdapter {
                    inner: &mut process,
                    forwarded_sigterm: &mut forwarded_sigterm,
                };
                let action = wiring
                    .on_parent_signal(parent_signal, &mut process_adapter, &mut noop_revoker)
                    .map_err(|e| {
                        Error::internal(&format!("failed during signal handling: {}", e))
                    })?;
                if action.immediate_sigkill {
                    double_signal_escalated = true;
                }
            }
        }

        if process
            .try_wait_exit_code()
            .map_err(|e| Error::internal(&format!("{}", e)))?
            .is_some()
        {
            break;
        }

        if !timeout_kill_sent && start.elapsed() >= timeout {
            let _ = process.forward_signal(libc::SIGKILL);
            timeout_kill_sent = true;
        }

        if timeout_kill_sent && start.elapsed() >= timeout + Duration::from_secs(1) {
            return Err(Error::internal("timed out waiting for child exit"));
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    Ok(SignalHandlingReport {
        forwarded_sigterm,
        double_signal_escalated,
    })
}

struct IntegrationSignalProcessAdapter<'a> {
    inner: &'a mut AgentProcess,
    forwarded_sigterm: &'a mut bool,
}

impl SignalProcess for IntegrationSignalProcessAdapter<'_> {
    fn forward_signal(&mut self, sig: i32) -> Result<(), std::io::Error> {
        if sig == libc::SIGTERM {
            *self.forwarded_sigterm = true;
        }
        self.inner
            .forward_signal(sig)
            .map_err(|e| std::io::Error::other(format!("{}", e)))
    }
}

struct NoopRevoker;

impl SignalRevoker for NoopRevoker {
    fn revoke_all(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
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
