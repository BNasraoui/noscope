// Child supervision.
// Spawns the child with injected credentials, forwards parent signals
//, revokes on shutdown, passes the child exit
// code through, and drives the per-credential refresh loop
// with log-only expiry
// handling. Refresh activates for every credential whose
// provider defines a refresh command (res_refresh_subsystem_ships).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use secrecy::SecretString;

use crate::agent_process::{AgentMode, AgentProcess, AgentProcessConfig};
use crate::app::revoke::revoke_on_shutdown_signal;
use crate::command_parse::parse_command;
use crate::credential_set::{CredentialSet, ExpiryAction, ExpiryPolicy};
use crate::error::Error;
use crate::provider::ResolvedProvider;
use crate::provider_exec::{self, ExecConfig};
use crate::refresh::{LeaseRefreshKind, RefreshRuntimeLoop, RuntimeCredential};
use crate::run_signal_wiring::{
    dispatch_pending_parent_signals, RunSignalWiring, SignalProcess, SignalRevoker,
};
use crate::token::ScopedToken;
use crate::token_convert::provider_output_to_scoped_token;

/// Adapts AgentProcess to the SignalProcess trait for signal forwarding.
pub struct AgentProcessSignalAdapter<'a> {
    pub inner: &'a mut AgentProcess,
}

impl SignalProcess for AgentProcessSignalAdapter<'_> {
    fn forward_signal(&mut self, sig: i32) -> Result<(), std::io::Error> {
        self.inner
            .forward_signal(sig)
            .map_err(|e| std::io::Error::other(format!("{}", e)))
    }
}

/// Adapts a revoke closure to the SignalRevoker trait.
pub struct ClosureRevoker<'a, F>
where
    F: FnMut() -> Result<(), Error>,
{
    pub revoke_all: &'a mut F,
}

impl<F> SignalRevoker for ClosureRevoker<'_, F>
where
    F: FnMut() -> Result<(), Error>,
{
    fn revoke_all(&mut self) -> Result<(), std::io::Error> {
        (self.revoke_all)().map_err(|e| std::io::Error::other(e.to_string()))
    }
}

/// Supervise a child process for the lifetime of the credential set.
pub fn run_supervised(
    child_command: &str,
    child_args: &[String],
    runtime: &tokio::runtime::Runtime,
    resolved_by_name: &Arc<HashMap<String, ResolvedProvider>>,
    cred_set: &CredentialSet,
) -> Result<i32, Error> {
    let env = cred_set
        .env_map()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut revoke_all = || {
        revoke_on_shutdown_signal(runtime, resolved_by_name.as_ref(), cred_set);
        Ok(())
    };

    // Env keys whose lease the refresh loop manages. Their expiry moves
    // with each successful refresh, so the static warning below
    // would be wrong for them; refresh failures already reach the
    // operator as RefreshFail events.
    let refresh_managed: HashSet<String> = cred_set
        .entries()
        .filter(|(spec, _)| {
            resolved_by_name
                .get(&spec.provider)
                .is_some_and(|resolved| resolved.refresh_cmd.is_some())
        })
        .map(|(spec, _)| spec.env_key.clone())
        .collect();

    let mut refresh_loop = build_refresh_loop(resolved_by_name, cred_set);
    if let Some(refresh) = refresh_loop.as_mut() {
        // env injection happens once at spawn; a refreshed
        // credential never reaches the running child.
        let mut warnings = Vec::new();
        refresh.startup(true, &mut warnings);
        for warning in warnings {
            eprintln!("noscope: {}", warning);
        }
    }

    let mut process = match AgentProcess::spawn(AgentProcessConfig {
        command: child_command.to_string(),
        args: child_args.to_vec(),
        mode: AgentMode::Run,
        injected_env: env,
        force_env: true,
        timeout: None,
    }) {
        Ok(process) => process,
        Err(e) => {
            let _ = revoke_all();
            return Err(Error::internal(&format!("{}", e)));
        }
    };

    let mut signals =
        signal_hook::iterator::Signals::new([libc::SIGTERM, libc::SIGINT, libc::SIGHUP])
            .map_err(|e| Error::internal(&format!("failed to register signal handlers: {}", e)))?;

    let mut wiring = RunSignalWiring::default();
    let mut process_adapter = AgentProcessSignalAdapter {
        inner: &mut process,
    };
    let expiry_policy = ExpiryPolicy;
    let mut expiry_warned: HashSet<String> = HashSet::new();

    loop {
        let mut revoker = ClosureRevoker {
            revoke_all: &mut revoke_all,
        };
        dispatch_pending_parent_signals(
            signals.pending(),
            &mut wiring,
            &mut process_adapter,
            &mut revoker,
        )
        .map_err(|e| Error::internal(&format!("failed during signal handling: {}", e)))?;

        if let Some(exit_code) = process_adapter
            .inner
            .try_wait_exit_code()
            .map_err(|e| Error::internal(&format!("{}", e)))?
        {
            if !wiring.revoke_attempted() {
                revoke_all()?;
            }
            return Ok(exit_code);
        }

        let now = Utc::now();
        if let Some(refresh) = refresh_loop.as_mut() {
            if matches!(refresh.next_wake_delay(now), Some(delay) if delay.is_zero()) {
                run_refresh_tick(refresh, runtime, resolved_by_name, cred_set, now);
            }
        }
        warn_expired_credentials(
            cred_set,
            &refresh_managed,
            &expiry_policy,
            &mut expiry_warned,
            now,
        );

        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Build the refresh loop over every credential whose provider defines a
/// refresh command. Returns None when no provider supports refresh.
fn build_refresh_loop(
    resolved_by_name: &HashMap<String, ResolvedProvider>,
    cred_set: &CredentialSet,
) -> Option<RefreshRuntimeLoop> {
    let credentials: Vec<RuntimeCredential> = cred_set
        .entries()
        .filter(|(spec, _)| {
            resolved_by_name
                .get(&spec.provider)
                .is_some_and(|resolved| resolved.refresh_cmd.is_some())
        })
        .map(|(spec, token)| {
            let credential_id = token
                .token_id()
                .map(str::to_string)
                .unwrap_or_else(|| format!("tok-{}", spec.provider));
            // The refresh runtime tracks its own copy of the lease. The
            // child's injected env is immutable after spawn.
            let token_copy = ScopedToken::new(
                SecretString::from(token.expose_secret().to_string()),
                token.role(),
                token.expires_at(),
                token.token_id().map(str::to_string),
                &spec.provider,
            );
            RuntimeCredential::new(&credential_id, &spec.provider, &spec.env_key, token_copy)
        })
        .collect();

    if credentials.is_empty() {
        None
    } else {
        Some(RefreshRuntimeLoop::new(credentials))
    }
}

/// Execute one refresh tick: invoke the provider refresh command for every
/// due credential and record the outcomes.
fn run_refresh_tick(
    refresh: &mut RefreshRuntimeLoop,
    runtime: &tokio::runtime::Runtime,
    resolved_by_name: &Arc<HashMap<String, ResolvedProvider>>,
    cred_set: &CredentialSet,
    now: chrono::DateTime<Utc>,
) {
    let spec_by_env_key: HashMap<String, (String, u64)> = cred_set
        .entries()
        .map(|(spec, _)| (spec.env_key.clone(), (spec.role.clone(), spec.ttl_secs)))
        .collect();

    let events = runtime.block_on(refresh.run_once(now, true, |request| {
        let resolved_by_name = Arc::clone(resolved_by_name);
        let (role, ttl_secs) = spec_by_env_key
            .get(&request.env_key)
            .cloned()
            .unwrap_or_else(|| (String::new(), 0));
        async move {
            let resolved = resolved_by_name
                .get(&request.provider)
                .ok_or_else(|| format!("provider '{}' missing during refresh", request.provider))?;
            let refresh_cmd = resolved
                .refresh_cmd
                .as_deref()
                .ok_or("provider does not define a refresh command")?;
            let argv = parse_command(refresh_cmd);
            if argv.is_empty() {
                return Err("empty refresh command".to_string());
            }

            let mut env = resolved.env.clone();
            // the refresh command receives the current credential
            // value, the lease identifier, and the granted TTL in seconds.
            env.extend(provider_exec::build_refresh_env(
                &request.token_value,
                request.token_id.as_deref().unwrap_or("unknown"),
                ttl_secs,
            ));
            env.insert("NOSCOPE_PROVIDER".to_string(), request.provider.clone());

            let result = provider_exec::execute_provider_command(
                &argv,
                &env,
                &ExecConfig::default(),
                ttl_secs,
            )
            .await
            .map_err(|e| format!("spawn failed: {}", e))?;
            let output = result.parsed_output.map_err(|e| e.to_string())?;

            Ok(provider_output_to_scoped_token(
                output,
                &role,
                Some(request.credential_id.clone()),
                &request.provider,
            ))
        }
    }));

    for event in events {
        if let Ok(LeaseRefreshKind::Rotation) = event.outcome {
            // A rotation invalidates the child's injected value.
            eprintln!(
                "noscope: refresh rotated credential {}; the running child still \
                 holds the previous value",
                event.credential_id
            );
        }
    }
}

/// Warn once per expired credential. Never stops the child and
/// never re-mints.
fn warn_expired_credentials(
    cred_set: &CredentialSet,
    refresh_managed: &HashSet<String>,
    policy: &ExpiryPolicy,
    warned: &mut HashSet<String>,
    now: chrono::DateTime<Utc>,
) {
    for (spec, token) in cred_set.entries() {
        if refresh_managed.contains(&spec.env_key) || token.expires_at() > now {
            continue;
        }
        let token_id = token.token_id().unwrap_or("unknown");
        let key = format!("{}:{}", spec.provider, token_id);
        if !warned.insert(key) {
            continue;
        }
        if let ExpiryAction::LogWarning { message } =
            policy.on_credential_expired(&spec.provider, token_id)
        {
            eprintln!("noscope: {}", message);
        }
    }
}
