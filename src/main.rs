// noscope-9l0: Binary entrypoint.
//
// This is a thin wrapper that delegates to the library's CLI module.
// All parsing, dispatch, and error handling logic lives in noscope::cli
// (NS-075: CLI parsing in adapter layer).

use std::future::Future;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use noscope::cli::{self, Command};
use noscope::credential_set::{CredentialSpec, MintConfig, MintResult};
use noscope::run_signal_wiring::{
    parent_signal_from_raw, RunSignalWiring, SignalProcess, SignalRevoker,
};
use noscope::signal_policy::{
    ActiveCredential, RevocationBudget, RevocationResultKind, SignalHandlingPolicy,
};
use noscope::{Client, ClientOptions, ProviderOverrides};

fn main() -> ExitCode {
    let cli = match cli::parse_from_args(std::env::args_os()) {
        Ok(cli) => cli,
        Err(err) => {
            // clap errors include --help and --version (which write to
            // stdout and exit 0) and actual parse errors (exit 2).
            err.exit();
        }
    };

    match run(cli) {
        // NS-054: All noscope exit codes are sysexits.h values (0-78)
        // which fit in u8. Child exit codes are 0-255 on Unix.
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("noscope: {}", err);
            ExitCode::from(cli::error_to_exit_code(&err) as u8)
        }
    }
}

/// NS-074: Dispatch subcommands through the Client facade.
fn run(cli: cli::Cli) -> Result<i32, noscope::Error> {
    match cli.command {
        Command::Run(args) => cmd_run(args, cli.verbose),
        Command::Mint(args) => cmd_mint(args, cli.verbose),
        Command::Revoke(args) => cmd_revoke(args, cli.verbose),
        Command::Validate(args) => cmd_validate(args),
        Command::DryRun(args) => cmd_dry_run(args),
        Command::Completions(args) => {
            cmd_completions(args);
            Ok(cli::SUCCESS_EXIT_CODE)
        }
    }
}

fn cmd_run(args: cli::RunArgs, verbose: bool) -> Result<i32, noscope::Error> {
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let client = Client::new(ClientOptions {
        verbose,
        xdg_config_home,
        ..ClientOptions::default()
    })?;

    let (specs, resolved_by_name) = resolve_run_specs_and_providers(&client, &args)?;
    let resolved_by_name = std::sync::Arc::new(resolved_by_name);
    if args.child_args.is_empty() {
        return Err(noscope::Error::usage("missing child command"));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| noscope::Error::internal(&format!("failed creating async runtime: {}", e)))?;

    let config = MintConfig::new(Duration::from_secs(30), 8)?;
    let resolved_for_mint = std::sync::Arc::clone(&resolved_by_name);
    let mint_result = runtime.block_on(async {
        noscope::orchestrator::mint_all(&specs, &config, move |spec| {
            let provider = resolved_for_mint
                .get(&spec.provider)
                .expect("resolved provider must exist for every credential spec");
            let provider_name = provider.name.clone();
            let mint_cmd = provider.mint_cmd.clone();
            let provider_env = provider.env.clone();
            let spec_provider = spec.provider.clone();
            let spec_role = spec.role.clone();
            let spec_ttl = spec.ttl_secs;
            let spec_env_key = spec.env_key.clone();
            async move {
                let spec_for_result =
                    CredentialSpec::new(&spec_provider, &spec_role, spec_ttl, &spec_env_key);
                let argv = parse_command(&mint_cmd);
                if argv.is_empty() {
                    return MintResult::Failure {
                        spec: spec_for_result,
                        error: "empty mint command".to_string(),
                    };
                }

                let mut env = provider_env;
                env.insert("NOSCOPE_PROVIDER".to_string(), provider_name.clone());
                env.insert("NOSCOPE_ROLE".to_string(), spec_role.clone());
                let rendered_argv =
                    noscope::provider_exec::substitute_template_vars(&argv, &spec_role, spec_ttl);

                match noscope::provider_exec::execute_provider_command(
                    &rendered_argv,
                    &env,
                    &noscope::provider_exec::ExecConfig {
                        timeout: Duration::from_secs(30),
                        kill_grace_period: Duration::from_secs(5),
                    },
                    spec_ttl,
                )
                .await
                {
                    Ok(exec_result) => match exec_result.parsed_output {
                        Ok(output) => {
                            let token = noscope::token_convert::provider_output_to_scoped_token(
                                output,
                                &spec_role,
                                Some(format!("tok-{}", provider_name)),
                                &provider_name,
                            );
                            MintResult::Success {
                                spec: spec_for_result,
                                token,
                            }
                        }
                        Err(err) => MintResult::Failure {
                            spec: spec_for_result,
                            error: err.to_string(),
                        },
                    },
                    Err(err) => MintResult::Failure {
                        spec: spec_for_result,
                        error: format!("spawn failed: {}", err),
                    },
                }
            }
        })
        .await
    });

    let cred_set = match mint_result {
        Ok(cred_set) => cred_set,
        Err(noscope::credential_set::CredentialSetError::MintFailed {
            failed_providers,
            succeeded_tokens,
        }) => {
            runtime.block_on(revoke_run_credentials(
                resolved_by_name.as_ref(),
                &succeeded_tokens,
                noscope::credential_set::RollbackBudget::default(),
            ));
            return Err(noscope::Error::config(&format_mint_failed_providers(
                &failed_providers,
            )));
        }
        Err(other) => return Err(other.into()),
    };

    let env = cred_set
        .env_map()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let child_command = args.child_args[0].clone();
    let child_argv = args.child_args[1..].to_vec();
    let child_exit = run_child_with_os_signals(&child_command, &child_argv, env, || {
        revoke_on_shutdown_signal(&runtime, resolved_by_name.as_ref(), &cred_set);
        Ok(())
    })?;

    Ok(child_exit)
}

fn format_mint_failed_providers(failures: &[noscope::credential_set::MintFailure]) -> String {
    let details = failures
        .iter()
        .map(|failure| format!("provider '{}': {}", failure.provider, failure.error))
        .collect::<Vec<_>>()
        .join("; ");
    format!("credential minting failed: {}", details)
}

fn rollback_backoff_for_retry(retry: u32) -> Duration {
    const ROLLBACK_BASE_BACKOFF: Duration = Duration::from_millis(100);
    let factor = 2u32.saturating_pow(retry);
    ROLLBACK_BASE_BACKOFF.saturating_mul(factor)
}

async fn revoke_token_with_budget<RevokeFn, RevokeFut, SleepFn, SleepFut, LogFn>(
    token: &noscope::token::ScopedToken,
    budget: &noscope::credential_set::RollbackBudget,
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
                let entry = noscope::credential_set::RollbackLogEntry::revocation_failed(
                    credential_id,
                    provider,
                    expires_at,
                    "rollback revocation attempt timed out",
                );
                log_line(format!("{} attempt={}", entry.format_log(), attempt + 1));
                return;
            }
            Ok(Ok(())) => {
                let entry = noscope::credential_set::RollbackLogEntry::new(
                    credential_id,
                    provider,
                    expires_at,
                );
                log_line(format!("{} attempt={}", entry.format_log(), attempt + 1));
                return;
            }
            Ok(Err(err)) => {
                let entry = noscope::credential_set::RollbackLogEntry::revocation_failed(
                    credential_id,
                    provider,
                    expires_at,
                    &err,
                );
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

async fn revoke_run_credentials(
    resolved_by_name: &std::collections::HashMap<String, noscope::provider::ResolvedProvider>,
    succeeded_tokens: &[noscope::token::ScopedToken],
    budget: noscope::credential_set::RollbackBudget,
) {
    for token in succeeded_tokens {
        let provider = token.provider().to_string();
        let credential_id = token.token_id().unwrap_or("unknown").to_string();

        let Some(resolved) = resolved_by_name.get(provider.as_str()) else {
            let entry = noscope::credential_set::RollbackLogEntry::revocation_failed(
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
                let input = noscope::mint::RevokeInput::from_token_id_and_provider(
                    &credential_id,
                    &provider,
                );
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

fn run_child_with_os_signals<F>(
    command: &str,
    args: &[String],
    env: std::collections::HashMap<String, String>,
    mut revoke_all: F,
) -> Result<i32, noscope::Error>
where
    F: FnMut() -> Result<(), noscope::Error>,
{
    let mut process = match noscope::agent_process::AgentProcess::spawn(
        noscope::agent_process::AgentProcessConfig {
            command: command.to_string(),
            args: args.to_vec(),
            mode: noscope::agent_process::AgentMode::Run,
            injected_env: env,
            force_env: true,
            timeout: None,
        },
    ) {
        Ok(process) => process,
        Err(e) => {
            let _ = revoke_all();
            return Err(noscope::Error::internal(&format!("{}", e)));
        }
    };

    let mut signals =
        signal_hook::iterator::Signals::new([libc::SIGTERM, libc::SIGINT, libc::SIGHUP]).map_err(
            |e| noscope::Error::internal(&format!("failed to register signal handlers: {}", e)),
        )?;

    let mut wiring = RunSignalWiring::default();

    loop {
        for raw in signals.pending() {
            if let Some(parent_signal) = parent_signal_from_raw(raw) {
                let mut process_adapter = AgentProcessSignalAdapter {
                    inner: &mut process,
                };
                let mut revoker = ClosureRevoker {
                    revoke_all: &mut revoke_all,
                };

                wiring
                    .on_parent_signal(parent_signal, &mut process_adapter, &mut revoker)
                    .map_err(|e| {
                        noscope::Error::internal(&format!("failed during signal handling: {}", e))
                    })?;
            }
        }

        if let Some(exit_code) = process
            .try_wait_exit_code()
            .map_err(|e| noscope::Error::internal(&format!("{}", e)))?
        {
            if !wiring.revoke_attempted() {
                revoke_all()?;
            }
            return Ok(exit_code);
        }

        std::thread::sleep(Duration::from_millis(20));
    }
}

struct AgentProcessSignalAdapter<'a> {
    inner: &'a mut noscope::agent_process::AgentProcess,
}

impl SignalProcess for AgentProcessSignalAdapter<'_> {
    fn forward_signal(&mut self, sig: i32) -> Result<(), std::io::Error> {
        self.inner
            .forward_signal(sig)
            .map_err(|e| std::io::Error::other(format!("{}", e)))
    }
}

struct ClosureRevoker<'a, F>
where
    F: FnMut() -> Result<(), noscope::Error>,
{
    revoke_all: &'a mut F,
}

impl<F> SignalRevoker for ClosureRevoker<'_, F>
where
    F: FnMut() -> Result<(), noscope::Error>,
{
    fn revoke_all(&mut self) -> Result<(), std::io::Error> {
        (self.revoke_all)().map_err(|e| std::io::Error::other(e.to_string()))
    }
}

fn resolve_run_specs_and_providers(
    client: &Client,
    args: &cli::RunArgs,
) -> Result<
    (
        Vec<noscope::credential_set::CredentialSpec>,
        std::collections::HashMap<String, noscope::provider::ResolvedProvider>,
    ),
    noscope::Error,
> {
    if let Some(profile_name) = &args.profile {
        return resolve_profile_run_specs_and_providers(client, profile_name);
    }

    let req = noscope::MintRequest {
        providers: args.provider.clone(),
        role: args.role.clone(),
        ttl_secs: args.ttl,
    };
    client.validate_mint(&req)?;

    let mut resolved_by_name = std::collections::HashMap::new();
    let mut specs = Vec::with_capacity(req.providers.len());
    for provider_name in &req.providers {
        let resolved = client.resolve_provider(provider_name, &ProviderOverrides::default())?;
        specs.push(CredentialSpec::new(
            provider_name,
            &req.role,
            req.ttl_secs,
            &format!("{}_TOKEN", provider_name.to_uppercase()),
        ));
        resolved_by_name.insert(provider_name.clone(), resolved);
    }
    Ok((specs, resolved_by_name))
}

fn resolve_profile_run_specs_and_providers(
    client: &Client,
    profile_name: &str,
) -> Result<
    (
        Vec<noscope::credential_set::CredentialSpec>,
        std::collections::HashMap<String, noscope::provider::ResolvedProvider>,
    ),
    noscope::Error,
> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let path = noscope::profile::profile_config_path(profile_name, xdg.as_deref())?;
    let profile = noscope::profile::load_profile(&path)?;

    let mut specs = Vec::with_capacity(profile.credentials.len());
    let mut resolved_by_name = std::collections::HashMap::new();
    for (idx, cred) in profile.credentials.iter().enumerate() {
        let resolved = client.resolve_provider(&cred.provider, &ProviderOverrides::default())?;
        let env_key = cred
            .env_key
            .clone()
            .unwrap_or_else(|| format!("{}_TOKEN_{}", cred.provider.to_uppercase(), idx));
        specs.push(CredentialSpec::new(
            &cred.provider,
            &cred.role,
            cred.ttl,
            &env_key,
        ));
        resolved_by_name
            .entry(cred.provider.clone())
            .or_insert(resolved);
    }
    Ok((specs, resolved_by_name))
}

fn revoke_on_shutdown_signal(
    runtime: &tokio::runtime::Runtime,
    resolved_by_name: &std::collections::HashMap<String, noscope::provider::ResolvedProvider>,
    cred_set: &noscope::credential_set::CredentialSet,
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

                    let input = noscope::mint::RevokeInput::from_token_id_and_provider(
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

fn cmd_mint(args: cli::MintArgs, verbose: bool) -> Result<i32, noscope::Error> {
    use std::io::IsTerminal;

    let client = Client::new(ClientOptions {
        verbose,
        force_terminal: args.force_terminal,
        ..ClientOptions::default()
    })?;

    let req = noscope::MintRequest {
        providers: args.provider,
        role: args.role,
        ttl_secs: args.ttl,
    };
    client.validate_mint(&req)?;

    client.check_stdout_not_terminal(std::io::stdout().is_terminal())?;

    let mut resolved_by_name = std::collections::HashMap::new();
    let mut specs = Vec::with_capacity(req.providers.len());
    for provider_name in &req.providers {
        let resolved = client.resolve_provider(provider_name, &ProviderOverrides::default())?;
        specs.push(CredentialSpec::new(
            provider_name,
            &req.role,
            req.ttl_secs,
            &format!("{}_TOKEN", provider_name.to_uppercase()),
        ));
        resolved_by_name.insert(provider_name.clone(), resolved);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| noscope::Error::internal(&format!("failed creating async runtime: {}", e)))?;

    let role = req.role.clone();
    let ttl_secs = req.ttl_secs;
    let cred_set = runtime.block_on(async {
        let config = MintConfig::new(Duration::from_secs(30), 8)?;
        noscope::orchestrator::mint_all(&specs, &config, move |spec| {
            let provider = resolved_by_name
                .get(&spec.provider)
                .expect("resolved provider must exist for every credential spec");
            let provider_name = provider.name.clone();
            let mint_cmd = provider.mint_cmd.clone();
            let provider_env = provider.env.clone();
            let role = role.clone();
            let spec_provider = spec.provider.clone();
            let spec_role = spec.role.clone();
            let spec_ttl = spec.ttl_secs;
            let spec_env_key = spec.env_key.clone();
            async move {
                let spec_for_result =
                    CredentialSpec::new(&spec_provider, &spec_role, spec_ttl, &spec_env_key);
                let argv = parse_command(&mint_cmd);
                if argv.is_empty() {
                    return MintResult::Failure {
                        spec: spec_for_result,
                        error: "empty mint command".to_string(),
                    };
                }

                let mut env = provider_env;
                env.insert("NOSCOPE_PROVIDER".to_string(), provider_name.clone());
                env.insert("NOSCOPE_ROLE".to_string(), role.clone());
                let rendered_argv =
                    noscope::provider_exec::substitute_template_vars(&argv, &role, ttl_secs);

                match noscope::provider_exec::execute_provider_command(
                    &rendered_argv,
                    &env,
                    &noscope::provider_exec::ExecConfig {
                        timeout: Duration::from_secs(30),
                        kill_grace_period: Duration::from_secs(5),
                    },
                    ttl_secs,
                )
                .await
                {
                    Ok(exec_result) => match exec_result.parsed_output {
                        Ok(output) => {
                            let token = noscope::token_convert::provider_output_to_scoped_token(
                                output,
                                &role,
                                Some(format!("tok-{}", provider_name)),
                                &provider_name,
                            );
                            MintResult::Success {
                                spec: spec_for_result,
                                token,
                            }
                        }
                        Err(err) => MintResult::Failure {
                            spec: spec_for_result,
                            error: err.to_string(),
                        },
                    },
                    Err(err) => MintResult::Failure {
                        spec: spec_for_result,
                        error: format!("spawn failed: {}", err),
                    },
                }
            }
        })
        .await
    })?;

    println!(
        "{}",
        noscope::orchestrator::format_orchestrator_output(&cred_set)
    );
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_revoke(args: cli::RevokeArgs, _verbose: bool) -> Result<i32, noscope::Error> {
    let client = Client::new(ClientOptions::default())?;

    let stdin_payload = if args.from_stdin {
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut raw)
            .map_err(|e| noscope::Error::usage(&format!("failed reading stdin: {}", e)))?;
        raw
    } else {
        String::new()
    };

    let input = build_revoke_input(&args, &stdin_payload)?;
    let resolved = client.resolve_provider(input.provider(), &ProviderOverrides::default())?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| noscope::Error::internal(&format!("failed creating async runtime: {}", e)))?;
    runtime.block_on(execute_revoke(&resolved, &input))?;

    eprintln!(
        "{}",
        format_revoke_result(input.provider(), input.token_id())
    );
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn build_revoke_input(
    args: &cli::RevokeArgs,
    stdin_payload: &str,
) -> Result<noscope::mint::RevokeInput, noscope::Error> {
    if args.from_stdin {
        return noscope::mint::RevokeInput::from_mint_json(stdin_payload)
            .map_err(noscope::Error::from);
    }

    let token_id = args.token_id.as_deref().ok_or_else(|| {
        noscope::Error::usage("--token-id is required unless --from-stdin is set")
    })?;
    let provider = args.provider.as_deref().ok_or_else(|| {
        noscope::Error::usage("--provider is required unless --from-stdin is set")
    })?;

    Ok(noscope::mint::RevokeInput::from_token_id_and_provider(
        token_id, provider,
    ))
}

async fn execute_revoke(
    resolved: &noscope::provider::ResolvedProvider,
    input: &noscope::mint::RevokeInput,
) -> Result<(), noscope::Error> {
    let revoke_cmd = resolved.revoke_cmd.as_deref().ok_or_else(|| {
        noscope::Error::provider(&resolved.name, "provider does not define a revoke command")
    })?;
    let argv = parse_command(revoke_cmd);
    if argv.is_empty() {
        return Err(noscope::Error::provider(
            &resolved.name,
            "empty revoke command",
        ));
    }

    let mut env = resolved.env.clone();
    env.extend(noscope::provider_exec::build_revoke_env(
        "",
        input.token_id(),
    ));

    let exec_result = noscope::provider_exec::execute_provider_command(
        &argv,
        &env,
        &noscope::provider_exec::ExecConfig {
            timeout: Duration::from_secs(30),
            kill_grace_period: Duration::from_secs(5),
        },
        0,
    )
    .await
    .map_err(|e| noscope::Error::provider(&resolved.name, &format!("spawn failed: {}", e)))?;

    if noscope::provider_exec::is_revoke_success(exec_result.exit_result.exit_code.as_raw()) {
        Ok(())
    } else {
        let stderr = if exec_result.stderr.is_empty() {
            exec_result.exit_result.stderr_message()
        } else {
            exec_result.stderr
        };
        Err(noscope::Error::provider(
            &resolved.name,
            &format!("revoke failed for token {}: {}", input.token_id(), stderr),
        ))
    }
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

fn format_revoke_result(provider: &str, token_id: &str) -> String {
    format!(
        "noscope: revoked token {} for provider {}",
        token_id, provider
    )
}

fn cmd_validate(args: cli::ValidateArgs) -> Result<i32, noscope::Error> {
    let client = Client::new(ClientOptions::default())?;
    let _resolved = client.resolve_provider(&args.provider, &ProviderOverrides::default())?;

    eprintln!(
        "noscope: provider '{}' configuration is valid",
        args.provider
    );
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_dry_run(args: cli::DryRunArgs) -> Result<i32, noscope::Error> {
    let client = Client::new(ClientOptions::default())?;
    let resolved = client.resolve_provider(&args.provider, &ProviderOverrides::default())?;
    let output = client.dry_run(&resolved, &args.role, args.ttl);
    println!("{}", output);
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_completions(args: cli::CompletionsArgs) {
    use clap::CommandFactory;
    clap_complete::generate(
        args.shell,
        &mut cli::Cli::command(),
        "noscope",
        &mut std::io::stdout(),
    );
}

#[cfg(test)]
mod revoke_wiring_tests {
    use super::*;

    #[test]
    fn revoke_cli_parses_token_id_and_provider_flags() {
        let cli = cli::parse_from_args([
            "noscope",
            "revoke",
            "--token-id",
            "tok-123",
            "--provider",
            "aws",
        ])
        .unwrap();

        match cli.command {
            Command::Revoke(args) => {
                assert_eq!(args.token_id.as_deref(), Some("tok-123"));
                assert_eq!(args.provider.as_deref(), Some("aws"));
                assert!(!args.from_stdin);
            }
            _ => panic!("expected revoke command"),
        }
    }

    #[test]
    fn revoke_cli_parses_from_stdin_flag() {
        let cli = cli::parse_from_args(["noscope", "revoke", "--from-stdin"]).unwrap();

        match cli.command {
            Command::Revoke(args) => {
                assert_eq!(args.token_id, None);
                assert_eq!(args.provider, None);
                assert!(args.from_stdin);
            }
            _ => panic!("expected revoke command"),
        }
    }

    #[test]
    fn revoke_builds_revoke_input_from_flags() {
        let args = cli::RevokeArgs {
            token_id: Some("tok-123".to_string()),
            provider: Some("aws".to_string()),
            from_stdin: false,
        };

        let input = build_revoke_input(&args, "").unwrap();
        assert_eq!(input.token_id(), "tok-123");
        assert_eq!(input.provider(), "aws");
    }

    #[test]
    fn revoke_builds_revoke_input_from_stdin_json() {
        let args = cli::RevokeArgs {
            token_id: None,
            provider: None,
            from_stdin: true,
        };
        let stdin = r#"{"token":"secret","token_id":"tok-9","provider":"vault","role":"ops"}"#;

        let input = build_revoke_input(&args, stdin).unwrap();
        assert_eq!(input.token_id(), "tok-9");
        assert_eq!(input.provider(), "vault");
    }

    #[test]
    fn revoke_cli_rejects_from_stdin_with_explicit_flags() {
        let cli = cli::parse_from_args([
            "noscope",
            "revoke",
            "--from-stdin",
            "--token-id",
            "tok-1",
            "--provider",
            "aws",
        ]);
        assert!(
            cli.is_err(),
            "revoke must reject --from-stdin when explicit token/provider flags are present"
        );
    }

    #[tokio::test]
    async fn revoke_executes_provider_revoke_command() {
        let output_file = tempfile::NamedTempFile::new().unwrap();
        let script = format!(
            "printf %s \"$NOSCOPE_TOKEN_ID\" > {}; exit 0",
            output_file.path().display()
        );
        let resolved = noscope::provider::ResolvedProvider {
            name: "aws".to_string(),
            contract_version: None,
            mint_cmd: "true".to_string(),
            refresh_cmd: None,
            revoke_cmd: Some(format!("/bin/sh -c '{}'", script)),
            env: std::collections::HashMap::new(),
            source: noscope::provider::ConfigSource::Flags,
        };
        let input = noscope::mint::RevokeInput::from_token_id_and_provider("tok-777", "aws");

        execute_revoke(&resolved, &input).await.unwrap();

        let written = std::fs::read_to_string(output_file.path()).unwrap();
        assert_eq!(written, "tok-777");
    }

    #[test]
    fn revoke_reports_result_message() {
        let msg = format_revoke_result("aws", "tok-123");
        assert_eq!(msg, "noscope: revoked token tok-123 for provider aws");
    }
}

#[cfg(test)]
mod run_wiring_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn write_executable(path: &Path, script: &str) {
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn write_provider_config(
        xdg_config_home: &Path,
        provider_name: &str,
        mint_cmd: &str,
        revoke_cmd: &str,
    ) {
        let providers_dir = xdg_config_home.join("noscope").join("providers");
        fs::create_dir_all(&providers_dir).unwrap();
        let cfg = format!(
            "contract_version = 1\n\n[commands]\nmint = \"{}\"\nrevoke = \"{}\"\n",
            mint_cmd, revoke_cmd
        );
        let path = providers_dir.join(format!("{}.toml", provider_name));
        fs::write(&path, cfg).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn make_run_args(
        providers: Vec<String>,
        role: &str,
        ttl: u64,
        profile: Option<String>,
        child_args: Vec<String>,
    ) -> cli::RunArgs {
        cli::RunArgs {
            provider: providers,
            role: role.to_string(),
            ttl,
            profile,
            child_args,
        }
    }

    fn scoped_env<T>(key: &str, value: &Path, f: impl FnOnce() -> T) -> T {
        let old = std::env::var_os(key);
        // SAFETY: test-local env mutation, restored before return.
        unsafe {
            std::env::set_var(key, value);
        }
        let out = f();
        match old {
            Some(prev) => {
                // SAFETY: test-local env restoration.
                unsafe {
                    std::env::set_var(key, prev);
                }
            }
            None => {
                // SAFETY: test-local env restoration.
                unsafe {
                    std::env::remove_var(key);
                }
            }
        }
        out
    }

    #[test]
    fn run_resolves_providers_from_cli_args() {
        let args = make_run_args(
            vec!["missing-provider".to_string()],
            "admin",
            3600,
            None,
            vec!["/bin/true".to_string()],
        );

        let result = cmd_run(args, false);
        assert!(
            result.is_err(),
            "cmd_run must resolve providers and fail for unknown provider"
        );
    }

    #[test]
    fn run_resolves_providers_from_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let profile_dir = tmp.path().join("noscope").join("profiles");
        fs::create_dir_all(&profile_dir).unwrap();

        let child = tmp.path().join("child.sh");
        write_executable(&child, "#!/bin/sh\nexit 17\n");

        let mint_script = tmp.path().join("mint.sh");
        write_executable(
            &mint_script,
            "#!/bin/sh\nprintf '{\"token\":\"profile-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );
        let revoke_script = tmp.path().join("revoke.sh");
        write_executable(&revoke_script, "#!/bin/sh\nexit 0\n");

        write_provider_config(
            tmp.path(),
            "aws",
            mint_script.to_string_lossy().as_ref(),
            revoke_script.to_string_lossy().as_ref(),
        );

        fs::write(
            profile_dir.join("dev.toml"),
            "[[credentials]]\nprovider = \"aws\"\nrole = \"profile-role\"\nttl = 3600\n",
        )
        .unwrap();
        fs::set_permissions(
            profile_dir.join("dev.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let args = make_run_args(
            vec!["missing-provider".to_string()],
            "ignored-role",
            3600,
            Some("dev".to_string()),
            vec![child.to_string_lossy().to_string()],
        );

        let result = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
        assert_eq!(
            result.unwrap(),
            17,
            "cmd_run must resolve provider from profile and run child"
        );
    }

    #[test]
    fn run_mints_credentials_before_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let mint_marker = tmp.path().join("mint-called.txt");
        let child = tmp.path().join("child.sh");
        let mint = tmp.path().join("mint.sh");
        let revoke = tmp.path().join("revoke.sh");

        write_executable(
            &mint,
            &format!(
                "#!/bin/sh\nprintf called > '{}'\nprintf '{{\"token\":\"minted-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}}'\n",
                mint_marker.display()
            ),
        );
        write_executable(&revoke, "#!/bin/sh\nexit 0\n");
        write_executable(&child, "#!/bin/sh\nexit 0\n");

        write_provider_config(
            tmp.path(),
            "aws",
            mint.to_string_lossy().as_ref(),
            revoke.to_string_lossy().as_ref(),
        );

        let args = make_run_args(
            vec!["aws".to_string()],
            "admin",
            3600,
            None,
            vec![child.to_string_lossy().to_string()],
        );

        let _ = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
        assert!(
            mint_marker.exists(),
            "cmd_run must mint credentials before spawning child"
        );
    }

    #[test]
    fn run_spawns_child_with_injected_env_vars() {
        let tmp = tempfile::tempdir().unwrap();
        let child_out = tmp.path().join("child-env.txt");
        let child = tmp.path().join("child.sh");
        let mint = tmp.path().join("mint.sh");
        let revoke = tmp.path().join("revoke.sh");

        write_executable(
            &mint,
            "#!/bin/sh\nprintf '{\"token\":\"aws-env-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );
        write_executable(&revoke, "#!/bin/sh\nexit 0\n");
        write_executable(
            &child,
            &format!(
                "#!/bin/sh\nprintf %s \"$AWS_TOKEN\" > '{}'\nexit 0\n",
                child_out.display()
            ),
        );

        write_provider_config(
            tmp.path(),
            "aws",
            mint.to_string_lossy().as_ref(),
            revoke.to_string_lossy().as_ref(),
        );

        let args = make_run_args(
            vec!["aws".to_string()],
            "admin",
            3600,
            None,
            vec![child.to_string_lossy().to_string()],
        );

        let _ = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
        let injected = fs::read_to_string(&child_out).unwrap_or_default();
        assert_eq!(
            injected, "aws-env-secret",
            "cmd_run must spawn child with minted env vars"
        );
    }

    #[test]
    fn run_waits_for_exit_and_returns_child_code() {
        let tmp = tempfile::tempdir().unwrap();
        let child = tmp.path().join("child.sh");
        let mint = tmp.path().join("mint.sh");
        let revoke = tmp.path().join("revoke.sh");

        write_executable(
            &mint,
            "#!/bin/sh\nprintf '{\"token\":\"wait-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );
        write_executable(&revoke, "#!/bin/sh\nexit 0\n");
        write_executable(&child, "#!/bin/sh\nexit 37\n");

        write_provider_config(
            tmp.path(),
            "aws",
            mint.to_string_lossy().as_ref(),
            revoke.to_string_lossy().as_ref(),
        );

        let args = make_run_args(
            vec!["aws".to_string()],
            "admin",
            3600,
            None,
            vec![child.to_string_lossy().to_string()],
        );

        let exit = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false)).unwrap();
        assert_eq!(
            exit, 37,
            "cmd_run must wait for child and return child exit code"
        );
    }

    #[test]
    fn run_revokes_all_credentials_before_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let revoke_log = tmp.path().join("revoke.log");
        let child = tmp.path().join("child.sh");

        let mint_aws = tmp.path().join("mint-aws.sh");
        let mint_gcp = tmp.path().join("mint-gcp.sh");
        let revoke_aws = tmp.path().join("revoke-aws.sh");
        let revoke_gcp = tmp.path().join("revoke-gcp.sh");

        write_executable(
            &mint_aws,
            "#!/bin/sh\nprintf '{\"token\":\"aws-revoke-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );
        write_executable(
            &mint_gcp,
            "#!/bin/sh\nprintf '{\"token\":\"gcp-revoke-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );
        write_executable(
            &revoke_aws,
            &format!(
                "#!/bin/sh\nprintf '%s\n' \"$NOSCOPE_TOKEN_ID\" >> '{}'\nexit 0\n",
                revoke_log.display()
            ),
        );
        write_executable(
            &revoke_gcp,
            &format!(
                "#!/bin/sh\nprintf '%s\n' \"$NOSCOPE_TOKEN_ID\" >> '{}'\nexit 0\n",
                revoke_log.display()
            ),
        );
        write_executable(&child, "#!/bin/sh\nexit 0\n");

        write_provider_config(
            tmp.path(),
            "aws",
            mint_aws.to_string_lossy().as_ref(),
            revoke_aws.to_string_lossy().as_ref(),
        );
        write_provider_config(
            tmp.path(),
            "gcp",
            mint_gcp.to_string_lossy().as_ref(),
            revoke_gcp.to_string_lossy().as_ref(),
        );

        let args = make_run_args(
            vec!["aws".to_string(), "gcp".to_string()],
            "admin",
            3600,
            None,
            vec![child.to_string_lossy().to_string()],
        );

        let _ = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
        let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
        assert!(
            revoked.contains("tok-aws"),
            "cmd_run must revoke minted aws credential"
        );
        assert!(
            revoked.contains("tok-gcp"),
            "cmd_run must revoke minted gcp credential"
        );
    }

    #[test]
    fn run_revokes_credentials_if_child_fails_to_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let revoke_log = tmp.path().join("revoke.log");

        let mint = tmp.path().join("mint.sh");
        let revoke = tmp.path().join("revoke.sh");

        write_executable(
            &mint,
            "#!/bin/sh\nprintf '{\"token\":\"spawn-fail-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );
        write_executable(
            &revoke,
            &format!(
                "#!/bin/sh\nprintf '%s\n' \"$NOSCOPE_TOKEN_ID\" >> '{}'\nexit 0\n",
                revoke_log.display()
            ),
        );

        write_provider_config(
            tmp.path(),
            "aws",
            mint.to_string_lossy().as_ref(),
            revoke.to_string_lossy().as_ref(),
        );

        let args = make_run_args(
            vec!["aws".to_string()],
            "admin",
            3600,
            None,
            vec!["/definitely/not/a/real/command".to_string()],
        );

        let result = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
        assert!(
            result.is_err(),
            "cmd_run must return an error when child cannot be spawned"
        );

        let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
        assert!(
            revoked.contains("tok-aws"),
            "cmd_run must revoke minted credential when child spawn fails"
        );
    }
}

#[cfg(test)]
mod rollback_budget_wiring_tests {
    use super::*;
    use chrono::Utc;
    use secrecy::SecretString;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn make_token(provider: &str, token_id: &str) -> noscope::token::ScopedToken {
        noscope::token::ScopedToken::new(
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
        let budget = noscope::credential_set::RollbackBudget::default();
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
            "NS-047: failed revokes must retry"
        );
    }

    #[tokio::test]
    async fn atomic_rollback_follows_revocation_budget_enforces_wall_clock_budget() {
        let token = make_token("aws", "tok-aws");
        let budget = noscope::credential_set::RollbackBudget {
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
            "NS-047: wall clock budget must cap total retry attempts"
        );
    }

    #[tokio::test]
    async fn atomic_rollback_follows_revocation_budget_applies_exponential_backoff() {
        let token = make_token("aws", "tok-aws");
        let budget = noscope::credential_set::RollbackBudget {
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
            "NS-047: rollback retries must use exponential backoff"
        );
    }

    #[tokio::test]
    async fn atomic_rollback_follows_revocation_budget_logs_each_attempt() {
        let token = make_token("aws", "tok-aws");
        let budget = noscope::credential_set::RollbackBudget::default();

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
            "NS-047: every rollback attempt must emit a rollback log entry"
        );
        assert!(
            lines.iter().all(|line| {
                line.contains("rollback:")
                    && line.contains("provider=aws")
                    && line.contains("credential_id=tok-aws")
            }),
            "NS-047: logs must use RollbackLogEntry format"
        );
    }

    #[tokio::test]
    async fn atomic_rollback_follows_revocation_budget_zero_disables_retries() {
        let token = make_token("aws", "tok-aws");
        let budget = noscope::credential_set::RollbackBudget {
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
            "NS-047: budget=0 must disable rollback retries"
        );
    }

    #[tokio::test]
    async fn atomic_rollback_follows_revocation_budget_attempt_timeout_logs_failure() {
        let token = make_token("aws", "tok-aws");
        let budget = noscope::credential_set::RollbackBudget {
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
            "NS-047: a timed-out attempt should consume budget and stop further retries"
        );
        let lines = logs.lock().unwrap().clone();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("timed out"),
            "NS-047: timed-out rollback attempts should be logged as failures"
        );
    }
}
