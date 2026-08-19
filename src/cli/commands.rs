// The command handlers behind the noscope binary. `run_cli` is the
// whole entry point; the binary itself only calls it.

/// Binary entry point: parse the CLI, dispatch, map errors to exit codes.
pub fn run_cli() -> ExitCode {
    let cli = match cli::parse_from_args(std::env::args_os()) {
        Ok(cli) => cli,
        Err(err) => {
            // clap errors include --help and --version (which write to
            // stdout and exit 0) and actual parse errors (exit 2).
            err.exit();
        }
    };

    let output_format = cli.output;
    let command_name = command_name(&cli.command);

    match run(cli) {
        // All noscope exit codes are sysexits.h values (0-78)
        // which fit in u8. Child exit codes are 0-255 on Unix.
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            match output_format {
                cli::OutputFormat::Text => eprintln!("noscope: {}", err),
                cli::OutputFormat::Json => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "status": "error",
                            "command": command_name,
                            "kind": err.kind().as_str(),
                            "message": err.message(),
                        })
                    );
                }
            }
            ExitCode::from(cli::error_to_exit_code(&err) as u8)
        }
    }
}

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crate::app::mint::format_mint_failed_providers;
use crate::app::resolve::CredentialSource;
use crate::app::revoke::{
    execute_revoke, format_revoke_result, revoke_inputs_from_cli, revoke_minted_tokens,
};
use crate::cli::{self, Command};
use crate::{Client, ClientOptions, ProviderOverrides};
use provenance_macros::rule;

#[rule("rule_errors_json_error_object")]

/// Dispatch subcommands through the Client facade.
fn run(cli: cli::Cli) -> Result<i32, crate::Error> {
    match cli.command {
        Command::Run(args) => cmd_run(args, cli.verbose),
        Command::Mint(args) => cmd_mint(args, cli.verbose),
        Command::Revoke(args) => cmd_revoke(args, cli.verbose, cli.output),
        Command::Validate(args) => cmd_validate(args, cli.output),
        Command::DryRun(args) => cmd_dry_run(args, cli.output),
        Command::Doctor(_args) => cmd_doctor(cli.output),
        Command::Init(_args) => cmd_init(cli.output),
        Command::Completions(args) => {
            cmd_completions(args);
            Ok(cli::SUCCESS_EXIT_CODE)
        }
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Run(_) => "run",
        Command::Mint(_) => "mint",
        Command::Revoke(_) => "revoke",
        Command::Validate(_) => "validate",
        Command::DryRun(_) => "dry-run",
        Command::Doctor(_) => "doctor",
        Command::Init(_) => "init",
        Command::Completions(_) => "completions",
    }
}

fn cmd_run(args: cli::RunArgs, verbose: bool) -> Result<i32, crate::Error> {
    let log_format = crate::LogFormat::parse(&args.log_format)
        .ok_or_else(|| crate::Error::usage("--log-format must be 'json' or 'text'"))?;
    let _runtime_emitter_guard = crate::ports::event::install_runtime_emitter(
        crate::ports::event::EventEmitter::new(log_format),
    );

    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let client = Client::new(ClientOptions {
        verbose,
        xdg_config_home: xdg_config_home.clone(),
        ..ClientOptions::default()
    })?;

    let source = CredentialSource::from_cli(
        args.profile.clone(),
        args.provider.clone(),
        args.role.clone(),
        args.ttl,
        args.env_key.clone(),
    )?;
    let (specs, resolved_by_name) = crate::app::resolve::resolve_specs_and_providers(
        &client,
        &source,
        xdg_config_home.as_deref(),
    )?;
    let resolved_by_name = std::sync::Arc::new(resolved_by_name);
    if args.child_args.is_empty() {
        return Err(crate::Error::usage("missing child command"));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| crate::Error::internal(&format!("failed creating async runtime: {}", e)))?;

    let mint_result = runtime.block_on(crate::app::mint::mint_all(
        &specs,
        &resolved_by_name,
        &crate::app::mint::MintOptions::default(),
    ));

    let cred_set = match mint_result {
        Ok(cred_set) => cred_set,
        Err(crate::core::credential_set::CredentialSetError::MintFailed {
            failed_providers,
            succeeded_tokens,
        }) => {
            runtime.block_on(revoke_minted_tokens(
                resolved_by_name.as_ref(),
                &succeeded_tokens,
                crate::core::credential_set::RollbackBudget::default(),
            ));
            return Err(crate::Error::config(&format_mint_failed_providers(
                &failed_providers,
            )));
        }
        Err(other) => return Err(other.into()),
    };

    let child_command = args.child_args[0].clone();
    let child_argv = args.child_args[1..].to_vec();
    let child_exit = crate::app::run::run_supervised(
        &child_command,
        &child_argv,
        &runtime,
        &resolved_by_name,
        &cred_set,
        args.restart_before_expiry.map(Duration::from_secs),
    )?;

    Ok(child_exit)
}

#[cfg(test)]
use crate::ports::run_signal_wiring::{RunSignalWiring, SignalProcess};

#[cfg(test)]
struct RunModeSignalPollOutcome {
    signal_processed: bool,
}

#[cfg(test)]
fn run_mode_poll_without_signal_for_test<P, F>(
    _wiring: &mut RunSignalWiring,
    _process: &mut P,
    _revoke_all: &mut F,
) -> Result<RunModeSignalPollOutcome, crate::Error>
where
    P: SignalProcess,
    F: FnMut() -> Result<(), crate::Error>,
{
    Ok(RunModeSignalPollOutcome {
        signal_processed: false,
    })
}

#[cfg(test)]
fn run_mode_dispatch_parent_signal_for_test<P, F>(
    wiring: &mut RunSignalWiring,
    signal: crate::core::signal_policy::ParentSignal,
    process: &mut P,
    revoke_all: &mut F,
) -> Result<RunModeSignalPollOutcome, crate::Error>
where
    P: SignalProcess,
    F: FnMut() -> Result<(), crate::Error>,
{
    let mut revoker = crate::app::run::ClosureRevoker { revoke_all };
    wiring
        .on_parent_signal(signal, process, &mut revoker)
        .map_err(|e| crate::Error::internal(&format!("failed during signal handling: {}", e)))?;

    Ok(RunModeSignalPollOutcome {
        signal_processed: true,
    })
}

fn cmd_mint(args: cli::MintArgs, verbose: bool) -> Result<i32, crate::Error> {
    use std::io::IsTerminal;

    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let client = Client::new(ClientOptions {
        verbose,
        force_terminal: args.force_terminal,
        xdg_config_home: xdg_config_home.clone(),
        ..ClientOptions::default()
    })?;

    client.check_stdout_not_terminal(std::io::stdout().is_terminal())?;

    let source = CredentialSource::from_cli(
        args.profile.clone(),
        args.provider,
        args.role,
        args.ttl,
        args.env_key,
    )?;
    let (specs, resolved_by_name) = crate::app::resolve::resolve_specs_and_providers(
        &client,
        &source,
        xdg_config_home.as_deref(),
    )?;
    let resolved_by_name = std::sync::Arc::new(resolved_by_name);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| crate::Error::internal(&format!("failed creating async runtime: {}", e)))?;

    let cred_set = runtime.block_on(crate::app::mint::mint_all(
        &specs,
        &resolved_by_name,
        &crate::app::mint::MintOptions::default(),
    ))?;

    println!(
        "{}",
        crate::app::orchestrator::format_orchestrator_output(&cred_set)
    );
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_revoke(
    args: cli::RevokeArgs,
    _verbose: bool,
    output: cli::OutputFormat,
) -> Result<i32, crate::Error> {
    let client = Client::new(ClientOptions {
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        ..ClientOptions::default()
    })?;

    let stdin_payload = if args.from_stdin {
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut raw)
            .map_err(|e| crate::Error::usage(&format!("failed reading stdin: {}", e)))?;
        raw
    } else {
        String::new()
    };

    let inputs = revoke_inputs_from_cli(
        args.from_stdin,
        &stdin_payload,
        args.token_id.as_deref(),
        args.provider.as_deref(),
    )?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| crate::Error::internal(&format!("failed creating async runtime: {}", e)))?;

    let mut failures = Vec::new();
    for input in &inputs {
        let result = client
            .resolve_provider(input.provider(), &ProviderOverrides::default())
            .and_then(|resolved| runtime.block_on(execute_revoke(&resolved, input)));
        match result {
            Ok(()) => match output {
                cli::OutputFormat::Text => {
                    println!(
                        "{}",
                        format_revoke_result(input.provider(), input.token_id())
                    );
                }
                cli::OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "ok",
                            "command": "revoke",
                            "provider": input.provider(),
                            "token_id": input.token_id(),
                            "message": format_revoke_result(input.provider(), input.token_id()),
                        })
                    );
                }
            },
            Err(err) => failures.push(err),
        }
    }

    if let Some(first) = failures.pop() {
        return Err(if failures.is_empty() {
            first
        } else {
            failures.push(first);
            crate::Error::multi(failures)
        });
    }
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_validate(args: cli::ValidateArgs, output: cli::OutputFormat) -> Result<i32, crate::Error> {
    let client = Client::new(ClientOptions {
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        ..ClientOptions::default()
    })?;
    let resolved = client.resolve_provider(&args.provider, &ProviderOverrides::default())?;
    crate::ports::provider::validate_provider(&resolved)?;

    let message = format!(
        "noscope: provider '{}' configuration is valid",
        args.provider
    );
    match output {
        cli::OutputFormat::Text => println!("{}", message),
        cli::OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "status": "ok",
                    "command": "validate",
                    "provider": args.provider,
                    "message": message,
                })
            );
        }
    }
    Ok(cli::SUCCESS_EXIT_CODE)
}

#[cfg(test)]
mod mint_profile_wiring_tests;

#[cfg(test)]
mod validate_wiring_tests;

fn cmd_dry_run(args: cli::DryRunArgs, output: cli::OutputFormat) -> Result<i32, crate::Error> {
    let client = Client::new(ClientOptions {
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        ..ClientOptions::default()
    })?;
    let resolved = client.resolve_provider(&args.provider, &ProviderOverrides::default())?;
    match output {
        cli::OutputFormat::Text => {
            let text = client.dry_run(&resolved, &args.role, args.ttl);
            println!("{}", text);
        }
        cli::OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "status": "ok",
                    "command": "dry-run",
                    "provider": resolved.name,
                    "source": config_source_label(resolved.source),
                    "role": args.role,
                    "ttl": args.ttl,
                    "commands": {
                        "mint": resolved.mint_cmd,
                        "refresh": resolved.refresh_cmd,
                        "revoke": resolved.revoke_cmd,
                    },
                    "env": resolved.env,
                })
            );
        }
    }
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn config_source_label(source: crate::ports::provider::ConfigSource) -> &'static str {
    match source {
        crate::ports::provider::ConfigSource::Flags => "flags",
        crate::ports::provider::ConfigSource::EnvVars => "environment variables",
        crate::ports::provider::ConfigSource::File => "config file",
    }
}

fn cmd_doctor(output: cli::OutputFormat) -> Result<i32, crate::Error> {
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
                .join(".config")
        });

    let report = crate::app::doctor::run_doctor(&xdg_config_home);

    match output {
        cli::OutputFormat::Text => {
            for check in &report.checks {
                let symbol = match check.status {
                    crate::app::doctor::CheckStatus::Pass => "✓",
                    crate::app::doctor::CheckStatus::Warn => "!",
                    crate::app::doctor::CheckStatus::Fail => "✗",
                };
                eprintln!("{} {}: {}", symbol, check.name, check.message);
            }
            let total = report.checks.len();
            let passed = report.pass_count();
            let warned = report.warn_count();
            let failed = report.fail_count();
            eprintln!(
                "\n{} checks: {} passed, {} warnings, {} failed",
                total, passed, warned, failed
            );
        }
        cli::OutputFormat::Json => {
            let checks: Vec<serde_json::Value> = report
                .checks
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "status": match c.status {
                            crate::app::doctor::CheckStatus::Pass => "pass",
                            crate::app::doctor::CheckStatus::Warn => "warn",
                            crate::app::doctor::CheckStatus::Fail => "fail",
                        },
                        "message": c.message,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "command": "doctor",
                    "checks": checks,
                    "summary": {
                        "total": report.checks.len(),
                        "passed": report.pass_count(),
                        "warnings": report.warn_count(),
                        "failures": report.fail_count(),
                    },
                    "exit_code": report.exit_code(),
                })
            );
        }
    }

    Ok(report.exit_code())
}

fn cmd_init(output: cli::OutputFormat) -> Result<i32, crate::Error> {
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
                .join(".config")
        });

    let result = crate::app::doctor::run_init(&xdg_config_home).map_err(|e| {
        crate::Error::config(&format!("failed to initialize config directories: {}", e))
    })?;

    match output {
        cli::OutputFormat::Text => {
            if result.created_dirs.is_empty() {
                println!("noscope: config directories already exist, nothing to do");
            } else {
                for dir in &result.created_dirs {
                    println!("noscope: created {}", dir.display());
                }
                println!("noscope: initialization complete");
            }
        }
        cli::OutputFormat::Json => {
            let created: Vec<String> = result
                .created_dirs
                .iter()
                .map(|d| d.display().to_string())
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "status": "ok",
                    "command": "init",
                    "created_dirs": created,
                })
            );
        }
    }

    Ok(cli::SUCCESS_EXIT_CODE)
}

#[rule("rule_cli_completions")]
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
mod revoke_wiring_tests;

#[cfg(test)]
mod run_wiring_tests;

#[cfg(test)]
mod rollback_budget_wiring_tests;

#[cfg(test)]
fn global_signal_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod run_mode_os_signal_e2e_tests;
