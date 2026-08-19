// Binary entrypoint.
// This is a thin wrapper that delegates to the library's CLI module.
// All parsing, dispatch, and error handling logic lives in noscope::cli
//.

use std::path::PathBuf;
use std::process::ExitCode;

use noscope::app::mint::format_mint_failed_providers;
use noscope::app::resolve::CredentialSource;
use noscope::app::revoke::{
    execute_revoke, format_revoke_result, revoke_inputs_from_cli, revoke_minted_tokens,
};
use noscope::cli::{self, Command};
use noscope::{Client, ClientOptions, ProviderOverrides};
use provenance_macros::rule;

#[rule("rule_errors_json_error_object")]
fn main() -> ExitCode {
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

/// Dispatch subcommands through the Client facade.
fn run(cli: cli::Cli) -> Result<i32, noscope::Error> {
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

fn cmd_run(args: cli::RunArgs, verbose: bool) -> Result<i32, noscope::Error> {
    let log_format = noscope::LogFormat::parse(&args.log_format)
        .ok_or_else(|| noscope::Error::usage("--log-format must be 'json' or 'text'"))?;
    let _runtime_emitter_guard =
        noscope::event::install_runtime_emitter(noscope::event::EventEmitter::new(log_format));

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
    )?;
    let (specs, resolved_by_name) = noscope::app::resolve::resolve_specs_and_providers(
        &client,
        &source,
        xdg_config_home.as_deref(),
    )?;
    let resolved_by_name = std::sync::Arc::new(resolved_by_name);
    if args.child_args.is_empty() {
        return Err(noscope::Error::usage("missing child command"));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| noscope::Error::internal(&format!("failed creating async runtime: {}", e)))?;

    let mint_result = runtime.block_on(noscope::app::mint::mint_all(
        &specs,
        &resolved_by_name,
        &noscope::app::mint::MintOptions::default(),
    ));

    let cred_set = match mint_result {
        Ok(cred_set) => cred_set,
        Err(noscope::credential_set::CredentialSetError::MintFailed {
            failed_providers,
            succeeded_tokens,
        }) => {
            runtime.block_on(revoke_minted_tokens(
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

    let child_command = args.child_args[0].clone();
    let child_argv = args.child_args[1..].to_vec();
    let child_exit = noscope::app::run::run_supervised(
        &child_command,
        &child_argv,
        &runtime,
        &resolved_by_name,
        &cred_set,
    )?;

    Ok(child_exit)
}

#[cfg(test)]
use noscope::run_signal_wiring::{RunSignalWiring, SignalProcess};

#[cfg(test)]
struct RunModeSignalPollOutcome {
    signal_processed: bool,
}

#[cfg(test)]
fn run_mode_poll_without_signal_for_test<P, F>(
    _wiring: &mut RunSignalWiring,
    _process: &mut P,
    _revoke_all: &mut F,
) -> Result<RunModeSignalPollOutcome, noscope::Error>
where
    P: SignalProcess,
    F: FnMut() -> Result<(), noscope::Error>,
{
    Ok(RunModeSignalPollOutcome {
        signal_processed: false,
    })
}

#[cfg(test)]
fn run_mode_dispatch_parent_signal_for_test<P, F>(
    wiring: &mut RunSignalWiring,
    signal: noscope::signal_policy::ParentSignal,
    process: &mut P,
    revoke_all: &mut F,
) -> Result<RunModeSignalPollOutcome, noscope::Error>
where
    P: SignalProcess,
    F: FnMut() -> Result<(), noscope::Error>,
{
    let mut revoker = noscope::app::run::ClosureRevoker { revoke_all };
    wiring
        .on_parent_signal(signal, process, &mut revoker)
        .map_err(|e| noscope::Error::internal(&format!("failed during signal handling: {}", e)))?;

    Ok(RunModeSignalPollOutcome {
        signal_processed: true,
    })
}

fn cmd_mint(args: cli::MintArgs, verbose: bool) -> Result<i32, noscope::Error> {
    use std::io::IsTerminal;

    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let client = Client::new(ClientOptions {
        verbose,
        force_terminal: args.force_terminal,
        xdg_config_home: xdg_config_home.clone(),
        ..ClientOptions::default()
    })?;

    client.check_stdout_not_terminal(std::io::stdout().is_terminal())?;

    let source =
        CredentialSource::from_cli(args.profile.clone(), args.provider, args.role, args.ttl)?;
    let (specs, resolved_by_name) = noscope::app::resolve::resolve_specs_and_providers(
        &client,
        &source,
        xdg_config_home.as_deref(),
    )?;
    let resolved_by_name = std::sync::Arc::new(resolved_by_name);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| noscope::Error::internal(&format!("failed creating async runtime: {}", e)))?;

    let cred_set = runtime.block_on(noscope::app::mint::mint_all(
        &specs,
        &resolved_by_name,
        &noscope::app::mint::MintOptions::default(),
    ))?;

    println!(
        "{}",
        noscope::orchestrator::format_orchestrator_output(&cred_set)
    );
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_revoke(
    args: cli::RevokeArgs,
    _verbose: bool,
    output: cli::OutputFormat,
) -> Result<i32, noscope::Error> {
    let client = Client::new(ClientOptions {
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        ..ClientOptions::default()
    })?;

    let stdin_payload = if args.from_stdin {
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut raw)
            .map_err(|e| noscope::Error::usage(&format!("failed reading stdin: {}", e)))?;
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
        .map_err(|e| noscope::Error::internal(&format!("failed creating async runtime: {}", e)))?;

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
            noscope::Error::multi(failures)
        });
    }
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_validate(args: cli::ValidateArgs, output: cli::OutputFormat) -> Result<i32, noscope::Error> {
    let client = Client::new(ClientOptions {
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        ..ClientOptions::default()
    })?;
    let resolved = client.resolve_provider(&args.provider, &ProviderOverrides::default())?;
    noscope::provider::validate_provider(&resolved)?;

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
mod mint_profile_wiring_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn write_executable(path: &Path, script: &str) {
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn write_provider_config(xdg: &Path, provider: &str, mint_cmd: &str) {
        let dir = xdg.join("noscope").join("providers");
        fs::create_dir_all(&dir).unwrap();
        let cfg = format!(
            "contract_version = 1\n\n[commands]\nmint = \"{}\"\n",
            mint_cmd
        );
        let path = dir.join(format!("{}.toml", provider));
        fs::write(&path, cfg).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn scoped_env<T>(key: &str, value: &Path, f: impl FnOnce() -> T) -> T {
        let old = std::env::var_os(key);
        // SAFETY: test-local env mutation, restored before return.
        unsafe {
            std::env::set_var(key, value);
        }
        let out = f();
        match old {
            Some(prev) => unsafe { std::env::set_var(key, prev) },
            None => unsafe { std::env::remove_var(key) },
        }
        out
    }

    #[test]
    fn cmd_mint_with_profile_mints_from_profile_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let profile_dir = tmp.path().join("noscope").join("profiles");
        fs::create_dir_all(&profile_dir).unwrap();

        let mint_script = tmp.path().join("mint.sh");
        write_executable(
            &mint_script,
            "#!/bin/sh\nprintf '{\"token\":\"profile-mint-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );

        write_provider_config(tmp.path(), "aws", mint_script.to_string_lossy().as_ref());

        let profile_toml =
            "[[credentials]]\nprovider = \"aws\"\nrole = \"profile-role\"\nttl = 3600\n";
        fs::write(profile_dir.join("dev.toml"), profile_toml).unwrap();
        fs::set_permissions(
            profile_dir.join("dev.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let args = cli::MintArgs {
            provider: vec![],
            role: None,
            ttl: None,
            profile: Some("dev".to_string()),
            force_terminal: true,
        };

        let result = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_mint(args, false));
        assert!(
            result.is_ok(),
            "cmd_mint --profile must succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn cmd_mint_without_profile_still_requires_provider_role_ttl() {
        let args = cli::MintArgs {
            provider: vec!["nonexistent-provider".to_string()],
            role: Some("admin".to_string()),
            ttl: Some(3600),
            profile: None,
            force_terminal: true,
        };

        let result = cmd_mint(args, false);
        assert!(
            result.is_err(),
            "cmd_mint without profile must still resolve providers"
        );
    }
}

#[cfg(test)]
mod validate_wiring_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn write_non_executable_file(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn scoped_env_var<T>(
        key: &str,
        value: impl AsRef<std::ffi::OsStr>,
        f: impl FnOnce() -> T,
    ) -> T {
        let old = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        let out = f();
        match old {
            Some(prev) => unsafe {
                std::env::set_var(key, prev);
            },
            None => unsafe {
                std::env::remove_var(key);
            },
        }
        out
    }

    fn scoped_validate_env<T>(mint_cmd: &Path, f: impl FnOnce() -> T) -> T {
        let mint_cmd: PathBuf = mint_cmd.into();
        scoped_env_var("NOSCOPE_MINT_CMD", mint_cmd.as_os_str(), || {
            scoped_env_var("NOSCOPE_REFRESH_CMD", "", || {
                scoped_env_var("NOSCOPE_REVOKE_CMD", "", f)
            })
        })
    }

    #[test]
    fn validate_command_performs_provider_executable_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let mint = tmp.path().join("mint.sh");
        write_non_executable_file(&mint);

        let result = scoped_validate_env(&mint, || {
            cmd_validate(
                cli::ValidateArgs {
                    provider: "aws".to_string(),
                },
                cli::OutputFormat::Text,
            )
        });

        assert!(
            result.is_err(),
            "validate must fail when provider command is not executable"
        );
    }

    #[test]
    fn validate_command_error_is_actionable_for_operator() {
        let tmp = tempfile::tempdir().unwrap();
        let mint = tmp.path().join("mint.sh");
        write_non_executable_file(&mint);
        let mint_cmd = mint.to_string_lossy().to_string();

        let result = scoped_validate_env(&mint, || {
            cmd_validate(
                cli::ValidateArgs {
                    provider: "aws".to_string(),
                },
                cli::OutputFormat::Text,
            )
        });

        let err = result.expect_err("validate must fail for non-executable command");
        let message = format!("{}", err);

        assert!(
            message.contains("mint") && message.contains(&mint_cmd),
            "validate failure must include failing command type and path, got: {}",
            message
        );
    }
}

fn cmd_dry_run(args: cli::DryRunArgs, output: cli::OutputFormat) -> Result<i32, noscope::Error> {
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

fn config_source_label(source: noscope::provider::ConfigSource) -> &'static str {
    match source {
        noscope::provider::ConfigSource::Flags => "flags",
        noscope::provider::ConfigSource::EnvVars => "environment variables",
        noscope::provider::ConfigSource::File => "config file",
    }
}

fn cmd_doctor(output: cli::OutputFormat) -> Result<i32, noscope::Error> {
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
                .join(".config")
        });

    let report = noscope::doctor::run_doctor(&xdg_config_home);

    match output {
        cli::OutputFormat::Text => {
            for check in &report.checks {
                let symbol = match check.status {
                    noscope::doctor::CheckStatus::Pass => "✓",
                    noscope::doctor::CheckStatus::Warn => "!",
                    noscope::doctor::CheckStatus::Fail => "✗",
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
                            noscope::doctor::CheckStatus::Pass => "pass",
                            noscope::doctor::CheckStatus::Warn => "warn",
                            noscope::doctor::CheckStatus::Fail => "fail",
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

fn cmd_init(output: cli::OutputFormat) -> Result<i32, noscope::Error> {
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
                .join(".config")
        });

    let result = noscope::doctor::run_init(&xdg_config_home).map_err(|e| {
        noscope::Error::config(&format!("failed to initialize config directories: {}", e))
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
        let inputs = revoke_inputs_from_cli(false, "", Some("tok-123"), Some("aws")).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].token_id(), "tok-123");
        assert_eq!(inputs[0].provider(), "aws");
    }

    #[test]
    fn revoke_builds_revoke_input_from_stdin_json() {
        let stdin = r#"{"token":"secret","token_id":"tok-9","provider":"vault","role":"ops"}"#;

        let inputs = revoke_inputs_from_cli(true, stdin, None, None).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].token_id(), "tok-9");
        assert_eq!(inputs[0].provider(), "vault");
    }

    #[test]
    fn revoke_accepts_mint_envelope_array_from_stdin() {
        // `noscope mint` emits a JSON array; the pipeline
        // `noscope mint ... | noscope revoke --from-stdin` must revoke
        // every envelope in it.
        let stdin = r#"[
            {"token":"s1","token_id":"tok-a","provider":"aws","role":"ops"},
            {"token":"s2","token_id":"tok-g","provider":"gcp","role":"ops"}
        ]"#;

        let inputs = revoke_inputs_from_cli(true, stdin, None, None).unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].token_id(), "tok-a");
        assert_eq!(inputs[0].provider(), "aws");
        assert_eq!(inputs[1].token_id(), "tok-g");
        assert_eq!(inputs[1].provider(), "gcp");
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
    use noscope::signal_policy::ParentSignal;
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
        log_format: &str,
        child_args: Vec<String>,
    ) -> cli::RunArgs {
        cli::RunArgs {
            provider: providers,
            role: Some(role.to_string()),
            ttl: Some(ttl),
            profile,
            log_format: log_format.to_string(),
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
            "text",
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
            "text",
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
            "text",
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
            "text",
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
            "text",
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
            "text",
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
            "text",
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

    #[test]
    fn ns_029_revocation_callback_not_invoked_before_signal_receipt_in_run_mode() {
        let mut revoke_calls = 0usize;
        let mut process = FakeSignalProcess::default();
        let mut wiring = RunSignalWiring::default();

        let polled = run_mode_poll_without_signal_for_test(&mut wiring, &mut process, &mut || {
            revoke_calls += 1;
            Ok(())
        })
        .expect("polling run loop without signals should succeed");

        assert!(
            !polled.signal_processed,
            "no signal should be processed when none were received"
        );
        assert_eq!(
            revoke_calls, 0,
            "ClosureRevoker callback must not run before shutdown signal receipt"
        );
    }

    #[test]
    fn ns_029_revocation_callback_triggers_only_after_shutdown_signal_in_run_mode() {
        let mut revoke_calls = 0usize;
        let mut process = FakeSignalProcess::default();
        let mut wiring = RunSignalWiring::default();

        let no_signal =
            run_mode_poll_without_signal_for_test(&mut wiring, &mut process, &mut || {
                revoke_calls += 1;
                Ok(())
            })
            .expect("polling run loop without signals should succeed");
        assert!(!no_signal.signal_processed);
        assert_eq!(revoke_calls, 0, "must not revoke before signal receipt");

        let with_signal = run_mode_dispatch_parent_signal_for_test(
            &mut wiring,
            ParentSignal::Sigterm,
            &mut process,
            &mut || {
                revoke_calls += 1;
                Ok(())
            },
        )
        .expect("dispatching shutdown signal should succeed");

        assert!(with_signal.signal_processed);
        assert_eq!(
            revoke_calls, 1,
            "ClosureRevoker callback must trigger after first shutdown signal"
        );
    }

    #[test]
    fn ns_029_revocation_callback_runs_at_most_once_across_multiple_shutdown_signals() {
        let mut revoke_calls = 0usize;
        let mut process = FakeSignalProcess::default();
        let mut wiring = RunSignalWiring::default();

        let first = run_mode_dispatch_parent_signal_for_test(
            &mut wiring,
            ParentSignal::Sigterm,
            &mut process,
            &mut || {
                revoke_calls += 1;
                Ok(())
            },
        )
        .expect("first shutdown signal dispatch should succeed");
        assert!(first.signal_processed);
        assert_eq!(revoke_calls, 1, "first shutdown signal should revoke once");

        let second = run_mode_dispatch_parent_signal_for_test(
            &mut wiring,
            ParentSignal::Sigint,
            &mut process,
            &mut || {
                revoke_calls += 1;
                Ok(())
            },
        )
        .expect("second shutdown signal dispatch should succeed");
        assert!(second.signal_processed);
        assert_eq!(
            revoke_calls, 1,
            "revocation callback must not run again after first shutdown-triggered revoke"
        );
    }

    #[derive(Default)]
    struct FakeSignalProcess {
        forwarded: Vec<i32>,
    }

    impl SignalProcess for FakeSignalProcess {
        fn forward_signal(&mut self, sig: i32) -> Result<(), std::io::Error> {
            self.forwarded.push(sig);
            Ok(())
        }
    }
}

#[cfg(test)]
mod rollback_budget_wiring_tests {
    use chrono::Utc;
    use noscope::app::revoke::revoke_token_with_budget;
    use provenance_macros::verifies;
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
            "failed revokes must retry"
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
            "wall clock budget must cap total retry attempts"
        );
    }

    #[tokio::test]
    #[verifies("rule_cross_rollback_budget", examples)]
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
            "rollback retries must use exponential backoff"
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
            "budget=0 must disable rollback retries"
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
            "a timed-out attempt should consume budget and stop further retries"
        );
        let lines = logs.lock().unwrap().clone();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("timed out"),
            "timed-out rollback attempts should be logged as failures"
        );
    }
}

#[cfg(test)]
fn global_signal_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod run_mode_os_signal_e2e_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    fn clear_pending_parent_signals() {
        let mut signals =
            signal_hook::iterator::Signals::new([libc::SIGTERM, libc::SIGINT, libc::SIGHUP])
                .unwrap();
        for _ in 0..5 {
            let mut saw_pending = false;
            for _ in signals.pending() {
                saw_pending = true;
            }
            if !saw_pending {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

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

    fn make_run_args(child_script: &Path) -> cli::RunArgs {
        cli::RunArgs {
            provider: vec!["aws".to_string()],
            role: Some("admin".to_string()),
            ttl: Some(3600),
            profile: None,
            log_format: "text".to_string(),
            child_args: vec![child_script.to_string_lossy().to_string()],
        }
    }

    fn scoped_xdg_config_home<T>(value: &Path, f: impl FnOnce() -> T) -> T {
        let old = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", value);
        }
        let out = f();
        match old {
            Some(prev) => unsafe {
                std::env::set_var("XDG_CONFIG_HOME", prev);
            },
            None => unsafe {
                std::env::remove_var("XDG_CONFIG_HOME");
            },
        }
        out
    }

    fn spawn_parent_signals_after_child_ready(
        ready_file: PathBuf,
        signals: Vec<i32>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready_file.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }

            let pid = unsafe { libc::getpid() };
            for sig in signals {
                let rc = unsafe { libc::kill(pid, sig) };
                assert_eq!(rc, 0, "failed to deliver parent signal {}", sig);
                thread::sleep(Duration::from_millis(100));
            }
        })
    }

    #[test]
    fn ns_026_run_mode_forwards_real_sigterm_sigint_sighup_via_cmd_run_path() {
        let _guard = global_signal_test_lock().lock().unwrap();
        clear_pending_parent_signals();

        let cases = [
            (libc::SIGTERM, "TERM"),
            (libc::SIGINT, "INT"),
            (libc::SIGHUP, "HUP"),
        ];

        for (signal, expected_marker) in cases {
            clear_pending_parent_signals();
            let tmp = tempfile::tempdir().unwrap();
            let ready_file = tmp.path().join(format!("ready-{}", signal));
            let signal_log = tmp.path().join(format!("signal-{}.log", signal));
            let revoke_log = tmp.path().join(format!("revoke-{}.log", signal));

            let child = tmp.path().join("child.sh");
            write_executable(
                &child,
                &format!(
                    "#!/bin/sh\nprintf ready > '{}'\ntrap 'printf TERM > {}; exit 0' TERM\ntrap 'printf INT > {}; exit 0' INT\ntrap 'printf HUP > {}; exit 0' HUP\nwhile :; do sleep 0.05; done\n",
                    ready_file.display(),
                    signal_log.display(),
                    signal_log.display(),
                    signal_log.display(),
                ),
            );

            let mint = tmp.path().join("mint.sh");
            write_executable(
                &mint,
                "#!/bin/sh\nprintf '{\"token\":\"signal-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
            );

            let revoke = tmp.path().join("revoke.sh");
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

            let sender = spawn_parent_signals_after_child_ready(ready_file.clone(), vec![signal]);
            let result =
                scoped_xdg_config_home(tmp.path(), || cmd_run(make_run_args(&child), false));
            sender.join().unwrap();

            assert_eq!(result.unwrap(), 0);
            assert_eq!(
                fs::read_to_string(&signal_log).unwrap_or_default(),
                expected_marker,
                "child must receive forwarded signal {} via cmd_run path",
                expected_marker
            );
        }
    }

    #[test]
    fn ns_003_run_mode_attempts_revoke_on_real_shutdown_signal_via_cmd_run_path() {
        let _guard = global_signal_test_lock().lock().unwrap();
        clear_pending_parent_signals();

        let tmp = tempfile::tempdir().unwrap();
        let ready_file = tmp.path().join("ready");
        let signal_log = tmp.path().join("signal.log");
        let revoke_log = tmp.path().join("revoke.log");

        let child = tmp.path().join("child.sh");
        write_executable(
            &child,
            &format!(
                "#!/bin/sh\nprintf ready > '{}'\ntrap 'printf TERM > {}; exit 0' TERM\ntrap 'printf INT > {}; exit 0' INT\ntrap 'printf HUP > {}; exit 0' HUP\nwhile :; do sleep 0.05; done\n",
                ready_file.display(),
                signal_log.display(),
                signal_log.display(),
                signal_log.display(),
            ),
        );

        let mint = tmp.path().join("mint.sh");
        write_executable(
            &mint,
            "#!/bin/sh\nprintf '{\"token\":\"revoke-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );

        let revoke = tmp.path().join("revoke.sh");
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

        let sender = spawn_parent_signals_after_child_ready(ready_file, vec![libc::SIGTERM]);
        let result = scoped_xdg_config_home(tmp.path(), || cmd_run(make_run_args(&child), false));
        sender.join().unwrap();

        assert_eq!(result.unwrap(), 0);
        let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
        assert!(
            revoked.contains("tok-aws"),
            "run-mode shutdown must attempt revocation on signal via cmd_run path"
        );
    }

    #[test]
    fn ns_028_run_mode_double_real_signal_escalates_to_sigkill_via_cmd_run_path() {
        let _guard = global_signal_test_lock().lock().unwrap();
        clear_pending_parent_signals();

        let tmp = tempfile::tempdir().unwrap();
        let ready_file = tmp.path().join("ready");
        let revoke_log = tmp.path().join("revoke.log");

        let child = tmp.path().join("child.sh");
        write_executable(
            &child,
            &format!(
                "#!/bin/sh\nprintf ready > '{}'\ntrap '' TERM\ntrap '' INT\ntrap '' HUP\nwhile :; do sleep 1; done\n",
                ready_file.display()
            ),
        );

        let mint = tmp.path().join("mint.sh");
        write_executable(
            &mint,
            "#!/bin/sh\nprintf '{\"token\":\"double-signal-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );

        let revoke = tmp.path().join("revoke.sh");
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

        let sender =
            spawn_parent_signals_after_child_ready(ready_file, vec![libc::SIGTERM, libc::SIGINT]);
        let result = scoped_xdg_config_home(tmp.path(), || cmd_run(make_run_args(&child), false));
        sender.join().unwrap();

        assert_eq!(result.unwrap(), 128 + libc::SIGKILL);

        let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
        assert_eq!(
            revoked.lines().filter(|line| *line == "tok-aws").count(),
            1,
            "double-signal escalation must not trigger duplicate revocations"
        );
    }
}
