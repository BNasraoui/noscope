// noscope-9l0: Binary entrypoint.
//
// This is a thin wrapper that delegates to the library's CLI module.
// All parsing, dispatch, and error handling logic lives in noscope::cli
// (NS-075: CLI parsing in adapter layer).

use std::process::ExitCode;
use std::time::Duration;

use noscope::cli::{self, Command};
use noscope::credential_set::{CredentialSpec, MintConfig, MintResult};
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
    let client = Client::new(ClientOptions {
        verbose,
        ..ClientOptions::default()
    })?;

    // Validate mint parameters through the facade.
    let req = noscope::MintRequest {
        providers: args.provider,
        role: args.role,
        ttl_secs: args.ttl,
    };
    client.validate_mint(&req)?;

    // TODO(noscope-lgb): Actually execute the child process with credentials.
    // For now, return success — the integration test suite will cover this.
    eprintln!(
        "noscope: run is not yet fully implemented (providers: {:?})",
        req.providers
    );
    Ok(cli::SUCCESS_EXIT_CODE)
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
