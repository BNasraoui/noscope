// noscope-9l0: Binary entrypoint.
//
// This is a thin wrapper that delegates to the library's CLI module.
// All parsing, dispatch, and error handling logic lives in noscope::cli
// (NS-075: CLI parsing in adapter layer).

use std::process::ExitCode;

use noscope::cli::{self, Command};
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

    // TODO(noscope-lgb): Actually execute minting.
    eprintln!(
        "noscope: mint is not yet fully implemented (providers: {:?})",
        req.providers
    );
    Ok(cli::SUCCESS_EXIT_CODE)
}

fn cmd_revoke(args: cli::RevokeArgs, _verbose: bool) -> Result<i32, noscope::Error> {
    let _client = Client::new(ClientOptions::default())?;
    let _req = noscope::RevokeRequest::from_token_id(&args.token_id, &args.provider);

    // TODO(noscope-lgb): Actually execute revocation.
    eprintln!(
        "noscope: revoke is not yet fully implemented (token_id: {})",
        args.token_id
    );
    Ok(cli::SUCCESS_EXIT_CODE)
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
