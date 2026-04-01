// noscope-9l0: CLI framework and binary entrypoint support.
//
// Provides the clap-based CLI definition and dispatch logic as a testable
// library module. The actual binary entrypoint (src/main.rs) is a thin
// wrapper that calls into this module.
//
// Provenance rules:
// - NS-054: Exit codes become real (Error → process exit code)
// - NS-071: Dry-run usable (dry-run subcommand)
// - NS-074: Facade for workflows (all subcommands go through Client)
// - NS-075: CLI parsing in adapter layer (clap types here, not in lib core)

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::error::Error;

/// NS-054: Successful exit code.
pub const SUCCESS_EXIT_CODE: i32 = 0;

/// NS-054: Map a noscope Error to a process exit code.
///
/// Delegates to `Error::exit_code()` which uses the sysexits.h mapping
/// defined in `NoscopeExitCode`. This function exists as the single
/// point where CLI error handling translates errors to exit codes.
pub fn error_to_exit_code(err: &Error) -> i32 {
    err.exit_code()
}

/// Parse CLI arguments from an iterator (testable alternative to
/// `Cli::parse()` which reads from `std::env::args_os()`).
///
/// NS-075: This is the adapter-layer entry point for CLI parsing.
/// Returns `Err` for invalid input, `--help`, or `--version`.
pub fn parse_from_args<I, T>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(args)
}

// ---------------------------------------------------------------------------
// Top-level CLI struct
// ---------------------------------------------------------------------------

/// Subprocess credential lifecycle manager.
#[derive(Parser)]
#[command(
    name = "noscope",
    version,
    about,
    long_about = None,
    after_help = "Examples:\n  noscope run --provider aws --role admin --ttl 3600 -- my-command --flag\n  noscope mint --provider aws --role viewer --ttl 900\n  noscope revoke --token-id tok-123 --provider aws\n  noscope revoke --from-stdin < mint-output.json"
)]
pub struct Cli {
    /// Enable verbose output (include provider stderr on success).
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Output format for command responses.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Output format for command responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text output.
    Text,
    /// Structured JSON output.
    Json,
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

/// NS-074: All workflow subcommands routed through the Client facade.
#[derive(Subcommand)]
pub enum Command {
    /// Mint credentials and run a child process with them in the environment.
    Run(RunArgs),

    /// Mint credentials and write the envelope to stdout (JSON).
    Mint(MintArgs),

    /// Revoke a previously minted credential.
    Revoke(RevokeArgs),

    /// Validate a provider configuration without executing it.
    Validate(ValidateArgs),

    /// Show what would be executed without running any provider.
    #[command(name = "dry-run")]
    DryRun(DryRunArgs),

    /// Generate shell completions for bash, zsh, or fish.
    Completions(CompletionsArgs),
}

// ---------------------------------------------------------------------------
// Subcommand argument structs
// ---------------------------------------------------------------------------

/// Arguments for the `run` subcommand.
#[derive(Parser)]
pub struct RunArgs {
    /// Provider name(s) to mint credentials from.
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub provider: Vec<String>,

    /// Role to request from each provider.
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub role: Option<String>,

    /// TTL in seconds for minted credentials.
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub ttl: Option<u64>,

    /// Use a named profile from `profiles/<name>.toml`.
    ///
    /// When set, this cannot be combined with --provider, --role, or --ttl.
    #[arg(long)]
    pub profile: Option<String>,

    /// Runtime event log format written to stderr (`text` or `json`).
    ///
    /// This only affects runtime event logs on stderr and does not change --output.
    #[arg(long, default_value = "text")]
    pub log_format: String,

    /// The child command and its arguments (after `--`).
    #[arg(last = true, required = true)]
    pub child_args: Vec<String>,
}

/// Arguments for the `mint` subcommand.
#[derive(Parser)]
pub struct MintArgs {
    /// Provider name(s) to mint credentials from.
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub provider: Vec<String>,

    /// Role to request from each provider.
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub role: Option<String>,

    /// TTL in seconds for minted credentials.
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub ttl: Option<u64>,

    /// Use a named profile from `profiles/<name>.toml`.
    ///
    /// When set, this cannot be combined with --provider, --role, or --ttl.
    #[arg(long)]
    pub profile: Option<String>,

    /// Allow output to a terminal.
    #[arg(long)]
    pub force_terminal: bool,
}

/// Arguments for the `revoke` subcommand.
#[derive(Parser)]
pub struct RevokeArgs {
    /// The token ID to revoke (opaque identifier, not the secret).
    #[arg(
        long,
        requires = "provider",
        required_unless_present = "from_stdin",
        conflicts_with = "from_stdin"
    )]
    pub token_id: Option<String>,

    /// The provider that minted the token.
    #[arg(
        long,
        requires = "token_id",
        required_unless_present = "from_stdin",
        conflicts_with = "from_stdin"
    )]
    pub provider: Option<String>,

    /// Read a mint envelope JSON object from stdin and extract token_id/provider.
    #[arg(long, conflicts_with_all = ["token_id", "provider"])]
    pub from_stdin: bool,
}

/// Arguments for the `validate` subcommand.
#[derive(Parser)]
pub struct ValidateArgs {
    /// Provider name to validate.
    #[arg(long)]
    pub provider: String,
}

/// Arguments for the `dry-run` subcommand.
#[derive(Parser)]
pub struct DryRunArgs {
    /// Provider name to dry-run.
    #[arg(long)]
    pub provider: String,

    /// Role to request.
    #[arg(long)]
    pub role: String,

    /// TTL in seconds.
    #[arg(long)]
    pub ttl: u64,
}

/// Arguments for the `completions` subcommand.
#[derive(Parser)]
pub struct CompletionsArgs {
    /// The shell to generate completions for.
    #[arg(long)]
    pub shell: Shell,
}

#[cfg(test)]
mod tests {
    // =========================================================================
    // NS-054: Exit codes become real.
    //
    // The CLI must map Error::exit_code() to process exit codes. Every
    // ErrorKind must produce the correct sysexits.h code when going through
    // the CLI error-to-exit-code path.
    // =========================================================================

    #[test]
    fn exit_codes_become_real_usage_error_maps_to_64() {
        // NS-054: Usage errors must produce exit code 64 through the CLI
        // error handling path.
        let exit = crate::cli::error_to_exit_code(&crate::Error::usage("bad flag"));
        assert_eq!(exit, 64);
    }

    #[test]
    fn exit_codes_become_real_config_error_maps_to_78() {
        let exit = crate::cli::error_to_exit_code(&crate::Error::config("malformed"));
        assert_eq!(exit, 78);
    }

    #[test]
    fn exit_codes_become_real_provider_error_maps_to_65() {
        let exit = crate::cli::error_to_exit_code(&crate::Error::provider("aws", "expired"));
        assert_eq!(exit, 65);
    }

    #[test]
    fn exit_codes_become_real_security_error_maps_to_64() {
        let exit = crate::cli::error_to_exit_code(&crate::Error::security("token in args"));
        assert_eq!(exit, 64);
    }

    #[test]
    fn exit_codes_become_real_profile_error_maps_to_66() {
        let exit = crate::cli::error_to_exit_code(&crate::Error::profile("not found"));
        assert_eq!(exit, 66);
    }

    #[test]
    fn exit_codes_become_real_internal_error_maps_to_70() {
        let exit = crate::cli::error_to_exit_code(&crate::Error::internal("bug"));
        assert_eq!(exit, 70);
    }

    #[test]
    fn exit_codes_become_real_multi_error_maps_to_65() {
        let multi = crate::Error::multi(vec![
            crate::Error::provider("aws", "expired"),
            crate::Error::provider("gcp", "timeout"),
        ]);
        let exit = crate::cli::error_to_exit_code(&multi);
        assert_eq!(exit, 65);
    }

    #[test]
    fn exit_codes_become_real_success_is_zero() {
        // A successful operation must produce exit code 0.
        let exit = crate::cli::SUCCESS_EXIT_CODE;
        assert_eq!(exit, 0);
    }

    // =========================================================================
    // NS-071: Dry-run usable.
    //
    // The dry-run subcommand must be parseable from CLI args and must be
    // recognized as a distinct subcommand.
    // =========================================================================

    #[test]
    fn dry_run_usable_subcommand_is_parseable() {
        // NS-071: "dry-run" must be a recognized subcommand.
        let cli = crate::cli::parse_from_args([
            "noscope",
            "dry-run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ]);
        assert!(
            cli.is_ok(),
            "dry-run subcommand must parse: {:?}",
            cli.err()
        );
    }

    #[test]
    fn dry_run_usable_subcommand_extracts_provider() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "dry-run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::DryRun(ref args) => {
                assert_eq!(args.provider, "aws");
            }
            _ => panic!("Expected DryRun subcommand"),
        }
    }

    #[test]
    fn dry_run_usable_subcommand_extracts_role() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "dry-run",
            "--provider",
            "aws",
            "--role",
            "viewer",
            "--ttl",
            "1800",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::DryRun(ref args) => {
                assert_eq!(args.role, "viewer");
            }
            _ => panic!("Expected DryRun subcommand"),
        }
    }

    #[test]
    fn dry_run_usable_subcommand_extracts_ttl() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "dry-run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "7200",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::DryRun(ref args) => {
                assert_eq!(args.ttl, 7200);
            }
            _ => panic!("Expected DryRun subcommand"),
        }
    }

    // =========================================================================
    // NS-074: Facade for workflows.
    //
    // All subcommands must be routable through the CLI. The CLI must define
    // all five subcommands: run, mint, revoke, validate, dry-run.
    // =========================================================================

    #[test]
    fn facade_for_workflows_run_subcommand_parseable() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
            "--",
            "my-program",
            "--arg1",
        ]);
        assert!(cli.is_ok(), "run subcommand must parse: {:?}", cli.err());
    }

    #[test]
    fn facade_for_workflows_run_extracts_child_command() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
            "--",
            "my-program",
            "--arg1",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::Run(ref args) => {
                assert_eq!(args.child_args, vec!["my-program", "--arg1"]);
            }
            _ => panic!("Expected Run subcommand"),
        }
    }

    #[test]
    fn facade_for_workflows_mint_subcommand_parseable() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "mint",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ]);
        assert!(cli.is_ok(), "mint subcommand must parse: {:?}", cli.err());
    }

    #[test]
    fn facade_for_workflows_mint_extracts_multiple_providers() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "mint",
            "--provider",
            "aws",
            "--provider",
            "gcp",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::Mint(ref args) => {
                assert_eq!(args.provider, vec!["aws", "gcp"]);
            }
            _ => panic!("Expected Mint subcommand"),
        }
    }

    #[test]
    fn facade_for_workflows_revoke_subcommand_parseable() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "revoke",
            "--token-id",
            "tok-123",
            "--provider",
            "aws",
        ]);
        assert!(cli.is_ok(), "revoke subcommand must parse: {:?}", cli.err());
    }

    #[test]
    fn facade_for_workflows_revoke_extracts_token_id() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "revoke",
            "--token-id",
            "tok-abc",
            "--provider",
            "aws",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::Revoke(ref args) => {
                assert_eq!(args.token_id.as_deref(), Some("tok-abc"));
                assert_eq!(args.provider.as_deref(), Some("aws"));
            }
            _ => panic!("Expected Revoke subcommand"),
        }
    }

    #[test]
    fn facade_for_workflows_validate_subcommand_parseable() {
        let cli = crate::cli::parse_from_args(["noscope", "validate", "--provider", "aws"]);
        assert!(
            cli.is_ok(),
            "validate subcommand must parse: {:?}",
            cli.err()
        );
    }

    #[test]
    fn facade_for_workflows_all_five_subcommands_are_distinct() {
        // Each subcommand must parse to a distinct variant.
        let run = crate::cli::parse_from_args([
            "noscope",
            "run",
            "--provider",
            "p",
            "--role",
            "r",
            "--ttl",
            "1",
            "--",
            "cmd",
        ])
        .unwrap();
        let mint = crate::cli::parse_from_args([
            "noscope",
            "mint",
            "--provider",
            "p",
            "--role",
            "r",
            "--ttl",
            "1",
        ])
        .unwrap();
        let revoke = crate::cli::parse_from_args([
            "noscope",
            "revoke",
            "--token-id",
            "t",
            "--provider",
            "p",
        ])
        .unwrap();
        let validate =
            crate::cli::parse_from_args(["noscope", "validate", "--provider", "p"]).unwrap();
        let dry_run = crate::cli::parse_from_args([
            "noscope",
            "dry-run",
            "--provider",
            "p",
            "--role",
            "r",
            "--ttl",
            "1",
        ])
        .unwrap();

        // Verify they produce distinct command variants
        assert!(matches!(run.command, crate::cli::Command::Run(_)));
        assert!(matches!(mint.command, crate::cli::Command::Mint(_)));
        assert!(matches!(revoke.command, crate::cli::Command::Revoke(_)));
        assert!(matches!(validate.command, crate::cli::Command::Validate(_)));
        assert!(matches!(dry_run.command, crate::cli::Command::DryRun(_)));
    }

    // =========================================================================
    // NS-075: CLI parsing in adapter layer.
    //
    // The clap types and parsing logic must be in the CLI module (adapter
    // layer), not in core library types. Core types are Client, MintRequest,
    // etc. CLI types are Cli, Command, RunArgs, etc.
    // =========================================================================

    #[test]
    fn cli_parsing_in_adapter_layer_cli_struct_is_distinct_from_client() {
        // The CLI struct must be a separate type from Client.
        // Verify by instantiating both — they must have different fields.
        let _cli = crate::cli::parse_from_args([
            "noscope",
            "mint",
            "--provider",
            "p",
            "--role",
            "r",
            "--ttl",
            "1",
        ])
        .unwrap();
        let _client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        // Both exist and are separate types — NS-075 satisfied.
    }

    #[test]
    fn cli_parsing_in_adapter_layer_parse_from_args_returns_result() {
        // parse_from_args must return a Result, not panic on bad input.
        let result = crate::cli::parse_from_args(["noscope"]);
        // Missing subcommand — should be an error (clap requires subcommand).
        assert!(result.is_err(), "Missing subcommand must be an error");
    }

    #[test]
    fn cli_parsing_in_adapter_layer_unknown_subcommand_is_error() {
        let result = crate::cli::parse_from_args(["noscope", "frobnicate"]);
        assert!(result.is_err(), "Unknown subcommand must be an error");
    }

    // =========================================================================
    // --help and --version support.
    // =========================================================================

    #[test]
    fn help_flag_is_recognized() {
        // --help should cause clap to produce an error (it writes to stdout
        // and exits). We verify it's recognized, not treated as unknown.
        let result = crate::cli::parse_from_args(["noscope", "--help"]);
        // clap treats --help as an error (DisplayHelp kind), not a parse success.
        assert!(result.is_err());
    }

    #[test]
    fn version_flag_is_recognized() {
        // --version should be recognized by clap.
        let result = crate::cli::parse_from_args(["noscope", "--version"]);
        assert!(result.is_err());
    }

    // =========================================================================
    // Shell completions support.
    // =========================================================================

    #[test]
    fn completions_subcommand_parseable() {
        // A completions subcommand for generating shell completions.
        let cli = crate::cli::parse_from_args(["noscope", "completions", "--shell", "bash"]);
        assert!(
            cli.is_ok(),
            "completions subcommand must parse: {:?}",
            cli.err()
        );
    }

    #[test]
    fn completions_subcommand_accepts_all_shells() {
        for shell in &["bash", "zsh", "fish"] {
            let cli = crate::cli::parse_from_args(["noscope", "completions", "--shell", shell]);
            assert!(
                cli.is_ok(),
                "completions must accept shell '{}': {:?}",
                shell,
                cli.err()
            );
        }
    }

    // =========================================================================
    // Subcommand argument validation — edge cases.
    // =========================================================================

    #[test]
    fn mint_subcommand_requires_provider() {
        let result =
            crate::cli::parse_from_args(["noscope", "mint", "--role", "admin", "--ttl", "3600"]);
        assert!(result.is_err(), "mint without --provider must fail");
    }

    #[test]
    fn mint_subcommand_requires_role() {
        let result =
            crate::cli::parse_from_args(["noscope", "mint", "--provider", "aws", "--ttl", "3600"]);
        assert!(result.is_err(), "mint without --role must fail");
    }

    #[test]
    fn mint_subcommand_requires_ttl() {
        let result = crate::cli::parse_from_args([
            "noscope",
            "mint",
            "--provider",
            "aws",
            "--role",
            "admin",
        ]);
        assert!(result.is_err(), "mint without --ttl must fail");
    }

    #[test]
    fn run_subcommand_requires_child_command() {
        // run without -- <command> should fail.
        let result = crate::cli::parse_from_args([
            "noscope",
            "run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ]);
        assert!(result.is_err(), "run without child command must fail");
    }

    #[test]
    fn revoke_subcommand_requires_token_id() {
        let result = crate::cli::parse_from_args(["noscope", "revoke", "--provider", "aws"]);
        assert!(result.is_err(), "revoke without --token-id must fail");
    }

    #[test]
    fn revoke_subcommand_requires_provider() {
        let result = crate::cli::parse_from_args(["noscope", "revoke", "--token-id", "tok-123"]);
        assert!(result.is_err(), "revoke without --provider must fail");
    }

    // =========================================================================
    // noscope-3ez.8: Profile is a first-class alternative to --provider/--role/--ttl.
    // =========================================================================

    #[test]
    fn mint_profile_only_parses_without_provider_role_ttl() {
        let cli = crate::cli::parse_from_args(["noscope", "mint", "--profile", "dev"]);
        assert!(
            cli.is_ok(),
            "noscope-3ez.8: mint --profile alone must parse: {:?}",
            cli.err()
        );
    }

    #[test]
    fn mint_profile_conflicts_with_provider() {
        let result = crate::cli::parse_from_args([
            "noscope",
            "mint",
            "--profile",
            "dev",
            "--provider",
            "aws",
        ]);
        assert!(
            result.is_err(),
            "noscope-3ez.8: --profile must conflict with --provider"
        );
    }

    #[test]
    fn mint_profile_conflicts_with_role() {
        let result =
            crate::cli::parse_from_args(["noscope", "mint", "--profile", "dev", "--role", "admin"]);
        assert!(
            result.is_err(),
            "noscope-3ez.8: --profile must conflict with --role"
        );
    }

    #[test]
    fn mint_profile_conflicts_with_ttl() {
        let result =
            crate::cli::parse_from_args(["noscope", "mint", "--profile", "dev", "--ttl", "3600"]);
        assert!(
            result.is_err(),
            "noscope-3ez.8: --profile must conflict with --ttl"
        );
    }

    #[test]
    fn run_profile_only_parses_without_provider_role_ttl() {
        let cli =
            crate::cli::parse_from_args(["noscope", "run", "--profile", "dev", "--", "sleep", "1"]);
        assert!(
            cli.is_ok(),
            "noscope-3ez.8: run --profile alone must parse: {:?}",
            cli.err()
        );
    }

    #[test]
    fn run_profile_conflicts_with_provider() {
        let result = crate::cli::parse_from_args([
            "noscope",
            "run",
            "--profile",
            "dev",
            "--provider",
            "aws",
            "--",
            "sleep",
            "1",
        ]);
        assert!(
            result.is_err(),
            "noscope-3ez.8: run --profile must conflict with --provider"
        );
    }

    #[test]
    fn mint_requires_profile_or_provider_role_ttl() {
        let result = crate::cli::parse_from_args(["noscope", "mint"]);
        assert!(
            result.is_err(),
            "noscope-3ez.8: mint with no flags at all must fail"
        );
    }

    // =========================================================================
    // Verbose flag support.
    // =========================================================================

    #[test]
    fn verbose_flag_is_global() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "--verbose",
            "mint",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ])
        .unwrap();
        assert!(cli.verbose, "Global --verbose flag must be captured");
    }

    #[test]
    fn verbose_flag_defaults_to_false() {
        let cli = crate::cli::parse_from_args([
            "noscope",
            "mint",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ])
        .unwrap();
        assert!(!cli.verbose, "--verbose must default to false");
    }

    // =========================================================================
    // noscope-3ez.11: Improve help text quality and semantics.
    // =========================================================================

    fn render_help(args: impl IntoIterator<Item = &'static str>) -> String {
        match crate::cli::parse_from_args(args) {
            Ok(_) => panic!("--help should return clap::Error"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn help_includes_concrete_usage_examples() {
        let root_help = render_help(["noscope", "--help"]);
        assert!(
            root_help.contains("Examples:"),
            "root help must include concrete examples"
        );
        assert!(
            root_help.contains("noscope run"),
            "root help examples must include run"
        );
        assert!(
            root_help.contains("noscope mint"),
            "root help examples must include mint"
        );
        assert!(
            root_help.contains("noscope revoke"),
            "root help examples must include revoke"
        );
    }

    #[test]
    fn profile_help_clarifies_flag_behavior() {
        let run_help = render_help(["noscope", "run", "--help"]);
        assert!(
            run_help.contains("cannot be combined with --provider, --role, or --ttl"),
            "run --profile help must explain mutual exclusion semantics"
        );

        let mint_help = render_help(["noscope", "mint", "--help"]);
        assert!(
            mint_help.contains("cannot be combined with --provider, --role, or --ttl"),
            "mint --profile help must explain mutual exclusion semantics"
        );
    }

    #[test]
    fn log_format_help_clarifies_scope_and_relationship_to_output() {
        let run_help = render_help(["noscope", "run", "--help"]);
        assert!(
            run_help.contains("only affects runtime event logs on stderr"),
            "--log-format help must explain it only affects stderr runtime events"
        );
        assert!(
            run_help.contains("does not change --output"),
            "--log-format help must explain it does not affect --output"
        );
    }

    #[test]
    fn user_facing_help_avoids_internal_rule_jargon() {
        let root_help = render_help(["noscope", "--help"]);
        assert!(
            !root_help.contains("NS-"),
            "root help should avoid internal rule identifiers"
        );

        let dry_run_help = render_help(["noscope", "dry-run", "--help"]);
        assert!(
            !dry_run_help.contains("NS-"),
            "subcommand help should avoid internal rule identifiers"
        );

        let mint_help = render_help(["noscope", "mint", "--help"]);
        assert!(
            !mint_help.contains("NS-"),
            "argument help should avoid internal rule identifiers"
        );
    }
}
