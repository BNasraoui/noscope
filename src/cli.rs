// CLI framework and binary entrypoint support.
// Provides the clap-based CLI definition and dispatch logic as a testable
// library module. The actual binary entrypoint (src/main.rs) is a thin
// wrapper that calls into this module.
// Provenance rules:

mod commands;
pub use commands::run_cli;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::core::error::Error;

/// Successful exit code.
pub const SUCCESS_EXIT_CODE: i32 = 0;

/// Map a noscope Error to a process exit code.
/// Delegates to `Error::exit_code()` which uses the sysexits.h mapping
/// defined in `NoscopeExitCode`. This function exists as the single
/// point where CLI error handling translates errors to exit codes.
pub fn error_to_exit_code(err: &Error) -> i32 {
    err.exit_code()
}

/// Parse CLI arguments from an iterator (testable alternative to
/// `Cli::parse()` which reads from `std::env::args_os()`).
/// This is the adapter-layer entry point for CLI parsing.
/// Returns `Err` for invalid input, `--help`, or `--version`.
pub fn parse_from_args<I, T>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(args)
}

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

/// All workflow subcommands routed through the Client facade.
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

    /// Check local setup: config directories, provider configs, command paths.
    Doctor(DoctorArgs),

    /// Create the noscope config directory structure with secure permissions.
    Init(InitArgs),

    /// Generate shell completions for bash, zsh, or fish.
    Completions(CompletionsArgs),
}

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
    /// When set, this cannot be combined with --provider, --role, or --ttl.
    #[arg(long)]
    pub profile: Option<String>,

    /// Runtime event log format written to stderr (`text` or `json`).
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

/// Arguments for the `doctor` subcommand.
#[derive(Parser)]
pub struct DoctorArgs {
    // Doctor takes no arguments — it inspects the local environment.
}

/// Arguments for the `init` subcommand.
#[derive(Parser)]
pub struct InitArgs {
    // Init takes no arguments — it creates the default config structure.
}

/// Arguments for the `completions` subcommand.
#[derive(Parser)]
pub struct CompletionsArgs {
    /// The shell to generate completions for.
    #[arg(long)]
    pub shell: Shell,
}

#[cfg(test)]
mod tests;
