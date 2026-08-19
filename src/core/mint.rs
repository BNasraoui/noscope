// Mint output envelope
// Revoke CLI input contract
// Mint mode TTL requirement
// Mint multi-provider atomicity
// Redaction exception for mint stdout
// Terminal detection for mint

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;
use zeroize::Zeroize;

use crate::core::exit_code::NoscopeExitCode;
use crate::core::redaction::RedactedToken;
use crate::core::signal_policy::{SignalHandlingPolicy, TtlBounds};
use crate::core::token::ScopedToken;
use provenance_macros::rule;

/// Mint output envelope for stdout.
/// Contains the raw token value — the one place redaction does not
/// apply, since stdout IS the credential channel. `to_json()` produces
/// the stdout output; `to_log_string()` produces the redacted stderr form.
/// Not Clone — the raw token value should not be duplicated carelessly.
/// Token field is zeroized on drop.
pub struct MintEnvelope {
    token: String,
    expires_at: DateTime<Utc>,
    token_id: String,
    provider: String,
    role: String,
}

// Zeroize the raw token value on drop. The token is stored in a
// plain String (not SecretString) because it needs to be serialized to
// stdout JSON. We compensate by manually zeroizing on drop.
impl Drop for MintEnvelope {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Debug never shows the raw token value.
/// The token is redacted in Debug output, matching the ScopedToken pattern.
impl fmt::Debug for MintEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = RedactedToken::new(&self.token, Some(&self.token_id));
        f.debug_struct("MintEnvelope")
            .field("token", &redacted)
            .field("expires_at", &self.expires_at)
            .field("token_id", &self.token_id)
            .field("provider", &self.provider)
            .field("role", &self.role)
            .finish()
    }
}

/// Internal serialization helper — keeps Serialize out of the public type.
/// Field names match JSON contract exactly.
#[derive(Serialize)]
#[rule("rule_token_mint_envelope_five_fields")]
struct SerializableMintEnvelope<'a> {
    token: &'a str,
    expires_at: String,
    token_id: &'a str,
    provider: &'a str,
    role: &'a str,
}

impl MintEnvelope {
    /// Create a new mint envelope from raw components.
    pub fn new(
        token: &str,
        expires_at: DateTime<Utc>,
        token_id: &str,
        provider: &str,
        role: &str,
    ) -> Self {
        Self {
            token: token.to_string(),
            expires_at,
            token_id: token_id.to_string(),
            provider: provider.to_string(),
            role: role.to_string(),
        }
    }

    /// Create a mint envelope from a ScopedToken.
    /// This intentionally calls `expose_secret()` — the mint
    /// envelope is the designated path for outputting raw credentials.
    pub fn from_scoped_token(token: &ScopedToken) -> Self {
        Self {
            token: token.expose_secret().to_string(),
            expires_at: token.expires_at(),
            token_id: token.token_id().unwrap_or("").to_string(),
            provider: token.provider().to_string(),
            role: token.role().to_string(),
        }
    }

    /// Serialize to compact single-line JSON for stdout.
    /// This output intentionally contains the raw token value.
    pub fn to_json(&self) -> String {
        let serializable = SerializableMintEnvelope {
            token: &self.token,
            expires_at: self.expires_at.to_rfc3339(),
            token_id: &self.token_id,
            provider: &self.provider,
            role: &self.role,
        };
        serde_json::to_string(&serializable).expect("MintEnvelope serialization should never fail")
    }

    /// Produce a redacted log string for stderr/log output.
    /// still applies to stderr — the token value is replaced with
    /// its redacted form.
    pub fn to_log_string(&self) -> String {
        let redacted = RedactedToken::new(&self.token, Some(&self.token_id));
        format!(
            "minted token {} for provider={} role={}",
            redacted, self.provider, self.role
        )
    }
}

/// Input for the revoke subcommand.
/// Extracts only `token_id` and `provider` from the input source.
/// The raw token value is never stored.
#[derive(Debug)]
pub struct RevokeInput {
    token_id: String,
    provider: String,
}

impl RevokeInput {
    /// Create revoke input from explicit --token-id and --provider flags.
    pub fn from_token_id_and_provider(token_id: &str, provider: &str) -> Self {
        Self {
            token_id: token_id.to_string(),
            provider: provider.to_string(),
        }
    }

    /// Parse revoke input from a full mint JSON envelope via --from-stdin.
    /// Extracts only `token_id` and `provider`. The raw `token` field is
    /// read from JSON but never stored.
    #[rule("rule_token_revoke_stdin_envelope")]
    pub fn from_mint_json(json_str: &str) -> Result<Self, MintError> {
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| MintError::InvalidInput {
                message: format!("invalid JSON: {}", e),
            })?;

        let token_id = parsed
            .get("token_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MintError::InvalidInput {
                message: "missing required field: token_id".to_string(),
            })?;

        let provider = parsed
            .get("provider")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MintError::InvalidInput {
                message: "missing required field: provider".to_string(),
            })?;

        Ok(Self {
            token_id: token_id.to_string(),
            provider: provider.to_string(),
        })
    }

    /// Get the token ID for revocation.
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// Get the provider name for revocation.
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

/// Validate that revoke CLI arguments do not contain a --token flag.
/// The `--token-id` flag is allowed (it's an opaque identifier, not a secret).
/// The `--token` flag is rejected because it would pass raw secret values
/// via CLI args, visible in /proc/*/cmdline.
pub fn validate_revoke_args(args: &[String]) -> Result<(), MintError> {
    for (i, arg) in args.iter().enumerate() {
        // Reject --token and --token=<value> but allow --token-id and --token-id=<value>.
        // The distinction is critical: --token-id is an opaque identifier (safe for CLI),
        // while --token would carry the raw secret (visible in /proc/*/cmdline).
        if arg == "--token" || (arg.starts_with("--token=") && !arg.starts_with("--token-id")) {
            return Err(MintError::InvalidInput {
                message: format!(
                    "argument at index {} is --token; raw token values must not be \
                     passed as CLI arguments. Use --token-id or --from-stdin instead",
                    i
                ),
            });
        }
    }
    Ok(())
}

/// Validate mint subcommand arguments.
/// TTL is mandatory. At least one provider and a non-empty role are required.
pub fn validate_mint_args(
    ttl_secs: Option<u64>,
    providers: &[String],
    role: &str,
) -> Result<u64, MintError> {
    let ttl = SignalHandlingPolicy::validate_ttl(ttl_secs, &TtlBounds::default()).map_err(|e| {
        MintError::InvalidInput {
            message: match e {
                crate::core::signal_policy::TtlError::Missing => {
                    "--ttl is required for mint mode".to_string()
                }
                other => other.to_string(),
            },
        }
    })?;

    if providers.is_empty() {
        return Err(MintError::InvalidInput {
            message: "at least one provider is required".to_string(),
        });
    }

    if role.is_empty() {
        return Err(MintError::InvalidInput {
            message: "role must not be empty".to_string(),
        });
    }

    Ok(ttl)
}

/// Format mint output as a JSON array or empty string.
/// - Non-empty slice: serialized as a compact single-line JSON array.
/// - Empty slice: returns empty string (represents total failure — no stdout).
///
/// This enforces atomicity: the caller collects ALL envelopes before calling
/// this function, so partial output is structurally impossible.
pub fn format_mint_output(envelopes: &[MintEnvelope]) -> String {
    if envelopes.is_empty() {
        return String::new();
    }

    let serializable: Vec<SerializableMintEnvelope<'_>> = envelopes
        .iter()
        .map(|e| SerializableMintEnvelope {
            token: &e.token,
            expires_at: e.expires_at.to_rfc3339(),
            token_id: &e.token_id,
            provider: &e.provider,
            role: &e.role,
        })
        .collect();

    serde_json::to_string(&serializable)
        .expect("MintEnvelope array serialization should never fail")
}

/// Check that stdout is not a terminal.
/// If `is_tty` is true and `force` is false, returns an error with exit code 64.
/// Tokens in terminal scrollback are a security risk.
#[rule("rule_cross_terminal_refusal")]
pub fn check_stdout_not_terminal(is_tty: bool, force: bool) -> Result<(), MintError> {
    if is_tty && !force {
        return Err(MintError::TerminalDetected);
    }
    Ok(())
}

/// Error type for mint/revoke operations.
#[derive(Debug)]
pub enum MintError {
    /// Invalid input (bad args, missing fields, etc.).
    InvalidInput { message: String },
    /// stdout is a terminal — tokens in scrollback are a risk.
    TerminalDetected,
}

impl MintError {
    /// Get the noscope exit code for this error.
    pub fn exit_code(&self) -> NoscopeExitCode {
        match self {
            Self::InvalidInput { .. } => NoscopeExitCode::Usage,
            Self::TerminalDetected => NoscopeExitCode::Usage,
        }
    }
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { message } => write!(f, "mint/revoke error: {}", message),
            Self::TerminalDetected => write!(
                f,
                "refusing to output tokens to a terminal; stdout is a tty \
                 and tokens would remain in scrollback history. \
                 Redirect stdout to a pipe or file, or use --force to override"
            ),
        }
    }
}

impl std::error::Error for MintError {}

#[cfg(test)]
mod tests;
