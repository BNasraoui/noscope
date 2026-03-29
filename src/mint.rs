// NS-060: Mint output envelope
// NS-061: Revoke CLI input contract
// NS-062: Mint mode TTL requirement
// NS-063: Mint multi-provider atomicity
// NS-064: Redaction exception for mint stdout
// NS-065: Terminal detection for mint

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;
use zeroize::Zeroize;

use crate::exit_code::NoscopeExitCode;
use crate::redaction::RedactedToken;
use crate::token::ScopedToken;

/// NS-060: Mint output envelope for stdout.
///
/// Contains the raw token value — this is the ONE place where NS-005
/// (redaction) does not apply (NS-064). The `to_json()` method produces
/// the stdout output; `to_log_string()` produces the redacted stderr form.
///
/// Not Clone — the raw token value should not be duplicated carelessly.
/// NS-019: Token field is zeroized on drop.
pub struct MintEnvelope {
    token: String,
    expires_at: DateTime<Utc>,
    token_id: String,
    provider: String,
    role: String,
}

// NS-019: Zeroize the raw token value on drop. The token is stored in a
// plain String (not SecretString) because it needs to be serialized to
// stdout JSON. We compensate by manually zeroizing on drop.
impl Drop for MintEnvelope {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// NS-005 + NS-064: Debug never shows the raw token value.
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
/// Field names match the NS-060 JSON contract exactly.
#[derive(Serialize)]
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

    /// NS-060: Create a mint envelope from a ScopedToken.
    ///
    /// NS-064: This intentionally calls `expose_secret()` — the mint
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

    /// NS-060: Serialize to compact single-line JSON for stdout.
    ///
    /// NS-064: This output intentionally contains the raw token value.
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

    /// NS-064: Produce a redacted log string for stderr/log output.
    ///
    /// NS-005 still applies to stderr — the token value is replaced with
    /// its redacted form.
    pub fn to_log_string(&self) -> String {
        let redacted = RedactedToken::new(&self.token, Some(&self.token_id));
        format!(
            "minted token {} for provider={} role={}",
            redacted, self.provider, self.role
        )
    }
}

/// NS-061: Input for the revoke subcommand.
///
/// Extracts only `token_id` and `provider` from the input source.
/// The raw token value is never stored (NS-012).
#[derive(Debug)]
pub struct RevokeInput {
    token_id: String,
    provider: String,
}

impl RevokeInput {
    /// NS-061: Create revoke input from explicit --token-id and --provider flags.
    pub fn from_token_id_and_provider(token_id: &str, provider: &str) -> Self {
        Self {
            token_id: token_id.to_string(),
            provider: provider.to_string(),
        }
    }

    /// NS-061: Parse revoke input from a full mint JSON envelope via --from-stdin.
    ///
    /// Extracts only `token_id` and `provider`. The raw `token` field is
    /// read from JSON but never stored (NS-012).
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

/// NS-061/NS-012: Validate that revoke CLI arguments do not contain a --token flag.
///
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
                     passed as CLI arguments (NS-012). Use --token-id or --from-stdin instead",
                    i
                ),
            });
        }
    }
    Ok(())
}

/// NS-062: Validate mint subcommand arguments.
///
/// TTL is mandatory. At least one provider and a non-empty role are required.
pub fn validate_mint_args(
    ttl_secs: Option<u64>,
    providers: &[String],
    role: &str,
) -> Result<u64, MintError> {
    let ttl = ttl_secs.ok_or(MintError::InvalidInput {
        message: "--ttl is required for mint mode (NS-062)".to_string(),
    })?;

    if ttl == 0 {
        return Err(MintError::InvalidInput {
            message: "--ttl must be greater than zero".to_string(),
        });
    }

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

/// NS-063: Format mint output as a JSON array or empty string.
///
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

/// NS-065: Check that stdout is not a terminal.
///
/// If `is_tty` is true and `force` is false, returns an error with exit code 64.
/// Tokens in terminal scrollback are a security risk.
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
    /// NS-065: stdout is a terminal — tokens in scrollback are a risk.
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
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::Value;

    // =========================================================================
    // NS-060: Mint output envelope — JSON to stdout: token (string),
    // expires_at (ISO 8601), token_id (provider-supplied or UUID),
    // provider, role.
    // =========================================================================

    #[test]
    fn mint_output_envelope_contains_token_field() {
        let envelope = super::MintEnvelope::new(
            "secret-token-value",
            Utc::now() + chrono::Duration::hours(1),
            "tok-123",
            "aws",
            "admin",
        );
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["token"].as_str().unwrap(),
            "secret-token-value",
            "NS-060: envelope must contain 'token' field with raw value"
        );
    }

    #[test]
    fn mint_output_envelope_contains_expires_at_iso8601() {
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let envelope = super::MintEnvelope::new("tok-value", expiry, "tok-id", "aws", "admin");
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let expires_str = parsed["expires_at"].as_str().unwrap();
        // Must be valid ISO 8601 / RFC 3339
        let _parsed_dt: DateTime<Utc> = expires_str
            .parse()
            .expect("NS-060: expires_at must be valid ISO 8601");
    }

    #[test]
    fn mint_output_envelope_contains_token_id() {
        let envelope = super::MintEnvelope::new(
            "tok",
            Utc::now() + chrono::Duration::hours(1),
            "provider-tok-id-42",
            "gcp",
            "viewer",
        );
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["token_id"].as_str().unwrap(),
            "provider-tok-id-42",
            "NS-060: envelope must contain 'token_id' field"
        );
    }

    #[test]
    fn mint_output_envelope_contains_provider() {
        let envelope = super::MintEnvelope::new(
            "tok",
            Utc::now() + chrono::Duration::hours(1),
            "id",
            "vault",
            "deployer",
        );
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["provider"].as_str().unwrap(),
            "vault",
            "NS-060: envelope must contain 'provider' field"
        );
    }

    #[test]
    fn mint_output_envelope_contains_role() {
        let envelope = super::MintEnvelope::new(
            "tok",
            Utc::now() + chrono::Duration::hours(1),
            "id",
            "aws",
            "read-only",
        );
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["role"].as_str().unwrap(),
            "read-only",
            "NS-060: envelope must contain 'role' field"
        );
    }

    #[test]
    fn mint_output_envelope_has_exactly_five_fields() {
        let envelope = super::MintEnvelope::new(
            "tok",
            Utc::now() + chrono::Duration::hours(1),
            "id",
            "aws",
            "admin",
        );
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "NS-060: envelope must have exactly 5 fields (token, expires_at, token_id, provider, role), got: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn mint_output_envelope_is_single_line_json() {
        let envelope = super::MintEnvelope::new(
            "my-secret",
            Utc::now() + chrono::Duration::hours(1),
            "tid",
            "aws",
            "admin",
        );
        let json = envelope.to_json();
        assert!(
            !json.contains('\n'),
            "NS-060: mint envelope JSON must be single-line"
        );
    }

    #[test]
    fn mint_output_envelope_from_scoped_token() {
        use crate::token::ScopedToken;
        use secrecy::SecretString;

        let expiry = Utc::now() + chrono::Duration::hours(1);
        let token = ScopedToken::new(
            SecretString::from("raw-secret".to_string()),
            "admin",
            expiry,
            Some("tok-abc".to_string()),
            "aws",
        );
        let envelope = super::MintEnvelope::from_scoped_token(&token);
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["token"].as_str().unwrap(), "raw-secret");
        assert_eq!(parsed["provider"].as_str().unwrap(), "aws");
        assert_eq!(parsed["role"].as_str().unwrap(), "admin");
        assert_eq!(parsed["token_id"].as_str().unwrap(), "tok-abc");
    }

    // =========================================================================
    // NS-061: Revoke CLI input contract — accept --token-id+--provider or
    // full mint JSON via --from-stdin; token values never as CLI args (NS-012).
    // =========================================================================

    #[test]
    fn revoke_input_from_token_id_and_provider() {
        let input = super::RevokeInput::from_token_id_and_provider("tok-abc-123", "aws");
        assert_eq!(input.token_id(), "tok-abc-123");
        assert_eq!(input.provider(), "aws");
    }

    #[test]
    fn revoke_input_from_mint_json_stdin() {
        let mint_json = r#"{"token":"secret","expires_at":"2025-01-01T00:00:00Z","token_id":"tok-99","provider":"gcp","role":"viewer"}"#;
        let input = super::RevokeInput::from_mint_json(mint_json).unwrap();
        assert_eq!(input.token_id(), "tok-99");
        assert_eq!(input.provider(), "gcp");
    }

    #[test]
    fn revoke_input_from_mint_json_rejects_invalid_json() {
        let bad_json = "not valid json {{{";
        let result = super::RevokeInput::from_mint_json(bad_json);
        assert!(result.is_err(), "NS-061: invalid JSON must be rejected");
    }

    #[test]
    fn revoke_input_from_mint_json_rejects_missing_token_id() {
        let incomplete = r#"{"token":"secret","provider":"aws","role":"admin","expires_at":"2025-01-01T00:00:00Z"}"#;
        let result = super::RevokeInput::from_mint_json(incomplete);
        assert!(
            result.is_err(),
            "NS-061: mint JSON without token_id must be rejected"
        );
    }

    #[test]
    fn revoke_input_from_mint_json_rejects_missing_provider() {
        let incomplete = r#"{"token":"secret","token_id":"tok-1","role":"admin","expires_at":"2025-01-01T00:00:00Z"}"#;
        let result = super::RevokeInput::from_mint_json(incomplete);
        assert!(
            result.is_err(),
            "NS-061: mint JSON without provider must be rejected"
        );
    }

    #[test]
    fn revoke_input_does_not_store_token_value() {
        // NS-012/NS-061: The revoke input must NOT retain the raw token value.
        // Only token_id and provider are needed for revocation.
        let mint_json = r#"{"token":"super-secret-value","expires_at":"2025-01-01T00:00:00Z","token_id":"tok-99","provider":"gcp","role":"viewer"}"#;
        let input = super::RevokeInput::from_mint_json(mint_json).unwrap();
        let debug = format!("{:?}", input);
        assert!(
            !debug.contains("super-secret-value"),
            "NS-061/NS-012: RevokeInput must not store the raw token value, got debug: {}",
            debug
        );
    }

    #[test]
    fn revoke_input_validates_no_token_value_in_cli_args() {
        // NS-012: Token values must never appear as CLI arguments.
        // validate_no_token_in_args checks that no argument looks like a raw token.
        let result = super::validate_revoke_args(&[
            "noscope".to_string(),
            "revoke".to_string(),
            "--token-id".to_string(),
            "tok-123".to_string(),
            "--provider".to_string(),
            "aws".to_string(),
        ]);
        assert!(
            result.is_ok(),
            "NS-061: --token-id and --provider args are allowed (not raw token values)"
        );
    }

    #[test]
    fn revoke_input_rejects_raw_token_flag() {
        // NS-012: A --token flag with the actual secret value must be rejected.
        let result = super::validate_revoke_args(&[
            "noscope".to_string(),
            "revoke".to_string(),
            "--token".to_string(),
            "actual-secret-value".to_string(),
        ]);
        assert!(
            result.is_err(),
            "NS-061/NS-012: --token flag with raw secret value must be rejected"
        );
    }

    // =========================================================================
    // NS-062: Mint mode TTL requirement — --ttl required; no refresh/revocation
    // unless explicit noscope revoke; caller responsibility after mint.
    // =========================================================================

    #[test]
    fn mint_ttl_requirement_ttl_is_mandatory() {
        let result = super::validate_mint_args(None, &["aws".to_string()], "admin");
        assert!(
            result.is_err(),
            "NS-062: --ttl must be required for mint mode"
        );
    }

    #[test]
    fn mint_ttl_requirement_accepts_valid_ttl() {
        let result = super::validate_mint_args(Some(3600), &["aws".to_string()], "admin");
        assert!(result.is_ok(), "NS-062: valid TTL should be accepted");
    }

    #[test]
    fn mint_ttl_requirement_rejects_zero_ttl() {
        let result = super::validate_mint_args(Some(0), &["aws".to_string()], "admin");
        assert!(result.is_err(), "NS-062: zero TTL must be rejected");
    }

    #[test]
    fn mint_ttl_requirement_rejects_empty_providers() {
        let result = super::validate_mint_args(Some(3600), &[], "admin");
        assert!(result.is_err(), "NS-062: at least one provider is required");
    }

    #[test]
    fn mint_ttl_requirement_rejects_empty_role() {
        let result = super::validate_mint_args(Some(3600), &["aws".to_string()], "");
        assert!(result.is_err(), "NS-062: empty role must be rejected");
    }

    // =========================================================================
    // NS-063: Mint multi-provider atomicity — follows NS-006; output is JSON
    // array or nothing on failure; no partial stdout.
    // =========================================================================

    #[test]
    fn mint_multi_provider_atomicity_single_provider_returns_object() {
        let envelope = super::MintEnvelope::new(
            "tok",
            Utc::now() + chrono::Duration::hours(1),
            "id",
            "aws",
            "admin",
        );
        let output = super::format_mint_output(&[envelope]);
        let parsed: Value = serde_json::from_str(&output).unwrap();
        // Single provider: still a JSON array per NS-063
        assert!(
            parsed.is_array(),
            "NS-063: single provider output must be a JSON array, got: {}",
            output
        );
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn mint_multi_provider_atomicity_multiple_providers_returns_array() {
        let e1 = super::MintEnvelope::new(
            "tok1",
            Utc::now() + chrono::Duration::hours(1),
            "id1",
            "aws",
            "admin",
        );
        let e2 = super::MintEnvelope::new(
            "tok2",
            Utc::now() + chrono::Duration::hours(1),
            "id2",
            "gcp",
            "viewer",
        );
        let output = super::format_mint_output(&[e1, e2]);
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert!(
            parsed.is_array(),
            "NS-063: multi-provider output must be a JSON array"
        );
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn mint_multi_provider_atomicity_empty_on_failure() {
        // NS-063: On failure, output is nothing — empty string.
        let output = super::format_mint_output(&[]);
        assert!(
            output.is_empty(),
            "NS-063: on failure (no successful mints), output must be empty, got: {:?}",
            output
        );
    }

    #[test]
    fn mint_multi_provider_atomicity_no_partial_stdout() {
        // NS-063: The output must be all-or-nothing. The function takes
        // a complete slice of envelopes — partial results are not representable.
        // This test verifies the API design: you can't add envelopes incrementally.
        let e1 = super::MintEnvelope::new(
            "tok1",
            Utc::now() + chrono::Duration::hours(1),
            "id1",
            "aws",
            "admin",
        );
        let output = super::format_mint_output(&[e1]);
        let parsed: Value = serde_json::from_str(&output).unwrap();
        // Verify it's valid JSON — no partial/broken output
        assert!(parsed.is_array());
    }

    #[test]
    fn mint_multi_provider_atomicity_output_is_single_line() {
        let e1 = super::MintEnvelope::new(
            "tok1",
            Utc::now() + chrono::Duration::hours(1),
            "id1",
            "aws",
            "admin",
        );
        let e2 = super::MintEnvelope::new(
            "tok2",
            Utc::now() + chrono::Duration::hours(1),
            "id2",
            "gcp",
            "viewer",
        );
        let output = super::format_mint_output(&[e1, e2]);
        assert!(
            !output.contains('\n'),
            "NS-063: mint output must be single-line JSON"
        );
    }

    // =========================================================================
    // NS-064: Redaction exception for mint stdout — NS-005 does not apply to
    // mint stdout (by definition contains token); still applies to stderr/logs.
    // =========================================================================

    #[test]
    fn redaction_exception_mint_stdout_contains_raw_token() {
        // NS-064: The mint envelope intentionally contains the raw token value.
        // This is the whole point of the mint subcommand.
        let envelope = super::MintEnvelope::new(
            "raw-secret-credential-12345",
            Utc::now() + chrono::Duration::hours(1),
            "tid",
            "aws",
            "admin",
        );
        let json = envelope.to_json();
        assert!(
            json.contains("raw-secret-credential-12345"),
            "NS-064: mint stdout must contain the raw token value"
        );
    }

    #[test]
    fn redaction_exception_stderr_still_redacted() {
        // NS-064: NS-005 still applies to stderr/log messages.
        // MintEnvelope must provide a redacted form for logging purposes.
        let envelope = super::MintEnvelope::new(
            "secret-that-should-not-appear-in-logs",
            Utc::now() + chrono::Duration::hours(1),
            "tid",
            "aws",
            "admin",
        );
        let log_msg = envelope.to_log_string();
        assert!(
            !log_msg.contains("secret-that-should-not-appear-in-logs"),
            "NS-064: stderr/log output must still redact token value, got: {}",
            log_msg
        );
    }

    #[test]
    fn redaction_exception_log_string_contains_provider_and_role() {
        let envelope = super::MintEnvelope::new(
            "secret",
            Utc::now() + chrono::Duration::hours(1),
            "tid",
            "vault",
            "deployer",
        );
        let log_msg = envelope.to_log_string();
        assert!(
            log_msg.contains("vault"),
            "NS-064: log string should contain provider"
        );
        assert!(
            log_msg.contains("deployer"),
            "NS-064: log string should contain role"
        );
    }

    // =========================================================================
    // NS-065: Terminal detection for mint — if stdout isatty, warn to stderr
    // and exit 64 unless --force; tokens in scrollback are a risk.
    // =========================================================================

    #[test]
    fn terminal_detection_rejects_tty_stdout() {
        // NS-065: If stdout is a terminal, mint should be rejected.
        let result = super::check_stdout_not_terminal(true, false);
        assert!(
            result.is_err(),
            "NS-065: mint to terminal stdout must be rejected"
        );
    }

    #[test]
    fn terminal_detection_allows_pipe_stdout() {
        // NS-065: If stdout is a pipe (not a terminal), mint is allowed.
        let result = super::check_stdout_not_terminal(false, false);
        assert!(
            result.is_ok(),
            "NS-065: mint to piped stdout must be allowed"
        );
    }

    #[test]
    fn terminal_detection_force_overrides_tty_check() {
        // NS-065: --force flag overrides the terminal check.
        let result = super::check_stdout_not_terminal(true, true);
        assert!(
            result.is_ok(),
            "NS-065: --force must override terminal detection"
        );
    }

    #[test]
    fn terminal_detection_exit_code_is_64() {
        // NS-065: The exit code for terminal detection failure is 64 (usage error).
        let err = super::check_stdout_not_terminal(true, false).unwrap_err();
        assert_eq!(
            err.exit_code().as_raw(),
            64,
            "NS-065: terminal detection failure must exit with code 64"
        );
    }

    #[test]
    fn terminal_detection_error_message_warns_about_scrollback() {
        let err = super::check_stdout_not_terminal(true, false).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.to_lowercase().contains("terminal") || msg.to_lowercase().contains("tty"),
            "NS-065: error message must mention terminal/tty, got: {}",
            msg
        );
    }

    #[test]
    fn terminal_detection_error_message_mentions_force_flag() {
        let err = super::check_stdout_not_terminal(true, false).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("--force"),
            "NS-065: error message must mention --force flag, got: {}",
            msg
        );
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn mint_envelope_debug_does_not_expose_raw_token() {
        // NS-005/NS-064: Debug output must redact the token value.
        let envelope = super::MintEnvelope::new(
            "super-secret-credential-that-must-not-leak",
            Utc::now() + chrono::Duration::hours(1),
            "tid",
            "aws",
            "admin",
        );
        let debug = format!("{:?}", envelope);
        assert!(
            !debug.contains("super-secret-credential-that-must-not-leak"),
            "Debug must not expose raw token, got: {}",
            debug
        );
    }

    #[test]
    fn mint_envelope_debug_shows_metadata() {
        let envelope = super::MintEnvelope::new(
            "secret",
            Utc::now() + chrono::Duration::hours(1),
            "tid-xyz",
            "vault",
            "deployer",
        );
        let debug = format!("{:?}", envelope);
        assert!(debug.contains("vault"), "Debug should show provider");
        assert!(debug.contains("deployer"), "Debug should show role");
        assert!(debug.contains("tid-xyz"), "Debug should show token_id");
        assert!(
            debug.contains("MintEnvelope"),
            "Debug should show type name"
        );
    }

    #[test]
    fn mint_envelope_is_not_clone() {
        static_assertions::assert_not_impl_any!(super::MintEnvelope: Clone);
    }

    #[test]
    fn revoke_input_rejects_combined_token_equals_value_flag() {
        // NS-012: --token=<secret> combined form must also be rejected.
        let result = super::validate_revoke_args(&[
            "noscope".to_string(),
            "revoke".to_string(),
            "--token=actual-secret-value".to_string(),
        ]);
        assert!(
            result.is_err(),
            "NS-061/NS-012: --token=value combined form must be rejected"
        );
    }

    #[test]
    fn revoke_input_allows_token_id_equals_combined_form() {
        // --token-id=tok-123 is safe (opaque identifier, not a secret)
        let result = super::validate_revoke_args(&[
            "noscope".to_string(),
            "revoke".to_string(),
            "--token-id=tok-123".to_string(),
            "--provider".to_string(),
            "aws".to_string(),
        ]);
        assert!(
            result.is_ok(),
            "NS-061: --token-id=value combined form should be allowed"
        );
    }

    #[test]
    fn revoke_input_from_mint_json_array_element() {
        // NS-063 outputs a JSON array. Revoke should handle a single element
        // extracted from that array.
        let array_element = r#"{"token":"secret","expires_at":"2025-01-01T00:00:00Z","token_id":"tok-from-array","provider":"aws","role":"admin"}"#;
        let input = super::RevokeInput::from_mint_json(array_element).unwrap();
        assert_eq!(input.token_id(), "tok-from-array");
        assert_eq!(input.provider(), "aws");
    }

    #[test]
    fn mint_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<super::MintError>();
    }

    #[test]
    fn format_mint_output_handles_special_characters_in_token() {
        // Tokens may contain characters that need JSON escaping.
        let envelope = super::MintEnvelope::new(
            "tok-with-\"quotes\"-and-\\backslashes",
            Utc::now() + chrono::Duration::hours(1),
            "tid",
            "aws",
            "admin",
        );
        let output = super::format_mint_output(&[envelope]);
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(
            arr[0]["token"].as_str().unwrap(),
            "tok-with-\"quotes\"-and-\\backslashes",
            "Special characters must survive JSON round-trip"
        );
    }

    #[test]
    fn mint_envelope_from_scoped_token_without_token_id() {
        // When ScopedToken has no token_id, envelope should use empty string.
        use crate::token::ScopedToken;
        use secrecy::SecretString;

        let token = ScopedToken::new(
            SecretString::from("secret".to_string()),
            "admin",
            Utc::now() + chrono::Duration::hours(1),
            None,
            "aws",
        );
        let envelope = super::MintEnvelope::from_scoped_token(&token);
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["token_id"].as_str().unwrap(),
            "",
            "Missing token_id should produce empty string"
        );
    }

    #[test]
    fn validate_mint_args_returns_validated_ttl() {
        let result = super::validate_mint_args(Some(7200), &["aws".to_string()], "admin");
        assert_eq!(
            result.unwrap(),
            7200,
            "validate_mint_args should return the validated TTL value"
        );
    }

    #[test]
    fn mint_error_display_for_invalid_input() {
        let err = super::MintError::InvalidInput {
            message: "test error".to_string(),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("test error"),
            "Display should include the message"
        );
    }

    #[test]
    fn terminal_detection_pipe_with_force_also_works() {
        // Edge case: force=true, is_tty=false should still succeed
        let result = super::check_stdout_not_terminal(false, true);
        assert!(result.is_ok(), "Non-terminal with --force should succeed");
    }
}
