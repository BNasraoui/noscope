// NS-009: Provider output contract
// NS-033: Template variable injection prevention
// NS-034: Missing expires_at computed from requested TTL
// NS-035: Provider command execution timeout
// NS-036: Provider stdout size limit
// NS-037: TTL format is integer seconds for providers
// NS-038: Revoke command receives token via env var
// NS-039: Refresh command receives token via env var
// NS-040: Provider stderr handling
// NS-041: Provider capability declaration
// NS-068: Provider command environment sandboxing

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use zeroize::Zeroize;

/// NS-036: Maximum provider stdout size in bytes (1 MiB).
pub const MAX_STDOUT_BYTES: usize = 1024 * 1024;

/// NS-040: Maximum stderr bytes captured on failure.
pub const MAX_STDERR_CAPTURE_BYTES: usize = 4096;

/// NS-009 + NS-034: Parsed provider command output.
///
/// Contains the token value and expiry time. If the provider did not
/// supply `expires_at`, it is computed from the requested TTL and
/// `expires_at_provided` is `false` (the caller should emit a warning
/// per NS-034).
#[derive(Debug)]
pub struct ProviderOutput {
    /// The raw token string from the provider.
    pub token: String,
    /// The expiry time — either from the provider or computed from TTL.
    pub expires_at: DateTime<Utc>,
    /// Whether the provider explicitly supplied `expires_at`.
    /// `false` means it was computed from `now() + requested_ttl` (NS-034).
    pub expires_at_provided: bool,
}

// NS-019: Zeroize the raw token value on drop, matching MintEnvelope pattern.
// ProviderOutput is a transient parsing result, but the token lives in memory
// until this struct is dropped.
impl Drop for ProviderOutput {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Error type for provider command execution.
#[derive(Debug)]
pub enum ProviderExecError {
    /// NS-009: Provider output violated the JSON contract.
    OutputContract { message: String },
    /// NS-035: Provider command timed out.
    Timeout { timeout: Duration },
    /// NS-036: Provider stdout exceeded size limit.
    StdoutTooLarge { size: usize, limit: usize },
    /// NS-033: Invalid role string.
    InvalidRole { role: String, reason: String },
    /// NS-041: Capability/config inconsistency.
    CapabilityMismatch { message: String },
    /// Config parsing error (not a provider output issue).
    ConfigParse { message: String },
}

impl ProviderExecError {
    /// Map this error to a provider exit code.
    ///
    /// NS-035: Timeout is treated as exit code 4 (Unavailable).
    pub fn as_provider_exit_code(&self) -> i32 {
        match self {
            Self::Timeout { .. } => 4,
            _ => 1,
        }
    }
}

impl fmt::Display for ProviderExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputContract { message } => {
                write!(f, "provider output contract violation: {}", message)
            }
            Self::Timeout { timeout } => {
                write!(f, "provider command timed out after {}s", timeout.as_secs())
            }
            Self::StdoutTooLarge { size, limit } => {
                write!(
                    f,
                    "provider stdout too large: {} bytes exceeds {} byte limit",
                    size, limit
                )
            }
            Self::InvalidRole { role, reason } => {
                write!(f, "invalid role '{}': {}", role, reason)
            }
            Self::CapabilityMismatch { message } => {
                write!(f, "provider capability mismatch: {}", message)
            }
            Self::ConfigParse { message } => {
                write!(f, "provider config parse error: {}", message)
            }
        }
    }
}

impl std::error::Error for ProviderExecError {}

/// NS-035: Configuration for provider command execution.
pub struct ExecConfig {
    /// NS-035: Command timeout (default 30s).
    pub timeout: Duration,
    /// NS-035: Grace period after SIGTERM before SIGKILL (default 5s).
    pub kill_grace_period: Duration,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            kill_grace_period: Duration::from_secs(5),
        }
    }
}

/// NS-041: Provider capability declaration.
///
/// Owned by crate::provider so capability parsing/validation shares the same
/// parsing flow as provider config.
pub type ProviderCapabilities = crate::provider::ProviderCapabilities;

/// NS-040: Policy for handling provider stderr.
pub struct StderrPolicy {
    discard: bool,
}

impl StderrPolicy {
    /// NS-040: On success, discard stderr unless verbose.
    pub fn on_success(verbose: bool) -> Self {
        Self { discard: !verbose }
    }

    /// NS-040: On failure, always capture stderr.
    pub fn on_failure() -> Self {
        Self { discard: false }
    }

    /// Whether stderr should be discarded.
    pub fn should_discard(&self) -> bool {
        self.discard
    }
}

// ---------------------------------------------------------------------------
// NS-009 + NS-034: Parse provider JSON output
// ---------------------------------------------------------------------------

/// NS-009: Parse provider command stdout as JSON.
///
/// Extracts `token` (required, string) and `expires_at` (optional, ISO 8601).
/// If `expires_at` is absent, computes `now() + requested_ttl_secs` and sets
/// `expires_at_provided = false` so the caller can emit the NS-034 warning.
pub fn parse_provider_output(
    json_str: &str,
    requested_ttl_secs: u64,
) -> Result<ProviderOutput, ProviderExecError> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| ProviderExecError::OutputContract {
            message: format!("invalid JSON: {}", e),
        })?;

    // NS-009: 'token' is required and must be a non-empty string.
    let token = parsed
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProviderExecError::OutputContract {
            message: "missing or non-string 'token' field".to_string(),
        })?;

    if token.is_empty() {
        return Err(ProviderExecError::OutputContract {
            message: "'token' field must not be empty".to_string(),
        });
    }

    // NS-009 + NS-034: 'expires_at' is optional.
    let (expires_at, provided) = match parsed.get("expires_at").and_then(|v| v.as_str()) {
        Some(s) => {
            let dt: DateTime<Utc> = s.parse().map_err(|e| ProviderExecError::OutputContract {
                message: format!("invalid ISO 8601 expires_at '{}': {}", s, e),
            })?;
            (dt, true)
        }
        None => {
            // NS-034: Compute from requested TTL.
            let dt = Utc::now() + chrono::Duration::seconds(requested_ttl_secs as i64);
            (dt, false)
        }
    };

    Ok(ProviderOutput {
        token: token.to_string(),
        expires_at,
        expires_at_provided: provided,
    })
}

// ---------------------------------------------------------------------------
// NS-033: Role validation and template variable substitution
// ---------------------------------------------------------------------------

/// NS-033: Validate that a role string contains only safe characters.
///
/// Allowed: alphanumeric, hyphens, underscores, dots.
/// Rejected: empty string, spaces, shell metacharacters, slashes, etc.
pub fn validate_role(role: &str) -> Result<(), ProviderExecError> {
    if role.is_empty() {
        return Err(ProviderExecError::InvalidRole {
            role: role.to_string(),
            reason: "role must not be empty".to_string(),
        });
    }

    for ch in role.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.') {
            return Err(ProviderExecError::InvalidRole {
                role: role.to_string(),
                reason: format!(
                    "invalid character '{}'; only alphanumeric, hyphens, underscores, and dots are allowed",
                    ch
                ),
            });
        }
    }

    Ok(())
}

/// NS-033 + NS-037: Substitute template variables in an argv array.
///
/// Replaces `{role}` with the role string and `{ttl}` with TTL as integer
/// seconds. This is pure string replacement on each element of the array —
/// no shell is involved.
pub fn substitute_template_vars(template: &[String], role: &str, ttl_secs: u64) -> Vec<String> {
    let ttl_str = ttl_secs.to_string();
    template
        .iter()
        .map(|arg| arg.replace("{role}", role).replace("{ttl}", &ttl_str))
        .collect()
}

// ---------------------------------------------------------------------------
// NS-036: Stdout size limit
// ---------------------------------------------------------------------------

/// NS-036: Check that provider stdout does not exceed 1 MiB.
pub fn check_stdout_size_limit(size: usize) -> Result<(), ProviderExecError> {
    if size > MAX_STDOUT_BYTES {
        return Err(ProviderExecError::StdoutTooLarge {
            size,
            limit: MAX_STDOUT_BYTES,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NS-038: Revoke command environment variables
// ---------------------------------------------------------------------------

/// NS-038: Build environment variables for a revoke command.
///
/// Sets NOSCOPE_TOKEN and NOSCOPE_TOKEN_ID. Does NOT set NOSCOPE_TTL
/// (that's only for refresh per NS-039).
pub fn build_revoke_env(token: &str, token_id: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("NOSCOPE_TOKEN".to_string(), token.to_string());
    env.insert("NOSCOPE_TOKEN_ID".to_string(), token_id.to_string());
    env
}

/// NS-038: Check if a revoke command exit code indicates success.
///
/// Exit 0 is success, including the case where the token was already revoked.
pub fn is_revoke_success(exit_code: i32) -> bool {
    exit_code == 0
}

// ---------------------------------------------------------------------------
// NS-039: Refresh command environment variables
// ---------------------------------------------------------------------------

/// NS-039: Build environment variables for a refresh command.
///
/// Sets NOSCOPE_TOKEN, NOSCOPE_TOKEN_ID, and NOSCOPE_TTL (integer seconds).
pub fn build_refresh_env(token: &str, token_id: &str, ttl_secs: u64) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("NOSCOPE_TOKEN".to_string(), token.to_string());
    env.insert("NOSCOPE_TOKEN_ID".to_string(), token_id.to_string());
    env.insert("NOSCOPE_TTL".to_string(), ttl_secs.to_string());
    env
}

// ---------------------------------------------------------------------------
// NS-040: Provider stderr handling
// ---------------------------------------------------------------------------

/// NS-040: Capture stderr up to the size limit.
///
/// Truncates to `MAX_STDERR_CAPTURE_BYTES` (4096 bytes).
pub fn capture_stderr(stderr: &str) -> &str {
    if stderr.len() <= MAX_STDERR_CAPTURE_BYTES {
        stderr
    } else {
        // Truncate at a safe UTF-8 boundary.
        let mut end = MAX_STDERR_CAPTURE_BYTES;
        while end > 0 && !stderr.is_char_boundary(end) {
            end -= 1;
        }
        &stderr[..end]
    }
}

/// NS-040: Redact known token values from stderr.
///
/// Replaces each occurrence of a known token with `[redacted]`.
pub fn redact_stderr(stderr: &str, known_tokens: &[&str]) -> String {
    let mut result = stderr.to_string();
    for token in known_tokens {
        if !token.is_empty() {
            result = result.replace(token, "[redacted]");
        }
    }
    result
}

// ---------------------------------------------------------------------------
// NS-041: Provider capability declaration
// ---------------------------------------------------------------------------

/// NS-041: Parse capability booleans from provider TOML content.
///
/// Looks for top-level `supports_refresh` and `supports_revoke` booleans.
/// Defaults to `false` if absent.
pub fn parse_capabilities_from_toml(
    content: &str,
) -> Result<ProviderCapabilities, ProviderExecError> {
    let parsed = crate::provider::parse_provider_toml(content).map_err(|e| {
        ProviderExecError::ConfigParse {
            message: e.to_string(),
        }
    })?;
    Ok(parsed.capabilities)
}

/// NS-041: Validate that capability declarations are consistent with
/// configured commands.
///
/// If `supports_refresh` is true, a refresh command must be present.
/// If `supports_revoke` is true, a revoke command must be present.
pub fn validate_capabilities(
    caps: &ProviderCapabilities,
    has_refresh_cmd: bool,
    has_revoke_cmd: bool,
) -> Result<(), ProviderExecError> {
    crate::provider::validate_declared_capabilities(caps, has_refresh_cmd, has_revoke_cmd).map_err(
        |e| ProviderExecError::CapabilityMismatch {
            message: e.to_string(),
        },
    )
}

// ---------------------------------------------------------------------------
// NS-068: Provider command environment sandboxing
// ---------------------------------------------------------------------------

/// NS-068: Build a minimal sandboxed environment for provider commands.
///
/// Contains only PATH, HOME, and LANG from the current environment.
/// All other environment variables are excluded.
pub fn build_sandboxed_env() -> HashMap<String, String> {
    let mut env = HashMap::new();

    // Use current env values with sensible fallbacks.
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let lang = std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".to_string());

    env.insert("PATH".to_string(), path);
    env.insert("HOME".to_string(), home);
    env.insert("LANG".to_string(), lang);

    env
}

#[cfg(test)]
mod tests {
    use chrono::Datelike;
    use std::time::Duration;

    // =========================================================================
    // NS-009: Provider output contract — JSON with 'token' (required) and
    // 'expires_at' (optional ISO 8601).
    // =========================================================================

    #[test]
    fn provider_output_contract_parses_valid_json_with_token_and_expires_at() {
        let json = r#"{"token": "my-secret-token-123", "expires_at": "2026-03-30T12:00:00Z"}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_ok(),
            "NS-009: valid JSON with token and expires_at must parse, got: {:?}",
            result
        );
        let output = result.unwrap();
        assert_eq!(output.token, "my-secret-token-123");
        assert!(
            output.expires_at_provided,
            "expires_at was provided in JSON"
        );
    }

    #[test]
    fn provider_output_contract_token_is_required() {
        let json = r#"{"expires_at": "2026-03-30T12:00:00Z"}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_err(),
            "NS-009: JSON without 'token' must be rejected"
        );
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.to_lowercase().contains("token"),
            "Error must mention missing 'token' field, got: {}",
            msg
        );
    }

    #[test]
    fn provider_output_contract_empty_token_is_rejected() {
        let json = r#"{"token": ""}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_err(),
            "NS-009: empty 'token' value must be rejected"
        );
    }

    #[test]
    fn provider_output_contract_token_must_be_string() {
        let json = r#"{"token": 12345}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_err(),
            "NS-009: non-string 'token' must be rejected"
        );
    }

    #[test]
    fn provider_output_contract_expires_at_is_optional() {
        // NS-009 says expires_at is optional; NS-034 governs the fallback.
        let json = r#"{"token": "my-secret-token-123"}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_ok(),
            "NS-009: JSON without expires_at must be accepted, got: {:?}",
            result
        );
        let output = result.unwrap();
        assert!(
            !output.expires_at_provided,
            "expires_at was NOT provided in JSON"
        );
    }

    #[test]
    fn provider_output_contract_expires_at_must_be_valid_iso8601() {
        let json = r#"{"token": "tok", "expires_at": "not-a-date"}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_err(),
            "NS-009: invalid ISO 8601 expires_at must be rejected"
        );
    }

    #[test]
    fn provider_output_contract_rejects_invalid_json() {
        let result = super::parse_provider_output("not json {{{", 3600);
        assert!(result.is_err(), "NS-009: invalid JSON must be rejected");
    }

    #[test]
    fn provider_output_contract_extra_fields_are_ignored() {
        // Provider may include extra fields; noscope ignores them.
        let json = r#"{"token": "tok", "expires_at": "2026-03-30T12:00:00Z", "extra": "ignored"}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(result.is_ok(), "NS-009: extra fields should be ignored");
    }

    // =========================================================================
    // NS-033: Template variable injection prevention — argv array substitution,
    // never shell; role validated alphanumeric+hyphens+underscores+dots.
    // =========================================================================

    #[test]
    fn template_variable_injection_prevention_role_valid_alphanumeric() {
        assert!(super::validate_role("admin").is_ok());
        assert!(super::validate_role("read-only").is_ok());
        assert!(super::validate_role("my_role").is_ok());
        assert!(super::validate_role("my.role.v2").is_ok());
        assert!(super::validate_role("Admin-Role_v2.1").is_ok());
    }

    #[test]
    fn template_variable_injection_prevention_role_rejects_shell_metacharacters() {
        assert!(
            super::validate_role("admin; rm -rf /").is_err(),
            "NS-033: role with semicolon must be rejected"
        );
        assert!(
            super::validate_role("admin$(whoami)").is_err(),
            "NS-033: role with command substitution must be rejected"
        );
        assert!(
            super::validate_role("admin`whoami`").is_err(),
            "NS-033: role with backtick must be rejected"
        );
        assert!(
            super::validate_role("admin|cat /etc/passwd").is_err(),
            "NS-033: role with pipe must be rejected"
        );
    }

    #[test]
    fn template_variable_injection_prevention_role_rejects_empty() {
        assert!(
            super::validate_role("").is_err(),
            "NS-033: empty role must be rejected"
        );
    }

    #[test]
    fn template_variable_injection_prevention_role_rejects_spaces() {
        assert!(
            super::validate_role("admin user").is_err(),
            "NS-033: role with spaces must be rejected"
        );
    }

    #[test]
    fn template_variable_injection_prevention_role_rejects_slashes() {
        assert!(
            super::validate_role("admin/subdir").is_err(),
            "NS-033: role with forward slash must be rejected"
        );
        assert!(
            super::validate_role("admin\\subdir").is_err(),
            "NS-033: role with backslash must be rejected"
        );
    }

    #[test]
    fn template_variable_injection_prevention_argv_substitution() {
        // Template variables are substituted in an argv array, never via shell.
        let template = vec![
            "/usr/bin/mint".to_string(),
            "--role".to_string(),
            "{role}".to_string(),
            "--ttl".to_string(),
            "{ttl}".to_string(),
        ];
        let result = super::substitute_template_vars(&template, "admin", 3600);
        assert_eq!(result[0], "/usr/bin/mint");
        assert_eq!(result[1], "--role");
        assert_eq!(result[2], "admin");
        assert_eq!(result[3], "--ttl");
        assert_eq!(result[4], "3600");
    }

    #[test]
    fn template_variable_injection_prevention_no_shell_expansion() {
        // Even if the role contains shell-like patterns, they are passed literally
        // (after validation — which would reject them. This tests the substitution
        // itself doesn't invoke a shell).
        let template = vec!["/usr/bin/mint".to_string(), "{role}".to_string()];
        // Note: in practice this role would fail validate_role(), but we're
        // testing that substitute_template_vars is a pure string replacement.
        let result = super::substitute_template_vars(&template, "literal-value", 100);
        assert_eq!(result[1], "literal-value");
    }

    #[test]
    fn template_variable_injection_prevention_multiple_role_substitutions() {
        let template = vec![
            "/usr/bin/cmd".to_string(),
            "--a={role}".to_string(),
            "--b={role}".to_string(),
        ];
        let result = super::substitute_template_vars(&template, "myrole", 60);
        assert_eq!(result[1], "--a=myrole");
        assert_eq!(result[2], "--b=myrole");
    }

    #[test]
    fn template_variable_injection_prevention_ttl_substituted_as_integer_string() {
        let template = vec!["/cmd".to_string(), "{ttl}".to_string()];
        let result = super::substitute_template_vars(&template, "role", 7200);
        assert_eq!(result[1], "7200");
    }

    // =========================================================================
    // NS-034: Missing expires_at computed from requested TTL — now() +
    // requested_ttl with warning.
    // =========================================================================

    #[test]
    fn missing_expires_at_computed_from_requested_ttl() {
        let json = r#"{"token": "tok-123"}"#;
        let before = chrono::Utc::now();
        let result = super::parse_provider_output(json, 3600).unwrap();
        let after = chrono::Utc::now();

        assert!(
            !result.expires_at_provided,
            "NS-034: expires_at was not provided"
        );
        // The computed expires_at should be approximately now + 3600s
        let expected_min = before + chrono::Duration::seconds(3600);
        let expected_max = after + chrono::Duration::seconds(3600);
        assert!(
            result.expires_at >= expected_min && result.expires_at <= expected_max,
            "NS-034: computed expires_at should be now + requested_ttl, got: {:?}, expected between {:?} and {:?}",
            result.expires_at, expected_min, expected_max
        );
    }

    #[test]
    fn missing_expires_at_generates_warning() {
        let json = r#"{"token": "tok"}"#;
        let result = super::parse_provider_output(json, 3600).unwrap();
        assert!(
            !result.expires_at_provided,
            "NS-034: expires_at was not provided, warning should be generated"
        );
        // The caller checks expires_at_provided to emit the warning.
    }

    #[test]
    fn provided_expires_at_is_used_as_is() {
        let json = r#"{"token": "tok", "expires_at": "2099-12-31T23:59:59Z"}"#;
        let result = super::parse_provider_output(json, 3600).unwrap();
        assert!(result.expires_at_provided);
        assert_eq!(
            result.expires_at.year(),
            2099,
            "NS-034: provided expires_at must be used as-is"
        );
    }

    // =========================================================================
    // NS-035: Provider command execution timeout — default 30s, SIGTERM then
    // SIGKILL after 5s, treat as exit 4.
    // =========================================================================

    #[test]
    fn provider_command_execution_timeout_default_is_30_seconds() {
        let config = super::ExecConfig::default();
        assert_eq!(
            config.timeout,
            Duration::from_secs(30),
            "NS-035: default provider command timeout must be 30s"
        );
    }

    #[test]
    fn provider_command_execution_timeout_kill_grace_period_is_5_seconds() {
        let config = super::ExecConfig::default();
        assert_eq!(
            config.kill_grace_period,
            Duration::from_secs(5),
            "NS-035: SIGKILL grace period after SIGTERM must be 5s"
        );
    }

    #[test]
    fn provider_command_execution_timeout_treated_as_exit_4() {
        // When a provider times out, it's treated as exit code 4 (Unavailable).
        let result = super::ProviderExecError::Timeout {
            timeout: Duration::from_secs(30),
        };
        assert_eq!(
            result.as_provider_exit_code(),
            4,
            "NS-035: timeout must be treated as exit code 4 (unavailable)"
        );
    }

    // =========================================================================
    // NS-036: Provider stdout size limit — reject output exceeding 1 MiB.
    // =========================================================================

    #[test]
    fn provider_stdout_size_limit_accepts_small_output() {
        let small = "x".repeat(1024); // 1 KiB
        assert!(
            super::check_stdout_size_limit(small.len()).is_ok(),
            "NS-036: 1 KiB output must be accepted"
        );
    }

    #[test]
    fn provider_stdout_size_limit_accepts_exactly_1_mib() {
        let exactly_1_mib = 1024 * 1024;
        assert!(
            super::check_stdout_size_limit(exactly_1_mib).is_ok(),
            "NS-036: exactly 1 MiB output must be accepted"
        );
    }

    #[test]
    fn provider_stdout_size_limit_rejects_over_1_mib() {
        let over_1_mib = (1024 * 1024) + 1;
        assert!(
            super::check_stdout_size_limit(over_1_mib).is_err(),
            "NS-036: output exceeding 1 MiB must be rejected"
        );
    }

    #[test]
    fn provider_stdout_size_limit_constant_is_1_mib() {
        assert_eq!(
            super::MAX_STDOUT_BYTES,
            1024 * 1024,
            "NS-036: stdout size limit must be exactly 1 MiB"
        );
    }

    // =========================================================================
    // NS-037: TTL format is integer seconds for providers — human durations
    // are CLI concern only.
    // =========================================================================

    #[test]
    fn ttl_format_is_integer_seconds_for_providers() {
        // When building provider command args, TTL must be integer seconds.
        let template = vec!["/cmd".to_string(), "{ttl}".to_string()];
        let result = super::substitute_template_vars(&template, "role", 3600);
        assert_eq!(
            result[1], "3600",
            "NS-037: TTL must be formatted as integer seconds string"
        );
    }

    #[test]
    fn ttl_format_no_human_duration_suffix() {
        let template = vec!["/cmd".to_string(), "{ttl}".to_string()];
        let result = super::substitute_template_vars(&template, "role", 7200);
        // Must be "7200", not "2h" or "120m" or anything else
        assert!(
            result[1].parse::<u64>().is_ok(),
            "NS-037: TTL must be a pure integer string, got: {}",
            result[1]
        );
        assert_eq!(result[1], "7200");
    }

    // =========================================================================
    // NS-038: Revoke command receives token via env var — NOSCOPE_TOKEN,
    // NOSCOPE_TOKEN_ID; exit 0 for already-revoked.
    // =========================================================================

    #[test]
    fn revoke_command_env_vars_include_noscope_token() {
        let env = super::build_revoke_env("secret-token-value", "tok-id-123");
        assert_eq!(
            env.get("NOSCOPE_TOKEN").map(|s| s.as_str()),
            Some("secret-token-value"),
            "NS-038: revoke env must include NOSCOPE_TOKEN"
        );
    }

    #[test]
    fn revoke_command_env_vars_include_noscope_token_id() {
        let env = super::build_revoke_env("secret-token", "tok-abc");
        assert_eq!(
            env.get("NOSCOPE_TOKEN_ID").map(|s| s.as_str()),
            Some("tok-abc"),
            "NS-038: revoke env must include NOSCOPE_TOKEN_ID"
        );
    }

    #[test]
    fn revoke_command_env_has_exactly_two_credential_vars() {
        let env = super::build_revoke_env("tok", "id");
        // Should have NOSCOPE_TOKEN and NOSCOPE_TOKEN_ID (credential vars only)
        assert!(env.contains_key("NOSCOPE_TOKEN"));
        assert!(env.contains_key("NOSCOPE_TOKEN_ID"));
        // Should NOT contain NOSCOPE_TTL (that's for refresh)
        assert!(
            !env.contains_key("NOSCOPE_TTL"),
            "NS-038: revoke must NOT include NOSCOPE_TTL"
        );
    }

    #[test]
    fn revoke_command_exit_0_for_already_revoked() {
        // exit 0 means success (including already-revoked); the caller
        // should treat exit 0 from revoke as success regardless.
        // This tests the interpret function recognizes this pattern.
        assert!(
            super::is_revoke_success(0),
            "NS-038: exit 0 from revoke must be treated as success (including already-revoked)"
        );
    }

    #[test]
    fn revoke_command_non_zero_exit_is_failure() {
        assert!(
            !super::is_revoke_success(1),
            "NS-038: exit 1 from revoke is failure"
        );
    }

    // =========================================================================
    // NS-039: Refresh command receives token via env var — NOSCOPE_TOKEN,
    // NOSCOPE_TOKEN_ID, NOSCOPE_TTL; same JSON output as mint.
    // =========================================================================

    #[test]
    fn refresh_command_env_vars_include_noscope_token() {
        let env = super::build_refresh_env("secret-token", "tok-id", 3600);
        assert_eq!(
            env.get("NOSCOPE_TOKEN").map(|s| s.as_str()),
            Some("secret-token"),
            "NS-039: refresh env must include NOSCOPE_TOKEN"
        );
    }

    #[test]
    fn refresh_command_env_vars_include_noscope_token_id() {
        let env = super::build_refresh_env("tok", "tok-id-123", 3600);
        assert_eq!(
            env.get("NOSCOPE_TOKEN_ID").map(|s| s.as_str()),
            Some("tok-id-123"),
            "NS-039: refresh env must include NOSCOPE_TOKEN_ID"
        );
    }

    #[test]
    fn refresh_command_env_vars_include_noscope_ttl() {
        let env = super::build_refresh_env("tok", "id", 7200);
        assert_eq!(
            env.get("NOSCOPE_TTL").map(|s| s.as_str()),
            Some("7200"),
            "NS-039: refresh env must include NOSCOPE_TTL as integer seconds"
        );
    }

    #[test]
    fn refresh_command_env_has_exactly_three_credential_vars() {
        let env = super::build_refresh_env("tok", "id", 3600);
        assert!(env.contains_key("NOSCOPE_TOKEN"));
        assert!(env.contains_key("NOSCOPE_TOKEN_ID"));
        assert!(env.contains_key("NOSCOPE_TTL"));
    }

    #[test]
    fn refresh_command_output_same_contract_as_mint() {
        // NS-039: refresh output uses same JSON format as mint
        let json = r#"{"token": "refreshed-token", "expires_at": "2026-12-31T23:59:59Z"}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_ok(),
            "NS-039: refresh output must parse with same contract as mint"
        );
        let output = result.unwrap();
        assert_eq!(output.token, "refreshed-token");
    }

    // =========================================================================
    // NS-040: Provider stderr handling — capture 4096 bytes on failure,
    // discard on success unless --verbose, redact tokens.
    // =========================================================================

    #[test]
    fn provider_stderr_handling_capture_limit_is_4096_bytes() {
        assert_eq!(
            super::MAX_STDERR_CAPTURE_BYTES,
            4096,
            "NS-040: stderr capture limit must be 4096 bytes"
        );
    }

    #[test]
    fn provider_stderr_handling_truncates_to_limit() {
        let long_stderr = "x".repeat(8192);
        let captured = super::capture_stderr(&long_stderr);
        assert!(
            captured.len() <= 4096,
            "NS-040: captured stderr must be <= 4096 bytes, got: {}",
            captured.len()
        );
    }

    #[test]
    fn provider_stderr_handling_preserves_short_stderr() {
        let short = "error: auth failed";
        let captured = super::capture_stderr(short);
        assert_eq!(
            captured, short,
            "NS-040: short stderr should be preserved verbatim"
        );
    }

    #[test]
    fn provider_stderr_handling_redacts_known_token() {
        let stderr_with_token = "error: token abc123secret456789xyz is invalid";
        let captured = super::redact_stderr(stderr_with_token, &["abc123secret456789xyz"]);
        assert!(
            !captured.contains("abc123secret456789xyz"),
            "NS-040: known token values must be redacted from stderr, got: {}",
            captured
        );
        assert!(
            captured.contains("[redacted]"),
            "NS-040: redacted token must be replaced with [redacted], got: {}",
            captured
        );
    }

    #[test]
    fn provider_stderr_handling_redacts_multiple_tokens() {
        let stderr = "token1=secret_aaa token2=secret_bbb";
        let captured = super::redact_stderr(stderr, &["secret_aaa", "secret_bbb"]);
        assert!(!captured.contains("secret_aaa"));
        assert!(!captured.contains("secret_bbb"));
    }

    #[test]
    fn provider_stderr_handling_no_tokens_no_change() {
        let stderr = "provider error: connection refused";
        let captured = super::redact_stderr(stderr, &[]);
        assert_eq!(
            captured, stderr,
            "NS-040: with no known tokens, stderr should be unchanged"
        );
    }

    #[test]
    fn provider_stderr_handling_discard_on_success_default() {
        let policy = super::StderrPolicy::on_success(false);
        assert!(
            policy.should_discard(),
            "NS-040: on success without --verbose, stderr should be discarded"
        );
    }

    #[test]
    fn provider_stderr_handling_keep_on_success_verbose() {
        let policy = super::StderrPolicy::on_success(true);
        assert!(
            !policy.should_discard(),
            "NS-040: on success with --verbose, stderr should be kept"
        );
    }

    #[test]
    fn provider_stderr_handling_keep_on_failure() {
        let policy = super::StderrPolicy::on_failure();
        assert!(
            !policy.should_discard(),
            "NS-040: on failure, stderr must always be captured"
        );
    }

    // =========================================================================
    // NS-041: Provider capability declaration — supports_refresh,
    // supports_revoke booleans in config.
    // =========================================================================

    #[test]
    fn provider_capability_declaration_default_no_refresh_no_revoke() {
        let caps = super::ProviderCapabilities::default();
        assert!(
            !caps.supports_refresh,
            "NS-041: default should NOT support refresh"
        );
        assert!(
            !caps.supports_revoke,
            "NS-041: default should NOT support revoke"
        );
    }

    #[test]
    fn provider_capability_declaration_from_config_both_true() {
        let caps = super::ProviderCapabilities {
            supports_refresh: true,
            supports_revoke: true,
        };
        assert!(caps.supports_refresh);
        assert!(caps.supports_revoke);
    }

    #[test]
    fn provider_capability_declaration_from_config_refresh_only() {
        let caps = super::ProviderCapabilities {
            supports_refresh: true,
            supports_revoke: false,
        };
        assert!(caps.supports_refresh);
        assert!(!caps.supports_revoke);
    }

    #[test]
    fn provider_capability_declaration_parsed_from_toml() {
        let toml = r#"
contract_version = 1
supports_refresh = true
supports_revoke = false

[commands]
mint = "/usr/bin/mint"
refresh = "/usr/bin/refresh"
"#;
        let caps = super::parse_capabilities_from_toml(toml);
        assert!(
            caps.is_ok(),
            "NS-041: valid capability TOML must parse, got: {:?}",
            caps
        );
        let caps = caps.unwrap();
        assert!(
            caps.supports_refresh,
            "NS-041: supports_refresh should be true"
        );
        assert!(
            !caps.supports_revoke,
            "NS-041: supports_revoke should be false"
        );
    }

    #[test]
    fn provider_capability_declaration_defaults_when_absent_in_toml() {
        let toml = r#"
contract_version = 1

[commands]
mint = "/usr/bin/mint"
"#;
        let caps = super::parse_capabilities_from_toml(toml).unwrap();
        assert!(
            !caps.supports_refresh,
            "NS-041: absent supports_refresh defaults to false"
        );
        assert!(
            !caps.supports_revoke,
            "NS-041: absent supports_revoke defaults to false"
        );
    }

    #[test]
    fn provider_capability_declaration_revoke_without_revoke_cmd_is_inconsistent() {
        // If supports_revoke = true but no revoke command, that's a validation issue.
        let caps = super::ProviderCapabilities {
            supports_refresh: false,
            supports_revoke: true,
        };
        let has_revoke_cmd = false;
        assert!(
            super::validate_capabilities(&caps, false, has_revoke_cmd).is_err(),
            "NS-041: supports_revoke=true without revoke command should be rejected"
        );
    }

    #[test]
    fn provider_capability_declaration_refresh_without_refresh_cmd_is_inconsistent() {
        let caps = super::ProviderCapabilities {
            supports_refresh: true,
            supports_revoke: false,
        };
        let has_refresh_cmd = false;
        assert!(
            super::validate_capabilities(&caps, has_refresh_cmd, false).is_err(),
            "NS-041: supports_refresh=true without refresh command should be rejected"
        );
    }

    #[test]
    fn provider_capability_declaration_consistent_config_passes() {
        let caps = super::ProviderCapabilities {
            supports_refresh: true,
            supports_revoke: true,
        };
        assert!(
            super::validate_capabilities(&caps, true, true).is_ok(),
            "NS-041: consistent capability config should pass"
        );
    }

    // =========================================================================
    // NS-068: Provider command environment sandboxing — minimal env: PATH,
    // HOME, LANG only.
    // =========================================================================

    #[test]
    fn provider_command_environment_sandboxing_only_path_home_lang() {
        let env = super::build_sandboxed_env();
        // Must contain exactly PATH, HOME, LANG
        assert!(
            env.contains_key("PATH"),
            "NS-068: sandboxed env must include PATH"
        );
        assert!(
            env.contains_key("HOME"),
            "NS-068: sandboxed env must include HOME"
        );
        assert!(
            env.contains_key("LANG"),
            "NS-068: sandboxed env must include LANG"
        );
    }

    #[test]
    fn provider_command_environment_sandboxing_excludes_other_vars() {
        let env = super::build_sandboxed_env();
        // Should NOT contain common env vars like USER, TERM, SHELL, etc.
        let forbidden = [
            "USER",
            "TERM",
            "SHELL",
            "EDITOR",
            "DISPLAY",
            "SSH_AUTH_SOCK",
        ];
        for var in &forbidden {
            assert!(
                !env.contains_key(*var),
                "NS-068: sandboxed env must NOT include {}, but it does",
                var
            );
        }
    }

    #[test]
    fn provider_command_environment_sandboxing_has_exactly_three_base_keys() {
        let env = super::build_sandboxed_env();
        assert_eq!(
            env.len(),
            3,
            "NS-068: sandboxed env must have exactly 3 keys (PATH, HOME, LANG), got: {:?}",
            env.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn provider_command_environment_sandboxing_with_credential_vars_for_revoke() {
        // When revoking, the sandboxed env gets NOSCOPE_TOKEN and NOSCOPE_TOKEN_ID added.
        let mut env = super::build_sandboxed_env();
        let cred_vars = super::build_revoke_env("secret", "id");
        for (k, v) in &cred_vars {
            env.insert(k.clone(), v.clone());
        }
        // Should now have PATH, HOME, LANG + NOSCOPE_TOKEN + NOSCOPE_TOKEN_ID = 5
        assert_eq!(env.len(), 5);
        assert_eq!(env.get("NOSCOPE_TOKEN").map(|s| s.as_str()), Some("secret"));
    }

    #[test]
    fn provider_command_environment_sandboxing_with_credential_vars_for_refresh() {
        let mut env = super::build_sandboxed_env();
        let cred_vars = super::build_refresh_env("secret", "id", 3600);
        for (k, v) in &cred_vars {
            env.insert(k.clone(), v.clone());
        }
        // PATH, HOME, LANG + NOSCOPE_TOKEN + NOSCOPE_TOKEN_ID + NOSCOPE_TTL = 6
        assert_eq!(env.len(), 6);
    }

    #[test]
    fn provider_command_environment_sandboxing_path_is_not_empty() {
        let env = super::build_sandboxed_env();
        let path = env.get("PATH").unwrap();
        assert!(
            !path.is_empty(),
            "NS-068: PATH in sandboxed env must not be empty"
        );
    }

    #[test]
    fn provider_command_environment_sandboxing_home_is_not_empty() {
        let env = super::build_sandboxed_env();
        let home = env.get("HOME").unwrap();
        assert!(
            !home.is_empty(),
            "NS-068: HOME in sandboxed env must not be empty"
        );
    }

    // =========================================================================
    // Integration / cross-rule tests
    // =========================================================================

    #[test]
    fn exec_config_is_constructible() {
        let config = super::ExecConfig {
            timeout: Duration::from_secs(60),
            kill_grace_period: Duration::from_secs(10),
        };
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.kill_grace_period, Duration::from_secs(10));
    }

    #[test]
    fn provider_exec_error_implements_display() {
        let err = super::ProviderExecError::OutputContract {
            message: "missing token".to_string(),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("missing token"),
            "Display should include message"
        );
    }

    #[test]
    fn provider_exec_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<super::ProviderExecError>();
    }

    #[test]
    fn provider_output_has_chrono_datetime() {
        // Verify ProviderOutput.expires_at is a chrono DateTime<Utc>
        let json = r#"{"token": "tok", "expires_at": "2026-06-15T10:30:00Z"}"#;
        let output = super::parse_provider_output(json, 3600).unwrap();
        assert_eq!(output.expires_at.year(), 2026);
        assert_eq!(output.expires_at.month(), 6);
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn provider_output_contract_expires_at_null_treated_as_absent() {
        // JSON null for expires_at should be treated the same as absent.
        let json = r#"{"token": "tok", "expires_at": null}"#;
        let result = super::parse_provider_output(json, 3600).unwrap();
        assert!(
            !result.expires_at_provided,
            "NS-034: null expires_at should be treated as absent"
        );
    }

    #[test]
    fn provider_output_contract_expires_at_in_past_accepted() {
        // Provider might have clock skew — accept past timestamps without error.
        let json = r#"{"token": "tok", "expires_at": "2020-01-01T00:00:00Z"}"#;
        let result = super::parse_provider_output(json, 3600);
        assert!(
            result.is_ok(),
            "NS-009: past expires_at should be accepted (provider clock skew)"
        );
        let output = result.unwrap();
        assert!(output.expires_at_provided);
        assert_eq!(output.expires_at.year(), 2020);
    }

    #[test]
    fn template_variable_injection_prevention_role_rejects_non_ascii() {
        // NS-033: only ASCII alphanumeric + hyphens + underscores + dots
        assert!(
            super::validate_role("rôle").is_err(),
            "NS-033: non-ASCII characters must be rejected"
        );
        assert!(
            super::validate_role("ロール").is_err(),
            "NS-033: CJK characters must be rejected"
        );
    }

    #[test]
    fn provider_output_token_is_zeroized_on_drop() {
        // NS-019: Verify the token string is zeroized when ProviderOutput is dropped.
        // We can't directly observe the zeroization, but we can verify the trait
        // impl exists by checking the type compiles with our Drop impl.
        let json = r#"{"token": "sensitive-credential-value-12345", "expires_at": "2026-06-15T10:30:00Z"}"#;
        let output = super::parse_provider_output(json, 3600).unwrap();
        assert_eq!(output.token, "sensitive-credential-value-12345");
        // Drop happens here — token.zeroize() is called.
    }

    #[test]
    fn provider_exec_error_config_parse_variant_exists() {
        // Verify the ConfigParse error variant exists and displays properly.
        let err = super::ProviderExecError::ConfigParse {
            message: "bad toml syntax".to_string(),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("bad toml syntax"),
            "ConfigParse should display message"
        );
        assert!(
            msg.contains("config"),
            "ConfigParse display should mention config, got: {}",
            msg
        );
    }

    #[test]
    fn provider_stderr_handling_truncation_respects_utf8_boundary() {
        // Create a string where byte 4096 falls in the middle of a multi-byte char.
        let mut s = "a".repeat(4094); // 4094 ASCII bytes
        s.push('\u{00E9}'); // 2-byte UTF-8 char at position 4094-4095
        s.push('x'); // byte 4096
        assert!(s.len() > 4096);
        let captured = super::capture_stderr(&s);
        // Should not panic and should be valid UTF-8
        assert!(captured.len() <= 4096);
        // Verify it's valid UTF-8 (this is implicit since &str is always valid)
        let _ = captured.to_string();
    }

    #[test]
    fn provider_stdout_size_limit_zero_is_accepted() {
        assert!(
            super::check_stdout_size_limit(0).is_ok(),
            "Zero-length stdout should be accepted"
        );
    }

    #[test]
    fn template_variable_injection_prevention_no_unknown_vars_expanded() {
        // Unknown template variables like {unknown} should remain as-is.
        let template = vec!["/cmd".to_string(), "{unknown}".to_string()];
        let result = super::substitute_template_vars(&template, "role", 100);
        assert_eq!(
            result[1], "{unknown}",
            "Unknown template variables must not be expanded"
        );
    }

    #[test]
    fn provider_exec_error_timeout_display() {
        let err = super::ProviderExecError::Timeout {
            timeout: Duration::from_secs(30),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("30"),
            "Timeout display should include duration"
        );
    }

    #[test]
    fn provider_exec_error_stdout_too_large_display() {
        let err = super::ProviderExecError::StdoutTooLarge {
            size: 2_000_000,
            limit: 1_048_576,
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("2000000"),
            "StdoutTooLarge display should include actual size"
        );
    }

    #[test]
    fn provider_exec_error_invalid_role_display() {
        let err = super::ProviderExecError::InvalidRole {
            role: "bad;role".to_string(),
            reason: "contains semicolon".to_string(),
        };
        let msg = format!("{}", err);
        assert!(
            msg.contains("bad;role"),
            "InvalidRole display should include the role"
        );
    }
}
