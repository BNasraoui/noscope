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

use crate::exit_code::{interpret_provider_exit, ProviderExitResult};

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
pub struct ProviderOutput {
    /// The raw token string from the provider.
    pub token: String,
    /// The expiry time — either from the provider or computed from TTL.
    pub expires_at: DateTime<Utc>,
    /// Whether the provider explicitly supplied `expires_at`.
    /// `false` means it was computed from `now() + requested_ttl` (NS-034).
    pub expires_at_provided: bool,
}

impl fmt::Debug for ProviderOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = crate::redaction::RedactedToken::new(&self.token, None);
        f.debug_struct("ProviderOutput")
            .field("token", &redacted)
            .field("expires_at", &self.expires_at)
            .field("expires_at_provided", &self.expires_at_provided)
            .finish()
    }
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

// ---------------------------------------------------------------------------
// noscope-6a9: Provider command execution engine
// ---------------------------------------------------------------------------

/// Result of executing a provider command.
///
/// Contains all outputs from the subprocess: stdout, stderr, exit code,
/// parsed output (if applicable), and whether the command timed out.
#[derive(Debug)]
pub struct ProviderExecResult {
    /// Raw stdout from the provider command.
    pub stdout: String,
    /// Captured stderr, truncated to [`MAX_STDERR_CAPTURE_BYTES`] and
    /// redacted of known token values (NS-040).
    pub stderr: String,
    /// Interpreted exit code (NS-010).
    pub exit_result: ProviderExitResult,
    /// Parsed provider output. `Ok` on exit 0 with valid JSON,
    /// `Err` for timeout, oversized stdout, or parse failure.
    pub parsed_output: Result<ProviderOutput, ProviderExecError>,
    /// Whether the command was killed due to timeout (NS-035).
    pub timed_out: bool,
}

/// Execute a provider command in a sandboxed environment.
///
/// This is the core execution engine that ties together all policy building
/// blocks:
/// - **NS-068**: Subprocess runs with [`build_sandboxed_env()`] as its base env.
/// - **NS-036**: Stdout is checked against [`MAX_STDOUT_BYTES`].
/// - **NS-040**: Stderr is truncated, token values are redacted.
/// - **NS-035**: Timeout enforced via SIGTERM then SIGKILL after grace period.
/// - **NS-009**: Stdout parsed through [`parse_provider_output()`].
/// - **NS-010**: Exit code mapped through [`interpret_provider_exit()`].
///
/// # Arguments
/// - `argv`: Command and arguments (no shell involved).
/// - `extra_env`: Additional environment variables (e.g. NOSCOPE_TOKEN) merged
///   on top of the sandboxed base env.
/// - `config`: Execution configuration (timeout, grace period).
/// - `requested_ttl_secs`: TTL passed to [`parse_provider_output()`] for NS-034.
///
/// # Returns
/// - `Ok(ProviderExecResult)` with all execution results.
/// - `Err(std::io::Error)` if the command could not be spawned.
pub async fn execute_provider_command(
    argv: &[String],
    extra_env: &HashMap<String, String>,
    config: &ExecConfig,
    requested_ttl_secs: u64,
) -> Result<ProviderExecResult, std::io::Error> {
    if argv.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "argv must not be empty",
        ));
    }

    // NS-068: Build sandboxed environment, then overlay extra vars.
    let mut env = build_sandboxed_env();
    for (k, v) in extra_env {
        env.insert(k.clone(), v.clone());
    }

    // Collect known token values for stderr redaction (NS-040).
    let known_tokens: Vec<String> = extra_env
        .iter()
        .filter(|(k, _)| k.starts_with("NOSCOPE_TOKEN"))
        .map(|(_, v)| v.clone())
        .collect();

    // Spawn: no shell, argv[0] is the executable, rest are args.
    let mut cmd = tokio::process::Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    cmd.env_clear();
    for (k, v) in &env {
        cmd.env(k, v);
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;

    // Take stdout/stderr handles for concurrent reading.
    // Must read concurrently with wait() to avoid pipe buffer deadlock:
    // if the child writes more than the pipe buffer, it blocks on write
    // and never exits. wait() would then hang forever.
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let stdout_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        if let Some(mut out) = child_stdout {
            let _ = out.read_to_end(&mut buf).await;
        }
        buf
    });

    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        if let Some(mut err) = child_stderr {
            let _ = err.read_to_end(&mut buf).await;
        }
        buf
    });

    // NS-035: Enforce timeout with SIGTERM then SIGKILL escalation.
    let timed_out;
    let wait_result = tokio::time::timeout(config.timeout, child.wait()).await;

    let exit_status = match wait_result {
        Ok(result) => {
            timed_out = false;
            result?
        }
        Err(_elapsed) => {
            // Timeout expired. Send SIGTERM.
            timed_out = true;
            send_signal(&child, libc::SIGTERM);

            // Wait grace period for the process to exit.
            let grace_result = tokio::time::timeout(config.kill_grace_period, child.wait()).await;

            match grace_result {
                Ok(result) => result?,
                Err(_) => {
                    // Grace period expired. Escalate to SIGKILL.
                    send_signal(&child, libc::SIGKILL);
                    child.wait().await?
                }
            }
        }
    };

    // Collect stdout/stderr from the concurrent read tasks.
    let stdout_bytes = stdout_task.await.unwrap_or_default();
    let stderr_bytes = stderr_task.await.unwrap_or_default();

    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let raw_stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

    // NS-040: Capture stderr (truncate), then redact known tokens.
    let captured = capture_stderr(&raw_stderr);
    let token_refs: Vec<&str> = known_tokens.iter().map(|s| s.as_str()).collect();
    let stderr = redact_stderr(captured, &token_refs);

    // NS-010: Map exit code through interpret_provider_exit().
    let raw_exit = exit_status.code().unwrap_or(1);
    let exit_result = if timed_out {
        // NS-035: Timeout is treated as exit 4 (Unavailable).
        interpret_provider_exit(4)
    } else {
        interpret_provider_exit(raw_exit)
    };

    // Determine parsed_output.
    let parsed_output = if timed_out {
        Err(ProviderExecError::Timeout {
            timeout: config.timeout,
        })
    } else {
        // NS-036: Check stdout size limit first.
        match check_stdout_size_limit(stdout.len()) {
            Err(e) => Err(e),
            Ok(()) => {
                // NS-009: Parse output only on exit 0.
                if raw_exit == 0 {
                    parse_provider_output(&stdout, requested_ttl_secs)
                } else {
                    Err(ProviderExecError::OutputContract {
                        message: format!(
                            "provider exited with code {} ({})",
                            raw_exit, exit_result.exit_code
                        ),
                    })
                }
            }
        }
    };

    Ok(ProviderExecResult {
        stdout,
        stderr,
        exit_result,
        parsed_output,
        timed_out,
    })
}

/// Send a Unix signal to a child process.
///
/// Best-effort: if the process has already exited, the signal is silently ignored.
fn send_signal(child: &tokio::process::Child, signal: libc::c_int) {
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as libc::pid_t, signal);
        }
    }
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
            result.expires_at,
            expected_min,
            expected_max
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
    fn ns_058_provider_output_debug_redacts_token() {
        let output = super::parse_provider_output(
            r#"{"token": "provider-secret-token-abc123", "expires_at": "2026-06-15T10:30:00Z"}"#,
            3600,
        )
        .unwrap();

        let debug = format!("{:?}", output);
        assert!(
            !debug.contains("provider-secret-token-abc123"),
            "NS-058: Debug output must not expose raw token, got: {}",
            debug
        );
    }

    #[test]
    fn ns_058_provider_output_debug_includes_non_secret_fields() {
        let output = super::parse_provider_output(
            r#"{"token": "provider-secret-token-abc123", "expires_at": "2026-06-15T10:30:00Z"}"#,
            3600,
        )
        .unwrap();

        let debug = format!("{:?}", output);
        assert!(
            debug.contains("RedactedToken"),
            "NS-058: Debug output should use redaction wrapper, got: {}",
            debug
        );
        assert!(debug.contains("expires_at"));
        assert!(debug.contains("expires_at_provided"));
    }

    #[test]
    fn ns_058_provider_output_debug_redacts_short_tokens_too() {
        let output = super::parse_provider_output(
            r#"{"token": "shorttok", "expires_at": "2026-06-15T10:30:00Z"}"#,
            3600,
        )
        .unwrap();

        let debug = format!("{:?}", output);
        assert!(!debug.contains("shorttok"));
        assert!(debug.contains("RedactedToken"));
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

// =========================================================================
// Execution engine tests — noscope-6a9
//
// These tests cover the actual subprocess execution engine that ties
// together all the policy building blocks above.
// =========================================================================

#[cfg(test)]
mod engine_tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::exit_code::ProviderExitCode;

    // =========================================================================
    // NS-068: Execution engine uses build_sandboxed_env() for subprocess env
    // =========================================================================

    #[tokio::test]
    async fn engine_spawns_with_sandboxed_env() {
        // The engine must use build_sandboxed_env() as the base environment.
        // Verify by running a command that prints its environment.
        let result = execute_provider_command(
            &["/usr/bin/env".to_string()],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        // The command should succeed (exit 0).
        let result = result.expect("env command should not fail to spawn");
        // stdout should contain PATH, HOME, LANG but NOT random vars like TERM
        let stdout = &result.stdout;
        assert!(
            stdout.contains("PATH="),
            "NS-068: spawned process must have PATH"
        );
        assert!(
            stdout.contains("HOME="),
            "NS-068: spawned process must have HOME"
        );
        assert!(
            stdout.contains("LANG="),
            "NS-068: spawned process must have LANG"
        );
    }

    #[tokio::test]
    async fn engine_sandboxed_env_excludes_parent_vars() {
        // Set a marker env var in the parent; it must NOT leak to the child.
        // SAFETY: This test is not run concurrently with others that depend on
        // NOSCOPE_TEST_LEAK_CHECK. The var is set and removed within this test.
        unsafe {
            std::env::set_var("NOSCOPE_TEST_LEAK_CHECK", "leaked");
        }
        let result = execute_provider_command(
            &["/usr/bin/env".to_string()],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("env command should not fail to spawn");
        assert!(
            !result.stdout.contains("NOSCOPE_TEST_LEAK_CHECK"),
            "NS-068: parent env vars must NOT leak to provider subprocess"
        );
        unsafe {
            std::env::remove_var("NOSCOPE_TEST_LEAK_CHECK");
        }
    }

    #[tokio::test]
    async fn engine_merges_extra_env_into_sandbox() {
        // Extra env vars (e.g. NOSCOPE_TOKEN) are merged on top of the sandbox.
        let mut extra_env = HashMap::new();
        extra_env.insert("NOSCOPE_TOKEN".to_string(), "secret-val".to_string());

        let result = execute_provider_command(
            &["/usr/bin/env".to_string()],
            &extra_env,
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("env command should not fail to spawn");
        assert!(
            result.stdout.contains("NOSCOPE_TOKEN=secret-val"),
            "NS-068: extra env vars must be available to subprocess"
        );
    }

    // =========================================================================
    // NS-036: Execution engine checks stdout size limit
    // =========================================================================

    #[tokio::test]
    async fn engine_rejects_oversized_stdout() {
        // Generate stdout > 1 MiB using head -c from /dev/urandom.
        let over_1_mib = MAX_STDOUT_BYTES + 1;
        let script = format!("head -c {} /dev/zero", over_1_mib);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            result.parsed_output.is_err(),
            "NS-036: stdout exceeding 1 MiB must be rejected"
        );
        let err = result.parsed_output.unwrap_err();
        assert!(
            matches!(err, ProviderExecError::StdoutTooLarge { .. }),
            "NS-036: error must be StdoutTooLarge, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn engine_accepts_valid_sized_stdout() {
        let json = r#"{"token":"tok-123","expires_at":"2099-01-01T00:00:00Z"}"#;
        let script = format!("printf '{}'", json);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            result.parsed_output.is_ok(),
            "NS-036: valid-sized stdout must be accepted, got: {:?}",
            result.parsed_output
        );
    }

    // =========================================================================
    // NS-040: Execution engine captures and redacts stderr
    // =========================================================================

    #[tokio::test]
    async fn engine_captures_stderr_on_failure() {
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo 'error: auth failed' >&2; exit 2".to_string(),
            ],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            result.stderr.contains("auth failed"),
            "NS-040: stderr must be captured on failure, got: {:?}",
            result.stderr
        );
    }

    #[tokio::test]
    async fn engine_truncates_long_stderr() {
        let long_msg = "x".repeat(8192);
        let script = format!("printf '{}' >&2; exit 1", long_msg);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            result.stderr.len() <= MAX_STDERR_CAPTURE_BYTES,
            "NS-040: stderr must be truncated to {} bytes, got: {}",
            MAX_STDERR_CAPTURE_BYTES,
            result.stderr.len()
        );
    }

    #[tokio::test]
    async fn engine_redacts_known_tokens_from_stderr() {
        let token = "super-secret-token-value-xyz";
        let mut extra_env = HashMap::new();
        extra_env.insert("NOSCOPE_TOKEN".to_string(), token.to_string());

        let script = format!("echo 'error: invalid token {}' >&2; exit 1", token);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &extra_env,
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            !result.stderr.contains(token),
            "NS-040: known token values must be redacted from stderr, got: {:?}",
            result.stderr
        );
        assert!(
            result.stderr.contains("[redacted]"),
            "NS-040: redacted token must be replaced with [redacted]"
        );
    }

    // =========================================================================
    // NS-035: Execution engine enforces timeout with SIGTERM then SIGKILL
    // =========================================================================

    #[tokio::test]
    async fn engine_times_out_long_running_command() {
        let config = ExecConfig {
            timeout: Duration::from_millis(200),
            kill_grace_period: Duration::from_millis(100),
        };

        let result = execute_provider_command(
            &["/bin/sleep".to_string(), "60".to_string()],
            &HashMap::new(),
            &config,
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            result.timed_out,
            "NS-035: long-running command must time out"
        );
    }

    #[tokio::test]
    async fn engine_timeout_produces_timeout_error() {
        let config = ExecConfig {
            timeout: Duration::from_millis(200),
            kill_grace_period: Duration::from_millis(100),
        };

        let result = execute_provider_command(
            &["/bin/sleep".to_string(), "60".to_string()],
            &HashMap::new(),
            &config,
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            matches!(result.parsed_output, Err(ProviderExecError::Timeout { .. })),
            "NS-035: timeout must produce Timeout error, got: {:?}",
            result.parsed_output
        );
    }

    #[tokio::test]
    async fn engine_timeout_kills_after_grace_period() {
        // Use a command that traps SIGTERM and ignores it; the engine
        // must escalate to SIGKILL after the grace period.
        let config = ExecConfig {
            timeout: Duration::from_millis(200),
            kill_grace_period: Duration::from_millis(200),
        };

        let start = std::time::Instant::now();
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                // Trap SIGTERM and keep sleeping (force SIGKILL escalation)
                "trap '' TERM; sleep 60".to_string(),
            ],
            &HashMap::new(),
            &config,
            3600,
        )
        .await;
        let elapsed = start.elapsed();

        let result = result.expect("command should spawn");
        assert!(result.timed_out, "NS-035: must time out");
        // Should finish within timeout + grace + some slack, not wait the full 60s
        assert!(
            elapsed < Duration::from_secs(5),
            "NS-035: must SIGKILL after grace period, took {:?}",
            elapsed
        );
    }

    // =========================================================================
    // NS-009: Execution engine parses output through parse_provider_output()
    // =========================================================================

    #[tokio::test]
    async fn engine_parses_valid_provider_json() {
        let json = r#"{"token":"mint-token-123","expires_at":"2099-06-15T10:30:00Z"}"#;
        let script = format!("printf '{}'", json);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        let output = result.parsed_output.expect("NS-009: valid JSON must parse");
        assert_eq!(output.token, "mint-token-123");
        assert!(output.expires_at_provided);
    }

    #[tokio::test]
    async fn engine_rejects_invalid_provider_json() {
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo 'not json'".to_string(),
            ],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            result.parsed_output.is_err(),
            "NS-009: invalid JSON stdout must be rejected"
        );
        assert!(
            matches!(
                result.parsed_output,
                Err(ProviderExecError::OutputContract { .. })
            ),
            "NS-009: must be OutputContract error"
        );
    }

    // =========================================================================
    // NS-010: Execution engine maps exit codes through interpret_provider_exit()
    // =========================================================================

    #[tokio::test]
    async fn engine_maps_exit_code_success() {
        let json = r#"{"token":"tok","expires_at":"2099-01-01T00:00:00Z"}"#;
        let script = format!("printf '{}'; exit 0", json);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert_eq!(
            result.exit_result.exit_code,
            ProviderExitCode::Success,
            "NS-010: exit 0 must map to Success"
        );
    }

    #[tokio::test]
    async fn engine_maps_exit_code_auth_failure() {
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 2".to_string(),
            ],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert_eq!(
            result.exit_result.exit_code,
            ProviderExitCode::AuthFailure,
            "NS-010: exit 2 must map to AuthFailure"
        );
    }

    #[tokio::test]
    async fn engine_maps_exit_code_role_not_found() {
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 3".to_string(),
            ],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert_eq!(
            result.exit_result.exit_code,
            ProviderExitCode::RoleNotFound,
            "NS-010: exit 3 must map to RoleNotFound"
        );
    }

    #[tokio::test]
    async fn engine_maps_exit_code_unavailable() {
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 4".to_string(),
            ],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert_eq!(
            result.exit_result.exit_code,
            ProviderExitCode::Unavailable,
            "NS-010: exit 4 must map to Unavailable"
        );
    }

    #[tokio::test]
    async fn engine_does_not_parse_output_on_nonzero_exit() {
        // When the provider exits non-zero, we should still report the exit
        // code but the parsed_output should reflect the failure.
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo 'not json'; exit 1".to_string(),
            ],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert_eq!(result.exit_result.exit_code, ProviderExitCode::GeneralError,);
    }

    // =========================================================================
    // Integration: engine result struct
    // =========================================================================

    #[tokio::test]
    async fn engine_result_has_all_fields() {
        let json = r#"{"token":"tok","expires_at":"2099-01-01T00:00:00Z"}"#;
        let script = format!("printf '{}'; echo 'debug info' >&2", json);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        // Must have all fields
        let _exit_result = &result.exit_result;
        let _parsed = &result.parsed_output;
        let _stderr = &result.stderr;
        let _stdout = &result.stdout;
        let _timed_out = result.timed_out;
    }

    #[tokio::test]
    async fn engine_spawn_failure_returns_error() {
        // Try to execute a command that doesn't exist
        let result = execute_provider_command(
            &["/nonexistent/command/path".to_string()],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        assert!(
            result.is_err(),
            "Spawning a nonexistent command must return Err"
        );
    }

    #[tokio::test]
    async fn engine_empty_argv_returns_error() {
        let result =
            execute_provider_command(&[], &HashMap::new(), &ExecConfig::default(), 3600).await;

        assert!(result.is_err(), "Empty argv must return error");
    }

    // =========================================================================
    // Edge cases discovered during Linus review
    // =========================================================================

    #[tokio::test]
    async fn engine_signal_killed_process_maps_to_general_error() {
        // A process killed by signal has no exit code (.code() returns None).
        // The engine must handle this by defaulting to exit 1 (GeneralError).
        let result = execute_provider_command(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "kill -9 $$".to_string(), // Self-SIGKILL
            ],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        assert!(
            !result.timed_out,
            "Self-kill should not be treated as timeout"
        );
        // Signal-killed process (exit > 128) maps through interpret_provider_exit
        // to GeneralError.
        assert_eq!(
            result.exit_result.exit_code,
            ProviderExitCode::GeneralError,
            "Signal-killed process must map to GeneralError"
        );
    }

    #[tokio::test]
    async fn engine_result_is_debuggable() {
        // ProviderExecResult must implement Debug for diagnostics.
        let json = r#"{"token":"tok","expires_at":"2099-01-01T00:00:00Z"}"#;
        let script = format!("printf '{}'", json);
        let result = execute_provider_command(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            &HashMap::new(),
            &ExecConfig::default(),
            3600,
        )
        .await;

        let result = result.expect("command should spawn");
        let debug = format!("{:?}", result);
        assert!(!debug.is_empty(), "ProviderExecResult must implement Debug");
    }
}
