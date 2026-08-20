// Provider output contract
// Template variable injection prevention
// Missing expires_at computed from requested TTL
// Provider command execution timeout
// Provider stdout size limit
// TTL format is integer seconds for providers
// Revoke command receives token via env var
// Refresh command receives token via env var
// Provider stderr handling
// Provider capability declaration
// Provider command environment sandboxing

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use zeroize::Zeroize;

use crate::core::exit_code::{interpret_provider_exit, ProviderExitResult};
use provenance_macros::rule;

/// Maximum provider stdout size in bytes (1 MiB).
pub const MAX_STDOUT_BYTES: usize = 1024 * 1024;

/// Maximum stderr bytes captured on failure.
pub const MAX_STDERR_CAPTURE_BYTES: usize = 4096;

/// Parsed provider command output.
/// Contains the token value and expiry time. If the provider did not
/// supply `expires_at`, it is computed from the requested TTL and
/// `expires_at_provided` is `false` (the caller should emit a warning
///).
pub struct ProviderOutput {
    /// The raw token string from the provider.
    pub token: String,
    /// Provider-supplied lease identifier (e.g. a NATS user public key).
    /// `None` when the provider does not name its leases.
    pub token_id: Option<String>,
    /// The expiry time — either from the provider or computed from TTL.
    pub expires_at: DateTime<Utc>,
    /// Whether the provider explicitly supplied `expires_at`.
    /// `false` means it was computed from `now() + requested_ttl`.
    pub expires_at_provided: bool,
}

impl fmt::Debug for ProviderOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = crate::core::redaction::RedactedToken::new(&self.token, None);
        f.debug_struct("ProviderOutput")
            .field("token", &redacted)
            .field("expires_at", &self.expires_at)
            .field("expires_at_provided", &self.expires_at_provided)
            .finish()
    }
}

// Zeroize the raw token value on drop, matching MintEnvelope pattern.
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
    /// Provider output violated the JSON contract.
    OutputContract { message: String },
    /// Provider command timed out.
    Timeout { timeout: Duration },
    /// Provider stdout exceeded size limit.
    StdoutTooLarge { size: usize, limit: usize },
    /// Invalid role string.
    InvalidRole { role: String, reason: String },
    /// Capability/config inconsistency.
    CapabilityMismatch { message: String },
    /// Config parsing error (not a provider output issue).
    ConfigParse { message: String },
}

impl ProviderExecError {
    /// Map this error to a provider exit code.
    /// Timeout is treated as exit code 4 (Unavailable).
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

/// Configuration for provider command execution.
pub struct ExecConfig {
    /// Command timeout (default 30s).
    pub timeout: Duration,
    /// Grace period after SIGTERM before SIGKILL (default 5s).
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

/// Provider capability declaration.
/// Owned by crate::ports::provider so capability parsing/validation shares the same
/// parsing flow as provider config.
pub type ProviderCapabilities = crate::ports::provider::ProviderCapabilities;

/// Policy for handling provider stderr.
pub struct StderrPolicy {
    discard: bool,
}

impl StderrPolicy {
    /// On success, discard stderr unless verbose.
    pub fn on_success(verbose: bool) -> Self {
        Self { discard: !verbose }
    }

    /// On failure, always capture stderr.
    pub fn on_failure() -> Self {
        Self { discard: false }
    }

    /// Whether stderr should be discarded.
    pub fn should_discard(&self) -> bool {
        self.discard
    }
}

/// Parse provider command stdout as JSON.
/// Extracts `token` (required, string) and `expires_at` (optional, ISO 8601).
/// If `expires_at` is absent, computes `now() + requested_ttl_secs` and sets
/// `expires_at_provided = false` so the caller can emit warning.
#[rule("rule_exec_expiry_fallback")]
#[rule("rule_exec_output_token_contract")]
pub fn parse_provider_output(
    json_str: &str,
    requested_ttl_secs: u64,
) -> Result<ProviderOutput, ProviderExecError> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| ProviderExecError::OutputContract {
            message: format!("invalid JSON: {}", e),
        })?;

    // 'token' is required and must be a non-empty string.
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

    // 'token_id' is optional. The provider names its lease when the
    // identifier matters for revocation (rule_provider_supplied_token_id).
    let token_id = parsed
        .get("token_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // 'expires_at' is optional.
    let (expires_at, provided) = match parsed.get("expires_at").and_then(|v| v.as_str()) {
        Some(s) => {
            let dt: DateTime<Utc> = s.parse().map_err(|e| ProviderExecError::OutputContract {
                message: format!("invalid ISO 8601 expires_at '{}': {}", s, e),
            })?;
            (dt, true)
        }
        None => {
            // Compute from requested TTL.
            let dt = Utc::now() + chrono::Duration::seconds(requested_ttl_secs as i64);
            (dt, false)
        }
    };

    Ok(ProviderOutput {
        token: token.to_string(),
        token_id,
        expires_at,
        expires_at_provided: provided,
    })
}

/// Validate that a role string contains only safe characters.
/// Allowed: alphanumeric, hyphens, underscores, dots.
/// Rejected: empty string, spaces, shell metacharacters, slashes, etc.
#[rule("rule_role_charset")]
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

/// Substitute template variables in an argv array.
/// Replaces `{role}` with the role string and `{ttl}` with TTL as integer
/// seconds. This is pure string replacement on each element of the array —
/// no shell is involved.
#[rule("rule_cross_template_substitution")]
pub fn substitute_template_vars(template: &[String], role: &str, ttl_secs: u64) -> Vec<String> {
    let ttl_str = ttl_secs.to_string();
    template
        .iter()
        .map(|arg| arg.replace("{role}", role).replace("{ttl}", &ttl_str))
        .collect()
}

/// Check that provider stdout does not exceed 1 MiB.
#[rule("rule_exec_stdout_1mib_cap")]
pub fn check_stdout_size_limit(size: usize) -> Result<(), ProviderExecError> {
    if size > MAX_STDOUT_BYTES {
        return Err(ProviderExecError::StdoutTooLarge {
            size,
            limit: MAX_STDOUT_BYTES,
        });
    }
    Ok(())
}

/// Build environment variables for a revoke command.
/// Sets NOSCOPE_TOKEN_ID only. Revocation addresses a lease by
/// identifier; the credential value is never passed to a revoke command
/// (res_revoke_contract_identifier_only). Does NOT set NOSCOPE_TTL
/// (that's only for refresh).
#[rule("rule_revoke_identifier_only")]
pub fn build_revoke_env(token_id: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("NOSCOPE_TOKEN_ID".to_string(), token_id.to_string());
    env
}

/// Check if a revoke command exit code indicates success.
/// Exit 0 is success, including the case where the token was already revoked.
#[rule("rule_cross_revoke_idempotent_exit0")]
pub fn is_revoke_success(exit_code: i32) -> bool {
    exit_code == 0
}

/// Build environment variables for a refresh command.
/// Sets NOSCOPE_TOKEN, NOSCOPE_TOKEN_ID, and NOSCOPE_TTL (integer seconds).
pub fn build_refresh_env(token: &str, token_id: &str, ttl_secs: u64) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("NOSCOPE_TOKEN".to_string(), token.to_string());
    env.insert("NOSCOPE_TOKEN_ID".to_string(), token_id.to_string());
    env.insert("NOSCOPE_TTL".to_string(), ttl_secs.to_string());
    env
}

/// Capture stderr up to the size limit.
/// Truncates to `MAX_STDERR_CAPTURE_BYTES` (4096 bytes).
#[rule("rule_exec_stderr_truncate")]
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

/// Redact known token values from stderr.
/// Replaces each occurrence of a known token with `[redacted]`.
#[rule("rule_exec_stderr_redaction")]
pub fn redact_stderr(stderr: &str, known_tokens: &[&str]) -> String {
    let mut result = stderr.to_string();
    for token in known_tokens {
        if !token.is_empty() {
            result = result.replace(token, "[redacted]");
        }
    }
    result
}

/// Parse capability booleans from provider TOML content.
/// Looks for top-level `supports_refresh` and `supports_revoke` booleans.
/// Defaults to `false` if absent.
pub fn parse_capabilities_from_toml(
    content: &str,
) -> Result<ProviderCapabilities, ProviderExecError> {
    let parsed = crate::ports::provider::parse_provider_toml(content).map_err(|e| {
        ProviderExecError::ConfigParse {
            message: e.to_string(),
        }
    })?;
    Ok(parsed.capabilities)
}

/// Validate that capability declarations are consistent with
/// configured commands.
/// If `supports_refresh` is true, a refresh command must be present.
/// If `supports_revoke` is true, a revoke command must be present.
pub fn validate_capabilities(
    caps: &ProviderCapabilities,
    has_refresh_cmd: bool,
    has_revoke_cmd: bool,
) -> Result<(), ProviderExecError> {
    crate::ports::provider::validate_declared_capabilities(caps, has_refresh_cmd, has_revoke_cmd)
        .map_err(|e| ProviderExecError::CapabilityMismatch {
            message: e.to_string(),
        })
}

/// Build a minimal sandboxed environment for provider commands.
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

/// Result of executing a provider command.
/// Contains all outputs from the subprocess: stdout, stderr, exit code,
/// parsed output (if applicable), and whether the command timed out.
#[derive(Debug)]
pub struct ProviderExecResult {
    /// Raw stdout from the provider command.
    pub stdout: String,
    /// Captured stderr, truncated to [`MAX_STDERR_CAPTURE_BYTES`] and
    /// redacted of known token values.
    pub stderr: String,
    /// Interpreted exit code.
    pub exit_result: ProviderExitResult,
    /// Parsed provider output. `Ok` on exit 0 with valid JSON,
    /// `Err` for timeout, oversized stdout, or parse failure.
    pub parsed_output: Result<ProviderOutput, ProviderExecError>,
    /// Whether the command was killed due to timeout.
    pub timed_out: bool,
}

/// Execute a provider command in a sandboxed environment.
/// This is the core execution engine that ties together all policy building
/// blocks:
/// # Arguments
/// - `argv`: Command and arguments (no shell involved).
/// - `extra_env`: Additional environment variables (e.g. NOSCOPE_TOKEN) merged
///   on top of the sandboxed base env.
/// - `config`: Execution configuration (timeout, grace period).
/// - `requested_ttl_secs`: TTL used to compute expiry when the provider omits it.
/// # Returns
/// - `Ok(ProviderExecResult)` with all execution results.
/// - `Err(std::io::Error)` if the command could not be spawned.
#[rule("rule_exec_exit0_only_mints")]
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

    // Build sandboxed environment, then overlay extra vars.
    let mut env = build_sandboxed_env();
    for (k, v) in extra_env {
        env.insert(k.clone(), v.clone());
    }

    // Collect known token values for stderr redaction.
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
    // If the caller's future is dropped (e.g. the orchestrator's
    // per-provider timeout fires), the provider must not keep running and
    // mint a credential nobody ever sees.
    cmd.kill_on_drop(true);
    // the provider leads its own process group so that timeout
    // escalation reaches every process the provider spawned, not only the
    // direct child. Without this a `sh -c '... ; sleep'` provider leaves
    // an orphan holding the output pipes after SIGKILL.
    // SAFETY: setpgid in pre_exec affects only the forked child.
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
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

    // Enforce timeout with SIGTERM then SIGKILL escalation.
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

    // Capture stderr (truncate), then redact known tokens.
    let captured = capture_stderr(&raw_stderr);
    let token_refs: Vec<&str> = known_tokens.iter().map(|s| s.as_str()).collect();
    let stderr = redact_stderr(captured, &token_refs);

    // Map exit code through interpret_provider_exit().
    let raw_exit = exit_status.code().unwrap_or(1);
    let exit_result = if timed_out {
        // Timeout is treated as exit 4 (Unavailable).
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
        // Check stdout size limit first.
        match check_stdout_size_limit(stdout.len()) {
            Err(e) => Err(e),
            Ok(()) => {
                // Parse output only on exit 0.
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

/// Send a Unix signal to a provider's whole process group.
/// The provider was made a process-group leader at spawn, so a negative
/// pid targets the group per POSIX and the signal reaches every process
/// the provider started.
/// Best-effort: if the process has already exited, the signal is silently ignored.
fn send_signal(child: &tokio::process::Child, signal: libc::c_int) {
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(-(pid as libc::pid_t), signal);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod engine_tests;
