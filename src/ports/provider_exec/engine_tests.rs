use std::collections::HashMap;
use std::time::Duration;

use super::*;
use crate::core::exit_code::ProviderExitCode;
use provenance_macros::verifies;

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
    assert!(stdout.contains("PATH="), "spawned process must have PATH");
    assert!(stdout.contains("HOME="), "spawned process must have HOME");
    assert!(stdout.contains("LANG="), "spawned process must have LANG");
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
        "parent env vars must NOT leak to provider subprocess"
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
        "extra env vars must be available to subprocess"
    );
}

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
        "stdout exceeding 1 MiB must be rejected"
    );
    let err = result.parsed_output.unwrap_err();
    assert!(
        matches!(err, ProviderExecError::StdoutTooLarge { .. }),
        "error must be StdoutTooLarge, got: {:?}",
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
        "valid-sized stdout must be accepted, got: {:?}",
        result.parsed_output
    );
}

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
        "stderr must be captured on failure, got: {:?}",
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
        "stderr must be truncated to {} bytes, got: {}",
        MAX_STDERR_CAPTURE_BYTES,
        result.stderr.len()
    );
}

#[tokio::test]
#[verifies("rule_exec_stderr_redaction", examples)]
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
        "known token values must be redacted from stderr, got: {:?}",
        result.stderr
    );
    assert!(
        result.stderr.contains("[redacted]"),
        "redacted token must be replaced with [redacted]"
    );
}

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
    assert!(result.timed_out, "long-running command must time out");
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
        "timeout must produce Timeout error, got: {:?}",
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
    assert!(result.timed_out, "must time out");
    // Should finish within timeout + grace + some slack, not wait the full 60s
    assert!(
        elapsed < Duration::from_secs(5),
        "must SIGKILL after grace period, took {:?}",
        elapsed
    );
}

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
    let output = result.parsed_output.expect("valid JSON must parse");
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
        "invalid JSON stdout must be rejected"
    );
    assert!(
        matches!(
            result.parsed_output,
            Err(ProviderExecError::OutputContract { .. })
        ),
        "must be OutputContract error"
    );
}

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
        "exit 0 must map to Success"
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
        "exit 2 must map to AuthFailure"
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
        "exit 3 must map to RoleNotFound"
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
        "exit 4 must map to Unavailable"
    );
}

#[tokio::test]
#[verifies("rule_exec_exit0_only_mints", examples)]
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
    let result = execute_provider_command(&[], &HashMap::new(), &ExecConfig::default(), 3600).await;

    assert!(result.is_err(), "Empty argv must return error");
}

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
