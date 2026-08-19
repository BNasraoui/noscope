// res_refresh_subsystem_ships: the refresh subsystem is wired to the
// live `noscope run` path. These tests drive the real binary.

use provenance_macros::verifies;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod script");
}

fn write_provider_config(xdg: &Path, provider: &str, mint_cmd: &str, refresh_cmd: Option<&str>) {
    let dir = xdg.join("noscope").join("providers");
    fs::create_dir_all(&dir).expect("create providers dir");
    let mut cfg = format!(
        "contract_version = 1\n\n[commands]\nmint = \"{}\"\n",
        mint_cmd
    );
    if let Some(refresh) = refresh_cmd {
        cfg.push_str(&format!("refresh = \"{}\"\n", refresh));
    }
    let path = dir.join(format!("{}.toml", provider));
    fs::write(&path, cfg).expect("write provider config");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod config");
}

fn run_noscope(xdg: &Path, child: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_noscope"))
        .env("XDG_CONFIG_HOME", xdg)
        .env_remove("NOSCOPE_MINT_CMD")
        .env_remove("NOSCOPE_REFRESH_CMD")
        .env_remove("NOSCOPE_REVOKE_CMD")
        .args([
            "run",
            "--provider",
            "mock",
            "--role",
            "dev",
            "--ttl",
            "3600",
            "--",
            "sh",
            "-c",
            child,
        ])
        .output()
        .expect("run noscope binary")
}

/// A provider whose lease expires in 2 seconds: the refresh timer (75% of
/// lifetime, NS-048) fires while the child is alive, and the provider's
/// refresh command runs with the NS-039 env contract.
#[test]
#[verifies("rule_refresh_rotate_mode_warning", conformance)]
fn run_mode_executes_provider_refresh_command_when_due() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("refresh-env");

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\n\
         expires=$(date -u -d '+2 seconds' +%Y-%m-%dT%H:%M:%SZ)\n\
         printf '{\"token\":\"initial-secret\",\"expires_at\":\"%s\"}' \"$expires\"\n",
    );

    let refresh = tmp.path().join("refresh.sh");
    write_executable(
        &refresh,
        &format!(
            "#!/bin/sh\n\
             printf 'token=%s id=%s ttl=%s' \"$NOSCOPE_TOKEN\" \"$NOSCOPE_TOKEN_ID\" \"$NOSCOPE_TTL\" > {}\n\
             expires=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)\n\
             printf '{{\"token\":\"rotated-secret\",\"expires_at\":\"%s\"}}' \"$expires\"\n",
            marker.display()
        ),
    );

    write_provider_config(
        tmp.path(),
        "mock",
        mint.to_string_lossy().as_ref(),
        Some(refresh.to_string_lossy().as_ref()),
    );

    let output = run_noscope(tmp.path(), "sleep 3");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "run must pass through child success; stderr: {}",
        stderr
    );

    // NS-039: refresh received the current value, the lease id, and the TTL.
    let recorded = fs::read_to_string(&marker)
        .expect("refresh command must have run while the child was alive");
    assert!(
        recorded.contains("token=initial-secret"),
        "refresh env must carry the current credential value: {}",
        recorded
    );
    assert!(
        recorded.contains("id=tok-mock"),
        "refresh env must carry the lease identifier: {}",
        recorded
    );
    assert!(
        recorded.contains("ttl=3600"),
        "refresh env must carry the granted TTL in seconds: {}",
        recorded
    );

    // NS-025: startup warning that env injection is point-in-time.
    assert!(
        stderr.contains("environment variable injection is point-in-time"),
        "refresh-enabled run must emit the NS-025 startup warning; stderr: {}",
        stderr
    );

    // The refresh returned a different value: a rotation leaves the child
    // holding the previous value, and the operator is told so.
    assert!(
        stderr.contains("rotated credential"),
        "rotation must warn that the child env is stale; stderr: {}",
        stderr
    );
}

/// Without a refresh command the loop stays dormant: no startup warning,
/// no refresh execution.
#[test]
fn run_mode_without_refresh_command_emits_no_refresh_warnings() {
    let tmp = tempfile::tempdir().unwrap();

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\n\
         printf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_provider_config(tmp.path(), "mock", mint.to_string_lossy().as_ref(), None);

    let output = run_noscope(tmp.path(), "true");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {}", stderr);
    assert!(
        !stderr.contains("environment variable injection is point-in-time"),
        "no refresh command, no rotate-mode warning; stderr: {}",
        stderr
    );
}

/// NS-049: an expired credential produces a log-only warning; the child
/// keeps running and the run still passes through the child exit code.
#[test]
#[verifies("rule_expiry_log_only", conformance)]
fn run_mode_expiry_warns_without_stopping_child() {
    let tmp = tempfile::tempdir().unwrap();

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\n\
         expires=$(date -u -d '+1 second' +%Y-%m-%dT%H:%M:%SZ)\n\
         printf '{\"token\":\"short-lived\",\"expires_at\":\"%s\"}' \"$expires\"\n",
    );
    write_provider_config(tmp.path(), "mock", mint.to_string_lossy().as_ref(), None);

    let output = run_noscope(tmp.path(), "sleep 2; exit 7");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // NS-004: the child ran to completion and its exit code passed through.
    assert_eq!(
        output.status.code(),
        Some(7),
        "expiry must not stop the child; stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("credential expired"),
        "expiry must warn the operator; stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("provider=mock"),
        "expiry warning must name the provider; stderr: {}",
        stderr
    );
}
