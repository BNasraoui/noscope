// The contract a supervised consumer relies on, driven through the
// real binary: caller-chosen env key, provider-supplied lease
// identity, no group survivors after child exit, and a scheduled
// restart before credential expiry. Landed from
// source_workflowd_integration_brief; the behaviors are generic.

use provenance_macros::verifies;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod script");
}

fn write_provider_config(xdg: &Path, provider: &str, mint_cmd: &str) {
    let dir = xdg.join("noscope").join("providers");
    fs::create_dir_all(&dir).expect("create providers dir");
    let cfg = format!(
        "contract_version = 1\n\n[commands]\nmint = \"{}\"\n",
        mint_cmd
    );
    let path = dir.join(format!("{}.toml", provider));
    fs::write(&path, cfg).expect("write provider config");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod config");
}

fn noscope(xdg: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_noscope"));
    cmd.env("XDG_CONFIG_HOME", xdg)
        .env_remove("NOSCOPE_MINT_CMD")
        .env_remove("NOSCOPE_REFRESH_CMD")
        .env_remove("NOSCOPE_REVOKE_CMD");
    cmd
}

fn iso_in(seconds: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// The systemd-unit shape: the credential arrives under the
/// caller-chosen name, as content.
#[test]
#[verifies("rule_env_key_flag", conformance)]
fn env_key_flag_delivers_credential_under_chosen_name() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("child-env");

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\n\
         printf '{\"token\":\"-----BEGIN NATS USER JWT-----\\\\ncreds-content\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_provider_config(tmp.path(), "nats", mint.to_string_lossy().as_ref());

    let child = format!("printf '%s' \"$SERVICE_NATS_CREDS\" > {}", marker.display());
    let output = noscope(tmp.path())
        .args([
            "run",
            "--provider",
            "nats",
            "--role",
            "coordinator",
            "--ttl",
            "3600",
            "--env-key",
            "SERVICE_NATS_CREDS",
            "--",
            "sh",
            "-c",
            &child,
        ])
        .output()
        .expect("run noscope");
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let recorded = fs::read_to_string(&marker).expect("child must have seen the env var");
    assert!(
        recorded.contains("BEGIN NATS USER JWT"),
        "SERVICE_NATS_CREDS must carry the creds content: {}",
        recorded
    );
}

/// The provider names its lease (a NATS user public key) and that name
/// reaches the mint envelope, so revocation can address the real lease.
#[test]
#[verifies("rule_provider_supplied_token_id", conformance)]
fn provider_supplied_token_id_reaches_the_envelope() {
    let tmp = tempfile::tempdir().unwrap();

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\n\
         printf '{\"token\":\"creds\",\"token_id\":\"UARUNNERUSERPUBKEY\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_provider_config(tmp.path(), "nats", mint.to_string_lossy().as_ref());

    let output = noscope(tmp.path())
        .args([
            "mint",
            "--provider",
            "nats",
            "--role",
            "runner-host-01",
            "--ttl",
            "3600",
            "--force-terminal",
        ])
        .output()
        .expect("run noscope mint");
    assert!(
        output.status.success(),
        "mint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let envelopes: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("mint stdout must be JSON");
    assert_eq!(
        envelopes[0]["token_id"], "UARUNNERUSERPUBKEY",
        "the provider-supplied lease identifier must reach the envelope"
    );
}

// Run mode places the child in its own process group on Linux only, so
// group reaping is verifiable there only.
#[cfg(target_os = "linux")]
#[test]
#[verifies("rule_group_termination_on_exit", conformance)]
fn no_process_from_the_child_group_survives_noscope() {
    let tmp = tempfile::tempdir().unwrap();
    let gpid_file = tmp.path().join("grandchild-pid");

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_provider_config(tmp.path(), "nats", mint.to_string_lossy().as_ref());

    // The child backgrounds a long sleep (a grandchild in the same
    // group), records its pid, and exits at once.
    let child = format!(
        "sleep 30 & printf '%s' $! > {}; exit 0",
        gpid_file.display()
    );
    let output = noscope(tmp.path())
        .args([
            "run",
            "--provider",
            "nats",
            "--role",
            "dev",
            "--ttl",
            "3600",
            "--",
            "sh",
            "-c",
            &child,
        ])
        .output()
        .expect("run noscope");
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let gpid: i32 = fs::read_to_string(&gpid_file)
        .expect("grandchild pid recorded")
        .trim()
        .parse()
        .expect("pid parses");

    // SIGTERM delivery is asynchronous; give the grandchild a moment to die.
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let alive = unsafe { libc::kill(gpid, 0) } == 0;
        if !alive {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "grandchild {} must not survive noscope's exit",
            gpid
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// With a restart margin, the wrapper stops the child before expiry so
/// the supervisor's restart re-mints on schedule instead of hitting an
/// authentication failure.
#[test]
#[verifies("rule_restart_before_expiry", conformance)]
fn restart_margin_stops_the_child_before_expiry() {
    let tmp = tempfile::tempdir().unwrap();

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        &format!(
            "#!/bin/sh\n\
             printf '{{\"token\":\"creds\",\"expires_at\":\"{}\"}}'\n",
            iso_in(58)
        ),
    );
    write_provider_config(tmp.path(), "nats", mint.to_string_lossy().as_ref());

    let start = Instant::now();
    let output = noscope(tmp.path())
        .args([
            "run",
            "--provider",
            "nats",
            "--role",
            "dev",
            "--ttl",
            "3600",
            "--restart-before-expiry",
            "55",
            "--",
            "sleep",
            "30",
        ])
        .output()
        .expect("run noscope");
    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The margin fires ~3s in; well before the child's own 30s sleep.
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "child must be stopped by the margin, not run to completion; took {:?}",
        elapsed
    );
    assert_eq!(
        output.status.code(),
        Some(143),
        "child stopped by SIGTERM must surface 128+15; stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("scheduled re-mint"),
        "the operator must be told why the child was stopped; stderr: {}",
        stderr
    );
}
