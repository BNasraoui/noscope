// rule_signals_process_group_setup: run mode places the child in a new
// process group before exec; mint mode applies no process-group change.
// Verified through the real binary: a process that leads a new group has
// pgid equal to its own pid.

#[cfg(target_os = "linux")]
use provenance_macros::verifies;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

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

fn read_pid_pgid(path: &Path) -> (String, String) {
    let recorded = fs::read_to_string(path).expect("marker must exist");
    let mut parts = recorded.split_whitespace();
    (
        parts.next().expect("pid").to_string(),
        parts.next().expect("pgid").to_string(),
    )
}

// The run-mode group setup (setpgid + PR_SET_PDEATHSIG) is Linux-only
// by construction: configure_child_for_run_mode is a documented no-op
// on other platforms, so the conformance test is Linux-only too.
#[cfg(target_os = "linux")]
#[test]
#[verifies("rule_signals_process_group_setup", conformance)]
fn run_mode_child_leads_its_own_process_group() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("child-ids");

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_provider_config(tmp.path(), "mock", mint.to_string_lossy().as_ref());

    let child = format!(
        "printf '%s %s' $$ \"$(ps -o pgid= -p $$)\" > {}",
        marker.display()
    );
    let output = noscope(tmp.path())
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
            &child,
        ])
        .output()
        .expect("run noscope");
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let (pid, pgid) = read_pid_pgid(&marker);
    assert_eq!(
        pid, pgid,
        "run mode must place the child in a new process group it leads"
    );
}

// a provider command leads its own process group so that timeout
// escalation reaches everything it spawned. (The rule about noscope NOT
// applying process-group setup in mint mode concerns the agent child,
// which does not exist in mint mode.)
#[test]
fn provider_command_leads_its_own_process_group() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("provider-ids");

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        &format!(
            "#!/bin/sh\n\
             printf '%s %s' $$ \"$(ps -o pgid= -p $$)\" > {}\n\
             printf '{{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}}'\n",
            marker.display()
        ),
    );
    write_provider_config(tmp.path(), "mock", mint.to_string_lossy().as_ref());

    let output = noscope(tmp.path())
        .args([
            "mint",
            "--provider",
            "mock",
            "--role",
            "dev",
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

    let (pid, pgid) = read_pid_pgid(&marker);
    assert_eq!(
        pid, pgid,
        "a provider must lead its own process group so escalation \
         reaches its descendants"
    );
}
