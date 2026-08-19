// The documented pipeline: noscope mint ... | noscope revoke --from-stdin.
// Mint emits a JSON array of envelopes (NS-063); revoke consumes that
// array and revokes every lease in it by identifier
// (res_revoke_contract_identifier_only).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod script");
}

fn write_provider_config(xdg: &Path, provider: &str, mint_cmd: &str, revoke_cmd: &str) {
    let dir = xdg.join("noscope").join("providers");
    fs::create_dir_all(&dir).expect("create providers dir");
    let cfg = format!(
        "contract_version = 1\n\n[commands]\nmint = \"{}\"\nrevoke = \"{}\"\n",
        mint_cmd, revoke_cmd
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

#[test]
fn mint_output_pipes_into_revoke_from_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let revoked_marker = tmp.path().join("revoked");

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\n\
         printf '{\"token\":\"pipeline-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );

    let revoke = tmp.path().join("revoke.sh");
    write_executable(
        &revoke,
        &format!(
            "#!/bin/sh\n\
             if [ -n \"${{NOSCOPE_TOKEN:-}}\" ]; then exit 2; fi\n\
             printf '%s' \"$NOSCOPE_TOKEN_ID\" > {}\n",
            revoked_marker.display()
        ),
    );

    write_provider_config(
        tmp.path(),
        "mock",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let mint_output = noscope(tmp.path())
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
        .expect("run mint");
    assert!(
        mint_output.status.success(),
        "mint failed: {}",
        String::from_utf8_lossy(&mint_output.stderr)
    );
    let envelopes = String::from_utf8_lossy(&mint_output.stdout);
    assert!(
        envelopes.trim_start().starts_with('['),
        "mint must emit a JSON array: {}",
        envelopes
    );

    let mut revoke_cmd = noscope(tmp.path())
        .args(["revoke", "--from-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn revoke");
    {
        use std::io::Write;
        revoke_cmd
            .stdin
            .as_mut()
            .unwrap()
            .write_all(envelopes.as_bytes())
            .unwrap();
    }
    let revoke_output = revoke_cmd.wait_with_output().expect("wait revoke");
    assert!(
        revoke_output.status.success(),
        "revoke --from-stdin must accept mint output; stderr: {}",
        String::from_utf8_lossy(&revoke_output.stderr)
    );

    let revoked_id =
        fs::read_to_string(&revoked_marker).expect("provider revoke command must have run");
    assert_eq!(
        revoked_id, "tok-mock",
        "revoke must address the lease minted by the pipeline"
    );
}
