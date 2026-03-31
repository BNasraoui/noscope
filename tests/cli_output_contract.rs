use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).expect("write script");
    let mut perms = fs::metadata(path).expect("script metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set script permissions");
}

fn write_provider_config(home_root: &Path, provider: &str, mint_cmd: &str, revoke_cmd: &str) {
    let providers_dir = home_root.join(".config").join("noscope").join("providers");
    fs::create_dir_all(&providers_dir).expect("create providers dir");

    let cfg = format!(
        "contract_version = 1\n\n[commands]\nmint = \"{}\"\nrevoke = \"{}\"\n",
        mint_cmd, revoke_cmd
    );

    let cfg_path = providers_dir.join(format!("{}.toml", provider));
    fs::write(&cfg_path, cfg).expect("write provider config");
    let mut perms = fs::metadata(&cfg_path)
        .expect("provider metadata")
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&cfg_path, perms).expect("set provider config permissions");
}

fn run_noscope(args: &[&str], home_root: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_noscope"))
        .env("HOME", home_root)
        .args(args)
        .output()
        .expect("run noscope")
}

#[test]
fn ns_079_success_messages_are_emitted_on_stdout_not_stderr() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mint = temp.path().join("mint.sh");
    let revoke = temp.path().join("revoke.sh");

    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(&revoke, "#!/bin/sh\nexit 0\n");
    write_provider_config(
        temp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let validate = run_noscope(&["validate", "--provider", "aws"], temp.path());
    assert!(
        validate.status.success(),
        "validate should succeed: stderr={} ",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(
        String::from_utf8_lossy(&validate.stdout).contains("configuration is valid"),
        "NS-079: validate success message must be on stdout"
    );
    assert!(
        validate.stderr.is_empty(),
        "NS-079: validate success must not write to stderr"
    );

    let revoke = run_noscope(
        &["revoke", "--token-id", "tok-123", "--provider", "aws"],
        temp.path(),
    );
    assert!(
        revoke.status.success(),
        "revoke should succeed: stderr={} ",
        String::from_utf8_lossy(&revoke.stderr)
    );
    assert!(
        String::from_utf8_lossy(&revoke.stdout).contains("revoked token tok-123"),
        "NS-079: revoke success message must be on stdout"
    );
    assert!(
        revoke.stderr.is_empty(),
        "NS-079: revoke success must not write to stderr"
    );
}

#[test]
fn ns_080_output_json_mode_emits_structured_success_payloads() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mint = temp.path().join("mint.sh");
    let revoke = temp.path().join("revoke.sh");

    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(&revoke, "#!/bin/sh\nexit 0\n");
    write_provider_config(
        temp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let dry_run = run_noscope(
        &[
            "--output",
            "json",
            "dry-run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ],
        temp.path(),
    );
    assert!(
        dry_run.status.success(),
        "dry-run should succeed: stderr={} ",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert!(dry_run.stderr.is_empty());
    let dry_run_json: Value =
        serde_json::from_slice(&dry_run.stdout).expect("dry-run --output json must be JSON");
    assert_eq!(dry_run_json["status"], "ok");
    assert_eq!(dry_run_json["command"], "dry-run");
    assert_eq!(dry_run_json["provider"], "aws");

    let validate = run_noscope(
        &["--output", "json", "validate", "--provider", "aws"],
        temp.path(),
    );
    assert!(validate.status.success());
    assert!(validate.stderr.is_empty());
    let validate_json: Value =
        serde_json::from_slice(&validate.stdout).expect("validate --output json must be JSON");
    assert_eq!(validate_json["status"], "ok");
    assert_eq!(validate_json["command"], "validate");
    assert_eq!(validate_json["provider"], "aws");

    let revoke = run_noscope(
        &[
            "--output",
            "json",
            "revoke",
            "--token-id",
            "tok-123",
            "--provider",
            "aws",
        ],
        temp.path(),
    );
    assert!(revoke.status.success());
    assert!(revoke.stderr.is_empty());
    let revoke_json: Value =
        serde_json::from_slice(&revoke.stdout).expect("revoke --output json must be JSON");
    assert_eq!(revoke_json["status"], "ok");
    assert_eq!(revoke_json["command"], "revoke");
    assert_eq!(revoke_json["provider"], "aws");
    assert_eq!(revoke_json["token_id"], "tok-123");
}

#[test]
fn ns_081_output_json_mode_emits_structured_errors_on_stderr() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mint = temp.path().join("mint.sh");
    let revoke = temp.path().join("revoke.sh");

    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(&revoke, "#!/bin/sh\nexit 0\n");
    write_provider_config(
        temp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let output = run_noscope(
        &[
            "--output",
            "json",
            "validate",
            "--provider",
            "does-not-exist",
        ],
        temp.path(),
    );

    assert!(
        !output.status.success(),
        "validate should fail for unknown provider"
    );
    assert!(
        output.stdout.is_empty(),
        "NS-081: failures must not emit payload to stdout"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let err_json: Value = serde_json::from_str(stderr.trim())
        .expect("NS-081: --output json failures must write JSON object to stderr");
    assert_eq!(err_json["status"], "error");
    assert_eq!(err_json["kind"], "config");
    assert_eq!(err_json["command"], "validate");
    assert!(err_json["message"]
        .as_str()
        .expect("message string")
        .contains("not found"));
}

#[test]
fn ns_081_output_json_mode_reports_provider_failures_for_revoke() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mint = temp.path().join("mint.sh");
    let revoke = temp.path().join("revoke.sh");

    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(&revoke, "#!/bin/sh\nprintf 'revoke failed' 1>&2\nexit 3\n");
    write_provider_config(
        temp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let output = run_noscope(
        &[
            "--output",
            "json",
            "revoke",
            "--token-id",
            "tok-123",
            "--provider",
            "aws",
        ],
        temp.path(),
    );

    assert!(!output.status.success(), "revoke should fail");
    assert!(
        output.stdout.is_empty(),
        "NS-081: revoke failures must not write to stdout"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let err_json: Value = serde_json::from_str(stderr.trim())
        .expect("NS-081: revoke failures must render JSON in --output json mode");
    assert_eq!(err_json["status"], "error");
    assert_eq!(err_json["command"], "revoke");
    assert_eq!(err_json["kind"], "provider");
    assert!(err_json["message"]
        .as_str()
        .expect("message string")
        .contains("revoke failed"));
}
