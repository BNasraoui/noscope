use super::*;
use crate::core::signal_policy::ParentSignal;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn write_provider_config(
    xdg_config_home: &Path,
    provider_name: &str,
    mint_cmd: &str,
    revoke_cmd: &str,
) {
    let providers_dir = xdg_config_home.join("noscope").join("providers");
    fs::create_dir_all(&providers_dir).unwrap();
    let cfg = format!(
        "contract_version = 1\n\n[commands]\nmint = \"{}\"\nrevoke = \"{}\"\n",
        mint_cmd, revoke_cmd
    );
    let path = providers_dir.join(format!("{}.toml", provider_name));
    fs::write(&path, cfg).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn make_run_args(
    providers: Vec<String>,
    role: &str,
    ttl: u64,
    profile: Option<String>,
    log_format: &str,
    child_args: Vec<String>,
) -> cli::RunArgs {
    cli::RunArgs {
        provider: providers,
        role: Some(role.to_string()),
        ttl: Some(ttl),
        profile,
        log_format: log_format.to_string(),
        child_args,
    }
}

fn scoped_env<T>(key: &str, value: &Path, f: impl FnOnce() -> T) -> T {
    let old = std::env::var_os(key);
    // SAFETY: test-local env mutation, restored before return.
    unsafe {
        std::env::set_var(key, value);
    }
    let out = f();
    match old {
        Some(prev) => {
            // SAFETY: test-local env restoration.
            unsafe {
                std::env::set_var(key, prev);
            }
        }
        None => {
            // SAFETY: test-local env restoration.
            unsafe {
                std::env::remove_var(key);
            }
        }
    }
    out
}

#[test]
fn run_resolves_providers_from_cli_args() {
    let args = make_run_args(
        vec!["missing-provider".to_string()],
        "admin",
        3600,
        None,
        "text",
        vec!["/bin/true".to_string()],
    );

    let result = cmd_run(args, false);
    assert!(
        result.is_err(),
        "cmd_run must resolve providers and fail for unknown provider"
    );
}

#[test]
fn run_resolves_providers_from_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_dir = tmp.path().join("noscope").join("profiles");
    fs::create_dir_all(&profile_dir).unwrap();

    let child = tmp.path().join("child.sh");
    write_executable(&child, "#!/bin/sh\nexit 17\n");

    let mint_script = tmp.path().join("mint.sh");
    write_executable(
        &mint_script,
        "#!/bin/sh\nprintf '{\"token\":\"profile-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    let revoke_script = tmp.path().join("revoke.sh");
    write_executable(&revoke_script, "#!/bin/sh\nexit 0\n");

    write_provider_config(
        tmp.path(),
        "aws",
        mint_script.to_string_lossy().as_ref(),
        revoke_script.to_string_lossy().as_ref(),
    );

    fs::write(
        profile_dir.join("dev.toml"),
        "[[credentials]]\nprovider = \"aws\"\nrole = \"profile-role\"\nttl = 3600\n",
    )
    .unwrap();
    fs::set_permissions(
        profile_dir.join("dev.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let args = make_run_args(
        vec!["missing-provider".to_string()],
        "ignored-role",
        3600,
        Some("dev".to_string()),
        "text",
        vec![child.to_string_lossy().to_string()],
    );

    let result = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
    assert_eq!(
        result.unwrap(),
        17,
        "cmd_run must resolve provider from profile and run child"
    );
}

#[test]
fn run_mints_credentials_before_spawn() {
    let tmp = tempfile::tempdir().unwrap();
    let mint_marker = tmp.path().join("mint-called.txt");
    let child = tmp.path().join("child.sh");
    let mint = tmp.path().join("mint.sh");
    let revoke = tmp.path().join("revoke.sh");

    write_executable(
        &mint,
        &format!(
            "#!/bin/sh\nprintf called > '{}'\nprintf '{{\"token\":\"minted-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}}'\n",
            mint_marker.display()
        ),
    );
    write_executable(&revoke, "#!/bin/sh\nexit 0\n");
    write_executable(&child, "#!/bin/sh\nexit 0\n");

    write_provider_config(
        tmp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let args = make_run_args(
        vec!["aws".to_string()],
        "admin",
        3600,
        None,
        "text",
        vec![child.to_string_lossy().to_string()],
    );

    let _ = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
    assert!(
        mint_marker.exists(),
        "cmd_run must mint credentials before spawning child"
    );
}

#[test]
fn run_spawns_child_with_injected_env_vars() {
    let tmp = tempfile::tempdir().unwrap();
    let child_out = tmp.path().join("child-env.txt");
    let child = tmp.path().join("child.sh");
    let mint = tmp.path().join("mint.sh");
    let revoke = tmp.path().join("revoke.sh");

    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"aws-env-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(&revoke, "#!/bin/sh\nexit 0\n");
    write_executable(
        &child,
        &format!(
            "#!/bin/sh\nprintf %s \"$AWS_TOKEN\" > '{}'\nexit 0\n",
            child_out.display()
        ),
    );

    write_provider_config(
        tmp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let args = make_run_args(
        vec!["aws".to_string()],
        "admin",
        3600,
        None,
        "text",
        vec![child.to_string_lossy().to_string()],
    );

    let _ = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
    let injected = fs::read_to_string(&child_out).unwrap_or_default();
    assert_eq!(
        injected, "aws-env-secret",
        "cmd_run must spawn child with minted env vars"
    );
}

#[test]
fn run_waits_for_exit_and_returns_child_code() {
    let tmp = tempfile::tempdir().unwrap();
    let child = tmp.path().join("child.sh");
    let mint = tmp.path().join("mint.sh");
    let revoke = tmp.path().join("revoke.sh");

    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"wait-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(&revoke, "#!/bin/sh\nexit 0\n");
    write_executable(&child, "#!/bin/sh\nexit 37\n");

    write_provider_config(
        tmp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let args = make_run_args(
        vec!["aws".to_string()],
        "admin",
        3600,
        None,
        "text",
        vec![child.to_string_lossy().to_string()],
    );

    let exit = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false)).unwrap();
    assert_eq!(
        exit, 37,
        "cmd_run must wait for child and return child exit code"
    );
}

#[test]
fn run_revokes_all_credentials_before_exit() {
    let tmp = tempfile::tempdir().unwrap();
    let revoke_log = tmp.path().join("revoke.log");
    let child = tmp.path().join("child.sh");

    let mint_aws = tmp.path().join("mint-aws.sh");
    let mint_gcp = tmp.path().join("mint-gcp.sh");
    let revoke_aws = tmp.path().join("revoke-aws.sh");
    let revoke_gcp = tmp.path().join("revoke-gcp.sh");

    write_executable(
        &mint_aws,
        "#!/bin/sh\nprintf '{\"token\":\"aws-revoke-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(
        &mint_gcp,
        "#!/bin/sh\nprintf '{\"token\":\"gcp-revoke-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(
        &revoke_aws,
        &format!(
            "#!/bin/sh\nprintf '%s\n' \"$NOSCOPE_TOKEN_ID\" >> '{}'\nexit 0\n",
            revoke_log.display()
        ),
    );
    write_executable(
        &revoke_gcp,
        &format!(
            "#!/bin/sh\nprintf '%s\n' \"$NOSCOPE_TOKEN_ID\" >> '{}'\nexit 0\n",
            revoke_log.display()
        ),
    );
    write_executable(&child, "#!/bin/sh\nexit 0\n");

    write_provider_config(
        tmp.path(),
        "aws",
        mint_aws.to_string_lossy().as_ref(),
        revoke_aws.to_string_lossy().as_ref(),
    );
    write_provider_config(
        tmp.path(),
        "gcp",
        mint_gcp.to_string_lossy().as_ref(),
        revoke_gcp.to_string_lossy().as_ref(),
    );

    let args = make_run_args(
        vec!["aws".to_string(), "gcp".to_string()],
        "admin",
        3600,
        None,
        "text",
        vec![child.to_string_lossy().to_string()],
    );

    let _ = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
    let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
    assert!(
        revoked.contains("tok-aws"),
        "cmd_run must revoke minted aws credential"
    );
    assert!(
        revoked.contains("tok-gcp"),
        "cmd_run must revoke minted gcp credential"
    );
}

#[test]
fn run_revokes_credentials_if_child_fails_to_spawn() {
    let tmp = tempfile::tempdir().unwrap();
    let revoke_log = tmp.path().join("revoke.log");

    let mint = tmp.path().join("mint.sh");
    let revoke = tmp.path().join("revoke.sh");

    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"spawn-fail-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_executable(
        &revoke,
        &format!(
            "#!/bin/sh\nprintf '%s\n' \"$NOSCOPE_TOKEN_ID\" >> '{}'\nexit 0\n",
            revoke_log.display()
        ),
    );

    write_provider_config(
        tmp.path(),
        "aws",
        mint.to_string_lossy().as_ref(),
        revoke.to_string_lossy().as_ref(),
    );

    let args = make_run_args(
        vec!["aws".to_string()],
        "admin",
        3600,
        None,
        "text",
        vec!["/definitely/not/a/real/command".to_string()],
    );

    let result = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_run(args, false));
    assert!(
        result.is_err(),
        "cmd_run must return an error when child cannot be spawned"
    );

    let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
    assert!(
        revoked.contains("tok-aws"),
        "cmd_run must revoke minted credential when child spawn fails"
    );
}

#[test]
fn ns_029_revocation_callback_not_invoked_before_signal_receipt_in_run_mode() {
    let mut revoke_calls = 0usize;
    let mut process = FakeSignalProcess::default();
    let mut wiring = RunSignalWiring::default();

    let polled = run_mode_poll_without_signal_for_test(&mut wiring, &mut process, &mut || {
        revoke_calls += 1;
        Ok(())
    })
    .expect("polling run loop without signals should succeed");

    assert!(
        !polled.signal_processed,
        "no signal should be processed when none were received"
    );
    assert_eq!(
        revoke_calls, 0,
        "ClosureRevoker callback must not run before shutdown signal receipt"
    );
}

#[test]
fn ns_029_revocation_callback_triggers_only_after_shutdown_signal_in_run_mode() {
    let mut revoke_calls = 0usize;
    let mut process = FakeSignalProcess::default();
    let mut wiring = RunSignalWiring::default();

    let no_signal = run_mode_poll_without_signal_for_test(&mut wiring, &mut process, &mut || {
        revoke_calls += 1;
        Ok(())
    })
    .expect("polling run loop without signals should succeed");
    assert!(!no_signal.signal_processed);
    assert_eq!(revoke_calls, 0, "must not revoke before signal receipt");

    let with_signal = run_mode_dispatch_parent_signal_for_test(
        &mut wiring,
        ParentSignal::Sigterm,
        &mut process,
        &mut || {
            revoke_calls += 1;
            Ok(())
        },
    )
    .expect("dispatching shutdown signal should succeed");

    assert!(with_signal.signal_processed);
    assert_eq!(
        revoke_calls, 1,
        "ClosureRevoker callback must trigger after first shutdown signal"
    );
}

#[test]
fn ns_029_revocation_callback_runs_at_most_once_across_multiple_shutdown_signals() {
    let mut revoke_calls = 0usize;
    let mut process = FakeSignalProcess::default();
    let mut wiring = RunSignalWiring::default();

    let first = run_mode_dispatch_parent_signal_for_test(
        &mut wiring,
        ParentSignal::Sigterm,
        &mut process,
        &mut || {
            revoke_calls += 1;
            Ok(())
        },
    )
    .expect("first shutdown signal dispatch should succeed");
    assert!(first.signal_processed);
    assert_eq!(revoke_calls, 1, "first shutdown signal should revoke once");

    let second = run_mode_dispatch_parent_signal_for_test(
        &mut wiring,
        ParentSignal::Sigint,
        &mut process,
        &mut || {
            revoke_calls += 1;
            Ok(())
        },
    )
    .expect("second shutdown signal dispatch should succeed");
    assert!(second.signal_processed);
    assert_eq!(
        revoke_calls, 1,
        "revocation callback must not run again after first shutdown-triggered revoke"
    );
}

#[derive(Default)]
struct FakeSignalProcess {
    forwarded: Vec<i32>,
}

impl SignalProcess for FakeSignalProcess {
    fn forward_signal(&mut self, sig: i32) -> Result<(), std::io::Error> {
        self.forwarded.push(sig);
        Ok(())
    }
}
