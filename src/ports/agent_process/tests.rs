use provenance_macros::verifies;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{AgentMode, AgentProcess, AgentProcessConfig, AgentProcessError};

fn shell_config(script: &str) -> AgentProcessConfig {
    AgentProcessConfig {
        command: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), script.to_string()],
        mode: AgentMode::Run,
        injected_env: HashMap::new(),
        force_env: false,
        timeout: None,
    }
}

#[test]
#[verifies("rule_exit_passthrough", examples)]
fn exit_code_passthrough_ns_002() {
    let mut process = AgentProcess::spawn(shell_config("exit 42")).unwrap();
    let exit = process.wait_with_revoke(|| Ok(())).unwrap();
    assert_eq!(exit, 42);
}

#[test]
fn stdout_belongs_to_child_or_mint_output_ns_013() {
    let mut cfg = shell_config("printf 'child-stdout-only'");
    cfg.mode = AgentMode::Mint;
    let mut process = AgentProcess::spawn(cfg).unwrap();
    let outcome = process.wait_capture_with_revoke(|| Ok(())).unwrap();

    let stdout = String::from_utf8_lossy(&outcome.stdout);
    let stderr = String::from_utf8_lossy(&outcome.stderr);

    assert_eq!(stdout, "child-stdout-only");
    assert!(!stderr.contains("child-stdout-only"));
}

#[test]
#[verifies("rule_signals_noscope_env_stripped", examples)]
fn strip_noscope_env_vars_before_spawn_ns_021() {
    // SAFETY: test-local env mutation only.
    unsafe {
        std::env::set_var("NOSCOPE_MINT_CMD", "must-not-leak");
        std::env::set_var("NOSCOPE_ANYTHING", "must-not-leak-either");
    }

    let mut cfg = shell_config("if env | grep -q '^NOSCOPE_'; then exit 99; else exit 0; fi");
    cfg.mode = AgentMode::Mint;

    let mut process = AgentProcess::spawn(cfg).unwrap();
    let exit = process.wait_with_revoke(|| Ok(())).unwrap();
    assert_eq!(exit, 0);

    // SAFETY: cleanup for test-local env mutation only.
    unsafe {
        std::env::remove_var("NOSCOPE_MINT_CMD");
        std::env::remove_var("NOSCOPE_ANYTHING");
    }
}

#[test]
fn strip_noscope_env_vars_rejects_reserved_injected_keys_ns_021() {
    let mut cfg = shell_config("exit 0");
    cfg.injected_env
        .insert("NOSCOPE_MINT_CMD".to_string(), "x".to_string());

    let err = AgentProcess::spawn(cfg).unwrap_err();
    assert!(matches!(
        err,
        AgentProcessError::ReservedEnvKey { key } if key == "NOSCOPE_MINT_CMD"
    ));
}

#[test]
fn env_var_collision_is_fatal_error_without_force_ns_022() {
    // SAFETY: test-local env mutation only.
    unsafe {
        std::env::set_var("AWS_TOKEN", "already-set");
    }

    let mut cfg = shell_config("exit 0");
    cfg.injected_env
        .insert("AWS_TOKEN".to_string(), "new-value".to_string());
    cfg.force_env = false;

    let err = AgentProcess::spawn(cfg).unwrap_err();
    assert!(matches!(
        err,
        AgentProcessError::EnvCollision { key } if key == "AWS_TOKEN"
    ));

    // SAFETY: cleanup for test-local env mutation only.
    unsafe {
        std::env::remove_var("AWS_TOKEN");
    }
}

#[test]
fn env_var_collision_can_be_overridden_with_force_ns_022() {
    // SAFETY: test-local env mutation only.
    unsafe {
        std::env::set_var("AWS_TOKEN", "already-set");
    }

    let mut cfg = shell_config("[ \"$AWS_TOKEN\" = \"new-value\" ]");
    cfg.injected_env
        .insert("AWS_TOKEN".to_string(), "new-value".to_string());
    cfg.force_env = true;

    let mut process = AgentProcess::spawn(cfg).unwrap();
    let exit = process.wait_with_revoke(|| Ok(())).unwrap();
    assert_eq!(exit, 0);

    // SAFETY: cleanup for test-local env mutation only.
    unsafe {
        std::env::remove_var("AWS_TOKEN");
    }
}

#[test]
fn signal_killed_child_exit_code_convention_ns_023() {
    let mut process = AgentProcess::spawn(shell_config("kill -TERM $$")).unwrap();
    let exit = process.wait_with_revoke(|| Ok(())).unwrap();
    assert_eq!(exit, 128 + libc::SIGTERM);
}

#[test]
fn missing_command_maps_to_127_ns_023() {
    let cfg = AgentProcessConfig {
        command: "/definitely/not/a/real/binary".to_string(),
        args: vec![],
        mode: AgentMode::Run,
        injected_env: HashMap::new(),
        force_env: false,
        timeout: None,
    };

    let err = AgentProcess::spawn(cfg).unwrap_err();
    assert_eq!(err.exit_code(), 127);
}

#[test]
fn permission_denied_maps_to_126_ns_023() {
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("not-executable.sh");
    std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let cfg = AgentProcessConfig {
        command: script.to_string_lossy().to_string(),
        args: vec![],
        mode: AgentMode::Run,
        injected_env: HashMap::new(),
        force_env: false,
        timeout: None,
    };

    let err = AgentProcess::spawn(cfg).unwrap_err();
    assert_eq!(err.exit_code(), 126);
}

#[test]
fn global_wall_clock_timeout_kills_child_and_revokes_ns_057() {
    let mut cfg = shell_config("sleep 60");
    cfg.timeout = Some(Duration::from_millis(150));

    let revoke_calls = Arc::new(AtomicUsize::new(0));
    let revoke_calls_clone = Arc::clone(&revoke_calls);

    let mut process = AgentProcess::spawn(cfg).unwrap();
    let exit = process
        .wait_with_revoke(|| {
            revoke_calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();

    assert_eq!(revoke_calls.load(Ordering::SeqCst), 1);
    assert_eq!(exit, 128 + libc::SIGKILL);
}

#[test]
fn global_wall_clock_timeout_applies_in_capture_mode_ns_057() {
    let mut cfg = shell_config("sleep 60");
    cfg.mode = AgentMode::Mint;
    cfg.timeout = Some(Duration::from_millis(100));

    let mut process = AgentProcess::spawn(cfg).unwrap();
    let outcome = process.wait_capture_with_revoke(|| Ok(())).unwrap();
    assert_eq!(outcome.exit_code, 128 + libc::SIGKILL);
}

#[test]
#[verifies("rule_signals_forward_to_group", examples)]
fn forwards_parent_signals_to_child() {
    let mut process = AgentProcess::spawn(shell_config("sleep 60")).unwrap();
    process.forward_signal(libc::SIGTERM).unwrap();
    let exit = process.wait_with_revoke(|| Ok(())).unwrap();
    assert_eq!(exit, 128 + libc::SIGTERM);
}

#[test]
fn revoke_on_exit_guarantee_runs_on_normal_exit() {
    let revoke_calls = Arc::new(AtomicUsize::new(0));
    let revoke_calls_clone = Arc::clone(&revoke_calls);

    let mut process = AgentProcess::spawn(shell_config("exit 0")).unwrap();
    let exit = process
        .wait_with_revoke(|| {
            revoke_calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();

    assert_eq!(exit, 0);
    assert_eq!(revoke_calls.load(Ordering::SeqCst), 1);
}
