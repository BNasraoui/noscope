use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

fn clear_pending_parent_signals() {
    let mut signals =
        signal_hook::iterator::Signals::new([libc::SIGTERM, libc::SIGINT, libc::SIGHUP]).unwrap();
    for _ in 0..5 {
        let mut saw_pending = false;
        for _ in signals.pending() {
            saw_pending = true;
        }
        if !saw_pending {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

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

fn make_run_args(child_script: &Path) -> cli::RunArgs {
    cli::RunArgs {
        provider: vec!["aws".to_string()],
        role: Some("admin".to_string()),
        ttl: Some(3600),
        profile: None,
        env_key: None,
        restart_before_expiry: None,
        log_format: "text".to_string(),
        child_args: vec![child_script.to_string_lossy().to_string()],
    }
}

fn scoped_xdg_config_home<T>(value: &Path, f: impl FnOnce() -> T) -> T {
    let old = std::env::var_os("XDG_CONFIG_HOME");
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", value);
    }
    let out = f();
    match old {
        Some(prev) => unsafe {
            std::env::set_var("XDG_CONFIG_HOME", prev);
        },
        None => unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        },
    }
    out
}

fn spawn_parent_signals_after_child_ready(
    ready_file: PathBuf,
    signals: Vec<i32>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready_file.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }

        let pid = unsafe { libc::getpid() };
        for sig in signals {
            let rc = unsafe { libc::kill(pid, sig) };
            assert_eq!(rc, 0, "failed to deliver parent signal {}", sig);
            thread::sleep(Duration::from_millis(100));
        }
    })
}

#[test]
fn ns_026_run_mode_forwards_real_sigterm_sigint_sighup_via_cmd_run_path() {
    let _guard = global_signal_test_lock().lock().unwrap();
    clear_pending_parent_signals();

    let cases = [
        (libc::SIGTERM, "TERM"),
        (libc::SIGINT, "INT"),
        (libc::SIGHUP, "HUP"),
    ];

    for (signal, expected_marker) in cases {
        clear_pending_parent_signals();
        let tmp = tempfile::tempdir().unwrap();
        let ready_file = tmp.path().join(format!("ready-{}", signal));
        let signal_log = tmp.path().join(format!("signal-{}.log", signal));
        let revoke_log = tmp.path().join(format!("revoke-{}.log", signal));

        let child = tmp.path().join("child.sh");
        write_executable(
            &child,
            &format!(
                "#!/bin/sh\nprintf ready > '{}'\ntrap 'printf TERM > {}; exit 0' TERM\ntrap 'printf INT > {}; exit 0' INT\ntrap 'printf HUP > {}; exit 0' HUP\nwhile :; do sleep 0.05; done\n",
                ready_file.display(),
                signal_log.display(),
                signal_log.display(),
                signal_log.display(),
            ),
        );

        let mint = tmp.path().join("mint.sh");
        write_executable(
            &mint,
            "#!/bin/sh\nprintf '{\"token\":\"signal-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );

        let revoke = tmp.path().join("revoke.sh");
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

        let sender = spawn_parent_signals_after_child_ready(ready_file.clone(), vec![signal]);
        let result = scoped_xdg_config_home(tmp.path(), || cmd_run(make_run_args(&child), false));
        sender.join().unwrap();

        assert_eq!(result.unwrap(), 0);
        assert_eq!(
            fs::read_to_string(&signal_log).unwrap_or_default(),
            expected_marker,
            "child must receive forwarded signal {} via cmd_run path",
            expected_marker
        );
    }
}

#[test]
fn ns_003_run_mode_attempts_revoke_on_real_shutdown_signal_via_cmd_run_path() {
    let _guard = global_signal_test_lock().lock().unwrap();
    clear_pending_parent_signals();

    let tmp = tempfile::tempdir().unwrap();
    let ready_file = tmp.path().join("ready");
    let signal_log = tmp.path().join("signal.log");
    let revoke_log = tmp.path().join("revoke.log");

    let child = tmp.path().join("child.sh");
    write_executable(
        &child,
        &format!(
            "#!/bin/sh\nprintf ready > '{}'\ntrap 'printf TERM > {}; exit 0' TERM\ntrap 'printf INT > {}; exit 0' INT\ntrap 'printf HUP > {}; exit 0' HUP\nwhile :; do sleep 0.05; done\n",
            ready_file.display(),
            signal_log.display(),
            signal_log.display(),
            signal_log.display(),
        ),
    );

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"revoke-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );

    let revoke = tmp.path().join("revoke.sh");
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

    let sender = spawn_parent_signals_after_child_ready(ready_file, vec![libc::SIGTERM]);
    let result = scoped_xdg_config_home(tmp.path(), || cmd_run(make_run_args(&child), false));
    sender.join().unwrap();

    assert_eq!(result.unwrap(), 0);
    let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
    assert!(
        revoked.contains("tok-aws"),
        "run-mode shutdown must attempt revocation on signal via cmd_run path"
    );
}

#[test]
fn ns_028_run_mode_double_real_signal_escalates_to_sigkill_via_cmd_run_path() {
    let _guard = global_signal_test_lock().lock().unwrap();
    clear_pending_parent_signals();

    let tmp = tempfile::tempdir().unwrap();
    let ready_file = tmp.path().join("ready");
    let revoke_log = tmp.path().join("revoke.log");

    let child = tmp.path().join("child.sh");
    write_executable(
        &child,
        &format!(
            "#!/bin/sh\nprintf ready > '{}'\ntrap '' TERM\ntrap '' INT\ntrap '' HUP\nwhile :; do sleep 1; done\n",
            ready_file.display()
        ),
    );

    let mint = tmp.path().join("mint.sh");
    write_executable(
        &mint,
        "#!/bin/sh\nprintf '{\"token\":\"double-signal-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );

    let revoke = tmp.path().join("revoke.sh");
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

    let sender =
        spawn_parent_signals_after_child_ready(ready_file, vec![libc::SIGTERM, libc::SIGINT]);
    let result = scoped_xdg_config_home(tmp.path(), || cmd_run(make_run_args(&child), false));
    sender.join().unwrap();

    assert_eq!(result.unwrap(), 128 + libc::SIGKILL);

    let revoked = fs::read_to_string(&revoke_log).unwrap_or_default();
    assert_eq!(
        revoked.lines().filter(|line| *line == "tok-aws").count(),
        1,
        "double-signal escalation must not trigger duplicate revocations"
    );
}
