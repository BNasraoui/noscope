use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::TempDir;

use noscope::integration_runtime::forward_sigterm_then_escalate;

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).expect("write file");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set permissions");
}

#[test]
fn ns_003_revoke_on_exit_requires_real_shutdown_path_not_synthetic_signal() {
    let temp = TempDir::new().expect("tempdir");
    let marker = temp.path().join("signal_marker");
    let child_script = temp.path().join("signal_child.sh");
    write_executable(
        &child_script,
        &format!(
            "#!/bin/sh\nset -eu\ntrap 'echo term >> {} ; exit 0' TERM\nexit 0\n",
            marker.display()
        ),
    );

    let report = forward_sigterm_then_escalate(child_script.display().to_string().as_str(), &[])
        .expect("signal handling report");

    assert!(
        !report.forwarded_sigterm,
        "NS-003: without a received shutdown signal, run mode must not synthesize TERM forwarding"
    );
}

#[test]
fn ns_026_parent_signal_forwarding_waits_for_os_signal_before_forwarding() {
    let temp = TempDir::new().expect("tempdir");
    let marker = temp.path().join("signal_marker");
    let child_script = temp.path().join("signal_child.sh");
    write_executable(
        &child_script,
        &format!(
            "#!/bin/sh\nset -eu\ntrap 'echo term >> {} ; exit 0' TERM\nwhile :; do sleep 1; done\n",
            marker.display()
        ),
    );

    let report = forward_sigterm_then_escalate(child_script.display().to_string().as_str(), &[])
        .expect("signal handling report");

    assert!(
        !report.forwarded_sigterm,
        "NS-026: TERM forwarding must happen only after an actual parent signal is received"
    );
}

#[test]
fn ns_028_double_signal_escalation_requires_two_received_os_signals() {
    let temp = TempDir::new().expect("tempdir");
    let child_script = temp.path().join("signal_child.sh");
    write_executable(
        &child_script,
        "#!/bin/sh\nset -eu\nwhile :; do sleep 1; done\n",
    );

    let report = forward_sigterm_then_escalate(child_script.display().to_string().as_str(), &[])
        .expect("signal handling report");

    assert!(
        !report.double_signal_escalated,
        "NS-028: escalation requires two actual shutdown signals from the OS"
    );
}

#[test]
fn ns_029_shutdown_revocation_triggered_only_after_shutdown_signal() {
    let temp = TempDir::new().expect("tempdir");
    let marker = temp.path().join("signal_marker");
    let child_script = temp.path().join("signal_child.sh");
    write_executable(
        &child_script,
        &format!(
            "#!/bin/sh\nset -eu\ntrap 'echo term >> {} ; exit 0' TERM\nwhile :; do sleep 1; done\n",
            marker.display()
        ),
    );

    let report = forward_sigterm_then_escalate(child_script.display().to_string().as_str(), &[])
        .expect("signal handling report");

    let marker_contents = fs::read_to_string(&marker).unwrap_or_default();
    assert!(
        !report.forwarded_sigterm && marker_contents.is_empty(),
        "NS-029: shutdown cleanup path must not run before an actual shutdown signal"
    );
}
