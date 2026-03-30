use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use noscope::integration_runtime::{
    AtomicMintReport, IntegrationRuntimeConfig, SignalHandlingReport, atomic_mint,
    atomic_mint_with_report, execute_provider_with_timeout, forward_sigterm_then_escalate,
    mint_profile, mint_refresh_revoke_cycle, refresh_schedule_outcomes, run_child_and_pass_exit,
};
use noscope::{ErrorKind, MintRequest, ProviderOverrides};

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).expect("write file");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set permissions");
}

fn copy_mock_scripts(temp: &TempDir) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/mock_providers");
    let dst = temp.path().join("bin");
    fs::create_dir_all(&dst).expect("create bin");

    for name in [
        "mint_success.sh",
        "refresh_success.sh",
        "revoke_success.sh",
        "mint_fail.sh",
        "mint_hang_ignore_term.sh",
    ] {
        let from = src.join(name);
        let to = dst.join(name);
        fs::copy(&from, &to).expect("copy script");
        let mut perms = fs::metadata(&to).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&to, perms).expect("chmod");
    }
}

fn write_provider_config(
    root: &Path,
    name: &str,
    mint: &str,
    refresh: &str,
    revoke: &str,
    mode: u32,
) {
    let providers_dir = root.join("noscope/providers");
    fs::create_dir_all(&providers_dir).expect("create providers dir");
    let path = providers_dir.join(format!("{}.toml", name));
    fs::write(
        &path,
        format!(
            "contract_version = 1\n\
supports_refresh = true\n\
supports_revoke = true\n\
[commands]\n\
mint = \"{}\"\n\
refresh = \"{}\"\n\
revoke = \"{}\"\n",
            mint, refresh, revoke
        ),
    )
    .expect("write provider config");
    let mut perms = fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).expect("permissions");
}

fn write_profile(root: &Path, name: &str, body: &str) {
    let profiles_dir = root.join("noscope/profiles");
    fs::create_dir_all(&profiles_dir).expect("create profiles dir");
    let path = profiles_dir.join(format!("{}.toml", name));
    fs::write(&path, body).expect("write profile");
    let mut perms = fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).expect("permissions");
}

#[tokio::test]
async fn full_credential_lifecycle_mint_refresh_revoke() {
    let temp = TempDir::new().expect("tempdir");
    copy_mock_scripts(&temp);
    let bin = temp.path().join("bin");
    write_provider_config(
        temp.path(),
        "aws",
        &bin.join("mint_success.sh").display().to_string(),
        &bin.join("refresh_success.sh").display().to_string(),
        &bin.join("revoke_success.sh").display().to_string(),
        0o600,
    );

    let cfg = IntegrationRuntimeConfig {
        xdg_config_home: temp.path().to_path_buf(),
        exec_timeout: Duration::from_secs(5),
        kill_grace_period: Duration::from_millis(200),
    };

    let report = mint_refresh_revoke_cycle(&cfg, "aws", "admin", 3600)
        .await
        .expect("lifecycle succeeds");
    assert_eq!(report.minted, 1);
    assert_eq!(report.refreshed, 1);
    assert_eq!(report.revoked, 1);
    assert!(report.event_types.iter().any(|e| {
        e.as_str() == "mint_start"
            && report
                .event_types
                .iter()
                .any(|r| r.as_str() == "mint_success")
    }));
}

#[tokio::test]
async fn multi_provider_atomic_minting_rolls_back_on_failure() {
    let temp = TempDir::new().expect("tempdir");
    copy_mock_scripts(&temp);
    let bin = temp.path().join("bin");
    write_provider_config(
        temp.path(),
        "aws",
        &bin.join("mint_success.sh").display().to_string(),
        &bin.join("refresh_success.sh").display().to_string(),
        &bin.join("revoke_success.sh").display().to_string(),
        0o600,
    );
    write_provider_config(
        temp.path(),
        "gcp",
        &bin.join("mint_fail.sh").display().to_string(),
        &bin.join("refresh_success.sh").display().to_string(),
        &bin.join("revoke_success.sh").display().to_string(),
        0o600,
    );

    let cfg = IntegrationRuntimeConfig {
        xdg_config_home: temp.path().to_path_buf(),
        exec_timeout: Duration::from_secs(5),
        kill_grace_period: Duration::from_millis(200),
    };

    let req = MintRequest {
        providers: vec!["aws".to_string(), "gcp".to_string()],
        role: "admin".to_string(),
        ttl_secs: 3600,
    };

    let result = atomic_mint(&cfg, &req, &ProviderOverrides::default()).await;
    assert!(result.is_err(), "atomic mint should fail");

    let report: AtomicMintReport =
        atomic_mint_with_report(&cfg, &req, &ProviderOverrides::default())
            .await
            .expect("report still returned");
    assert!(report.rollback_attempts >= 1);
}

#[test]
fn signal_handling_sigterm_forwarding_and_double_signal_escalation() {
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

    let report: SignalHandlingReport =
        forward_sigterm_then_escalate(child_script.display().to_string().as_str(), &[])
            .expect("signal forwarding report");

    assert!(report.forwarded_sigterm);
    assert!(report.double_signal_escalated);
}

#[tokio::test]
async fn profile_loading_to_credential_set_to_minting_pipeline() {
    let temp = TempDir::new().expect("tempdir");
    copy_mock_scripts(&temp);
    let bin = temp.path().join("bin");
    write_provider_config(
        temp.path(),
        "aws",
        &bin.join("mint_success.sh").display().to_string(),
        &bin.join("refresh_success.sh").display().to_string(),
        &bin.join("revoke_success.sh").display().to_string(),
        0o600,
    );
    write_profile(
        temp.path(),
        "dev",
        r#"
[[credentials]]
provider = "aws"
role = "admin"
ttl = 3600
env_key = "AWS_TOKEN"
"#,
    );

    let cfg = IntegrationRuntimeConfig {
        xdg_config_home: temp.path().to_path_buf(),
        exec_timeout: Duration::from_secs(5),
        kill_grace_period: Duration::from_millis(200),
    };
    let set = mint_profile(&cfg, "dev").await.expect("profile mint");
    assert_eq!(set.len(), 1);

    let outcomes = refresh_schedule_outcomes(&set, Duration::from_secs(3600));
    assert_eq!(outcomes.len(), 1);
}

#[test]
fn child_exit_code_passthrough() {
    let script = "/bin/sh";
    let args = vec!["-c".to_string(), "exit 42".to_string()];
    let env = HashMap::new();
    let code = run_child_and_pass_exit(script, &args, env).expect("child run");
    assert_eq!(code, 42);
}

#[tokio::test]
async fn provider_timeout_enforces_sigterm_then_sigkill() {
    let temp = TempDir::new().expect("tempdir");
    copy_mock_scripts(&temp);
    let hang = temp.path().join("bin/mint_hang_ignore_term.sh");
    let argv = vec![hang.display().to_string()];

    let result = execute_provider_with_timeout(
        &argv,
        Duration::from_millis(200),
        Duration::from_millis(100),
    )
    .await
    .expect("provider execution result");

    assert!(result.timed_out);
}

#[tokio::test]
async fn cross_module_error_propagation_end_to_end() {
    let temp = TempDir::new().expect("tempdir");
    copy_mock_scripts(&temp);
    let bin = temp.path().join("bin");
    let malformed_script = temp.path().join("bin/mint_malformed.sh");
    write_executable(
        &malformed_script,
        "#!/bin/sh\nset -eu\nprintf '{invalid json'\n",
    );

    write_provider_config(
        temp.path(),
        "aws",
        &malformed_script.display().to_string(),
        &bin.join("refresh_success.sh").display().to_string(),
        &bin.join("revoke_success.sh").display().to_string(),
        0o600,
    );

    let cfg = IntegrationRuntimeConfig {
        xdg_config_home: temp.path().to_path_buf(),
        exec_timeout: Duration::from_secs(5),
        kill_grace_period: Duration::from_millis(200),
    };

    let req = MintRequest {
        providers: vec!["aws".to_string()],
        role: "admin".to_string(),
        ttl_secs: 3600,
    };

    let err = atomic_mint(&cfg, &req, &ProviderOverrides::default())
        .await
        .expect_err("malformed provider output should fail");
    assert_eq!(err.kind(), ErrorKind::Provider);
    assert!(err.message().contains("output contract") || err.message().contains("invalid JSON"));
}

#[tokio::test]
async fn config_permission_rejection_with_real_filesystem() {
    let temp = TempDir::new().expect("tempdir");
    copy_mock_scripts(&temp);
    let bin = temp.path().join("bin");
    write_provider_config(
        temp.path(),
        "aws",
        &bin.join("mint_success.sh").display().to_string(),
        &bin.join("refresh_success.sh").display().to_string(),
        &bin.join("revoke_success.sh").display().to_string(),
        0o644,
    );

    let cfg = IntegrationRuntimeConfig {
        xdg_config_home: temp.path().to_path_buf(),
        exec_timeout: Duration::from_secs(5),
        kill_grace_period: Duration::from_millis(200),
    };

    let req = MintRequest {
        providers: vec!["aws".to_string()],
        role: "admin".to_string(),
        ttl_secs: 3600,
    };

    let err = atomic_mint(&cfg, &req, &ProviderOverrides::default())
        .await
        .expect_err("insecure provider config permissions should fail");
    assert_eq!(err.kind(), ErrorKind::Config);
}
