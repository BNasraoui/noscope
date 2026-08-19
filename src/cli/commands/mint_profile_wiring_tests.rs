use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn write_provider_config(xdg: &Path, provider: &str, mint_cmd: &str) {
    let dir = xdg.join("noscope").join("providers");
    fs::create_dir_all(&dir).unwrap();
    let cfg = format!(
        "contract_version = 1\n\n[commands]\nmint = \"{}\"\n",
        mint_cmd
    );
    let path = dir.join(format!("{}.toml", provider));
    fs::write(&path, cfg).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn scoped_env<T>(key: &str, value: &Path, f: impl FnOnce() -> T) -> T {
    let old = std::env::var_os(key);
    // SAFETY: test-local env mutation, restored before return.
    unsafe {
        std::env::set_var(key, value);
    }
    let out = f();
    match old {
        Some(prev) => unsafe { std::env::set_var(key, prev) },
        None => unsafe { std::env::remove_var(key) },
    }
    out
}

#[test]
fn cmd_mint_with_profile_mints_from_profile_credentials() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_dir = tmp.path().join("noscope").join("profiles");
    fs::create_dir_all(&profile_dir).unwrap();

    let mint_script = tmp.path().join("mint.sh");
    write_executable(
        &mint_script,
        "#!/bin/sh\nprintf '{\"token\":\"profile-mint-secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );

    write_provider_config(tmp.path(), "aws", mint_script.to_string_lossy().as_ref());

    let profile_toml = "[[credentials]]\nprovider = \"aws\"\nrole = \"profile-role\"\nttl = 3600\n";
    fs::write(profile_dir.join("dev.toml"), profile_toml).unwrap();
    fs::set_permissions(
        profile_dir.join("dev.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let args = cli::MintArgs {
        provider: vec![],
        role: None,
        ttl: None,
        profile: Some("dev".to_string()),
        force_terminal: true,
    };

    let result = scoped_env("XDG_CONFIG_HOME", tmp.path(), || cmd_mint(args, false));
    assert!(
        result.is_ok(),
        "cmd_mint --profile must succeed: {:?}",
        result.err()
    );
}

#[test]
fn cmd_mint_without_profile_still_requires_provider_role_ttl() {
    let args = cli::MintArgs {
        provider: vec!["nonexistent-provider".to_string()],
        role: Some("admin".to_string()),
        ttl: Some(3600),
        profile: None,
        force_terminal: true,
    };

    let result = cmd_mint(args, false);
    assert!(
        result.is_err(),
        "cmd_mint without profile must still resolve providers"
    );
}
