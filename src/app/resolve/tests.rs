use provenance_macros::verifies;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;
use crate::app::client::ClientOptions;
use crate::ports::provider::ProviderEnv;

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

fn write_profile(xdg: &Path, name: &str, toml: &str) {
    let dir = xdg.join("noscope").join("profiles");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.toml", name));
    fs::write(&path, toml).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn client_for(xdg: &Path) -> Client {
    Client::new(ClientOptions {
        xdg_config_home: Some(xdg.to_path_buf()),
        provider_env: Some(ProviderEnv::empty()),
        ..ClientOptions::default()
    })
    .unwrap()
}

fn resolve_profile(
    xdg: &Path,
    name: &str,
) -> Result<(Vec<CredentialSpec>, HashMap<String, ResolvedProvider>), Error> {
    let client = client_for(xdg);
    let source = CredentialSource::Profile {
        name: name.to_string(),
    };
    resolve_specs_and_providers(&client, &source, Some(xdg))
}

fn write_aws_provider(xdg: &Path) {
    let mint_script = xdg.join("mint.sh");
    write_executable(
        &mint_script,
        "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
    );
    write_provider_config(xdg, "aws", mint_script.to_string_lossy().as_ref());
}

#[test]
fn profile_resolves_single_credential() {
    let tmp = tempfile::tempdir().unwrap();
    write_aws_provider(tmp.path());
    write_profile(
        tmp.path(),
        "dev",
        "[[credentials]]\nprovider = \"aws\"\nrole = \"admin\"\nttl = 3600\n",
    );

    let (specs, resolved) = resolve_profile(tmp.path(), "dev").unwrap();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].provider, "aws");
    assert_eq!(specs[0].role, "admin");
    assert_eq!(specs[0].ttl_secs, 3600);
    assert!(resolved.contains_key("aws"));
}

#[test]
fn profile_generates_default_env_key_from_provider_and_index() {
    let tmp = tempfile::tempdir().unwrap();
    write_aws_provider(tmp.path());
    write_profile(
        tmp.path(),
        "dev",
        "[[credentials]]\nprovider = \"aws\"\nrole = \"admin\"\nttl = 3600\n",
    );

    let (specs, _) = resolve_profile(tmp.path(), "dev").unwrap();
    assert_eq!(
        specs[0].env_key, "AWS_TOKEN_0",
        "default env_key must be {{PROVIDER}}_TOKEN_{{idx}}"
    );
}

#[test]
fn profile_uses_explicit_env_key_when_specified() {
    let tmp = tempfile::tempdir().unwrap();
    write_aws_provider(tmp.path());
    write_profile(
        tmp.path(),
        "dev",
        "[[credentials]]\nprovider = \"aws\"\nrole = \"admin\"\nttl = 3600\nenv_key = \"MY_CUSTOM_TOKEN\"\n",
    );

    let (specs, _) = resolve_profile(tmp.path(), "dev").unwrap();
    assert_eq!(specs[0].env_key, "MY_CUSTOM_TOKEN");
}

#[test]
fn profile_resolves_multi_credential_with_provider_dedup() {
    let tmp = tempfile::tempdir().unwrap();
    write_aws_provider(tmp.path());
    write_profile(
        tmp.path(),
        "multi",
        "[[credentials]]\nprovider = \"aws\"\nrole = \"admin\"\nttl = 3600\n\n\
         [[credentials]]\nprovider = \"aws\"\nrole = \"readonly\"\nttl = 1800\n",
    );

    let (specs, resolved) = resolve_profile(tmp.path(), "multi").unwrap();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].env_key, "AWS_TOKEN_0");
    assert_eq!(specs[1].env_key, "AWS_TOKEN_1");
    assert_eq!(
        resolved.len(),
        1,
        "same provider used twice must be deduped in resolved map"
    );
}

#[test]
fn profile_fails_for_nonexistent_provider() {
    let tmp = tempfile::tempdir().unwrap();
    write_profile(
        tmp.path(),
        "bad",
        "[[credentials]]\nprovider = \"nonexistent\"\nrole = \"admin\"\nttl = 3600\n",
    );

    assert!(resolve_profile(tmp.path(), "bad").is_err());
}

#[test]
fn profile_fails_for_missing_profile() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(resolve_profile(tmp.path(), "nonexistent").is_err());
}

// profile credentials pass the same role validation as flags.
#[test]
#[verifies("rule_role_charset", examples)]
fn profile_rejects_role_with_shell_metacharacters() {
    let tmp = tempfile::tempdir().unwrap();
    write_aws_provider(tmp.path());
    write_profile(
        tmp.path(),
        "evil",
        "[[credentials]]\nprovider = \"aws\"\nrole = \"admin;whoami\"\nttl = 3600\n",
    );

    assert!(
        resolve_profile(tmp.path(), "evil").is_err(),
        "role with shell metacharacters must be rejected via profiles too"
    );
}

// profile credentials pass the same TTL bounds as flags.
#[test]
#[verifies("rule_ttl_bounds", examples)]
fn profile_rejects_out_of_bounds_ttl() {
    let tmp = tempfile::tempdir().unwrap();
    write_aws_provider(tmp.path());
    write_profile(
        tmp.path(),
        "shortttl",
        "[[credentials]]\nprovider = \"aws\"\nrole = \"admin\"\nttl = 1\n",
    );

    assert!(
        resolve_profile(tmp.path(), "shortttl").is_err(),
        "TTL below the minimum bound must be rejected via profiles too"
    );
}

// duplicate env keys are rejected on every path.
#[test]
fn profile_rejects_duplicate_env_keys() {
    let tmp = tempfile::tempdir().unwrap();
    write_aws_provider(tmp.path());
    write_profile(
        tmp.path(),
        "dup",
        "[[credentials]]\nprovider = \"aws\"\nrole = \"admin\"\nttl = 3600\nenv_key = \"SAME\"\n\n\
         [[credentials]]\nprovider = \"aws\"\nrole = \"readonly\"\nttl = 1800\nenv_key = \"SAME\"\n",
    );

    assert!(
        resolve_profile(tmp.path(), "dup").is_err(),
        "duplicate env keys must be rejected"
    );
}
