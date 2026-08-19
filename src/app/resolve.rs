// The single spec-resolution path.
// Turns CLI input (direct flags or a profile name) into validated
// CredentialSpecs plus the resolved provider for each spec. Every
// credential passes the same validation regardless of where it came
// from: TTL bounds, role character set, and
// env-key uniqueness. Profiles previously bypassed the TTL
// and role checks; they no longer do.

use std::collections::HashMap;
use std::path::Path;

use crate::client::{Client, MintRequest, ProviderOverrides};
use crate::credential_set::{validate_credential_specs, CredentialSpec};
use crate::error::Error;
use crate::profile;
use crate::provider::ResolvedProvider;

/// Where the credential specs come from.
pub enum CredentialSource {
    Direct {
        providers: Vec<String>,
        role: String,
        ttl_secs: u64,
    },
    Profile {
        name: String,
    },
}

impl CredentialSource {
    /// Build a source from CLI arguments.
    /// Clap guarantees provider/role/ttl are present when --profile is
    /// absent, so missing values with no profile are a usage error.
    pub fn from_cli(
        profile: Option<String>,
        providers: Vec<String>,
        role: Option<String>,
        ttl: Option<u64>,
    ) -> Result<Self, Error> {
        if let Some(name) = profile {
            return Ok(Self::Profile { name });
        }
        let role = role.ok_or_else(|| Error::usage("--role is required without --profile"))?;
        let ttl_secs = ttl.ok_or_else(|| Error::usage("--ttl is required without --profile"))?;
        Ok(Self::Direct {
            providers,
            role,
            ttl_secs,
        })
    }
}

/// Resolve a credential source into validated specs and their providers.
pub fn resolve_specs_and_providers(
    client: &Client,
    source: &CredentialSource,
    xdg_config_home: Option<&Path>,
) -> Result<(Vec<CredentialSpec>, HashMap<String, ResolvedProvider>), Error> {
    let (specs, resolved_by_name) = match source {
        CredentialSource::Direct {
            providers,
            role,
            ttl_secs,
        } => {
            let req = MintRequest {
                providers: providers.clone(),
                role: role.clone(),
                ttl_secs: *ttl_secs,
            };
            client.validate_mint(&req)?;

            let mut resolved_by_name = HashMap::new();
            let mut specs = Vec::with_capacity(providers.len());
            for provider_name in providers {
                let resolved =
                    client.resolve_provider(provider_name, &ProviderOverrides::default())?;
                specs.push(CredentialSpec::new(
                    provider_name,
                    role,
                    *ttl_secs,
                    &format!("{}_TOKEN", provider_name.to_uppercase()),
                ));
                resolved_by_name.insert(provider_name.clone(), resolved);
            }
            (specs, resolved_by_name)
        }
        CredentialSource::Profile { name } => {
            let path = profile::profile_config_path(name, xdg_config_home)?;
            let prof = profile::load_profile(&path)?;

            let mut specs = Vec::with_capacity(prof.credentials.len());
            let mut resolved_by_name = HashMap::new();
            for (idx, cred) in prof.credentials.iter().enumerate() {
                // profile credentials pass the same
                // validation as direct flags.
                client.validate_mint(&MintRequest {
                    providers: vec![cred.provider.clone()],
                    role: cred.role.clone(),
                    ttl_secs: cred.ttl,
                })?;

                let resolved =
                    client.resolve_provider(&cred.provider, &ProviderOverrides::default())?;
                let env_key = cred
                    .env_key
                    .clone()
                    .unwrap_or_else(|| format!("{}_TOKEN_{}", cred.provider.to_uppercase(), idx));
                specs.push(CredentialSpec::new(
                    &cred.provider,
                    &cred.role,
                    cred.ttl,
                    &env_key,
                ));
                resolved_by_name
                    .entry(cred.provider.clone())
                    .or_insert(resolved);
            }
            (specs, resolved_by_name)
        }
    };

    // env keys must be unique across the whole set.
    validate_credential_specs(&specs)?;

    Ok((specs, resolved_by_name))
}

#[cfg(test)]
mod tests {
    use provenance_macros::verifies;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::client::ClientOptions;
    use crate::provider::ProviderEnv;

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
}
