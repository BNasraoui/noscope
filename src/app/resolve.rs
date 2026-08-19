// The single spec-resolution path.
// Turns CLI input (direct flags or a profile name) into validated
// CredentialSpecs plus the resolved provider for each spec. Every
// credential passes the same validation regardless of where it came
// from: TTL bounds, role character set, and
// env-key uniqueness. Profiles previously bypassed the TTL
// and role checks; they no longer do.

use std::collections::HashMap;
use std::path::Path;

use crate::app::client::{Client, MintRequest, ProviderOverrides};
use crate::core::credential_set::{validate_credential_specs, CredentialSpec};
use crate::core::error::Error;
use crate::ports::profile;
use crate::ports::provider::ResolvedProvider;

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
mod tests;
