// The single mint execution path.
// (atomic mint), (per-provider timeout), (bounded
// parallelism). Both `noscope run` and `noscope mint` call `mint_all`;
// there is exactly one closure that turns a CredentialSpec into a
// provider invocation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::command_parse::parse_command;
use crate::credential_set::{
    CredentialSet, CredentialSetError, CredentialSpec, MintConfig, MintFailure, MintResult,
};
use crate::orchestrator;
use crate::provider::ResolvedProvider;
use crate::provider_exec::{self, ExecConfig};
use crate::token_convert::provider_output_to_scoped_token;

/// Execution knobs for a mint run.
pub struct MintOptions {
    /// Per-provider timeout.
    pub per_provider_timeout: Duration,
    /// Grace period after SIGTERM before SIGKILL.
    pub kill_grace_period: Duration,
    /// Maximum concurrent provider operations.
    pub max_concurrent: usize,
}

impl Default for MintOptions {
    fn default() -> Self {
        Self {
            per_provider_timeout: Duration::from_secs(30),
            kill_grace_period: Duration::from_secs(5),
            max_concurrent: 8,
        }
    }
}

/// Format the operator-facing message for a failed atomic mint.
pub fn format_mint_failed_providers(failures: &[MintFailure]) -> String {
    let details = failures
        .iter()
        .map(|failure| format!("provider '{}': {}", failure.provider, failure.error))
        .collect::<Vec<_>>()
        .join("; ");
    format!("credential minting failed: {}", details)
}

/// Mint one credential by invoking the provider's mint command.
pub async fn mint_one(
    provider: &ResolvedProvider,
    spec: &CredentialSpec,
    exec: &ExecConfig,
) -> MintResult {
    let spec_for_result =
        CredentialSpec::new(&spec.provider, &spec.role, spec.ttl_secs, &spec.env_key);

    let argv = parse_command(&provider.mint_cmd);
    if argv.is_empty() {
        return MintResult::Failure {
            spec: spec_for_result,
            error: "empty mint command".to_string(),
        };
    }

    let mut env = provider.env.clone();
    env.insert("NOSCOPE_PROVIDER".to_string(), provider.name.clone());
    env.insert("NOSCOPE_ROLE".to_string(), spec.role.clone());
    let rendered_argv = provider_exec::substitute_template_vars(&argv, &spec.role, spec.ttl_secs);

    match provider_exec::execute_provider_command(&rendered_argv, &env, exec, spec.ttl_secs).await {
        Ok(exec_result) => match exec_result.parsed_output {
            Ok(output) => {
                let token = provider_output_to_scoped_token(
                    output,
                    &spec.role,
                    Some(format!("tok-{}", provider.name)),
                    &provider.name,
                );
                MintResult::Success {
                    spec: spec_for_result,
                    token,
                }
            }
            Err(err) => MintResult::Failure {
                spec: spec_for_result,
                error: err.to_string(),
            },
        },
        Err(err) => MintResult::Failure {
            spec: spec_for_result,
            error: format!("spawn failed: {}", err),
        },
    }
}

/// Mint every spec atomically with bounded parallelism.
/// Every spec's provider must be present in `resolved_by_name`.
pub async fn mint_all(
    specs: &[CredentialSpec],
    resolved_by_name: &Arc<HashMap<String, ResolvedProvider>>,
    opts: &MintOptions,
) -> Result<CredentialSet, CredentialSetError> {
    let config = MintConfig::new(opts.per_provider_timeout, opts.max_concurrent)?;
    let timeout = opts.per_provider_timeout;
    let kill_grace_period = opts.kill_grace_period;
    let resolved = Arc::clone(resolved_by_name);

    orchestrator::mint_all(specs, &config, move |spec| {
        let resolved = Arc::clone(&resolved);
        let spec = CredentialSpec::new(&spec.provider, &spec.role, spec.ttl_secs, &spec.env_key);
        async move {
            let provider = resolved
                .get(&spec.provider)
                .expect("resolved provider must exist for every credential spec");
            let exec = ExecConfig {
                timeout,
                kill_grace_period,
            };
            mint_one(provider, &spec, &exec).await
        }
    })
    .await
}
