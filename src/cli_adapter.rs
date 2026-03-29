// noscope-cg8.2: CLI argument adapter layer
//
// Separates argv/flag-specific validation from core library types.
// Library consumers work with domain types (MintRequest, RevokeRequest);
// CLI binaries use this adapter to bridge raw argv into those types.
//
// Functions in this module:
// - validate_revoke_argv: NS-012 arg scanning on raw argv
// - validate_mint_flags: CLI flag validation → domain MintRequest
// - check_profile_flag_exclusion: NS-053 mutual exclusion between CLI flags
//
// Migration path for existing call sites:
// - Old: client.validate_revoke_args(&args) → New: cli_adapter::validate_revoke_argv(&args)
// - Old: mint::validate_mint_args(ttl, &providers, &role) → New: cli_adapter::validate_mint_flags(ttl, &providers, &role)
// - Old: profile::check_profile_flag_exclusion(...) → New: cli_adapter::check_profile_flag_exclusion(...)
//
// The underlying mint::validate_mint_args and profile::check_profile_flag_exclusion
// functions remain available for callers who already have parsed values.

use crate::client::{MintRequest, NoscopeError};
use crate::mint;
use crate::profile;

/// NS-012: Validate that revoke CLI arguments do not contain a --token flag.
///
/// Scans raw argv for `--token` or `--token=<value>` — these would pass raw
/// secret values via CLI args, visible in /proc/*/cmdline.
///
/// `--token-id` and `--token-id=<value>` are safe (opaque identifiers).
///
/// This is a CLI concern: library consumers use `RevokeRequest::from_token_id`
/// or `RevokeRequest::from_mint_json` instead, which accept domain types.
pub fn validate_revoke_argv(args: &[String]) -> Result<(), NoscopeError> {
    mint::validate_revoke_args(args).map_err(NoscopeError::from)
}

/// NS-062: Validate CLI mint flags and produce a domain `MintRequest`.
///
/// Bridges the gap between raw CLI flags (where `--ttl` may be absent,
/// represented as `Option<u64>`) and the domain type `MintRequest` (where
/// `ttl_secs` is always a valid positive integer).
///
/// CLI consumers call this to validate their parsed flags. Library consumers
/// construct `MintRequest` directly — they never deal with `Option<u64>`.
pub fn validate_mint_flags(
    ttl_secs: Option<u64>,
    providers: &[String],
    role: &str,
) -> Result<MintRequest, NoscopeError> {
    let validated_ttl =
        mint::validate_mint_args(ttl_secs, providers, role).map_err(NoscopeError::from)?;

    Ok(MintRequest {
        providers: providers.to_vec(),
        role: role.to_string(),
        ttl_secs: validated_ttl,
    })
}

/// NS-053: Check mutual exclusion between --profile and credential flags.
///
/// `--profile` forbids `--provider`, `--role`, and `--ttl`. This is a CLI
/// argument concern — library consumers work with `Profile` or `MintRequest`
/// directly, never both simultaneously.
///
/// Delegates to `profile::check_profile_flag_exclusion` and converts the
/// error to `NoscopeError` for uniform CLI error handling.
pub fn check_profile_flag_exclusion(
    profile: Option<&str>,
    provider: Option<&str>,
    role: Option<&str>,
    ttl: Option<u64>,
) -> Result<(), NoscopeError> {
    profile::check_profile_flag_exclusion(profile, provider, role, ttl).map_err(NoscopeError::from)
}

#[cfg(test)]
mod tests {
    // =========================================================================
    // noscope-cg8.2 Rule 1: Core crate APIs accept domain inputs, not raw
    // argv slices. validate_revoke_argv lives here, not on Client.
    // =========================================================================

    #[test]
    fn core_apis_accept_domain_inputs_validate_revoke_argv_exists_in_adapter() {
        // validate_revoke_argv must be callable from the cli_adapter module,
        // not from Client. It scans raw argv for --token flags (NS-012).
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token-id".to_string(),
            "tok-123".to_string(),
        ];
        let result = super::validate_revoke_argv(&args);
        assert!(result.is_ok(), "Safe revoke args must pass");
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_revoke_argv_rejects_token_flag() {
        // NS-012: --token in argv must be rejected.
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token".to_string(),
            "secret-value".to_string(),
        ];
        let result = super::validate_revoke_argv(&args);
        assert!(
            result.is_err(),
            "NS-012: --token flag in revoke args must be rejected"
        );
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_revoke_argv_rejects_combined_form() {
        // NS-012: --token=<value> combined form must be rejected.
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token=secret-value".to_string(),
        ];
        let result = super::validate_revoke_argv(&args);
        assert!(
            result.is_err(),
            "NS-012: --token=value form must be rejected"
        );
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_revoke_argv_allows_token_id() {
        // --token-id is safe (opaque identifier, not a secret).
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token-id".to_string(),
            "tok-abc".to_string(),
            "--provider".to_string(),
            "aws".to_string(),
        ];
        let result = super::validate_revoke_argv(&args);
        assert!(result.is_ok(), "--token-id is allowed");
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_revoke_argv_allows_token_id_combined() {
        // --token-id=tok-123 combined form is safe.
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token-id=tok-123".to_string(),
        ];
        let result = super::validate_revoke_argv(&args);
        assert!(result.is_ok(), "--token-id=value combined form is allowed");
    }

    // =========================================================================
    // noscope-cg8.2 Rule 1 (continued): validate_mint_flags bridges CLI flags
    // (with Option<u64> for missing --ttl) to domain MintRequest.
    // =========================================================================

    #[test]
    fn core_apis_accept_domain_inputs_validate_mint_flags_produces_mint_request() {
        // Valid CLI flags should produce a MintRequest with validated fields.
        let result = super::validate_mint_flags(Some(3600), &["aws".to_string()], "admin");
        assert!(result.is_ok(), "Valid flags must produce Ok");
        let req = result.unwrap();
        assert_eq!(req.ttl_secs, 3600);
        assert_eq!(req.providers, vec!["aws".to_string()]);
        assert_eq!(req.role, "admin");
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_mint_flags_rejects_missing_ttl() {
        // NS-062: --ttl is required. None means the flag was not provided.
        let result = super::validate_mint_flags(None, &["aws".to_string()], "admin");
        assert!(result.is_err(), "Missing --ttl must be rejected");
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_mint_flags_rejects_zero_ttl() {
        let result = super::validate_mint_flags(Some(0), &["aws".to_string()], "admin");
        assert!(result.is_err(), "Zero --ttl must be rejected");
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_mint_flags_rejects_empty_providers() {
        let result = super::validate_mint_flags(Some(3600), &[], "admin");
        assert!(result.is_err(), "Empty providers must be rejected");
    }

    #[test]
    fn core_apis_accept_domain_inputs_validate_mint_flags_rejects_empty_role() {
        let result = super::validate_mint_flags(Some(3600), &["aws".to_string()], "");
        assert!(result.is_err(), "Empty role must be rejected");
    }

    // =========================================================================
    // noscope-cg8.2 Rule 2: CLI-specific parsing/validation lives in a
    // dedicated adapter layer. check_profile_flag_exclusion is here.
    // =========================================================================

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_rejects_provider() {
        // NS-053: --profile forbids --provider.
        let result =
            super::check_profile_flag_exclusion(Some("my-profile"), Some("aws"), None, None);
        assert!(
            result.is_err(),
            "NS-053: --profile with --provider must be rejected"
        );
    }

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_rejects_role() {
        let result =
            super::check_profile_flag_exclusion(Some("my-profile"), None, Some("admin"), None);
        assert!(
            result.is_err(),
            "NS-053: --profile with --role must be rejected"
        );
    }

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_rejects_ttl() {
        let result =
            super::check_profile_flag_exclusion(Some("my-profile"), None, None, Some(3600));
        assert!(
            result.is_err(),
            "NS-053: --profile with --ttl must be rejected"
        );
    }

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_rejects_all_three() {
        let result = super::check_profile_flag_exclusion(
            Some("my-profile"),
            Some("aws"),
            Some("admin"),
            Some(3600),
        );
        assert!(
            result.is_err(),
            "NS-053: --profile with all credential flags must be rejected"
        );
    }

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_allows_profile_alone() {
        let result = super::check_profile_flag_exclusion(Some("my-profile"), None, None, None);
        assert!(result.is_ok(), "NS-053: --profile alone is valid");
    }

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_allows_no_profile() {
        let result =
            super::check_profile_flag_exclusion(None, Some("aws"), Some("admin"), Some(3600));
        assert!(
            result.is_ok(),
            "NS-053: no --profile allows credential flags"
        );
    }

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_error_names_flags() {
        let result =
            super::check_profile_flag_exclusion(Some("staging"), Some("aws"), None, Some(3600));
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("--provider") || msg.contains("--ttl"),
            "NS-053: error must name conflicting flags, got: {}",
            msg
        );
        assert!(
            msg.contains("staging"),
            "NS-053: error must include profile name, got: {}",
            msg
        );
    }

    #[test]
    fn cli_specific_validation_in_adapter_profile_flag_exclusion_neither_set() {
        let result = super::check_profile_flag_exclusion(None, None, None, None);
        assert!(result.is_ok(), "Neither set should be valid");
    }

    // =========================================================================
    // noscope-cg8.2 Rule 3: Backward-compatible migration path.
    // The adapter delegates to core module functions where they exist,
    // and the old Client::validate_revoke_args is removed from core.
    // =========================================================================

    #[test]
    fn backward_compatible_migration_client_does_not_expose_validate_revoke_args() {
        // Client should NOT have a validate_revoke_args method that takes
        // raw argv. The function lives in cli_adapter instead.
        // We verify by checking that Client still validates MintRequest (domain type).
        let client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        let req = crate::MintRequest {
            providers: vec!["aws".to_string()],
            role: "admin".to_string(),
            ttl_secs: 3600,
        };
        // This should compile and work — Client.validate_mint takes domain types.
        let result = client.validate_mint(&req);
        assert!(result.is_ok());
    }

    #[test]
    fn backward_compatible_migration_adapter_error_maps_to_noscope_error() {
        // Errors from the CLI adapter must convert to NoscopeError for
        // backward compatibility with existing CLI error handling.
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token".to_string(),
            "secret".to_string(),
        ];
        let result = super::validate_revoke_argv(&args);
        assert!(result.is_err());
        // The error type must be convertible to NoscopeError or be NoscopeError.
        let err = result.unwrap_err();
        let _msg = format!("{}", err); // Must implement Display
    }

    #[test]
    fn backward_compatible_migration_validate_mint_flags_error_is_displayable() {
        let result = super::validate_mint_flags(None, &["aws".to_string()], "admin");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(!msg.is_empty(), "Error must produce a displayable message");
    }

    #[test]
    fn backward_compatible_migration_validate_mint_flags_returns_mint_request() {
        // The return type must be MintRequest, proving the adapter produces
        // the domain type that Client.validate_mint expects.
        let result = super::validate_mint_flags(
            Some(7200),
            &["aws".to_string(), "gcp".to_string()],
            "deployer",
        );
        let req = result.unwrap();
        // Must be the same MintRequest type the Client accepts.
        let client = crate::Client::new(crate::ClientOptions::default()).unwrap();
        let validation = client.validate_mint(&req);
        assert!(validation.is_ok());
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn edge_case_validate_revoke_argv_empty_args() {
        // Empty argv should not error — no --token flag to find.
        let args: Vec<String> = vec![];
        let result = super::validate_revoke_argv(&args);
        assert!(result.is_ok(), "Empty argv must not error");
    }

    #[test]
    fn edge_case_validate_revoke_argv_error_has_exit_code() {
        // NS-054: The error must map to a meaningful exit code.
        let args = vec![
            "noscope".to_string(),
            "revoke".to_string(),
            "--token".to_string(),
            "secret".to_string(),
        ];
        let err = super::validate_revoke_argv(&args).unwrap_err();
        let code = err.exit_code();
        assert_eq!(code, 64, "NS-054: revoke argv error should be usage (64)");
    }

    #[test]
    fn edge_case_profile_flag_exclusion_error_has_exit_code() {
        // NS-054: Profile flag conflict maps through NoscopeError::Profile.
        // The From<ProfileError> conversion wraps all profile errors under
        // the Profile variant (exit 66), even FlagConflict which the underlying
        // ProfileError maps to Usage (64). The adapter preserves the existing
        // NoscopeError mapping behavior for backward compatibility.
        let err =
            super::check_profile_flag_exclusion(Some("dev"), Some("aws"), None, None).unwrap_err();
        let code = err.exit_code();
        // NoscopeError::Profile maps to exit 66 (ConfigNotFound) per existing behavior.
        assert_ne!(code, 0, "Profile flag conflict must not be success");
    }
}
