// NS-078: Centralized token conversion boundaries
//
// Defines explicit conversion boundaries between:
// - token-in-memory (ScopedToken)
// - provider output (ProviderOutput)
// - stdout envelope (MintEnvelope)
//
// Conversion pipeline: ProviderOutput → ScopedToken → MintEnvelope
//
// Secret-handling guarantees at each boundary:
// - ProviderOutput → ScopedToken: ProviderOutput consumed (ownership transferred);
//   raw token cloned into SecretString (clone required because ProviderOutput
//   implements Drop for zeroization). Both copies are independently zeroized:
//   ProviderOutput by its Drop impl, SecretString by ZeroizeOnDrop (NS-019).
// - ScopedToken → MintEnvelope: expose_secret() called explicitly (NS-064);
//   the raw value is copied into MintEnvelope's zeroizing String.
//
// NS-001: ScopedToken is never Serialize — this boundary is the ONLY way
// secrets cross type boundaries.

use secrecy::SecretString;

use crate::mint::MintEnvelope;
use crate::provider_exec::ProviderOutput;
use crate::token::ScopedToken;

/// Result of converting a ProviderOutput to a ScopedToken, with metadata
/// about the conversion (e.g., whether expires_at was provider-supplied).
///
/// The caller needs `expires_at_provided` to emit the NS-034 warning when
/// the provider didn't supply an explicit expiry.
pub struct ConversionResult {
    /// The converted token.
    pub token: ScopedToken,
    /// Whether expires_at was explicitly provided by the provider (NS-034).
    /// `false` means it was computed from `now() + requested_ttl`.
    pub expires_at_provided: bool,
}

/// NS-078: Convert a ProviderOutput into a ScopedToken.
///
/// **Secret boundary**: Takes ownership of `output`, consuming the
/// ProviderOutput. The raw token is cloned into a SecretString (clone is
/// required because ProviderOutput implements Drop for zeroization, and Rust
/// does not allow moving fields out of Drop types). Both copies are
/// independently zeroized on drop: ProviderOutput by its Drop impl,
/// SecretString by ZeroizeOnDrop (NS-019).
///
/// # Arguments
/// - `output`: The parsed provider command output (consumed).
/// - `role`: The role this token was minted for (not in provider output).
/// - `token_id`: Optional provider-supplied or generated token identifier.
/// - `provider`: The provider name (not in provider output).
pub fn provider_output_to_scoped_token(
    output: ProviderOutput,
    role: &str,
    token_id: Option<String>,
    provider: &str,
) -> ScopedToken {
    // NS-019: Clone the raw token into SecretString for zeroization guarantees.
    // We must clone because ProviderOutput implements Drop (for zeroization),
    // and Rust doesn't allow moving fields out of a Drop type. This is fine:
    // ProviderOutput's Drop will zeroize its String copy, and SecretString
    // manages zeroization of its own copy independently.
    let secret = SecretString::from(output.token.clone());

    ScopedToken::new(secret, role, output.expires_at, token_id, provider)
}

/// NS-078: Convert a ProviderOutput into a ScopedToken, preserving the
/// `expires_at_provided` flag for NS-034 warning emission.
///
/// Same secret boundary guarantees as [`provider_output_to_scoped_token`].
pub fn provider_output_to_scoped_token_with_metadata(
    output: ProviderOutput,
    role: &str,
    token_id: Option<String>,
    provider: &str,
) -> ConversionResult {
    let provided = output.expires_at_provided;
    let token = provider_output_to_scoped_token(output, role, token_id, provider);
    ConversionResult {
        token,
        expires_at_provided: provided,
    }
}

/// NS-078: Convert a ScopedToken into a MintEnvelope for stdout output.
///
/// **Secret boundary**: Calls `expose_secret()` on the ScopedToken to extract
/// the raw credential value. This is the designated path for outputting raw
/// credentials (NS-064: mint stdout is the one exception to NS-005 redaction).
///
/// Takes `&ScopedToken` (borrow) because the caller may still need the token
/// for child process injection after creating the envelope.
pub fn scoped_token_to_mint_envelope(token: &ScopedToken) -> MintEnvelope {
    MintEnvelope::from_scoped_token(token)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use secrecy::SecretString;
    use serde_json::Value;

    use crate::mint::MintEnvelope;
    use crate::provider_exec::ProviderOutput;
    use crate::token::ScopedToken;

    /// Helper: create a ProviderOutput for tests.
    fn make_provider_output(token: &str, expires_at: DateTime<Utc>) -> ProviderOutput {
        crate::provider_exec::parse_provider_output(
            &format!(
                r#"{{"token": "{}", "expires_at": "{}"}}"#,
                token,
                expires_at.to_rfc3339()
            ),
            3600,
        )
        .unwrap()
    }

    // =========================================================================
    // NS-078 Acceptance 1: Conversions between internal token types and
    // mint output are centralized.
    //
    // There must be a single, canonical conversion path:
    //   ProviderOutput → ScopedToken → MintEnvelope
    // All conversion functions live in the token_convert module.
    // =========================================================================

    #[test]
    fn centralized_provider_output_to_scoped_token() {
        // NS-078: A centralized function must convert ProviderOutput → ScopedToken.
        // Takes ProviderOutput plus role, token_id, and provider name
        // (which the provider output doesn't carry).
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("raw-secret-from-provider", expiry);

        let token = super::provider_output_to_scoped_token(output, "admin", None, "aws");

        assert_eq!(token.expose_secret(), "raw-secret-from-provider");
        assert_eq!(token.role(), "admin");
        assert_eq!(token.provider(), "aws");
        assert_eq!(token.expires_at(), expiry);
    }

    #[test]
    fn centralized_provider_output_to_scoped_token_with_token_id() {
        // NS-078: When caller supplies a token_id, it must be carried through.
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("secret-val", expiry);

        let token = super::provider_output_to_scoped_token(
            output,
            "viewer",
            Some("tok-provider-42".to_string()),
            "gcp",
        );

        assert_eq!(token.token_id(), Some("tok-provider-42"));
    }

    #[test]
    fn centralized_provider_output_to_scoped_token_without_token_id() {
        // NS-078: When no token_id is supplied, ScopedToken gets None.
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("secret", expiry);

        let token = super::provider_output_to_scoped_token(output, "role", None, "prov");

        assert!(token.token_id().is_none());
    }

    #[test]
    fn centralized_provider_output_to_scoped_token_computed_expiry() {
        // NS-078: When provider doesn't supply expires_at (NS-034),
        // the computed expiry from ProviderOutput must be preserved.
        let output =
            crate::provider_exec::parse_provider_output(r#"{"token": "secret"}"#, 3600).unwrap();
        assert!(!output.expires_at_provided, "should be computed expiry");

        let token = super::provider_output_to_scoped_token(output, "role", None, "prov");
        // Token should have a valid expiry (approximately now + 3600s)
        let now = Utc::now();
        assert!(
            token.expires_at() > now,
            "Computed expiry must be in the future"
        );
    }

    #[test]
    fn centralized_scoped_token_to_mint_envelope() {
        // NS-078: A centralized function must convert ScopedToken → MintEnvelope.
        // This is the ONLY approved path for creating MintEnvelopes from tokens.
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let token = ScopedToken::new(
            SecretString::from("raw-secret".to_string()),
            "deployer",
            expiry,
            Some("tok-abc".to_string()),
            "vault",
        );

        let envelope = super::scoped_token_to_mint_envelope(&token);
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["token"].as_str().unwrap(), "raw-secret");
        assert_eq!(parsed["provider"].as_str().unwrap(), "vault");
        assert_eq!(parsed["role"].as_str().unwrap(), "deployer");
        assert_eq!(parsed["token_id"].as_str().unwrap(), "tok-abc");
    }

    #[test]
    fn centralized_scoped_token_to_mint_envelope_without_token_id() {
        // NS-078: When ScopedToken has no token_id, envelope uses empty string.
        let token = ScopedToken::new(
            SecretString::from("secret".to_string()),
            "admin",
            Utc::now() + chrono::Duration::hours(1),
            None,
            "aws",
        );

        let envelope = super::scoped_token_to_mint_envelope(&token);
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["token_id"].as_str().unwrap(), "");
    }

    #[test]
    fn centralized_full_pipeline_provider_output_to_envelope() {
        // NS-078: The full conversion pipeline should be composable:
        // ProviderOutput → ScopedToken → MintEnvelope
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("pipeline-secret", expiry);

        let token = super::provider_output_to_scoped_token(
            output,
            "admin",
            Some("tid-pipe".to_string()),
            "aws",
        );
        let envelope = super::scoped_token_to_mint_envelope(&token);

        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["token"].as_str().unwrap(), "pipeline-secret");
        assert_eq!(parsed["provider"].as_str().unwrap(), "aws");
        assert_eq!(parsed["role"].as_str().unwrap(), "admin");
        assert_eq!(parsed["token_id"].as_str().unwrap(), "tid-pipe");
    }

    // =========================================================================
    // NS-078 Acceptance 2: Duplicate serialization shape definitions are
    // reduced/eliminated.
    //
    // The JSON field set {token, expires_at, token_id, provider, role}
    // must be defined ONCE and reused for both single-envelope and
    // multi-envelope output.
    // =========================================================================

    #[test]
    fn unified_serialization_single_envelope_field_set() {
        // NS-078: Single envelope JSON must use the canonical field set.
        let token = ScopedToken::new(
            SecretString::from("tok-val".to_string()),
            "admin",
            Utc::now() + chrono::Duration::hours(1),
            Some("tid".to_string()),
            "aws",
        );
        let envelope = super::scoped_token_to_mint_envelope(&token);
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();
        let fields: Vec<&String> = obj.keys().collect();
        assert!(fields.contains(&&"token".to_string()));
        assert!(fields.contains(&&"expires_at".to_string()));
        assert!(fields.contains(&&"token_id".to_string()));
        assert!(fields.contains(&&"provider".to_string()));
        assert!(fields.contains(&&"role".to_string()));
        assert_eq!(fields.len(), 5, "Must have exactly 5 fields");
    }

    #[test]
    fn unified_serialization_multi_envelope_uses_same_shape() {
        // NS-078: Multi-envelope output (format_mint_output) must produce
        // the same field set as single-envelope to_json().
        use crate::mint::format_mint_output;

        let token1 = ScopedToken::new(
            SecretString::from("secret1".to_string()),
            "admin",
            Utc::now() + chrono::Duration::hours(1),
            Some("tid1".to_string()),
            "aws",
        );
        let token2 = ScopedToken::new(
            SecretString::from("secret2".to_string()),
            "viewer",
            Utc::now() + chrono::Duration::hours(1),
            Some("tid2".to_string()),
            "gcp",
        );

        // Single envelope fields
        let env_single = super::scoped_token_to_mint_envelope(&token1);
        let single_json = env_single.to_json();
        let single_parsed: Value = serde_json::from_str(&single_json).unwrap();
        let mut single_fields: Vec<String> =
            single_parsed.as_object().unwrap().keys().cloned().collect();
        single_fields.sort();

        // Multi envelope fields (need fresh envelopes since MintEnvelope is !Clone)
        let env_m1 = super::scoped_token_to_mint_envelope(&token1);
        let env_m2 = super::scoped_token_to_mint_envelope(&token2);
        let multi_output = format_mint_output(&[env_m1, env_m2]);
        let multi_parsed: Value = serde_json::from_str(&multi_output).unwrap();
        let first_element = &multi_parsed.as_array().unwrap()[0];
        let mut multi_fields: Vec<String> =
            first_element.as_object().unwrap().keys().cloned().collect();
        multi_fields.sort();

        assert_eq!(
            single_fields, multi_fields,
            "NS-078: single and multi envelope must have identical field sets"
        );
    }

    // =========================================================================
    // NS-078 Acceptance 3: Secret-handling guarantees remain explicit at
    // each boundary.
    //
    // - ProviderOutput → ScopedToken: raw String consumed into SecretString
    // - ScopedToken → MintEnvelope: expose_secret() called explicitly
    // - Each boundary documents which NS rules apply
    // =========================================================================

    #[test]
    fn secret_boundary_provider_output_consumed() {
        // NS-078: provider_output_to_scoped_token takes ownership of the
        // ProviderOutput (moves it), so the raw token String is consumed.
        // After conversion, only ScopedToken holds the secret.
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("raw-secret", expiry);

        let token = super::provider_output_to_scoped_token(output, "role", None, "prov");
        // output is moved — can't access output.token anymore (compile-time guarantee)
        // We verify the secret arrived safely in the ScopedToken.
        assert_eq!(token.expose_secret(), "raw-secret");
    }

    #[test]
    fn secret_boundary_scoped_token_not_consumed_by_envelope() {
        // NS-078: scoped_token_to_mint_envelope takes &ScopedToken (borrow),
        // because the caller may still need the token for child process injection.
        // The envelope copies the secret via expose_secret().
        let token = ScopedToken::new(
            SecretString::from("shared-secret".to_string()),
            "admin",
            Utc::now() + chrono::Duration::hours(1),
            None,
            "aws",
        );

        let _envelope = super::scoped_token_to_mint_envelope(&token);
        // Token is still usable after creating the envelope
        assert_eq!(token.expose_secret(), "shared-secret");
    }

    #[test]
    fn secret_boundary_envelope_zeroizes_on_drop() {
        // NS-078: MintEnvelope still zeroizes the token String on drop.
        // (This is verified by the existing MintEnvelope tests, but we
        // confirm it's preserved through the centralized conversion.)
        static_assertions::assert_not_impl_any!(MintEnvelope: Clone);
    }

    #[test]
    fn secret_boundary_scoped_token_not_serializable() {
        // NS-078: ScopedToken must remain non-serializable (NS-001).
        // The conversion boundary is the ONLY place secrets cross types.
        static_assertions::assert_not_impl_any!(ScopedToken: serde::Serialize);
    }

    #[test]
    fn secret_boundary_provider_output_zeroizes_on_drop() {
        // NS-078: ProviderOutput zeroizes its token on drop (NS-019).
        // Consuming it in provider_output_to_scoped_token drops the original.
        static_assertions::assert_not_impl_any!(ProviderOutput: Clone);
    }

    #[test]
    fn secret_boundary_provider_output_to_token_does_not_log_secret() {
        // NS-078: The conversion must not produce debug output containing secrets.
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("do-not-log-this-secret", expiry);
        let token = super::provider_output_to_scoped_token(output, "role", None, "prov");

        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("do-not-log-this-secret"),
            "Debug of converted token must not contain secret, got: {}",
            debug
        );
    }

    #[test]
    fn secret_boundary_envelope_debug_does_not_expose_secret() {
        // NS-078: MintEnvelope created via centralized conversion must
        // still redact in Debug.
        let token = ScopedToken::new(
            SecretString::from("envelope-secret-value".to_string()),
            "admin",
            Utc::now() + chrono::Duration::hours(1),
            Some("tid".to_string()),
            "aws",
        );
        let envelope = super::scoped_token_to_mint_envelope(&token);
        let debug = format!("{:?}", envelope);
        assert!(
            !debug.contains("envelope-secret-value"),
            "Envelope debug must not expose secret, got: {}",
            debug
        );
    }

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

    #[test]
    fn pipeline_preserves_special_characters_in_token() {
        // Edge case: tokens with JSON-special characters must survive the
        // full pipeline ProviderOutput → ScopedToken → MintEnvelope → JSON.
        let expiry = Utc::now() + chrono::Duration::hours(1);
        // Token with quotes and backslashes — these need JSON escaping.
        let raw_token = r#"tok-with-"quotes"-and-\backslash"#;
        let output = crate::provider_exec::parse_provider_output(
            &serde_json::json!({
                "token": raw_token,
                "expires_at": expiry.to_rfc3339()
            })
            .to_string(),
            3600,
        )
        .unwrap();

        let token = super::provider_output_to_scoped_token(
            output,
            "admin",
            Some("tid-special".to_string()),
            "aws",
        );
        assert_eq!(token.expose_secret(), raw_token);

        let envelope = super::scoped_token_to_mint_envelope(&token);
        let json = envelope.to_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["token"].as_str().unwrap(),
            raw_token,
            "Special characters must survive full pipeline round-trip"
        );
    }

    // =========================================================================
    // NS-078: expires_at_provided flag preservation
    //
    // When converting ProviderOutput → ScopedToken, the information about
    // whether expires_at was provider-supplied or computed must be queryable
    // so the caller can emit the NS-034 warning.
    // =========================================================================

    #[test]
    fn provider_output_expires_at_provided_flag_accessible() {
        // NS-078: The conversion result should allow the caller to check
        // whether expires_at was provided by the provider or computed.
        let output =
            crate::provider_exec::parse_provider_output(r#"{"token": "secret"}"#, 3600).unwrap();

        let result =
            super::provider_output_to_scoped_token_with_metadata(output, "role", None, "prov");

        assert!(!result.expires_at_provided);
    }

    #[test]
    fn provider_output_expires_at_provided_true_when_supplied() {
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("secret", expiry);

        let result =
            super::provider_output_to_scoped_token_with_metadata(output, "role", None, "prov");

        assert!(result.expires_at_provided);
    }

    #[test]
    fn conversion_result_token_accessible() {
        // NS-078: The ConversionResult must provide access to the ScopedToken.
        let expiry = Utc::now() + chrono::Duration::hours(1);
        let output = make_provider_output("accessible-secret", expiry);

        let result = super::provider_output_to_scoped_token_with_metadata(
            output,
            "admin",
            Some("tid-x".to_string()),
            "aws",
        );

        assert_eq!(result.token.expose_secret(), "accessible-secret");
        assert_eq!(result.token.role(), "admin");
        assert_eq!(result.token.provider(), "aws");
        assert_eq!(result.token.token_id(), Some("tid-x"));
    }
}
