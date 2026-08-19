// Centralized token conversion boundaries
// Defines explicit conversion boundaries between:
// - token-in-memory (ScopedToken)
// - provider output (ProviderOutput)
// - stdout envelope (MintEnvelope)
// Conversion pipeline: ProviderOutput → ScopedToken → MintEnvelope
// Secret-handling guarantees at each boundary:
// - ProviderOutput → ScopedToken: ProviderOutput consumed (ownership transferred);
//   raw token cloned into SecretString (clone required because ProviderOutput
//   implements Drop for zeroization). Both copies are independently zeroized:
//   ProviderOutput by its Drop impl, SecretString by ZeroizeOnDrop.
// - ScopedToken → MintEnvelope: expose_secret() called explicitly;
//   the raw value is copied into MintEnvelope's zeroizing String.
// ScopedToken is never Serialize — this boundary is the ONLY way
// secrets cross type boundaries.

use secrecy::SecretString;

use crate::core::mint::MintEnvelope;
use crate::core::token::ScopedToken;
use crate::ports::provider_exec::ProviderOutput;
use provenance_macros::rule;

/// Result of converting a ProviderOutput to a ScopedToken, with metadata
/// about the conversion (e.g., whether expires_at was provider-supplied).
/// The caller needs `expires_at_provided` to emit warning when
/// the provider didn't supply an explicit expiry.
pub struct ConversionResult {
    /// The converted token.
    pub token: ScopedToken,
    /// Whether expires_at was explicitly provided by the provider.
    /// `false` means it was computed from `now() + requested_ttl`.
    pub expires_at_provided: bool,
}

/// Convert a ProviderOutput into a ScopedToken.
/// **Secret boundary**: Takes ownership of `output`, consuming the
/// ProviderOutput. The raw token is cloned into a SecretString (clone is
/// required because ProviderOutput implements Drop for zeroization, and Rust
/// does not allow moving fields out of Drop types). Both copies are
/// independently zeroized on drop: ProviderOutput by its Drop impl,
/// SecretString by ZeroizeOnDrop.
/// # Arguments
/// - `output`: The parsed provider command output (consumed).
/// - `role`: The role this token was minted for (not in provider output).
/// - `token_id`: Optional provider-supplied or generated token identifier.
/// - `provider`: The provider name (not in provider output).
#[rule("rule_cross_single_conversion_path")]
#[rule("rule_provider_supplied_token_id")]
pub fn provider_output_to_scoped_token(
    output: ProviderOutput,
    role: &str,
    token_id: Option<String>,
    provider: &str,
) -> ScopedToken {
    // Clone the raw token into SecretString for zeroization guarantees.
    // We must clone because ProviderOutput implements Drop (for zeroization),
    // and Rust doesn't allow moving fields out of a Drop type. This is fine:
    // ProviderOutput's Drop will zeroize its String copy, and SecretString
    // manages zeroization of its own copy independently.
    let secret = SecretString::from(output.token.clone());

    // The provider owns the lease identity when it supplies one
    // (rule_provider_supplied_token_id); the caller's value is the fallback.
    let token_id = output.token_id.clone().or(token_id);
    ScopedToken::new(secret, role, output.expires_at, token_id, provider)
}

/// Convert a ProviderOutput into a ScopedToken, preserving the
/// `expires_at_provided` flag for warning emission.
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

/// Convert a ScopedToken into a MintEnvelope for stdout output.
/// **Secret boundary**: Calls `expose_secret()` on the ScopedToken to extract
/// the raw credential value. This is the designated path for outputting raw
/// credentials.
/// Takes `&ScopedToken` (borrow) because the caller may still need the token
/// for child process injection after creating the envelope.
pub fn scoped_token_to_mint_envelope(token: &ScopedToken) -> MintEnvelope {
    MintEnvelope::from_scoped_token(token)
}

#[cfg(test)]
mod tests;
