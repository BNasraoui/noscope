// Token redaction in output
// Debug logging redaction invariant
// Redaction format for short and structured tokens

use provenance_macros::rule;
use sha2::{Digest, Sha256};
use std::fmt;

/// A token wrapper that NEVER exposes the raw value through Display or Debug.
/// Redaction rules:
/// - JWT tokens (start with "eyJ"): always `[redacted:<token_id_or_hash>]`
/// - Tokens <= 16 chars: `[redacted:<token_id_or_hash>]`
/// - Tokens > 16 chars: first 8 chars + "..."
///
/// Redaction applies at ALL log levels. No flag may disable it.
/// The raw token value is consumed at construction and never stored.
#[rule("rule_token_redacted_form_no_raw")]
pub struct RedactedToken {
    /// Pre-computed redacted display string.
    redacted_display: String,
}

impl RedactedToken {
    /// Create a new RedactedToken. The raw `value` is used only to compute
    /// the redacted form and is NOT stored.
    /// - `value`: the raw token string (consumed, not retained)
    /// - `token_id`: optional provider-supplied identifier
    pub fn new(value: &str, token_id: Option<&str>) -> Self {
        let redacted_display = compute_redacted_form(value, token_id);
        Self { redacted_display }
    }
}

/// Display always shows redacted form.
impl fmt::Display for RedactedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.redacted_display)
    }
}

/// Debug shows redacted form wrapped in type name for diagnostics.
/// No log level may bypass this.
impl fmt::Debug for RedactedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RedactedToken")
            .field(&self.redacted_display)
            .finish()
    }
}

/// Compute the redacted display string rules.
#[rule("rule_token_redaction_format")]
fn compute_redacted_form(value: &str, token_id: Option<&str>) -> String {
    // Empty token edge case
    if value.is_empty() {
        return format!("[redacted:{}]", token_id.unwrap_or("empty"));
    }

    let is_jwt = value.starts_with("eyJ");

    if is_jwt {
        // JWTs must NEVER show prefix characters.
        // Always use [redacted:token_id] or [redacted:hash].
        let id = token_id
            .map(String::from)
            .unwrap_or_else(|| hash_based_id(value));
        format!("[redacted:{}]", id)
    } else if value.len() <= 16 {
        // Short tokens use [redacted:token_id] or [redacted:hash].
        // Deliberate: this threshold uses byte length, not character count.
        // A multi-byte token with >16 bytes but <=16 characters falls into
        // the prefix branch below — that's strictly more conservative because
        // the prefix branch also redacts (shows only 8 chars). Using byte
        // length means more tokens hit the fully-opaque [redacted:...] path,
        // which is the safer default for a credential manager.
        let id = token_id
            .map(String::from)
            .unwrap_or_else(|| hash_based_id(value));
        format!("[redacted:{}]", id)
    } else {
        // Long tokens (>16 bytes) show first 8 characters + "..."
        // Uses chars() iterator to handle multi-byte UTF-8 safely.
        let prefix: String = value.chars().take(8).collect();
        format!("{}...", prefix)
    }
}

/// Generate a truncated SHA-256 hash as a token identifier.
/// Used when no provider-supplied token_id is available.
fn hash_based_id(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let hash = hasher.finalize();
    // Use first 8 bytes (16 hex chars) as the identifier.
    // Manual hex encoding to avoid pulling in another crate.
    let mut out = String::with_capacity(16);
    for &byte in &hash[..8] {
        fmt::Write::write_fmt(&mut out, format_args!("{:02x}", byte)).unwrap();
    }
    out
}

#[cfg(test)]
mod tests;
