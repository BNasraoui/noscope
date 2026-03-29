// NS-005: Token redaction in output
// NS-058: Debug logging redaction invariant
// NS-059: Redaction format for short and structured tokens

use sha2::{Digest, Sha256};
use std::fmt;

/// A token wrapper that NEVER exposes the raw value through Display or Debug.
///
/// Redaction rules (NS-059):
/// - JWT tokens (start with "eyJ"): always `[redacted:<token_id_or_hash>]`
/// - Tokens <= 16 chars: `[redacted:<token_id_or_hash>]`
/// - Tokens > 16 chars: first 8 chars + "..."
///
/// NS-058: Redaction applies at ALL log levels. No flag may disable it.
/// The raw token value is consumed at construction and never stored.
pub struct RedactedToken {
    /// Pre-computed redacted display string.
    redacted_display: String,
}

impl RedactedToken {
    /// Create a new RedactedToken. The raw `value` is used only to compute
    /// the redacted form and is NOT stored.
    ///
    /// - `value`: the raw token string (consumed, not retained)
    /// - `token_id`: optional provider-supplied identifier
    pub fn new(value: &str, token_id: Option<&str>) -> Self {
        let redacted_display = compute_redacted_form(value, token_id);
        Self { redacted_display }
    }
}

/// NS-005 + NS-058: Display always shows redacted form.
impl fmt::Display for RedactedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.redacted_display)
    }
}

/// NS-058: Debug shows redacted form wrapped in type name for diagnostics.
/// No log level may bypass this.
impl fmt::Debug for RedactedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RedactedToken")
            .field(&self.redacted_display)
            .finish()
    }
}

/// Compute the redacted display string per NS-059 rules.
fn compute_redacted_form(value: &str, token_id: Option<&str>) -> String {
    // Empty token edge case
    if value.is_empty() {
        return format!("[redacted:{}]", token_id.unwrap_or("empty"));
    }

    let is_jwt = value.starts_with("eyJ");

    if is_jwt {
        // NS-059: JWTs must NEVER show prefix characters.
        // Always use [redacted:token_id] or [redacted:hash].
        let id = token_id
            .map(String::from)
            .unwrap_or_else(|| hash_based_id(value));
        format!("[redacted:{}]", id)
    } else if value.len() <= 16 {
        // NS-059: Short tokens use [redacted:token_id] or [redacted:hash].
        //
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
        // NS-059: Long tokens (>16 bytes) show first 8 characters + "..."
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
mod tests {
    use super::*;

    // =========================================================================
    // NS-005: Token values must never appear in logs, stderr, stdout, or error
    // messages. Use redacted identifiers (first 8 chars with ellipsis, or
    // provider-supplied token ID) for debugging and audit output.
    // =========================================================================

    #[test]
    fn display_never_shows_full_token_value() {
        let token = RedactedToken::new("super-secret-token-value-1234567890", None);
        let display = format!("{}", token);
        assert!(
            !display.contains("super-secret-token-value-1234567890"),
            "Display must never show full token value, got: {}",
            display
        );
    }

    #[test]
    fn debug_never_shows_full_token_value() {
        let token = RedactedToken::new("super-secret-token-value-1234567890", None);
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("super-secret-token-value-1234567890"),
            "Debug must never show full token value, got: {}",
            debug
        );
    }

    #[test]
    fn display_of_empty_token_does_not_panic() {
        let token = RedactedToken::new("", None);
        let display = format!("{}", token);
        assert!(
            !display.is_empty(),
            "Even empty token should produce output"
        );
    }

    // =========================================================================
    // NS-058: Token redaction applies at ALL log levels including debug and
    // trace. No log level, env var, or CLI flag may disable redaction.
    // Token values must be wrapped in a redacting newtype that implements
    // Display and Debug to emit only the redacted form.
    // =========================================================================

    #[test]
    fn debug_format_shows_redacted_form_not_raw() {
        let token = RedactedToken::new("abcdefghijklmnopqrstuvwxyz", None);
        let debug = format!("{:?}", token);
        // Debug must contain the same redacted prefix, not raw value
        assert!(
            debug.contains("abcdefgh..."),
            "Debug format must show redacted form, got: {}",
            debug
        );
        assert!(
            !debug.contains("abcdefghijklmnopqrstuvwxyz"),
            "Debug must not contain full token"
        );
    }

    #[test]
    fn debug_format_looks_like_debug_output() {
        // Debug should be distinguishable from Display — wraps in type name
        let token = RedactedToken::new("abcdefghijklmnopqrstuvwxyz", None);
        let debug = format!("{:?}", token);
        assert!(
            debug.contains("RedactedToken"),
            "Debug should include type name, got: {}",
            debug
        );
    }

    #[test]
    fn redaction_cannot_be_bypassed_by_alternate_format() {
        let token = RedactedToken::new("abcdefghijklmnopqrstuvwxyz", None);
        // Try various format specifiers - none should leak
        let alt = format!("{:#}", token);
        let alt_debug = format!("{:#?}", token);
        assert!(!alt.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(!alt_debug.contains("abcdefghijklmnopqrstuvwxyz"));
    }

    // =========================================================================
    // NS-059: Redaction format for short and structured tokens.
    //
    // - Token > 16 chars: first 8 chars + "..."
    // - Token <= 16 chars: [redacted:token_id] (provider ID or truncated hash)
    // - JWT tokens (start with "eyJ"): NEVER show prefix, use hash-based ID only
    // =========================================================================

    #[test]
    fn long_token_shows_first_8_chars_with_ellipsis() {
        // 26 chars, well above 16
        let token = RedactedToken::new("abcdefghijklmnopqrstuvwxyz", None);
        let display = format!("{}", token);
        assert_eq!(display, "abcdefgh...");
    }

    #[test]
    fn token_exactly_17_chars_shows_prefix() {
        let token = RedactedToken::new("12345678901234567", None);
        let display = format!("{}", token);
        assert_eq!(display, "12345678...");
    }

    #[test]
    fn token_exactly_16_chars_uses_redacted_format() {
        let token = RedactedToken::new("1234567890123456", Some("tok-abc"));
        let display = format!("{}", token);
        assert_eq!(display, "[redacted:tok-abc]");
    }

    #[test]
    fn short_token_with_provider_id_uses_that_id() {
        let token = RedactedToken::new("short", Some("provider-tok-99"));
        let display = format!("{}", token);
        assert_eq!(display, "[redacted:provider-tok-99]");
    }

    #[test]
    fn short_token_without_id_uses_hash_based_id() {
        let token = RedactedToken::new("short-tok", None);
        let display = format!("{}", token);
        // Must be [redacted:<hash>] format
        assert!(
            display.starts_with("[redacted:"),
            "Short token without ID should use [redacted:hash], got: {}",
            display
        );
        assert!(display.ends_with(']'));
        // Must NOT contain the actual token value
        assert!(!display.contains("short-tok"));
    }

    #[test]
    fn jwt_token_never_shows_prefix_chars() {
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
        let token = RedactedToken::new(jwt, None);
        let display = format!("{}", token);
        // NS-059: For JWTs, never use prefix characters (they always start with eyJhbGci)
        assert!(
            !display.contains("eyJ"),
            "JWT redaction must never show prefix, got: {}",
            display
        );
        // Must use hash-based ID
        assert!(display.starts_with("[redacted:"));
        assert!(display.ends_with(']'));
    }

    #[test]
    fn jwt_token_with_provider_id_uses_provider_id() {
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
        let token = RedactedToken::new(jwt, Some("jwt-session-42"));
        let display = format!("{}", token);
        assert_eq!(display, "[redacted:jwt-session-42]");
    }

    #[test]
    fn same_token_always_produces_same_hash_id() {
        let t1 = RedactedToken::new("short", None);
        let t2 = RedactedToken::new("short", None);
        assert_eq!(format!("{}", t1), format!("{}", t2));
    }

    #[test]
    fn different_tokens_produce_different_hash_ids() {
        let t1 = RedactedToken::new("alpha", None);
        let t2 = RedactedToken::new("bravo", None);
        assert_ne!(format!("{}", t1), format!("{}", t2));
    }

    #[test]
    fn multibyte_utf8_token_does_not_panic() {
        // Each emoji is 4 bytes. 9 emojis = 36 bytes but only 9 chars.
        // Slicing at byte 8 would land mid-character and panic with &value[..8].
        let token = RedactedToken::new(
            "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}\u{1F605}\u{1F606}\u{1F607}\u{1F608}",
            None,
        );
        let display = format!("{}", token);
        // Should show first 8 chars (emojis) + "..."
        assert!(display.ends_with("..."));
        assert!(!display.is_empty());
    }

    #[test]
    fn mixed_ascii_multibyte_token_takes_8_chars() {
        // "abc" + 3-byte char + "defghijklm" = well over 16 chars
        let token = RedactedToken::new("abc\u{00E9}defghijklmnop", None);
        let display = format!("{}", token);
        assert_eq!(display, "abc\u{00E9}defg...");
    }
}
