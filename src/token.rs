// NS-001: No credential storage
// NS-019: Memory zeroization on drop

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use zeroize::Zeroize;

use crate::redaction::RedactedToken;

/// A scoped credential with mandatory expiry and zeroizing secret storage.
///
/// Design constraints:
/// - NS-001: No Serialize impl — credentials must never be persisted to disk
/// - NS-019: Value stored in SecretString (Zeroize + ZeroizeOnDrop)
/// - NS-019: Does NOT implement Clone (prevents implicit copies without zeroization)
/// - NS-016: expires_at is mandatory and non-optional
pub struct ScopedToken {
    /// The credential value, stored in a zeroizing secret type.
    value: SecretString,
    /// Pre-computed redacted form — avoids calling expose_secret() on every format.
    redacted: RedactedToken,
    /// Role this token was minted for.
    role: String,
    /// Mandatory expiry time. Construction without this is a compile-time error.
    expires_at: DateTime<Utc>,
    /// Provider-supplied or noscope-generated token identifier.
    token_id: Option<String>,
    /// The provider that minted this token.
    provider: String,
}

// NS-019: Zeroize metadata fields on drop.
// SecretString already zeroizes on drop, but we also zeroize role/provider
// metadata since they could be correlated with the token.
impl Drop for ScopedToken {
    fn drop(&mut self) {
        self.role.zeroize();
        if let Some(ref mut id) = self.token_id {
            id.zeroize();
        }
        self.provider.zeroize();
        // SecretString handles its own zeroization on drop
    }
}

impl ScopedToken {
    /// Create a new ScopedToken from an already-constructed `SecretString`.
    ///
    /// Takes ownership of the secret — no intermediate copies are created.
    /// The caller should construct `SecretString` directly from the credential
    /// source (e.g., parsing provider JSON output) to minimize copies.
    ///
    /// `expires_at` is mandatory per NS-016 — there is no constructor that
    /// omits it.
    pub fn new(
        value: SecretString,
        role: &str,
        expires_at: DateTime<Utc>,
        token_id: Option<String>,
        provider: &str,
    ) -> Self {
        // Pre-compute redacted form once at construction.
        // This is the only time we call expose_secret() for display purposes.
        let redacted = RedactedToken::new(value.expose_secret(), token_id.as_deref());
        Self {
            value,
            redacted,
            role: role.to_string(),
            expires_at,
            token_id,
            provider: provider.to_string(),
        }
    }

    /// Get the mandatory expiry time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Get the role this token was minted for.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Get the provider name.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Get the token ID (if available).
    pub fn token_id(&self) -> Option<&str> {
        self.token_id.as_deref()
    }

    /// Get the pre-computed RedactedToken for safe display/logging.
    ///
    /// This never touches the secret value — the redacted form was computed
    /// once at construction time.
    pub fn redacted_value(&self) -> &RedactedToken {
        &self.redacted
    }

    /// Explicitly expose the secret value.
    ///
    /// This is the ONLY way to get the raw credential — for injection into
    /// child process environment variables. The method name makes the intent
    /// explicit per the secrecy crate's conventions.
    pub fn expose_secret(&self) -> &str {
        self.value.expose_secret()
    }
}

/// NS-005 + NS-058: Display never shows the secret value.
impl fmt::Display for ScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScopedToken(provider={}, role={}, token={})",
            self.provider, self.role, self.redacted
        )
    }
}

/// NS-058: Debug also never shows the secret value.
impl fmt::Debug for ScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedToken")
            .field("provider", &self.provider)
            .field("role", &self.role)
            .field("expires_at", &self.expires_at)
            .field("token_id", &self.token_id)
            .field("value", &self.redacted)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Helper: create a ScopedToken from a &str for test convenience.
    /// In production, callers should construct SecretString directly.
    fn make_token(
        value: &str,
        role: &str,
        token_id: Option<String>,
        provider: &str,
    ) -> ScopedToken {
        ScopedToken::new(
            SecretString::from(value.to_string()),
            role,
            Utc::now() + chrono::Duration::hours(1),
            token_id,
            provider,
        )
    }

    // =========================================================================
    // NS-019: Memory zeroization on drop.
    // Token types must implement Zeroize and ZeroizeOnDrop.
    // Tokens must never be stored in types allowing implicit Clone.
    // =========================================================================

    #[test]
    fn scoped_token_display_does_not_expose_secret() {
        let token = make_token(
            "secret-value-that-should-be-zeroized",
            "admin",
            Some("tok-id-1".to_string()),
            "aws",
        );
        let display = format!("{}", token);
        assert!(
            !display.contains("secret-value-that-should-be-zeroized"),
            "Display must not expose secret, got: {}",
            display
        );
    }

    #[test]
    fn scoped_token_debug_does_not_expose_secret() {
        let token = make_token("my-secret-credential-12345678", "viewer", None, "gcp");
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("my-secret-credential-12345678"),
            "Debug must not expose secret, got: {}",
            debug
        );
    }

    #[test]
    fn scoped_token_debug_shows_non_secret_fields() {
        let token = make_token(
            "hidden-credential",
            "editor",
            Some("tok-xyz".to_string()),
            "azure",
        );
        let debug = format!("{:?}", token);
        assert!(debug.contains("editor"), "Debug should show role");
        assert!(debug.contains("azure"), "Debug should show provider");
        assert!(debug.contains("tok-xyz"), "Debug should show token_id");
    }

    #[test]
    fn scoped_token_requires_expires_at() {
        let expiry = Utc::now() + chrono::Duration::minutes(30);
        let token = ScopedToken::new(
            SecretString::from("some-secret".to_string()),
            "role",
            expiry,
            None,
            "provider",
        );
        assert_eq!(token.expires_at(), expiry);
    }

    #[test]
    fn scoped_token_exposes_metadata_but_not_value() {
        let token = make_token(
            "the-actual-secret",
            "deployer",
            Some("tok-meta".to_string()),
            "vault",
        );
        assert_eq!(token.role(), "deployer");
        assert_eq!(token.provider(), "vault");
        assert_eq!(token.token_id(), Some("tok-meta"));
        let redacted = token.redacted_value();
        let display = format!("{}", redacted);
        assert!(!display.contains("the-actual-secret"));
    }

    #[test]
    fn scoped_token_expose_secret_returns_value() {
        let token = make_token("real-credential-value", "admin", None, "aws");
        let exposed = token.expose_secret();
        assert_eq!(exposed, "real-credential-value");
    }

    #[test]
    fn scoped_token_is_not_clone() {
        static_assertions::assert_not_impl_any!(ScopedToken: Clone);
    }

    // =========================================================================
    // NS-001: No credential storage — never persist/cache/store to disk.
    // =========================================================================

    #[test]
    fn scoped_token_is_not_serializable() {
        static_assertions::assert_not_impl_any!(ScopedToken: serde::Serialize);
    }

    #[test]
    fn scoped_token_is_send() {
        static_assertions::assert_impl_all!(ScopedToken: Send);
    }

    #[test]
    fn scoped_token_is_sync() {
        static_assertions::assert_impl_all!(ScopedToken: Sync);
    }

    #[test]
    fn string_zeroize_actually_clears_data() {
        // Verify that the Zeroize trait on String actually clears the data.
        // This proves the trait is wired up, which is what our Drop impl uses.
        let mut s = String::from("sensitive-data-12345");
        assert_eq!(s, "sensitive-data-12345");
        s.zeroize();
        assert!(s.is_empty(), "After zeroize, string should be empty");
    }

    #[test]
    fn scoped_token_constructor_takes_secret_string_directly() {
        // Verify the constructor takes SecretString — no intermediate &str copy.
        let secret = SecretString::from("direct-ownership".to_string());
        let token = ScopedToken::new(
            secret,
            "role",
            Utc::now() + chrono::Duration::hours(1),
            None,
            "provider",
        );
        assert_eq!(token.expose_secret(), "direct-ownership");
    }

    #[test]
    fn redacted_value_returns_reference_not_new_computation() {
        // Calling redacted_value() multiple times should return the same
        // pre-computed redacted form (no expose_secret() on each call).
        let token = make_token("abcdefghijklmnopqrstuvwxyz", "role", None, "prov");
        let r1 = format!("{}", token.redacted_value());
        let r2 = format!("{}", token.redacted_value());
        assert_eq!(r1, r2);
        assert_eq!(r1, "abcdefgh...");
    }
}
