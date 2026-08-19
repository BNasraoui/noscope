// No credential storage
// Memory zeroization on drop

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroize;

use crate::core::redaction::RedactedToken;
use provenance_macros::rule;

/// A scoped credential with mandatory expiry and zeroizing secret storage.
/// Design constraints:
#[rule("rule_token_mandatory_expiry")]
pub struct ScopedToken {
    /// The credential value, stored in a zeroizing secret type.
    value: SecretString,
    /// Pre-computed redacted form — avoids calling expose_secret() on every format.
    redacted: RedactedToken,
    /// Role this token was minted for.
    role: String,
    /// Mandatory expiry time. Construction without this is a compile-time error.
    expires_at: DateTime<Utc>,
    /// Additional token metadata (provider, token_id, and future extensions).
    metadata: HashMap<String, String>,
}

// Zeroize metadata fields on drop.
// SecretString already zeroizes on drop, but we also zeroize role/provider
// metadata since they could be correlated with the token.
impl Drop for ScopedToken {
    fn drop(&mut self) {
        self.role.zeroize();
        for value in self.metadata.values_mut() {
            value.zeroize();
        }
        self.metadata.clear();
        // SecretString handles its own zeroization on drop
    }
}

impl ScopedToken {
    /// Create a new ScopedToken from an already-constructed `SecretString`.
    /// Takes ownership of the secret — no intermediate copies are created.
    /// The caller should construct `SecretString` directly from the credential
    /// source (e.g., parsing provider JSON output) to minimize copies.
    /// `expires_at` is mandatory — there is no constructor that
    /// omits it.
    pub fn new(
        value: SecretString,
        role: &str,
        expires_at: DateTime<Utc>,
        token_id: Option<String>,
        provider: &str,
    ) -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), provider.to_string());
        if let Some(token_id) = token_id {
            metadata.insert("token_id".to_string(), token_id);
        }

        Self::new_with_metadata(value, role, expires_at, metadata)
    }

    /// Create a new ScopedToken from an already-constructed `SecretString`
    /// and explicit metadata.
    pub fn new_with_metadata(
        value: SecretString,
        role: &str,
        expires_at: DateTime<Utc>,
        metadata: HashMap<String, String>,
    ) -> Self {
        // Pre-compute redacted form once at construction.
        // This is the only time we call expose_secret() for display purposes.
        let redacted = RedactedToken::new(
            value.expose_secret(),
            metadata.get("token_id").map(String::as_str),
        );
        Self {
            value,
            redacted,
            role: role.to_string(),
            expires_at,
            metadata,
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
        self.metadata
            .get("provider")
            .map(String::as_str)
            .unwrap_or("")
    }

    /// Get the token ID (if available).
    pub fn token_id(&self) -> Option<&str> {
        self.metadata.get("token_id").map(String::as_str)
    }

    /// Get immutable metadata.
    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Get the pre-computed RedactedToken for safe display/logging.
    /// This never touches the secret value — the redacted form was computed
    /// once at construction time.
    pub fn redacted_value(&self) -> &RedactedToken {
        &self.redacted
    }

    /// Explicitly expose the secret value.
    /// This is the ONLY way to get the raw credential — for injection into
    /// child process environment variables. The method name makes the intent
    /// explicit per the secrecy crate's conventions.
    pub fn expose_secret(&self) -> &str {
        self.value.expose_secret()
    }
}

/// Display never shows the secret value.
impl fmt::Display for ScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScopedToken(provider={}, role={}, token={})",
            self.provider(),
            self.role,
            self.redacted
        )
    }
}

/// Debug also never shows the secret value.
impl fmt::Debug for ScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedToken")
            .field("provider", &self.provider())
            .field("role", &self.role)
            .field("expires_at", &self.expires_at)
            .field("token_id", &self.token_id())
            .field("metadata", &self.metadata)
            .field("value", &self.redacted)
            .finish()
    }
}

#[cfg(test)]
mod tests;
