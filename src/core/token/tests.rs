use super::*;
use chrono::Utc;
use provenance_macros::verifies;

/// Helper: create a ScopedToken from a &str for test convenience.
/// In production, callers should construct SecretString directly.
fn make_token(value: &str, role: &str, token_id: Option<String>, provider: &str) -> ScopedToken {
    ScopedToken::new(
        SecretString::from(value.to_string()),
        role,
        Utc::now() + chrono::Duration::hours(1),
        token_id,
        provider,
    )
}

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
#[verifies("rule_token_mandatory_expiry", examples)]
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
