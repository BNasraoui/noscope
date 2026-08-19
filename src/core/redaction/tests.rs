use super::*;
use provenance_macros::verifies;

#[test]
#[verifies("rule_token_redacted_form_no_raw", examples)]
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

#[test]
#[verifies("rule_token_redaction_format", examples)]
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
    // For JWTs, never use prefix characters (they always start with eyJhbGci)
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
