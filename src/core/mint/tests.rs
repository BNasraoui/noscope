use chrono::{DateTime, Utc};
use provenance_macros::verifies;
use serde_json::Value;

#[test]
fn mint_output_envelope_contains_token_field() {
    let envelope = super::MintEnvelope::new(
        "secret-token-value",
        Utc::now() + chrono::Duration::hours(1),
        "tok-123",
        "aws",
        "admin",
    );
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["token"].as_str().unwrap(),
        "secret-token-value",
        "envelope must contain 'token' field with raw value"
    );
}

#[test]
fn mint_output_envelope_contains_expires_at_iso8601() {
    let expiry = Utc::now() + chrono::Duration::hours(1);
    let envelope = super::MintEnvelope::new("tok-value", expiry, "tok-id", "aws", "admin");
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    let expires_str = parsed["expires_at"].as_str().unwrap();
    // Must be valid ISO 8601 / RFC 3339
    let _parsed_dt: DateTime<Utc> = expires_str
        .parse()
        .expect("expires_at must be valid ISO 8601");
}

#[test]
fn mint_output_envelope_contains_token_id() {
    let envelope = super::MintEnvelope::new(
        "tok",
        Utc::now() + chrono::Duration::hours(1),
        "provider-tok-id-42",
        "gcp",
        "viewer",
    );
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["token_id"].as_str().unwrap(),
        "provider-tok-id-42",
        "envelope must contain 'token_id' field"
    );
}

#[test]
fn mint_output_envelope_contains_provider() {
    let envelope = super::MintEnvelope::new(
        "tok",
        Utc::now() + chrono::Duration::hours(1),
        "id",
        "vault",
        "deployer",
    );
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["provider"].as_str().unwrap(),
        "vault",
        "envelope must contain 'provider' field"
    );
}

#[test]
fn mint_output_envelope_contains_role() {
    let envelope = super::MintEnvelope::new(
        "tok",
        Utc::now() + chrono::Duration::hours(1),
        "id",
        "aws",
        "read-only",
    );
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["role"].as_str().unwrap(),
        "read-only",
        "envelope must contain 'role' field"
    );
}

#[test]
#[verifies("rule_token_mint_envelope_five_fields", examples)]
fn mint_output_envelope_has_exactly_five_fields() {
    let envelope = super::MintEnvelope::new(
        "tok",
        Utc::now() + chrono::Duration::hours(1),
        "id",
        "aws",
        "admin",
    );
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    let obj = parsed.as_object().unwrap();
    assert_eq!(
        obj.len(),
        5,
        "envelope must have exactly 5 fields (token, expires_at, token_id, provider, role), got: {:?}",
        obj.keys().collect::<Vec<_>>()
    );
}

#[test]
fn mint_output_envelope_is_single_line_json() {
    let envelope = super::MintEnvelope::new(
        "my-secret",
        Utc::now() + chrono::Duration::hours(1),
        "tid",
        "aws",
        "admin",
    );
    let json = envelope.to_json();
    assert!(
        !json.contains('\n'),
        "mint envelope JSON must be single-line"
    );
}

#[test]
fn mint_output_envelope_from_scoped_token() {
    use crate::core::token::ScopedToken;
    use secrecy::SecretString;

    let expiry = Utc::now() + chrono::Duration::hours(1);
    let token = ScopedToken::new(
        SecretString::from("raw-secret".to_string()),
        "admin",
        expiry,
        Some("tok-abc".to_string()),
        "aws",
    );
    let envelope = super::MintEnvelope::from_scoped_token(&token);
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["token"].as_str().unwrap(), "raw-secret");
    assert_eq!(parsed["provider"].as_str().unwrap(), "aws");
    assert_eq!(parsed["role"].as_str().unwrap(), "admin");
    assert_eq!(parsed["token_id"].as_str().unwrap(), "tok-abc");
}

#[test]
fn revoke_input_from_token_id_and_provider() {
    let input = super::RevokeInput::from_token_id_and_provider("tok-abc-123", "aws");
    assert_eq!(input.token_id(), "tok-abc-123");
    assert_eq!(input.provider(), "aws");
}

#[test]
#[verifies("rule_token_revoke_stdin_envelope", examples)]
fn revoke_input_from_mint_json_stdin() {
    let mint_json = r#"{"token":"secret","expires_at":"2025-01-01T00:00:00Z","token_id":"tok-99","provider":"gcp","role":"viewer"}"#;
    let input = super::RevokeInput::from_mint_json(mint_json).unwrap();
    assert_eq!(input.token_id(), "tok-99");
    assert_eq!(input.provider(), "gcp");
}

#[test]
fn revoke_input_from_mint_json_rejects_invalid_json() {
    let bad_json = "not valid json {{{";
    let result = super::RevokeInput::from_mint_json(bad_json);
    assert!(result.is_err(), "invalid JSON must be rejected");
}

#[test]
fn revoke_input_from_mint_json_rejects_missing_token_id() {
    let incomplete =
        r#"{"token":"secret","provider":"aws","role":"admin","expires_at":"2025-01-01T00:00:00Z"}"#;
    let result = super::RevokeInput::from_mint_json(incomplete);
    assert!(
        result.is_err(),
        "mint JSON without token_id must be rejected"
    );
}

#[test]
fn revoke_input_from_mint_json_rejects_missing_provider() {
    let incomplete = r#"{"token":"secret","token_id":"tok-1","role":"admin","expires_at":"2025-01-01T00:00:00Z"}"#;
    let result = super::RevokeInput::from_mint_json(incomplete);
    assert!(
        result.is_err(),
        "mint JSON without provider must be rejected"
    );
}

#[test]
fn revoke_input_does_not_store_token_value() {
    // The revoke input must NOT retain the raw token value.
    // Only token_id and provider are needed for revocation.
    let mint_json = r#"{"token":"super-secret-value","expires_at":"2025-01-01T00:00:00Z","token_id":"tok-99","provider":"gcp","role":"viewer"}"#;
    let input = super::RevokeInput::from_mint_json(mint_json).unwrap();
    let debug = format!("{:?}", input);
    assert!(
        !debug.contains("super-secret-value"),
        "RevokeInput must not store the raw token value, got debug: {}",
        debug
    );
}

#[test]
fn revoke_input_validates_no_token_value_in_cli_args() {
    // Token values must never appear as CLI arguments.
    // validate_no_token_in_args checks that no argument looks like a raw token.
    let result = super::validate_revoke_args(&[
        "noscope".to_string(),
        "revoke".to_string(),
        "--token-id".to_string(),
        "tok-123".to_string(),
        "--provider".to_string(),
        "aws".to_string(),
    ]);
    assert!(
        result.is_ok(),
        "--token-id and --provider args are allowed (not raw token values)"
    );
}

#[test]
fn revoke_input_rejects_raw_token_flag() {
    // A --token flag with the actual secret value must be rejected.
    let result = super::validate_revoke_args(&[
        "noscope".to_string(),
        "revoke".to_string(),
        "--token".to_string(),
        "actual-secret-value".to_string(),
    ]);
    assert!(
        result.is_err(),
        "--token flag with raw secret value must be rejected"
    );
}

#[test]
fn mint_ttl_requirement_ttl_is_mandatory() {
    let result = super::validate_mint_args(None, &["aws".to_string()], "admin");
    assert!(result.is_err(), "--ttl must be required for mint mode");
}

#[test]
fn mint_ttl_requirement_accepts_valid_ttl() {
    let result = super::validate_mint_args(Some(3600), &["aws".to_string()], "admin");
    assert!(result.is_ok(), "valid TTL should be accepted");
}

#[test]
fn mint_ttl_requirement_rejects_zero_ttl() {
    let result = super::validate_mint_args(Some(0), &["aws".to_string()], "admin");
    assert!(result.is_err(), "zero TTL must be rejected");
}

#[test]
fn mint_ttl_requirement_rejects_empty_providers() {
    let result = super::validate_mint_args(Some(3600), &[], "admin");
    assert!(result.is_err(), "at least one provider is required");
}

#[test]
fn mint_ttl_requirement_rejects_empty_role() {
    let result = super::validate_mint_args(Some(3600), &["aws".to_string()], "");
    assert!(result.is_err(), "empty role must be rejected");
}

#[test]
fn mint_multi_provider_atomicity_single_provider_returns_object() {
    let envelope = super::MintEnvelope::new(
        "tok",
        Utc::now() + chrono::Duration::hours(1),
        "id",
        "aws",
        "admin",
    );
    let output = super::format_mint_output(&[envelope]);
    let parsed: Value = serde_json::from_str(&output).unwrap();
    // Single provider: still a JSON array
    assert!(
        parsed.is_array(),
        "single provider output must be a JSON array, got: {}",
        output
    );
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn mint_multi_provider_atomicity_multiple_providers_returns_array() {
    let e1 = super::MintEnvelope::new(
        "tok1",
        Utc::now() + chrono::Duration::hours(1),
        "id1",
        "aws",
        "admin",
    );
    let e2 = super::MintEnvelope::new(
        "tok2",
        Utc::now() + chrono::Duration::hours(1),
        "id2",
        "gcp",
        "viewer",
    );
    let output = super::format_mint_output(&[e1, e2]);
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert!(
        parsed.is_array(),
        "multi-provider output must be a JSON array"
    );
    assert_eq!(parsed.as_array().unwrap().len(), 2);
}

#[test]
fn mint_multi_provider_atomicity_empty_on_failure() {
    // On failure, output is nothing — empty string.
    let output = super::format_mint_output(&[]);
    assert!(
        output.is_empty(),
        "on failure (no successful mints), output must be empty, got: {:?}",
        output
    );
}

#[test]
fn mint_multi_provider_atomicity_no_partial_stdout() {
    // The output must be all-or-nothing. The function takes
    // a complete slice of envelopes — partial results are not representable.
    // This test verifies the API design: you can't add envelopes incrementally.
    let e1 = super::MintEnvelope::new(
        "tok1",
        Utc::now() + chrono::Duration::hours(1),
        "id1",
        "aws",
        "admin",
    );
    let output = super::format_mint_output(&[e1]);
    let parsed: Value = serde_json::from_str(&output).unwrap();
    // Verify it's valid JSON — no partial/broken output
    assert!(parsed.is_array());
}

#[test]
fn mint_multi_provider_atomicity_output_is_single_line() {
    let e1 = super::MintEnvelope::new(
        "tok1",
        Utc::now() + chrono::Duration::hours(1),
        "id1",
        "aws",
        "admin",
    );
    let e2 = super::MintEnvelope::new(
        "tok2",
        Utc::now() + chrono::Duration::hours(1),
        "id2",
        "gcp",
        "viewer",
    );
    let output = super::format_mint_output(&[e1, e2]);
    assert!(
        !output.contains('\n'),
        "mint output must be single-line JSON"
    );
}

#[test]
fn redaction_exception_mint_stdout_contains_raw_token() {
    // The mint envelope intentionally contains the raw token value.
    // This is the whole point of the mint subcommand.
    let envelope = super::MintEnvelope::new(
        "raw-secret-credential-12345",
        Utc::now() + chrono::Duration::hours(1),
        "tid",
        "aws",
        "admin",
    );
    let json = envelope.to_json();
    assert!(
        json.contains("raw-secret-credential-12345"),
        "mint stdout must contain the raw token value"
    );
}

#[test]
fn redaction_exception_stderr_still_redacted() {
    // still applies to stderr/log messages.
    // MintEnvelope must provide a redacted form for logging purposes.
    let envelope = super::MintEnvelope::new(
        "secret-that-should-not-appear-in-logs",
        Utc::now() + chrono::Duration::hours(1),
        "tid",
        "aws",
        "admin",
    );
    let log_msg = envelope.to_log_string();
    assert!(
        !log_msg.contains("secret-that-should-not-appear-in-logs"),
        "stderr/log output must still redact token value, got: {}",
        log_msg
    );
}

#[test]
fn redaction_exception_log_string_contains_provider_and_role() {
    let envelope = super::MintEnvelope::new(
        "secret",
        Utc::now() + chrono::Duration::hours(1),
        "tid",
        "vault",
        "deployer",
    );
    let log_msg = envelope.to_log_string();
    assert!(
        log_msg.contains("vault"),
        "log string should contain provider"
    );
    assert!(
        log_msg.contains("deployer"),
        "log string should contain role"
    );
}

#[test]
#[verifies("rule_cross_terminal_refusal", examples)]
fn terminal_detection_rejects_tty_stdout() {
    // If stdout is a terminal, mint should be rejected.
    let result = super::check_stdout_not_terminal(true, false);
    assert!(result.is_err(), "mint to terminal stdout must be rejected");
}

#[test]
fn terminal_detection_allows_pipe_stdout() {
    // If stdout is a pipe (not a terminal), mint is allowed.
    let result = super::check_stdout_not_terminal(false, false);
    assert!(result.is_ok(), "mint to piped stdout must be allowed");
}

#[test]
fn terminal_detection_force_overrides_tty_check() {
    // --force flag overrides the terminal check.
    let result = super::check_stdout_not_terminal(true, true);
    assert!(result.is_ok(), "--force must override terminal detection");
}

#[test]
fn terminal_detection_exit_code_is_64() {
    // The exit code for terminal detection failure is 64 (usage error).
    let err = super::check_stdout_not_terminal(true, false).unwrap_err();
    assert_eq!(
        err.exit_code().as_raw(),
        64,
        "terminal detection failure must exit with code 64"
    );
}

#[test]
fn terminal_detection_error_message_warns_about_scrollback() {
    let err = super::check_stdout_not_terminal(true, false).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("terminal") || msg.to_lowercase().contains("tty"),
        "error message must mention terminal/tty, got: {}",
        msg
    );
}

#[test]
fn terminal_detection_error_message_mentions_force_flag() {
    let err = super::check_stdout_not_terminal(true, false).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("--force"),
        "error message must mention --force flag, got: {}",
        msg
    );
}

#[test]
fn mint_envelope_debug_does_not_expose_raw_token() {
    // Debug output must redact the token value.
    let envelope = super::MintEnvelope::new(
        "super-secret-credential-that-must-not-leak",
        Utc::now() + chrono::Duration::hours(1),
        "tid",
        "aws",
        "admin",
    );
    let debug = format!("{:?}", envelope);
    assert!(
        !debug.contains("super-secret-credential-that-must-not-leak"),
        "Debug must not expose raw token, got: {}",
        debug
    );
}

#[test]
fn mint_envelope_debug_shows_metadata() {
    let envelope = super::MintEnvelope::new(
        "secret",
        Utc::now() + chrono::Duration::hours(1),
        "tid-xyz",
        "vault",
        "deployer",
    );
    let debug = format!("{:?}", envelope);
    assert!(debug.contains("vault"), "Debug should show provider");
    assert!(debug.contains("deployer"), "Debug should show role");
    assert!(debug.contains("tid-xyz"), "Debug should show token_id");
    assert!(
        debug.contains("MintEnvelope"),
        "Debug should show type name"
    );
}

#[test]
fn mint_envelope_is_not_clone() {
    static_assertions::assert_not_impl_any!(super::MintEnvelope: Clone);
}

#[test]
fn revoke_input_rejects_combined_token_equals_value_flag() {
    // --token=<secret> combined form must also be rejected.
    let result = super::validate_revoke_args(&[
        "noscope".to_string(),
        "revoke".to_string(),
        "--token=actual-secret-value".to_string(),
    ]);
    assert!(
        result.is_err(),
        "--token=value combined form must be rejected"
    );
}

#[test]
fn revoke_input_allows_token_id_equals_combined_form() {
    // --token-id=tok-123 is safe (opaque identifier, not a secret)
    let result = super::validate_revoke_args(&[
        "noscope".to_string(),
        "revoke".to_string(),
        "--token-id=tok-123".to_string(),
        "--provider".to_string(),
        "aws".to_string(),
    ]);
    assert!(
        result.is_ok(),
        "--token-id=value combined form should be allowed"
    );
}

#[test]
fn revoke_input_from_mint_json_array_element() {
    // outputs a JSON array. Revoke should handle a single element
    // extracted from that array.
    let array_element = r#"{"token":"secret","expires_at":"2025-01-01T00:00:00Z","token_id":"tok-from-array","provider":"aws","role":"admin"}"#;
    let input = super::RevokeInput::from_mint_json(array_element).unwrap();
    assert_eq!(input.token_id(), "tok-from-array");
    assert_eq!(input.provider(), "aws");
}

#[test]
fn mint_error_implements_std_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<super::MintError>();
}

#[test]
fn format_mint_output_handles_special_characters_in_token() {
    // Tokens may contain characters that need JSON escaping.
    let envelope = super::MintEnvelope::new(
        "tok-with-\"quotes\"-and-\\backslashes",
        Utc::now() + chrono::Duration::hours(1),
        "tid",
        "aws",
        "admin",
    );
    let output = super::format_mint_output(&[envelope]);
    let parsed: Value = serde_json::from_str(&output).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(
        arr[0]["token"].as_str().unwrap(),
        "tok-with-\"quotes\"-and-\\backslashes",
        "Special characters must survive JSON round-trip"
    );
}

#[test]
fn mint_envelope_from_scoped_token_without_token_id() {
    // When ScopedToken has no token_id, envelope should use empty string.
    use crate::core::token::ScopedToken;
    use secrecy::SecretString;

    let token = ScopedToken::new(
        SecretString::from("secret".to_string()),
        "admin",
        Utc::now() + chrono::Duration::hours(1),
        None,
        "aws",
    );
    let envelope = super::MintEnvelope::from_scoped_token(&token);
    let json = envelope.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["token_id"].as_str().unwrap(),
        "",
        "Missing token_id should produce empty string"
    );
}

#[test]
fn validate_mint_args_returns_validated_ttl() {
    let result = super::validate_mint_args(Some(7200), &["aws".to_string()], "admin");
    assert_eq!(
        result.unwrap(),
        7200,
        "validate_mint_args should return the validated TTL value"
    );
}

#[test]
fn mint_error_display_for_invalid_input() {
    let err = super::MintError::InvalidInput {
        message: "test error".to_string(),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("test error"),
        "Display should include the message"
    );
}

#[test]
fn terminal_detection_pipe_with_force_also_works() {
    // Edge case: force=true, is_tty=false should still succeed
    let result = super::check_stdout_not_terminal(false, true);
    assert!(result.is_ok(), "Non-terminal with --force should succeed");
}
