use chrono::{DateTime, Utc};
use provenance_macros::verifies;
use serde_json::Value;
use std::time::Duration;

// ---- Event type coverage: all required event types exist ----

#[test]
fn structured_event_logging_mint_start_event() {
    // mint start event must be representable
    let event = super::Event::new(super::EventType::MintStart, "aws");
    assert_eq!(event.event_type(), &super::EventType::MintStart);
    assert_eq!(event.provider(), "aws");
}

#[test]
fn structured_event_logging_mint_success_event() {
    let event = super::Event::new(super::EventType::MintSuccess, "aws");
    assert_eq!(event.event_type(), &super::EventType::MintSuccess);
}

#[test]
fn structured_event_logging_mint_fail_event() {
    let event = super::Event::new(super::EventType::MintFail, "aws");
    assert_eq!(event.event_type(), &super::EventType::MintFail);
}

#[test]
fn structured_event_logging_refresh_start_event() {
    let event = super::Event::new(super::EventType::RefreshStart, "gcp");
    assert_eq!(event.event_type(), &super::EventType::RefreshStart);
}

#[test]
fn structured_event_logging_refresh_success_event() {
    let event = super::Event::new(super::EventType::RefreshSuccess, "gcp");
    assert_eq!(event.event_type(), &super::EventType::RefreshSuccess);
}

#[test]
fn structured_event_logging_refresh_fail_event() {
    let event = super::Event::new(super::EventType::RefreshFail, "gcp");
    assert_eq!(event.event_type(), &super::EventType::RefreshFail);
}

#[test]
fn structured_event_logging_revoke_start_event() {
    let event = super::Event::new(super::EventType::RevokeStart, "vault");
    assert_eq!(event.event_type(), &super::EventType::RevokeStart);
}

#[test]
fn structured_event_logging_revoke_success_event() {
    let event = super::Event::new(super::EventType::RevokeSuccess, "vault");
    assert_eq!(event.event_type(), &super::EventType::RevokeSuccess);
}

#[test]
fn structured_event_logging_revoke_fail_event() {
    let event = super::Event::new(super::EventType::RevokeFail, "vault");
    assert_eq!(event.event_type(), &super::EventType::RevokeFail);
}

#[test]
fn structured_event_logging_child_spawn_event() {
    let event = super::Event::new(super::EventType::ChildSpawn, "aws");
    assert_eq!(event.event_type(), &super::EventType::ChildSpawn);
}

#[test]
fn structured_event_logging_child_exit_event() {
    let event = super::Event::new(super::EventType::ChildExit, "aws");
    assert_eq!(event.event_type(), &super::EventType::ChildExit);
}

#[test]
fn structured_event_logging_signal_received_event() {
    let event = super::Event::new(super::EventType::SignalReceived, "aws");
    assert_eq!(event.event_type(), &super::EventType::SignalReceived);
}

#[test]
fn structured_event_logging_signal_forwarded_event() {
    let event = super::Event::new(super::EventType::SignalForwarded, "aws");
    assert_eq!(event.event_type(), &super::EventType::SignalForwarded);
}

// ---- JSON output format ----

#[test]
fn structured_event_logging_json_contains_timestamp() {
    // each event includes timestamp
    let event = super::Event::new(super::EventType::MintStart, "aws");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).expect("event must serialize to valid JSON");
    assert!(
        parsed.get("timestamp").is_some(),
        "JSON must contain 'timestamp' field, got: {}",
        json
    );
    // Timestamp must be a valid ISO 8601 / RFC 3339 string
    let ts_str = parsed["timestamp"].as_str().unwrap();
    let _parsed_ts: DateTime<Utc> = ts_str.parse().expect("timestamp must be valid RFC 3339");
}

#[test]
fn structured_event_logging_json_contains_type() {
    // each event includes type
    let event = super::Event::new(super::EventType::MintSuccess, "aws");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.get("type").is_some(),
        "JSON must contain 'type' field, got: {}",
        json
    );
    assert_eq!(parsed["type"].as_str().unwrap(), "mint_success");
}

#[test]
fn structured_event_logging_json_contains_provider() {
    // each event includes provider
    let event = super::Event::new(super::EventType::MintStart, "vault");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["provider"].as_str().unwrap(),
        "vault",
        "JSON must contain correct provider"
    );
}

#[test]
fn structured_event_logging_json_contains_redacted_token_id() {
    // each event includes redacted token ID
    let mut event = super::Event::new(super::EventType::MintSuccess, "aws");
    event.set_token_id("tok-abc-123");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.get("token_id").is_some(),
        "JSON must contain 'token_id' field, got: {}",
        json
    );
    assert_eq!(parsed["token_id"].as_str().unwrap(), "tok-abc-123");
}

#[test]
fn structured_event_logging_json_token_id_null_when_absent() {
    // When no token ID is set, the field should be null
    let event = super::Event::new(super::EventType::MintStart, "aws");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed["token_id"].is_null(),
        "token_id must be null when not set, got: {}",
        json
    );
}

#[test]
fn structured_event_logging_json_contains_duration() {
    // each event includes duration
    let mut event = super::Event::new(super::EventType::MintSuccess, "aws");
    event.set_duration(Duration::from_millis(1234));
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.get("duration_ms").is_some(),
        "JSON must contain 'duration_ms' field, got: {}",
        json
    );
    assert_eq!(parsed["duration_ms"].as_u64().unwrap(), 1234);
}

#[test]
fn structured_event_logging_json_duration_null_when_absent() {
    let event = super::Event::new(super::EventType::MintStart, "aws");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed["duration_ms"].is_null(),
        "duration_ms must be null when not set, got: {}",
        json
    );
}

#[test]
fn structured_event_logging_json_is_single_line() {
    // JSON-per-line format — no embedded newlines
    let mut event = super::Event::new(super::EventType::MintSuccess, "aws");
    event.set_token_id("tok-123");
    event.set_duration(Duration::from_secs(5));
    let json = event.to_json();
    assert!(
        !json.contains('\n'),
        "JSON output must be single-line, got: {}",
        json
    );
}

#[test]
fn structured_event_logging_json_is_valid_json() {
    // Every event must produce valid JSON
    let mut event = super::Event::new(super::EventType::RefreshFail, "gcp");
    event.set_token_id("tok-xyz");
    event.set_duration(Duration::from_millis(42));
    let json = event.to_json();
    let parsed: Result<Value, _> = serde_json::from_str(&json);
    assert!(
        parsed.is_ok(),
        "Must produce valid JSON, got parse error for: {}",
        json
    );
}

// ---- Event type serialization names ----

#[test]
fn structured_event_logging_event_type_names() {
    // verify all event type names are snake_case strings
    let cases = vec![
        (super::EventType::MintStart, "mint_start"),
        (super::EventType::MintSuccess, "mint_success"),
        (super::EventType::MintFail, "mint_fail"),
        (super::EventType::RefreshStart, "refresh_start"),
        (super::EventType::RefreshSuccess, "refresh_success"),
        (super::EventType::RefreshFail, "refresh_fail"),
        (super::EventType::RevokeStart, "revoke_start"),
        (super::EventType::RevokeSuccess, "revoke_success"),
        (super::EventType::RevokeFail, "revoke_fail"),
        (super::EventType::ChildSpawn, "child_spawn"),
        (super::EventType::ChildExit, "child_exit"),
        (super::EventType::SignalReceived, "signal_received"),
        (super::EventType::SignalForwarded, "signal_forwarded"),
    ];
    for (event_type, expected_name) in cases {
        assert_eq!(
            event_type.as_str(),
            expected_name,
            "EventType {:?} must serialize as '{}'",
            event_type,
            expected_name
        );
    }
}

// ---- Log format selector ----

#[test]
fn structured_event_logging_log_format_json() {
    // --log-format json selects JSON output
    let format = super::LogFormat::parse("json");
    assert!(
        matches!(format, Some(super::LogFormat::Json)),
        "\"json\" must parse to LogFormat::Json"
    );
}

#[test]
fn structured_event_logging_log_format_text() {
    // Default/text format is also a valid option
    let format = super::LogFormat::parse("text");
    assert!(
        matches!(format, Some(super::LogFormat::Text)),
        "\"text\" must parse to LogFormat::Text"
    );
}

#[test]
#[verifies("rule_events_log_format_strict", examples)]
fn structured_event_logging_log_format_unknown_returns_none() {
    let format = super::LogFormat::parse("xml");
    assert!(format.is_none(), "Unknown format must return None");
}

// ---- EventEmitter formats based on LogFormat ----

#[test]
fn structured_event_logging_emitter_json_format_output() {
    // When LogFormat::Json is selected, format_event produces JSON
    let emitter = super::EventEmitter::new(super::LogFormat::Json);
    let event = super::Event::new(super::EventType::MintStart, "aws");
    let output = emitter.format_event(&event);
    let parsed: Result<Value, _> = serde_json::from_str(&output);
    assert!(
        parsed.is_ok(),
        "JSON format emitter must produce valid JSON, got: {}",
        output
    );
}

#[test]
fn structured_event_logging_emitter_text_format_output() {
    // When LogFormat::Text is selected, format_event produces human-readable text
    let emitter = super::EventEmitter::new(super::LogFormat::Text);
    let event = super::Event::new(super::EventType::MintStart, "aws");
    let output = emitter.format_event(&event);
    // Text format should NOT be valid JSON (it's human-readable)
    let parsed: Result<Value, _> = serde_json::from_str(&output);
    assert!(
        parsed.is_err(),
        "Text format should not be valid JSON, got: {}",
        output
    );
    // But should contain the event type and provider
    assert!(
        output.contains("mint_start"),
        "Text must contain event type: {}",
        output
    );
    assert!(
        output.contains("aws"),
        "Text must contain provider: {}",
        output
    );
}

#[test]
#[verifies("rule_events_single_line", examples)]
fn structured_event_logging_emitter_json_single_line() {
    let emitter = super::EventEmitter::new(super::LogFormat::Json);
    let mut event = super::Event::new(super::EventType::RevokeSuccess, "vault");
    event.set_token_id("tok-456");
    event.set_duration(Duration::from_millis(100));
    let output = emitter.format_event(&event);
    assert!(
        !output.contains('\n'),
        "JSON emitter output must be single-line, got: {}",
        output
    );
}

// ---- Token ID must be the redacted form, not raw ----

#[test]
fn structured_event_logging_token_id_is_redacted_not_raw() {
    // says "redacted token ID" — if someone passes a raw token
    // value as the token_id, it should be stored as-is (the caller is
    // responsible for passing the redacted form). But we verify that
    // the Event API accepts and stores the redacted token ID.
    let mut event = super::Event::new(super::EventType::MintSuccess, "aws");
    event.set_token_id("[redacted:tok-abc]");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["token_id"].as_str().unwrap(), "[redacted:tok-abc]");
}

// ---- Extra fields (child exit code, signal number) ----

#[test]
fn structured_event_logging_child_exit_includes_exit_code() {
    let mut event = super::Event::new(super::EventType::ChildExit, "aws");
    event.set_exit_code(42);
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["exit_code"].as_i64().unwrap(),
        42,
        "child_exit event must include exit_code"
    );
}

#[test]
fn structured_event_logging_signal_received_includes_signal() {
    let mut event = super::Event::new(super::EventType::SignalReceived, "aws");
    event.set_signal(15); // SIGTERM
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["signal"].as_i64().unwrap(),
        15,
        "signal_received event must include signal number"
    );
}

#[test]
fn structured_event_logging_signal_forwarded_includes_signal() {
    let mut event = super::Event::new(super::EventType::SignalForwarded, "aws");
    event.set_signal(9); // SIGKILL
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["signal"].as_i64().unwrap(), 9,);
}

// ---- Event does NOT leak raw token values ----

#[test]
fn structured_event_logging_json_never_contains_raw_secret() {
    // Even if someone misuses the API, Debug/Display should not leak
    let event = super::Event::new(super::EventType::MintSuccess, "aws");
    let json = event.to_json();
    let debug = format!("{:?}", event);
    // No field named "secret" or "value" should exist
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.get("secret").is_none(),
        "JSON must not contain a 'secret' field"
    );
    assert!(
        parsed.get("value").is_none(),
        "JSON must not contain a 'value' field"
    );
    // Debug format should also not leak
    assert!(!debug.contains("secret"), "Debug must not contain 'secret'");
}

// ---- Timestamp is close to now ----

#[test]
fn structured_event_logging_timestamp_is_current() {
    let before = Utc::now();
    let event = super::Event::new(super::EventType::MintStart, "aws");
    let after = Utc::now();
    let ts = event.timestamp();
    assert!(
        ts >= before && ts <= after,
        "Timestamp should be between before ({}) and after ({}), got: {}",
        before,
        after,
        ts
    );
}

// ---- Error message field for fail events ----

#[test]
fn structured_event_logging_fail_event_includes_error_message() {
    let mut event = super::Event::new(super::EventType::MintFail, "aws");
    event.set_error("provider timed out after 30s");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["error"].as_str().unwrap(),
        "provider timed out after 30s"
    );
}

#[test]
fn structured_event_logging_error_null_when_not_set() {
    let event = super::Event::new(super::EventType::MintStart, "aws");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["error"].is_null(), "error must be null when not set");
}

#[test]
fn structured_event_logging_all_fields_set_simultaneously() {
    // Integration test: event with every optional field populated
    let mut event = super::Event::new(super::EventType::ChildExit, "aws");
    event.set_token_id("[redacted:tok-full]");
    event.set_duration(Duration::from_millis(999));
    event.set_exit_code(0);
    event.set_signal(15);
    event.set_error("graceful shutdown");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"].as_str().unwrap(), "child_exit");
    assert_eq!(parsed["provider"].as_str().unwrap(), "aws");
    assert_eq!(parsed["token_id"].as_str().unwrap(), "[redacted:tok-full]");
    assert_eq!(parsed["duration_ms"].as_u64().unwrap(), 999);
    assert_eq!(parsed["exit_code"].as_i64().unwrap(), 0);
    assert_eq!(parsed["signal"].as_i64().unwrap(), 15);
    assert_eq!(parsed["error"].as_str().unwrap(), "graceful shutdown");
}

#[test]
fn structured_event_logging_text_format_escapes_quotes_in_error() {
    // Error messages with embedded quotes must not break text format
    let emitter = super::EventEmitter::new(super::LogFormat::Text);
    let mut event = super::Event::new(super::EventType::MintFail, "aws");
    event.set_error("failed: \"connection refused\"");
    let output = emitter.format_event(&event);
    // The embedded quotes must be escaped
    assert!(
        output.contains("\\\"connection refused\\\""),
        "Text format must escape embedded quotes, got: {}",
        output
    );
}

#[test]
fn structured_event_logging_json_error_with_quotes() {
    // JSON format handles quotes via serde — verify it works
    let mut event = super::Event::new(super::EventType::RefreshFail, "gcp");
    event.set_error("key \"abc\" not found");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["error"].as_str().unwrap(), "key \"abc\" not found");
}

#[test]
fn structured_event_logging_large_duration_does_not_panic() {
    // u128 as_millis truncated to u64 — verify no panic
    let mut event = super::Event::new(super::EventType::MintSuccess, "aws");
    event.set_duration(Duration::from_secs(u64::MAX / 1000));
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed["duration_ms"].as_u64().is_some(),
        "Large duration must serialize without panic"
    );
}

#[test]
fn structured_event_logging_zero_duration() {
    let mut event = super::Event::new(super::EventType::MintSuccess, "aws");
    event.set_duration(Duration::ZERO);
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["duration_ms"].as_u64().unwrap(), 0);
}

#[test]
fn structured_event_logging_negative_exit_code() {
    // Processes can exit with negative codes on some platforms
    let mut event = super::Event::new(super::EventType::ChildExit, "aws");
    event.set_exit_code(-1);
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["exit_code"].as_i64().unwrap(), -1);
}

#[test]
fn structured_event_logging_event_type_display_matches_as_str() {
    // Display impl must produce the same string as as_str()
    let types = vec![
        super::EventType::MintStart,
        super::EventType::ChildExit,
        super::EventType::SignalForwarded,
    ];
    for t in types {
        assert_eq!(
            format!("{}", t),
            t.as_str(),
            "Display and as_str must match for {:?}",
            t
        );
    }
}

#[test]
fn structured_event_logging_log_format_parse_is_case_sensitive() {
    // CLI convention: lowercase flags
    assert!(super::LogFormat::parse("JSON").is_none());
    assert!(super::LogFormat::parse("Text").is_none());
    assert!(super::LogFormat::parse("json").is_some());
}

#[test]
fn structured_event_logging_empty_provider_name() {
    // Edge case: empty provider string should not panic
    let event = super::Event::new(super::EventType::MintStart, "");
    let json = event.to_json();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["provider"].as_str().unwrap(), "");
}
