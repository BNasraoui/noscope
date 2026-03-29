// NS-070: Structured event logging
//
// Emit structured events to stderr (JSON-per-line with --log-format json) for:
// - mint/refresh/revoke start/success/fail
// - child spawn/exit
// - signal received/forwarded
//
// Each event includes: timestamp, type, provider, redacted token ID, duration.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;
use std::time::Duration;

/// NS-070: All structured event types emitted by noscope.
///
/// Covers the three credential lifecycle operations (mint/refresh/revoke)
/// in three phases (start/success/fail), plus child process and signal events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    MintStart,
    MintSuccess,
    MintFail,
    RefreshStart,
    RefreshSuccess,
    RefreshFail,
    RevokeStart,
    RevokeSuccess,
    RevokeFail,
    ChildSpawn,
    ChildExit,
    SignalReceived,
    SignalForwarded,
}

impl EventType {
    /// Return the snake_case string representation of this event type.
    ///
    /// Used as the `"type"` field value in JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MintStart => "mint_start",
            Self::MintSuccess => "mint_success",
            Self::MintFail => "mint_fail",
            Self::RefreshStart => "refresh_start",
            Self::RefreshSuccess => "refresh_success",
            Self::RefreshFail => "refresh_fail",
            Self::RevokeStart => "revoke_start",
            Self::RevokeSuccess => "revoke_success",
            Self::RevokeFail => "revoke_fail",
            Self::ChildSpawn => "child_spawn",
            Self::ChildExit => "child_exit",
            Self::SignalReceived => "signal_received",
            Self::SignalForwarded => "signal_forwarded",
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// NS-070: A structured event for logging.
///
/// Contains the mandatory fields (timestamp, type, provider) and optional
/// fields (redacted token ID, duration, exit code, signal, error message).
///
/// The event never stores raw token values — the `token_id` field holds
/// the redacted identifier (e.g. `[redacted:tok-abc]` or `abcdefgh...`).
#[derive(Debug)]
pub struct Event {
    timestamp: DateTime<Utc>,
    event_type: EventType,
    provider: String,
    token_id: Option<String>,
    duration_ms: Option<u64>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    error: Option<String>,
}

impl Event {
    /// Create a new event with the given type and provider.
    ///
    /// Timestamp is captured at construction time (Utc::now()).
    /// Optional fields default to None.
    pub fn new(event_type: EventType, provider: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            provider: provider.to_string(),
            token_id: None,
            duration_ms: None,
            exit_code: None,
            signal: None,
            error: None,
        }
    }

    /// Get the event type.
    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// Get the provider name.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Set the redacted token ID.
    ///
    /// The caller is responsible for passing the redacted form (from
    /// `RedactedToken::to_string()` or a provider-supplied token ID).
    pub fn set_token_id(&mut self, id: &str) {
        self.token_id = Some(id.to_string());
    }

    /// Set the duration in milliseconds.
    pub fn set_duration(&mut self, duration: Duration) {
        self.duration_ms = Some(duration.as_millis() as u64);
    }

    /// Set the child process exit code (for ChildExit events).
    pub fn set_exit_code(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    /// Set the signal number (for SignalReceived/SignalForwarded events).
    pub fn set_signal(&mut self, signal: i32) {
        self.signal = Some(signal);
    }

    /// Set an error message (for *Fail events).
    pub fn set_error(&mut self, message: &str) {
        self.error = Some(message.to_string());
    }

    /// Serialize this event to a single-line JSON string.
    ///
    /// NS-070: JSON-per-line format for `--log-format json`.
    pub fn to_json(&self) -> String {
        let serializable = SerializableEvent {
            timestamp: self.timestamp.to_rfc3339(),
            event_type: self.event_type.as_str(),
            provider: &self.provider,
            token_id: self.token_id.as_deref(),
            duration_ms: self.duration_ms,
            exit_code: self.exit_code,
            signal: self.signal,
            error: self.error.as_deref(),
        };
        // serde_json::to_string produces compact single-line JSON by default.
        serde_json::to_string(&serializable).expect("Event serialization should never fail")
    }
}

/// Internal serialization helper — keeps Serialize out of the public Event type.
///
/// Field names match the JSON output contract:
/// - `type` (via rename) instead of `event_type`
/// - `duration_ms` for millisecond precision
#[derive(Serialize)]
struct SerializableEvent<'a> {
    timestamp: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    provider: &'a str,
    token_id: Option<&'a str>,
    duration_ms: Option<u64>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    error: Option<&'a str>,
}

/// NS-070: Log output format selector.
///
/// `--log-format json` selects JSON-per-line output to stderr.
/// `--log-format text` selects human-readable output (default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Text,
}

impl LogFormat {
    /// Parse a format string from CLI flags.
    ///
    /// Returns `None` for unrecognized values.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            _ => None,
        }
    }
}

/// NS-070: Formats events according to the selected LogFormat.
///
/// Does not perform I/O — returns the formatted string for the caller
/// to write to stderr.
pub struct EventEmitter {
    format: LogFormat,
}

impl EventEmitter {
    /// Create a new emitter with the given format.
    pub fn new(format: LogFormat) -> Self {
        Self { format }
    }

    /// Format an event as a string according to the configured format.
    ///
    /// - `Json`: single-line JSON (same as `event.to_json()`)
    /// - `Text`: human-readable `timestamp type provider [token_id] [duration]`
    pub fn format_event(&self, event: &Event) -> String {
        match self.format {
            LogFormat::Json => event.to_json(),
            LogFormat::Text => {
                let mut out = format!(
                    "[{}] {} provider={}",
                    event.timestamp.to_rfc3339(),
                    event.event_type.as_str(),
                    event.provider,
                );
                if let Some(ref id) = event.token_id {
                    out.push_str(&format!(" token_id={}", id));
                }
                if let Some(ms) = event.duration_ms {
                    out.push_str(&format!(" duration={}ms", ms));
                }
                if let Some(code) = event.exit_code {
                    out.push_str(&format!(" exit_code={}", code));
                }
                if let Some(sig) = event.signal {
                    out.push_str(&format!(" signal={}", sig));
                }
                if let Some(ref err) = event.error {
                    // Escape embedded quotes to keep the text format parseable.
                    let escaped = err.replace('\\', "\\\\").replace('"', "\\\"");
                    out.push_str(&format!(" error=\"{}\"", escaped));
                }
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use std::time::Duration;

    // =========================================================================
    // NS-070: Structured event logging — emit structured events to stderr
    // (JSON-per-line with --log-format json) for: mint/refresh/revoke
    // start/success/fail, child spawn/exit, signal received/forwarded;
    // each event includes timestamp, type, provider, redacted token ID,
    // duration.
    // =========================================================================

    // ---- Event type coverage: all required event types exist ----

    #[test]
    fn structured_event_logging_mint_start_event() {
        // NS-070: mint start event must be representable
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
        // NS-070: each event includes timestamp
        let event = super::Event::new(super::EventType::MintStart, "aws");
        let json = event.to_json();
        let parsed: Value =
            serde_json::from_str(&json).expect("event must serialize to valid JSON");
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
        // NS-070: each event includes type
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
        // NS-070: each event includes provider
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
        // NS-070: each event includes redacted token ID
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
        // NS-070: each event includes duration
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
        // NS-070: JSON-per-line format — no embedded newlines
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
        // NS-070: verify all event type names are snake_case strings
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
        // NS-070: --log-format json selects JSON output
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
        // NS-070 says "redacted token ID" — if someone passes a raw token
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

    // =========================================================================
    // Edge cases discovered during Linus review.
    // =========================================================================

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
}
