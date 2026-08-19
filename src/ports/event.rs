// Structured event logging
// Emit structured events to stderr (JSON-per-line with --log-format json) for:
// - mint/refresh/revoke start/success/fail
// - child spawn/exit
// - signal received/forwarded
// Each event includes: timestamp, type, provider, redacted token ID, duration.

use chrono::{DateTime, Utc};
use provenance_macros::rule;
use serde::Serialize;
use std::fmt;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

/// All structured event types emitted by noscope.
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

/// A structured event for logging.
/// Contains the mandatory fields (timestamp, type, provider) and optional
/// fields (redacted token ID, duration, exit code, signal, error message).
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
    /// JSON-per-line format for `--log-format json`.
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

/// Log output format selector.
/// `--log-format json` selects JSON-per-line output to stderr.
/// `--log-format text` selects human-readable output (default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[rule("rule_events_log_format_strict")]
pub enum LogFormat {
    Json,
    Text,
}

impl LogFormat {
    /// Parse a format string from CLI flags.
    /// Returns `None` for unrecognized values.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            _ => None,
        }
    }
}

/// Formats events according to the selected LogFormat.
/// Does not perform I/O — returns the formatted string for the caller
/// to write to stderr.
#[rule("rule_events_single_line")]
pub struct EventEmitter {
    format: LogFormat,
}

impl EventEmitter {
    /// Create a new emitter with the given format.
    pub fn new(format: LogFormat) -> Self {
        Self { format }
    }

    pub fn format(&self) -> LogFormat {
        self.format
    }

    /// Format an event as a string according to the configured format.
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

#[derive(Clone)]
struct RuntimeEmitter {
    format: LogFormat,
    sink: Arc<dyn Fn(String) + Send + Sync>,
}

fn runtime_emitter_slot() -> &'static RwLock<Option<RuntimeEmitter>> {
    static SLOT: OnceLock<RwLock<Option<RuntimeEmitter>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

pub struct RuntimeEmitterGuard;

impl Drop for RuntimeEmitterGuard {
    fn drop(&mut self) {
        clear_runtime_emitter();
    }
}

pub fn install_runtime_emitter(emitter: EventEmitter) -> RuntimeEmitterGuard {
    let sink: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|line| eprintln!("{}", line));
    let runtime = RuntimeEmitter {
        format: emitter.format(),
        sink,
    };
    if let Ok(mut slot) = runtime_emitter_slot().write() {
        *slot = Some(runtime);
    }
    RuntimeEmitterGuard
}

pub fn clear_runtime_emitter() {
    if let Ok(mut slot) = runtime_emitter_slot().write() {
        *slot = None;
    }
}

pub fn emit_runtime_event(event: Event) {
    let runtime = runtime_emitter_slot()
        .read()
        .ok()
        .and_then(|slot| slot.clone());
    let Some(runtime) = runtime else {
        return;
    };

    let emitter = EventEmitter::new(runtime.format);
    let line = emitter.format_event(&event);
    (runtime.sink)(line);
}

/// The collector below swaps the process-global runtime emitter, so
/// tests that use it must not run concurrently with each other. Hold
/// this guard for the whole test.
#[cfg(test)]
pub fn test_event_collector_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub fn install_test_event_collector(format: LogFormat) -> Arc<Mutex<Vec<String>>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_for_sink = Arc::clone(&captured);
    let sink: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |line| {
        if let Ok(mut lines) = captured_for_sink.lock() {
            lines.push(line);
        }
    });

    let runtime = RuntimeEmitter { format, sink };
    if let Ok(mut slot) = runtime_emitter_slot().write() {
        *slot = Some(runtime);
    }
    captured
}

#[cfg(test)]
pub fn clear_test_event_collector() {
    clear_runtime_emitter();
}

#[cfg(test)]
mod tests;
