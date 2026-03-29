# Provenance Draft: noscope-4of

## Thread Message (for requirement jn780pzjkgn2dq9geb9mqq7b4h83vcb9)

Implemented NS-070 (structured event logging) in src/event.rs.

### What was built

- `EventType` enum covering all 13 required event types: mint/refresh/revoke start/success/fail, child spawn/exit, signal received/forwarded
- `Event` struct with mandatory fields (timestamp, type, provider) and optional fields (redacted token ID, duration_ms, exit_code, signal, error)
- `to_json()` method producing single-line JSON (JSON-per-line format for stderr)
- `LogFormat` enum for --log-format flag selection (json/text)
- `EventEmitter` for format-dispatched event rendering
- Text format with proper quote escaping in error messages

### Design decisions

- `Event` does NOT derive `Serialize` — an internal `SerializableEvent<'a>` borrows from `Event` to keep Serialize out of the public API, matching the crate's pattern of not putting serde traits on public types (see: `ScopedToken` deliberately avoids `Serialize`)
- `token_id` field is caller-provided (redacted form) — the Event type has no access to raw token values and never stores them
- `serde` and `serde_json` added as production dependencies (required for JSON serialization)
- `chrono` gains `serde` feature for timestamp formatting
- `LogFormat::parse()` instead of `from_str()` to avoid clippy's `should_implement_trait` warning without the overhead of `FromStr` trait

### Test coverage

46 tests total for NS-070:
- 13 event type existence tests
- 10 JSON field presence/correctness tests
- 3 log format parsing tests
- 3 emitter format-dispatch tests
- 5 optional field tests (token_id, duration, exit_code, signal, error)
- 3 security tests (no raw secrets leak)
- 9 edge case tests from Linus review (quote escaping, large duration, zero duration, negative exit code, empty provider, all-fields-set, Display/as_str consistency, case sensitivity)

## New Artifacts (if any)

- type: resolution
  content: NS-070 implemented via Event/EventType/LogFormat/EventEmitter types in src/event.rs. JSON-per-line format to stderr. 46 tests. No raw token values ever stored in events.
