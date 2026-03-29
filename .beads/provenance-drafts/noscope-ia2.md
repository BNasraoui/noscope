# Provenance Draft: noscope-ia2

## Thread Message (for requirement jn77se3zt6bbvvrsw8yakg72e983taj2)

Implemented refresh failure policy module (`src/refresh.rs`) covering all 5 rules:

- **NS-008**: `RefreshPolicy::on_refresh_failure()` never returns `KillChild`. Returns `Retry` with backoff for retryable failures, `AllowExpiry` when retries exhausted. Always sets `log_warning: true`. Tested exhaustively across 0..100 attempts.
- **NS-025**: `rotate_mode_startup_warning()` returns a static warning string mentioning "point-in-time" and "environment variable" limitations for rotate mode.
- **NS-030**: `RetryParams` encodes the exact spec: base 1s, 2x multiplier, max 4 retries, +/-25% jitter. `max_retry_window()` validates worst-case window <= 50% remaining lifetime. Per-attempt delay check in `on_refresh_failure()` caps individual retry delays. Overflow-safe via `checked_pow` + saturation.
- **NS-031**: `RefreshTracker` is per-credential — each credential gets its own instance with independent failure counters. Tests prove mutation on one tracker does not affect another.
- **NS-032**: `should_attempt_refresh()` always returns `true` — failure windows never permanently disable refresh. `reset_retry_window()` clears the failure count for a fresh retry window at the next normal interval.

Design decisions:
- `KillChild` variant exists in `RefreshAction` solely as a negative constraint testable by `!matches!(action, KillChild)`. No code path produces it.
- Jitter uses a cheap thread-local xorshift64 PRNG (not cryptographic, only for timing). Zero-seed fixup prevents degenerate all-same-jitter behavior.
- `consecutive_failures` uses `saturating_add` to prevent u32 wrap.

27 tests total (24 rule tests + 3 edge case tests from review).
