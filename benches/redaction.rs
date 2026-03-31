use criterion::{black_box, criterion_group, criterion_main, Criterion};
use noscope::redaction::RedactedToken;
use noscope::token::ScopedToken;
use secrecy::SecretString;

/// Realistic JWT for benchmarking. Defined once to avoid duplication.
const BENCH_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.\
    NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteb\
    d0sBhqRXBYM2G-JypJlAF8GJfMxLnB_edGvAB_lVqD-9N5Y2x0GjD2cYE_MN08jvYh6VN3A-qAAJQ";

/// Realistic API key for benchmarking.
const BENCH_API_KEY: &str = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234";

// ---------------------------------------------------------------------------
// RedactedToken::new() — cost of redaction by token shape
// ---------------------------------------------------------------------------

fn bench_redacted_token_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("RedactedToken::new");

    // Long ASCII token (>16 chars): chars().take(8) path
    group.bench_function("long_ascii_52B", |b| {
        b.iter(|| RedactedToken::new(black_box(BENCH_API_KEY), None));
    });

    // Short token without provider ID: SHA-256 hash path
    let short_token = "tok_abc123";
    group.bench_function("short_no_id_10B", |b| {
        b.iter(|| RedactedToken::new(black_box(short_token), None));
    });

    // Short token with provider ID: no hash, no clone — just format
    group.bench_function("short_with_id_10B", |b| {
        b.iter(|| RedactedToken::new(black_box(short_token), Some("provider-tok-99")));
    });

    // JWT (~350 bytes): SHA-256 hash over larger input
    group.bench_function("jwt_no_id_353B", |b| {
        b.iter(|| RedactedToken::new(black_box(BENCH_JWT), None));
    });

    // JWT with provider ID: skip hash entirely
    group.bench_function("jwt_with_id_353B", |b| {
        b.iter(|| RedactedToken::new(black_box(BENCH_JWT), Some("jwt-session-42")));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ScopedToken::new() — full construction overhead (SecretString + redaction)
// ---------------------------------------------------------------------------

fn bench_scoped_token_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("ScopedToken::new");
    let expiry = chrono::Utc::now() + chrono::Duration::hours(1);

    // Typical API key
    group.bench_function("api_key_52B", |b| {
        b.iter(|| {
            ScopedToken::new(
                SecretString::from(black_box(BENCH_API_KEY).to_string()),
                "admin",
                expiry,
                Some("tok-1".to_string()),
                "aws",
            )
        });
    });

    // JWT credential
    group.bench_function("jwt_353B", |b| {
        b.iter(|| {
            ScopedToken::new(
                SecretString::from(black_box(BENCH_JWT).to_string()),
                "viewer",
                expiry,
                None,
                "okta",
            )
        });
    });

    group.finish();
}

criterion_group!(benches, bench_redacted_token_new, bench_scoped_token_new);
criterion_main!(benches);
