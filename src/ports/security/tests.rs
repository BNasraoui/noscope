use super::*;
use chrono::Utc;
use secrecy::SecretString;

/// Helper: create a ScopedToken for test convenience.
fn make_token(value: &str) -> ScopedToken {
    ScopedToken::new(
        SecretString::from(value.to_string()),
        "test-role",
        Utc::now() + chrono::Duration::hours(1),
        None,
        "test-provider",
    )
}

#[test]
fn disable_core_dumps_succeeds_on_linux() {
    let result = disable_core_dumps();
    assert!(result.is_ok(), "disable_core_dumps should succeed on Linux");
}

#[test]
fn disable_core_dumps_sets_rlimit_to_zero() {
    disable_core_dumps().unwrap();

    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let ret = libc::getrlimit(libc::RLIMIT_CORE, &mut rlim);
        assert_eq!(ret, 0, "getrlimit should succeed");
        assert_eq!(rlim.rlim_cur, 0, "soft limit must be 0");
        assert_eq!(rlim.rlim_max, 0, "hard limit must be 0");
    }
}

#[test]
fn rejects_args_containing_known_token_value() {
    let token = make_token("super-secret-token-123");
    let args = &[
        "my-command".to_string(),
        "--token".to_string(),
        "super-secret-token-123".to_string(),
    ];
    let result = validate_no_tokens_in_args(args, &[&token]);
    assert!(
        result.is_err(),
        "Should reject args containing token values"
    );
}

#[test]
fn allows_args_without_token_values() {
    let token = make_token("super-secret-token-123");
    let args = &[
        "my-command".to_string(),
        "--role".to_string(),
        "admin".to_string(),
    ];
    let result = validate_no_tokens_in_args(args, &[&token]);
    assert!(result.is_ok(), "Should allow clean args");
}

#[test]
fn rejects_token_as_substring_in_arg() {
    let token = make_token("secret42");
    let args = &["cmd".to_string(), "--header=Bearer secret42".to_string()];
    let result = validate_no_tokens_in_args(args, &[&token]);
    assert!(
        result.is_err(),
        "Should reject token even as substring of an argument"
    );
}

#[test]
fn empty_args_always_valid() {
    let token = make_token("secret");
    let args: &[String] = &[];
    let result = validate_no_tokens_in_args(args, &[&token]);
    assert!(result.is_ok());
}

#[test]
fn empty_known_tokens_always_valid() {
    let known_tokens: &[&ScopedToken] = &[];
    let args = &["cmd".to_string(), "--flag".to_string()];
    let result = validate_no_tokens_in_args(args, known_tokens);
    assert!(result.is_ok());
}

#[test]
fn error_message_does_not_contain_token_value() {
    // also applies here: the error message itself must not leak the token
    let token = make_token("leak-me-not-12345");
    let args = &["cmd".to_string(), "leak-me-not-12345".to_string()];
    let result = validate_no_tokens_in_args(args, &[&token]);
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        !msg.contains("leak-me-not-12345"),
        "Error message must not contain token value, got: {}",
        msg
    );
}
