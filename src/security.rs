// NS-012: No tokens in process arguments
// NS-020: Core dump prevention

use std::fmt;
use std::io;

use crate::token::ScopedToken;

/// Error type for security validation failures.
///
/// NS-005: Error messages must never contain token values.
#[derive(Debug)]
pub enum SecurityError {
    /// A token value was found in process arguments.
    /// The argument index is stored but NOT the token value (NS-005).
    TokenInArgs { arg_index: usize },
    /// Failed to disable core dumps.
    CoreDumpDisableFailed(io::Error),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::TokenInArgs { arg_index } => {
                // NS-005: Never include the token value in the error message
                write!(
                    f,
                    "credential value detected in command argument at index {}; \
                     tokens must only be passed via environment variables or file descriptors (NS-012)",
                    arg_index
                )
            }
            SecurityError::CoreDumpDisableFailed(e) => {
                write!(f, "failed to disable core dumps: {}", e)
            }
        }
    }
}

impl std::error::Error for SecurityError {}

/// NS-020: Disable core dumps via setrlimit(RLIMIT_CORE, 0).
///
/// Must be called at startup BEFORE any credentials are loaded.
///
/// **This is irreversible for the process lifetime.** Both soft and hard limits
/// are set to zero, meaning even root cannot re-enable core dumps for this
/// process without `CAP_SYS_RESOURCE`. This is intentional for a credential
/// manager — core dumps could contain secrets in memory.
///
/// If the platform does not support core dump suppression, returns an error.
/// The caller should log a warning to stderr per NS-020.
pub fn disable_core_dumps() -> Result<(), SecurityError> {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    if ret == 0 {
        Ok(())
    } else {
        Err(SecurityError::CoreDumpDisableFailed(
            io::Error::last_os_error(),
        ))
    }
}

/// NS-012: Validate that no known token values appear in command arguments.
///
/// Command-line arguments are visible via /proc/*/cmdline and ps output.
/// Credentials must only be delivered via environment variables or file descriptors.
///
/// Takes `&[&ScopedToken]` so callers don't need to handle raw credential strings.
/// The function calls `expose_secret()` internally for the comparison — the
/// secrets are never returned or stored outside this function.
///
/// Returns an error if any argument contains a known token value.
/// The error message does NOT include the token value (NS-005).
pub fn validate_no_tokens_in_args(
    args: &[String],
    known_tokens: &[&ScopedToken],
) -> Result<(), SecurityError> {
    for (idx, arg) in args.iter().enumerate() {
        for token in known_tokens {
            let secret = token.expose_secret();
            if !secret.is_empty() && arg.contains(secret) {
                return Err(SecurityError::TokenInArgs { arg_index: idx });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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

    // =========================================================================
    // NS-020: Core dump prevention.
    // setrlimit(RLIMIT_CORE, 0) at startup before credentials loaded.
    // If platform doesn't support it, log warning to stderr.
    // =========================================================================

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

    // =========================================================================
    // NS-012: No tokens in process arguments.
    // Never pass token values as CLI args (/proc/*/cmdline visible).
    // Credentials must only be delivered via env vars or FDs.
    // =========================================================================

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
        // NS-005 also applies here: the error message itself must not leak the token
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
}
