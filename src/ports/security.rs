// No tokens in process arguments
// Core dump prevention

use std::fmt;
use std::io;

use crate::core::token::ScopedToken;

/// Error type for security validation failures.
/// Error messages must never contain token values.
#[derive(Debug)]
pub enum SecurityError {
    /// A token value was found in process arguments.
    /// The argument index is stored but NOT the token value.
    TokenInArgs { arg_index: usize },
    /// Failed to disable core dumps.
    CoreDumpDisableFailed(io::Error),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::TokenInArgs { arg_index } => {
                // Never include the token value in the error message
                write!(
                    f,
                    "credential value detected in command argument at index {}; \
                     tokens must only be passed via environment variables or file descriptors",
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

/// Disable core dumps via setrlimit(RLIMIT_CORE, 0).
/// Must be called at startup BEFORE any credentials are loaded.
/// **This is irreversible for the process lifetime.** Both soft and hard limits
/// are set to zero, meaning even root cannot re-enable core dumps for this
/// process without `CAP_SYS_RESOURCE`. This is intentional for a credential
/// manager — core dumps could contain secrets in memory.
/// If the platform does not support core dump suppression, returns an error.
/// The caller should log a warning to stderr.
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

/// Validate that no known token values appear in command arguments.
/// Command-line arguments are visible via /proc/*/cmdline and ps output.
/// Credentials must only be delivered via environment variables or file descriptors.
/// Takes `&[&ScopedToken]` so callers don't need to handle raw credential strings.
/// The function calls `expose_secret()` internally for the comparison — the
/// secrets are never returned or stored outside this function.
/// Returns an error if any argument contains a known token value.
/// The error message does NOT include the token value.
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
mod tests;
