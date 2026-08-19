// Provider error exit codes
// noscope exit code range (sysexits.h)
// Signal-terminated provider handling
// Multi-provider error reporting

use provenance_macros::rule;
use std::fmt;

/// Provider exit code protocol.
/// Providers MUST use these exit codes so noscope can give actionable feedback.
/// 0=success, 1=general error, 2=auth failure, 3=role/scope not found,
/// 4=provider unavailable/timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderExitCode {
    /// Provider command succeeded.
    Success,
    /// General / unclassified error.
    GeneralError,
    /// Authentication failed (bad credentials, expired token, etc.).
    AuthFailure,
    /// Requested role or scope does not exist.
    RoleNotFound,
    /// Provider unreachable or timed out.
    Unavailable,
}

impl ProviderExitCode {
    /// Return the raw integer exit code.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::GeneralError => 1,
            Self::AuthFailure => 2,
            Self::RoleNotFound => 3,
            Self::Unavailable => 4,
        }
    }

    /// Parse a raw integer into a known provider exit code.
    /// Returns `None` for codes outside the 0-4 range.
    pub fn from_raw(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::GeneralError),
            2 => Some(Self::AuthFailure),
            3 => Some(Self::RoleNotFound),
            4 => Some(Self::Unavailable),
            _ => None,
        }
    }

    /// Returns `true` if this exit code represents an error (non-zero).
    pub fn is_error(self) -> bool {
        !matches!(self, Self::Success)
    }
}

impl fmt::Display for ProviderExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "provider exit 0: success"),
            Self::GeneralError => write!(f, "provider exit 1: general error"),
            Self::AuthFailure => write!(f, "provider exit 2: auth failure"),
            Self::RoleNotFound => write!(f, "provider exit 3: role/scope not found"),
            Self::Unavailable => write!(f, "provider exit 4: provider unavailable/timeout"),
        }
    }
}

/// noscope's own exit codes, based on sysexits.h.
/// When noscope itself fails (not the child), it uses these codes.
/// When the child process ran, its exit code is passed through via `ChildExit`.
/// `Success` is used when noscope completes without running a child (e.g.
/// all providers minted successfully in mint-only mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoscopeExitCode {
    /// 0 — noscope completed successfully (no child process involved).
    Success,
    /// 64 — Command-line usage error (bad flags, missing args).
    Usage,
    /// 65 — Credential minting failed.
    MintFailure,
    /// 66 — Config file not found.
    ConfigNotFound,
    /// 69 — Service unavailable (provider not reachable).
    Unavailable,
    /// 70 — Internal software error (bug in noscope).
    Internal,
    /// 77 — Permission denied (e.g. config file permissions).
    Permission,
    /// 78 — Configuration error (malformed config).
    ConfigError,
    /// 79 — Profile validation failed.
    ProfileValidation,
    /// Child process ran — pass through its exit code directly.
    ChildExit(i32),
}

impl NoscopeExitCode {
    /// Return the raw integer exit code for `std::process::exit()`.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Usage => 64,
            Self::MintFailure => 65,
            Self::ConfigNotFound => 66,
            Self::Unavailable => 69,
            Self::Internal => 70,
            Self::Permission => 77,
            Self::ConfigError => 78,
            Self::ProfileValidation => 79,
            Self::ChildExit(code) => code,
        }
    }
}

impl fmt::Display for NoscopeExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "exit 0: success"),
            Self::Usage => write!(f, "exit 64: command-line usage error"),
            Self::MintFailure => write!(f, "exit 65: credential mint failure"),
            Self::ConfigNotFound => write!(f, "exit 66: config file not found"),
            Self::Unavailable => write!(f, "exit 69: service unavailable"),
            Self::Internal => write!(f, "exit 70: internal error"),
            Self::Permission => write!(f, "exit 77: permission denied"),
            Self::ConfigError => write!(f, "exit 78: configuration error"),
            Self::ProfileValidation => write!(f, "exit 79: profile validation failed"),
            Self::ChildExit(code) => write!(f, "child process exited with code {}", code),
        }
    }
}

/// Result of interpreting a raw provider exit status.
/// For signal-terminated providers (exit > 128), the exit code is mapped to
/// `GeneralError` (1) and the signal number is extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderExitResult {
    /// The interpreted provider exit code.
    pub exit_code: ProviderExitCode,
    /// If the provider was killed by a signal (raw exit > 128),
    /// this is `Some(signal_number)`.
    pub signal_number: Option<i32>,
}

impl ProviderExitResult {
    /// Format a message suitable for writing to stderr.
    /// If signal-terminated, the message includes the signal number.
    pub fn stderr_message(&self) -> String {
        match self.signal_number {
            Some(sig) => format!(
                "provider terminated by signal {} (raw exit {}); treated as general error",
                sig,
                128 + sig
            ),
            None => format!("{}", self.exit_code),
        }
    }
}

impl fmt::Display for ProviderExitResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.signal_number {
            Some(sig) => write!(
                f,
                "provider terminated by signal {} (treated as {})",
                sig, self.exit_code
            ),
            None => write!(f, "{}", self.exit_code),
        }
    }
}

/// Interpret a raw provider exit code.
/// - Known codes (0-4): mapped directly to `ProviderExitCode`.
/// - Exit > 128: treated as signal-terminated, mapped to `GeneralError`,
///   signal number = raw - 128.
/// - Other unknown codes (including negatives): mapped to `GeneralError`,
///   no signal.
#[rule("rule_exec_exit_interpretation")]
pub fn interpret_provider_exit(raw: i32) -> ProviderExitResult {
    if let Some(known) = ProviderExitCode::from_raw(raw) {
        return ProviderExitResult {
            exit_code: known,
            signal_number: None,
        };
    }

    if raw > 128 {
        let signal = raw - 128;
        return ProviderExitResult {
            exit_code: ProviderExitCode::GeneralError,
            signal_number: Some(signal),
        };
    }

    ProviderExitResult {
        exit_code: ProviderExitCode::GeneralError,
        signal_number: None,
    }
}

#[cfg(test)]
mod tests;
