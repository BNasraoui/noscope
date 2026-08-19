// Typed machine-readable public error taxonomy
// Replace stringly, ad-hoc error aggregation with a typed top-level
// error hierarchy that is ergonomic for humans and machine consumers (agents).

use std::fmt;

use crate::core::exit_code::NoscopeExitCode;
use provenance_macros::rule;

/// Machine-readable error category for programmatic consumers.
/// Each variant maps to a stable string tag via [`ErrorKind::as_str`] and
/// a noscope exit code via the parent [`Error::exit_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[rule("rule_errors_six_kinds")]
pub enum ErrorKind {
    /// Command-line usage error (bad flags, missing args). Exit 64.
    Usage,
    /// Configuration error (malformed config, missing provider). Exit 78.
    Config,
    /// Provider operation failed (mint, refresh, revoke). Exit 65.
    Provider,
    /// Security invariant violated (token in args, etc.). Exit 64.
    Security,
    /// Profile error (not found, validation failed). Exit 66.
    Profile,
    /// Internal software error (bug in noscope). Exit 70.
    Internal,
}

impl ErrorKind {
    /// Stable string tag for machine consumers (e.g. JSON error responses).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Config => "config",
            Self::Provider => "provider",
            Self::Security => "security",
            Self::Profile => "profile",
            Self::Internal => "internal",
        }
    }

    /// Map this kind to a noscope exit code.
    fn exit_code(self) -> i32 {
        match self {
            Self::Usage => NoscopeExitCode::Usage.as_raw(),
            Self::Config => NoscopeExitCode::ConfigError.as_raw(),
            Self::Provider => NoscopeExitCode::MintFailure.as_raw(),
            Self::Security => NoscopeExitCode::Usage.as_raw(),
            Self::Profile => NoscopeExitCode::ConfigNotFound.as_raw(),
            Self::Internal => NoscopeExitCode::Internal.as_raw(),
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Typed top-level error for the noscope public API.
/// Designed for both human and machine consumers:
/// - [`Error::kind`] returns a machine-readable [`ErrorKind`].
/// - [`Error::message`] returns the human-readable detail string.
/// - [`Error::provider_name`] returns the provider name (if applicable).
/// - [`Error::errors`] returns inner errors for multi-error cases.
/// - [`Error::exit_code`] maps to a noscope exit code.
///
/// Multi-error cases (e.g. multiple provider failures) are represented
/// via [`Error::multi`] without flattening into brittle strings.
pub struct Error {
    kind: ErrorKind,
    message: String,
    /// Provider name, if this error is associated with a specific provider.
    provider_name: Option<String>,
    /// Inner errors for multi-error aggregation.
    inner: Vec<Error>,
    /// Optional source error for chaining.
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    // -- Private helper ------------------------------------------------------

    fn new(kind: ErrorKind, message: &str) -> Self {
        Self {
            kind,
            message: message.to_string(),
            provider_name: None,
            inner: Vec::new(),
            source: None,
        }
    }

    // -- Constructors --------------------------------------------------------

    /// Create a usage error (bad flags, missing args).
    pub fn usage(message: &str) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    /// Create a configuration error (malformed config, missing provider).
    pub fn config(message: &str) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    /// Create a provider error with the provider name for programmatic access.
    pub fn provider(provider: &str, message: &str) -> Self {
        let mut err = Self::new(ErrorKind::Provider, message);
        err.provider_name = Some(provider.to_string());
        err
    }

    /// Create a security error (token in args, etc.).
    pub fn security(message: &str) -> Self {
        Self::new(ErrorKind::Security, message)
    }

    /// Create a profile error (not found, validation failed).
    pub fn profile(message: &str) -> Self {
        Self::new(ErrorKind::Profile, message)
    }

    /// Create an internal error (bug in noscope).
    pub fn internal(message: &str) -> Self {
        Self::new(ErrorKind::Internal, message)
    }

    /// Create a multi-error aggregating multiple failures.
    /// Multi-errors preserve individual error kinds, provider names, and
    /// messages — no flattening into a single string.
    pub fn multi(errors: Vec<Error>) -> Self {
        Self {
            kind: ErrorKind::Provider,
            message: String::new(),
            provider_name: None,
            inner: errors,
            source: None,
        }
    }

    /// Attach a source error for chaining.
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    // -- Accessors -----------------------------------------------------------

    /// Machine-readable error category.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Human-readable detail message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Provider name, if this error is associated with a specific provider.
    pub fn provider_name(&self) -> Option<&str> {
        self.provider_name.as_deref()
    }

    /// Inner errors for multi-error cases. Empty for single errors.
    pub fn errors(&self) -> &[Error] {
        &self.inner
    }

    /// Map this error to a process exit code.
    pub fn exit_code(&self) -> i32 {
        // Multi-error: use MintFailure (65) since multi-errors represent
        // multi-provider failures.
        if !self.inner.is_empty() {
            return NoscopeExitCode::MintFailure.as_raw();
        }
        self.kind.exit_code()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Multi-error: display all inner errors (may be empty).
        if self.message.is_empty() && self.provider_name.is_none() {
            for (i, err) in self.inner.iter().enumerate() {
                if i > 0 {
                    write!(f, "; ")?;
                }
                write!(f, "{}", err)?;
            }
            return Ok(());
        }

        match self.kind {
            ErrorKind::Provider => {
                if let Some(ref name) = self.provider_name {
                    write!(f, "provider '{}' error: {}", name, self.message)
                } else {
                    write!(f, "provider error: {}", self.message)
                }
            }
            _ => write!(f, "{} error: {}", self.kind, self.message),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Error");
        s.field("kind", &self.kind);
        s.field("message", &self.message);
        if let Some(ref name) = self.provider_name {
            s.field("provider", name);
        }
        if !self.inner.is_empty() {
            s.field("errors", &self.inner);
        }
        if self.source.is_some() {
            s.field("source", &"<error>");
        }
        s.finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<crate::core::mint::MintError> for Error {
    fn from(e: crate::core::mint::MintError) -> Self {
        Self::usage(&format!("{}", e))
    }
}

impl From<crate::ports::provider::ProviderConfigError> for Error {
    fn from(e: crate::ports::provider::ProviderConfigError) -> Self {
        Self::config(&format!("{}", e))
    }
}

impl From<crate::ports::security::SecurityError> for Error {
    fn from(e: crate::ports::security::SecurityError) -> Self {
        Self::security(&format!("{}", e))
    }
}

impl From<crate::ports::profile::ProfileError> for Error {
    fn from(e: crate::ports::profile::ProfileError) -> Self {
        Self::profile(&format!("{}", e))
    }
}

impl From<crate::core::credential_set::CredentialSetError> for Error {
    fn from(e: crate::core::credential_set::CredentialSetError) -> Self {
        // Credential set errors are configuration/usage errors depending
        // on variant, but map to provider-level failures for consistency.
        Self::config(&format!("{}", e))
    }
}

impl From<crate::ports::provider_exec::ProviderExecError> for Error {
    fn from(e: crate::ports::provider_exec::ProviderExecError) -> Self {
        Self::new(ErrorKind::Provider, &format!("{}", e))
    }
}

impl From<crate::ports::config_path::ConfigPathError> for Error {
    fn from(e: crate::ports::config_path::ConfigPathError) -> Self {
        Self::security(&format!("{}", e))
    }
}

#[cfg(test)]
mod tests;
