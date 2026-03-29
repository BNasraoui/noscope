// NS-010: Provider error exit codes
// NS-054: noscope exit code range (sysexits.h)
// NS-055: Signal-terminated provider handling
// NS-056: Multi-provider error reporting

use std::fmt;

/// NS-010: Provider exit code protocol.
///
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
    /// Return the raw integer exit code per NS-010.
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

/// NS-054: noscope's own exit codes, based on sysexits.h.
///
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
            Self::ChildExit(code) => write!(f, "child process exited with code {}", code),
        }
    }
}

/// NS-055: Result of interpreting a raw provider exit status.
///
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
    ///
    /// NS-055: If signal-terminated, the message includes the signal number.
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

/// NS-055: Interpret a raw provider exit code.
///
/// - Known codes (0-4): mapped directly to `ProviderExitCode`.
/// - Exit > 128: treated as signal-terminated, mapped to `GeneralError`,
///   signal number = raw - 128.
/// - Other unknown codes (including negatives): mapped to `GeneralError`,
///   no signal.
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

/// NS-056: Collects results from multiple provider invocations.
///
/// All failures are recorded so that the first failure does not shadow
/// subsequent ones. When any failure exists, the noscope exit code is 65
/// (mint failure).
#[derive(Debug)]
pub struct MultiProviderReport {
    failures: Vec<ProviderFailure>,
    successes: Vec<String>,
}

/// A single provider failure record.
#[derive(Debug, Clone)]
pub struct ProviderFailure {
    /// The provider that failed.
    pub provider: String,
    /// The provider's exit code.
    pub exit_code: ProviderExitCode,
    /// Stderr or diagnostic message from the provider.
    pub message: String,
}

impl Default for MultiProviderReport {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiProviderReport {
    /// Create an empty report.
    pub fn new() -> Self {
        Self {
            failures: Vec::new(),
            successes: Vec::new(),
        }
    }

    /// Record a provider failure.
    pub fn record_failure(&mut self, provider: &str, exit_code: ProviderExitCode, message: &str) {
        self.failures.push(ProviderFailure {
            provider: provider.to_string(),
            exit_code,
            message: message.to_string(),
        });
    }

    /// Record a provider success.
    pub fn record_success(&mut self, provider: &str) {
        self.successes.push(provider.to_string());
    }

    /// Number of failed providers.
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Number of successful providers.
    pub fn success_count(&self) -> usize {
        self.successes.len()
    }

    /// Iterate over recorded failures.
    pub fn failures(&self) -> &[ProviderFailure] {
        &self.failures
    }

    /// Iterate over successful provider names.
    pub fn successes(&self) -> &[String] {
        &self.successes
    }

    /// Format all failures for stderr output.
    ///
    /// NS-056: First failure must not shadow subsequent — all are reported.
    /// Returns an empty string when there are no failures.
    pub fn format_stderr(&self) -> String {
        let mut out = String::new();
        for (i, f) in self.failures.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!(
                "error: provider '{}' failed (exit {}): {}",
                f.provider,
                f.exit_code.as_raw(),
                f.message
            ));
        }
        out
    }

    /// Determine the noscope exit code for this multi-provider run.
    ///
    /// NS-056: If any failures exist, exit 65 (mint failure).
    /// If all succeeded, exit 0 (Success — no child involved).
    pub fn noscope_exit_code(&self) -> NoscopeExitCode {
        if self.failures.is_empty() {
            NoscopeExitCode::Success
        } else {
            NoscopeExitCode::MintFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // NS-010: Provider error exit codes.
    // 0=success, 1=general error, 2=auth failure, 3=role/scope not found,
    // 4=provider unavailable/timeout.
    // =========================================================================

    #[test]
    fn provider_exit_code_success_is_zero() {
        assert_eq!(ProviderExitCode::Success.as_raw(), 0);
    }

    #[test]
    fn provider_exit_code_general_error_is_one() {
        assert_eq!(ProviderExitCode::GeneralError.as_raw(), 1);
    }

    #[test]
    fn provider_exit_code_auth_failure_is_two() {
        assert_eq!(ProviderExitCode::AuthFailure.as_raw(), 2);
    }

    #[test]
    fn provider_exit_code_role_not_found_is_three() {
        assert_eq!(ProviderExitCode::RoleNotFound.as_raw(), 3);
    }

    #[test]
    fn provider_exit_code_unavailable_is_four() {
        assert_eq!(ProviderExitCode::Unavailable.as_raw(), 4);
    }

    #[test]
    fn provider_exit_code_from_raw_roundtrips_all_known_codes() {
        for code in 0..=4 {
            let parsed = ProviderExitCode::from_raw(code);
            assert!(parsed.is_some(), "code {} should parse", code);
            assert_eq!(parsed.unwrap().as_raw(), code);
        }
    }

    #[test]
    fn provider_exit_code_from_raw_returns_none_for_unknown() {
        assert!(ProviderExitCode::from_raw(5).is_none());
        assert!(ProviderExitCode::from_raw(127).is_none());
        assert!(ProviderExitCode::from_raw(255).is_none());
    }

    #[test]
    fn provider_exit_code_display_includes_code_number_and_meaning() {
        let display = format!("{}", ProviderExitCode::AuthFailure);
        assert!(display.contains("2"), "Should contain exit code number");
        assert!(
            display.to_lowercase().contains("auth"),
            "Should describe meaning"
        );
    }

    #[test]
    fn provider_exit_code_success_is_not_error() {
        assert!(!ProviderExitCode::Success.is_error());
    }

    #[test]
    fn provider_exit_code_non_zero_are_errors() {
        assert!(ProviderExitCode::GeneralError.is_error());
        assert!(ProviderExitCode::AuthFailure.is_error());
        assert!(ProviderExitCode::RoleNotFound.is_error());
        assert!(ProviderExitCode::Unavailable.is_error());
    }

    // =========================================================================
    // NS-054: noscope exit code range — sysexits.h.
    // 64=usage, 65=mint failure, 66=config not found, 69=unavailable,
    // 70=internal, 77=permission, 78=config error.
    // Child exit code used when child ran.
    // =========================================================================

    #[test]
    fn noscope_exit_code_success_is_zero() {
        assert_eq!(NoscopeExitCode::Success.as_raw(), 0);
    }

    #[test]
    fn noscope_exit_code_usage_is_64() {
        assert_eq!(NoscopeExitCode::Usage.as_raw(), 64);
    }

    #[test]
    fn noscope_exit_code_mint_failure_is_65() {
        assert_eq!(NoscopeExitCode::MintFailure.as_raw(), 65);
    }

    #[test]
    fn noscope_exit_code_config_not_found_is_66() {
        assert_eq!(NoscopeExitCode::ConfigNotFound.as_raw(), 66);
    }

    #[test]
    fn noscope_exit_code_unavailable_is_69() {
        assert_eq!(NoscopeExitCode::Unavailable.as_raw(), 69);
    }

    #[test]
    fn noscope_exit_code_internal_is_70() {
        assert_eq!(NoscopeExitCode::Internal.as_raw(), 70);
    }

    #[test]
    fn noscope_exit_code_permission_is_77() {
        assert_eq!(NoscopeExitCode::Permission.as_raw(), 77);
    }

    #[test]
    fn noscope_exit_code_config_error_is_78() {
        assert_eq!(NoscopeExitCode::ConfigError.as_raw(), 78);
    }

    #[test]
    fn noscope_exit_code_child_exit_preserves_child_code() {
        let code = NoscopeExitCode::ChildExit(42);
        assert_eq!(code.as_raw(), 42);
    }

    #[test]
    fn noscope_exit_code_child_exit_zero_is_success() {
        let code = NoscopeExitCode::ChildExit(0);
        assert_eq!(code.as_raw(), 0);
    }

    #[test]
    fn noscope_exit_code_child_exit_passes_through_any_value() {
        for val in [0, 1, 2, 42, 127, 255] {
            let code = NoscopeExitCode::ChildExit(val);
            assert_eq!(code.as_raw(), val);
        }
    }

    #[test]
    fn noscope_exit_code_display_includes_meaning() {
        let display = format!("{}", NoscopeExitCode::MintFailure);
        assert!(
            display.to_lowercase().contains("mint"),
            "Should describe the failure: {}",
            display
        );
    }

    #[test]
    fn noscope_exit_code_display_child_exit_mentions_child() {
        let display = format!("{}", NoscopeExitCode::ChildExit(1));
        assert!(
            display.to_lowercase().contains("child"),
            "Should mention child process: {}",
            display
        );
    }

    #[test]
    fn noscope_exit_code_display_success_mentions_success() {
        let display = format!("{}", NoscopeExitCode::Success);
        assert!(
            display.to_lowercase().contains("success"),
            "Should mention success: {}",
            display
        );
    }

    #[test]
    fn noscope_exit_codes_do_not_overlap_with_provider_codes() {
        // sysexits start at 64, provider codes are 0-4 -- no overlap
        let noscope_codes = [0, 64, 65, 66, 69, 70, 77, 78];
        let provider_error_codes = [1, 2, 3, 4]; // exclude 0 (both mean success)
        for nc in &noscope_codes {
            if *nc == 0 {
                continue; // Both namespaces use 0 for success, that's fine
            }
            assert!(
                !provider_error_codes.contains(nc),
                "noscope code {} must not overlap with provider error codes",
                nc
            );
        }
    }

    #[test]
    fn noscope_success_is_semantically_distinct_from_child_exit_zero() {
        // These both produce raw 0, but are semantically different:
        // Success = noscope completed (no child), ChildExit(0) = child ran and exited 0.
        assert_ne!(NoscopeExitCode::Success, NoscopeExitCode::ChildExit(0));
        assert_eq!(
            NoscopeExitCode::Success.as_raw(),
            NoscopeExitCode::ChildExit(0).as_raw()
        );
    }

    // =========================================================================
    // NS-055: Signal-terminated provider handling.
    // Exit >128 treated as exit 1 (general error), include signal number
    // in stderr message.
    // =========================================================================

    #[test]
    fn signal_terminated_provider_maps_to_general_error() {
        // exit code 137 = killed by SIGKILL (128 + 9)
        let result = interpret_provider_exit(137);
        assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
    }

    #[test]
    fn signal_terminated_provider_includes_signal_number() {
        // 128 + 9 = SIGKILL
        let result = interpret_provider_exit(137);
        assert!(
            result.signal_number.is_some(),
            "Should extract signal number"
        );
        assert_eq!(result.signal_number.unwrap(), 9);
    }

    #[test]
    fn signal_terminated_provider_stderr_message_contains_signal() {
        let result = interpret_provider_exit(137);
        let msg = result.stderr_message();
        assert!(
            msg.contains("9"),
            "stderr message should contain signal number: {}",
            msg
        );
        assert!(
            msg.to_lowercase().contains("signal"),
            "stderr message should mention 'signal': {}",
            msg
        );
    }

    #[test]
    fn exit_129_is_signal_1_sighup() {
        let result = interpret_provider_exit(129);
        assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
        assert_eq!(result.signal_number, Some(1));
    }

    #[test]
    fn exit_exactly_128_is_not_signal_terminated() {
        // 128 itself is NOT signal-terminated (signals start at 128+1)
        let result = interpret_provider_exit(128);
        assert!(
            result.signal_number.is_none(),
            "Exit 128 is not signal-terminated"
        );
    }

    #[test]
    fn exit_255_is_signal_127() {
        // Maximum valid Unix exit code
        let result = interpret_provider_exit(255);
        assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
        assert_eq!(result.signal_number, Some(127));
    }

    #[test]
    fn negative_exit_code_maps_to_general_error_no_signal() {
        // Negative values are not valid Unix exit codes but i32 allows them.
        // Should fall through to general error without signal extraction.
        let result = interpret_provider_exit(-1);
        assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
        assert!(
            result.signal_number.is_none(),
            "Negative exit codes should not be treated as signals"
        );
    }

    #[test]
    fn known_provider_exit_codes_interpreted_directly() {
        let result = interpret_provider_exit(0);
        assert_eq!(result.exit_code, ProviderExitCode::Success);
        assert!(result.signal_number.is_none());

        let result = interpret_provider_exit(2);
        assert_eq!(result.exit_code, ProviderExitCode::AuthFailure);
        assert!(result.signal_number.is_none());

        let result = interpret_provider_exit(4);
        assert_eq!(result.exit_code, ProviderExitCode::Unavailable);
        assert!(result.signal_number.is_none());
    }

    #[test]
    fn unknown_non_signal_exit_code_maps_to_general_error() {
        // Code 42 is not a known provider code and not >128
        let result = interpret_provider_exit(42);
        assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
        assert!(result.signal_number.is_none());
    }

    #[test]
    fn non_signal_stderr_message_shows_provider_exit_code() {
        let result = interpret_provider_exit(2);
        let msg = result.stderr_message();
        assert!(
            msg.to_lowercase().contains("auth"),
            "Non-signal stderr should show exit code meaning: {}",
            msg
        );
    }

    #[test]
    fn provider_exit_result_implements_display() {
        let result = interpret_provider_exit(137);
        let display = format!("{}", result);
        assert!(
            display.to_lowercase().contains("signal"),
            "Display should mention signal: {}",
            display
        );

        let result = interpret_provider_exit(2);
        let display = format!("{}", result);
        assert!(
            display.to_lowercase().contains("auth"),
            "Display should show exit code meaning: {}",
            display
        );
    }

    #[test]
    fn provider_exit_result_is_eq_comparable() {
        let a = interpret_provider_exit(137);
        let b = interpret_provider_exit(137);
        assert_eq!(a, b);

        let c = interpret_provider_exit(2);
        assert_ne!(a, c);
    }

    // =========================================================================
    // NS-056: Multi-provider error reporting.
    // Report all failures to stderr, exit 65 (mint failure),
    // first failure must not shadow subsequent.
    // =========================================================================

    #[test]
    fn multi_provider_report_collects_all_failures() {
        let mut report = MultiProviderReport::new();
        report.record_failure("aws", ProviderExitCode::AuthFailure, "auth expired");
        report.record_failure("gcp", ProviderExitCode::Unavailable, "timeout");
        assert_eq!(report.failure_count(), 2);
    }

    #[test]
    fn multi_provider_report_empty_has_zero_failures() {
        let report = MultiProviderReport::new();
        assert_eq!(report.failure_count(), 0);
    }

    #[test]
    fn multi_provider_report_first_failure_not_shadowed() {
        let mut report = MultiProviderReport::new();
        report.record_failure("aws", ProviderExitCode::AuthFailure, "first error");
        report.record_failure("gcp", ProviderExitCode::Unavailable, "second error");

        let stderr = report.format_stderr();
        assert!(
            stderr.contains("aws"),
            "First failure must appear in report: {}",
            stderr
        );
        assert!(
            stderr.contains("gcp"),
            "Second failure must appear in report: {}",
            stderr
        );
        assert!(
            stderr.contains("first error"),
            "First error message must appear: {}",
            stderr
        );
        assert!(
            stderr.contains("second error"),
            "Second error message must appear: {}",
            stderr
        );
    }

    #[test]
    fn multi_provider_report_exit_code_is_65_mint_failure() {
        let mut report = MultiProviderReport::new();
        report.record_failure("aws", ProviderExitCode::AuthFailure, "expired");
        let exit = report.noscope_exit_code();
        assert_eq!(exit.as_raw(), 65);
    }

    #[test]
    fn multi_provider_report_with_no_failures_returns_success_not_child_exit() {
        let report = MultiProviderReport::new();
        let exit = report.noscope_exit_code();
        assert_eq!(exit, NoscopeExitCode::Success);
        assert_eq!(exit.as_raw(), 0);
    }

    #[test]
    fn multi_provider_report_tracks_successes_too() {
        let mut report = MultiProviderReport::new();
        report.record_success("aws");
        report.record_failure("gcp", ProviderExitCode::AuthFailure, "expired");
        assert_eq!(report.failure_count(), 1);
        assert_eq!(report.success_count(), 1);
    }

    #[test]
    fn multi_provider_report_stderr_contains_all_providers_in_order() {
        let mut report = MultiProviderReport::new();
        report.record_failure("alpha", ProviderExitCode::GeneralError, "err1");
        report.record_failure("bravo", ProviderExitCode::AuthFailure, "err2");
        report.record_failure("charlie", ProviderExitCode::Unavailable, "err3");

        let stderr = report.format_stderr();
        let alpha_pos = stderr.find("alpha").expect("alpha missing");
        let bravo_pos = stderr.find("bravo").expect("bravo missing");
        let charlie_pos = stderr.find("charlie").expect("charlie missing");

        // Order must be preserved (first failure first)
        assert!(alpha_pos < bravo_pos, "alpha should appear before bravo");
        assert!(
            bravo_pos < charlie_pos,
            "bravo should appear before charlie"
        );
    }

    #[test]
    fn multi_provider_report_stderr_includes_exit_code_per_provider() {
        let mut report = MultiProviderReport::new();
        report.record_failure("aws", ProviderExitCode::AuthFailure, "bad creds");

        let stderr = report.format_stderr();
        // Should mention the provider's exit code (2 for auth failure)
        assert!(
            stderr.contains("2"),
            "Should include provider exit code: {}",
            stderr
        );
    }

    #[test]
    fn multi_provider_report_format_stderr_empty_when_no_failures() {
        let report = MultiProviderReport::new();
        let stderr = report.format_stderr();
        assert!(
            stderr.is_empty(),
            "No failures should produce empty stderr: {:?}",
            stderr
        );
    }

    #[test]
    fn multi_provider_report_failures_are_accessible() {
        let mut report = MultiProviderReport::new();
        report.record_failure("aws", ProviderExitCode::AuthFailure, "expired");
        report.record_failure("gcp", ProviderExitCode::Unavailable, "timeout");

        let failures = report.failures();
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].provider, "aws");
        assert_eq!(failures[0].exit_code, ProviderExitCode::AuthFailure);
        assert_eq!(failures[1].provider, "gcp");
        assert_eq!(failures[1].exit_code, ProviderExitCode::Unavailable);
    }

    #[test]
    fn multi_provider_report_successes_are_accessible() {
        let mut report = MultiProviderReport::new();
        report.record_success("aws");
        report.record_success("gcp");

        let successes = report.successes();
        assert_eq!(successes.len(), 2);
        assert_eq!(successes[0], "aws");
        assert_eq!(successes[1], "gcp");
    }

    #[test]
    fn multi_provider_report_can_filter_retryable_failures() {
        // Demonstrate that exposed failures allow programmatic retry logic
        let mut report = MultiProviderReport::new();
        report.record_failure("aws", ProviderExitCode::Unavailable, "timeout");
        report.record_failure("gcp", ProviderExitCode::AuthFailure, "bad creds");

        let retryable: Vec<&str> = report
            .failures()
            .iter()
            .filter(|f| f.exit_code == ProviderExitCode::Unavailable)
            .map(|f| f.provider.as_str())
            .collect();

        assert_eq!(retryable, vec!["aws"]);
    }
}
