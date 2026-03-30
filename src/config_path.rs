use std::fmt;
use std::path::{Path, PathBuf};

/// Error type for config name validation failures.
///
/// Returned when a provider or profile name contains path traversal
/// characters (`/`, `\`, `..`) or is otherwise unsafe for use as a
/// filesystem path component.
#[derive(Debug)]
pub struct ConfigPathError {
    name: String,
    reason: &'static str,
}

impl ConfigPathError {
    /// The rejected name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Why the name was rejected.
    pub fn reason(&self) -> &str {
        self.reason
    }
}

impl fmt::Display for ConfigPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid config name '{}': {}", self.name, self.reason)
    }
}

impl std::error::Error for ConfigPathError {}

/// Validate that a config name is safe for use as a single path component.
///
/// **Allowed characters:** ASCII alphanumeric (`a-z`, `A-Z`, `0-9`),
/// hyphen (`-`), underscore (`_`), and dot (`.`).
///
/// **Rejected:**
/// - Empty string
/// - `.` or `..` (current/parent directory)
/// - Any character outside the allowed set (path separators, NUL,
///   whitespace, control characters, colons, tildes, etc.)
///
/// This is a strict allowlist — only characters known to be safe as
/// filesystem path components on all supported platforms are permitted.
pub(crate) fn validate_config_name(name: &str) -> Result<(), ConfigPathError> {
    if name.is_empty() {
        return Err(ConfigPathError {
            name: name.to_string(),
            reason: "name must not be empty",
        });
    }

    if name == "." || name == ".." {
        return Err(ConfigPathError {
            name: name.to_string(),
            reason: "name must not be '.' or '..'",
        });
    }

    for ch in name.chars() {
        let allowed = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.';
        if !allowed {
            return Err(ConfigPathError {
                name: name.to_string(),
                reason: "name contains invalid characters; \
                         only ASCII alphanumeric, hyphen, underscore, and dot are allowed",
            });
        }
    }

    Ok(())
}

fn config_base_dir(xdg_config_home: Option<&Path>, home: Option<&Path>) -> PathBuf {
    match xdg_config_home {
        Some(base) => base.to_path_buf(),
        None => {
            let home_dir = match home {
                Some(path) => path.to_path_buf(),
                None => {
                    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
                }
            };
            home_dir.join(".config")
        }
    }
}

pub(crate) fn named_config_toml_path(
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
    domain: &str,
    name: &str,
) -> Result<PathBuf, ConfigPathError> {
    validate_config_name(name)?;
    Ok(config_base_dir(xdg_config_home, home)
        .join("noscope")
        .join(domain)
        .join(format!("{}.toml", name)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // =========================================================================
    // noscope-bsq.1.1: Block config-name path traversal in config_path.
    //
    // Acceptance criteria:
    // 1. Traversal inputs are rejected with typed errors.
    // 2. Valid names still resolve under the expected XDG/HOME directories.
    // 3. Tests cover positive and negative cases.
    //
    // Rules:
    // - Reject names containing path separators (`/`, `\`), `..`, or other
    //   traversal primitives.
    // - Define a strict allowed-name contract (documented and tested).
    // - Apply to both provider and profile lookup paths.
    // =========================================================================

    // -------------------------------------------------------------------------
    // Rule: Reject names containing path separators.
    // -------------------------------------------------------------------------

    #[test]
    fn rejects_forward_slash_in_name() {
        let result = validate_config_name("../../etc/passwd");
        assert!(result.is_err(), "Forward slash must be rejected");
    }

    #[test]
    fn rejects_single_forward_slash() {
        let result = validate_config_name("foo/bar");
        assert!(result.is_err(), "Name with '/' must be rejected");
    }

    #[test]
    fn rejects_backslash_in_name() {
        let result = validate_config_name("foo\\bar");
        assert!(result.is_err(), "Backslash must be rejected");
    }

    #[test]
    fn rejects_windows_traversal() {
        let result = validate_config_name("..\\..\\windows\\system32");
        assert!(result.is_err(), "Windows-style traversal must be rejected");
    }

    // -------------------------------------------------------------------------
    // Rule: Reject names containing `..` (parent directory traversal).
    // -------------------------------------------------------------------------

    #[test]
    fn rejects_dot_dot() {
        let result = validate_config_name("..");
        assert!(result.is_err(), "'..' must be rejected");
    }

    #[test]
    fn rejects_dot_dot_with_extension() {
        // "..hidden" contains `..` as prefix — but the allowlist handles
        // this by rejecting `.` as standalone, and `..` specifically.
        // "..hidden" should pass because it's not exactly ".." and all
        // chars are in the allowlist. Let's verify that only exact "." and
        // ".." are special-cased, not substrings.
        let result = validate_config_name("..hidden");
        assert!(
            result.is_ok(),
            "'..hidden' should be accepted — not exactly '..'"
        );
    }

    // -------------------------------------------------------------------------
    // Rule: Reject other traversal primitives (NUL, empty, dot-only).
    // -------------------------------------------------------------------------

    #[test]
    fn rejects_empty_name() {
        let result = validate_config_name("");
        assert!(result.is_err(), "Empty name must be rejected");
    }

    #[test]
    fn rejects_nul_byte_in_name() {
        let result = validate_config_name("foo\0bar");
        assert!(result.is_err(), "NUL byte in name must be rejected");
    }

    #[test]
    fn rejects_single_dot() {
        // "." refers to current directory — not a valid config name
        let result = validate_config_name(".");
        assert!(result.is_err(), "'.' must be rejected");
    }

    // -------------------------------------------------------------------------
    // Rule: Define strict allowed-name contract.
    //
    // Allowed characters: ASCII alphanumeric, hyphen, underscore, dot
    // (but not `.` or `..` as the entire name).
    // -------------------------------------------------------------------------

    #[test]
    fn accepts_simple_alphanumeric_name() {
        let result = validate_config_name("aws");
        assert!(result.is_ok(), "'aws' must be accepted");
    }

    #[test]
    fn accepts_name_with_hyphens() {
        let result = validate_config_name("my-provider");
        assert!(result.is_ok(), "'my-provider' must be accepted");
    }

    #[test]
    fn accepts_name_with_underscores() {
        let result = validate_config_name("my_provider");
        assert!(result.is_ok(), "'my_provider' must be accepted");
    }

    #[test]
    fn accepts_name_with_dots_not_traversal() {
        // A name like "v1.2" is fine — it's not ".." or "."
        let result = validate_config_name("v1.2");
        assert!(result.is_ok(), "'v1.2' must be accepted");
    }

    #[test]
    fn accepts_name_with_numbers() {
        let result = validate_config_name("provider123");
        assert!(result.is_ok(), "'provider123' must be accepted");
    }

    #[test]
    fn rejects_space_in_name() {
        let result = validate_config_name("my provider");
        assert!(result.is_err(), "Space in name must be rejected");
    }

    #[test]
    fn rejects_colon_in_name() {
        // Colon is special on Windows (drive letter, NTFS streams)
        let result = validate_config_name("C:aws");
        assert!(result.is_err(), "Colon in name must be rejected");
    }

    #[test]
    fn rejects_tilde_in_name() {
        // Tilde could expand to home directory in some contexts
        let result = validate_config_name("~admin");
        assert!(result.is_err(), "Tilde in name must be rejected");
    }

    // -------------------------------------------------------------------------
    // Rule: Typed error carries name and reason.
    // -------------------------------------------------------------------------

    #[test]
    fn error_carries_rejected_name() {
        let err = validate_config_name("../../etc/passwd").unwrap_err();
        assert_eq!(err.name(), "../../etc/passwd");
    }

    #[test]
    fn error_has_human_readable_reason() {
        let err = validate_config_name("foo/bar").unwrap_err();
        assert!(!err.reason().is_empty(), "Reason must not be empty");
    }

    #[test]
    fn error_display_includes_name_and_reason() {
        let err = validate_config_name("../secret").unwrap_err();
        let display = format!("{}", err);
        assert!(
            display.contains("../secret"),
            "Display must show name: {}",
            display
        );
        assert!(
            display.contains("invalid"),
            "Display must indicate invalidity: {}",
            display
        );
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<ConfigPathError>();
    }

    // -------------------------------------------------------------------------
    // Rule: named_config_toml_path rejects traversal names.
    // -------------------------------------------------------------------------

    #[test]
    fn named_config_toml_path_rejects_traversal_name() {
        let xdg = Path::new("/home/user/.config");
        let result = named_config_toml_path(Some(xdg), None, "providers", "../../../etc/shadow");
        assert!(
            result.is_err(),
            "Traversal name must be rejected by named_config_toml_path"
        );
    }

    #[test]
    fn named_config_toml_path_accepts_valid_name() {
        let xdg = Path::new("/home/user/.config");
        let result = named_config_toml_path(Some(xdg), None, "providers", "aws");
        assert!(result.is_ok(), "Valid name must be accepted");
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/home/user/.config/noscope/providers/aws.toml")
        );
    }

    // -------------------------------------------------------------------------
    // Rule: Valid names still resolve under expected XDG/HOME directories.
    // -------------------------------------------------------------------------

    #[test]
    fn valid_provider_resolves_under_xdg() {
        let xdg = Path::new("/home/user/.config");
        let path = named_config_toml_path(Some(xdg), None, "providers", "gcp").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/.config/noscope/providers/gcp.toml")
        );
    }

    #[test]
    fn valid_profile_resolves_under_home() {
        let home = Path::new("/home/user");
        let path = named_config_toml_path(None, Some(home), "profiles", "dev").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/.config/noscope/profiles/dev.toml")
        );
    }

    // -------------------------------------------------------------------------
    // Rule: Apply to both provider and profile lookup paths.
    //
    // The public callers (provider_config_path, profile_config_path) must
    // propagate the error. These tests verify end-to-end.
    // -------------------------------------------------------------------------

    #[test]
    fn provider_config_path_rejects_traversal() {
        let result = crate::provider::provider_config_path("../etc/shadow", None);
        assert!(
            result.is_err(),
            "provider_config_path must reject traversal"
        );
    }

    #[test]
    fn provider_config_path_accepts_valid_name() {
        let xdg = Path::new("/home/user/.config");
        let path = crate::provider::provider_config_path("aws", Some(xdg)).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/.config/noscope/providers/aws.toml")
        );
    }

    #[test]
    fn profile_config_path_rejects_traversal() {
        let result = crate::profile::profile_config_path("../etc/shadow", None);
        assert!(result.is_err(), "profile_config_path must reject traversal");
    }

    #[test]
    fn profile_config_path_accepts_valid_name() {
        let xdg = Path::new("/home/user/.config");
        let path = crate::profile::profile_config_path("dev", Some(xdg)).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/user/.config/noscope/profiles/dev.toml")
        );
    }

    // -------------------------------------------------------------------------
    // Edge cases: boundary names
    // -------------------------------------------------------------------------

    #[test]
    fn accepts_single_char_name() {
        let result = validate_config_name("a");
        assert!(result.is_ok(), "Single char name must be accepted");
    }

    #[test]
    fn accepts_dotfile_style_name() {
        // ".hidden" is a valid name (starts with dot, but not "." or "..")
        let result = validate_config_name(".hidden");
        assert!(result.is_ok(), "'.hidden' must be accepted");
    }

    #[test]
    fn rejects_control_characters() {
        let result = validate_config_name("foo\nbar");
        assert!(result.is_err(), "Newline in name must be rejected");
    }

    #[test]
    fn rejects_tab_character() {
        let result = validate_config_name("foo\tbar");
        assert!(result.is_err(), "Tab in name must be rejected");
    }

    // -------------------------------------------------------------------------
    // Edge cases discovered during Linus review.
    // -------------------------------------------------------------------------

    #[test]
    fn error_is_send_and_sync() {
        static_assertions::assert_impl_all!(ConfigPathError: Send, Sync);
    }

    #[test]
    fn rejects_non_ascii_unicode() {
        // Non-ASCII characters (even innocent-looking ones) are rejected
        // by the strict allowlist. This prevents confusable attacks.
        let result = validate_config_name("provid\u{00E9}r");
        assert!(result.is_err(), "Non-ASCII characters must be rejected");
    }

    #[test]
    fn accepts_all_uppercase() {
        let result = validate_config_name("AWS");
        assert!(result.is_ok(), "Uppercase ASCII must be accepted");
    }

    #[test]
    fn accepts_mixed_case() {
        let result = validate_config_name("MyProvider-v2.1_beta");
        assert!(
            result.is_ok(),
            "Mixed-case with all allowed chars must be accepted"
        );
    }

    #[test]
    fn config_path_error_from_converts_to_security_error() {
        // ConfigPathError converts to Error with Security kind — path traversal
        // is a security violation, not just a config error.
        let err = validate_config_name("../evil").unwrap_err();
        let top_err: crate::error::Error = err.into();
        assert_eq!(top_err.kind(), crate::error::ErrorKind::Security);
    }
}
