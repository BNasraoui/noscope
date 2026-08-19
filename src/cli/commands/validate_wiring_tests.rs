use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn write_non_executable_file(path: &Path) {
    fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
}

fn scoped_env_var<T>(key: &str, value: impl AsRef<std::ffi::OsStr>, f: impl FnOnce() -> T) -> T {
    let old = std::env::var_os(key);
    unsafe {
        std::env::set_var(key, value);
    }
    let out = f();
    match old {
        Some(prev) => unsafe {
            std::env::set_var(key, prev);
        },
        None => unsafe {
            std::env::remove_var(key);
        },
    }
    out
}

fn scoped_validate_env<T>(mint_cmd: &Path, f: impl FnOnce() -> T) -> T {
    let mint_cmd: PathBuf = mint_cmd.into();
    scoped_env_var("NOSCOPE_MINT_CMD", mint_cmd.as_os_str(), || {
        scoped_env_var("NOSCOPE_REFRESH_CMD", "", || {
            scoped_env_var("NOSCOPE_REVOKE_CMD", "", f)
        })
    })
}

#[test]
fn validate_command_performs_provider_executable_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let mint = tmp.path().join("mint.sh");
    write_non_executable_file(&mint);

    let result = scoped_validate_env(&mint, || {
        cmd_validate(
            cli::ValidateArgs {
                provider: "aws".to_string(),
            },
            cli::OutputFormat::Text,
        )
    });

    assert!(
        result.is_err(),
        "validate must fail when provider command is not executable"
    );
}

#[test]
fn validate_command_error_is_actionable_for_operator() {
    let tmp = tempfile::tempdir().unwrap();
    let mint = tmp.path().join("mint.sh");
    write_non_executable_file(&mint);
    let mint_cmd = mint.to_string_lossy().to_string();

    let result = scoped_validate_env(&mint, || {
        cmd_validate(
            cli::ValidateArgs {
                provider: "aws".to_string(),
            },
            cli::OutputFormat::Text,
        )
    });

    let err = result.expect_err("validate must fail for non-executable command");
    let message = format!("{}", err);

    assert!(
        message.contains("mint") && message.contains(&mint_cmd),
        "validate failure must include failing command type and path, got: {}",
        message
    );
}
