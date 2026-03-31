use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ── Structural guards (noscope-3ez.5: dedup stays in place) ──────────

#[test]
fn deduplicate_parse_command_has_single_canonical_helper_module() {
    let command_parse_rs = repo_root().join("src/command_parse.rs");
    assert!(
        command_parse_rs.exists(),
        "noscope-3ez.5: canonical parse helper module must exist at src/command_parse.rs"
    );
}

#[test]
fn deduplicate_parse_command_main_uses_shared_helper() {
    let main_rs =
        std::fs::read_to_string(repo_root().join("src/main.rs")).expect("read src/main.rs");

    assert!(
        !main_rs.contains("fn parse_command(command: &str) -> Vec<String>"),
        "noscope-3ez.5: src/main.rs must not define a local parse_command helper"
    );
    assert!(
        main_rs.contains("noscope::command_parse::parse_command")
            || main_rs.contains("use noscope::command_parse::parse_command"),
        "noscope-3ez.5: src/main.rs must call the shared parse_command helper"
    );
}

#[test]
fn deduplicate_parse_command_integration_runtime_uses_shared_helper() {
    let integration_runtime_rs =
        std::fs::read_to_string(repo_root().join("src/integration_runtime.rs"))
            .expect("read src/integration_runtime.rs");

    assert!(
        !integration_runtime_rs.contains("fn parse_command(command: &str) -> Vec<String>"),
        "noscope-3ez.5: src/integration_runtime.rs must not define a local parse_command helper"
    );
    assert!(
        integration_runtime_rs.contains("crate::command_parse::parse_command")
            || integration_runtime_rs.contains("use crate::command_parse::parse_command"),
        "noscope-3ez.5: src/integration_runtime.rs must call the shared parse_command helper"
    );
}

// ── Behavioral tests ─────────────────────────────────────────────────

#[test]
fn shared_helper_preserves_single_quoted_segments() {
    let argv = crate::command_parse::parse_command("/bin/sh -c 'printf hello world'");
    assert_eq!(argv, vec!["/bin/sh", "-c", "printf hello world"]);
}

#[test]
fn shared_helper_preserves_double_quoted_segments() {
    let argv = crate::command_parse::parse_command(r#"echo "hello world" done"#);
    assert_eq!(argv, vec!["echo", "hello world", "done"]);
}

#[test]
fn shared_helper_falls_back_on_unbalanced_quotes() {
    let argv = crate::command_parse::parse_command("/bin/echo 'unterminated quote");
    assert_eq!(argv, vec!["/bin/echo", "'unterminated", "quote"]);
}

// ── Edge cases ───────────────────────────────────────────────────────

#[test]
fn shared_helper_empty_string_returns_empty_vec() {
    let argv = crate::command_parse::parse_command("");
    assert!(argv.is_empty(), "empty input must yield empty argv");
}

#[test]
fn shared_helper_whitespace_only_returns_empty_vec() {
    let argv = crate::command_parse::parse_command("   \t  ");
    assert!(
        argv.is_empty(),
        "whitespace-only input must yield empty argv"
    );
}

#[test]
fn shared_helper_single_token_no_args() {
    let argv = crate::command_parse::parse_command("ls");
    assert_eq!(argv, vec!["ls"]);
}
