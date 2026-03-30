use std::process::Command;

use serde_json::Value;

fn run_noscope(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_noscope"));
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to execute noscope binary")
}

#[test]
fn cmd_mint_emits_json_envelope_array_to_stdout() {
    let output = run_noscope(
        &[
            "mint",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ],
        &[(
            "NOSCOPE_MINT_CMD",
            r#"/bin/sh -c 'printf "{\"token\":\"secret-aws\",\"expires_at\":\"2030-01-01T00:00:00Z\"}"'"#,
        )],
    );

    assert!(
        output.status.success(),
        "mint command should succeed: status={:?}, stderr={} ",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(&stdout).expect("mint stdout must be valid JSON array envelope(s)");
    let arr = parsed
        .as_array()
        .expect("mint stdout must be a JSON array when using orchestrator output");
    assert_eq!(arr.len(), 1, "single provider should emit one envelope");
    assert_eq!(arr[0]["provider"], "aws");
    assert_eq!(arr[0]["role"], "admin");
    assert_eq!(arr[0]["token"], "secret-aws");
}

#[test]
fn cmd_mint_resolves_multiple_providers_and_outputs_all_envelopes() {
    let output = run_noscope(
        &[
            "mint",
            "--provider",
            "aws",
            "--provider",
            "gcp",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ],
        &[(
            "NOSCOPE_MINT_CMD",
            r#"/bin/sh -c "printf '{\"token\":\"tok-%s\",\"expires_at\":\"2030-01-01T00:00:00Z\"}' \"$NOSCOPE_PROVIDER\"""#,
        )],
    );

    assert!(output.status.success(), "mint command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("stdout must be JSON");
    let arr = parsed
        .as_array()
        .expect("stdout must be a JSON array envelope(s)");
    assert_eq!(arr.len(), 2, "two providers should emit two envelopes");

    let providers: std::collections::HashSet<&str> = arr
        .iter()
        .map(|item| item["provider"].as_str().expect("provider string"))
        .collect();
    assert!(providers.contains("aws"));
    assert!(providers.contains("gcp"));
}

#[test]
fn cmd_mint_uses_atomic_orchestrator_behavior_on_provider_failure() {
    let output = run_noscope(
        &[
            "mint",
            "--provider",
            "aws",
            "--provider",
            "gcp",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ],
        &[(
            "NOSCOPE_MINT_CMD",
            r#"/bin/sh -c "if [ \"$NOSCOPE_PROVIDER\" = \"gcp\" ]; then exit 2; fi; printf '{\"token\":\"tok-%s\",\"expires_at\":\"2030-01-01T00:00:00Z\"}' \"$NOSCOPE_PROVIDER\"""#,
        )],
    );

    assert!(
        !output.status.success(),
        "provider failure should fail the whole mint operation"
    );
    assert!(
        output.stdout.is_empty(),
        "atomic mint should not emit partial stdout on failure"
    );
}

#[test]
fn ns_065_cmd_mint_rejects_terminal_stdout_without_force() {
    let binary = env!("CARGO_BIN_EXE_noscope");
    let command_line = format!("{} mint --provider aws --role admin --ttl 3600", binary);

    // Run through `script` so the child sees stdout as a tty.
    let output = Command::new("script")
        .env(
            "NOSCOPE_MINT_CMD",
            r#"/bin/sh -c 'printf "{\"token\":\"secret\",\"expires_at\":\"2030-01-01T00:00:00Z\"}"'"#,
        )
        .args(["-qefc", &command_line, "/dev/null"])
        .output()
        .expect("failed to execute script(1)");

    assert_eq!(
        output.status.code(),
        Some(64),
        "NS-065: mint should exit 64 when stdout is a terminal without --force"
    );
}

#[test]
fn ns_065_cmd_mint_allows_terminal_stdout_with_force() {
    let binary = env!("CARGO_BIN_EXE_noscope");
    let command_line = format!(
        "{} mint --provider aws --role admin --ttl 3600 --force-terminal",
        binary
    );

    let output = Command::new("script")
        .env(
            "NOSCOPE_MINT_CMD",
            r#"/bin/sh -c 'printf "{\"token\":\"secret\",\"expires_at\":\"2030-01-01T00:00:00Z\"}"'"#,
        )
        .args(["-qefc", &command_line, "/dev/null"])
        .output()
        .expect("failed to execute script(1)");

    assert_eq!(
        output.status.code(),
        Some(0),
        "NS-065: --force-terminal should allow mint output to tty"
    );
}

#[test]
fn cmd_mint_substitutes_role_and_ttl_template_vars() {
    let output = run_noscope(
        &[
            "mint",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
        ],
        &[(
            "NOSCOPE_MINT_CMD",
            r#"/bin/sh -c "printf '{\"token\":\"%s:%s\",\"expires_at\":\"2030-01-01T00:00:00Z\"}' \"$1\" \"$2\"" _ {role} {ttl}"#,
        )],
    );

    assert!(output.status.success(), "mint command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("stdout must be JSON");
    let arr = parsed.as_array().expect("stdout must be JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["token"], "admin:3600");
}
