use super::*;

#[test]
fn revoke_cli_parses_token_id_and_provider_flags() {
    let cli = cli::parse_from_args([
        "noscope",
        "revoke",
        "--token-id",
        "tok-123",
        "--provider",
        "aws",
    ])
    .unwrap();

    match cli.command {
        Command::Revoke(args) => {
            assert_eq!(args.token_id.as_deref(), Some("tok-123"));
            assert_eq!(args.provider.as_deref(), Some("aws"));
            assert!(!args.from_stdin);
        }
        _ => panic!("expected revoke command"),
    }
}

#[test]
fn revoke_cli_parses_from_stdin_flag() {
    let cli = cli::parse_from_args(["noscope", "revoke", "--from-stdin"]).unwrap();

    match cli.command {
        Command::Revoke(args) => {
            assert_eq!(args.token_id, None);
            assert_eq!(args.provider, None);
            assert!(args.from_stdin);
        }
        _ => panic!("expected revoke command"),
    }
}

#[test]
fn revoke_builds_revoke_input_from_flags() {
    let inputs = revoke_inputs_from_cli(false, "", Some("tok-123"), Some("aws")).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].token_id(), "tok-123");
    assert_eq!(inputs[0].provider(), "aws");
}

#[test]
fn revoke_builds_revoke_input_from_stdin_json() {
    let stdin = r#"{"token":"secret","token_id":"tok-9","provider":"vault","role":"ops"}"#;

    let inputs = revoke_inputs_from_cli(true, stdin, None, None).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].token_id(), "tok-9");
    assert_eq!(inputs[0].provider(), "vault");
}

#[test]
fn revoke_accepts_mint_envelope_array_from_stdin() {
    // `noscope mint` emits a JSON array; the pipeline
    // `noscope mint ... | noscope revoke --from-stdin` must revoke
    // every envelope in it.
    let stdin = r#"[
        {"token":"s1","token_id":"tok-a","provider":"aws","role":"ops"},
        {"token":"s2","token_id":"tok-g","provider":"gcp","role":"ops"}
    ]"#;

    let inputs = revoke_inputs_from_cli(true, stdin, None, None).unwrap();
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0].token_id(), "tok-a");
    assert_eq!(inputs[0].provider(), "aws");
    assert_eq!(inputs[1].token_id(), "tok-g");
    assert_eq!(inputs[1].provider(), "gcp");
}

#[test]
fn revoke_cli_rejects_from_stdin_with_explicit_flags() {
    let cli = cli::parse_from_args([
        "noscope",
        "revoke",
        "--from-stdin",
        "--token-id",
        "tok-1",
        "--provider",
        "aws",
    ]);
    assert!(
        cli.is_err(),
        "revoke must reject --from-stdin when explicit token/provider flags are present"
    );
}

#[tokio::test]
async fn revoke_executes_provider_revoke_command() {
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let script = format!(
        "printf %s \"$NOSCOPE_TOKEN_ID\" > {}; exit 0",
        output_file.path().display()
    );
    let resolved = crate::ports::provider::ResolvedProvider {
        name: "aws".to_string(),
        contract_version: None,
        mint_cmd: "true".to_string(),
        refresh_cmd: None,
        revoke_cmd: Some(format!("/bin/sh -c '{}'", script)),
        env: std::collections::HashMap::new(),
        source: crate::ports::provider::ConfigSource::Flags,
    };
    let input = crate::core::mint::RevokeInput::from_token_id_and_provider("tok-777", "aws");

    execute_revoke(&resolved, &input).await.unwrap();

    let written = std::fs::read_to_string(output_file.path()).unwrap();
    assert_eq!(written, "tok-777");
}

#[test]
fn revoke_reports_result_message() {
    let msg = format_revoke_result("aws", "tok-123");
    assert_eq!(msg, "noscope: revoked token tok-123 for provider aws");
}
