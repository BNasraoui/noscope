#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::time::Duration;

    use chrono::Utc;
    use secrecy::SecretString;
    use tokio::sync::Mutex;

    fn write_executable(path: &Path, script: &str) {
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn write_provider_config(
        xdg_config_home: &Path,
        provider_name: &str,
        mint_cmd: &str,
        refresh_cmd: Option<&str>,
        revoke_cmd: &str,
    ) {
        let providers_dir = xdg_config_home.join("noscope").join("providers");
        fs::create_dir_all(&providers_dir).unwrap();
        let mut cfg = format!(
            "contract_version = 1\n\n[commands]\nmint = \"{}\"\nrevoke = \"{}\"\n",
            mint_cmd, revoke_cmd
        );
        if let Some(refresh_cmd) = refresh_cmd {
            cfg.push_str(&format!("refresh = \"{}\"\n", refresh_cmd));
        }
        let path = providers_dir.join(format!("{}.toml", provider_name));
        fs::write(&path, cfg).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn event_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn ns_070_cmd_run_accepts_log_format_flag() {
        let _lock = event_test_lock().blocking_lock();
        let cli = crate::cli::parse_from_args([
            "noscope",
            "run",
            "--provider",
            "aws",
            "--role",
            "admin",
            "--ttl",
            "3600",
            "--log-format",
            "json",
            "--",
            "/bin/true",
        ]);
        assert!(
            cli.is_ok(),
            "NS-070: run must accept --log-format so cmd_run can wire EventEmitter"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ns_070_orchestrator_emits_mint_start_success_failure() {
        let _lock = event_test_lock().lock().await;
        let captured = crate::event::install_test_event_collector(crate::LogFormat::Json);

        let specs = vec![
            crate::credential_set::CredentialSpec::new("aws", "admin", 3600, "AWS_TOKEN"),
            crate::credential_set::CredentialSpec::new("gcp", "admin", 3600, "GCP_TOKEN"),
        ];
        let config = crate::credential_set::MintConfig::new(Duration::from_secs(2), 2).unwrap();

        let _ = crate::orchestrator::mint_all(&specs, &config, |spec| {
            let provider = spec.provider.clone();
            async move {
                if provider == "aws" {
                    crate::credential_set::MintResult::Success {
                        spec: crate::credential_set::CredentialSpec::new(
                            &provider,
                            "admin",
                            3600,
                            "AWS_TOKEN",
                        ),
                        token: crate::token::ScopedToken::new(
                            SecretString::from("ok".to_string()),
                            "admin",
                            Utc::now() + chrono::Duration::minutes(5),
                            Some("tok-aws".to_string()),
                            "aws",
                        ),
                    }
                } else {
                    crate::credential_set::MintResult::Failure {
                        spec: crate::credential_set::CredentialSpec::new(
                            &provider,
                            "admin",
                            3600,
                            "GCP_TOKEN",
                        ),
                        error: "boom".to_string(),
                    }
                }
            }
        })
        .await;

        let lines = captured.lock().unwrap().clone();
        assert!(
            lines.iter().any(|l| l.contains("\"type\":\"mint_start\"")),
            "NS-070: must emit mint_start"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("\"type\":\"mint_success\"")),
            "NS-070: must emit mint_success"
        );
        assert!(
            lines.iter().any(|l| l.contains("\"type\":\"mint_fail\"")),
            "NS-070: must emit mint_fail"
        );

        crate::event::clear_test_event_collector();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ns_070_refresh_runtime_emits_refresh_start_success_failure() {
        let _lock = event_test_lock().lock().await;
        let captured = crate::event::install_test_event_collector(crate::LogFormat::Json);

        let now = Utc::now();
        let token = crate::token::ScopedToken::new(
            SecretString::from("seed".to_string()),
            "admin",
            now + chrono::Duration::minutes(5),
            Some("tok-aws".to_string()),
            "aws",
        );
        let mut runtime =
            crate::refresh::RefreshRuntimeLoop::new(vec![crate::refresh::RuntimeCredential::new(
                "cred-aws",
                "aws",
                "AWS_TOKEN",
                token,
            )]);

        let _ = runtime
            .run_once(now + chrono::Duration::minutes(10), true, |_request| {
                Box::pin(async {
                    Ok(crate::token::ScopedToken::new(
                        SecretString::from("next".to_string()),
                        "admin",
                        Utc::now() + chrono::Duration::minutes(5),
                        Some("tok-aws".to_string()),
                        "aws",
                    ))
                })
            })
            .await;

        let _ = runtime
            .run_once(now + chrono::Duration::minutes(11), true, |_request| {
                Box::pin(async { Err("refresh failed".to_string()) })
            })
            .await;

        let lines = captured.lock().unwrap().clone();
        assert!(lines.iter().any(|l| l.contains("refresh_start")));
        assert!(lines.iter().any(|l| l.contains("refresh_success")));
        assert!(lines.iter().any(|l| l.contains("refresh_fail")));

        crate::event::clear_test_event_collector();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ns_070_revocation_paths_emit_revoke_start_success_failure() {
        let _lock = event_test_lock().lock().await;
        let captured = crate::event::install_test_event_collector(crate::LogFormat::Json);

        let tmp = tempfile::tempdir().unwrap();
        let mint = tmp.path().join("mint.sh");
        let revoke_ok = tmp.path().join("revoke-ok.sh");
        let revoke_fail = tmp.path().join("revoke-fail.sh");
        write_executable(
            &mint,
            "#!/bin/sh\nprintf '{\"token\":\"secret\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'\n",
        );
        write_executable(&revoke_ok, "#!/bin/sh\nexit 0\n");
        write_executable(&revoke_fail, "#!/bin/sh\nexit 3\n");
        write_provider_config(
            tmp.path(),
            "aws",
            mint.to_string_lossy().as_ref(),
            None,
            revoke_ok.to_string_lossy().as_ref(),
        );
        write_provider_config(
            tmp.path(),
            "gcp",
            mint.to_string_lossy().as_ref(),
            None,
            revoke_fail.to_string_lossy().as_ref(),
        );

        let cfg = crate::integration_runtime::IntegrationRuntimeConfig {
            xdg_config_home: tmp.path().to_path_buf(),
            exec_timeout: Duration::from_secs(2),
            kill_grace_period: Duration::from_secs(1),
        };
        let _ =
            crate::integration_runtime::mint_refresh_revoke_cycle(&cfg, "aws", "admin", 3600).await;
        let _ =
            crate::integration_runtime::mint_refresh_revoke_cycle(&cfg, "gcp", "admin", 3600).await;

        let lines = captured.lock().unwrap().clone();
        assert!(lines.iter().any(|l| l.contains("revoke_start")));
        assert!(lines.iter().any(|l| l.contains("revoke_success")));
        assert!(
            lines.iter().any(|l| l.contains("revoke_fail")),
            "NS-070: must emit revoke_fail on failed revocation paths"
        );

        crate::event::clear_test_event_collector();
    }

    #[test]
    fn ns_070_agent_process_emits_child_spawn_and_child_exit() {
        let _lock = event_test_lock().blocking_lock();
        let captured = crate::event::install_test_event_collector(crate::LogFormat::Json);

        let mut process =
            crate::agent_process::AgentProcess::spawn(crate::agent_process::AgentProcessConfig {
                command: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "exit 0".to_string()],
                mode: crate::agent_process::AgentMode::Run,
                injected_env: HashMap::new(),
                force_env: true,
                timeout: None,
            })
            .unwrap();
        let _ = process.wait_with_revoke(|| Ok(()));

        let lines = captured.lock().unwrap().clone();
        assert!(lines.iter().any(|l| l.contains("child_spawn")));
        assert!(lines.iter().any(|l| l.contains("child_exit")));

        crate::event::clear_test_event_collector();
    }

    #[test]
    fn ns_070_signal_handler_emits_signal_received_and_signal_forwarded() {
        let _lock = event_test_lock().blocking_lock();
        let captured = crate::event::install_test_event_collector(crate::LogFormat::Json);

        #[derive(Default)]
        struct FakeProcess;
        impl crate::run_signal_wiring::SignalProcess for FakeProcess {
            fn forward_signal(&mut self, _sig: i32) -> Result<(), std::io::Error> {
                Ok(())
            }
        }

        #[derive(Default)]
        struct FakeRevoker;
        impl crate::run_signal_wiring::SignalRevoker for FakeRevoker {
            fn revoke_all(&mut self) -> Result<(), std::io::Error> {
                Ok(())
            }
        }

        let mut wiring = crate::run_signal_wiring::RunSignalWiring::default();
        let mut process = FakeProcess;
        let mut revoker = FakeRevoker;

        let _ = wiring.on_parent_signal(
            crate::signal_policy::ParentSignal::Sigterm,
            &mut process,
            &mut revoker,
        );

        let lines = captured.lock().unwrap().clone();
        assert!(lines.iter().any(|l| l.contains("signal_received")));
        assert!(lines.iter().any(|l| l.contains("signal_forwarded")));

        crate::event::clear_test_event_collector();
    }

    #[test]
    fn ns_070_events_are_written_to_stderr_not_stdout() {
        let _lock = event_test_lock().blocking_lock();
        let collector = crate::event::install_test_event_collector(crate::LogFormat::Json);
        let mut event = crate::Event::new(crate::EventType::MintStart, "aws");
        event.set_token_id("tok-aws");
        crate::event::emit_runtime_event(event);

        let lines = collector.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            1,
            "NS-070: events must be emitted through stderr sink exactly once"
        );

        crate::event::clear_test_event_collector();
    }
}
