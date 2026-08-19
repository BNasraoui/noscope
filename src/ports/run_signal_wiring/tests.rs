use crate::core::signal_policy::ParentSignal;
use provenance_macros::verifies;

#[derive(Default)]
struct FakeProcess {
    forwarded: Vec<i32>,
}

impl FakeProcess {
    fn forward_signal(&mut self, sig: i32) {
        self.forwarded.push(sig);
    }
}

impl super::SignalProcess for FakeProcess {
    fn forward_signal(&mut self, sig: i32) -> Result<(), std::io::Error> {
        self.forward_signal(sig);
        Ok(())
    }
}

#[derive(Default)]
struct FakeRevoker {
    calls: usize,
}

impl FakeRevoker {
    fn revoke_all(&mut self) {
        self.calls += 1;
    }
}

impl super::SignalRevoker for FakeRevoker {
    fn revoke_all(&mut self) -> Result<(), std::io::Error> {
        self.revoke_all();
        Ok(())
    }
}

#[test]
fn ns_026_forwards_sigterm_sigint_sighup_to_child_group() {
    let mut process = FakeProcess::default();
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    wiring
        .on_parent_signal(ParentSignal::Sigterm, &mut process, &mut revoker)
        .unwrap();
    wiring
        .on_parent_signal(ParentSignal::Sighup, &mut process, &mut revoker)
        .unwrap();
    wiring
        .on_parent_signal(ParentSignal::Sigint, &mut process, &mut revoker)
        .unwrap();

    assert!(process.forwarded.contains(&libc::SIGTERM));
    assert!(process.forwarded.contains(&libc::SIGHUP));
    assert!(process.forwarded.contains(&libc::SIGINT));
}

#[test]
fn ns_028_double_signal_escalates_to_sigkill() {
    let mut process = FakeProcess::default();
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    wiring
        .on_parent_signal(ParentSignal::Sigterm, &mut process, &mut revoker)
        .unwrap();
    let report = wiring
        .on_parent_signal(ParentSignal::Sigint, &mut process, &mut revoker)
        .unwrap();

    assert!(report.immediate_sigkill);
    assert!(process.forwarded.contains(&libc::SIGKILL));
}

#[test]
fn ns_070_double_signal_sigkill_path_emits_signal_forwarded() {
    let _guard = crate::ports::event::test_event_collector_guard();
    let captured = crate::ports::event::install_test_event_collector(crate::LogFormat::Json);

    let mut process = FakeProcess::default();
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    wiring
        .on_parent_signal(ParentSignal::Sigterm, &mut process, &mut revoker)
        .unwrap();
    wiring
        .on_parent_signal(ParentSignal::Sigint, &mut process, &mut revoker)
        .unwrap();

    let lines = captured.lock().unwrap().clone();
    let forwarded_sigkill = lines.iter().any(|line| {
        line.contains("\"type\":\"signal_forwarded\"")
            && line.contains(&format!("\"signal\":{}", libc::SIGKILL))
    });
    assert!(
        forwarded_sigkill,
        "SIGKILL escalation path must emit signal_forwarded"
    );

    crate::ports::event::clear_test_event_collector();
}

#[test]
#[verifies("rule_signals_event_honesty", examples)]
fn ns_070_sigkill_forward_failure_does_not_emit_signal_forwarded() {
    struct FailingProcess;

    impl super::SignalProcess for FailingProcess {
        fn forward_signal(&mut self, _sig: i32) -> Result<(), std::io::Error> {
            Err(std::io::Error::other("simulated forward failure"))
        }
    }

    let _guard = crate::ports::event::test_event_collector_guard();
    let captured = crate::ports::event::install_test_event_collector(crate::LogFormat::Json);

    let mut process = FailingProcess;
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    let _ = wiring.on_parent_signal(ParentSignal::Sigterm, &mut process, &mut revoker);

    let lines = captured.lock().unwrap().clone();
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("\"type\":\"signal_forwarded\"")),
        "failed signal forwarding must not emit signal_forwarded"
    );

    crate::ports::event::clear_test_event_collector();
}

#[test]
fn ns_029_shutdown_signal_triggers_revoke_all_on_signal() {
    let mut process = FakeProcess::default();
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    wiring
        .on_parent_signal(ParentSignal::Sigterm, &mut process, &mut revoker)
        .unwrap();

    assert_eq!(revoker.calls, 1);
}

#[test]
fn ns_003_revoke_on_exit_guarantee_applies_during_signal_shutdown() {
    let mut process = FakeProcess::default();
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    wiring
        .on_parent_signal(ParentSignal::Sighup, &mut process, &mut revoker)
        .unwrap();

    assert!(wiring.revoke_attempted());
}

#[test]
fn dispatch_pending_parent_signals_ignores_unmapped_raw_signals() {
    let mut process = FakeProcess::default();
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    let actions = super::dispatch_pending_parent_signals(
        [libc::SIGTERM, libc::SIGUSR1],
        &mut wiring,
        &mut process,
        &mut revoker,
    )
    .unwrap();

    assert_eq!(actions.len(), 1);
    assert!(process.forwarded.contains(&libc::SIGTERM));
}

#[test]
fn dispatch_pending_parent_signals_reports_sigkill_escalation() {
    let mut process = FakeProcess::default();
    let mut revoker = FakeRevoker::default();
    let mut wiring = super::RunSignalWiring::default();

    let actions = super::dispatch_pending_parent_signals(
        [libc::SIGTERM, libc::SIGINT],
        &mut wiring,
        &mut process,
        &mut revoker,
    )
    .unwrap();

    assert_eq!(actions.len(), 2);
    assert!(actions.iter().any(|action| action.immediate_sigkill));
}
