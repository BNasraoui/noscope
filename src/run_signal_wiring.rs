use crate::signal_policy::{ParentSignal, SignalHandlingPolicy};
use crate::{event::emit_runtime_event, Event, EventType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalActionReport {
    pub immediate_sigkill: bool,
}

pub trait SignalProcess {
    fn forward_signal(&mut self, sig: i32) -> Result<(), std::io::Error>;
}

pub trait SignalRevoker {
    fn revoke_all(&mut self) -> Result<(), std::io::Error>;
}

#[derive(Default)]
pub struct RunSignalWiring {
    policy: SignalHandlingPolicy,
    revoke_attempted: bool,
}

impl RunSignalWiring {
    pub fn on_parent_signal<P, R>(
        &mut self,
        signal: ParentSignal,
        process: &mut P,
        revoker: &mut R,
    ) -> Result<SignalActionReport, std::io::Error>
    where
        P: SignalProcess,
        R: SignalRevoker,
    {
        let mut received = Event::new(EventType::SignalReceived, "signal");
        received.set_signal(libc_signal(signal));
        emit_runtime_event(received);

        if self.policy.should_forward_to_child_group(signal) {
            process.forward_signal(libc_signal(signal))?;

            let mut forwarded = Event::new(EventType::SignalForwarded, "signal");
            forwarded.set_signal(libc_signal(signal));
            emit_runtime_event(forwarded);
        }

        let decision = self.policy.on_shutdown_signal(signal);
        if decision.started_graceful_shutdown && !self.revoke_attempted {
            revoker.revoke_all()?;
            self.revoke_attempted = true;
        }

        if decision.immediate_sigkill {
            process.forward_signal(libc::SIGKILL)?;
            let mut forwarded = Event::new(EventType::SignalForwarded, "signal");
            forwarded.set_signal(libc::SIGKILL);
            emit_runtime_event(forwarded);
        }

        Ok(SignalActionReport {
            immediate_sigkill: decision.immediate_sigkill,
        })
    }

    pub fn revoke_attempted(&self) -> bool {
        self.revoke_attempted
    }
}

pub fn parent_signal_from_raw(raw: i32) -> Option<ParentSignal> {
    match raw {
        libc::SIGTERM => Some(ParentSignal::Sigterm),
        libc::SIGINT => Some(ParentSignal::Sigint),
        libc::SIGHUP => Some(ParentSignal::Sighup),
        _ => None,
    }
}

pub fn dispatch_pending_parent_signals<I, P, R>(
    raw_signals: I,
    wiring: &mut RunSignalWiring,
    process: &mut P,
    revoker: &mut R,
) -> Result<Vec<SignalActionReport>, std::io::Error>
where
    I: IntoIterator<Item = i32>,
    P: SignalProcess,
    R: SignalRevoker,
{
    let mut actions = Vec::new();
    for raw in raw_signals {
        if let Some(signal) = parent_signal_from_raw(raw) {
            actions.push(wiring.on_parent_signal(signal, process, revoker)?);
        }
    }
    Ok(actions)
}

fn libc_signal(signal: ParentSignal) -> i32 {
    match signal {
        ParentSignal::Sigterm => libc::SIGTERM,
        ParentSignal::Sigint => libc::SIGINT,
        ParentSignal::Sighup => libc::SIGHUP,
        ParentSignal::Sigpipe => libc::SIGPIPE,
    }
}

#[cfg(test)]
mod tests {
    use crate::signal_policy::ParentSignal;

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
        let captured = crate::event::install_test_event_collector(crate::LogFormat::Json);

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
            "NS-070: SIGKILL escalation path must emit signal_forwarded"
        );

        crate::event::clear_test_event_collector();
    }

    #[test]
    fn ns_070_sigkill_forward_failure_does_not_emit_signal_forwarded() {
        struct FailingProcess;

        impl super::SignalProcess for FailingProcess {
            fn forward_signal(&mut self, _sig: i32) -> Result<(), std::io::Error> {
                Err(std::io::Error::other("simulated forward failure"))
            }
        }

        let captured = crate::event::install_test_event_collector(crate::LogFormat::Json);

        let mut process = FailingProcess;
        let mut revoker = FakeRevoker::default();
        let mut wiring = super::RunSignalWiring::default();

        let _ = wiring.on_parent_signal(ParentSignal::Sigterm, &mut process, &mut revoker);

        let lines = captured.lock().unwrap().clone();
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("\"type\":\"signal_forwarded\"")),
            "NS-070: failed signal forwarding must not emit signal_forwarded"
        );

        crate::event::clear_test_event_collector();
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
}
