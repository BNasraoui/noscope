use crate::core::signal_policy::{ParentSignal, SignalHandlingPolicy};
use crate::ports::event::{emit_runtime_event, Event, EventType};
use provenance_macros::rule;

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
    #[rule("rule_signals_event_honesty")]
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
mod tests;
