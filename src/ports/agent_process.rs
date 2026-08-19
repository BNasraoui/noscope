use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::ports::event::{emit_runtime_event, Event, EventType};
use provenance_macros::rule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentMode {
    Run,
    Mint,
}

#[derive(Debug)]
pub struct AgentProcessConfig {
    pub command: String,
    pub args: Vec<String>,
    pub mode: AgentMode,
    pub injected_env: HashMap<String, String>,
    pub force_env: bool,
    pub timeout: Option<Duration>,
}

#[derive(Debug)]
pub struct AgentProcessOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

#[derive(Debug)]
pub enum AgentProcessError {
    EnvCollision {
        key: String,
    },
    ReservedEnvKey {
        key: String,
    },
    SpawnFailed {
        command: String,
        source: io::Error,
    },
    Io {
        context: &'static str,
        source: io::Error,
    },
}

impl AgentProcessError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::SpawnFailed { source, .. } => match source.kind() {
                io::ErrorKind::NotFound => 127,
                io::ErrorKind::PermissionDenied => 126,
                _ => 70,
            },
            Self::ReservedEnvKey { .. } => 64,
            Self::EnvCollision { .. } => 64,
            Self::Io { .. } => 70,
        }
    }
}

impl fmt::Display for AgentProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvCollision { key } => {
                write!(f, "environment collision for key '{}'", key)
            }
            Self::ReservedEnvKey { key } => {
                write!(f, "reserved env key '{}' is not allowed", key)
            }
            Self::SpawnFailed { command, source } => {
                write!(f, "failed to spawn '{}': {}", command, source)
            }
            Self::Io { context, source } => write!(f, "{}: {}", context, source),
        }
    }
}

impl std::error::Error for AgentProcessError {}

#[derive(Debug)]
pub struct AgentProcess {
    child: Option<Child>,
    mode: AgentMode,
    timeout: Option<Duration>,
}

impl AgentProcess {
    #[rule("rule_signals_noscope_env_stripped")]
    pub fn spawn(config: AgentProcessConfig) -> Result<Self, AgentProcessError> {
        let mut env: HashMap<String, String> = std::env::vars()
            .filter(|(k, _)| !k.starts_with("NOSCOPE_"))
            .collect();

        for (key, value) in &config.injected_env {
            if key.starts_with("NOSCOPE_") {
                return Err(AgentProcessError::ReservedEnvKey { key: key.clone() });
            }
            if !config.force_env && env.contains_key(key) {
                return Err(AgentProcessError::EnvCollision { key: key.clone() });
            }
            env.insert(key.clone(), value.clone());
        }

        let mut command = Command::new(&config.command);
        command.args(&config.args);
        command.env_clear();
        command.envs(&env);

        match config.mode {
            AgentMode::Run => {
                #[cfg(unix)]
                {
                    unsafe {
                        command.pre_exec(|| {
                            crate::ports::process_group::configure_child_for_mode(
                                crate::ports::process_group::ProcessGroupMode::Run,
                            )
                        });
                    }
                }
                command.stdout(Stdio::inherit());
                command.stderr(Stdio::inherit());
            }
            AgentMode::Mint => {
                command.stdout(Stdio::piped());
                command.stderr(Stdio::piped());
            }
        }

        let child = command
            .spawn()
            .map_err(|source| AgentProcessError::SpawnFailed {
                command: config.command,
                source,
            })?;

        emit_runtime_event(Event::new(EventType::ChildSpawn, "child"));

        Ok(Self {
            child: Some(child),
            mode: config.mode,
            timeout: config.timeout,
        })
    }

    #[rule("rule_signals_forward_to_group")]
    pub fn forward_signal(&mut self, signal: libc::c_int) -> Result<(), AgentProcessError> {
        let child = self.child.as_ref().ok_or_else(|| AgentProcessError::Io {
            context: "child already waited",
            source: io::Error::new(io::ErrorKind::BrokenPipe, "child already waited"),
        })?;

        let pid = child.id();
        let pgid = -(pid as libc::pid_t);

        let rc_group = unsafe { libc::kill(pgid, signal) };
        if rc_group != 0 {
            let group_err = io::Error::last_os_error();
            if group_err.raw_os_error() != Some(libc::ESRCH) {
                return Err(AgentProcessError::Io {
                    context: "failed to forward signal",
                    source: group_err,
                });
            }

            let rc_child = unsafe { libc::kill(pid as libc::pid_t, signal) };
            if rc_child != 0 {
                let child_err = io::Error::last_os_error();
                if child_err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(AgentProcessError::Io {
                        context: "failed to forward signal",
                        source: child_err,
                    });
                }
            }
        }

        Ok(())
    }

    pub fn try_wait_exit_code(&mut self) -> Result<Option<i32>, AgentProcessError> {
        let child = self.child.as_mut().ok_or_else(|| AgentProcessError::Io {
            context: "child already waited",
            source: io::Error::new(io::ErrorKind::BrokenPipe, "child already waited"),
        })?;

        let status = child.try_wait().map_err(|source| AgentProcessError::Io {
            context: "failed polling child status",
            source,
        })?;

        match status {
            Some(s) => {
                self.child.take();
                let exit_code = exit_status_code(s);
                let mut event = Event::new(EventType::ChildExit, "child");
                event.set_exit_code(exit_code);
                emit_runtime_event(event);
                Ok(Some(exit_code))
            }
            None => Ok(None),
        }
    }

    pub fn wait_with_revoke<F>(&mut self, revoke: F) -> Result<i32, AgentProcessError>
    where
        F: FnOnce() -> Result<(), AgentProcessError>,
    {
        let status = self.wait_for_exit_status()?;
        let exit_code = exit_status_code(status);
        let mut event = Event::new(EventType::ChildExit, "child");
        event.set_exit_code(exit_code);
        emit_runtime_event(event);
        revoke()?;
        Ok(exit_code)
    }

    pub fn wait_capture_with_revoke<F>(
        &mut self,
        revoke: F,
    ) -> Result<AgentProcessOutput, AgentProcessError>
    where
        F: FnOnce() -> Result<(), AgentProcessError>,
    {
        let mut child = self.child.take().ok_or_else(|| AgentProcessError::Io {
            context: "child already waited",
            source: io::Error::new(io::ErrorKind::BrokenPipe, "child already waited"),
        })?;

        let status = wait_child_with_optional_timeout(&mut child, self.timeout)?;
        let exit_code = exit_status_code(status);
        let mut event = Event::new(EventType::ChildExit, "child");
        event.set_exit_code(exit_code);
        emit_runtime_event(event);

        let mut stdout = Vec::new();
        if let Some(mut pipe) = child.stdout.take() {
            pipe.read_to_end(&mut stdout)
                .map_err(|source| AgentProcessError::Io {
                    context: "failed reading child stdout",
                    source,
                })?;
        }

        let mut stderr = Vec::new();
        if let Some(mut pipe) = child.stderr.take() {
            pipe.read_to_end(&mut stderr)
                .map_err(|source| AgentProcessError::Io {
                    context: "failed reading child stderr",
                    source,
                })?;
        }

        revoke()?;

        if self.mode == AgentMode::Run {
            return Ok(AgentProcessOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code,
            });
        }

        Ok(AgentProcessOutput {
            stdout,
            stderr,
            exit_code,
        })
    }

    fn wait_for_exit_status(&mut self) -> Result<ExitStatus, AgentProcessError> {
        let child = self.child.as_mut().ok_or_else(|| AgentProcessError::Io {
            context: "child already waited",
            source: io::Error::new(io::ErrorKind::BrokenPipe, "child already waited"),
        })?;

        let status = wait_child_with_optional_timeout(child, self.timeout)?;
        self.child.take();
        Ok(status)
    }
}

#[rule("rule_exit_passthrough")]
fn exit_status_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }

    1
}

fn wait_child_with_optional_timeout(
    child: &mut Child,
    timeout: Option<Duration>,
) -> Result<ExitStatus, AgentProcessError> {
    match timeout {
        None => child.wait().map_err(|source| AgentProcessError::Io {
            context: "failed waiting for child",
            source,
        }),
        Some(timeout) => {
            let start = Instant::now();
            loop {
                if let Some(status) = child.try_wait().map_err(|source| AgentProcessError::Io {
                    context: "failed polling child status",
                    source,
                })? {
                    return Ok(status);
                }

                if start.elapsed() >= timeout {
                    let pid = child.id();
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGKILL);
                    }
                    return child.wait().map_err(|source| AgentProcessError::Io {
                        context: "failed waiting after timeout kill",
                        source,
                    });
                }

                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests;
