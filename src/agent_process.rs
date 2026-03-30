use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::event::{emit_runtime_event, Event, EventType};

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
                            crate::process_group::configure_child_for_mode(
                                crate::process_group::ProcessGroupMode::Run,
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
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{AgentMode, AgentProcess, AgentProcessConfig, AgentProcessError};

    fn shell_config(script: &str) -> AgentProcessConfig {
        AgentProcessConfig {
            command: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), script.to_string()],
            mode: AgentMode::Run,
            injected_env: HashMap::new(),
            force_env: false,
            timeout: None,
        }
    }

    #[test]
    fn exit_code_passthrough_ns_002() {
        let mut process = AgentProcess::spawn(shell_config("exit 42")).unwrap();
        let exit = process.wait_with_revoke(|| Ok(())).unwrap();
        assert_eq!(exit, 42);
    }

    #[test]
    fn stdout_belongs_to_child_or_mint_output_ns_013() {
        let mut cfg = shell_config("printf 'child-stdout-only'");
        cfg.mode = AgentMode::Mint;
        let mut process = AgentProcess::spawn(cfg).unwrap();
        let outcome = process.wait_capture_with_revoke(|| Ok(())).unwrap();

        let stdout = String::from_utf8_lossy(&outcome.stdout);
        let stderr = String::from_utf8_lossy(&outcome.stderr);

        assert_eq!(stdout, "child-stdout-only");
        assert!(!stderr.contains("child-stdout-only"));
    }

    #[test]
    fn strip_noscope_env_vars_before_spawn_ns_021() {
        // SAFETY: test-local env mutation only.
        unsafe {
            std::env::set_var("NOSCOPE_MINT_CMD", "must-not-leak");
            std::env::set_var("NOSCOPE_ANYTHING", "must-not-leak-either");
        }

        let mut cfg = shell_config("if env | grep -q '^NOSCOPE_'; then exit 99; else exit 0; fi");
        cfg.mode = AgentMode::Mint;

        let mut process = AgentProcess::spawn(cfg).unwrap();
        let exit = process.wait_with_revoke(|| Ok(())).unwrap();
        assert_eq!(exit, 0);

        // SAFETY: cleanup for test-local env mutation only.
        unsafe {
            std::env::remove_var("NOSCOPE_MINT_CMD");
            std::env::remove_var("NOSCOPE_ANYTHING");
        }
    }

    #[test]
    fn strip_noscope_env_vars_rejects_reserved_injected_keys_ns_021() {
        let mut cfg = shell_config("exit 0");
        cfg.injected_env
            .insert("NOSCOPE_MINT_CMD".to_string(), "x".to_string());

        let err = AgentProcess::spawn(cfg).unwrap_err();
        assert!(matches!(
            err,
            AgentProcessError::ReservedEnvKey { key } if key == "NOSCOPE_MINT_CMD"
        ));
    }

    #[test]
    fn env_var_collision_is_fatal_error_without_force_ns_022() {
        // SAFETY: test-local env mutation only.
        unsafe {
            std::env::set_var("AWS_TOKEN", "already-set");
        }

        let mut cfg = shell_config("exit 0");
        cfg.injected_env
            .insert("AWS_TOKEN".to_string(), "new-value".to_string());
        cfg.force_env = false;

        let err = AgentProcess::spawn(cfg).unwrap_err();
        assert!(matches!(
            err,
            AgentProcessError::EnvCollision { key } if key == "AWS_TOKEN"
        ));

        // SAFETY: cleanup for test-local env mutation only.
        unsafe {
            std::env::remove_var("AWS_TOKEN");
        }
    }

    #[test]
    fn env_var_collision_can_be_overridden_with_force_ns_022() {
        // SAFETY: test-local env mutation only.
        unsafe {
            std::env::set_var("AWS_TOKEN", "already-set");
        }

        let mut cfg = shell_config("[ \"$AWS_TOKEN\" = \"new-value\" ]");
        cfg.injected_env
            .insert("AWS_TOKEN".to_string(), "new-value".to_string());
        cfg.force_env = true;

        let mut process = AgentProcess::spawn(cfg).unwrap();
        let exit = process.wait_with_revoke(|| Ok(())).unwrap();
        assert_eq!(exit, 0);

        // SAFETY: cleanup for test-local env mutation only.
        unsafe {
            std::env::remove_var("AWS_TOKEN");
        }
    }

    #[test]
    fn signal_killed_child_exit_code_convention_ns_023() {
        let mut process = AgentProcess::spawn(shell_config("kill -TERM $$")).unwrap();
        let exit = process.wait_with_revoke(|| Ok(())).unwrap();
        assert_eq!(exit, 128 + libc::SIGTERM);
    }

    #[test]
    fn missing_command_maps_to_127_ns_023() {
        let cfg = AgentProcessConfig {
            command: "/definitely/not/a/real/binary".to_string(),
            args: vec![],
            mode: AgentMode::Run,
            injected_env: HashMap::new(),
            force_env: false,
            timeout: None,
        };

        let err = AgentProcess::spawn(cfg).unwrap_err();
        assert_eq!(err.exit_code(), 127);
    }

    #[test]
    fn permission_denied_maps_to_126_ns_023() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("not-executable.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let cfg = AgentProcessConfig {
            command: script.to_string_lossy().to_string(),
            args: vec![],
            mode: AgentMode::Run,
            injected_env: HashMap::new(),
            force_env: false,
            timeout: None,
        };

        let err = AgentProcess::spawn(cfg).unwrap_err();
        assert_eq!(err.exit_code(), 126);
    }

    #[test]
    fn global_wall_clock_timeout_kills_child_and_revokes_ns_057() {
        let mut cfg = shell_config("sleep 60");
        cfg.timeout = Some(Duration::from_millis(150));

        let revoke_calls = Arc::new(AtomicUsize::new(0));
        let revoke_calls_clone = Arc::clone(&revoke_calls);

        let mut process = AgentProcess::spawn(cfg).unwrap();
        let exit = process
            .wait_with_revoke(|| {
                revoke_calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();

        assert_eq!(revoke_calls.load(Ordering::SeqCst), 1);
        assert_eq!(exit, 128 + libc::SIGKILL);
    }

    #[test]
    fn global_wall_clock_timeout_applies_in_capture_mode_ns_057() {
        let mut cfg = shell_config("sleep 60");
        cfg.mode = AgentMode::Mint;
        cfg.timeout = Some(Duration::from_millis(100));

        let mut process = AgentProcess::spawn(cfg).unwrap();
        let outcome = process.wait_capture_with_revoke(|| Ok(())).unwrap();
        assert_eq!(outcome.exit_code, 128 + libc::SIGKILL);
    }

    #[test]
    fn forwards_parent_signals_to_child() {
        let mut process = AgentProcess::spawn(shell_config("sleep 60")).unwrap();
        process.forward_signal(libc::SIGTERM).unwrap();
        let exit = process.wait_with_revoke(|| Ok(())).unwrap();
        assert_eq!(exit, 128 + libc::SIGTERM);
    }

    #[test]
    fn revoke_on_exit_guarantee_runs_on_normal_exit() {
        let revoke_calls = Arc::new(AtomicUsize::new(0));
        let revoke_calls_clone = Arc::clone(&revoke_calls);

        let mut process = AgentProcess::spawn(shell_config("exit 0")).unwrap();
        let exit = process
            .wait_with_revoke(|| {
                revoke_calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();

        assert_eq!(exit, 0);
        assert_eq!(revoke_calls.load(Ordering::SeqCst), 1);
    }
}
