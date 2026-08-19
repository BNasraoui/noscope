use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGroupMode {
    Run,
    Mint,
}

pub fn configure_child_for_mode(mode: ProcessGroupMode) -> io::Result<()> {
    match mode {
        ProcessGroupMode::Run => configure_child_for_run_mode(),
        ProcessGroupMode::Mint => Ok(()),
    }
}

pub fn terminate_group_for_mode(mode: ProcessGroupMode, pgid: libc::pid_t) -> io::Result<()> {
    match mode {
        ProcessGroupMode::Run => terminate_process_group(pgid),
        ProcessGroupMode::Mint => Ok(()),
    }
}

#[cfg(target_os = "linux")]
fn configure_child_for_run_mode() -> io::Result<()> {
    // SAFETY: setpgid with (0, 0) changes only the current process.
    let setpgid_ret = unsafe { libc::setpgid(0, 0) };
    if setpgid_ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: prctl is called with a valid operation and integer argument.
    let prctl_ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if prctl_ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_child_for_run_mode() -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn terminate_process_group(pgid: libc::pid_t) -> io::Result<()> {
    if pgid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process group id must be positive",
        ));
    }

    // SAFETY: kill with negative pid targets process group |pgid| per POSIX.
    let ret = unsafe { libc::kill(-pgid, libc::SIGTERM) };
    if ret == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn terminate_process_group(_pgid: libc::pid_t) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn run_mode_termination_rejects_invalid_process_group_id() {
        let err = crate::process_group::terminate_group_for_mode(
            crate::process_group::ProcessGroupMode::Run,
            0,
        )
        .expect_err("run mode termination should reject invalid pgid");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn mint_mode_ignores_invalid_process_group_id() {
        crate::process_group::terminate_group_for_mode(
            crate::process_group::ProcessGroupMode::Mint,
            0,
        )
        .expect("mint mode should not apply process group termination behavior");
    }
}
