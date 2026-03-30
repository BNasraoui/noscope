use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGroupMode {
    Run,
    Mint,
}

#[derive(Debug)]
pub struct RunModeProcessGroupSetupResult {
    pub created_new_group: bool,
}

#[derive(Debug)]
pub struct RunModeGroupTerminationResult {
    pub group_terminated: bool,
    pub grandchildren_terminated: bool,
}

#[derive(Debug)]
pub struct MintModeProcessGroupBehavior {
    pub applied: bool,
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

#[cfg(target_os = "linux")]
pub fn parent_death_signal_after_run_setup() -> io::Result<libc::c_int> {
    let (reader, writer) = make_pipe()?;
    // SAFETY: fork duplicates current process; both branches handle fds and exit paths.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_fd(reader);
        close_fd(writer);
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        close_fd(reader);
        let _ = configure_child_for_mode(ProcessGroupMode::Run);
        let mut signal: libc::c_int = 0;
        // SAFETY: PR_GET_PDEATHSIG expects pointer to c_int.
        let prctl_ret = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal) };
        if prctl_ret == 0 {
            let _ = write_i32(writer, signal);
            // SAFETY: immediate child exit without running destructors in forked child.
            unsafe { libc::_exit(0) };
        }
        // SAFETY: immediate child exit without running destructors in forked child.
        unsafe { libc::_exit(1) };
    }

    close_fd(writer);
    let sig = read_i32(reader)?;
    close_fd(reader);
    wait_for_child(pid);
    Ok(sig)
}

#[cfg(not(target_os = "linux"))]
pub fn parent_death_signal_after_run_setup() -> io::Result<libc::c_int> {
    Ok(0)
}

#[cfg(target_os = "linux")]
pub fn run_mode_process_group_setup_result() -> io::Result<RunModeProcessGroupSetupResult> {
    let (reader, writer) = make_pipe()?;
    // SAFETY: fork duplicates current process; both branches handle fds and exit paths.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_fd(reader);
        close_fd(writer);
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        close_fd(reader);
        // SAFETY: getpid/getpgid are pure syscalls with no invariants here.
        let child_pid = unsafe { libc::getpid() };
        // SAFETY: getpgid(0) queries current process group.
        let before = unsafe { libc::getpgid(0) };

        if configure_child_for_mode(ProcessGroupMode::Run).is_ok() {
            // SAFETY: getpgid(0) queries current process group.
            let after = unsafe { libc::getpgid(0) };
            let created = after == child_pid && after != before;
            let value = if created { 1 } else { 0 };
            let _ = write_i32(writer, value);
            // SAFETY: immediate child exit without running destructors in forked child.
            unsafe { libc::_exit(0) };
        }

        // SAFETY: immediate child exit without running destructors in forked child.
        unsafe { libc::_exit(1) };
    }

    close_fd(writer);
    let raw = read_i32(reader)?;
    close_fd(reader);
    wait_for_child(pid);

    Ok(RunModeProcessGroupSetupResult {
        created_new_group: raw == 1,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn run_mode_process_group_setup_result() -> io::Result<RunModeProcessGroupSetupResult> {
    Ok(RunModeProcessGroupSetupResult {
        created_new_group: false,
    })
}

#[cfg(target_os = "linux")]
pub fn terminate_run_mode_group_and_report() -> io::Result<RunModeGroupTerminationResult> {
    let (reader, writer) = make_pipe()?;

    // SAFETY: fork duplicates current process; both branches handle fds and exit paths.
    let leader_pid = unsafe { libc::fork() };
    if leader_pid < 0 {
        close_fd(reader);
        close_fd(writer);
        return Err(io::Error::last_os_error());
    }

    if leader_pid == 0 {
        close_fd(reader);
        let _ = configure_child_for_mode(ProcessGroupMode::Run);

        // SAFETY: fork in child process to create a grandchild.
        let grandchild_pid = unsafe { libc::fork() };
        if grandchild_pid == 0 {
            loop {
                // SAFETY: pause waits for a signal; this loop keeps process alive.
                unsafe { libc::pause() };
            }
        }

        if grandchild_pid > 0 {
            // SAFETY: getpgid(0) queries current process group.
            let pgid = unsafe { libc::getpgid(0) };
            let _ = write_i32(writer, pgid);
            let _ = write_i32(writer, grandchild_pid);
            loop {
                // SAFETY: pause waits for a signal; this loop keeps process alive.
                unsafe { libc::pause() };
            }
        }

        // SAFETY: immediate child exit without running destructors in forked child.
        unsafe { libc::_exit(1) };
    }

    close_fd(writer);
    let pgid = read_i32(reader)?;
    let grandchild_pid = read_i32(reader)?;
    close_fd(reader);

    terminate_group_for_mode(ProcessGroupMode::Run, pgid)?;

    let mut status: libc::c_int = 0;
    // SAFETY: waitpid called with known child pid.
    let waited = unsafe { libc::waitpid(leader_pid, &mut status, 0) };
    if waited < 0 {
        return Err(io::Error::last_os_error());
    }

    let group_terminated = signal_exit(status) == Some(libc::SIGTERM);
    let grandchildren_terminated = wait_until_pid_exits(grandchild_pid);

    Ok(RunModeGroupTerminationResult {
        group_terminated,
        grandchildren_terminated,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn terminate_run_mode_group_and_report() -> io::Result<RunModeGroupTerminationResult> {
    Ok(RunModeGroupTerminationResult {
        group_terminated: false,
        grandchildren_terminated: false,
    })
}

pub fn mint_mode_process_group_behavior() -> io::Result<MintModeProcessGroupBehavior> {
    configure_child_for_mode(ProcessGroupMode::Mint)?;
    Ok(MintModeProcessGroupBehavior { applied: false })
}

#[cfg(target_os = "linux")]
fn make_pipe() -> io::Result<(libc::c_int, libc::c_int)> {
    let mut fds = [0; 2];
    // SAFETY: pipe writes two valid fds into fds on success.
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
fn write_i32(fd: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let bytes = value.to_ne_bytes();
    // SAFETY: fd is owned by caller and bytes points to initialized memory.
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if written == bytes.len() as isize {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn read_i32(fd: libc::c_int) -> io::Result<libc::c_int> {
    let mut bytes = [0u8; std::mem::size_of::<libc::c_int>()];
    // SAFETY: fd is owned by caller and bytes is valid writable memory.
    let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    if read == bytes.len() as isize {
        Ok(libc::c_int::from_ne_bytes(bytes))
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn close_fd(fd: libc::c_int) {
    // SAFETY: best-effort close of an fd owned by caller.
    unsafe {
        libc::close(fd);
    }
}

#[cfg(target_os = "linux")]
fn wait_for_child(pid: libc::pid_t) {
    let mut status: libc::c_int = 0;
    // SAFETY: best-effort waitpid on known child PID.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
}

#[cfg(target_os = "linux")]
fn signal_exit(status: libc::c_int) -> Option<libc::c_int> {
    if (status & 0x7f) > 0 && (status & 0x7f) != 0x7f {
        Some(status & 0x7f)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn wait_until_pid_exits(pid: libc::pid_t) -> bool {
    for _ in 0..50 {
        // SAFETY: kill with signal 0 probes process existence only.
        let probe = unsafe { libc::kill(pid, 0) };
        if probe != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn process_group_management_in_run_mode_sets_pdeathsig_on_child_before_exec() {
        let sig = crate::process_group::parent_death_signal_after_run_setup()
            .expect("run mode setup should report pdeathsig");
        assert_eq!(sig, libc::SIGTERM);
    }

    #[test]
    fn process_group_management_in_run_mode_creates_new_process_group() {
        let outcome = crate::process_group::run_mode_process_group_setup_result()
            .expect("run mode setup should report pgid");
        assert!(
            outcome.created_new_group,
            "run mode must create a new process group"
        );
    }

    #[test]
    fn process_group_management_in_run_mode_kills_entire_group_on_exit() {
        let outcome = crate::process_group::terminate_run_mode_group_and_report()
            .expect("group termination result should be available");
        assert!(
            outcome.group_terminated,
            "run mode must terminate whole process group"
        );
        assert!(
            outcome.grandchildren_terminated,
            "run mode exit must terminate grandchildren too"
        );
    }

    #[test]
    fn process_group_management_does_not_apply_to_mint_mode() {
        let outcome = crate::process_group::mint_mode_process_group_behavior()
            .expect("mint mode behavior should be reportable");
        assert!(
            !outcome.applied,
            "process group and pdeathsig protections must not apply in mint mode"
        );
    }

    #[test]
    fn process_group_management_in_run_mode_rejects_invalid_process_group_id() {
        let err = crate::process_group::terminate_group_for_mode(
            crate::process_group::ProcessGroupMode::Run,
            0,
        )
        .expect_err("run mode termination should reject invalid pgid");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn process_group_management_in_mint_mode_ignores_invalid_process_group_id() {
        crate::process_group::terminate_group_for_mode(
            crate::process_group::ProcessGroupMode::Mint,
            0,
        )
        .expect("mint mode should not apply process group termination behavior");
    }
}
