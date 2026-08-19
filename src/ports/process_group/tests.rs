#[test]
fn run_mode_termination_rejects_invalid_process_group_id() {
    let err = crate::ports::process_group::terminate_group_for_mode(
        crate::ports::process_group::ProcessGroupMode::Run,
        0,
    )
    .expect_err("run mode termination should reject invalid pgid");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn mint_mode_ignores_invalid_process_group_id() {
    crate::ports::process_group::terminate_group_for_mode(
        crate::ports::process_group::ProcessGroupMode::Mint,
        0,
    )
    .expect("mint mode should not apply process group termination behavior");
}
