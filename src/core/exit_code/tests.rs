use super::*;
use provenance_macros::verifies;

#[test]
fn provider_exit_code_success_is_zero() {
    assert_eq!(ProviderExitCode::Success.as_raw(), 0);
}

#[test]
fn provider_exit_code_general_error_is_one() {
    assert_eq!(ProviderExitCode::GeneralError.as_raw(), 1);
}

#[test]
fn provider_exit_code_auth_failure_is_two() {
    assert_eq!(ProviderExitCode::AuthFailure.as_raw(), 2);
}

#[test]
fn provider_exit_code_role_not_found_is_three() {
    assert_eq!(ProviderExitCode::RoleNotFound.as_raw(), 3);
}

#[test]
fn provider_exit_code_unavailable_is_four() {
    assert_eq!(ProviderExitCode::Unavailable.as_raw(), 4);
}

#[test]
fn provider_exit_code_from_raw_roundtrips_all_known_codes() {
    for code in 0..=4 {
        let parsed = ProviderExitCode::from_raw(code);
        assert!(parsed.is_some(), "code {} should parse", code);
        assert_eq!(parsed.unwrap().as_raw(), code);
    }
}

#[test]
fn provider_exit_code_from_raw_returns_none_for_unknown() {
    assert!(ProviderExitCode::from_raw(5).is_none());
    assert!(ProviderExitCode::from_raw(127).is_none());
    assert!(ProviderExitCode::from_raw(255).is_none());
}

#[test]
fn provider_exit_code_display_includes_code_number_and_meaning() {
    let display = format!("{}", ProviderExitCode::AuthFailure);
    assert!(display.contains("2"), "Should contain exit code number");
    assert!(
        display.to_lowercase().contains("auth"),
        "Should describe meaning"
    );
}

#[test]
fn provider_exit_code_success_is_not_error() {
    assert!(!ProviderExitCode::Success.is_error());
}

#[test]
fn provider_exit_code_non_zero_are_errors() {
    assert!(ProviderExitCode::GeneralError.is_error());
    assert!(ProviderExitCode::AuthFailure.is_error());
    assert!(ProviderExitCode::RoleNotFound.is_error());
    assert!(ProviderExitCode::Unavailable.is_error());
}

#[test]
fn noscope_exit_code_success_is_zero() {
    assert_eq!(NoscopeExitCode::Success.as_raw(), 0);
}

#[test]
fn noscope_exit_code_usage_is_64() {
    assert_eq!(NoscopeExitCode::Usage.as_raw(), 64);
}

#[test]
fn noscope_exit_code_mint_failure_is_65() {
    assert_eq!(NoscopeExitCode::MintFailure.as_raw(), 65);
}

#[test]
fn noscope_exit_code_config_not_found_is_66() {
    assert_eq!(NoscopeExitCode::ConfigNotFound.as_raw(), 66);
}

#[test]
fn noscope_exit_code_unavailable_is_69() {
    assert_eq!(NoscopeExitCode::Unavailable.as_raw(), 69);
}

#[test]
fn noscope_exit_code_internal_is_70() {
    assert_eq!(NoscopeExitCode::Internal.as_raw(), 70);
}

#[test]
fn noscope_exit_code_permission_is_77() {
    assert_eq!(NoscopeExitCode::Permission.as_raw(), 77);
}

#[test]
fn noscope_exit_code_config_error_is_78() {
    assert_eq!(NoscopeExitCode::ConfigError.as_raw(), 78);
}

#[test]
fn noscope_exit_code_child_exit_preserves_child_code() {
    let code = NoscopeExitCode::ChildExit(42);
    assert_eq!(code.as_raw(), 42);
}

#[test]
fn noscope_exit_code_child_exit_zero_is_success() {
    let code = NoscopeExitCode::ChildExit(0);
    assert_eq!(code.as_raw(), 0);
}

#[test]
fn noscope_exit_code_child_exit_passes_through_any_value() {
    for val in [0, 1, 2, 42, 127, 255] {
        let code = NoscopeExitCode::ChildExit(val);
        assert_eq!(code.as_raw(), val);
    }
}

#[test]
fn noscope_exit_code_display_includes_meaning() {
    let display = format!("{}", NoscopeExitCode::MintFailure);
    assert!(
        display.to_lowercase().contains("mint"),
        "Should describe the failure: {}",
        display
    );
}

#[test]
fn noscope_exit_code_display_child_exit_mentions_child() {
    let display = format!("{}", NoscopeExitCode::ChildExit(1));
    assert!(
        display.to_lowercase().contains("child"),
        "Should mention child process: {}",
        display
    );
}

#[test]
fn noscope_exit_code_display_success_mentions_success() {
    let display = format!("{}", NoscopeExitCode::Success);
    assert!(
        display.to_lowercase().contains("success"),
        "Should mention success: {}",
        display
    );
}

#[test]
fn noscope_exit_codes_do_not_overlap_with_provider_codes() {
    // sysexits start at 64, provider codes are 0-4 -- no overlap
    let noscope_codes = [0, 64, 65, 66, 69, 70, 77, 78, 79];
    let provider_error_codes = [1, 2, 3, 4]; // exclude 0 (both mean success)
    for nc in &noscope_codes {
        if *nc == 0 {
            continue; // Both namespaces use 0 for success, that's fine
        }
        assert!(
            !provider_error_codes.contains(nc),
            "noscope code {} must not overlap with provider error codes",
            nc
        );
    }
}

#[test]
fn noscope_success_is_semantically_distinct_from_child_exit_zero() {
    // These both produce raw 0, but are semantically different:
    // Success = noscope completed (no child), ChildExit(0) = child ran and exited 0.
    assert_ne!(NoscopeExitCode::Success, NoscopeExitCode::ChildExit(0));
    assert_eq!(
        NoscopeExitCode::Success.as_raw(),
        NoscopeExitCode::ChildExit(0).as_raw()
    );
}

#[test]
fn signal_terminated_provider_maps_to_general_error() {
    // exit code 137 = killed by SIGKILL (128 + 9)
    let result = interpret_provider_exit(137);
    assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
}

#[test]
fn signal_terminated_provider_includes_signal_number() {
    // 128 + 9 = SIGKILL
    let result = interpret_provider_exit(137);
    assert!(
        result.signal_number.is_some(),
        "Should extract signal number"
    );
    assert_eq!(result.signal_number.unwrap(), 9);
}

#[test]
fn signal_terminated_provider_stderr_message_contains_signal() {
    let result = interpret_provider_exit(137);
    let msg = result.stderr_message();
    assert!(
        msg.contains("9"),
        "stderr message should contain signal number: {}",
        msg
    );
    assert!(
        msg.to_lowercase().contains("signal"),
        "stderr message should mention 'signal': {}",
        msg
    );
}

#[test]
fn exit_129_is_signal_1_sighup() {
    let result = interpret_provider_exit(129);
    assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
    assert_eq!(result.signal_number, Some(1));
}

#[test]
fn exit_exactly_128_is_not_signal_terminated() {
    // 128 itself is NOT signal-terminated (signals start at 128+1)
    let result = interpret_provider_exit(128);
    assert!(
        result.signal_number.is_none(),
        "Exit 128 is not signal-terminated"
    );
}

#[test]
fn exit_255_is_signal_127() {
    // Maximum valid Unix exit code
    let result = interpret_provider_exit(255);
    assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
    assert_eq!(result.signal_number, Some(127));
}

#[test]
fn negative_exit_code_maps_to_general_error_no_signal() {
    // Negative values are not valid Unix exit codes but i32 allows them.
    // Should fall through to general error without signal extraction.
    let result = interpret_provider_exit(-1);
    assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
    assert!(
        result.signal_number.is_none(),
        "Negative exit codes should not be treated as signals"
    );
}

#[test]
#[verifies("rule_exec_exit_interpretation", examples)]
fn known_provider_exit_codes_interpreted_directly() {
    let result = interpret_provider_exit(0);
    assert_eq!(result.exit_code, ProviderExitCode::Success);
    assert!(result.signal_number.is_none());

    let result = interpret_provider_exit(2);
    assert_eq!(result.exit_code, ProviderExitCode::AuthFailure);
    assert!(result.signal_number.is_none());

    let result = interpret_provider_exit(4);
    assert_eq!(result.exit_code, ProviderExitCode::Unavailable);
    assert!(result.signal_number.is_none());
}

#[test]
fn unknown_non_signal_exit_code_maps_to_general_error() {
    // Code 42 is not a known provider code and not >128
    let result = interpret_provider_exit(42);
    assert_eq!(result.exit_code, ProviderExitCode::GeneralError);
    assert!(result.signal_number.is_none());
}

#[test]
fn non_signal_stderr_message_shows_provider_exit_code() {
    let result = interpret_provider_exit(2);
    let msg = result.stderr_message();
    assert!(
        msg.to_lowercase().contains("auth"),
        "Non-signal stderr should show exit code meaning: {}",
        msg
    );
}

#[test]
fn provider_exit_result_implements_display() {
    let result = interpret_provider_exit(137);
    let display = format!("{}", result);
    assert!(
        display.to_lowercase().contains("signal"),
        "Display should mention signal: {}",
        display
    );

    let result = interpret_provider_exit(2);
    let display = format!("{}", result);
    assert!(
        display.to_lowercase().contains("auth"),
        "Display should show exit code meaning: {}",
        display
    );
}

#[test]
fn provider_exit_result_is_eq_comparable() {
    let a = interpret_provider_exit(137);
    let b = interpret_provider_exit(137);
    assert_eq!(a, b);

    let c = interpret_provider_exit(2);
    assert_ne!(a, c);
}
