#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn consolidate_duplicated_run_signal_loop_logic_main_uses_shared_dispatch_helper() {
        let main_rs =
            std::fs::read_to_string(repo_root().join("src/main.rs")).expect("read src/main.rs");

        assert!(
            main_rs.contains("dispatch_pending_parent_signals("),
            "noscope-3ez.4: src/main.rs must dispatch via shared helper"
        );
        assert!(
            !main_rs.contains("wiring.on_parent_signal(parent_signal"),
            "noscope-3ez.4: src/main.rs must not inline signal dispatch loop"
        );
    }

    #[test]
    fn consolidate_duplicated_run_signal_loop_logic_integration_runtime_uses_shared_dispatch_helper(
    ) {
        let integration_runtime_rs =
            std::fs::read_to_string(repo_root().join("src/integration_runtime.rs"))
                .expect("read src/integration_runtime.rs");

        assert!(
            integration_runtime_rs.contains("dispatch_pending_parent_signals("),
            "noscope-3ez.4: src/integration_runtime.rs must dispatch via shared helper"
        );
        assert!(
            !integration_runtime_rs.contains("wiring.on_parent_signal(parent_signal"),
            "noscope-3ez.4: src/integration_runtime.rs must not inline signal dispatch loop"
        );
    }
}
