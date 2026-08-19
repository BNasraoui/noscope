// I/O adapters: config loading, provider command execution, child
// process lifecycle, and event emission.

pub mod agent_process;
pub mod command_parse;
pub(crate) mod config_path;
pub mod event;
pub mod process_group;
pub mod profile;
pub mod provider;
pub mod provider_exec;
pub mod run_signal_wiring;
pub mod security;
