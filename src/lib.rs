// noscope: short-lived credential supervision for agent subprocesses.
//
// Three layers:
// - `core`: domain types and policies, no I/O.
// - `ports`: I/O adapters — config loading, provider command execution,
//   child process lifecycle, event emission.
// - `app`: the workflows (`mint`, `revoke`, `run`, `doctor`) composing
//   core and ports; `cli` maps clap input onto them.

pub mod app;
pub mod cli;
pub mod core;
pub mod ports;

pub use app::client::{Client, ClientOptions, MintRequest, ProviderOverrides};
pub use core::error::{Error, ErrorKind};
pub use core::exit_code::{NoscopeExitCode, ProviderExitCode};
pub use core::mint::MintEnvelope;
pub use core::token::ScopedToken;
pub use ports::event::{Event, EventType, LogFormat};
