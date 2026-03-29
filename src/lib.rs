mod config_path;
pub mod cli_adapter;
pub mod client;
pub mod credential_set;
pub mod error;
pub mod event;
pub mod exit_code;
pub mod mint;
pub mod profile;
pub mod provider;
pub mod provider_exec;
pub mod redaction;
pub mod refresh;
pub mod security;
pub mod token;
pub mod token_convert;

// ---------------------------------------------------------------------------
// Re-exports: stable, ergonomic types from crate root (noscope-cg8.1).
//
// Consumers can write `use noscope::{Client, MintRequest, NoscopeError}`
// instead of importing from individual modules.
// ---------------------------------------------------------------------------

pub use client::{Client, ClientOptions, MintRequest, NoscopeError, ProviderOverrides, RevokeRequest};
pub use error::{Error, ErrorKind};
pub use event::{Event, EventType, LogFormat};
pub use exit_code::{NoscopeExitCode, ProviderExitCode};
pub use mint::MintEnvelope;
pub use token::ScopedToken;
pub use token_convert::{
    provider_output_to_scoped_token, provider_output_to_scoped_token_with_metadata,
    scoped_token_to_mint_envelope, ConversionResult,
};
