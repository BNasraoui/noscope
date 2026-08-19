// Application layer.
//
// One place composes the core types and the I/O ports into the noscope
// workflows. The binary's command handlers call these functions instead of
// assembling providers, specs, and closures themselves.

pub mod mint;
pub mod resolve;
