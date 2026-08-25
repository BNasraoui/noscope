//! Materializes the NoScope requirements-as-code declaration.
//!
//! Writes the typed desired-state document to standard output so the
//! Provenance CLI can reconcile it:
//!
//! ```text
//! cargo run --features provenance-spec --bin noscope-provenance-spec \
//!   | provenance sdk plan --repo .
//! ```
//!
//! `provenance sdk apply` consumes the same document and writes the result.

use std::process::ExitCode;

fn main() -> ExitCode {
    let materialized = match noscope::provenance_spec::desired_state() {
        Ok(materialized) => materialized,
        Err(error) => {
            eprintln!("declaration is invalid: {error}");
            return ExitCode::FAILURE;
        }
    };
    match serde_json::to_string_pretty(&materialized) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not serialize the document: {error}");
            ExitCode::FAILURE
        }
    }
}
