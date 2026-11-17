//! Client interrogation, server side: checks the report sent by the probe
//! script against what the request claimed and against itself.
//!
//! Everything in a report is attacker-controlled. Nothing here may panic.

mod analyze;
mod nonce;
mod parse;
mod types;

pub use analyze::analyze;
pub use nonce::{issue_nonce, verify_nonce, ProbeKey};
pub use parse::{parse_report, parse_truth};
pub use types::*;
