//! Decision events: where they go and how they are queried.
//!
//! Sinks sit on the request path. `record` must return quickly, never block
//! on I/O and never panic, whatever the event contains.

pub mod addr;
pub mod clickhouse;
mod ring;
mod types;

pub use ring::{Fanout, MemoryRing};
pub use types::*;
