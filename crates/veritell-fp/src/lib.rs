//! Network-layer fingerprints. Pure parsers with no I/O and no proxy
//! dependency; every function tolerates arbitrary peer-controlled input.

pub mod h2;
pub mod ja4;
pub mod syn;
