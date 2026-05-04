//! Error and result types for `darwinscope`.
//!
//! The crate follows a fail-soft posture: structural parse failures
//! yield [`Error`], but per-row decode failures inside variable-length
//! tables (method lists, ivar lists, type descriptors) are silently
//! skipped. This mirrors the convention in the sibling parser crates
//! (`undelphi`, `visualbasic`, `innospect`) — partial data is more
//! useful than an all-or-nothing failure when staring at a malformed
//! or adversarial sample.

use std::fmt;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level errors surfaced from `MachoBinary::parse` and friends.
///
/// Per-row decode failures inside variable-length runtime tables do
/// not produce `Error`s — they are skipped silently, with optional
/// `tracing` events when the `tracing` feature is enabled.
#[derive(Debug)]
pub enum Error {
    /// The byte slice is not a Mach-O image (no recognised magic).
    NotMachO,
    /// Goblin failed to decode the structural Mach-O layer.
    Structural(String),
    /// A multi-architecture (fat / universal) wrapper was supplied
    /// but no slice matched the requested selection criteria.
    NoMatchingArchSlice,
    /// Catch-all for unexpected I/O or layout errors.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMachO => f.write_str("input is not a Mach-O binary"),
            Self::Structural(s) => write!(f, "structural decode error: {s}"),
            Self::NoMatchingArchSlice => {
                f.write_str("no matching architecture slice in fat binary")
            }
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

impl From<goblin::error::Error> for Error {
    fn from(e: goblin::error::Error) -> Self {
        Self::Structural(e.to_string())
    }
}
