//! `__swift5_capture` walker (lower priority).
//!
//! Decodes [`CaptureDescriptor`] entries — the per-closure capture
//! layouts the runtime needs to enumerate captured values. Cite:
//! `swift/include/swift/RemoteInspection/Records.h` (search
//! `CaptureDescriptor`).
//!
//! On-disk layout:
//!
//! ```text
//! struct CaptureDescriptor {
//!     uint32_t NumCaptureTypes;
//!     uint32_t NumMetadataSources;
//!     uint32_t NumBindings;
//!     CaptureTypeRecord    captures[NumCaptureTypes];      // 4 bytes each
//!     MetadataSourceRecord sources[NumMetadataSources];    // 8 bytes each
//!     // bindings (NumBindings) follow; structure varies by binding kind.
//! };
//! ```
//!
//! v0.1 surfaces the header (count of capture types, metadata
//! sources, bindings) plus the descriptor's VA. Per-binding
//! decoding is post-v0.1 — bindings vary by kind and require
//! extending the runtime's metadata-source machinery, which is
//! outside the v0.1 scope.

use crate::{swift::SwiftRuntime, util::read_u32_le_at};

/// Header size (bytes) — `(NumCaptureTypes, NumMetadataSources,
/// NumBindings)`.
const CAPTURE_HEADER_SIZE: u64 = 12;

/// Per-record size for `CaptureTypeRecord` (4 bytes — single
/// i32-relative pointer to the captured type's mangled name).
const CAPTURE_TYPE_RECORD_SIZE: u64 = 4;

/// Per-record size for `MetadataSourceRecord` (8 bytes — two
/// i32-relative pointers).
const METADATA_SOURCE_RECORD_SIZE: u64 = 8;

/// One `CaptureDescriptor` header.
#[derive(Debug, Clone)]
pub struct CaptureDescriptor {
    /// VA of the descriptor header inside `__swift5_capture`.
    pub address: u64,
    /// `NumCaptureTypes` — captured-type count.
    pub num_capture_types: u32,
    /// `NumMetadataSources` — count of `MetadataSourceRecord` entries.
    pub num_metadata_sources: u32,
    /// `NumBindings` — count of generic-binding entries (per-binding
    /// structure decoded post-v0.1).
    pub num_bindings: u32,
}

impl CaptureDescriptor {
    /// VA of the `CaptureTypeRecord[NumCaptureTypes]` array.
    pub fn capture_types_address(&self) -> u64 {
        self.address.wrapping_add(CAPTURE_HEADER_SIZE)
    }

    /// VA of the `MetadataSourceRecord[NumMetadataSources]` array.
    pub fn metadata_sources_address(&self) -> u64 {
        self.capture_types_address()
            .wrapping_add(u64::from(self.num_capture_types).wrapping_mul(CAPTURE_TYPE_RECORD_SIZE))
    }

    /// VA of the bindings region.
    pub fn bindings_address(&self) -> u64 {
        self.metadata_sources_address().wrapping_add(
            u64::from(self.num_metadata_sources).wrapping_mul(METADATA_SOURCE_RECORD_SIZE),
        )
    }
}

/// Iterator over `__swift5_capture`.
pub struct CaptureIter<'a, 'p> {
    rt: &'p SwiftRuntime<'a>,
    /// Byte offset into the section body. Each descriptor advances
    /// the cursor by `12 + 4 * NumCaptureTypes + 8 * NumMetadataSources`.
    /// (Bindings size varies per binding kind; v0.1 stops at the
    /// metadata-sources end since the runtime structure is the only
    /// way to size individual binding entries.)
    cursor: usize,
}

impl<'a, 'p> CaptureIter<'a, 'p> {
    pub(crate) fn new(rt: &'p SwiftRuntime<'a>) -> Self {
        Self { rt, cursor: 0 }
    }
}

impl<'a, 'p> Iterator for CaptureIter<'a, 'p> {
    type Item = CaptureDescriptor;
    fn next(&mut self) -> Option<Self::Item> {
        let section = self.rt.capture.as_ref()?;
        let start_off = self.cursor;
        let header_end = start_off.checked_add(CAPTURE_HEADER_SIZE as usize)?;
        if header_end > section.body.len() {
            return None;
        }
        let header = section.body.get(start_off..header_end)?;
        let num_capture_types = read_u32_le_at(header, 0)?;
        let num_metadata_sources = read_u32_le_at(header, 4)?;
        let num_bindings = read_u32_le_at(header, 8)?;

            // Compute the (lower-bound) descriptor end. Bindings are
            // omitted from this calculation because their per-entry
            // size depends on the binding kind — failing to size
            // them correctly would mis-align the next descriptor's
            // header, but for v0.1 we're conservative: stop after
            // metadata sources. If bindings are non-zero AND there
            // are more bytes left in the section, we bail out of the
            // iterator after this row. (Real-world usage: most
            // closures emit num_bindings == 0.)
            let after_captures = u64::from(num_capture_types)
                .checked_mul(CAPTURE_TYPE_RECORD_SIZE)
                .and_then(|n| n.checked_add(CAPTURE_HEADER_SIZE))?;
            let after_sources = u64::from(num_metadata_sources)
                .checked_mul(METADATA_SOURCE_RECORD_SIZE)
                .and_then(|n| n.checked_add(after_captures))?;
            let next_off_offset = usize::try_from(after_sources).ok()?;
            let next_off = start_off.checked_add(next_off_offset)?;

            let descriptor_va = section.vmaddr.wrapping_add(start_off as u64);

            self.cursor = if num_bindings != 0 {
                // Bindings of unknown size — stop after this row.
                section.body.len()
            } else if next_off > section.body.len() {
                section.body.len()
            } else {
                next_off
            };

        Some(CaptureDescriptor {
            address: descriptor_va,
            num_capture_types,
            num_metadata_sources,
            num_bindings,
        })
    }
}
