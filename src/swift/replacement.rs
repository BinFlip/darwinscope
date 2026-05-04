//! `__swift5_replac` walker (lower priority).
//!
//! Decodes [`DynamicReplacementScope`] entries — the original /
//! replacement function pairs the Swift runtime resolves at
//! `_dynamicReplacement(for:)` time. Cite:
//! `swift/include/swift/ABI/Metadata.h` (search
//! `AutomaticDynamicReplacements`).
//!
//! `__swift5_replac` is laid out as a single
//! `AutomaticDynamicReplacements` header (8 bytes: `flags` u32 +
//! `num_scopes` u32) followed by `num_scopes`
//! `AutomaticDynamicReplacementEntry` records. Each entry is 8
//! bytes: a relative pointer to a `DynamicReplacementScope` plus a
//! `u32` flag word. The walker surfaces one
//! [`DynamicReplacementScope`] per entry (one row per scope) — the
//! per-replacement function-pair table inside each scope is
//! decoded only enough to surface count + base.
//!
//! v0.1 surfaces presence + per-scope flags / counts; structural
//! decode of individual replacement function pairs is post-v0.1.

use crate::{
    swift::SwiftRuntime,
    util::{read_i32_le_at, read_u32_le_at, relative_pointer},
};

/// One `DynamicReplacementScope` entry.
#[derive(Debug, Clone)]
pub struct DynamicReplacementScope {
    /// VA of the entry record inside `__swift5_replac`.
    pub address: u64,
    /// Resolved VA of the `DynamicReplacementScope` payload.
    pub scope_va: u64,
    /// `flags` word stored on the entry.
    pub flags: u32,
}

/// Iterator over `__swift5_replac`.
pub struct ReplacementIter<'a, 'p> {
    rt: &'p SwiftRuntime<'a>,
    /// Byte offset into the section body. Pre-walks the
    /// `AutomaticDynamicReplacements` header on first iteration.
    cursor: usize,
    /// Total entry count from the header. `0` means uninitialised
    /// or section absent.
    total: u32,
    /// Entries already yielded.
    consumed: u32,
    /// Have we read the header?
    header_done: bool,
}

impl<'a, 'p> ReplacementIter<'a, 'p> {
    pub(crate) fn new(rt: &'p SwiftRuntime<'a>) -> Self {
        Self {
            rt,
            cursor: 0,
            total: 0,
            consumed: 0,
            header_done: false,
        }
    }
}

impl<'a, 'p> Iterator for ReplacementIter<'a, 'p> {
    type Item = DynamicReplacementScope;
    fn next(&mut self) -> Option<Self::Item> {
        let section = self.rt.replac.as_ref()?;

        if !self.header_done {
            // Read the AutomaticDynamicReplacements header at offset
            // 0: (flags, num_scopes). Both u32.
            let header = section.body.get(0..8)?;
            // Skip the flags word; surface only the count.
            let num_scopes = read_u32_le_at(header, 4)?;
            self.total = num_scopes;
            self.cursor = 8;
            self.header_done = true;
        }

        if self.consumed >= self.total {
            return None;
        }

        // Each entry is 8 bytes: scope (i32 rel) + flags (u32).
        let entry_off = self.cursor;
        let entry_end = entry_off.checked_add(8)?;
        if entry_end > section.body.len() {
            return None;
        }
        let bytes = section.body.get(entry_off..entry_end)?;
        let scope_rel = read_i32_le_at(bytes, 0)?;
        let flags = read_u32_le_at(bytes, 4)?;

        self.cursor = entry_end;
        self.consumed = self.consumed.checked_add(1)?;

        let entry_va = section.vmaddr.wrapping_add(entry_off as u64);
        let scope_va = if scope_rel == 0 {
            0
        } else {
            relative_pointer(entry_va, scope_rel)
        };

        Some(DynamicReplacementScope {
            address: entry_va,
            scope_va,
            flags,
        })
    }
}
