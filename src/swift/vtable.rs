//! Vtable + override-table entry decoders.
//!
//! Decodes the [`VTableEntry`], [`OverrideEntry`], and
//! [`DefaultOverrideEntry`] arrays trailing a `TargetClassDescriptor`
//! when the [`crate::swift::TypeContextDescriptorFlags::class_has_vtable`]
//! / `class_has_override_table` /
//! `class_has_default_override_table` bits are set.
//!
//! Per-entry layouts:
//!
//! - **`TargetMethodDescriptor`** (8 bytes): `Flags` (`u32`) +
//!   `Impl` (i32 relative).
//! - **`TargetMethodOverrideDescriptor`** (12 bytes): `Class` (i32
//!   relative ContextDescriptor) + `Method` (i32 relative
//!   MethodDescriptor) + `Impl` (i32 relative).
//! - **`TargetMethodDefaultOverrideDescriptor`** (8 bytes):
//!   `Method` (i32 relative MethodDescriptor) + `Impl` (i32
//!   relative).

use crate::{
    swift::{
        context::{MethodDescriptorFlags, SwiftMethodKind},
        SwiftRuntime,
    },
    util::{read_i32_le_at, read_u32_le_at, relative_pointer},
};

/// One `TargetMethodDescriptor` entry from a Swift class vtable.
///
/// Cite: `swift/include/swift/ABI/Metadata.h:2138-2168`
/// (`TargetMethodDescriptor`).
///
/// Each entry is exactly 8 bytes on disk: a `u32` `Flags` word
/// followed by a 4-byte i32 relative pointer to the implementation.
/// Swift class vtables are append-only — subclasses extend rather
/// than replace the parent's vtable, and override-table entries
/// (decoded as [`OverrideEntry`] / [`DefaultOverrideEntry`])
/// re-target individual slots without changing the layout.
///
/// `impl_va == 0` marks an *abstract* slot: the slot is reserved in
/// the layout but no concrete implementation lives in this image.
/// Protocol witness tables are populated through this mechanism
/// (the conforming class supplies the real address at runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VTableEntry {
    /// VA of the descriptor (start of the 8-byte entry on disk).
    pub address: u64,
    /// Decoded `MethodDescriptorFlags` — kind tag (Method / Init /
    /// Getter / Setter / etc.), `IsInstance` bit, dynamic-dispatch
    /// flags. See [`MethodDescriptorFlags`] for the full layout.
    pub flags: MethodDescriptorFlags,
    /// `Impl` target VA, resolved from the i32 relative pointer.
    /// `0` when the entry has no implementation (abstract vtable
    /// slot — typically protocol-method declaration that conforming
    /// classes fill in at runtime).
    pub impl_va: u64,
}

impl VTableEntry {
    /// Convenience: dispatch kind from [`Self::flags`].
    pub fn kind(self) -> SwiftMethodKind {
        self.flags.kind()
    }

    /// Convenience: `IsInstance` from [`Self::flags`].
    pub fn is_instance(self) -> bool {
        self.flags.is_instance()
    }
}

/// Iterator over `TargetMethodDescriptor[VTableSize]`.
pub struct VTableIter<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) base_va: u64,
    pub(crate) count: u32,
    pub(crate) cursor: u32,
}

impl<'a, 'p> VTableIter<'a, 'p> {
    #[allow(dead_code)] // Reserved for explicit-empty construction by future PRs.
    pub(crate) fn empty(rt: &'p SwiftRuntime<'a>) -> Self {
        Self {
            rt,
            base_va: 0,
            count: 0,
            cursor: 0,
        }
    }
}

impl<'a, 'p> Iterator for VTableIter<'a, 'p> {
    type Item = VTableEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.count {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;
        let entry_off = u64::from(i).checked_mul(8)?;
        let entry_va = self.base_va.checked_add(entry_off)?;

        let bytes = self.rt.read_bytes(entry_va, 8)?;
        let flags_raw = read_u32_le_at(bytes, 0)?;
        let impl_rel = read_i32_le_at(bytes, 4)?;

        let impl_slot_va = entry_va.checked_add(4)?;
        let impl_va = if impl_rel == 0 {
            0
        } else {
            relative_pointer(impl_slot_va, impl_rel)
        };

        Some(VTableEntry {
            address: entry_va,
            flags: MethodDescriptorFlags(flags_raw),
            impl_va,
        })
    }
}

/// One `TargetMethodOverrideDescriptor` entry.
///
/// Cite: `swift/include/swift/ABI/Metadata.h` (search
/// `TargetMethodOverrideDescriptor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverrideEntry {
    /// VA of the descriptor (start of the 12-byte entry on disk).
    pub address: u64,
    /// Resolved VA of the parent class context descriptor (the
    /// class introducing the method being overridden). `0` if null.
    pub class_va: u64,
    /// Resolved VA of the parent class's `TargetMethodDescriptor`
    /// being overridden. `0` if null.
    pub method_va: u64,
    /// `Impl` target VA in this subclass, resolved from the i32
    /// relative pointer. `0` if null.
    pub impl_va: u64,
}

/// Iterator over `TargetMethodOverrideDescriptor[NumEntries]`.
pub struct OverrideEntryIter<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) base_va: u64,
    pub(crate) count: u32,
    pub(crate) cursor: u32,
}

impl<'a, 'p> OverrideEntryIter<'a, 'p> {
    #[allow(dead_code)] // Reserved for explicit-empty construction by future PRs.
    pub(crate) fn empty(rt: &'p SwiftRuntime<'a>) -> Self {
        Self {
            rt,
            base_va: 0,
            count: 0,
            cursor: 0,
        }
    }
}

impl<'a, 'p> Iterator for OverrideEntryIter<'a, 'p> {
    type Item = OverrideEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.count {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;
        let entry_off = u64::from(i).checked_mul(12)?;
        let entry_va = self.base_va.checked_add(entry_off)?;

        let bytes = self.rt.read_bytes(entry_va, 12)?;
        let class_rel = read_i32_le_at(bytes, 0)?;
        let method_rel = read_i32_le_at(bytes, 4)?;
        let impl_rel = read_i32_le_at(bytes, 8)?;

        let class_va = if class_rel == 0 {
            0
        } else {
            relative_pointer(entry_va, class_rel)
        };
        let method_slot_va = entry_va.checked_add(4)?;
        let method_va = if method_rel == 0 {
            0
        } else {
            relative_pointer(method_slot_va, method_rel)
        };
        let impl_slot_va = entry_va.checked_add(8)?;
        let impl_va = if impl_rel == 0 {
            0
        } else {
            relative_pointer(impl_slot_va, impl_rel)
        };

        Some(OverrideEntry {
            address: entry_va,
            class_va,
            method_va,
            impl_va,
        })
    }
}

/// One `TargetMethodDefaultOverrideDescriptor` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultOverrideEntry {
    /// VA of the descriptor on disk.
    pub address: u64,
    /// Resolved VA of the protocol method being defaulted.
    pub method_va: u64,
    /// `Impl` target VA, resolved from the i32 relative pointer.
    pub impl_va: u64,
}

/// Iterator over default-override-table entries.
pub struct DefaultOverrideEntryIter<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) base_va: u64,
    pub(crate) count: u32,
    pub(crate) cursor: u32,
}

impl<'a, 'p> DefaultOverrideEntryIter<'a, 'p> {
    #[allow(dead_code)] // Reserved for explicit-empty construction by future PRs.
    pub(crate) fn empty(rt: &'p SwiftRuntime<'a>) -> Self {
        Self {
            rt,
            base_va: 0,
            count: 0,
            cursor: 0,
        }
    }
}

impl<'a, 'p> Iterator for DefaultOverrideEntryIter<'a, 'p> {
    type Item = DefaultOverrideEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.count {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;
        let entry_off = u64::from(i).checked_mul(8)?;
        let entry_va = self.base_va.checked_add(entry_off)?;

        let bytes = self.rt.read_bytes(entry_va, 8)?;
        let method_rel = read_i32_le_at(bytes, 0)?;
        let impl_rel = read_i32_le_at(bytes, 4)?;

        let method_va = if method_rel == 0 {
            0
        } else {
            relative_pointer(entry_va, method_rel)
        };
        let impl_slot_va = entry_va.checked_add(4)?;
        let impl_va = if impl_rel == 0 {
            0
        } else {
            relative_pointer(impl_slot_va, impl_rel)
        };

        Some(DefaultOverrideEntry {
            address: entry_va,
            method_va,
            impl_va,
        })
    }
}
