//! `__swift5_fieldmd` walker + reflstr field-name resolution.
//!
//! Decodes a flat sequence of variable-length [`FieldDescriptor`]
//! records. Each carries a 16-byte header (per
//! `swift/include/swift/RemoteInspection/Records.h:177-247` and
//! `RESEARCH.md:2037-2049`) followed by `NumFields` x
//! `FieldRecordSize`-byte [`FieldRecord`] entries (per `Records.h:85-114`,
//! `RESEARCH.md:2066-2085`).
//!
//! Header layout:
//!
//! | Off | Field           | Type                |
//! |-----|-----------------|---------------------|
//! | 0   | MangledTypeName | i32 relative        |
//! | 4   | Superclass      | i32 relative        |
//! | 8   | Kind            | `u16`               |
//! | 10  | FieldRecordSize | `u16` (always 12)   |
//! | 12  | NumFields       | `u32`               |
//!
//! Each [`FieldRecord`] (12 bytes / entry):
//!
//! | Off | Field           | Type                |
//! |-----|-----------------|---------------------|
//! | 0   | Flags           | `u32`               |
//! | 4   | MangledTypeName | i32 relative        |
//! | 8   | FieldName       | i32 relative        |
//!
//! Field-name relative pointers target either a body-local NUL-
//! terminated string or a slot in `__swift5_reflstr`; both resolve
//! through [`reflstr::lookup_field_name`].

use crate::{
    swift::{
        context::{FieldDescriptorKind, FieldRecordFlags},
        reflstr, SwiftRuntime,
    },
    util::{read_i32_le_at, read_u16_le_at, read_u32_le_at, relative_pointer},
};

/// 16-byte fixed header.
const FIELD_DESCRIPTOR_HEADER_SIZE: u64 = 16;

/// One `TargetFieldDescriptor` entry from `__swift5_fieldmd`.
///
/// Cite: `swift/include/swift/RemoteInspection/Records.h:177-247`.
///
/// Field descriptors are how Swift exposes the *names* and
/// *mangled types* of nominal-type fields to runtime reflection
/// (`Mirror(reflecting:)`, `_typeName`, the `print` machinery for
/// custom types). Each nominal type that has stored properties
/// emits exactly one descriptor referenced by the type
/// descriptor's `Fields` slot.
///
/// Layout: 16-byte header (`MangledTypeName`, `Superclass`, `Kind`,
/// `FieldRecordSize`, `NumFields`) followed by `NumFields` ×
/// 12-byte [`FieldRecord`] entries. The `Kind` is read as a `u16`
/// rather than `u8` because the on-disk encoding leaves the high
/// byte reserved for future tag values; the meaningful tag still
/// fits in the low bits.
#[derive(Debug)]
pub struct FieldDescriptor<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) address: u64,
    pub(crate) mangled_type_name: Option<&'a str>,
    pub(crate) superclass_mangled_name: Option<&'a str>,
    pub(crate) kind: FieldDescriptorKind,
    pub(crate) field_record_size: u16,
    pub(crate) num_fields: u32,
}

impl<'a, 'p> FieldDescriptor<'a, 'p> {
    /// VA of the descriptor header.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Mangled type name the field block belongs to. `None` when
    /// the relative pointer is null.
    pub fn mangled_type_name(&self) -> Option<&'a str> {
        self.mangled_type_name
    }

    /// Mangled superclass name (only meaningful when
    /// [`Self::kind`] returns [`FieldDescriptorKind::Class`]).
    /// `None` for root classes and non-class kinds.
    pub fn superclass_mangled_name(&self) -> Option<&'a str> {
        self.superclass_mangled_name
    }

    /// Field-descriptor kind tag.
    pub fn kind(&self) -> FieldDescriptorKind {
        self.kind
    }

    /// `FieldRecordSize` — bytes per trailing record. Currently
    /// always `12`; surfaced verbatim so callers can detect
    /// future-runtime drift.
    pub fn field_record_size(&self) -> u16 {
        self.field_record_size
    }

    /// `NumFields` — count of trailing [`FieldRecord`] entries.
    pub fn num_fields(&self) -> u32 {
        self.num_fields
    }

    /// Iterator over the trailing field-record array.
    pub fn records(&self) -> FieldRecordIter<'a, 'p> {
        let base_va = self
            .address
            .checked_add(FIELD_DESCRIPTOR_HEADER_SIZE)
            .unwrap_or(0);
        FieldRecordIter {
            rt: self.rt,
            base_va,
            count: self.num_fields,
            entry_size: u32::from(self.field_record_size),
            cursor: 0,
        }
    }
}

/// One `TargetFieldRecord` entry inside a [`FieldDescriptor`].
#[derive(Debug, Clone)]
pub struct FieldRecord<'a> {
    pub(crate) flags: FieldRecordFlags,
    pub(crate) mangled_type_name: Option<&'a str>,
    pub(crate) field_name: Option<&'a str>,
}

impl<'a> FieldRecord<'a> {
    /// Per-record flag word.
    pub fn flags(&self) -> FieldRecordFlags {
        self.flags
    }

    /// Mangled type name of the field. `None` when the relative
    /// pointer is null.
    pub fn mangled_type_name(&self) -> Option<&'a str> {
        self.mangled_type_name
    }

    /// Field name (resolved through `__swift5_reflstr` if present).
    /// `None` when the relative pointer is null.
    pub fn field_name(&self) -> Option<&'a str> {
        self.field_name
    }
}

/// Iterator over `__swift5_fieldmd`.
pub struct FieldIter<'a, 'p> {
    rt: &'p SwiftRuntime<'a>,
    /// Byte offset into the section body. Each record advances the
    /// cursor by `16 + NumFields * FieldRecordSize`.
    cursor: usize,
}

impl<'a, 'p> FieldIter<'a, 'p> {
    pub(crate) fn new(rt: &'p SwiftRuntime<'a>) -> Self {
        Self { rt, cursor: 0 }
    }
}

impl<'a, 'p> Iterator for FieldIter<'a, 'p> {
    type Item = FieldDescriptor<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let section = self.rt.fieldmd.as_ref()?;
        let start_off = self.cursor;
        let header_end = start_off.checked_add(FIELD_DESCRIPTOR_HEADER_SIZE as usize)?;
        if header_end > section.body.len() {
            return None;
        }
        let header = section.body.get(start_off..header_end)?;

            let mangled_rel = read_i32_le_at(header, 0).unwrap_or(0);
            let superclass_rel = read_i32_le_at(header, 4).unwrap_or(0);
            let kind_raw = read_u16_le_at(header, 8).unwrap_or(0);
            let field_record_size = read_u16_le_at(header, 10).unwrap_or(12);
            let num_fields = read_u32_le_at(header, 12).unwrap_or(0);

            // Compute the start of the next record. If the size
            // arithmetic overflows or the records run past the
            // section body, fail-soft and stop.
            let body_size = u64::from(num_fields).checked_mul(u64::from(field_record_size));
            let total = body_size
                .and_then(|b| b.checked_add(FIELD_DESCRIPTOR_HEADER_SIZE))
                .and_then(|t| usize::try_from(t).ok());
            let next_off = total
                .and_then(|t| start_off.checked_add(t));
            self.cursor = match next_off {
                Some(off) if off <= section.body.len() => off,
                Some(_) | None => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        "darwinscope::swift: field descriptor at section+0x{:x} overruns __swift5_fieldmd — stop",
                        start_off,
                    );
                    return None;
                }
            };

            let descriptor_va = section.vmaddr.wrapping_add(start_off as u64);

            let mangled_slot_va = descriptor_va;
            let mangled_type_name = if mangled_rel == 0 {
                None
            } else {
                self.rt
                    .read_cstr(relative_pointer(mangled_slot_va, mangled_rel))
            };

            let superclass_slot_va = descriptor_va.checked_add(4)?;
            let superclass_mangled_name = if superclass_rel == 0 {
                None
            } else {
                self.rt
                    .read_cstr(relative_pointer(superclass_slot_va, superclass_rel))
            };

        Some(FieldDescriptor {
            rt: self.rt,
            address: descriptor_va,
            mangled_type_name,
            superclass_mangled_name,
            kind: FieldDescriptorKind::from_bits(kind_raw),
            field_record_size,
            num_fields,
        })
    }
}

/// Iterator over [`FieldRecord`] entries inside a single
/// [`FieldDescriptor`].
pub struct FieldRecordIter<'a, 'p> {
    rt: &'p SwiftRuntime<'a>,
    base_va: u64,
    count: u32,
    entry_size: u32,
    cursor: u32,
}

impl<'a, 'p> Iterator for FieldRecordIter<'a, 'p> {
    type Item = FieldRecord<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.count {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;

        let entry_off = u64::from(i).checked_mul(u64::from(self.entry_size))?;
        let entry_va = self.base_va.checked_add(entry_off)?;

        let bytes = self.rt.read_bytes(entry_va, 12)?;
        let flags_raw = read_u32_le_at(bytes, 0)?;
        let mangled_rel = read_i32_le_at(bytes, 4)?;
        let name_rel = read_i32_le_at(bytes, 8)?;

        let flags = FieldRecordFlags(flags_raw);

        let mangled_slot_va = entry_va.checked_add(4)?;
        let mangled_type_name = if mangled_rel == 0 {
            None
        } else {
            self.rt
                .read_cstr(relative_pointer(mangled_slot_va, mangled_rel))
        };

        let name_slot_va = entry_va.checked_add(8)?;
        let field_name = if name_rel == 0 {
            None
        } else {
            reflstr::lookup_field_name(self.rt, relative_pointer(name_slot_va, name_rel))
        };

        Some(FieldRecord {
            flags,
            mangled_type_name,
            field_name,
        })
    }
}
