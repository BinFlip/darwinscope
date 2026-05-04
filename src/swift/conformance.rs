//! `__swift5_proto` walker.
//!
//! Decodes [`Conformance`] rows — one per
//! `TargetProtocolConformanceDescriptor` (per
//! `swift/include/swift/ABI/Metadata.h:2837-2882` and
//! `RESEARCH.md:1956-1974`). The single most attribution-bearing
//! Swift section: every row binds a `(type, protocol, witness
//! table)` triple plus the [`crate::swift::ConformanceFlags`] that tag the
//! type-reference interpretation and any conditional-requirement
//! payload that follows.
//!
//! On-disk layout of the 16-byte header (each entry in the
//! `__swift5_proto` array is an i32 relative pointer to one of
//! these — *not* a flat array of structs):
//!
//! | Off | Field                | Type                         |
//! |-----|----------------------|------------------------------|
//! | 0   | Protocol             | i32 relative (ProtocolDescriptor) |
//! | 4   | TypeRef              | i32 relative (interpretation per Flags.TypeReferenceKind) |
//! | 8   | WitnessTablePattern  | i32 relative                 |
//! | 12  | ConformanceFlags     | `u32`                        |
//!
//! Trailing-objects (resilient witnesses, generic witness tables,
//! conditional requirements, generic pack shapes, global-actor
//! references) live past the header and are gated on the
//! corresponding `ConformanceFlags` bits. v0.1 surfaces the *flag
//! bits* — full structured decode of the trailing arrays is post-
//! v0.1.

use crate::{
    swift::{
        context::{ConformanceFlags, TypeReferenceKind},
        SwiftRuntime,
    },
    util::{read_i32_le_at, read_u32_le_at, relative_pointer},
};

/// Tagged interpretation of
/// `TargetProtocolConformanceDescriptor.TypeRef`.
///
/// The conformance descriptor's `TypeRef` slot is a polymorphic
/// reference to the type that's conforming — the Swift compiler
/// picks one of four encodings depending on whether the type is
/// Swift or Obj-C and whether the descriptor needs an extra layer
/// of indirection (for resilient classes, where the descriptor
/// pointer can be patched at runtime).
///
/// Cite:
/// `swift/include/swift/ABI/MetadataValues.h:556-589`
/// (`TypeReferenceKind`). The 3-bit kind tag is read from
/// [`crate::swift::ConformanceFlags::type_reference_kind`]; values
/// `0..=3` map to the four named variants below, and `4..=7` are
/// reserved (surfaced as [`Other`](Self::Other)).
#[derive(Debug, Clone)]
pub enum TypeReference<'a> {
    /// `kind = 0` — Direct relative pointer to a Swift
    /// `TargetTypeContextDescriptor`. The most common case for
    /// resilient-internal Swift types. Carries the resolved VA of
    /// the descriptor base.
    DirectTypeDescriptor(u64),
    /// `kind = 1` — Indirect relative pointer; the slot at the
    /// resolved VA contains a *pointer* to the
    /// `TargetTypeContextDescriptor`. Used for resilient-public
    /// types where the descriptor address may move across module
    /// versions. Carries the resolved VA of the indirection slot.
    IndirectTypeDescriptor(u64),
    /// `kind = 2` — Direct relative pointer to a NUL-terminated
    /// Obj-C class name (a C-string in `__TEXT,__objc_classname`).
    /// Used when a Swift type conforms on behalf of an imported
    /// Obj-C class. Already resolved into the borrowed string.
    DirectObjCClassName(&'a str),
    /// `kind = 3` — Indirect relative pointer to an Obj-C class
    /// object slot (`_OBJC_CLASS_$_<name>` inside `__DATA,__data`).
    /// Carries the resolved VA of the class-object slot.
    IndirectObjCClass(u64),
    /// Reserved kind tag in the range `4..=7`. Preserves the raw
    /// value plus the resolved target VA for forward-compat.
    Other {
        /// Raw 3-bit kind tag.
        kind: u8,
        /// Resolved VA computed as `relative_pointer(slot, raw)`.
        target: u64,
    },
}

/// One protocol-conformance row from `__swift5_proto`.
///
/// Cite: `swift/include/swift/ABI/Metadata.h:2837-2882`
/// (`TargetProtocolConformanceDescriptor`).
///
/// Each row binds a `(type, protocol, witness table)` triple — the
/// Swift runtime walks `__swift5_proto` at process start and
/// registers each conformance into the global protocol-witness
/// lookup, so casts of the form `value as? P` succeed for types
/// declared in this image. The witness-table-pattern slot is the
/// canonical witness table for non-generic conformances and a
/// pattern (with placeholders the runtime fills in) for generic
/// ones — gated on [`ConformanceFlags`].
///
/// On-disk layout is the 16-byte header documented at the top of
/// this module; trailing fields (resilient witnesses, conditional
/// requirements, generic pack shapes, global-actor references) live
/// past the header and are gated on the corresponding
/// `ConformanceFlags` bits. v0.1 surfaces the flag bits — full
/// structured decode of the trailing arrays is post-v0.1.
#[derive(Debug)]
pub struct Conformance<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) address: u64,
    pub(crate) protocol_descriptor_va: u64,
    pub(crate) type_ref: TypeReference<'a>,
    pub(crate) witness_table_va: u64,
    pub(crate) flags: ConformanceFlags,
}

impl<'a, 'p> Conformance<'a, 'p> {
    /// Owning [`SwiftRuntime`] borrow.
    pub fn runtime(&self) -> &'p SwiftRuntime<'a> {
        self.rt
    }

    /// VA of the conformance descriptor base.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Resolved VA of the protocol descriptor.
    pub fn protocol_descriptor_address(&self) -> u64 {
        self.protocol_descriptor_va
    }

    /// Tagged interpretation of the `TypeRef` field.
    pub fn type_ref(&self) -> &TypeReference<'a> {
        &self.type_ref
    }

    /// Resolved VA of the witness table (or witness-table pattern
    /// for generics). `0` when null.
    pub fn witness_table_address(&self) -> u64 {
        self.witness_table_va
    }

    /// Conformance flag word.
    pub fn flags(&self) -> ConformanceFlags {
        self.flags
    }
}

/// Iterator over `__swift5_proto`.
pub struct ConformanceIter<'a, 'p> {
    rt: &'p SwiftRuntime<'a>,
    cursor: usize,
}

impl<'a, 'p> ConformanceIter<'a, 'p> {
    pub(crate) fn new(rt: &'p SwiftRuntime<'a>) -> Self {
        Self { rt, cursor: 0 }
    }
}

impl<'a, 'p> Iterator for ConformanceIter<'a, 'p> {
    type Item = Conformance<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let section = self.rt.proto.as_ref()?;
        loop {
            let slot_off = self.cursor;
            let slot_end = slot_off.checked_add(4)?;
            if slot_end > section.body.len() {
                return None;
            }
            self.cursor = slot_end;

            let Some(rel) = read_i32_le_at(section.body, slot_off) else {
                continue;
            };
            if rel == 0 {
                continue;
            }
            let slot_va = section.vmaddr.wrapping_add(slot_off as u64);
            let descriptor_va = relative_pointer(slot_va, rel);

            if let Some(c) = decode_conformance(self.rt, descriptor_va) {
                return Some(c);
            }
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::swift: conformance descriptor at 0x{:x} (slot 0x{:x}) skipped",
                descriptor_va,
                slot_va,
            );
        }
    }
}

fn decode_conformance<'a, 'p>(
    rt: &'p SwiftRuntime<'a>,
    descriptor_va: u64,
) -> Option<Conformance<'a, 'p>> {
    let header = rt.read_bytes(descriptor_va, 16)?;
    let protocol_rel = read_i32_le_at(header, 0)?;
    let type_ref_rel = read_i32_le_at(header, 4)?;
    let witness_rel = read_i32_le_at(header, 8)?;
    let flags_raw = read_u32_le_at(header, 12)?;

    let flags = ConformanceFlags(flags_raw);

    let protocol_slot = descriptor_va;
    let protocol_descriptor_va = if protocol_rel == 0 {
        0
    } else {
        relative_pointer(protocol_slot, protocol_rel)
    };

    let type_ref_slot = descriptor_va.checked_add(4)?;
    let type_ref = decode_type_reference(rt, type_ref_slot, type_ref_rel, flags.type_reference_kind());

    let witness_slot = descriptor_va.checked_add(8)?;
    let witness_table_va = if witness_rel == 0 {
        0
    } else {
        relative_pointer(witness_slot, witness_rel)
    };

    Some(Conformance {
        rt,
        address: descriptor_va,
        protocol_descriptor_va,
        type_ref,
        witness_table_va,
        flags,
    })
}

fn decode_type_reference<'a>(
    rt: &SwiftRuntime<'a>,
    slot_va: u64,
    rel: i32,
    kind: TypeReferenceKind,
) -> TypeReference<'a> {
    let target = if rel == 0 {
        0
    } else {
        relative_pointer(slot_va, rel)
    };
    match kind {
        TypeReferenceKind::DirectTypeDescriptor => TypeReference::DirectTypeDescriptor(target),
        TypeReferenceKind::IndirectTypeDescriptor => TypeReference::IndirectTypeDescriptor(target),
        TypeReferenceKind::DirectObjCClassName => {
            // Resolve to the C-string. Fall back to a raw target if
            // the read fails (corrupt descriptor / out-of-range
            // pointer).
            match rt.read_cstr(target) {
                Some(name) => TypeReference::DirectObjCClassName(name),
                None => TypeReference::Other { kind: 2, target },
            }
        }
        TypeReferenceKind::IndirectObjCClass => TypeReference::IndirectObjCClass(target),
        TypeReferenceKind::Other(k) => TypeReference::Other { kind: k, target },
    }
}
