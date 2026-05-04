//! Class- (and value-type-) trailing-objects decoders.
//!
//! Walks the trailing-objects sequence after a class / struct /
//! enum context descriptor's fixed header. Each block is conditionally
//! present based on the descriptor's
//! [`crate::swift::ContextDescriptorFlags`] common header and
//! [`crate::swift::TypeContextDescriptorFlags`] kind-specific block.
//!
//! Cite: `swift/include/swift/ABI/Metadata.h:4258-4280` (class
//! `TrailingGenericContextObjects` member list) and
//! `RESEARCH.md:1854-1881`.
//!
//! Block order (declared in the trailing-objects template type
//! list — fixed, can't be permuted):
//!
//! 1. `TargetTypeGenericContextDescriptorHeader` — iff `Generic`.
//! 2. `TargetResilientSuperclass` — iff
//!    `Class_HasResilientSuperclass` (class only).
//! 3. `TargetForeignMetadataInitialization` — iff
//!    `MetadataInitialization == Foreign`.
//! 4. `TargetSingletonMetadataInitialization` — iff
//!    `MetadataInitialization == Singleton`.
//! 5. `TargetVTableDescriptorHeader` + `TargetMethodDescriptor[N]`
//!    — iff `Class_HasVTable` (class only).
//! 6. `TargetOverrideTableHeader` +
//!    `TargetMethodOverrideDescriptor[N]` — iff
//!    `Class_HasOverrideTable` (class only).
//! 7. `TargetObjCResilientClassStubInfo` — iff stub-flag set
//!    (class only). Detected via the `ExtraClassFlags`
//!    `HasObjCResilientClassStub` bit.
//! 8. Canonical specialised metadatas (count + entries +
//!    accessors) — iff
//!    [`crate::swift::TypeContextDescriptorFlags::has_canonical_metadata_prespecializations`]
//!    is set.
//! 9. `InvertibleProtocolSet` — iff
//!    [`crate::swift::ContextDescriptorFlags::has_invertible_protocols`].
//! 10. `TargetSingletonMetadataPointer` — iff
//!     [`crate::swift::TypeContextDescriptorFlags::has_singleton_metadata_pointer`].
//! 11. `TargetMethodDefaultOverrideTableHeader` +
//!     `TargetMethodDefaultOverrideDescriptor[N]` — iff
//!     `Class_HasDefaultOverrideTable` (class only).
//!
//! All inter-block alignment is 4 bytes — every relative pointer
//! and `u32` count satisfies that natively. The lone exception is
//! `InvertibleProtocolSet` (a `u16`), which we pad to 4 bytes after
//! consuming the payload to keep the cursor 4-aligned for any
//! subsequent block.
//!
//! Per-row decode failures fail-soft: if reading a block's size
//! word fails, the cursor stops advancing and subsequent blocks
//! are silently skipped. Better to surface partial trailing
//! information than to fail the entire descriptor walk.

use crate::{
    swift::{
        SwiftRuntime,
        context::{ContextDescriptorFlags, MetadataInitializationKind},
        typedescriptor::{
            ClassBody, DefaultOverrideTableHeader, OverrideTableHeader, VTableHeader,
        },
    },
    util::{read_i32_le_at, read_u16_le_at, read_u32_le_at, relative_pointer},
};

/// `TargetGenericContextDescriptorHeader` decoded snapshot — the
/// universal generic header. For type-kind descriptors the on-disk
/// `TargetTypeGenericContextDescriptorHeader` adds
/// `(InstantiationCache, DefaultInstantiationPattern)` slots
/// *before* the base; the value-type walker does not surface those
/// pointers separately because the subsequent prespecialisation
/// block is the only thing that consumes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericContextHeader<'a> {
    /// VA of the header.
    pub address: u64,
    /// `NumParams` — generic parameter count.
    pub num_params: u16,
    /// `NumRequirements` — generic-requirement count.
    pub num_requirements: u16,
    /// `NumKeyArguments` — runtime-passed generic argument count.
    pub num_key_arguments: u16,
    /// `NumExtraArguments` (renamed `NumPackShapes` in modern Swift)
    /// — extra generic-argument count.
    pub num_extra_arguments: u16,
    /// `InstantiationCache` relative pointer (resolved VA, `0` when
    /// null) — present for type-context generic headers.
    pub instantiation_cache_va: u64,
    /// `DefaultInstantiationPattern` relative pointer (resolved VA,
    /// `0` when null) — present for type-context generic headers.
    pub default_instantiation_pattern_va: u64,
    /// VA of the trailing `GenericParamDescriptor[NumParams]` array.
    pub params_base_va: u64,
    /// VA of the trailing `GenericRequirementDescriptor[NumRequirements]`
    /// array.
    pub requirements_base_va: u64,
    /// Phantom borrow tying the header to the [`SwiftRuntime`] data
    /// slice for forward-compat.
    pub _marker: core::marker::PhantomData<&'a [u8]>,
}

/// `TargetResilientSuperclass` — class trailing block carrying the
/// resilient-superclass type reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResilientSuperclass<'a> {
    /// VA of the trailing block.
    pub address: u64,
    /// Resolved VA of the superclass type reference (interpretation
    /// per
    /// [`crate::swift::TypeContextDescriptorFlags::class_resilient_superclass_reference_kind`]).
    pub superclass_va: u64,
    /// Phantom borrow.
    pub _marker: core::marker::PhantomData<&'a [u8]>,
}

/// `TargetForeignMetadataInitialization` — trailing block emitted
/// when [`crate::swift::MetadataInitializationKind::Foreign`] is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignMetadataInit {
    /// VA of the trailing block.
    pub address: u64,
    /// Resolved VA of the `CompletionFunction` relative pointer.
    pub completion_function_va: u64,
}

/// `TargetSingletonMetadataInitialization` — trailing block emitted
/// when [`crate::swift::MetadataInitializationKind::Singleton`] is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingletonMetadataInit {
    /// VA of the trailing block.
    pub address: u64,
    /// Resolved VA of `InitializationCache` (relative pointer).
    pub initialization_cache_va: u64,
    /// Resolved VA of `IncompleteMetadata` / `ResilientPattern`
    /// (relative pointer; first union slot).
    pub incomplete_metadata_va: u64,
    /// Resolved VA of the `CompletionFunction` (compact function
    /// pointer).
    pub completion_function_va: u64,
}

/// `TargetSingletonMetadataPointer` — trailing block emitted when
/// [`crate::swift::TypeContextDescriptorFlags::has_singleton_metadata_pointer`]
/// is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingletonMetadataPointer {
    /// VA of the trailing block.
    pub address: u64,
    /// Resolved VA of the singleton metadata pointer slot.
    pub metadata_va: u64,
}

/// `TargetObjCResilientClassStubInfo` — trailing block emitted when
/// the class declares an Obj-C resilient stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcResilientClassStubInfo {
    /// VA of the trailing block.
    pub address: u64,
    /// Resolved VA of the stub.
    pub stub_va: u64,
}

/// 16-bit `InvertibleProtocolSet` payload — emitted when
/// [`crate::swift::ContextDescriptorFlags::has_invertible_protocols`] is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvertibleProtocolSet {
    /// VA of the payload.
    pub address: u64,
    /// 16-bit bitmask of inverted protocol kinds (`Copyable`,
    /// `Escapable`, …) — bit positions per
    /// `swift/include/swift/ABI/InvertibleProtocols.def`.
    pub bits: u16,
}

/// Iterator over canonical-specialised-metadata pointers
/// (prespecialisations).
pub struct PrespecializationIter<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) base_va: u64,
    pub(crate) count: u32,
    pub(crate) cursor: u32,
}

impl<'a, 'p> PrespecializationIter<'a, 'p> {
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

impl<'a, 'p> Iterator for PrespecializationIter<'a, 'p> {
    /// Resolved VA of one canonical specialised metadata pointer.
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.count {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;
        let entry_off = u64::from(i).checked_mul(4)?;
        let slot_va = self.base_va.checked_add(entry_off)?;
        let bytes = self.rt.read_bytes(slot_va, 4)?;
        let rel = read_i32_le_at(bytes, 0)?;
        if rel == 0 {
            return Some(0);
        }
        Some(relative_pointer(slot_va, rel))
    }
}

/// Walk the trailing-objects sequence after a class descriptor, in
/// declared order, populating the [`ClassBody`] in place.
///
/// `trailing_start` is the VA of the first byte after the
/// `TargetClassDescriptor` fixed header (i.e. base + 24).
pub(crate) fn decode_class_trailers<'a>(
    rt: &SwiftRuntime<'a>,
    flags: &ContextDescriptorFlags,
    trailing_start: u64,
    body: &mut ClassBody<'a>,
) {
    let type_flags = flags.type_flags();
    let mut cursor = trailing_start;

    // 1. Generic header
    if flags.is_generic() {
        if let Some((header_va, end)) = decode_generic_header(rt, cursor) {
            body.generic_header_va = Some(header_va);
            cursor = end;
        } else {
            return;
        }
    }

    // 2. Resilient superclass
    if type_flags.class_has_resilient_superclass() {
        body.resilient_superclass_va = Some(cursor);
        cursor = match cursor.checked_add(4) {
            Some(c) => c,
            None => return,
        };
    }

    // 3 & 4. Metadata-initialisation block (mutually exclusive).
    match type_flags.metadata_initialization() {
        MetadataInitializationKind::Foreign => {
            body.foreign_metadata_init_va = Some(cursor);
            cursor = match cursor.checked_add(4) {
                Some(c) => c,
                None => return,
            };
        }
        MetadataInitializationKind::Singleton => {
            body.singleton_metadata_init_va = Some(cursor);
            cursor = match cursor.checked_add(12) {
                Some(c) => c,
                None => return,
            };
        }
        MetadataInitializationKind::None | MetadataInitializationKind::Other => {}
    }

    // 5. VTable
    if type_flags.class_has_vtable() {
        match decode_vtable_header(rt, cursor) {
            Some((header, end)) => {
                body.vtable_header = Some(header);
                cursor = end;
            }
            None => return,
        }
    }

    // 6. Override table
    if type_flags.class_has_override_table() {
        match decode_override_header(rt, cursor) {
            Some((header, end)) => {
                body.override_table_header = Some(header);
                cursor = end;
            }
            None => return,
        }
    }

    // 7. ObjC resilient class stub info — gated on a bit in
    // ExtraClassFlags. We surface presence when ExtraClassFlags is
    // populated AND its bit 0 (HasObjCResilientClassStub) is set.
    let has_objc_stub = body
        .extra_class_flags
        .map(|f| (f & 0x1) != 0)
        .unwrap_or(false);
    if has_objc_stub {
        body.objc_resilient_class_stub_va = Some(cursor);
        cursor = match cursor.checked_add(4) {
            Some(c) => c,
            None => return,
        };
    }

    // 8. Canonical specialised metadatas
    if type_flags.has_canonical_metadata_prespecializations() {
        match decode_prespecializations(rt, cursor) {
            Some((count, base_va, end)) => {
                body.prespecializations_count = Some(count);
                body.prespecializations_base_va = Some(base_va);
                cursor = end;
            }
            None => return,
        }
    }

    // 9. Invertible protocol set
    if flags.has_invertible_protocols() {
        match read_u16_at_va(rt, cursor) {
            Some(bits) => {
                body.invertible_protocol_set = Some(bits);
                // Pad to 4-byte boundary for any subsequent block.
                cursor = match cursor.checked_add(4) {
                    Some(c) => c,
                    None => return,
                };
            }
            None => return,
        }
    }

    // 10. Singleton metadata pointer
    if type_flags.has_singleton_metadata_pointer() {
        body.singleton_metadata_pointer_va = Some(cursor);
        cursor = match cursor.checked_add(4) {
            Some(c) => c,
            None => return,
        };
    }

    // 11. Default override table
    if type_flags.class_has_default_override_table()
        && let Some((header, _end)) = decode_default_override_header(rt, cursor)
    {
        body.default_override_table_header = Some(header);
    }
}

/// Walk the trailing-objects sequence after a value-type descriptor
/// (struct / enum), invoking the supplied callbacks as each block
/// is decoded.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_value_type_trailers(
    rt: &SwiftRuntime<'_>,
    flags: &ContextDescriptorFlags,
    trailing_start: u64,
    mut on_generic: impl FnMut(u64),
    mut on_foreign: impl FnMut(u64),
    mut on_singleton: impl FnMut(u64),
    mut on_prespec: impl FnMut(u32, u64),
    mut on_invertible: impl FnMut(u16),
    mut on_singleton_pointer: impl FnMut(u64),
) {
    let type_flags = flags.type_flags();
    let mut cursor = trailing_start;

    // 1. Generic header
    if flags.is_generic() {
        if let Some((header_va, end)) = decode_generic_header(rt, cursor) {
            on_generic(header_va);
            cursor = end;
        } else {
            return;
        }
    }

    // 2 & 3. Foreign / singleton init
    match type_flags.metadata_initialization() {
        MetadataInitializationKind::Foreign => {
            on_foreign(cursor);
            cursor = match cursor.checked_add(4) {
                Some(c) => c,
                None => return,
            };
        }
        MetadataInitializationKind::Singleton => {
            on_singleton(cursor);
            cursor = match cursor.checked_add(12) {
                Some(c) => c,
                None => return,
            };
        }
        MetadataInitializationKind::None | MetadataInitializationKind::Other => {}
    }

    // 4. Canonical specialised metadatas
    if type_flags.has_canonical_metadata_prespecializations() {
        match decode_prespecializations(rt, cursor) {
            Some((count, base_va, end)) => {
                on_prespec(count, base_va);
                cursor = end;
            }
            None => return,
        }
    }

    // 5. Invertible protocol set
    if flags.has_invertible_protocols() {
        if let Some(bits) = read_u16_at_va(rt, cursor) {
            on_invertible(bits);
            cursor = match cursor.checked_add(4) {
                Some(c) => c,
                None => return,
            };
        } else {
            return;
        }
    }

    // 6. Singleton metadata pointer
    if type_flags.has_singleton_metadata_pointer() {
        on_singleton_pointer(cursor);
    }
}

/// Decode the `TargetTypeGenericContextDescriptorHeader` at virtual
/// address `header_va` and return `(header_va, cursor_after_header)`.
///
/// Header layout (16 bytes):
///
/// | Off | Field                       | Type                |
/// |-----|-----------------------------|---------------------|
/// | 0   | InstantiationCache          | i32 relative        |
/// | 4   | DefaultInstantiationPattern | i32 relative        |
/// | 8   | NumParams                   | `u16`               |
/// | 10  | NumRequirements             | `u16`               |
/// | 12  | NumKeyArguments             | `u16`               |
/// | 14  | NumExtraArguments           | `u16`               |
///
/// Trailing arrays:
///
/// - `GenericParamDescriptor[NumParams]` — 1 byte each, padded to
///   4-byte alignment.
/// - `GenericRequirementDescriptor[NumRequirements]` — 12 bytes
///   each.
///
/// Key-arguments / extra-arguments occupy slots in the trailing
/// `GenericContext` payload that we don't structurally decode.
fn decode_generic_header(rt: &SwiftRuntime<'_>, header_va: u64) -> Option<(u64, u64)> {
    let header = rt.read_bytes(header_va, 16)?;
    let num_params = read_u16_le_at(header, 8)?;
    let num_requirements = read_u16_le_at(header, 10)?;

    let mut cursor = header_va.checked_add(16)?;

    // GenericParamDescriptor[NumParams] — 1 byte each, padded up to
    // a 4-byte boundary.
    let params_size = u64::from(num_params);
    cursor = cursor.checked_add(params_size)?;
    let pad = (4u64.wrapping_sub(params_size & 0x3)) & 0x3;
    cursor = cursor.checked_add(pad)?;

    // GenericRequirementDescriptor[NumRequirements] — 12 bytes
    // each.
    let req_size = u64::from(num_requirements).checked_mul(12)?;
    cursor = cursor.checked_add(req_size)?;

    Some((header_va, cursor))
}

fn decode_vtable_header(rt: &SwiftRuntime<'_>, header_va: u64) -> Option<(VTableHeader, u64)> {
    let bytes = rt.read_bytes(header_va, 8)?;
    let vtable_offset = read_u32_le_at(bytes, 0)?;
    let vtable_size = read_u32_le_at(bytes, 4)?;
    let entries_va = header_va.checked_add(8)?;
    let entries_size = u64::from(vtable_size).checked_mul(8)?;
    let end = entries_va.checked_add(entries_size)?;
    Some((
        VTableHeader {
            vtable_offset,
            vtable_size,
            entries_va,
        },
        end,
    ))
}

fn decode_override_header(
    rt: &SwiftRuntime<'_>,
    header_va: u64,
) -> Option<(OverrideTableHeader, u64)> {
    let bytes = rt.read_bytes(header_va, 4)?;
    let num_entries = read_u32_le_at(bytes, 0)?;
    let entries_va = header_va.checked_add(4)?;
    let entries_size = u64::from(num_entries).checked_mul(12)?;
    let end = entries_va.checked_add(entries_size)?;
    Some((
        OverrideTableHeader {
            num_entries,
            entries_va,
        },
        end,
    ))
}

fn decode_default_override_header(
    rt: &SwiftRuntime<'_>,
    header_va: u64,
) -> Option<(DefaultOverrideTableHeader, u64)> {
    let bytes = rt.read_bytes(header_va, 4)?;
    let num_entries = read_u32_le_at(bytes, 0)?;
    let entries_va = header_va.checked_add(4)?;
    // TargetMethodDefaultOverrideDescriptor is (Method i32-rel, Impl
    // i32-rel) = 8 bytes per entry.
    let entries_size = u64::from(num_entries).checked_mul(8)?;
    let end = entries_va.checked_add(entries_size)?;
    Some((
        DefaultOverrideTableHeader {
            num_entries,
            entries_va,
        },
        end,
    ))
}

fn decode_prespecializations(rt: &SwiftRuntime<'_>, header_va: u64) -> Option<(u32, u64, u64)> {
    // CanonicalSpecializedMetadatasListCount
    let count_bytes = rt.read_bytes(header_va, 4)?;
    let count = read_u32_le_at(count_bytes, 0)?;
    let entries_va = header_va.checked_add(4)?;
    // CanonicalSpecializedMetadatasListEntry[count] — i32 rel each.
    let entries_size = u64::from(count).checked_mul(4)?;
    let after_entries = entries_va.checked_add(entries_size)?;
    // CanonicalSpecializedMetadataAccessorsListEntry[count] — i32
    // rel each (compact function pointer).
    let accessors_size = u64::from(count).checked_mul(4)?;
    let end = after_entries.checked_add(accessors_size)?;
    Some((count, entries_va, end))
}

fn read_u16_at_va(rt: &SwiftRuntime<'_>, va: u64) -> Option<u16> {
    let bytes = rt.read_bytes(va, 2)?;
    read_u16_le_at(bytes, 0)
}
