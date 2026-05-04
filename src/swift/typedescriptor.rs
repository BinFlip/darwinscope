//! `__swift5_types` walker.
//!
//! Decodes [`TypeDescriptor`] entries from the i32-relative pointer
//! array in `__swift5_types`. Each row resolves to a
//! `TargetTypeContextDescriptor` (per
//! `swift/include/swift/ABI/Metadata.h:4025-4138`) carrying the
//! common `(Flags, Parent, Name, AccessFunctionPtr, Fields)` prefix
//! plus a per-kind tail body decoded into [`TypeKindBody`].
//!
//! On-disk layout of the base descriptor (every type kind shares
//! this 20-byte header):
//!
//! | Off | Field             | Type                 |
//! |-----|-------------------|----------------------|
//! | 0   | Flags             | `u32`                |
//! | 4   | Parent            | i32 relative pointer |
//! | 8   | Name              | i32 relative pointer |
//! | 12  | AccessFunctionPtr | i32 relative pointer |
//! | 16  | Fields            | i32 relative pointer |
//!
//! Per-kind tail (extends the base header):
//!
//! - **Class** (`TargetClassDescriptor`, +24 bytes header → 44 total):
//!   `SuperclassType` (i32-rel),
//!   `{MetadataNegativeSizeInWords | ResilientMetadataBounds}` (4),
//!   `{MetadataPositiveSizeInWords | ExtraClassFlags}` (4),
//!   `NumImmediateMembers` (u32), `NumFields` (u32),
//!   `FieldOffsetVectorOffset` (u32). The two 4-byte slots at
//!   offsets +24/+28 carry the resilient-superclass alternates when
//!   [`crate::swift::TypeContextDescriptorFlags::class_has_resilient_superclass`]
//!   is set.
//! - **Struct** (`TargetStructDescriptor`, +8 bytes → 28 total):
//!   `NumFields`, `FieldOffsetVectorOffset` (both u32).
//! - **Enum** (`TargetEnumDescriptor`, +8 bytes → 28 total):
//!   `NumPayloadCasesAndPayloadSizeOffset` (low 24 bits =
//!   payload-case count, high 8 bits = payload size offset),
//!   `NumEmptyCases` (u32).
//!
//! Trailing-objects (vtable, override table, resilient superclass,
//! foreign / singleton metadata init, prespecialisations, invertible
//! protocols, singleton metadata pointer, default override table)
//! are decoded by [`classtrailers::decode_class_trailers`].
//! Fields populated here include kind, flags, mangled name, parent
//! VA, and the basic per-kind counts. The trailing-block `Option<u64>`
//! fields are populated in the same pass to give consumers the
//! complete picture in a single iteration.

use crate::{
    swift::{
        SwiftRuntime, classtrailers,
        context::{ContextDescriptorFlags, ContextDescriptorKind, MetadataInitializationKind},
    },
    util::{read_i32_le_at, read_u32_le_at, relative_pointer},
};

/// Byte offset of the per-kind tail relative to the descriptor base.
const TYPE_DESCRIPTOR_BASE_SIZE: u64 = 20;

/// One Swift type context descriptor — class, struct, or enum.
///
/// Cite: `swift/include/swift/ABI/Metadata.h:4025-4138`
/// (`TargetTypeContextDescriptor` and its three subclasses
/// `TargetClassDescriptor`, `TargetStructDescriptor`,
/// `TargetEnumDescriptor`).
///
/// One descriptor is emitted per nominal type the source module
/// declares; `__swift5_types` is an array of i32-relative pointers
/// to them. The descriptor carries the static metadata Swift's
/// runtime needs to materialise the type at runtime — generic
/// instantiation, vtable layout for classes, payload layout for
/// enums, etc. Mirror reflection (`Mirror(reflecting:)`) walks the
/// same descriptors at runtime that `darwinscope` walks statically.
///
/// The 20-byte common header (flags, parent, name, access function,
/// fields) is always present; the per-kind tail body lives in
/// [`TypeKindBody`]. Trailing-objects (vtable, override table,
/// resilient-superclass alternate, generic context, singleton
/// metadata initializer, …) are decoded eagerly during the same
/// pass and surfaced through the kind body.
#[derive(Debug)]
pub struct TypeDescriptor<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) address: u64,
    pub(crate) flags: ContextDescriptorFlags,
    pub(crate) parent_va: u64,
    pub(crate) name: &'a str,
    pub(crate) body: TypeKindBody<'a>,
}

/// Per-kind tail body of a [`TypeDescriptor`].
///
/// Cite: `swift/include/swift/ABI/Metadata.h:4140-4250`. The
/// per-kind tail extends the 20-byte common header with kind-
/// specific fields:
///
/// - `Class` → 24-byte tail (44 total) carrying superclass mangled
///   name, metadata size words (or resilient-bounds alternate),
///   immediate-member / field counts, and field-offset-vector
///   placement.
/// - `Struct` / `Enum` → 8-byte tail (28 total). Structs carry
///   `(NumFields, FieldOffsetVectorOffset)`; enums carry
///   `(NumPayloadCasesAndPayloadSizeOffset, NumEmptyCases)` where
///   the first field packs a 24-bit payload-case count plus an
///   8-bit payload-size offset.
///
/// `NonType` covers descriptors that *appeared* in `__swift5_types`
/// but whose kind tag isn't one of the three nominal kinds — the
/// emitter is being lenient with the section, so this surface
/// preserves them rather than rejecting the binary.
#[derive(Debug, Clone)]
pub enum TypeKindBody<'a> {
    /// `TargetClassDescriptor` (kind=`Class`) tail body — 44-byte
    /// total descriptor.
    Class(ClassBody<'a>),
    /// `TargetStructDescriptor` (kind=`Struct`) tail body — 28-byte
    /// total descriptor.
    Struct(StructBody),
    /// `TargetEnumDescriptor` (kind=`Enum`) tail body — 28-byte
    /// total descriptor.
    Enum(EnumBody),
    /// Non-type kinds (Module / Extension / Anonymous / Protocol /
    /// OpaqueType / Other). The descriptor was found in
    /// `__swift5_types` but its kind tag is non-type — surfaced as
    /// fail-soft rather than rejecting the row.
    NonType,
}

/// Per-class trailing-objects state.
#[derive(Debug, Clone)]
pub struct ClassBody<'a> {
    /// `SuperclassType` mangled-name pointer. `None` for root
    /// classes (the relative pointer is 0) or when the resilient
    /// superclass path replaces the slot with a relative pointer to
    /// a different reference kind (in which case
    /// [`ClassBody::resilient_superclass_va`] is populated).
    pub superclass_mangled_name: Option<&'a str>,
    /// `MetadataNegativeSizeInWords` (offset +24, default
    /// interpretation).
    pub metadata_negative_size_words: Option<u32>,
    /// VA of the `ResilientMetadataBounds` cache when
    /// [`crate::swift::TypeContextDescriptorFlags::class_has_resilient_superclass`]
    /// is set (the alternate interpretation of the +24 word).
    pub resilient_metadata_bounds_va: Option<u64>,
    /// `MetadataPositiveSizeInWords` (offset +28, default
    /// interpretation).
    pub metadata_positive_size_words: Option<u32>,
    /// `ExtraClassFlags` when the `Class_HasResilientSuperclass`
    /// alternate interpretation applies.
    pub extra_class_flags: Option<u32>,
    /// `NumImmediateMembers`.
    pub num_immediate_members: u32,
    /// `NumFields`.
    pub num_fields: u32,
    /// `FieldOffsetVectorOffset` (in metadata words; `0` ⇒ none).
    pub field_offset_vector_offset: u32,

    /// Resolved VA of `TargetTypeGenericContextDescriptorHeader` if
    /// the `Generic` flag is set.
    pub generic_header_va: Option<u64>,
    /// Resolved VA of the [`classtrailers::ResilientSuperclass`]
    /// trailing block when present.
    pub resilient_superclass_va: Option<u64>,
    /// Resolved VA of the [`classtrailers::ForeignMetadataInit`]
    /// block when [`MetadataInitializationKind::Foreign`].
    pub foreign_metadata_init_va: Option<u64>,
    /// Resolved VA of the [`classtrailers::SingletonMetadataInit`]
    /// block when [`MetadataInitializationKind::Singleton`].
    pub singleton_metadata_init_va: Option<u64>,
    /// Decoded vtable header when `Class_HasVTable` is set.
    pub vtable_header: Option<VTableHeader>,
    /// Decoded override-table header when `Class_HasOverrideTable`.
    pub override_table_header: Option<OverrideTableHeader>,
    /// VA of the `TargetObjCResilientClassStubInfo` trailing block
    /// when present.
    pub objc_resilient_class_stub_va: Option<u64>,
    /// Count of canonical specialised metadatas (prespecialisations).
    pub prespecializations_count: Option<u32>,
    /// VA of the prespecialisations array (immediately after the
    /// count word).
    pub prespecializations_base_va: Option<u64>,
    /// 16-bit `InvertibleProtocolSet` payload when present.
    pub invertible_protocol_set: Option<u16>,
    /// VA of the `TargetSingletonMetadataPointer` block when
    /// present.
    pub singleton_metadata_pointer_va: Option<u64>,
    /// Decoded default-override-table header when
    /// `Class_HasDefaultOverrideTable`.
    pub default_override_table_header: Option<DefaultOverrideTableHeader>,
}

/// Per-struct trailing-objects state.
#[derive(Debug, Clone)]
pub struct StructBody {
    /// `NumFields`.
    pub num_fields: u32,
    /// `FieldOffsetVectorOffset`.
    pub field_offset_vector_offset: u32,

    /// Resolved VA of `TargetTypeGenericContextDescriptorHeader` if
    /// `Generic`.
    pub generic_header_va: Option<u64>,
    /// Resolved VA of `TargetForeignMetadataInitialization` if
    /// `MetadataInitialization == Foreign`.
    pub foreign_metadata_init_va: Option<u64>,
    /// Resolved VA of `TargetSingletonMetadataInitialization` if
    /// `MetadataInitialization == Singleton`.
    pub singleton_metadata_init_va: Option<u64>,
    /// Count of canonical specialised metadatas when present.
    pub prespecializations_count: Option<u32>,
    /// Resolved VA of the prespecializations array.
    pub prespecializations_base_va: Option<u64>,
    /// 16-bit `InvertibleProtocolSet` payload when present.
    pub invertible_protocol_set: Option<u16>,
    /// Resolved VA of `TargetSingletonMetadataPointer` when present.
    pub singleton_metadata_pointer_va: Option<u64>,
}

/// Per-enum trailing-objects state.
#[derive(Debug, Clone)]
pub struct EnumBody {
    /// Low 24 bits of `NumPayloadCasesAndPayloadSizeOffset`.
    pub num_payload_cases: u32,
    /// High 8 bits of `NumPayloadCasesAndPayloadSizeOffset`.
    pub payload_size_offset: u8,
    /// `NumEmptyCases`.
    pub num_empty_cases: u32,

    /// Resolved VA of `TargetTypeGenericContextDescriptorHeader` if
    /// `Generic`.
    pub generic_header_va: Option<u64>,
    /// Resolved VA of `TargetForeignMetadataInitialization` if
    /// `MetadataInitialization == Foreign`.
    pub foreign_metadata_init_va: Option<u64>,
    /// Resolved VA of `TargetSingletonMetadataInitialization` if
    /// `MetadataInitialization == Singleton`.
    pub singleton_metadata_init_va: Option<u64>,
    /// Count of canonical specialised metadatas when present.
    pub prespecializations_count: Option<u32>,
    /// Resolved VA of the prespecializations array.
    pub prespecializations_base_va: Option<u64>,
    /// 16-bit `InvertibleProtocolSet` payload when present.
    pub invertible_protocol_set: Option<u16>,
    /// Resolved VA of `TargetSingletonMetadataPointer` when present.
    pub singleton_metadata_pointer_va: Option<u64>,
}

/// `TargetVTableDescriptorHeader` — class vtable trailing block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VTableHeader {
    /// `VTableOffset` (in metadata words).
    pub vtable_offset: u32,
    /// `VTableSize` (entry count).
    pub vtable_size: u32,
    /// VA of the first `TargetMethodDescriptor` entry.
    pub entries_va: u64,
}

/// `TargetOverrideTableHeader` — class method-override trailing block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverrideTableHeader {
    /// `NumEntries`.
    pub num_entries: u32,
    /// VA of the first `TargetMethodOverrideDescriptor` entry.
    pub entries_va: u64,
}

/// `TargetMethodDefaultOverrideTableHeader` — protocol-default
/// override trailing block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultOverrideTableHeader {
    /// `NumEntries`.
    pub num_entries: u32,
    /// VA of the first default-override descriptor.
    pub entries_va: u64,
}

impl<'a, 'p> TypeDescriptor<'a, 'p> {
    /// Owning [`SwiftRuntime`] borrow — re-exposed so per-kind
    /// accessors that build follow-on iterators (vtable, parent
    /// chain) can plumb it without dragging extra parameters.
    pub fn runtime(&self) -> &'p SwiftRuntime<'a> {
        self.rt
    }

    /// VA of the descriptor base (the `Flags` word).
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Decoded common-header flags.
    pub fn flags(&self) -> ContextDescriptorFlags {
        self.flags
    }

    /// Convenience: descriptor kind (`flags().kind()`).
    pub fn kind(&self) -> ContextDescriptorKind {
        self.flags.kind()
    }

    /// Convenience: kind-specific flag block.
    pub fn type_flags(&self) -> crate::swift::TypeContextDescriptorFlags {
        self.flags.type_flags()
    }

    /// Resolved VA of the `Parent` context (`0` for top-level).
    pub fn parent_address(&self) -> u64 {
        self.parent_va
    }

    /// Mangled name from the descriptor's `Name` relative pointer.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Per-kind tail body.
    pub fn body(&self) -> &TypeKindBody<'a> {
        &self.body
    }

    /// Iterator over the class vtable, if this is a class with
    /// `Class_HasVTable` set. Returns `None` for non-class kinds
    /// and for classes without a vtable.
    pub fn vtable(&self) -> Option<crate::swift::VTableIter<'a, 'p>> {
        let class = match &self.body {
            TypeKindBody::Class(c) => c,
            _ => return None,
        };
        let header = class.vtable_header.as_ref()?;
        Some(crate::swift::VTableIter {
            rt: self.rt,
            base_va: header.entries_va,
            count: header.vtable_size,
            cursor: 0,
        })
    }

    /// Iterator over the class override table, if present.
    pub fn override_table(&self) -> Option<crate::swift::OverrideEntryIter<'a, 'p>> {
        let class = match &self.body {
            TypeKindBody::Class(c) => c,
            _ => return None,
        };
        let header = class.override_table_header.as_ref()?;
        Some(crate::swift::OverrideEntryIter {
            rt: self.rt,
            base_va: header.entries_va,
            count: header.num_entries,
            cursor: 0,
        })
    }

    /// Iterator over the class default-override table, if present.
    pub fn default_override_table(&self) -> Option<crate::swift::DefaultOverrideEntryIter<'a, 'p>> {
        let class = match &self.body {
            TypeKindBody::Class(c) => c,
            _ => return None,
        };
        let header = class.default_override_table_header.as_ref()?;
        Some(crate::swift::DefaultOverrideEntryIter {
            rt: self.rt,
            base_va: header.entries_va,
            count: header.num_entries,
            cursor: 0,
        })
    }

    /// Resolved [`crate::swift::ResilientSuperclass`] block when present.
    pub fn resilient_superclass(&self) -> Option<crate::swift::ResilientSuperclass<'a>> {
        let class = match &self.body {
            TypeKindBody::Class(c) => c,
            _ => return None,
        };
        let address = class.resilient_superclass_va?;
        // Read the i32-relative pointer encoded at `address`.
        let bytes = self.rt.read_bytes(address, 4)?;
        let rel = read_i32_le_at(bytes, 0)?;
        let superclass_va = if rel == 0 {
            0
        } else {
            relative_pointer(address, rel)
        };
        Some(crate::swift::ResilientSuperclass {
            address,
            superclass_va,
            _marker: core::marker::PhantomData,
        })
    }

    /// Decoded `TargetForeignMetadataInitialization` block when
    /// present (any kind).
    pub fn foreign_metadata_init(&self) -> Option<crate::swift::ForeignMetadataInit> {
        let address = match &self.body {
            TypeKindBody::Class(c) => c.foreign_metadata_init_va?,
            TypeKindBody::Struct(s) => s.foreign_metadata_init_va?,
            TypeKindBody::Enum(e) => e.foreign_metadata_init_va?,
            TypeKindBody::NonType => return None,
        };
        let bytes = self.rt.read_bytes(address, 4)?;
        let rel = read_i32_le_at(bytes, 0)?;
        let completion_function_va = if rel == 0 {
            0
        } else {
            relative_pointer(address, rel)
        };
        Some(crate::swift::ForeignMetadataInit {
            address,
            completion_function_va,
        })
    }

    /// Decoded `TargetSingletonMetadataInitialization` block when
    /// present (any kind).
    pub fn singleton_metadata_init(&self) -> Option<crate::swift::SingletonMetadataInit> {
        let address = match &self.body {
            TypeKindBody::Class(c) => c.singleton_metadata_init_va?,
            TypeKindBody::Struct(s) => s.singleton_metadata_init_va?,
            TypeKindBody::Enum(e) => e.singleton_metadata_init_va?,
            TypeKindBody::NonType => return None,
        };
        let bytes = self.rt.read_bytes(address, 12)?;
        let cache_rel = read_i32_le_at(bytes, 0)?;
        let pattern_rel = read_i32_le_at(bytes, 4)?;
        let completion_rel = read_i32_le_at(bytes, 8)?;

        let resolve = |slot_off: u64, rel: i32| -> Option<u64> {
            if rel == 0 {
                return Some(0);
            }
            let slot = address.checked_add(slot_off)?;
            Some(relative_pointer(slot, rel))
        };

        Some(crate::swift::SingletonMetadataInit {
            address,
            initialization_cache_va: resolve(0, cache_rel)?,
            incomplete_metadata_va: resolve(4, pattern_rel)?,
            completion_function_va: resolve(8, completion_rel)?,
        })
    }

    /// Iterator over canonical specialised metadatas
    /// (prespecialisations) when present.
    pub fn prespecializations(&self) -> Option<crate::swift::PrespecializationIter<'a, 'p>> {
        let (count, base_va) = match &self.body {
            TypeKindBody::Class(c) => (c.prespecializations_count?, c.prespecializations_base_va?),
            TypeKindBody::Struct(s) => (s.prespecializations_count?, s.prespecializations_base_va?),
            TypeKindBody::Enum(e) => (e.prespecializations_count?, e.prespecializations_base_va?),
            TypeKindBody::NonType => return None,
        };
        Some(crate::swift::PrespecializationIter {
            rt: self.rt,
            base_va,
            count,
            cursor: 0,
        })
    }

    /// Decoded `InvertibleProtocolSet` payload when present.
    pub fn invertible_protocol_set(&self) -> Option<crate::swift::InvertibleProtocolSet> {
        let (address, bits) = match &self.body {
            TypeKindBody::Class(c) => (None, c.invertible_protocol_set?),
            TypeKindBody::Struct(s) => (None, s.invertible_protocol_set?),
            TypeKindBody::Enum(e) => (None, e.invertible_protocol_set?),
            TypeKindBody::NonType => return None,
        };
        Some(crate::swift::InvertibleProtocolSet {
            address: address.unwrap_or(0),
            bits,
        })
    }

    /// Decoded `TargetSingletonMetadataPointer` block when present.
    pub fn singleton_metadata_pointer(&self) -> Option<crate::swift::SingletonMetadataPointer> {
        let address = match &self.body {
            TypeKindBody::Class(c) => c.singleton_metadata_pointer_va?,
            TypeKindBody::Struct(s) => s.singleton_metadata_pointer_va?,
            TypeKindBody::Enum(e) => e.singleton_metadata_pointer_va?,
            TypeKindBody::NonType => return None,
        };
        let bytes = self.rt.read_bytes(address, 4)?;
        let rel = read_i32_le_at(bytes, 0)?;
        let metadata_va = if rel == 0 {
            0
        } else {
            relative_pointer(address, rel)
        };
        Some(crate::swift::SingletonMetadataPointer {
            address,
            metadata_va,
        })
    }

    /// Decoded `TargetObjCResilientClassStubInfo` block when
    /// present (class only).
    pub fn objc_resilient_class_stub_info(
        &self,
    ) -> Option<crate::swift::ObjcResilientClassStubInfo> {
        let address = match &self.body {
            TypeKindBody::Class(c) => c.objc_resilient_class_stub_va?,
            _ => return None,
        };
        let bytes = self.rt.read_bytes(address, 4)?;
        let rel = read_i32_le_at(bytes, 0)?;
        let stub_va = if rel == 0 {
            0
        } else {
            relative_pointer(address, rel)
        };
        Some(crate::swift::ObjcResilientClassStubInfo { address, stub_va })
    }

    /// VA of the `TargetTypeGenericContextDescriptorHeader` when
    /// the descriptor is generic.
    pub fn generic_context_header_address(&self) -> Option<u64> {
        match &self.body {
            TypeKindBody::Class(c) => c.generic_header_va,
            TypeKindBody::Struct(s) => s.generic_header_va,
            TypeKindBody::Enum(e) => e.generic_header_va,
            TypeKindBody::NonType => None,
        }
    }
}

/// Iterator over `__swift5_types`.
pub struct TypeIter<'a, 'p> {
    rt: &'p SwiftRuntime<'a>,
    /// Byte offset into the section body. Each entry is exactly 4
    /// bytes (i32 relative pointer).
    cursor: usize,
}

impl<'a, 'p> TypeIter<'a, 'p> {
    pub(crate) fn new(rt: &'p SwiftRuntime<'a>) -> Self {
        Self { rt, cursor: 0 }
    }
}

impl<'a, 'p> Iterator for TypeIter<'a, 'p> {
    type Item = TypeDescriptor<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let section = self.rt.types.as_ref()?;
        loop {
            // Each slot is 4 bytes (i32 relative pointer).
            let slot_off = self.cursor;
            let slot_end = slot_off.checked_add(4)?;
            if slot_end > section.body.len() {
                return None;
            }
            self.cursor = slot_end;

            let Some(rel) = read_i32_le_at(section.body, slot_off) else {
                continue;
            };
            // Skip null relative pointers (rare but legal in
            // synthesised images).
            if rel == 0 {
                continue;
            }
            let slot_va = section.vmaddr.wrapping_add(slot_off as u64);
            let descriptor_va = relative_pointer(slot_va, rel);

            if let Some(descriptor) = decode_type_descriptor(self.rt, descriptor_va) {
                return Some(descriptor);
            }
            // Fail-soft: skip rows that fail to resolve.
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::swift: type descriptor at 0x{:x} (slot 0x{:x}) skipped — decode failed",
                descriptor_va,
                slot_va,
            );
        }
    }
}

/// Decode one `TargetTypeContextDescriptor` at virtual address
/// `descriptor_va`.
///
/// Returns `None` when the base header can't be read or when a
/// load-bearing relative pointer (the mangled `Name`) fails to
/// resolve. Per-kind tail decode failures fall back to
/// [`TypeKindBody::NonType`].
pub(crate) fn decode_type_descriptor<'a, 'p>(
    rt: &'p SwiftRuntime<'a>,
    descriptor_va: u64,
) -> Option<TypeDescriptor<'a, 'p>> {
    let header = rt.read_bytes(descriptor_va, 20)?;
    let flags_raw = read_u32_le_at(header, 0)?;
    let parent_rel = read_i32_le_at(header, 4)?;
    let name_rel = read_i32_le_at(header, 8)?;

    let flags = ContextDescriptorFlags(flags_raw);

    // Parent slot VA = descriptor_va + 4. A null parent (top-level)
    // is encoded as offset 0; we surface it as parent_va == 0.
    let parent_slot_va = descriptor_va.checked_add(4)?;
    let parent_va = if parent_rel == 0 {
        0
    } else {
        relative_pointer(parent_slot_va, parent_rel)
    };

    let name_slot_va = descriptor_va.checked_add(8)?;
    let name_va = relative_pointer(name_slot_va, name_rel);
    let name = rt.read_cstr(name_va)?;

    let body = match flags.kind() {
        ContextDescriptorKind::Class => decode_class_body(rt, descriptor_va, flags)
            .map(TypeKindBody::Class)
            .unwrap_or(TypeKindBody::NonType),
        ContextDescriptorKind::Struct => decode_struct_body(rt, descriptor_va, flags)
            .map(TypeKindBody::Struct)
            .unwrap_or(TypeKindBody::NonType),
        ContextDescriptorKind::Enum => decode_enum_body(rt, descriptor_va, flags)
            .map(TypeKindBody::Enum)
            .unwrap_or(TypeKindBody::NonType),
        _ => TypeKindBody::NonType,
    };

    Some(TypeDescriptor {
        rt,
        address: descriptor_va,
        flags,
        parent_va,
        name,
        body,
    })
}

fn decode_class_body<'a>(
    rt: &SwiftRuntime<'a>,
    descriptor_va: u64,
    flags: ContextDescriptorFlags,
) -> Option<ClassBody<'a>> {
    // Class-specific header is 24 bytes following the 20-byte base.
    let class_off = descriptor_va.checked_add(TYPE_DESCRIPTOR_BASE_SIZE)?;
    let header = rt.read_bytes(class_off, 24)?;

    let superclass_rel = read_i32_le_at(header, 0)?;
    let union_24 = read_u32_le_at(header, 4)?;
    let union_28 = read_u32_le_at(header, 8)?;
    let num_immediate_members = read_u32_le_at(header, 12)?;
    let num_fields = read_u32_le_at(header, 16)?;
    let field_offset_vector_offset = read_u32_le_at(header, 20)?;

    let type_flags = flags.type_flags();
    let resilient = type_flags.class_has_resilient_superclass();

    let superclass_slot_va = class_off;
    let superclass_mangled_name = if superclass_rel == 0 {
        None
    } else {
        let target = relative_pointer(superclass_slot_va, superclass_rel);
        rt.read_cstr(target)
    };

    // The +24 union: when resilient-superclass is set, the slot is a
    // relative pointer to a `ResilientMetadataBounds` cache; the raw
    // `union_24` is therefore the relative-pointer offset (signed).
    let (metadata_negative_size_words, resilient_metadata_bounds_va) = if resilient {
        let off = i32::from_le_bytes(union_24.to_le_bytes());
        let slot = class_off.checked_add(4)?;
        let target = if off == 0 {
            0
        } else {
            relative_pointer(slot, off)
        };
        (None, Some(target))
    } else {
        (Some(union_24), None)
    };

    // The +28 union: when resilient-superclass is set, the slot is
    // `ExtraClassFlags`; otherwise `MetadataPositiveSizeInWords`.
    let (metadata_positive_size_words, extra_class_flags) = if resilient {
        (None, Some(union_28))
    } else {
        (Some(union_28), None)
    };

    let mut body = ClassBody {
        superclass_mangled_name,
        metadata_negative_size_words,
        resilient_metadata_bounds_va,
        metadata_positive_size_words,
        extra_class_flags,
        num_immediate_members,
        num_fields,
        field_offset_vector_offset,
        generic_header_va: None,
        resilient_superclass_va: None,
        foreign_metadata_init_va: None,
        singleton_metadata_init_va: None,
        vtable_header: None,
        override_table_header: None,
        objc_resilient_class_stub_va: None,
        prespecializations_count: None,
        prespecializations_base_va: None,
        invertible_protocol_set: None,
        singleton_metadata_pointer_va: None,
        default_override_table_header: None,
    };

    // Resolve trailing-objects in declared order. Each block returns
    // `(decoded, new_cursor)`; failures fail-soft and short-circuit
    // the rest of the trailing chain.
    let trailing_start = class_off.checked_add(24)?;
    classtrailers::decode_class_trailers(rt, &flags, trailing_start, &mut body);

    Some(body)
}

fn decode_struct_body(
    rt: &SwiftRuntime<'_>,
    descriptor_va: u64,
    flags: ContextDescriptorFlags,
) -> Option<StructBody> {
    // Struct-specific header is 8 bytes following the 20-byte base.
    let struct_off = descriptor_va.checked_add(TYPE_DESCRIPTOR_BASE_SIZE)?;
    let header = rt.read_bytes(struct_off, 8)?;

    let num_fields = read_u32_le_at(header, 0)?;
    let field_offset_vector_offset = read_u32_le_at(header, 4)?;

    let mut body = StructBody {
        num_fields,
        field_offset_vector_offset,
        generic_header_va: None,
        foreign_metadata_init_va: None,
        singleton_metadata_init_va: None,
        prespecializations_count: None,
        prespecializations_base_va: None,
        invertible_protocol_set: None,
        singleton_metadata_pointer_va: None,
    };

    let trailing_start = struct_off.checked_add(8)?;
    classtrailers::decode_value_type_trailers(
        rt,
        &flags,
        trailing_start,
        |va| body.generic_header_va = Some(va),
        |va| body.foreign_metadata_init_va = Some(va),
        |va| body.singleton_metadata_init_va = Some(va),
        |count, base| {
            body.prespecializations_count = Some(count);
            body.prespecializations_base_va = Some(base);
        },
        |bits| body.invertible_protocol_set = Some(bits),
        |va| body.singleton_metadata_pointer_va = Some(va),
    );

    Some(body)
}

fn decode_enum_body(
    rt: &SwiftRuntime<'_>,
    descriptor_va: u64,
    flags: ContextDescriptorFlags,
) -> Option<EnumBody> {
    // Enum-specific header is 8 bytes following the 20-byte base.
    let enum_off = descriptor_va.checked_add(TYPE_DESCRIPTOR_BASE_SIZE)?;
    let header = rt.read_bytes(enum_off, 8)?;

    let packed = read_u32_le_at(header, 0)?;
    let num_empty_cases = read_u32_le_at(header, 4)?;

    let num_payload_cases = packed & 0x00FF_FFFF;
    let payload_size_offset = ((packed >> 24) & 0xFF) as u8;

    let mut body = EnumBody {
        num_payload_cases,
        payload_size_offset,
        num_empty_cases,
        generic_header_va: None,
        foreign_metadata_init_va: None,
        singleton_metadata_init_va: None,
        prespecializations_count: None,
        prespecializations_base_va: None,
        invertible_protocol_set: None,
        singleton_metadata_pointer_va: None,
    };

    let trailing_start = enum_off.checked_add(8)?;
    classtrailers::decode_value_type_trailers(
        rt,
        &flags,
        trailing_start,
        |va| body.generic_header_va = Some(va),
        |va| body.foreign_metadata_init_va = Some(va),
        |va| body.singleton_metadata_init_va = Some(va),
        |count, base| {
            body.prespecializations_count = Some(count);
            body.prespecializations_base_va = Some(base);
        },
        |bits| body.invertible_protocol_set = Some(bits),
        |va| body.singleton_metadata_pointer_va = Some(va),
    );

    Some(body)
}

/// Decoded `MetadataInitializationKind` for the trailing-objects
/// walker.
#[allow(dead_code)]
pub(crate) fn metadata_init_kind(flags: ContextDescriptorFlags) -> MetadataInitializationKind {
    flags.type_flags().metadata_initialization()
}
