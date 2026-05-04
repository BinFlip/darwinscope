//! Swift context-descriptor flag and enum decoders.
//!
//! Decodes the bitfield layouts that govern every `__swift5_*`
//! descriptor: kind enum + per-kind flag words for type contexts,
//! protocol descriptors, conformances, fields, and method
//! descriptors. Pure value types — no allocation, no I/O — so the
//! descriptor walkers can build them on demand from the raw `u32`
//! payload they read off disk.
//!
//! References used throughout:
//!
//! - `swift/include/swift/ABI/MetadataValues.h:1815-1846`
//!   — `ContextDescriptorKind` (5-bit enum).
//! - `swift/include/swift/ABI/MetadataValues.h:1848-1929`
//!   — `ContextDescriptorFlags` (32-bit common header).
//! - `swift/include/swift/ABI/MetadataValues.h:1933-2008`
//!   — `TypeContextDescriptorFlags` (16-bit kind-specific block).
//! - `swift/include/swift/ABI/MetadataValues.h:749-882`
//!   — `ConformanceFlags`.
//! - `swift/include/swift/RemoteInspection/Records.h:32-83`
//!   — `FieldRecordFlags`.
//! - `swift/include/swift/RemoteInspection/Records.h:146-174`
//!   — `FieldDescriptorKind`.
//! - `swift/include/swift/ABI/MetadataValues.h` `TypeReferenceKind`.
//! - `swift/include/swift/ABI/MetadataValues.h:381-…`
//!   — `MethodDescriptorFlags`.
//!
//! All citations also surface in `RESEARCH.md` §"Swift type
//! metadata" (lines 1725-2085).

/// `ContextDescriptorKind` — the 5-bit kind enum stored in the low
/// bits of every [`ContextDescriptorFlags`] payload.
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h:1815-1846` and
/// `RESEARCH.md:1725-1742`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextDescriptorKind {
    /// Top-level Swift module (`SwiftModule.Foo`).
    Module,
    /// `extension` block applied to a foreign type.
    Extension,
    /// Anonymous lexical scope (file-private extensions, closures).
    Anonymous,
    /// Swift `protocol` declaration.
    Protocol,
    /// Opaque-result type witness (`some Foo` returns).
    OpaqueType,
    /// Swift `class`. Kind value `0x10`; tagged as `Type_First` in
    /// the upstream header.
    Class,
    /// Swift `struct`. Kind value `0x11`.
    Struct,
    /// Swift `enum`. Kind value `0x12`.
    Enum,
    /// Kind values outside the documented set (5..15, 19..31). Held
    /// verbatim — newer Swift releases occasionally add experimental
    /// kinds and the walker fail-soft surfaces them rather than
    /// rejecting the descriptor.
    Other(u8),
}

impl ContextDescriptorKind {
    /// Decode a raw 5-bit kind value (the low bits of
    /// `ContextDescriptorFlags`).
    pub(crate) fn from_bits(raw: u8) -> Self {
        match raw & 0x1F {
            0 => Self::Module,
            1 => Self::Extension,
            2 => Self::Anonymous,
            3 => Self::Protocol,
            4 => Self::OpaqueType,
            16 => Self::Class,
            17 => Self::Struct,
            18 => Self::Enum,
            other => Self::Other(other),
        }
    }

    /// `true` for kinds that carry a `TargetTypeContextDescriptor`
    /// payload — i.e. `Class`, `Struct`, or `Enum`. Walkers use
    /// this to gate the per-kind tail-decoders.
    pub fn is_type(self) -> bool {
        matches!(self, Self::Class | Self::Struct | Self::Enum)
    }
}

/// Common 32-bit header word every Swift context descriptor opens
/// with.
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h:1848-1929` and
/// `RESEARCH.md:1744-1756`.
///
/// | Bits     | Field                       |
/// |----------|-----------------------------|
/// | `0..4`   | [`ContextDescriptorKind`]   |
/// | `5`      | `HasInvertibleProtocols`    |
/// | `6`      | `Unique`                    |
/// | `7`      | `Generic`                   |
/// | `8..15`  | reserved (must be zero)     |
/// | `16..31` | `KindSpecificFlags`         |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextDescriptorFlags(pub u32);

impl ContextDescriptorFlags {
    /// Decode the low-5-bit kind enum.
    pub fn kind(self) -> ContextDescriptorKind {
        ContextDescriptorKind::from_bits((self.0 & 0x1F) as u8)
    }

    /// `HasInvertibleProtocols` (bit `5`). Indicates a trailing
    /// `InvertibleProtocolSet` payload.
    pub fn has_invertible_protocols(self) -> bool {
        (self.0 & (1 << 5)) != 0
    }

    /// `Unique` (bit `6`). The descriptor is module-unique rather
    /// than duplicated for incremental compilation.
    pub fn is_unique(self) -> bool {
        (self.0 & (1 << 6)) != 0
    }

    /// `Generic` (bit `7`). Descriptor has trailing generic-context
    /// metadata (`TargetTypeGenericContextDescriptorHeader` for type
    /// kinds; `TargetGenericContextDescriptorHeader` otherwise).
    pub fn is_generic(self) -> bool {
        (self.0 & (1 << 7)) != 0
    }

    /// High 16 bits — the kind-specific flag block. For type kinds
    /// (`Class`, `Struct`, `Enum`) decode through
    /// [`TypeContextDescriptorFlags`].
    pub fn kind_specific(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// Decode the kind-specific flags as a [`TypeContextDescriptorFlags`].
    /// Meaningful when [`Self::kind`] returns a type kind.
    pub fn type_flags(self) -> TypeContextDescriptorFlags {
        TypeContextDescriptorFlags(self.kind_specific())
    }
}

/// Type-kind metadata-initialisation strategy stored in
/// [`TypeContextDescriptorFlags`] bits `0..1`.
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h:1933-1960`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataInitializationKind {
    /// No runtime metadata initialisation needed.
    None,
    /// Trailing `TargetSingletonMetadataInitialization` payload.
    Singleton,
    /// Trailing `TargetForeignMetadataInitialization` payload.
    Foreign,
    /// Reserved value `3` — surfaced verbatim.
    Other,
}

impl MetadataInitializationKind {
    pub(crate) fn from_bits(raw: u8) -> Self {
        match raw & 0x3 {
            0 => Self::None,
            1 => Self::Singleton,
            2 => Self::Foreign,
            _ => Self::Other,
        }
    }
}

/// High 16 bits of [`ContextDescriptorFlags`] for type-kind
/// descriptors (`Class`, `Struct`, `Enum`).
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h:1933-2008` and
/// `RESEARCH.md:1758-1777`.
///
/// | Bit      | Constant                                                             | Kinds   |
/// |----------|----------------------------------------------------------------------|---------|
/// | `0..1`   | [`MetadataInitializationKind`]                                       | all     |
/// | `2`      | `HasImportInfo`                                                      | all     |
/// | `3`      | `HasCanonicalMetadataPrespecializationsOrSingletonMetadataPointer`   | all     |
/// | `4`      | `HasLayoutString`                                                    | all     |
/// | `6`      | `Class_HasDefaultOverrideTable`                                      | class   |
/// | `7`      | `Class_IsActor`                                                      | class   |
/// | `8`      | `Class_IsDefaultActor`                                               | class   |
/// | `9..11`  | `Class_ResilientSuperclassReferenceKind` (3 bits, `TypeReferenceKind`) | class |
/// | `12`     | `Class_AreImmediateMembersNegative`                                  | class   |
/// | `13`     | `Class_HasResilientSuperclass`                                       | class   |
/// | `14`     | `Class_HasOverrideTable`                                             | class   |
/// | `15`     | `Class_HasVTable`                                                    | class   |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeContextDescriptorFlags(pub u16);

impl TypeContextDescriptorFlags {
    /// Bits `0..1` — metadata initialisation strategy.
    pub fn metadata_initialization(self) -> MetadataInitializationKind {
        MetadataInitializationKind::from_bits((self.0 & 0x3) as u8)
    }

    /// Bit `2` — `HasImportInfo`. Trailing module-import info present.
    pub fn has_import_info(self) -> bool {
        (self.0 & (1 << 2)) != 0
    }

    /// Bit `3` — `HasCanonicalMetadataPrespecializations`
    /// **or** `HasSingletonMetadataPointer` depending on context.
    /// Walkers use [`Self::has_singleton_metadata_pointer`] /
    /// [`Self::has_canonical_metadata_prespecializations`] to gate
    /// the trailing-objects walk.
    pub fn has_canonical_metadata_prespecializations_or_singleton(self) -> bool {
        (self.0 & (1 << 3)) != 0
    }

    /// Bit `3` interpreted as `HasCanonicalMetadataPrespecializations`
    /// (the meaning when [`MetadataInitializationKind::Singleton`] is
    /// not in effect).
    pub fn has_canonical_metadata_prespecializations(self) -> bool {
        self.has_canonical_metadata_prespecializations_or_singleton()
            && !matches!(
                self.metadata_initialization(),
                MetadataInitializationKind::Singleton
            )
    }

    /// Bit `3` interpreted as `HasSingletonMetadataPointer` (the
    /// meaning when [`MetadataInitializationKind::Singleton`] is in
    /// effect).
    pub fn has_singleton_metadata_pointer(self) -> bool {
        self.has_canonical_metadata_prespecializations_or_singleton()
            && matches!(
                self.metadata_initialization(),
                MetadataInitializationKind::Singleton
            )
    }

    /// Bit `4` — `HasLayoutString`.
    pub fn has_layout_string(self) -> bool {
        (self.0 & (1 << 4)) != 0
    }

    /// Bit `6` — `Class_HasDefaultOverrideTable`.
    pub fn class_has_default_override_table(self) -> bool {
        (self.0 & (1 << 6)) != 0
    }

    /// Bit `7` — `Class_IsActor`.
    pub fn class_is_actor(self) -> bool {
        (self.0 & (1 << 7)) != 0
    }

    /// Bit `8` — `Class_IsDefaultActor`.
    pub fn class_is_default_actor(self) -> bool {
        (self.0 & (1 << 8)) != 0
    }

    /// Bits `9..11` — `Class_ResilientSuperclassReferenceKind`.
    pub fn class_resilient_superclass_reference_kind(self) -> TypeReferenceKind {
        TypeReferenceKind::from_bits(((self.0 >> 9) & 0x7) as u8)
    }

    /// Bit `12` — `Class_AreImmediateMembersNegative`.
    pub fn class_immediate_members_negative(self) -> bool {
        (self.0 & (1 << 12)) != 0
    }

    /// Bit `13` — `Class_HasResilientSuperclass`.
    pub fn class_has_resilient_superclass(self) -> bool {
        (self.0 & (1 << 13)) != 0
    }

    /// Bit `14` — `Class_HasOverrideTable`.
    pub fn class_has_override_table(self) -> bool {
        (self.0 & (1 << 14)) != 0
    }

    /// Bit `15` — `Class_HasVTable`.
    pub fn class_has_vtable(self) -> bool {
        (self.0 & (1 << 15)) != 0
    }
}

/// `TypeReferenceKind` — the 3-bit tag stored in
/// [`ConformanceFlags`] bits `3..5` and in the class-resilient-
/// superclass reference field.
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h` (search
/// `enum class TypeReferenceKind : unsigned`). 4 documented values
/// + reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeReferenceKind {
    /// Direct relative pointer to a `TargetTypeContextDescriptor`.
    DirectTypeDescriptor,
    /// Indirect: relative pointer to a slot containing the
    /// `TargetTypeContextDescriptor` pointer.
    IndirectTypeDescriptor,
    /// Direct relative pointer to a NUL-terminated Obj-C class name
    /// C-string.
    DirectObjCClassName,
    /// Indirect: relative pointer to a slot containing the Obj-C
    /// class object pointer.
    IndirectObjCClass,
    /// Reserved value (4..7) — surfaced verbatim.
    Other(u8),
}

impl TypeReferenceKind {
    pub(crate) fn from_bits(raw: u8) -> Self {
        match raw & 0x7 {
            0 => Self::DirectTypeDescriptor,
            1 => Self::IndirectTypeDescriptor,
            2 => Self::DirectObjCClassName,
            3 => Self::IndirectObjCClass,
            other => Self::Other(other),
        }
    }
}

/// Flag word stored in
/// `TargetProtocolConformanceDescriptor.Flags`.
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h:749-882` and
/// `RESEARCH.md:1976-1991`.
///
/// | Bits     | Field                                  |
/// |----------|----------------------------------------|
/// | `0..2`   | `UnusedLowBits` (historical)           |
/// | `3..5`   | [`TypeReferenceKind`] for `TypeRef`    |
/// | `6`      | `IsRetroactive`                        |
/// | `7`      | `IsSynthesizedNonUnique`               |
/// | `8..15`  | `NumConditionalRequirements`           |
/// | `16`     | `HasResilientWitnesses`                |
/// | `17`     | `HasGenericWitnessTable`               |
/// | `18`     | `IsConformanceOfProtocol`              |
/// | `19`     | `HasGlobalActorIsolation`              |
/// | `24..31` | `NumConditionalPackDescriptors`        |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformanceFlags(pub u32);

impl ConformanceFlags {
    /// Bits `3..5` — interpretation tag for `TypeRef`.
    pub fn type_reference_kind(self) -> TypeReferenceKind {
        TypeReferenceKind::from_bits(((self.0 >> 3) & 0x7) as u8)
    }

    /// Bit `6` — `IsRetroactive` (conformance defined in a third
    /// module, neither type nor protocol owner).
    pub fn is_retroactive(self) -> bool {
        (self.0 & (1 << 6)) != 0
    }

    /// Bit `7` — `IsSynthesizedNonUnique` (compiler-emitted for an
    /// imported entity).
    pub fn is_synthesized_non_unique(self) -> bool {
        (self.0 & (1 << 7)) != 0
    }

    /// Bits `8..15` — number of trailing
    /// `TargetGenericRequirementDescriptor` entries when the
    /// conformance is conditional.
    pub fn num_conditional_requirements(self) -> u8 {
        ((self.0 >> 8) & 0xff) as u8
    }

    /// Bit `16` — `HasResilientWitnesses`.
    pub fn has_resilient_witnesses(self) -> bool {
        (self.0 & (1 << 16)) != 0
    }

    /// Bit `17` — `HasGenericWitnessTable`.
    pub fn has_generic_witness_table(self) -> bool {
        (self.0 & (1 << 17)) != 0
    }

    /// Bit `18` — `IsConformanceOfProtocol` (protocol-to-protocol
    /// conformance synthesised for inheritance).
    pub fn is_conformance_of_protocol(self) -> bool {
        (self.0 & (1 << 18)) != 0
    }

    /// Bit `19` — `HasGlobalActorIsolation` (trailing
    /// `TargetGlobalActorReference` payload present).
    pub fn has_global_actor_isolation(self) -> bool {
        (self.0 & (1 << 19)) != 0
    }

    /// Bits `24..31` — number of trailing
    /// `GenericPackShapeDescriptor` entries when conditional pack
    /// requirements are present.
    pub fn num_conditional_pack_descriptors(self) -> u8 {
        ((self.0 >> 24) & 0xff) as u8
    }
}

/// `FieldDescriptorKind` (`uint16_t`) — disambiguates the role of a
/// `TargetFieldDescriptor` entry in `__swift5_fieldmd`.
///
/// Cite: `swift/include/swift/RemoteInspection/Records.h:146-174`
/// and `RESEARCH.md:2051-2064`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldDescriptorKind {
    /// Stored properties of a Swift `struct`.
    Struct,
    /// Stored properties of a Swift `class`.
    Class,
    /// Cases of a Swift `enum` (single-payload + no-payload).
    Enum,
    /// Multi-payload enum (paired with `__swift5_mpenum`).
    MultiPayloadEnum,
    /// Opaque Swift protocol.
    Protocol,
    /// Class-bound Swift protocol.
    ClassProtocol,
    /// Imported Obj-C protocol.
    ObjCProtocol,
    /// Imported Obj-C class.
    ObjCClass,
    /// Reserved value (>= 8).
    Other(u16),
}

impl FieldDescriptorKind {
    pub(crate) fn from_bits(raw: u16) -> Self {
        match raw {
            0 => Self::Struct,
            1 => Self::Class,
            2 => Self::Enum,
            3 => Self::MultiPayloadEnum,
            4 => Self::Protocol,
            5 => Self::ClassProtocol,
            6 => Self::ObjCProtocol,
            7 => Self::ObjCClass,
            other => Self::Other(other),
        }
    }
}

/// `FieldRecordFlags` (32-bit) — per-record flag word in a
/// [`crate::swift::FieldRecord`].
///
/// Cite: `swift/include/swift/RemoteInspection/Records.h:32-83` and
/// `RESEARCH.md:2077-2085`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRecordFlags(pub u32);

impl FieldRecordFlags {
    /// Bit `0` — `IsIndirectCase`. The enum case is `indirect`
    /// (heap-boxed).
    pub fn is_indirect_case(self) -> bool {
        (self.0 & (1 << 0)) != 0
    }

    /// Bit `1` — `IsVar`. Mutable `var` property (vs `let`).
    pub fn is_var(self) -> bool {
        (self.0 & (1 << 1)) != 0
    }

    /// Bit `2` — `IsArtificial`. Compiler-generated field (e.g.
    /// `_storage` for resilient classes).
    pub fn is_artificial(self) -> bool {
        (self.0 & (1 << 2)) != 0
    }
}

/// `MethodKind` — enum stored in the low 4 bits of
/// [`MethodDescriptorFlags`]. Disambiguates the dispatch role of a
/// vtable entry.
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h` (search
/// `class MethodDescriptorFlags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwiftMethodKind {
    /// Ordinary instance / class method.
    Method,
    /// Initialiser (`init`).
    Init,
    /// Property getter.
    Getter,
    /// Property setter.
    Setter,
    /// `_modify` coroutine.
    ModifyCoroutine,
    /// `_read` coroutine.
    ReadCoroutine,
    /// Reserved value (>= 6).
    Other(u8),
}

impl SwiftMethodKind {
    pub(crate) fn from_bits(raw: u8) -> Self {
        match raw & 0xF {
            0 => Self::Method,
            1 => Self::Init,
            2 => Self::Getter,
            3 => Self::Setter,
            4 => Self::ModifyCoroutine,
            5 => Self::ReadCoroutine,
            other => Self::Other(other),
        }
    }
}

/// 32-bit `MethodDescriptorFlags` — flag word on each
/// `TargetMethodDescriptor` and `TargetMethodOverrideDescriptor`.
///
/// Cite: `swift/include/swift/ABI/MetadataValues.h` (search
/// `class MethodDescriptorFlags`).
///
/// | Bits     | Field                                      |
/// |----------|--------------------------------------------|
/// | `0..3`   | [`SwiftMethodKind`]                        |
/// | `4`      | `IsInstance`                               |
/// | `5`      | `IsDynamic`                                |
/// | `6`      | `IsAsync`                                  |
/// | `7`      | `HasExtendedContext`                       |
/// | `16..31` | `ExtraDiscriminator` (PAC discriminator)   |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodDescriptorFlags(pub u32);

impl MethodDescriptorFlags {
    /// Low 4 bits — dispatch kind.
    pub fn kind(self) -> SwiftMethodKind {
        SwiftMethodKind::from_bits((self.0 & 0xF) as u8)
    }

    /// Bit `4` — `IsInstance`.
    pub fn is_instance(self) -> bool {
        (self.0 & (1 << 4)) != 0
    }

    /// Bit `5` — `IsDynamic` (eligible for dynamic replacement).
    pub fn is_dynamic(self) -> bool {
        (self.0 & (1 << 5)) != 0
    }

    /// Bit `6` — `IsAsync`.
    pub fn is_async(self) -> bool {
        (self.0 & (1 << 6)) != 0
    }

    /// Bit `7` — `HasExtendedContext` (additional method-context
    /// payload follows).
    pub fn has_extended_context(self) -> bool {
        (self.0 & (1 << 7)) != 0
    }

    /// Bits `16..31` — PAC discriminator used to sign the Impl
    /// pointer at runtime.
    pub fn extra_discriminator(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_descriptor_kind_round_trips() {
        for (raw, expected) in [
            (0u8, ContextDescriptorKind::Module),
            (1, ContextDescriptorKind::Extension),
            (2, ContextDescriptorKind::Anonymous),
            (3, ContextDescriptorKind::Protocol),
            (4, ContextDescriptorKind::OpaqueType),
            (16, ContextDescriptorKind::Class),
            (17, ContextDescriptorKind::Struct),
            (18, ContextDescriptorKind::Enum),
        ] {
            assert_eq!(ContextDescriptorKind::from_bits(raw), expected);
        }
        assert_eq!(
            ContextDescriptorKind::from_bits(19),
            ContextDescriptorKind::Other(19)
        );
        // High bits beyond 5 are masked off.
        assert_eq!(
            ContextDescriptorKind::from_bits(0xFF),
            ContextDescriptorKind::Other(31)
        );
    }

    #[test]
    fn context_descriptor_flags_decode() {
        // kind=Class (bits 0..4 = 0x10), Generic (bit 7),
        // KindSpecificFlags=0x0080.
        let f = ContextDescriptorFlags(0x0080_0090);
        assert_eq!(f.kind(), ContextDescriptorKind::Class);
        assert!(f.is_generic());
        assert!(!f.is_unique());
        assert_eq!(f.kind_specific(), 0x0080);
    }

    #[test]
    fn type_context_flags_class_bits() {
        let t = TypeContextDescriptorFlags(0x8000); // Class_HasVTable
        assert!(t.class_has_vtable());
        assert!(!t.class_has_override_table());
        assert!(!t.class_has_resilient_superclass());
    }

    #[test]
    fn type_context_metadata_init() {
        assert_eq!(
            TypeContextDescriptorFlags(0).metadata_initialization(),
            MetadataInitializationKind::None
        );
        assert_eq!(
            TypeContextDescriptorFlags(1).metadata_initialization(),
            MetadataInitializationKind::Singleton
        );
        assert_eq!(
            TypeContextDescriptorFlags(2).metadata_initialization(),
            MetadataInitializationKind::Foreign
        );
        assert_eq!(
            TypeContextDescriptorFlags(3).metadata_initialization(),
            MetadataInitializationKind::Other
        );
    }

    #[test]
    fn type_context_singleton_pointer_aliasing_with_bit3() {
        // bit3 set + Singleton → singleton metadata pointer.
        let with_singleton = TypeContextDescriptorFlags(0b0000_1001);
        assert!(with_singleton.has_singleton_metadata_pointer());
        assert!(!with_singleton.has_canonical_metadata_prespecializations());
        // bit3 set + None → canonical prespecializations.
        let with_canonical = TypeContextDescriptorFlags(0b0000_1000);
        assert!(with_canonical.has_canonical_metadata_prespecializations());
        assert!(!with_canonical.has_singleton_metadata_pointer());
    }

    #[test]
    fn conformance_flags_decode() {
        // type_reference_kind = IndirectTypeDescriptor (1 << 3),
        // num_conditional_requirements = 2 (2 << 8),
        // has_resilient_witnesses (1 << 16).
        let cf = ConformanceFlags((1 << 3) | (2 << 8) | (1 << 16));
        assert_eq!(
            cf.type_reference_kind(),
            TypeReferenceKind::IndirectTypeDescriptor
        );
        assert_eq!(cf.num_conditional_requirements(), 2);
        assert!(cf.has_resilient_witnesses());
        assert!(!cf.is_retroactive());
        assert!(!cf.has_generic_witness_table());
    }

    #[test]
    fn type_reference_kind_round_trips() {
        for (raw, expected) in [
            (0u8, TypeReferenceKind::DirectTypeDescriptor),
            (1, TypeReferenceKind::IndirectTypeDescriptor),
            (2, TypeReferenceKind::DirectObjCClassName),
            (3, TypeReferenceKind::IndirectObjCClass),
        ] {
            assert_eq!(TypeReferenceKind::from_bits(raw), expected);
        }
        assert_eq!(
            TypeReferenceKind::from_bits(7),
            TypeReferenceKind::Other(7)
        );
    }

    #[test]
    fn field_descriptor_kind_round_trips() {
        assert_eq!(
            FieldDescriptorKind::from_bits(0),
            FieldDescriptorKind::Struct
        );
        assert_eq!(FieldDescriptorKind::from_bits(7), FieldDescriptorKind::ObjCClass);
        assert_eq!(FieldDescriptorKind::from_bits(99), FieldDescriptorKind::Other(99));
    }

    #[test]
    fn field_record_flags_decode() {
        let f = FieldRecordFlags(0b110);
        assert!(!f.is_indirect_case());
        assert!(f.is_var());
        assert!(f.is_artificial());
    }

    #[test]
    fn method_descriptor_flags_decode() {
        // kind=Getter (2), IsInstance, IsAsync, ExtraDiscriminator=0xBEEF
        let m = MethodDescriptorFlags(0xBEEF_0052);
        assert_eq!(m.kind(), SwiftMethodKind::Getter);
        assert!(m.is_instance());
        assert!(!m.is_dynamic());
        assert!(m.is_async());
        assert!(!m.has_extended_context());
        assert_eq!(m.extra_discriminator(), 0xBEEF);
    }
}
