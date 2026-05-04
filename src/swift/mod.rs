//! Swift 5 type-metadata walker.
//!
//! Walks every reflection section the Swift runtime emits into a
//! Mach-O image:
//!
//! - `__TEXT,__swift5_types` — i32-relative pointer array of
//!   [`TypeDescriptor`]s (`TargetTypeContextDescriptor` per
//!   `swift/include/swift/ABI/Metadata.h:4025-4138`). Class / struct
//!   / enum kinds; per-kind tail decoders surface vtable, override
//!   table, resilient superclass, foreign / singleton metadata
//!   initialisation, prespecialisations, invertible protocols, and
//!   singleton-metadata-pointer trailing objects.
//! - `__TEXT,__swift5_protos` — i32-relative pointer array of
//!   [`SwiftProtocol`]s (`TargetProtocolDescriptor`).
//! - `__TEXT,__swift5_proto` — packed array of [`Conformance`] rows
//!   (`TargetProtocolConformanceDescriptor`). Resolves the
//!   `(type_descriptor, protocol_descriptor, witness_table, flags)`
//!   triple per [`crate::swift::ConformanceFlags`].
//! - `__TEXT,__swift5_fieldmd` — variable-length sequence of
//!   [`FieldDescriptor`]s, each carrying `NumFields` x
//!   [`FieldRecord`] entries (mangled type name + reflstr-hosted
//!   field name).
//! - `__TEXT,__swift5_replac` / `__swift5_replac2` —
//!   dynamic-replacement scope descriptors / chain entries.
//! - `__TEXT,__swift5_capture` — closure-capture descriptors.
//! - `__TEXT,__swift5_reflstr` — pool of NUL-terminated UTF-8 names
//!   referenced by [`FieldRecord::field_name`].
//! - `__TEXT,__swift5_typeref` / `__swift5_builtin` — mangled type
//!   reference pool / builtin-type layout records (presence-only).
//!
//! All names are stored in their **mangled** form. The schema
//! reserves a separate slot for a future demangler.
//!
//! See `RESEARCH.md` §"Swift type metadata" (lines 1696-2480) for
//! layout references. Section name synonyms are catalogued in
//! `RESEARCH.md` §"Section-name catalogue" — the lookup is
//! segment-agnostic on purpose.
//!
//! ## Lifetime convention
//!
//! Every typed view here uses `<'a, 'p>` — `'a` is the data slice
//! lifetime (where mangled names, field strings, and section bodies
//! live) and `'p` is the borrow of the parent [`SwiftRuntime`]. Swift
//! string fields all live in `__TEXT,__swift5_reflstr` /
//! `__swift5_typeref` / type-descriptor-local string blobs and are
//! addressable through [`MachoBinary::raw`], so `&'a str` is the
//! correct name lifetime — matching the [`crate::objc::ObjcRuntime`]
//! convention.
//!
//! [`MachoBinary`]: crate::binary::MachoBinary
//! [`MachoBinary::raw`]: crate::binary::MachoBinary::raw
//!
//! ## Fail-soft posture
//!
//! [`MachoBinary::swift`](crate::binary::MachoBinary::swift) returns
//! `None` when the image carries no Swift content — concretely, when
//! none of `__swift5_types`, `__swift5_protos`, `__swift5_proto`,
//! `__swift5_fieldmd` is present. A reflection-stripped Swift binary
//! that ships only conformances still produces `Some(_)`.
//!
//! Per-row decode failures inside variable-length tables (type
//! descriptors, field records, vtable entries) silently skip the
//! row; when the `tracing` feature is enabled the bail-out is
//! emitted at debug level. Unknown enum kinds surface as
//! [`ContextDescriptorKind::Other`] / [`TypeReferenceKind::Other`] /
//! [`FieldDescriptorKind::Other`] / [`SwiftMethodKind::Other`]
//! rather than dropping the row.

use std::collections::HashMap;

use crate::{
    binary::MachoBinary,
    util::{read_cstr_at, read_u32_le_at, read_u64_le_at, vm_to_file_offset_in},
};

mod capture;
mod classtrailers;
mod conformance;
mod context;
mod field;
mod parent;
mod protocol;
mod reflstr;
mod replacement;
mod section;
mod typedescriptor;
mod vtable;

pub use capture::{CaptureDescriptor, CaptureIter};
pub use classtrailers::{
    ForeignMetadataInit, GenericContextHeader, InvertibleProtocolSet, ObjcResilientClassStubInfo,
    PrespecializationIter, ResilientSuperclass, SingletonMetadataInit, SingletonMetadataPointer,
};
pub use conformance::{Conformance, ConformanceIter, TypeReference};
pub use context::{
    ConformanceFlags, ContextDescriptorFlags, ContextDescriptorKind, FieldDescriptorKind,
    FieldRecordFlags, MetadataInitializationKind, MethodDescriptorFlags, SwiftMethodKind,
    TypeContextDescriptorFlags, TypeReferenceKind,
};
pub use field::{FieldDescriptor, FieldIter, FieldRecord, FieldRecordIter};
pub use parent::{ParentChain, ParentContext};
pub use protocol::{ProtocolIter, SwiftProtocol};
pub use replacement::{DynamicReplacementScope, ReplacementIter};
pub use typedescriptor::{
    DefaultOverrideTableHeader, OverrideTableHeader, TypeDescriptor, TypeIter, TypeKindBody,
    VTableHeader,
};
pub use vtable::{
    DefaultOverrideEntry, DefaultOverrideEntryIter, OverrideEntry, OverrideEntryIter, VTableEntry,
    VTableIter,
};

pub(crate) use section::{SwiftSection, find_swift_section};

/// Aggregate view over the Swift 5 runtime metadata embedded in a
/// Mach-O image.
///
/// Constructed via
/// [`MachoBinary::swift`](crate::binary::MachoBinary::swift); returns
/// `None` when the image carries no Swift content (none of
/// `__swift5_types`, `__swift5_protos`, `__swift5_proto`, or
/// `__swift5_fieldmd` is present) or when the parsed Mach-O is
/// 32-bit (the v0.1 walker is 64-bit only).
///
/// Carries the parsed-once metadata by value (cached section
/// lookups, segment table for `vm_to_file_offset`, chained-fixup
/// rebase / bind index) so iterators can borrow `&self`
/// independently of the originating [`MachoBinary`] borrow.
///
/// Cite: `RESEARCH.md` §"Swift type metadata" (line 1696),
/// §"Section-name catalogue" (line 2369).
#[derive(Debug)]
pub struct SwiftRuntime<'a> {
    pub(crate) data: &'a [u8],
    /// Cached `(vmaddr, vmsize, fileoff, filesize)` tuples for every
    /// segment with non-zero file backing — the input to
    /// [`vm_to_file_offset_in`]. Kept by value so the runtime
    /// outlives the originating [`MachoBinary`] borrow.
    pub(crate) segments: Vec<(u64, u64, u64, u64)>,

    pub(crate) types: Option<SwiftSection<'a>>,
    pub(crate) protos: Option<SwiftSection<'a>>,
    pub(crate) proto: Option<SwiftSection<'a>>,
    pub(crate) fieldmd: Option<SwiftSection<'a>>,
    pub(crate) replac: Option<SwiftSection<'a>>,
    pub(crate) replac2: Option<SwiftSection<'a>>,
    pub(crate) capture: Option<SwiftSection<'a>>,
    /// `__swift5_reflstr` — pool of NUL-terminated UTF-8 reflection
    /// strings. Field-name resolution falls back here when the
    /// primary segment-table lookup fails (forward-compat for
    /// linker variants that emit reflstr outside the standard
    /// `__TEXT` placement).
    pub(crate) reflstr: Option<SwiftSection<'a>>,
    /// `__swift5_typeref` — mangled-name pool. Reserved for
    /// future use; presence is surfaced via the section-discovery
    /// path.
    #[allow(dead_code)]
    pub(crate) typeref: Option<SwiftSection<'a>>,
    pub(crate) builtin: Option<SwiftSection<'a>>,
    pub(crate) entry: Option<SwiftSection<'a>>,
    pub(crate) mpenum: Option<SwiftSection<'a>>,
    pub(crate) acfuncs: Option<SwiftSection<'a>>,
    pub(crate) assocty: Option<SwiftSection<'a>>,

    /// `vm_address → (symbol_name, dylib)` for every chained-fixup
    /// bind in the image. Reserved for future conformance-walker
    /// extensions that resolve external Obj-C class references.
    #[allow(dead_code)]
    pub(crate) binds_by_va: HashMap<u64, (&'a str, &'a str)>,
    /// `vm_address → canonical target VA` for every chained-fixup
    /// rebase. Used by [`Self::resolve_absolute_pointer`] for the
    /// rare absolute slots (dynamic-replacement caches, indirect
    /// type references).
    #[allow(dead_code)]
    pub(crate) rebases_by_va: HashMap<u64, u64>,
}

impl<'a> SwiftRuntime<'a> {
    /// Construct the aggregate from a parent [`MachoBinary`].
    ///
    /// Returns `None` when:
    ///
    /// - The image is 32-bit. v0.1 deliberately scopes the Swift
    ///   walker to 64-bit Mach-O; 32-bit slices return `None` here
    ///   so the caller can record a single skip-with-reason event
    ///   without having to inspect every accessor.
    /// - The image carries no Swift content — concretely, none of
    ///   `__swift5_types`, `__swift5_protos`, `__swift5_proto`, or
    ///   `__swift5_fieldmd` is present. Reflection-stripped images
    ///   that ship only conformances still produce `Some(_)`.
    pub(crate) fn build(bin: &MachoBinary<'a>) -> Option<Self> {
        if !bin.header().is_64() {
            #[cfg(feature = "tracing")]
            tracing::debug!("darwinscope::swift: 32-bit Mach-O — Swift walker is 64-bit only");
            return None;
        }

        let types = find_swift_section(bin, "__swift5_types");
        let protos = find_swift_section(bin, "__swift5_protos");
        let proto = find_swift_section(bin, "__swift5_proto");
        let fieldmd = find_swift_section(bin, "__swift5_fieldmd");

        // Detector union — any of the four "load-bearing" Swift
        // sections counts as Swift content. A binary can be stripped
        // of fieldmd reflection but still carry types + conformances;
        // a third-party library can ship only conformances against
        // an external type. The unioned detector covers every
        // real-world case.
        if types.is_none() && protos.is_none() && proto.is_none() && fieldmd.is_none() {
            return None;
        }

        let mut segments: Vec<(u64, u64, u64, u64)> = Vec::new();
        for s in bin.segments() {
            segments.push((s.vmaddr(), s.vmsize(), s.fileoff(), s.filesize()));
        }

        // Index every bind site by slot VA. Foreign-class type
        // references in conformances resolve through this map.
        // Re-borrow into the data lifetime — names live in
        // `__LINKEDIT` / `LC_SYMTAB.stroff`, both of which are
        // addressable through `bin.raw()`.
        let mut binds_by_va: HashMap<u64, (&'a str, &'a str)> = HashMap::new();
        let data = bin.raw();
        for imp in bin.imports() {
            let Some(name) = reborrow_into_data(data, imp.name) else {
                continue;
            };
            let Some(dylib) = reborrow_into_data(data, imp.dylib) else {
                continue;
            };
            binds_by_va.insert(imp.address, (name, dylib));
        }

        let mut rebases_by_va: HashMap<u64, u64> = HashMap::new();
        for r in bin.chained_rebases() {
            rebases_by_va.insert(r.vm_address(), r.target_vmaddr());
        }

        Some(Self {
            data,
            segments,
            types,
            protos,
            proto,
            fieldmd,
            replac: find_swift_section(bin, "__swift5_replac"),
            replac2: find_swift_section(bin, "__swift5_replac2"),
            capture: find_swift_section(bin, "__swift5_capture"),
            reflstr: find_swift_section(bin, "__swift5_reflstr"),
            typeref: find_swift_section(bin, "__swift5_typeref"),
            builtin: find_swift_section(bin, "__swift5_builtin"),
            entry: find_swift_section(bin, "__swift5_entry"),
            mpenum: find_swift_section(bin, "__swift5_mpenum"),
            acfuncs: find_swift_section(bin, "__swift5_acfuncs"),
            assocty: find_swift_section(bin, "__swift5_assocty"),
            binds_by_va,
            rebases_by_va,
        })
    }

    /// Iterator over every type context descriptor in
    /// `__swift5_types` — class, struct, enum, plus any other kind
    /// surfaced as [`ContextDescriptorKind::Other`].
    pub fn types(&self) -> TypeIter<'a, '_> {
        TypeIter::new(self)
    }

    /// Iterator over every protocol descriptor in `__swift5_protos`.
    pub fn protocols(&self) -> ProtocolIter<'a, '_> {
        ProtocolIter::new(self)
    }

    /// Iterator over every protocol-conformance row in
    /// `__swift5_proto`. The single most attribution-bearing Swift
    /// section.
    pub fn conformances(&self) -> ConformanceIter<'a, '_> {
        ConformanceIter::new(self)
    }

    /// Iterator over every field descriptor in `__swift5_fieldmd`.
    /// Each [`FieldDescriptor`] yields its own [`FieldRecord`]
    /// stream.
    pub fn field_descriptors(&self) -> FieldIter<'a, '_> {
        FieldIter::new(self)
    }

    /// Iterator over `__swift5_replac` dynamic-replacement scope
    /// descriptors.
    pub fn dynamic_replacements(&self) -> ReplacementIter<'a, '_> {
        ReplacementIter::new(self)
    }

    /// Iterator over `__swift5_capture` closure-capture descriptors.
    pub fn captures(&self) -> CaptureIter<'a, '_> {
        CaptureIter::new(self)
    }

    /// `true` when the image carries an `__swift5_entry` section
    /// (Swift `@main` entry-point info).
    pub fn has_entry_point(&self) -> bool {
        self.entry.is_some()
    }

    /// `true` when the image carries an `__swift5_builtin` section.
    /// Presence-only — the structured walker is post-v0.1.
    pub fn has_builtin_descriptors(&self) -> bool {
        self.builtin.is_some()
    }

    /// `true` when the image carries an `__swift5_mpenum` section
    /// (multi-payload enum spare-bit info). Presence-only.
    pub fn has_multi_payload_enum_descriptors(&self) -> bool {
        self.mpenum.is_some()
    }

    /// `true` when the image carries an `__swift5_acfuncs` section
    /// (`@_silgen_name` accessible-function table, Swift 5.7+).
    /// Presence-only.
    pub fn has_accessible_functions(&self) -> bool {
        self.acfuncs.is_some()
    }

    /// `true` when the image carries an `__swift5_assocty` section
    /// (associated-type witnesses). Presence-only.
    pub fn has_associated_type_descriptors(&self) -> bool {
        self.assocty.is_some()
    }

    /// `true` when the image carries an `__swift5_replac2` section
    /// (Swift 5.5+ dynamic replacement chain). Presence-only.
    pub fn has_replacement_chain(&self) -> bool {
        self.replac2.is_some()
    }

    /// Translate a virtual-memory address to its on-disk file
    /// offset using the cached segment table.
    pub(crate) fn vm_to_file_offset(&self, vmaddr: u64) -> Option<u64> {
        vm_to_file_offset_in(self.segments.iter().copied(), vmaddr)
    }

    /// Read the C-string at virtual address `vmaddr`. Returns `None`
    /// when the address fails to resolve through the segment table
    /// or when the bytes are not valid UTF-8.
    pub(crate) fn read_cstr(&self, vmaddr: u64) -> Option<&'a str> {
        if vmaddr == 0 {
            return None;
        }
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        read_cstr_at(self.data, off)
    }

    /// Read a little-endian `u32` at virtual address `vmaddr`.
    #[allow(dead_code)]
    pub(crate) fn read_u32(&self, vmaddr: u64) -> Option<u32> {
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        read_u32_le_at(self.data, off)
    }

    /// Read a little-endian `u64` at virtual address `vmaddr`. The
    /// result is **not** PAC-stripped. Used by
    /// [`Self::resolve_absolute_pointer`] for rare absolute slot
    /// reads.
    #[allow(dead_code)]
    pub(crate) fn read_u64(&self, vmaddr: u64) -> Option<u64> {
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        read_u64_le_at(self.data, off)
    }

    /// Translate a VA into a file offset and return a slice of `len`
    /// bytes from that offset, or `None` on out-of-bounds.
    pub(crate) fn read_bytes(&self, vmaddr: u64, len: usize) -> Option<&'a [u8]> {
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }

    /// Resolve an *absolute* pointer slot at virtual address
    /// `slot_va` to its canonical target VA.
    ///
    /// Most Swift descriptor pointers are i32-relative and don't
    /// reach this function — they're resolved via
    /// [`crate::util::relative_pointer`]. Absolute slots (the rare
    /// dynamic-replacement caches and `IndirectTypeDescriptor` /
    /// `IndirectObjCClass` slots) go through the chained-fixup
    /// rebase map first, then fall back to a PAC-stripped raw read.
    ///
    /// Returns `None` if the slot can't be read.
    #[allow(dead_code)]
    pub(crate) fn resolve_absolute_pointer(&self, slot_va: u64) -> Option<u64> {
        if let Some(&target) = self.rebases_by_va.get(&slot_va) {
            return Some(target);
        }
        let raw = self.read_u64(slot_va)?;
        Some(crate::ptrauth::strip_signature(raw))
    }
}

/// Re-borrow a `&str` slice that aliases somewhere inside `data`,
/// returning a `&'a str` whose lifetime is the data lifetime.
///
/// The workaround for the lifetime-collapse documented in
/// [`crate::import`]: `goblin::mach::MachO::imports` ties its name
/// strings to the `&self` borrow rather than to the data lifetime,
/// even though the bytes themselves live in `__LINKEDIT` /
/// `LC_SYMTAB.stroff` and are addressable through `bin.raw()`. We
/// locate the slice's pointer range inside `data`, reborrow at that
/// range, and confirm the bytes still parse as valid UTF-8.
fn reborrow_into_data<'a>(data: &'a [u8], borrowed: &str) -> Option<&'a str> {
    if borrowed.is_empty() {
        // Empty strings can't be located inside `data` (no anchor
        // pointer); the caller treats them as "no name" anyway.
        return Some("");
    }
    let data_start = data.as_ptr() as usize;
    let data_end = data_start.checked_add(data.len())?;
    let s_start = borrowed.as_ptr() as usize;
    let s_end = s_start.checked_add(borrowed.len())?;
    if s_start < data_start || s_end > data_end {
        return None;
    }
    let off = s_start.checked_sub(data_start)?;
    let end = off.checked_add(borrowed.len())?;
    let slice = data.get(off..end)?;
    core::str::from_utf8(slice).ok()
}
