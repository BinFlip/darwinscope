//! Objective-C 2 / non-fragile-ABI runtime metadata walker.
//!
//! Walks the `__objc_classlist` (lazy) and `__objc_nlclslist`
//! (non-lazy) class indirection tables and emits typed views over
//! the `class_t` / `class_ro_t` / `method_list_t` (legacy 24-byte
//! and small 12-byte) / `ivar_list_t` / `property_list_t` /
//! `protocol_t` / `category_t` structs they reference.
//!
//! Also reads the cross-section reference tables
//! (`__objc_selrefs`, `__objc_classrefs`, `__objc_superrefs`,
//! `__objc_protorefs`), the `__objc_protolist` protocol descriptor
//! list, the `__objc_catlist` and `__objc_nlcatlist` category
//! lists, and the `__objc_imageinfo` versioning metadata.
//!
//! See `RESEARCH.md` §"Objective-C runtime" for layout references.
//! Section name synonyms are catalogued in `RESEARCH.md`
//! §"Section names" — the lookup is segment-agnostic on purpose.
//!
//! ## Lifetime convention
//!
//! Every typed view here uses `<'a, 'p>` — `'a` is the data slice
//! lifetime (where ObjC strings, struct payloads, and section
//! bodies live) and `'p` is the borrow of the parent
//! [`MachoBinary`] that owns the aggregate [`ObjcRuntime`]. ObjC
//! string fields all live in `__TEXT,__objc_methname` /
//! `__objc_classname` / `__objc_methtype` and are addressable
//! through [`MachoBinary::raw`], so `&'a str` is the right name
//! lifetime — this matches the [`Symbol`] and [`Section`]
//! conventions.
//!
//! [`MachoBinary`]: crate::binary::MachoBinary
//! [`MachoBinary::raw`]: crate::binary::MachoBinary::raw
//! [`Symbol`]: crate::symbol::Symbol
//! [`Section`]: crate::segment::Section
//!
//! ## Fail-soft posture
//!
//! [`MachoBinary::objc`](crate::binary::MachoBinary::objc) returns
//! `None` when the image has no `__objc_imageinfo` (i.e. carries no
//! ObjC content). Per-row decode failures inside variable-length
//! tables (method / ivar / property lists) silently skip the row;
//! when the `tracing` feature is enabled the bail-out is emitted
//! at debug level.

use std::collections::HashMap;

use crate::{
    binary::MachoBinary,
    util::{read_cstr_at, read_u32_le_at, read_u64_le_at, vm_to_file_offset_in},
};

mod category;
mod class;
mod conformance;
mod imageinfo;
mod ivar;
mod method;
mod property;
mod protocol;
mod refs;
mod section;

pub use category::{CategoryIter, ObjcCategory};
pub use class::{ClassIter, ClassRo, ObjcClass};
pub use conformance::{ConformanceEdge, ConformanceIter};
pub use imageinfo::{
    ImageInfo, OBJC_IMAGE_DYLD_CATEGORIES_OPTIMIZED, OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES,
    OBJC_IMAGE_IS_SIMULATED, OBJC_IMAGE_OPTIMIZED_BY_DYLD, OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE,
    OBJC_IMAGE_REQUIRES_GC, OBJC_IMAGE_SIGNED_CLASS_RO, OBJC_IMAGE_SUPPORTS_GC,
    OBJC_IMAGE_SWIFT_STABLE_VERSION_MASK, OBJC_IMAGE_SWIFT_UNSTABLE_VERSION_MASK,
};
pub use ivar::{Ivar, IvarIter};
pub use method::{Method, MethodIter, MethodKind};
pub use property::{ParsedAttribute, ParsedAttributes, Property, PropertyIter};
pub use protocol::{ObjcProtocol, ProtocolIter, ProtocolNameIter};
pub use refs::{ClassRefIter, ProtoRefIter, RefTarget, SelRefIter, SuperRefIter};

pub(crate) use section::{ObjcSection, find_section};

/// Aggregate view over the Obj-C 2 runtime metadata embedded in a
/// Mach-O image.
///
/// Constructed via
/// [`MachoBinary::objc`](crate::binary::MachoBinary::objc); returns
/// `None` when the image has no `__objc_imageinfo` section (i.e.
/// the image carries no ObjC content) or when the parsed Mach-O is
/// 32-bit (the v0.1 walker is 64-bit only).
///
/// Carries the parsed-once metadata by value (image info, section
/// lookups, segment table for `vm_to_file_offset`, chained-fixup
/// bind index) so iterators can borrow `&self` independently of the
/// originating [`MachoBinary`] borrow.
///
/// Cite: `RESEARCH.md` §"Objective-C runtime" (line 1289),
/// §"Section names" (line 2381).
#[derive(Debug)]
pub struct ObjcRuntime<'a> {
    pub(crate) data: &'a [u8],
    /// Cached `(vmaddr, vmsize, fileoff, filesize)` tuples for
    /// every segment with non-zero file backing — the input to
    /// [`vm_to_file_offset_in`]. Kept by value so the runtime
    /// outlives the originating [`MachoBinary`] borrow.
    pub(crate) segments: Vec<(u64, u64, u64, u64)>,

    pub(crate) image_info: ImageInfo,

    pub(crate) class_list: Option<ObjcSection<'a>>,
    pub(crate) nlclslist: Option<ObjcSection<'a>>,
    pub(crate) cat_list: Option<ObjcSection<'a>>,
    pub(crate) nlcat_list: Option<ObjcSection<'a>>,
    pub(crate) proto_list: Option<ObjcSection<'a>>,

    pub(crate) sel_refs: Option<ObjcSection<'a>>,
    pub(crate) class_refs: Option<ObjcSection<'a>>,
    pub(crate) super_refs: Option<ObjcSection<'a>>,
    pub(crate) proto_refs: Option<ObjcSection<'a>>,

    /// `vm_address → (symbol_name, dylib)` for every chained-fixup
    /// bind in the image. Drives ref-section resolution for
    /// foreign-class / foreign-protocol pointers.
    pub(crate) binds_by_va: HashMap<u64, (&'a str, &'a str)>,
    /// `vm_address → canonical target VA` for every chained-fixup
    /// rebase. For images that use `LC_DYLD_CHAINED_FIXUPS`, the
    /// raw bytes in `__objc_classlist` / `__objc_protolist` etc.
    /// encode chain-format pointer slots, not raw pointers — the
    /// canonical target lives in [`Rebase::target_vmaddr`]. For
    /// legacy `LC_DYLD_INFO` images this map is empty and the
    /// walker falls back to PAC-stripping the raw slot value.
    pub(crate) rebases_by_va: HashMap<u64, u64>,
}

impl<'a> ObjcRuntime<'a> {
    /// Construct the aggregate from a parent [`MachoBinary`].
    ///
    /// Returns `None` when:
    ///
    /// - The image is 32-bit. v0.1 deliberately scopes the Obj-C
    ///   walker to 64-bit Mach-O; 32-bit slices return `None` here
    ///   so the caller can record a single skip-with-reason event
    ///   without having to inspect every accessor.
    /// - The image has no `__objc_imageinfo` section, i.e. carries
    ///   no ObjC content.
    /// - `__objc_imageinfo` was found but its body is truncated
    ///   below the 8-byte minimum.
    pub(crate) fn build(bin: &MachoBinary<'a>) -> Option<Self> {
        if !bin.header().is_64() {
            #[cfg(feature = "tracing")]
            tracing::debug!("darwinscope::objc: 32-bit Mach-O — Obj-C walker is 64-bit only");
            return None;
        }
        let imageinfo_sec = find_section(bin, "__objc_imageinfo")?;
        let image_info = ImageInfo::parse(imageinfo_sec.body)?;

        // Index every bind site (both legacy `LC_DYLD_INFO` opcodes
        // and modern `LC_DYLD_CHAINED_FIXUPS` chains) by the slot
        // VA. ObjC ref sections and category `cls` slots resolve
        // through this map. Real binaries ship exactly one of the
        // two bind encodings — `MachoBinary::imports` merges them
        // for us, so we don't have to dispatch on which one was
        // emitted.
        //
        // SAFETY w.r.t. lifetimes: `Import<'p>::name` and `dylib`
        // are tied to the goblin `&self` borrow; we widen them to
        // the data lifetime by reborrowing the underlying byte
        // slice. The names live in `__LINKEDIT` for chained fixups
        // and in `LC_SYMTAB.stroff` for legacy binds, both of which
        // are addressable through `bin.raw()` (the `'a` slice).
        // `Import.name` already points at those bytes; the cast
        // here merely re-asserts the pre-existing aliasing.
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

        let mut segments: Vec<(u64, u64, u64, u64)> = Vec::new();
        for s in bin.segments() {
            segments.push((s.vmaddr(), s.vmsize(), s.fileoff(), s.filesize()));
        }

        let mut rebases_by_va: HashMap<u64, u64> = HashMap::new();
        for r in bin.chained_rebases() {
            rebases_by_va.insert(r.vm_address(), r.target_vmaddr());
        }

        Some(Self {
            data: bin.raw(),
            segments,
            image_info,
            class_list: find_section(bin, "__objc_classlist"),
            nlclslist: find_section(bin, "__objc_nlclslist"),
            cat_list: find_section(bin, "__objc_catlist"),
            nlcat_list: find_section(bin, "__objc_nlcatlist"),
            proto_list: find_section(bin, "__objc_protolist"),
            sel_refs: find_section(bin, "__objc_selrefs"),
            class_refs: find_section(bin, "__objc_classrefs"),
            super_refs: find_section(bin, "__objc_superrefs"),
            proto_refs: find_section(bin, "__objc_protorefs"),
            binds_by_va,
            rebases_by_va,
        })
    }

    /// Decoded `__objc_imageinfo` payload (always present — a
    /// successful [`ObjcRuntime`] is gated on its existence).
    pub fn image_info(&self) -> ImageInfo {
        self.image_info
    }

    /// Iterator over every class in the image.
    ///
    /// Walks `__objc_classlist` (lazy) and `__objc_nlclslist`
    /// (non-lazy), de-duplicating by `class_t` VM address. Each
    /// instance class is paired with its metaclass twin: the
    /// instance-class row is emitted first and the metaclass row
    /// (with [`ObjcClass::is_meta`] returning `true`) second.
    pub fn classes(&self) -> ClassIter<'a, '_> {
        ClassIter::new(self)
    }

    /// Iterator over every protocol descriptor in `__objc_protolist`.
    pub fn protocols(&self) -> ProtocolIter<'a, '_> {
        ProtocolIter::new(self)
    }

    /// Iterator over every category in `__objc_catlist` plus
    /// `__objc_nlcatlist` (de-duped by category VA).
    pub fn categories(&self) -> CategoryIter<'a, '_> {
        CategoryIter::new(self)
    }

    /// Class ↔ protocol conformance edges flattened across every
    /// class in [`Self::classes`].
    pub fn conformances(&self) -> ConformanceIter<'a, '_> {
        ConformanceIter::new(self)
    }

    /// Selectors referenced at runtime via `__objc_selrefs`.
    pub fn selector_refs(&self) -> SelRefIter<'a, '_> {
        SelRefIter::new(self)
    }

    /// Class references via `__objc_classrefs`.
    pub fn class_refs(&self) -> ClassRefIter<'a, '_> {
        ClassRefIter::new(self)
    }

    /// Super-class references via `__objc_superrefs`.
    pub fn super_refs(&self) -> SuperRefIter<'a, '_> {
        SuperRefIter::new(self)
    }

    /// Protocol references via `__objc_protorefs`.
    pub fn protocol_refs(&self) -> ProtoRefIter<'a, '_> {
        ProtoRefIter::new(self)
    }

    /// Translate a virtual-memory address to its on-disk file
    /// offset using the cached segment table.
    pub(crate) fn vm_to_file_offset(&self, vmaddr: u64) -> Option<u64> {
        vm_to_file_offset_in(self.segments.iter().copied(), vmaddr)
    }

    /// Read the C-string at virtual address `vmaddr`.
    ///
    /// Used internally by every walker to resolve ObjC names from
    /// `__TEXT,__objc_methname` / `__objc_classname` /
    /// `__objc_methtype`. Returns `None` when the address fails to
    /// resolve through the segment table or when the bytes are not
    /// valid UTF-8.
    pub(crate) fn read_cstr(&self, vmaddr: u64) -> Option<&'a str> {
        if vmaddr == 0 {
            return None;
        }
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        read_cstr_at(self.data, off)
    }

    /// Read a little-endian `u32` at virtual address `vmaddr`.
    pub(crate) fn read_u32(&self, vmaddr: u64) -> Option<u32> {
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        read_u32_le_at(self.data, off)
    }

    /// Read a little-endian `u64` at virtual address `vmaddr`.
    ///
    /// The result is **not** PAC-stripped — callers that read
    /// PAC-signed slots (`isa`, `superclass`, `imp`) should pipe
    /// through [`ptr_auth::strip_signature`](crate::ptr_auth::strip_signature)
    /// before dereferencing.
    pub(crate) fn read_u64(&self, vmaddr: u64) -> Option<u64> {
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        read_u64_le_at(self.data, off)
    }

    /// Translate a VA into a file offset and return a slice of
    /// `len` bytes from that offset, or `None` on out-of-bounds.
    pub(crate) fn read_bytes(&self, vmaddr: u64, len: usize) -> Option<&'a [u8]> {
        let off = self.vm_to_file_offset(vmaddr)? as usize;
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }

    /// Resolve a pointer slot at virtual address `slot_va` to its
    /// canonical target VA.
    ///
    /// For images that ship `LC_DYLD_CHAINED_FIXUPS`, the on-disk
    /// bytes in ObjC metadata sections (`__objc_classlist`,
    /// `class_t.isa`, `class_t.superclass`, `class_ro_t.name`, …)
    /// are *chain-format* slot encodings — high bits carry chain
    /// metadata, not VA. The canonical target lives in the decoded
    /// [`Rebase::target_vmaddr`](crate::fixup::Rebase::target_vmaddr).
    ///
    /// For legacy `LC_DYLD_INFO` images, the slot bytes are a raw
    /// 64-bit pointer (PAC-signed on arm64e); we strip the PAC bits
    /// and return the canonical VA.
    ///
    /// Returns `None` if the slot can't be read.
    pub(crate) fn resolve_pointer(&self, slot_va: u64) -> Option<u64> {
        if let Some(&target) = self.rebases_by_va.get(&slot_va) {
            return Some(target);
        }
        let raw = self.read_u64(slot_va)?;
        Some(crate::ptrauth::strip_signature(raw))
    }
}

/// Re-borrow a `&str` slice that we know aliases somewhere inside
/// `data`, returning a `&'a str` whose lifetime is the data
/// lifetime.
///
/// This is the workaround for the lifetime-collapse documented in
/// [`crate::import`] (line 19-29): `goblin::mach::MachO::imports`
/// ties its name strings to the `&self` borrow rather than to the
/// data lifetime, even though the bytes themselves live in
/// `__LINKEDIT` / `LC_SYMTAB.stroff` and are addressable through
/// `bin.raw()`. We locate the slice's pointer range inside `data`,
/// reborrow at that range, and confirm the bytes still parse as
/// valid UTF-8 (they always do — this is a sanity check, not a
/// correctness guard).
///
/// Returns `None` when the slice does not lie inside `data` (which
/// would indicate a goblin internal that allocated a fresh string,
/// not aliasing the input bytes).
fn reborrow_into_data<'a>(data: &'a [u8], s: &str) -> Option<&'a str> {
    let s_ptr = s.as_ptr() as usize;
    let s_len = s.len();
    let data_start = data.as_ptr() as usize;
    let data_end = data_start.checked_add(data.len())?;
    if s_ptr < data_start {
        return None;
    }
    let s_end = s_ptr.checked_add(s_len)?;
    if s_end > data_end {
        return None;
    }
    let off = s_ptr.checked_sub(data_start)?;
    let end = off.checked_add(s_len)?;
    let bytes = data.get(off..end)?;
    core::str::from_utf8(bytes).ok()
}

/// Strip the canonical ObjC linker prefix from a chained-fixup bind
/// symbol name.
///
/// Examples:
///
/// - `_OBJC_CLASS_$_NSObject` → `NSObject`
/// - `_OBJC_METACLASS_$_NSObject` → `NSObject`
/// - `_OBJC_PROTOCOL_$_NSCoding` → `NSCoding`
/// - `_OBJC_REF_$_NSCoding` → `NSCoding`
///
/// Used when resolving `__objc_classrefs` / `__objc_superrefs` /
/// `__objc_protorefs` cross-image binds to ergonomic class /
/// protocol names. The prefix list is the exhaustive set linkers
/// emit; cite `objc4/runtime/objc-private.h:99-105` and
/// `clang/lib/CodeGen/CGObjCMac.cpp` (the `GetClassName` /
/// `GetProtocolName` symbol-prefix functions).
pub(crate) fn strip_objc_symbol_prefix(name: &str) -> &str {
    const PREFIXES: &[&str] = &[
        "_OBJC_CLASS_$_",
        "_OBJC_METACLASS_$_",
        "_OBJC_PROTOCOL_$_",
        "_OBJC_REF_$_",
        "_OBJC_LABEL_PROTOCOL_$_",
    ];
    for p in PREFIXES {
        if let Some(rest) = name.strip_prefix(p) {
            return rest;
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_class_prefix() {
        assert_eq!(
            strip_objc_symbol_prefix("_OBJC_CLASS_$_NSObject"),
            "NSObject"
        );
        assert_eq!(
            strip_objc_symbol_prefix("_OBJC_METACLASS_$_NSObject"),
            "NSObject"
        );
        assert_eq!(
            strip_objc_symbol_prefix("_OBJC_PROTOCOL_$_NSCoding"),
            "NSCoding"
        );
        // Untouched if the prefix doesn't match.
        assert_eq!(
            strip_objc_symbol_prefix("_NSConcreteStackBlock"),
            "_NSConcreteStackBlock"
        );
    }
}
