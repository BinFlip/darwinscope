//! Class + class_ro_t walker.
//!
//! Walks `__objc_classlist` (lazy) and `__objc_nlclslist` (non-lazy)
//! and emits typed views over the `class_t` and `class_ro_t`
//! structures they reference.
//!
//! Cite: `objc4/runtime/objc-runtime-new.h:2635-2643` (`class_t`),
//! `:1598-1664` (`class_ro_t`), `:120-180` (`FAST_*` flag bits),
//! `:133-148` (`FAST_DATA_MASK` per arch). `RESEARCH.md` anchors at
//! lines 1325, 1340, 1380.
//!
//! ## `class_t` (40 bytes)
//!
//! ```text
//! isa         u64  @ 0    PAC-signed; points to metaclass
//! superclass  u64  @ 8    PAC-signed; 0 for root or chained-bind
//! cache       16B  @ 16   zero on disk
//! bits        u64  @ 32   FAST_DATA_MASK + FAST_*_FLAGS
//! ```
//!
//! ## `class_ro_t` (LP64, 72 bytes)
//!
//! ```text
//! flags          u32  @ 0
//! instanceStart  u32  @ 4
//! instanceSize   u32  @ 8
//! reserved       u32  @ 12  LP64 padding
//! ivarLayout     u64  @ 16  (or nonMetaclass when RO_META set)
//! name           u64  @ 24  -> __TEXT,__objc_classname C-string
//! baseMethods    u64  @ 32
//! baseProtocols  u64  @ 40
//! ivars          u64  @ 48
//! weakIvarLayout u64  @ 56
//! baseProperties u64  @ 64
//! ```

use std::marker::PhantomData;

use bitflags::bitflags;

use crate::{
    objc::{
        ivar::{ivar_list_iter, IvarIter},
        method::{method_list_iter, MethodIter},
        property::{property_list_iter, PropertyIter},
        protocol::{protocol_name_iter, ProtocolNameIter},
        strip_objc_symbol_prefix, ObjcRuntime,
    },
    util::read_u32_le_at,
};

/// On-disk size of a `class_t` struct.
pub(crate) const CLASS_T_SIZE: usize = 40;

/// Offset of the `bits` word inside `class_t`.
const CLASS_T_BITS_OFFSET: usize = 32;

/// On-disk size of a `class_ro_t` struct (through `baseProperties`).
const CLASS_RO_T_SIZE: usize = 72;

/// `FAST_DATA_MASK` for arm64 / x86_64 (16 KB pages, no large-VM):
/// extracts a 35-bit `class_ro_t` pointer with low-3-bits cleared.
/// Cite: `objc4/runtime/objc-runtime-new.h:140`.
const FAST_DATA_MASK_64: u64 = 0x0000_007f_ffff_fff8;

/// `FAST_DATA_MASK` for arm64e — wider to accommodate the larger
/// VA range PAC stripping leaves.
/// Cite: `objc4/runtime/objc-runtime-new.h:138`.
const FAST_DATA_MASK_ARM64E: u64 = 0x0f00_7fff_ffff_fff8;

/// `FAST_FLAGS_MASK` — the 3 fast-flag bits.
/// Cite: `objc4/runtime/objc-runtime-new.h:145`.
const FAST_FLAGS_MASK: u64 = 0x0000_0000_0000_0007;

/// `FAST_IS_SWIFT_LEGACY` — Swift 4 / earlier ABI.
/// Cite: `objc4/runtime/objc-runtime-new.h:121`.
pub const FAST_IS_SWIFT_LEGACY: u64 = 0x1;
/// `FAST_IS_SWIFT_STABLE` — Swift 5+ stable ABI.
/// Cite: `objc4/runtime/objc-runtime-new.h:122`.
pub const FAST_IS_SWIFT_STABLE: u64 = 0x2;
/// `FAST_HAS_DEFAULT_RR` — class has default retain/release.
/// Cite: `objc4/runtime/objc-runtime-new.h:123`.
pub const FAST_HAS_DEFAULT_RR: u64 = 0x4;

bitflags! {
    /// `RO_*` flag bits in `class_ro_t.flags`.
    ///
    /// Cite: `objc4/runtime/objc-runtime-new.h:43-70` and
    /// `RESEARCH.md` §"`RO_*` flags" (line 1407).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RoFlags: u32 {
        /// `RO_META` — this `class_ro_t` belongs to a metaclass.
        const META = 1 << 0;
        /// `RO_ROOT` — root class (e.g. `NSObject`).
        const ROOT = 1 << 1;
        /// `RO_HAS_CXX_STRUCTORS` — class has C++ ctor and dtor.
        const HAS_CXX_STRUCTORS = 1 << 2;
        /// `RO_HIDDEN` — class is symbol-hidden.
        const HIDDEN = 1 << 4;
        /// `RO_EXCEPTION` — Obj-C exception class.
        const EXCEPTION = 1 << 5;
        /// `RO_HAS_SWIFT_INITIALIZER` — Swift-metadata initialiser
        /// trailing pointer is present.
        const HAS_SWIFT_INITIALIZER = 1 << 6;
        /// `RO_IS_ARC` — built with ARC.
        const IS_ARC = 1 << 7;
        /// `RO_HAS_CXX_DTOR_ONLY` — C++ destructor only (no ctor).
        const HAS_CXX_DTOR_ONLY = 1 << 8;
        /// `RO_HAS_WEAK_WITHOUT_ARC` — weak ivars but not ARC.
        const HAS_WEAK_WITHOUT_ARC = 1 << 9;
        /// `RO_FORBIDS_ASSOCIATED_OBJECTS` — cannot have associated
        /// objects.
        const FORBIDS_ASSOCIATED_OBJECTS = 1 << 10;
        /// `RO_FROM_BUNDLE` — class came from a bundle.
        const FROM_BUNDLE = 1 << 29;
        /// `RO_FUTURE` — set by runtime, never on disk.
        const FUTURE = 1 << 30;
        /// `RO_REALIZED` — set by runtime, never on disk.
        const REALIZED = 1 << 31;
    }
}

/// One Obj-C class (or metaclass).
///
/// Each instance class in `__objc_classlist` / `__objc_nlclslist` is
/// emitted as two consecutive [`ObjcClass`] rows: the instance
/// class, then the metaclass (with [`Self::is_meta`] returning
/// `true`).
#[derive(Clone)]
pub struct ObjcClass<'a, 'p> {
    pub(crate) rt: &'p ObjcRuntime<'a>,
    pub(crate) address: u64,
    pub(crate) isa: u64,
    pub(crate) superclass: u64,
    pub(crate) bits: u64,
    pub(crate) is_meta: bool,
}

impl<'a, 'p> ObjcClass<'a, 'p> {
    /// VM address of the `class_t` struct.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// `class_t.isa` after PAC strip (instance class → metaclass).
    pub fn isa(&self) -> u64 {
        self.isa
    }

    /// `class_t.superclass` after PAC strip. `0` for root classes.
    /// Foreign superclasses (resolved by dyld through chained-fixup
    /// binds) appear here as `0`; query [`Self::superclass_name`]
    /// for the resolved name.
    pub fn superclass_address(&self) -> u64 {
        self.superclass
    }

    /// Best-effort superclass name — `Some(name)` when the
    /// superclass pointer resolves in this image (a class with a
    /// matching `class_t` VA), or when the slot is a chained-fixup
    /// bind to `_OBJC_CLASS_$_<name>` / `_OBJC_METACLASS_$_<name>`.
    /// `None` for root classes, opaque external superclasses, or
    /// unresolvable slots.
    pub fn superclass_name(&self) -> Option<&'a str> {
        if self.superclass != 0 {
            if let Some(decoded) = decode_class_name(self.rt, self.superclass) {
                return Some(decoded);
            }
        }
        // Cross-image bind: the superclass slot lives at
        // (class_t address + 8).
        let super_slot_va = self.address.checked_add(8)?;
        if let Some((sym, _)) = self.rt.binds_by_va.get(&super_slot_va) {
            return Some(strip_objc_symbol_prefix(sym));
        }
        None
    }

    /// Raw `class_data_bits_t.bits` — `class_ro_t` pointer plus
    /// FAST_*_FLAGS in the low 3 bits.
    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// FAST_*_FLAGS bits — the low 3 bits of [`Self::bits`].
    pub fn fast_flags(&self) -> u64 {
        self.bits & FAST_FLAGS_MASK
    }

    /// `true` when the class carries either Swift fast-flag
    /// (`FAST_IS_SWIFT_LEGACY` or `FAST_IS_SWIFT_STABLE`) — i.e.
    /// the class is paired with a Swift type metadata record.
    pub fn is_swift(&self) -> bool {
        (self.fast_flags() & (FAST_IS_SWIFT_LEGACY | FAST_IS_SWIFT_STABLE)) != 0
    }

    /// `true` when `FAST_HAS_DEFAULT_RR` is set.
    pub fn has_default_rr(&self) -> bool {
        (self.fast_flags() & FAST_HAS_DEFAULT_RR) != 0
    }

    /// `true` when this row represents the metaclass twin paired
    /// with an instance class. The metaclass is emitted immediately
    /// after its instance class in the [`ClassIter`] sequence.
    pub fn is_meta(&self) -> bool {
        self.is_meta
    }

    /// Decoded `class_ro_t`. `None` when the masked `bits` pointer
    /// fails to resolve through the segment table (e.g. corrupt
    /// input).
    pub fn ro(&self) -> Option<ClassRo<'a, 'p>> {
        let ro_va = mask_class_ro_pointer(self.rt, self.bits)?;
        decode_class_ro(self.rt, ro_va)
    }
}

impl core::fmt::Debug for ObjcClass<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjcClass")
            .field("address", &format_args!("0x{:x}", self.address))
            .field("is_meta", &self.is_meta)
            .field("isa", &format_args!("0x{:x}", self.isa))
            .field("superclass", &format_args!("0x{:x}", self.superclass))
            .field("bits", &format_args!("0x{:x}", self.bits))
            .field("is_swift", &self.is_swift())
            .field("name", &self.ro().map(|r| r.name).unwrap_or("?"))
            .finish()
    }
}

/// Decoded `class_ro_t` — the *read-only* per-class metadata blob
/// the Obj-C runtime ingests at first message.
///
/// `class_ro_t` is the immutable static side of the class
/// representation. The instance / metaclass `class_t` carries a
/// pointer to it through `bits & FAST_DATA_MASK`; once the runtime
/// realises the class, that pointer is replaced with a mutable
/// `class_rw_t` that wraps the original `ro` plus the per-class
/// dispatch caches. Static analysis only ever sees the `ro` form.
///
/// Cite: `objc4/runtime/objc-runtime-new.h:1598-1664`
/// (`class_ro_t`). On-disk LP64 layout (72 bytes through
/// `baseProperties`) is documented at the top of this module.
///
/// All trailing pointers are PAC-stripped and resolved through the
/// segment table; `&'a str` references (e.g. [`name`](Self::name))
/// borrow directly from `__TEXT,__objc_classname` rather than
/// allocating.
#[derive(Clone)]
pub struct ClassRo<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    address: u64,
    flags: RoFlags,
    instance_start: u32,
    instance_size: u32,
    name: &'a str,
    base_methods_va: u64,
    base_protocols_va: u64,
    ivars_va: u64,
    base_properties_va: u64,
    weak_ivar_layout_va: u64,
    ivar_layout_va: u64,
}

impl<'a, 'p> ClassRo<'a, 'p> {
    /// VM address of the `class_ro_t` struct.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// `class_ro_t.flags` (`RO_*` bits).
    pub fn flags(&self) -> RoFlags {
        self.flags
    }

    /// `instanceStart` — offset where this class's ivars begin in
    /// the instance.
    pub fn instance_start(&self) -> u32 {
        self.instance_start
    }

    /// `instanceSize` — total instance size in bytes.
    pub fn instance_size(&self) -> u32 {
        self.instance_size
    }

    /// Class name (NUL-terminated UTF-8 from `__TEXT,__objc_classname`).
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// `RO_META` — this `class_ro_t` belongs to a metaclass.
    pub fn is_meta(&self) -> bool {
        self.flags.contains(RoFlags::META)
    }

    /// `RO_ROOT`.
    pub fn is_root(&self) -> bool {
        self.flags.contains(RoFlags::ROOT)
    }

    /// `RO_HAS_CXX_STRUCTORS`.
    pub fn has_cxx_structors(&self) -> bool {
        self.flags.contains(RoFlags::HAS_CXX_STRUCTORS)
    }

    /// `RO_IS_ARC`.
    pub fn is_arc(&self) -> bool {
        self.flags.contains(RoFlags::IS_ARC)
    }

    /// `RO_HAS_SWIFT_INITIALIZER`.
    pub fn has_swift_initializer(&self) -> bool {
        self.flags.contains(RoFlags::HAS_SWIFT_INITIALIZER)
    }

    /// `RO_EXCEPTION`.
    pub fn is_exception(&self) -> bool {
        self.flags.contains(RoFlags::EXCEPTION)
    }

    /// VM address of the `ivarLayout` field (or `nonMetaclass`
    /// owning-class pointer when [`Self::is_meta`]).
    pub fn ivar_layout_address(&self) -> u64 {
        self.ivar_layout_va
    }

    /// VM address of the `weakIvarLayout` field (LP64 only).
    pub fn weak_ivar_layout_address(&self) -> u64 {
        self.weak_ivar_layout_va
    }

    /// Methods defined by this class (instance methods for
    /// non-meta, class methods for the metaclass twin).
    pub fn methods(&self) -> MethodIter<'a, 'p> {
        method_list_iter(self.rt, self.base_methods_va)
    }

    /// Ivars defined by this class.
    pub fn ivars(&self) -> IvarIter<'a, 'p> {
        ivar_list_iter(self.rt, self.ivars_va)
    }

    /// Properties defined by this class.
    pub fn properties(&self) -> PropertyIter<'a, 'p> {
        property_list_iter(self.rt, self.base_properties_va)
    }

    /// Names of protocols this class declares conformance to.
    /// Resolves through in-image protocol descriptors and
    /// chained-fixup binds.
    pub fn protocols(&self) -> ProtocolNameIter<'a, 'p> {
        protocol_name_iter(self.rt, self.base_protocols_va)
    }
}

impl core::fmt::Debug for ClassRo<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClassRo")
            .field("name", &self.name)
            .field("flags", &self.flags)
            .field("instance_start", &self.instance_start)
            .field("instance_size", &self.instance_size)
            .finish()
    }
}

/// Mask the `class_ro_t` pointer out of a `class_data_bits_t.bits`
/// word. Tries the wide arm64e mask first and falls back to the
/// standard 64-bit mask if the wide result fails to resolve through
/// the segment table.
///
/// Per the Obj-C masking ground rules.
fn mask_class_ro_pointer(rt: &ObjcRuntime<'_>, bits: u64) -> Option<u64> {
    let candidate_wide = bits & FAST_DATA_MASK_ARM64E;
    if candidate_wide != 0 && rt.vm_to_file_offset(candidate_wide).is_some() {
        return Some(candidate_wide);
    }
    let candidate_std = bits & FAST_DATA_MASK_64;
    if candidate_std != 0 && rt.vm_to_file_offset(candidate_std).is_some() {
        return Some(candidate_std);
    }
    // If neither resolves cleanly, fall back to the standard mask.
    // Higher-level decoders take a `None` from `read_bytes` as a
    // skip-with-tracing signal.
    if candidate_std != 0 {
        Some(candidate_std)
    } else {
        None
    }
}

fn decode_class_ro<'a, 'p>(
    rt: &'p ObjcRuntime<'a>,
    ro_va: u64,
) -> Option<ClassRo<'a, 'p>> {
    let bytes = rt.read_bytes(ro_va, CLASS_RO_T_SIZE)?;

    let raw_flags = read_u32_le_at(bytes, 0)?;
    let flags = RoFlags::from_bits_retain(raw_flags);
    let instance_start = read_u32_le_at(bytes, 4)?;
    let instance_size = read_u32_le_at(bytes, 8)?;
    // bytes 12..16 are reserved (LP64 padding).
    // Per-slot VAs for resolve_pointer (chained-fixup or legacy).
    let ivar_layout_va = rt.resolve_pointer(ro_va.checked_add(16)?).unwrap_or(0);
    let name_va = rt.resolve_pointer(ro_va.checked_add(24)?)?;
    let base_methods_va = rt.resolve_pointer(ro_va.checked_add(32)?).unwrap_or(0);
    let base_protocols_va = rt.resolve_pointer(ro_va.checked_add(40)?).unwrap_or(0);
    let ivars_va = rt.resolve_pointer(ro_va.checked_add(48)?).unwrap_or(0);
    let weak_ivar_layout_va = rt.resolve_pointer(ro_va.checked_add(56)?).unwrap_or(0);
    let base_properties_va = rt.resolve_pointer(ro_va.checked_add(64)?).unwrap_or(0);

    let name = rt.read_cstr(name_va)?;

    Some(ClassRo {
        rt,
        address: ro_va,
        flags,
        instance_start,
        instance_size,
        name,
        base_methods_va,
        base_protocols_va,
        ivars_va,
        base_properties_va,
        weak_ivar_layout_va,
        ivar_layout_va,
    })
}

/// Iterator over every Obj-C class in the image.
///
/// Walks `__objc_classlist` first, then `__objc_nlclslist`,
/// de-duplicating by `class_t` VA. For each instance class the
/// iterator yields two consecutive rows: the instance class, then
/// its metaclass (carrying [`ObjcClass::is_meta`] = `true`).
pub struct ClassIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    class_addrs: std::vec::IntoIter<u64>,
    pending_meta: Option<u64>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> ClassIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        // De-dup by class_t VA. Lazy list first; non-lazy is a
        // strict subset on conforming compilers.
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut ordered: Vec<u64> = Vec::new();
        for sec in [rt.class_list, rt.nlclslist].iter().flatten() {
            let mut off = 0usize;
            while off.checked_add(8).is_some_and(|end| end <= sec.body.len()) {
                let slot_va = sec.vmaddr.wrapping_add(off as u64);
                let va = rt.resolve_pointer(slot_va).unwrap_or(0);
                off = match off.checked_add(8) {
                    Some(v) => v,
                    None => break,
                };
                if va == 0 {
                    continue;
                }
                if seen.insert(va) {
                    ordered.push(va);
                }
            }
        }
        Self {
            rt,
            class_addrs: ordered.into_iter(),
            pending_meta: None,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for ClassIter<'a, 'p> {
    type Item = ObjcClass<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(meta_va) = self.pending_meta.take() {
            if let Some(c) = decode_class(self.rt, meta_va, true) {
                return Some(c);
            }
            // If the metaclass decode fails fall through to the
            // next instance class — we deliberately do NOT recurse
            // through the metaclass's own `isa` (root metaclasses
            // self-loop, which would make iteration non-terminating).
        }

        loop {
            let va = self.class_addrs.next()?;
            let Some(class) = decode_class(self.rt, va, false) else {
                continue;
            };
            // Queue the metaclass to emit on the next call.
            // `class_t.isa` after PAC strip is the metaclass VA.
            // Skip if it points back at the same address (root
            // class self-isa) or fails to resolve.
            if class.isa != 0 && class.isa != va {
                self.pending_meta = Some(class.isa);
            }
            return Some(class);
        }
    }
}

pub(crate) fn decode_class<'a, 'p>(
    rt: &'p ObjcRuntime<'a>,
    class_va: u64,
    is_meta: bool,
) -> Option<ObjcClass<'a, 'p>> {
    // Sanity: every byte of the class_t must lie within a mapped
    // segment.
    rt.read_bytes(class_va, CLASS_T_SIZE)?;

    let isa_slot_va = class_va;
    let super_slot_va = class_va.checked_add(8)?;
    let bits_slot_va = class_va.checked_add(CLASS_T_BITS_OFFSET as u64)?;

    let isa = rt.resolve_pointer(isa_slot_va).unwrap_or(0);
    let superclass = rt.resolve_pointer(super_slot_va).unwrap_or(0);

    // For class_t.bits we need both:
    //
    // 1. The canonical class_ro_t pointer — comes from the rebase
    //    table on chained-fixup binaries (the chain encoding's
    //    target field is already FAST_DATA_MASK-aligned and
    //    PAC-stripped); on legacy binaries we PAC-strip the raw
    //    slot and apply FAST_DATA_MASK ourselves.
    //
    // 2. The FAST_*_FLAGS in the low 3 bits — these are stored
    //    on disk inside the slot itself even when the rest of the
    //    word is chain-format. We recover them from the raw u64
    //    that was written to disk.
    let raw_bits = rt.read_u64(bits_slot_va)?;
    let fast_flags = raw_bits & FAST_FLAGS_MASK;
    let class_ro_va = if let Some(&target) = rt.rebases_by_va.get(&bits_slot_va) {
        target
    } else {
        mask_class_ro_pointer(rt, raw_bits).unwrap_or(0)
    };
    // Re-stitch into a single `bits` word: high bits zeroed (we do
    // not surface PAC envelope bits), middle = class_ro_va, low
    // 3 bits = fast_flags. Keeps `ObjcClass::bits()` ergonomic.
    let bits = (class_ro_va & !FAST_FLAGS_MASK) | fast_flags;

    Some(ObjcClass {
        rt,
        address: class_va,
        isa,
        superclass,
        bits,
        is_meta,
    })
}

/// Best-effort name lookup for an in-image class.
///
/// Walks the class's `bits → class_ro_t.name` indirection. Returns
/// `None` when `class_va` doesn't decode as a valid `class_t` or
/// when the name pointer fails to resolve.
pub(crate) fn decode_class_name<'a>(
    rt: &ObjcRuntime<'a>,
    class_va: u64,
) -> Option<&'a str> {
    rt.read_bytes(class_va, CLASS_T_SIZE)?;
    let bits_slot_va = class_va.checked_add(CLASS_T_BITS_OFFSET as u64)?;
    let class_ro_va = if let Some(&target) = rt.rebases_by_va.get(&bits_slot_va) {
        target
    } else {
        let raw_bits = rt.read_u64(bits_slot_va)?;
        mask_class_ro_pointer(rt, raw_bits)?
    };
    let name_slot_va = class_ro_va.checked_add(24)?;
    let name_va = rt.resolve_pointer(name_slot_va)?;
    rt.read_cstr(name_va)
}
