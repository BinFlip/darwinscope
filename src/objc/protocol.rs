//! Protocol descriptor walker.
//!
//! Cite: `objc4/runtime/objc-runtime-new.h:1516-1566`
//! (`protocol_t`) and `RESEARCH.md` §"`protocol_t`" (line 1556).
//!
//! `protocol_t` on disk (LP64), with trailing fields gated by the
//! `size` field via the `HAS_FIELD` predicate
//! (`objc-runtime-new.h:1545`):
//!
//! ```text
//! isa                        u64 ptr   @ 0   (often null on disk)
//! mangledName                u64 ptr   @ 8   (NUL-terminated UTF-8)
//! protocols                  u64 ptr   @ 16  -> protocol_list_t
//! instanceMethods            u64 ptr   @ 24  -> method_list_t
//! classMethods               u64 ptr   @ 32  -> method_list_t
//! optionalInstanceMethods    u64 ptr   @ 40
//! optionalClassMethods       u64 ptr   @ 48
//! instanceProperties         u64 ptr   @ 56  -> property_list_t
//! size                       u32       @ 64
//! flags                      u32       @ 68
//! _extendedMethodTypes       u64 ptr   @ 72  (gated)
//! _demangledName             u64 ptr   @ 80  (gated)
//! _classProperties           u64 ptr   @ 88  (gated)
//! ```

use std::marker::PhantomData;

use crate::{
    objc::{
        ObjcRuntime,
        method::{MethodIter, method_list_iter},
        property::{PropertyIter, property_list_iter},
        strip_objc_symbol_prefix,
    },
    util::{read_u32_le_at, read_u64_le_at},
};

/// Minimum on-disk size of a `protocol_t` — through `flags`.
const PROTOCOL_BASE_SIZE: usize = 72;

/// Offset of the `_extendedMethodTypes` trailing field.
const PROTOCOL_FIELD_EXTENDED_METHOD_TYPES_OFFSET: u32 = 72;
/// Offset of the `_demangledName` trailing field.
const PROTOCOL_FIELD_DEMANGLED_NAME_OFFSET: u32 = 80;
/// Offset of the `_classProperties` trailing field.
const PROTOCOL_FIELD_CLASS_PROPERTIES_OFFSET: u32 = 88;

/// One Obj-C protocol descriptor (`protocol_t`).
///
/// Cite: `objc4/runtime/objc-runtime-new.h:1516-1566`. Each protocol
/// declares a set of method requirements (instance and class, both
/// required and optional) plus a list of inherited protocols and
/// instance/class properties. The runtime stores them in
/// `__objc_protolist` and references them from class
/// `class_ro_t.baseProtocols` lists.
///
/// Trailing fields (`_extendedMethodTypes`, `_demangledName`,
/// `_classProperties`) are gated on the `size` word — older
/// compilers may emit a shorter struct that ends at `flags`. The
/// view exposes them via `Option`-returning accessors so consumers
/// do not have to special-case the size check.
#[derive(Debug, Clone)]
pub struct ObjcProtocol<'a, 'p> {
    pub(crate) rt: &'p ObjcRuntime<'a>,
    pub(crate) address: u64,

    pub(crate) name: &'a str,
    pub(crate) instance_methods_va: u64,
    pub(crate) class_methods_va: u64,
    pub(crate) optional_instance_methods_va: u64,
    pub(crate) optional_class_methods_va: u64,
    pub(crate) instance_properties_va: u64,
    pub(crate) class_properties_va: Option<u64>,
    pub(crate) protocols_va: u64,
    pub(crate) size: u32,
    pub(crate) flags: u32,
}

impl<'a, 'p> ObjcProtocol<'a, 'p> {
    /// VM address of the `protocol_t` struct.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Protocol name (mangled, as stored on disk).
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// `protocol_t.size` — gates the trailing fields.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// `protocol_t.flags`.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Required instance methods.
    pub fn instance_methods(&self) -> MethodIter<'a, 'p> {
        method_list_iter(self.rt, self.instance_methods_va)
    }

    /// Required class methods.
    pub fn class_methods(&self) -> MethodIter<'a, 'p> {
        method_list_iter(self.rt, self.class_methods_va)
    }

    /// Optional (`@optional`) instance methods.
    pub fn optional_instance_methods(&self) -> MethodIter<'a, 'p> {
        method_list_iter(self.rt, self.optional_instance_methods_va)
    }

    /// Optional (`@optional`) class methods.
    pub fn optional_class_methods(&self) -> MethodIter<'a, 'p> {
        method_list_iter(self.rt, self.optional_class_methods_va)
    }

    /// Instance properties declared on the protocol.
    pub fn instance_properties(&self) -> PropertyIter<'a, 'p> {
        property_list_iter(self.rt, self.instance_properties_va)
    }

    /// Class properties — only meaningful when [`Self::size`] is
    /// large enough to include the trailing field. Returns an empty
    /// iterator when the field is not present.
    pub fn class_properties(&self) -> PropertyIter<'a, 'p> {
        match self.class_properties_va {
            Some(va) => property_list_iter(self.rt, va),
            None => PropertyIter::empty(self.rt),
        }
    }

    /// Iterator over names of inherited protocols.
    pub fn protocols(&self) -> ProtocolNameIter<'a, 'p> {
        protocol_name_iter(self.rt, self.protocols_va)
    }
}

/// Iterator over [`ObjcProtocol`]s in `__objc_protolist` order.
pub struct ProtocolIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    cursor: u64,
    end: u64,
}

impl<'a, 'p> ProtocolIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        let (cursor, end) = match rt.proto_list {
            Some(s) => (0u64, s.body.len() as u64),
            None => (0u64, 0u64),
        };
        Self { rt, cursor, end }
    }
}

impl<'a, 'p> Iterator for ProtocolIter<'a, 'p> {
    type Item = ObjcProtocol<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let proto_list = self.rt.proto_list?;
        loop {
            // Each entry in `__objc_protolist` is a u64 pointer
            // slot (PAC-signed on arm64e legacy or chain-format
            // on chained-fixup binaries).
            if self.cursor.checked_add(8)? > self.end {
                return None;
            }
            let slot_va = proto_list.vmaddr.wrapping_add(self.cursor);
            let slot_idx = self.cursor / 8;
            self.cursor = self.cursor.checked_add(8)?;
            let proto_va = self.rt.resolve_pointer(slot_va).unwrap_or(0);
            if proto_va == 0 {
                continue;
            }
            if let Some(p) = decode_protocol(self.rt, proto_va) {
                return Some(p);
            }
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::objc: protocol at 0x{:x} (slot idx={}) skipped — decode failed",
                proto_va,
                slot_idx,
            );
            #[cfg(not(feature = "tracing"))]
            let _ = slot_idx;
        }
    }
}

pub(crate) fn decode_protocol<'a, 'p>(
    rt: &'p ObjcRuntime<'a>,
    proto_va: u64,
) -> Option<ObjcProtocol<'a, 'p>> {
    let bytes = rt.read_bytes(proto_va, PROTOCOL_BASE_SIZE)?;
    // Slot 0 is `isa` — typically null on disk; we don't surface
    // it but reading the bytes confirms the struct fits.
    let name_va = rt.resolve_pointer(proto_va.checked_add(8)?)?;
    let protocols_va = rt.resolve_pointer(proto_va.checked_add(16)?).unwrap_or(0);
    let instance_methods_va = rt.resolve_pointer(proto_va.checked_add(24)?).unwrap_or(0);
    let class_methods_va = rt.resolve_pointer(proto_va.checked_add(32)?).unwrap_or(0);
    let optional_instance_methods_va = rt.resolve_pointer(proto_va.checked_add(40)?).unwrap_or(0);
    let optional_class_methods_va = rt.resolve_pointer(proto_va.checked_add(48)?).unwrap_or(0);
    let instance_properties_va = rt.resolve_pointer(proto_va.checked_add(56)?).unwrap_or(0);
    let size = read_u32_le_at(bytes, 64)?;
    let flags = read_u32_le_at(bytes, 68)?;

    let name = rt.read_cstr(name_va)?;

    // Trailing fields per `HAS_FIELD` predicate
    // (`objc-runtime-new.h:1545`): a field is present iff
    // `offsetof(field) + sizeof(field) <= size`. We require the
    // full pointer-sized slot (8 bytes) to exist on disk.
    let class_properties_va = if size as usize
        >= (PROTOCOL_FIELD_CLASS_PROPERTIES_OFFSET as usize).saturating_add(8)
    {
        let slot_va = proto_va.checked_add(u64::from(PROTOCOL_FIELD_CLASS_PROPERTIES_OFFSET))?;
        rt.read_bytes(slot_va, 8)?;
        let resolved = rt.resolve_pointer(slot_va).unwrap_or(0);
        if resolved == 0 { None } else { Some(resolved) }
    } else {
        None
    };

    // _extendedMethodTypes / _demangledName trailing fields are
    // currently surfaced through `size`/`flags`; explicit accessors
    // can be added later without an API break. The offset constants
    // are defined here so that future PRs don't have to re-derive
    // them. Reference them so the compiler does not flag them as
    // unused.
    let _ = PROTOCOL_FIELD_EXTENDED_METHOD_TYPES_OFFSET;
    let _ = PROTOCOL_FIELD_DEMANGLED_NAME_OFFSET;

    Some(ObjcProtocol {
        rt,
        address: proto_va,
        name,
        instance_methods_va,
        class_methods_va,
        optional_instance_methods_va,
        optional_class_methods_va,
        instance_properties_va,
        class_properties_va,
        protocols_va,
        size,
        flags,
    })
}

/// Iterator over protocol *names* referenced by a `protocol_list_t`.
///
/// `protocol_list_t` layout (cite
/// `objc4/runtime/objc-runtime-new.h:1462-1488`):
///
/// ```text
/// count   uintptr_t (u64 on LP64)   @ 0
/// list[]  protocol_ref_t[]          @ 8   each entry is u64
/// ```
///
/// Names are resolved by following each pointer to its
/// `protocol_t.mangledName`. Foreign-protocol pointers (e.g. ones
/// satisfied by a chained-fixup bind) yield the bind name with the
/// canonical `_OBJC_PROTOCOL_$_` / `_OBJC_LABEL_PROTOCOL_$_` prefix
/// stripped.
pub struct ProtocolNameIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    list_base: Option<u64>,
    count: u64,
    cursor: u64,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> ProtocolNameIter<'a, 'p> {
    pub(crate) fn empty(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            list_base: None,
            count: 0,
            cursor: 0,
            _phantom: PhantomData,
        }
    }
}

pub(crate) fn protocol_name_iter<'a, 'p>(
    rt: &'p ObjcRuntime<'a>,
    list_va: u64,
) -> ProtocolNameIter<'a, 'p> {
    if list_va == 0 || (list_va & 0x1) != 0 {
        return ProtocolNameIter::empty(rt);
    }
    let Some(header) = rt.read_bytes(list_va, 8) else {
        return ProtocolNameIter::empty(rt);
    };
    let Some(count) = read_u64_le_at(header, 0) else {
        return ProtocolNameIter::empty(rt);
    };
    // Cap iteration at a sane upper bound to avoid runaway
    // allocations on malformed `count` values.
    let count = count.min(1 << 20);
    let Some(base) = list_va.checked_add(8) else {
        return ProtocolNameIter::empty(rt);
    };

    ProtocolNameIter {
        rt,
        list_base: Some(base),
        count,
        cursor: 0,
        _phantom: PhantomData,
    }
}

impl<'a, 'p> Iterator for ProtocolNameIter<'a, 'p> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        let base = self.list_base?;
        loop {
            if self.cursor >= self.count {
                return None;
            }
            let i = self.cursor;
            self.cursor = self.cursor.checked_add(1)?;
            let slot_va = base.checked_add(i.checked_mul(8)?)?;
            let proto_va = self.rt.resolve_pointer(slot_va).unwrap_or(0);
            // Try local resolution first.
            if proto_va != 0
                && let Some(p) = decode_protocol(self.rt, proto_va)
            {
                return Some(p.name());
            }
            // Cross-image bind?
            if let Some((sym, _)) = self.rt.binds_by_va.get(&slot_va) {
                return Some(strip_objc_symbol_prefix(sym));
            }
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::objc: protocol-list slot at 0x{:x} unresolved",
                slot_va
            );
        }
    }
}
