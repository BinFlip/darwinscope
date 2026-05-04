//! Category walker.
//!
//! Cite: `objc4/runtime/objc-runtime-new.h:3196-3217`
//! (`category_t`) and `RESEARCH.md` §"`category_t`" (line 1604).
//!
//! `category_t` on disk (LP64):
//!
//! ```text
//! name                u64 ptr   @ 0    -> __TEXT,__objc_classname
//! cls                 u64 ptr   @ 8    -> class_t (in-image) or
//!                                         chained-fixup bind to
//!                                         _OBJC_CLASS_$_<name>
//! instanceMethods     u64 ptr   @ 16
//! classMethods        u64 ptr   @ 24
//! protocols           u64 ptr   @ 32
//! instanceProperties  u64 ptr   @ 40
//! _classProperties    u64 ptr   @ 48   conditional on
//!                                       OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES
//! ```
//!
//! Walks both `__objc_catlist` (lazy) and `__objc_nlcatlist`
//! (non-lazy), de-duped by category VA — modern toolchains emit
//! the same category record into both sections under the
//! "non-lazy means it must be eagerly attached" rule, but we never
//! emit a duplicate row.

use std::{collections::HashSet, marker::PhantomData};

use crate::objc::{
    class::decode_class_name,
    method::{method_list_iter, MethodIter},
    property::{property_list_iter, PropertyIter},
    protocol::{protocol_name_iter, ProtocolNameIter},
    strip_objc_symbol_prefix, ObjcRuntime,
};

const CATEGORY_BASE_SIZE: usize = 48;
const CATEGORY_WITH_CLASS_PROPS_SIZE: usize = 56;

/// One Obj-C category (`category_t`).
///
/// Cite: `objc4/runtime/objc-runtime-new.h:3196-3217`. A category
/// declares additional methods, protocols, and properties that the
/// runtime grafts onto an existing class at image load time. Unlike
/// a subclass, a category modifies the *target* class itself —
/// callers that already hold instances see the new methods
/// immediately. The host class can live in any image; cross-image
/// categories use a chained-fixup bind on the `cls` slot, which
/// [`Self::class_name`] resolves transparently.
///
/// On-disk layout is documented at the top of this module. The
/// trailing `_classProperties` field is gated on the image's
/// `OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES` flag and exposed as
/// `Option`-returning accessors so consumers do not have to special
/// case the size check.
pub struct ObjcCategory<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    address: u64,
    name: &'a str,
    class_va: u64,
    /// VA of the `cls` slot itself, used for chained-fixup bind
    /// lookup (foreign-class categories).
    cls_slot_va: u64,
    instance_methods_va: u64,
    class_methods_va: u64,
    protocols_va: u64,
    instance_properties_va: u64,
    class_properties_va: Option<u64>,
}

impl<'a, 'p> ObjcCategory<'a, 'p> {
    /// VM address of the `category_t` struct.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Category name (e.g. `"Talkative"` for `@interface
    /// Greeter (Talkative)`).
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// VM address of the host class (the `cls` slot post-PAC-strip).
    /// `0` when the class lives in another image and is bound by
    /// dyld at load time.
    pub fn class_address(&self) -> u64 {
        self.class_va
    }

    /// Resolved host-class name. Tries:
    ///
    /// 1. In-image lookup — if `cls` resolves to a `class_t` whose
    ///    `class_ro_t.name` is reachable, return that name.
    /// 2. Chained-fixup bind on the `cls` slot — return the bind
    ///    symbol's name with the `_OBJC_CLASS_$_` prefix stripped.
    ///
    /// Returns `None` when both fail (heavily stripped / corrupt
    /// input).
    pub fn class_name(&self) -> Option<&'a str> {
        if self.class_va != 0 {
            if let Some(n) = decode_class_name(self.rt, self.class_va) {
                return Some(n);
            }
        }
        if let Some((sym, _)) = self.rt.binds_by_va.get(&self.cls_slot_va) {
            return Some(strip_objc_symbol_prefix(sym));
        }
        None
    }

    /// Instance-method additions.
    pub fn instance_methods(&self) -> MethodIter<'a, 'p> {
        method_list_iter(self.rt, self.instance_methods_va)
    }

    /// Class-method additions.
    pub fn class_methods(&self) -> MethodIter<'a, 'p> {
        method_list_iter(self.rt, self.class_methods_va)
    }

    /// Protocol-conformance additions.
    pub fn protocols(&self) -> ProtocolNameIter<'a, 'p> {
        protocol_name_iter(self.rt, self.protocols_va)
    }

    /// Instance-property additions.
    pub fn instance_properties(&self) -> PropertyIter<'a, 'p> {
        property_list_iter(self.rt, self.instance_properties_va)
    }

    /// Class-property additions. Empty when
    /// `OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES` is clear in
    /// `__objc_imageinfo.flags` — older toolchains do not emit this
    /// trailing field.
    pub fn class_properties(&self) -> PropertyIter<'a, 'p> {
        match self.class_properties_va {
            Some(va) => property_list_iter(self.rt, va),
            None => PropertyIter::empty(self.rt),
        }
    }
}

impl core::fmt::Debug for ObjcCategory<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjcCategory")
            .field("address", &format_args!("0x{:x}", self.address))
            .field("name", &self.name)
            .field("class_name", &self.class_name().unwrap_or("?"))
            .finish()
    }
}

/// Iterator over [`ObjcCategory`] rows.
pub struct CategoryIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    cat_addrs: std::vec::IntoIter<u64>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> CategoryIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        let mut seen: HashSet<u64> = HashSet::new();
        let mut ordered: Vec<u64> = Vec::new();
        for sec in [rt.cat_list, rt.nlcat_list].iter().flatten() {
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
            cat_addrs: ordered.into_iter(),
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for CategoryIter<'a, 'p> {
    type Item = ObjcCategory<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let va = self.cat_addrs.next()?;
            if let Some(c) = decode_category(self.rt, va) {
                return Some(c);
            }
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::objc: category at 0x{:x} skipped — decode failed",
                va
            );
        }
    }
}

fn decode_category<'a, 'p>(
    rt: &'p ObjcRuntime<'a>,
    cat_va: u64,
) -> Option<ObjcCategory<'a, 'p>> {
    let want_class_props = rt.image_info.has_category_class_properties();
    let want_size = if want_class_props {
        CATEGORY_WITH_CLASS_PROPS_SIZE
    } else {
        CATEGORY_BASE_SIZE
    };
    rt.read_bytes(cat_va, want_size)?;

    let name_va = rt.resolve_pointer(cat_va)?;
    let cls_slot_va = cat_va.checked_add(8)?;
    let class_va = rt.resolve_pointer(cls_slot_va).unwrap_or(0);
    let instance_methods_va = rt.resolve_pointer(cat_va.checked_add(16)?).unwrap_or(0);
    let class_methods_va = rt.resolve_pointer(cat_va.checked_add(24)?).unwrap_or(0);
    let protocols_va = rt.resolve_pointer(cat_va.checked_add(32)?).unwrap_or(0);
    let instance_properties_va = rt.resolve_pointer(cat_va.checked_add(40)?).unwrap_or(0);
    let class_properties_va = if want_class_props {
        let resolved = rt.resolve_pointer(cat_va.checked_add(48)?).unwrap_or(0);
        if resolved == 0 { None } else { Some(resolved) }
    } else {
        None
    };

    let name = rt.read_cstr(name_va)?;

    Some(ObjcCategory {
        rt,
        address: cat_va,
        name,
        class_va,
        cls_slot_va,
        instance_methods_va,
        class_methods_va,
        protocols_va,
        instance_properties_va,
        class_properties_va,
    })
}
