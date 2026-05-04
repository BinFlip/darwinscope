//! Cross-section reference walkers.
//!
//! ObjC images carry four reference sections that each hold an
//! array of 64-bit pointer slots:
//!
//! - `__objc_selrefs` — selectors referenced at runtime. Each slot
//!   resolves (after PAC strip) to a NUL-terminated UTF-8 string in
//!   `__TEXT,__objc_methname`.
//! - `__objc_classrefs` — class references (e.g. `[NSObject foo]`).
//!   Resolves to a `class_t` in this image, or to a chained-fixup
//!   bind for foreign classes (`_OBJC_CLASS_$_<name>`).
//! - `__objc_superrefs` — super-class references for messaging
//!   patterns; same resolution semantics as `__objc_classrefs`.
//! - `__objc_protorefs` — protocol references (i.e. `@protocol(X)`).
//!   Resolves to a `protocol_t` in this image, or to a chained-fixup
//!   bind for foreign protocols (`_OBJC_PROTOCOL_$_<name>` /
//!   `_OBJC_LABEL_PROTOCOL_$_<name>`).

use std::marker::PhantomData;

use crate::objc::{
    ObjcRuntime, class::decode_class_name, protocol::decode_protocol, strip_objc_symbol_prefix,
};

/// Resolution of a single reference-section slot.
#[derive(Debug, Clone, Copy)]
pub enum RefTarget<'a> {
    /// The slot resolved to an in-image class / protocol.
    Local {
        /// VM address of the target struct (`class_t` /
        /// `protocol_t`).
        address: u64,
        /// Best-effort name — `Some` when the target struct's name
        /// pointer resolves; `None` for opaque locals.
        name: Option<&'a str>,
    },
    /// The slot is a chained-fixup bind to a foreign symbol.
    External {
        /// Symbol name with the canonical `_OBJC_CLASS_$_` /
        /// `_OBJC_METACLASS_$_` / `_OBJC_PROTOCOL_$_` /
        /// `_OBJC_LABEL_PROTOCOL_$_` prefix stripped.
        name: &'a str,
        /// Dylib path the symbol resolves into.
        dylib: &'a str,
    },
    /// Slot didn't resolve and there's no matching bind site.
    /// Surfaced so callers can record the unresolved address rather
    /// than silently dropping the row.
    Unresolved {
        /// VM address of the slot whose contents failed to resolve.
        slot_address: u64,
        /// Raw u64 value at the slot (post-PAC-strip).
        target: u64,
    },
}

/// Iterator over `__objc_selrefs` — yields each referenced
/// selector C-string in slot order.
pub struct SelRefIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    cursor: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> SelRefIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            cursor: 0,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for SelRefIter<'a, 'p> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        let sec = self.rt.sel_refs?;
        loop {
            if self.cursor.checked_add(8)? > sec.body.len() {
                return None;
            }
            let slot_va = sec.vmaddr.wrapping_add(self.cursor as u64);
            self.cursor = self.cursor.checked_add(8)?;
            let sel_va = self.rt.resolve_pointer(slot_va).unwrap_or(0);
            if sel_va == 0 {
                continue;
            }
            if let Some(s) = self.rt.read_cstr(sel_va) {
                return Some(s);
            }
        }
    }
}

/// Internal helper macro builder — generate the three pointer-set
/// iterators (`__objc_classrefs`, `__objc_superrefs`,
/// `__objc_protorefs`) which only differ in the section they read
/// from and how an in-image target is resolved (class vs protocol
/// name lookup).
fn next_ref_target<'a>(
    rt: &ObjcRuntime<'a>,
    sec_body: &[u8],
    sec_vmaddr: u64,
    cursor: &mut usize,
    resolve_local: impl Fn(&ObjcRuntime<'a>, u64) -> Option<&'a str>,
) -> Option<RefTarget<'a>> {
    if cursor.checked_add(8)? > sec_body.len() {
        return None;
    }
    let slot_offset = *cursor as u64;
    *cursor = cursor.checked_add(8)?;
    let slot_va = sec_vmaddr.wrapping_add(slot_offset);
    let target = rt.resolve_pointer(slot_va).unwrap_or(0);

    // Local resolution first.
    if target != 0 {
        if let Some(name) = resolve_local(rt, target) {
            return Some(RefTarget::Local {
                address: target,
                name: Some(name),
            });
        }
        // Local target VA exists but name resolution failed — return
        // it as Local-with-no-name rather than falling through to
        // external (we know it's in this image because the VA is
        // non-zero and not a bind site).
        if !rt.binds_by_va.contains_key(&slot_va) && rt.vm_to_file_offset(target).is_some() {
            return Some(RefTarget::Local {
                address: target,
                name: None,
            });
        }
    }

    if let Some((sym, dylib)) = rt.binds_by_va.get(&slot_va) {
        return Some(RefTarget::External {
            name: strip_objc_symbol_prefix(sym),
            dylib,
        });
    }

    Some(RefTarget::Unresolved {
        slot_address: slot_va,
        target,
    })
}

/// Iterator over `__objc_classrefs`.
pub struct ClassRefIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    cursor: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> ClassRefIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            cursor: 0,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for ClassRefIter<'a, 'p> {
    type Item = RefTarget<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let sec = self.rt.class_refs?;
        next_ref_target(self.rt, sec.body, sec.vmaddr, &mut self.cursor, |rt, va| {
            decode_class_name(rt, va)
        })
    }
}

/// Iterator over `__objc_superrefs`.
pub struct SuperRefIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    cursor: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> SuperRefIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            cursor: 0,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for SuperRefIter<'a, 'p> {
    type Item = RefTarget<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let sec = self.rt.super_refs?;
        next_ref_target(self.rt, sec.body, sec.vmaddr, &mut self.cursor, |rt, va| {
            decode_class_name(rt, va)
        })
    }
}

/// Iterator over `__objc_protorefs`.
pub struct ProtoRefIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    cursor: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> ProtoRefIter<'a, 'p> {
    pub(crate) fn new(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            cursor: 0,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for ProtoRefIter<'a, 'p> {
    type Item = RefTarget<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let sec = self.rt.proto_refs?;
        next_ref_target(self.rt, sec.body, sec.vmaddr, &mut self.cursor, |rt, va| {
            decode_protocol(rt, va).map(|p| p.name())
        })
    }
}
