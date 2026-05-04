//! Method-list walker.
//!
//! Decodes both on-disk shapes the toolchain emits:
//!
//! - **Legacy** 24-byte format (`method_t`): three absolute u64
//!   pointers — `(SEL, types, IMP)`. Cite:
//!   `objc4/runtime/objc-runtime-new.h:914-973` and
//!   `RESEARCH.md` §"`method_t`" (line 1457).
//! - **Small** 12-byte format (`method_t::small`): three signed
//!   32-bit relative offsets. The selector slot indirects through
//!   `__objc_selrefs` unless
//!   `relativeMethodSelectorsAreDirectFlag` is set, in which case
//!   it points directly into `__objc_methname`. Cite:
//!   `objc4/runtime/objc-runtime-new.h:975-1037` and `RESEARCH.md`
//!   §"`method_t::small`" (line 1478).
//!
//! The walker fail-soft skips rows that fail to resolve a selector
//! string — partial enumerations are preferred to abort.

use crate::{
    objc::ObjcRuntime,
    ptrauth::strip_signature,
    util::{read_i32_le_at, read_u32_le_at, relative_pointer},
};

/// `method_list_t.entsizeAndFlags` flag mask.
///
/// Cite: `objc4/runtime/objc-runtime-new.h:1241` —
/// `entsize_list_tt<method_t, method_list_t, 0xffff0003, ...>`. Bits
/// in the mask are flags; bits *not* in the mask are the entry
/// size. So `entsize = entsizeAndFlags & 0x0000_fffc`.
const METHOD_LIST_FLAG_MASK: u32 = 0xffff_0003;

/// `smallMethodListFlag` — entries use the 12-byte relative-offset
/// layout. Cite: `objc4/runtime/objc-runtime-new.h:980`.
const SMALL_METHOD_LIST_FLAG: u32 = 0x8000_0000;

/// `relativeMethodSelectorsAreDirectFlag` — small `name` slot
/// points directly into `__objc_methname` (skipping the selref
/// indirection). Cite: `objc4/runtime/objc-runtime-new.h:982`.
const RELATIVE_METHOD_SELECTORS_ARE_DIRECT_FLAG: u32 = 0x4000_0000;

/// Which on-disk variant of `method_t` produced this row.
///
/// LLVM emits the 12-byte "small" form by default since Xcode 13;
/// older binaries (and some hand-rolled assemblers) keep using the
/// 24-byte legacy form. The runtime upgrades the small form into the
/// legacy shape lazily during class realization, but the on-disk
/// representation is fixed and observable to static analysis.
///
/// The `SmallIndirect` vs `SmallDirect` distinction matters because
/// only `SmallIndirect` requires the dynamic linker to resolve a
/// selref slot — the direct form references the selector string
/// pool directly and is cheaper to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    /// `method_t` (24 bytes / entry): three absolute 64-bit pointers
    /// `(SEL, types, IMP)`. Each pointer is PAC-signed on arm64e and
    /// chained-fixup-bound on modern binaries. Cite:
    /// `objc4/runtime/objc-runtime-new.h:914-973`.
    Legacy,
    /// `method_t::small` (12 bytes / entry) without
    /// `relativeMethodSelectorsAreDirectFlag` — the selector slot
    /// references a `__objc_selrefs` cell, which dyld then binds at
    /// load time to the canonical `SEL` value. Standard in modern
    /// release binaries: it lets the linker dedupe selectors across
    /// translation units. Cite:
    /// `objc4/runtime/objc-runtime-new.h:975-1037`.
    SmallIndirect,
    /// `method_t::small` (12 bytes / entry) with
    /// `relativeMethodSelectorsAreDirectFlag = 0x4000_0000` — the
    /// selector slot points *directly* into `__objc_methname`,
    /// skipping the `__objc_selrefs` indirection. Emitted for
    /// classes the toolchain has determined need no cross-image
    /// selector unification. Cite:
    /// `objc4/runtime/objc-runtime-new.h:982`.
    SmallDirect,
}

/// One method entry from a `method_list_t`.
///
/// Cite: `objc4/runtime/objc-runtime-new.h:914-1037`.
///
/// All three fields ([`selector`](Self::selector),
/// [`types`](Self::types), implementation) are surfaced post-decode:
/// for `SmallIndirect` rows the selref is followed once during
/// iteration, so consumers do not need to translate themselves.
#[derive(Debug, Clone)]
pub struct Method<'a> {
    /// Selector C-string (`SEL` → name), e.g. `"applicationDidFinishLaunching:"`.
    selector: &'a str,
    /// Method type-encoding string in Apple's `@encode` grammar
    /// (e.g. `v16@0:8` → `void(id self, SEL _cmd)`). Cite: Apple's
    /// "Type Encodings" docs and
    /// `objc4/runtime/runtime.h:@encode`.
    types: &'a str,
    /// Implementation VM address (post-PAC-strip). `None` when the
    /// method has no implementation — protocols emit method
    /// declarations with `imp = 0`, and the runtime treats those as
    /// abstract until a conforming class supplies a real IMP.
    imp: Option<u64>,
    kind: MethodKind,
}

impl<'a> Method<'a> {
    /// Selector C-string (e.g. `"greet"`).
    pub fn selector(&self) -> &'a str {
        self.selector
    }

    /// Method type-encoding string.
    pub fn types(&self) -> &'a str {
        self.types
    }

    /// IMP target VA (post-PAC-strip). `None` for abstract methods
    /// — protocols emit method declarations with `imp = 0`.
    pub fn implementation(&self) -> Option<u64> {
        self.imp
    }

    /// On-disk variant that produced this row.
    pub fn kind(&self) -> MethodKind {
        self.kind
    }

    /// `true` when the row was decoded from the 12-byte
    /// relative-offset layout.
    pub fn is_small(&self) -> bool {
        matches!(self.kind, MethodKind::SmallIndirect | MethodKind::SmallDirect)
    }
}

/// Iterator over a single `method_list_t`.
///
/// Constructed via the per-class / per-protocol / per-category
/// `methods()` accessors. Empty when the list pointer is null,
/// when the header is truncated, when the `relative_list_list_t`
/// low-bit indicates a runtime-allocated list (skipped fail-soft,
/// never appears on disk), or when the pointer fails to resolve.
pub struct MethodIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    /// Layout describing how to walk the list. `None` when the list
    /// is empty / unresolved.
    layout: Option<MethodListLayout>,
    cursor: u32,
}

#[derive(Debug, Clone, Copy)]
struct MethodListLayout {
    base_va: u64,
    entsize: u32,
    count: u32,
    kind: MethodKind,
}

impl<'a, 'p> MethodIter<'a, 'p> {
    pub(crate) fn empty(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            layout: None,
            cursor: 0,
        }
    }
}

impl<'a, 'p> Iterator for MethodIter<'a, 'p> {
    type Item = Method<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let layout = self.layout?;
        loop {
            if self.cursor >= layout.count {
                return None;
            }
            let i = self.cursor;
            self.cursor = self.cursor.checked_add(1)?;
            let entry_off = u64::from(i).checked_mul(u64::from(layout.entsize))?;
            let entry_va = layout.base_va.checked_add(entry_off)?;
            if let Some(m) = decode_method(self.rt, entry_va, layout.kind) {
                return Some(m);
            }
            // Fail-soft: skip rows that fail to resolve.
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::objc: method row at 0x{:x} (idx={}) skipped — decode failed",
                entry_va,
                i
            );
        }
    }
}

/// Build a [`MethodIter`] over the `method_list_t` at virtual
/// address `list_va`.
///
/// `list_va` is a raw pointer slot value — the caller has already
/// PAC-stripped it. Returns an empty iterator when:
///
/// - `list_va == 0` (no list).
/// - The low bit of `list_va` is set (`relative_list_list_t` —
///   runtime-allocated, never on disk).
/// - The header at `list_va` cannot be read.
/// - `entsize` is `0` or smaller than the format demands.
pub(crate) fn method_list_iter<'a, 'p>(
    rt: &'p ObjcRuntime<'a>,
    list_va: u64,
) -> MethodIter<'a, 'p> {
    if list_va == 0 || (list_va & 0x1) != 0 {
        if (list_va & 0x1) != 0 {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::objc: method list at 0x{:x} has list-of-lists low bit — skipped (runtime-only)",
                list_va,
            );
        }
        return MethodIter::empty(rt);
    }

    let Some(header) = rt.read_bytes(list_va, 8) else {
        return MethodIter::empty(rt);
    };
    let Some(entsize_and_flags) = read_u32_le_at(header, 0) else {
        return MethodIter::empty(rt);
    };
    let Some(count) = read_u32_le_at(header, 4) else {
        return MethodIter::empty(rt);
    };

    let entsize = entsize_and_flags & !METHOD_LIST_FLAG_MASK;
    if entsize == 0 {
        return MethodIter::empty(rt);
    }

    let is_small = (entsize_and_flags & SMALL_METHOD_LIST_FLAG) != 0;
    let is_direct = (entsize_and_flags & RELATIVE_METHOD_SELECTORS_ARE_DIRECT_FLAG) != 0;

    let kind = if is_small {
        if is_direct {
            MethodKind::SmallDirect
        } else {
            MethodKind::SmallIndirect
        }
    } else {
        MethodKind::Legacy
    };

    let min_entsize = match kind {
        MethodKind::Legacy => 24,
        MethodKind::SmallIndirect | MethodKind::SmallDirect => 12,
    };
    if entsize < min_entsize {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            "darwinscope::objc: method list at 0x{:x} has entsize={} (< {}) — skipped",
            list_va,
            entsize,
            min_entsize,
        );
        return MethodIter::empty(rt);
    }

    // Entries start immediately after the 8-byte header.
    let base_va = match list_va.checked_add(8) {
        Some(v) => v,
        None => return MethodIter::empty(rt),
    };

    MethodIter {
        rt,
        layout: Some(MethodListLayout {
            base_va,
            entsize,
            count,
            kind,
        }),
        cursor: 0,
    }
}

fn decode_method<'a>(
    rt: &ObjcRuntime<'a>,
    entry_va: u64,
    kind: MethodKind,
) -> Option<Method<'a>> {
    match kind {
        MethodKind::Legacy => decode_legacy_method(rt, entry_va),
        MethodKind::SmallIndirect => decode_small_method(rt, entry_va, false),
        MethodKind::SmallDirect => decode_small_method(rt, entry_va, true),
    }
}

fn decode_legacy_method<'a>(
    rt: &ObjcRuntime<'a>,
    entry_va: u64,
) -> Option<Method<'a>> {
    rt.read_bytes(entry_va, 24)?;
    let sel_va = rt.resolve_pointer(entry_va)?;
    let types_va = rt.resolve_pointer(entry_va.checked_add(8)?)?;
    let imp_va = rt.resolve_pointer(entry_va.checked_add(16)?).unwrap_or(0);

    let selector = rt.read_cstr(sel_va)?;
    let types = rt.read_cstr(types_va).unwrap_or("");
    let imp = if imp_va == 0 { None } else { Some(imp_va) };

    Some(Method {
        selector,
        types,
        imp,
        kind: MethodKind::Legacy,
    })
}

fn decode_small_method<'a>(
    rt: &ObjcRuntime<'a>,
    entry_va: u64,
    direct_selectors: bool,
) -> Option<Method<'a>> {
    let bytes = rt.read_bytes(entry_va, 12)?;
    let name_off = read_i32_le_at(bytes, 0)?;
    let types_off = read_i32_le_at(bytes, 4)?;
    let imp_off = read_i32_le_at(bytes, 8)?;

    // Each i32 is a relative pointer from its own slot's address —
    // *not* from the start of the record. Cite
    // `objc4/runtime/objc-runtime-new.h:643-665`.
    let name_slot_va = entry_va;
    let types_slot_va = entry_va.checked_add(4)?;
    let imp_slot_va = entry_va.checked_add(8)?;

    let name_target = relative_pointer(name_slot_va, name_off);
    let types_target = relative_pointer(types_slot_va, types_off);
    let imp_target = relative_pointer(imp_slot_va, imp_off);

    let selector = if direct_selectors {
        rt.read_cstr(name_target)?
    } else {
        // Indirect: name_target is a `selref` slot in __objc_selrefs;
        // its slot bytes resolve through the chained-fixup rebase
        // table (or PAC strip on legacy) to the selector C-string
        // VA in __objc_methname. Cite RESEARCH.md:1485-1493.
        let sel_va = rt.resolve_pointer(name_target)?;
        rt.read_cstr(sel_va)?
    };

    let types = rt.read_cstr(types_target).unwrap_or("");

    let imp = if imp_off == 0 {
        // Abstract method (protocol declaration).
        None
    } else {
        Some(strip_signature(imp_target))
    };

    Some(Method {
        selector,
        types,
        imp,
        kind: if direct_selectors {
            MethodKind::SmallDirect
        } else {
            MethodKind::SmallIndirect
        },
    })
}
