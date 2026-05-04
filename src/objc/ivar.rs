//! Ivar-list walker.
//!
//! Cite: `objc4/runtime/objc-runtime-new.h:1205-1225`
//! (`ivar_t`) and `:1490-1496` (`ivar_list_t` —
//! `entsize_list_tt<ivar_t, ivar_list_t, 0>`). `RESEARCH.md`
//! anchors the layout at line 1512.
//!
//! `ivar_t` on disk:
//!
//! ```text
//! offset       u64 ptr      -> int32_t* (resolved at runtime)
//! name         u64 ptr      -> NUL-terminated UTF-8
//! type         u64 ptr      -> ObjC type-encoding string
//! alignment_raw u32          (log2 alignment; ~0 ⇒ WORD_SHIFT)
//! size         u32           bytes
//! ```
//!
//! Total: 32 bytes per entry.

use crate::{objc::ObjcRuntime, util::read_u32_le_at};

/// 64-bit `WORD_SHIFT` from `objc4/runtime/objc-runtime-new.h:200`
/// — the default ivar log2-alignment when `alignment_raw == ~0`.
const WORD_SHIFT_64: u8 = 3;

/// Per-element size of an `ivar_list_t` entry.
const IVAR_ENTSIZE: u32 = 32;

/// One ivar entry from a `class_ro_t.ivars` list.
///
/// Cite: `objc4/runtime/objc-runtime-new.h:1205-1225` (`ivar_t`).
///
/// Each ivar binds a name + type-encoding to a runtime offset
/// inside the instance. The on-disk encoding stores the offset
/// **indirectly** — the `offset` slot is a pointer to a 32-bit cell
/// (`int32_t* g_ivar_offset_<class>_<name>`). The runtime patches
/// that cell during class realization to account for superclass
/// growth, which is why ivars on Apple frameworks ship with offsets
/// of `0` on disk and the linker patches them at first message.
/// [`Ivar::offset`] dereferences the indirection for callers.
///
/// `log2_alignment` defaults to `WORD_SHIFT` (3 on LP64) when the
/// on-disk `alignment_raw` is `0xffffffff` — the sentinel the
/// compiler writes for "use the platform default".
#[derive(Debug, Clone)]
pub struct Ivar<'a> {
    name: &'a str,
    type_encoding: &'a str,
    offset: Option<u32>,
    size: u32,
    log2_alignment: u8,
}

impl<'a> Ivar<'a> {
    /// Ivar name (e.g. `"_name"`).
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// ObjC type-encoding string (e.g. `"@\"NSString\""`).
    pub fn type_encoding(&self) -> &'a str {
        self.type_encoding
    }

    /// Literal ivar offset in bytes from the start of the instance.
    ///
    /// On disk the on-class ivar table stores a *pointer* to the
    /// 32-bit offset slot; this method dereferences it. Returns
    /// `None` when the slot pointer is null or fails to resolve
    /// (heavily stripped / corrupt input).
    pub fn offset(&self) -> Option<u32> {
        self.offset
    }

    /// Ivar size in bytes.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// `log2(alignment)` — defaults to `WORD_SHIFT` (3 on LP64) when
    /// the on-disk `alignment_raw` is `~0`.
    pub fn log2_alignment(&self) -> u8 {
        self.log2_alignment
    }
}

/// Iterator over a single `ivar_list_t`.
pub struct IvarIter<'a, 'p> {
    rt: &'p ObjcRuntime<'a>,
    layout: Option<IvarListLayout>,
    cursor: u32,
}

#[derive(Debug, Clone, Copy)]
struct IvarListLayout {
    base_va: u64,
    entsize: u32,
    count: u32,
}

impl<'a, 'p> IvarIter<'a, 'p> {
    pub(crate) fn empty(rt: &'p ObjcRuntime<'a>) -> Self {
        Self {
            rt,
            layout: None,
            cursor: 0,
        }
    }
}

impl<'a, 'p> Iterator for IvarIter<'a, 'p> {
    type Item = Ivar<'a>;
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
            if let Some(v) = decode_ivar(self.rt, entry_va) {
                return Some(v);
            }
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::objc: ivar row at 0x{:x} (idx={}) skipped — decode failed",
                entry_va,
                i
            );
        }
    }
}

pub(crate) fn ivar_list_iter<'a, 'p>(rt: &'p ObjcRuntime<'a>, list_va: u64) -> IvarIter<'a, 'p> {
    if list_va == 0 {
        return IvarIter::empty(rt);
    }

    let Some(header) = rt.read_bytes(list_va, 8) else {
        return IvarIter::empty(rt);
    };
    let Some(entsize_and_flags) = read_u32_le_at(header, 0) else {
        return IvarIter::empty(rt);
    };
    let Some(count) = read_u32_le_at(header, 4) else {
        return IvarIter::empty(rt);
    };
    // `ivar_list_t` has `FlagMask = 0` (cite RESEARCH.md:1454), so
    // entsize is the full word.
    let entsize = entsize_and_flags;
    if entsize < IVAR_ENTSIZE {
        return IvarIter::empty(rt);
    }

    let base_va = match list_va.checked_add(8) {
        Some(v) => v,
        None => return IvarIter::empty(rt),
    };

    IvarIter {
        rt,
        layout: Some(IvarListLayout {
            base_va,
            entsize,
            count,
        }),
        cursor: 0,
    }
}

fn decode_ivar<'a>(rt: &ObjcRuntime<'a>, entry_va: u64) -> Option<Ivar<'a>> {
    let bytes = rt.read_bytes(entry_va, IVAR_ENTSIZE as usize)?;
    let offset_slot_va = rt.resolve_pointer(entry_va).unwrap_or(0);
    let name_va = rt.resolve_pointer(entry_va.checked_add(8)?)?;
    let type_va = rt.resolve_pointer(entry_va.checked_add(16)?).unwrap_or(0);
    let alignment_raw = read_u32_le_at(bytes, 24)?;
    let size = read_u32_le_at(bytes, 28)?;

    let name = rt.read_cstr(name_va)?;
    let type_encoding = rt.read_cstr(type_va).unwrap_or("");

    let offset = if offset_slot_va == 0 {
        None
    } else {
        rt.read_u32(offset_slot_va)
    };

    let log2_alignment = if alignment_raw == u32::MAX {
        WORD_SHIFT_64
    } else {
        // Clamp to u8 — alignment shifts above 63 are nonsensical.
        // Defensive: we never index by this value, just surface it.
        (alignment_raw & 0xff) as u8
    };

    Some(Ivar {
        name,
        type_encoding,
        offset,
        size,
        log2_alignment,
    })
}
