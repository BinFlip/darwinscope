//! `__swift5_reflstr` lookup helper.
//!
//! `__swift5_reflstr` is a pool of NUL-terminated UTF-8 strings
//! referenced by relative pointers from
//! [`crate::swift::FieldRecord::field_name`]. The walker resolves
//! field names through this section transparently — no separate
//! iterator is exposed.
//!
//! Resolution strategy:
//!
//! 1. Primary: [`SwiftRuntime::read_cstr`] — segment-table-based
//!    lookup. Works for any in-image VA, including names that live
//!    inside `__TEXT,__swift5_reflstr` directly.
//! 2. Fallback: if the primary lookup fails, locate the target VA
//!    inside the cached `__swift5_reflstr` section body and read
//!    the C-string from there. Catches linker variants that emit
//!    reflection strings outside the standard segment-table-
//!    addressable region.

use crate::{swift::SwiftRuntime, util::read_cstr_at};

/// Resolve a field-name relative-pointer target VA to its string.
pub(crate) fn lookup_field_name<'a>(
    rt: &SwiftRuntime<'a>,
    target_va: u64,
) -> Option<&'a str> {
    if target_va == 0 {
        return None;
    }
    if let Some(s) = rt.read_cstr(target_va) {
        return Some(s);
    }
    // Fallback: try the cached __swift5_reflstr body. Computes the
    // offset into the section body if the target VA lands inside
    // its `[vmaddr, vmaddr + body.len())` range.
    let section = rt.reflstr.as_ref()?;
    if target_va < section.vmaddr {
        return None;
    }
    let off = target_va.checked_sub(section.vmaddr)?;
    let off_usize = usize::try_from(off).ok()?;
    if off_usize >= section.body.len() {
        return None;
    }
    read_cstr_at(section.body, off_usize)
}
