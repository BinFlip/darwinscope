//! Section-name lookup helper for `__objc_*` sections.
//!
//! Modern Xcode places ObjC metadata in `__DATA_CONST` while older
//! binaries put it in `__DATA`; selector-string sections have always
//! lived in `__TEXT`. The lookup utility checks **only** the section
//! name — the segment is informational. Cite:
//! `ld64/src/ld/Options.cpp` (the
//! `addSectionRename("__DATA", "__objc_…", "__DATA_CONST", "__objc_…")`
//! block).

use crate::binary::MachoBinary;

/// On-disk view of one ObjC metadata section.
///
/// Holds the raw section body and the VM address it maps to so that
/// the walkers can translate a relative offset within the section
/// (`body_offset`) into an absolute VM address (`vmaddr + offset`)
/// without re-scanning the segment table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ObjcSection<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) vmaddr: u64,
}

/// Locate an ObjC metadata section by canonical name.
///
/// `name` must include the leading `__objc_` (e.g. `"__objc_classlist"`).
/// The matcher is segment-agnostic per the section-name catalogue
/// (`RESEARCH.md:2381-2412`); the linker's choice of `__DATA` vs
/// `__DATA_CONST` does not affect identity.
///
/// Returns `None` when no section with the given name exists.
pub(crate) fn find_section<'a>(bin: &MachoBinary<'a>, name: &str) -> Option<ObjcSection<'a>> {
    for sect in bin.sections() {
        if sect.sectname() == name {
            return Some(ObjcSection {
                body: sect.body(),
                vmaddr: sect.addr(),
            });
        }
    }
    None
}
