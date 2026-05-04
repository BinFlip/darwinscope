//! Section-name lookup helper for `__swift5_*` sections.
//!
//! Cite: `RESEARCH.md` §"Section overview" (line 1696). The
//! canonical segment for every Swift reflection section is `__TEXT`
//! (per `swift/include/swift/ABI/ObjectFile.h:62`'s
//! `sectionContainsReflectionData` predicate), but linker variants
//! occasionally place individual sections under `__DATA_CONST` or
//! `__const`. The lookup therefore matches **section name only** —
//! the segment is informational. This mirrors the ObjC convention in
//! [`crate::objc::section`].

use crate::binary::MachoBinary;

/// On-disk view of one Swift metadata section.
///
/// Holds the raw section body and the VM address it maps to so that
/// the walkers can translate a relative offset within the section
/// (`body_offset`) into an absolute VM address (`vmaddr + offset`)
/// without re-scanning the segment table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SwiftSection<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) vmaddr: u64,
}

/// Locate a Swift metadata section by canonical name.
///
/// `name` must include the leading `__swift5_` (e.g. `"__swift5_types"`).
/// The matcher is segment-agnostic per the section-name catalogue
/// (`RESEARCH.md:1721-1723`); the linker's choice of `__TEXT` vs
/// `__DATA_CONST` does not affect identity.
///
/// Returns `None` when no section with the given name exists.
pub(crate) fn find_swift_section<'a>(
    bin: &MachoBinary<'a>,
    name: &str,
) -> Option<SwiftSection<'a>> {
    for sect in bin.sections() {
        if sect.sectname() == name {
            return Some(SwiftSection {
                body: sect.body(),
                vmaddr: sect.addr(),
            });
        }
    }
    None
}
