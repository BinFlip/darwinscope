//! Segments and sections (`LC_SEGMENT_64` / `LC_SEGMENT`).
//!
//! Wraps `goblin::mach::segment` and exposes typed iterators with
//! the borrowed-slice view-type shape used elsewhere in the crate.
//!
//! - [`Segment`] — view over a single segment load command.
//! - [`SegmentIter`] — iterator over [`MachoBinary::segments`].
//! - [`Section`] — view over a single section header plus body
//!   slice. The lazy [`Section::shannon_entropy`] and
//!   [`Section::blake3`] accessors are computed on caller request
//!   and *not* part of the base view, so a consumer that only
//!   enumerates names pays nothing.
//! - [`SectionIter`] — flat iterator over every section across every
//!   segment (returned by [`MachoBinary::sections`]).
//!
//! ## Zero-fill sections
//!
//! `S_ZEROFILL`, `S_GB_ZEROFILL`, and `S_THREAD_LOCAL_ZEROFILL` have
//! no on-disk bytes. [`Section::body`] returns an empty slice for
//! them rather than `Option` or panic.
//!
//! [`MachoBinary::segments`]: crate::binary::MachoBinary::segments
//! [`MachoBinary::sections`]: crate::binary::MachoBinary::sections

use core::marker::PhantomData;

use bitflags::bitflags;
use goblin::mach::segment::{
    Section as GoblinSection, SectionIterator as GoblinSectionIter, Segment as GoblinSegment,
};

use crate::util::cstr_from_fixed;

/// Bitmask isolating the section type in `Section::flags`.
const SECTION_TYPE_MASK: u32 = 0x0000_00ff;

/// View over one Mach-O segment load command.
///
/// `'a` is the data lifetime; `'p` is the borrow of the parent
/// [`MachoBinary`](crate::binary::MachoBinary).
pub struct Segment<'a, 'p> {
    inner: &'p GoblinSegment<'a>,
}

impl<'a, 'p> Segment<'a, 'p> {
    pub(crate) fn new(inner: &'p GoblinSegment<'a>) -> Self {
        Self { inner }
    }

    /// Segment name (`__TEXT`, `__DATA`, …) with the trailing NULs
    /// trimmed. Empty for malformed/missing names.
    ///
    /// The kickoff sketch types this as `&'a str`, but the on-disk
    /// `segname[16]` field is owned by the goblin segment struct
    /// (not borrowed from `data`), so the borrow is parent-bound.
    pub fn name(&self) -> &str {
        cstr_from_fixed(&self.inner.segname)
    }

    /// Virtual memory address.
    pub fn vmaddr(&self) -> u64 {
        self.inner.vmaddr
    }

    /// Virtual memory size.
    pub fn vmsize(&self) -> u64 {
        self.inner.vmsize
    }

    /// File offset of the segment payload.
    pub fn fileoff(&self) -> u64 {
        self.inner.fileoff
    }

    /// On-disk size of the segment payload.
    pub fn filesize(&self) -> u64 {
        self.inner.filesize
    }

    /// Maximum VM protection (`VM_PROT_*`).
    pub fn maxprot(&self) -> u32 {
        self.inner.maxprot
    }

    /// Initial VM protection (`VM_PROT_*`).
    pub fn initprot(&self) -> u32 {
        self.inner.initprot
    }

    /// Number of sections directly contained in this segment.
    pub fn nsects(&self) -> u32 {
        self.inner.nsects
    }

    /// `SG_*` flags.
    pub fn flags(&self) -> u32 {
        self.inner.flags
    }

    /// Sections contained in this segment.
    pub fn sections(&self) -> SectionIter<'a, 'p> {
        SectionIter {
            segments: SegmentSource::Single(Some(self.inner)),
            current: None,
            _parent: PhantomData,
        }
    }

    /// On-disk bytes of the segment (`[fileoff..fileoff+filesize]`).
    /// Empty for `__PAGEZERO` and any segment with `filesize == 0`.
    pub fn body(&self) -> &'a [u8] {
        self.inner.data
    }
}

impl core::fmt::Debug for Segment<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Segment")
            .field("name", &self.name())
            .field("vmaddr", &self.vmaddr())
            .field("vmsize", &self.vmsize())
            .field("fileoff", &self.fileoff())
            .field("filesize", &self.filesize())
            .field("nsects", &self.nsects())
            .field("flags", &format_args!("0x{:x}", self.flags()))
            .finish()
    }
}

/// Iterator over [`Segment`]s in load-command order.
pub struct SegmentIter<'a, 'p> {
    inner: core::slice::Iter<'p, GoblinSegment<'a>>,
}

impl<'a, 'p> SegmentIter<'a, 'p> {
    pub(crate) fn new(slice: &'p [GoblinSegment<'a>]) -> Self {
        Self {
            inner: slice.iter(),
        }
    }
}

impl<'a, 'p> Iterator for SegmentIter<'a, 'p> {
    type Item = Segment<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Segment::new)
    }
}

/// View over one section header plus its on-disk body.
pub struct Section<'a, 'p> {
    inner: GoblinSection,
    body: &'a [u8],
    _parent: PhantomData<&'p ()>,
}

impl<'a, 'p> Section<'a, 'p> {
    /// Containing segment name (e.g. `__TEXT`).
    pub fn segname(&self) -> &str {
        cstr_from_fixed(&self.inner.segname)
    }

    /// Section name (e.g. `__text`).
    pub fn sectname(&self) -> &str {
        cstr_from_fixed(&self.inner.sectname)
    }

    /// VM address of the section.
    pub fn addr(&self) -> u64 {
        self.inner.addr
    }

    /// Size in bytes (also the size on disk for non-zero-fill).
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// File offset of the section payload. `0` for zero-fill
    /// sections (no on-disk bytes).
    pub fn offset(&self) -> u32 {
        self.inner.offset
    }

    /// Section alignment, expressed as a power of two (i.e. `align()
    /// == 4` means alignment of `2^4 = 16`).
    pub fn align(&self) -> u32 {
        self.inner.align
    }

    /// File offset of the section's relocation entries.
    pub fn reloff(&self) -> u32 {
        self.inner.reloff
    }

    /// Number of relocation entries.
    pub fn nreloc(&self) -> u32 {
        self.inner.nreloc
    }

    /// Raw `flags` field (section type in low 8 bits, attributes in
    /// high 24).
    pub fn flags(&self) -> u32 {
        self.inner.flags
    }

    /// Section type — the low 8 bits of `flags`.
    pub fn section_type(&self) -> SectionType {
        SectionType::from_raw(self.inner.flags & SECTION_TYPE_MASK)
    }

    /// Section attributes — the high 24 bits of `flags`.
    pub fn attributes(&self) -> SectionAttributes {
        SectionAttributes::from_bits_retain(self.inner.flags & !SECTION_TYPE_MASK)
    }

    /// On-disk bytes for this section.
    ///
    /// Empty for `S_ZEROFILL`, `S_GB_ZEROFILL`, and
    /// `S_THREAD_LOCAL_ZEROFILL` (those sections allocate VM but
    /// have no file backing). Empty also when goblin determined the
    /// section's claimed offset/size run past the end of the file
    /// (defensive fail-soft).
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Shannon entropy (in bits) of [`body`](Self::body), in the
    /// range `0.0..=8.0`. Returns `0.0` for empty bodies (zero-fill
    /// sections, truncated input).
    ///
    /// Computed on every call — the result is **not** cached.
    /// Callers that need it repeatedly should memoize externally.
    pub fn shannon_entropy(&self) -> f64 {
        shannon_entropy(self.body)
    }

    /// BLAKE3 hash of [`body`](Self::body).
    ///
    /// Returns the empty-input BLAKE3 digest for empty bodies.
    pub fn blake3(&self) -> blake3::Hash {
        blake3::hash(self.body)
    }
}

impl core::fmt::Debug for Section<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Section")
            .field("segname", &self.segname())
            .field("sectname", &self.sectname())
            .field("addr", &self.addr())
            .field("size", &self.size())
            .field("offset", &self.offset())
            .field("align", &self.align())
            .field("flags", &format_args!("0x{:x}", self.flags()))
            .finish()
    }
}

/// Source of segments for a [`SectionIter`] — either flat across all
/// of them, or scoped to a single segment.
enum SegmentSource<'a, 'p> {
    All(core::slice::Iter<'p, GoblinSegment<'a>>),
    Single(Option<&'p GoblinSegment<'a>>),
}

impl<'a, 'p> SegmentSource<'a, 'p> {
    fn next(&mut self) -> Option<&'p GoblinSegment<'a>> {
        match self {
            Self::All(it) => it.next(),
            Self::Single(slot) => slot.take(),
        }
    }
}

/// Flattened iterator over every section in every segment.
pub struct SectionIter<'a, 'p> {
    segments: SegmentSource<'a, 'p>,
    current: Option<GoblinSectionIter<'a>>,
    _parent: PhantomData<&'p ()>,
}

impl<'a, 'p> SectionIter<'a, 'p> {
    pub(crate) fn new(slice: &'p [GoblinSegment<'a>]) -> Self {
        Self {
            segments: SegmentSource::All(slice.iter()),
            current: None,
            _parent: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for SectionIter<'a, 'p> {
    type Item = Section<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(it) = &mut self.current {
                match it.next() {
                    Some(Ok((section, data))) => {
                        return Some(Section {
                            inner: section,
                            body: data,
                            _parent: PhantomData,
                        });
                    }
                    Some(Err(_)) => {
                        // Per fail-soft posture (`error.rs:6-9`):
                        // skip malformed rows. With the `tracing`
                        // feature the underlying goblin error is
                        // already logged at debug level.
                        continue;
                    }
                    None => {
                        self.current = None;
                    }
                }
            }
            let next_segment = self.segments.next()?;
            self.current = Some(next_segment.into_iter());
        }
    }
}

/// Mach-O `S_*` section type (low 8 bits of `Section::flags`).
///
/// `Other` carries the raw value when a future or vendor-specific
/// type appears that this crate does not yet recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// `S_REGULAR` — regular section.
    Regular,
    /// `S_ZEROFILL` — zero-fill on demand.
    ZeroFill,
    /// `S_CSTRING_LITERALS` — only NUL-terminated C strings.
    CStringLiterals,
    /// `S_4BYTE_LITERALS` — only 4-byte literals.
    FourByteLiterals,
    /// `S_8BYTE_LITERALS` — only 8-byte literals.
    EightByteLiterals,
    /// `S_LITERAL_POINTERS` — section with only pointers to literals.
    LiteralPointers,
    /// `S_NON_LAZY_SYMBOL_POINTERS`.
    NonLazySymbolPointers,
    /// `S_LAZY_SYMBOL_POINTERS`.
    LazySymbolPointers,
    /// `S_SYMBOL_STUBS` — section with only symbol stubs.
    SymbolStubs,
    /// `S_MOD_INIT_FUNC_POINTERS`.
    ModInitFuncPointers,
    /// `S_MOD_TERM_FUNC_POINTERS`.
    ModTermFuncPointers,
    /// `S_COALESCED` — coalesced symbols.
    Coalesced,
    /// `S_GB_ZEROFILL` — > 4 GiB zero-fill on demand.
    GbZeroFill,
    /// `S_INTERPOSING` — interposing functions.
    Interposing,
    /// `S_16BYTE_LITERALS` — only 16-byte literals.
    SixteenByteLiterals,
    /// `S_DTRACE_DOF`.
    DtraceDof,
    /// `S_LAZY_DYLIB_SYMBOL_POINTERS`.
    LazyDylibSymbolPointers,
    /// `S_THREAD_LOCAL_REGULAR`.
    ThreadLocalRegular,
    /// `S_THREAD_LOCAL_ZEROFILL`.
    ThreadLocalZeroFill,
    /// `S_THREAD_LOCAL_VARIABLES`.
    ThreadLocalVariables,
    /// `S_THREAD_LOCAL_VARIABLE_POINTERS`.
    ThreadLocalVariablePointers,
    /// `S_THREAD_LOCAL_INIT_FUNCTION_POINTERS`.
    ThreadLocalInitFunctionPointers,
    /// Anything else — value preserved for round-trip.
    Other(u32),
}

impl SectionType {
    /// Construct from the raw 8-bit type value.
    pub fn from_raw(v: u32) -> Self {
        match v {
            0x00 => Self::Regular,
            0x01 => Self::ZeroFill,
            0x02 => Self::CStringLiterals,
            0x03 => Self::FourByteLiterals,
            0x04 => Self::EightByteLiterals,
            0x05 => Self::LiteralPointers,
            0x06 => Self::NonLazySymbolPointers,
            0x07 => Self::LazySymbolPointers,
            0x08 => Self::SymbolStubs,
            0x09 => Self::ModInitFuncPointers,
            0x0a => Self::ModTermFuncPointers,
            0x0b => Self::Coalesced,
            0x0c => Self::GbZeroFill,
            0x0d => Self::Interposing,
            0x0e => Self::SixteenByteLiterals,
            0x0f => Self::DtraceDof,
            0x10 => Self::LazyDylibSymbolPointers,
            0x11 => Self::ThreadLocalRegular,
            0x12 => Self::ThreadLocalZeroFill,
            0x13 => Self::ThreadLocalVariables,
            0x14 => Self::ThreadLocalVariablePointers,
            0x15 => Self::ThreadLocalInitFunctionPointers,
            other => Self::Other(other),
        }
    }

    /// Whether this section type has no on-disk bytes (zero-fill
    /// family). Section bodies are guaranteed empty for these.
    pub fn is_zero_fill(self) -> bool {
        matches!(
            self,
            Self::ZeroFill | Self::GbZeroFill | Self::ThreadLocalZeroFill
        )
    }
}

bitflags! {
    /// Mach-O `S_ATTR_*` section attribute flags (high 24 bits of
    /// `Section::flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionAttributes: u32 {
        /// `S_ATTR_PURE_INSTRUCTIONS` — section contains only
        /// machine instructions.
        const PURE_INSTRUCTIONS = 0x8000_0000;
        /// `S_ATTR_NO_TOC` — coalesced symbols not in TOC.
        const NO_TOC = 0x4000_0000;
        /// `S_ATTR_STRIP_STATIC_SYMS` — strippable static symbols.
        const STRIP_STATIC_SYMS = 0x2000_0000;
        /// `S_ATTR_NO_DEAD_STRIP` — no dead-strip the section.
        const NO_DEAD_STRIP = 0x1000_0000;
        /// `S_ATTR_LIVE_SUPPORT` — live blocks reference this section.
        const LIVE_SUPPORT = 0x0800_0000;
        /// `S_ATTR_SELF_MODIFYING_CODE`.
        const SELF_MODIFYING_CODE = 0x0400_0000;
        /// `S_ATTR_DEBUG` — debug section.
        const DEBUG_SECTION = 0x0200_0000;
        /// `S_ATTR_SOME_INSTRUCTIONS` — contains some instructions.
        const SOME_INSTRUCTIONS = 0x0000_0400;
        /// `S_ATTR_EXT_RELOC` — has external relocation entries.
        const EXT_RELOC = 0x0000_0200;
        /// `S_ATTR_LOC_RELOC` — has local relocation entries.
        const LOC_RELOC = 0x0000_0100;
    }
}

/// Shannon entropy in bits.
///
/// Pulled out of the [`Section`] impl to keep the histogram loop small.
/// The byte histogram is indexed through `get_mut` and accumulated with
/// `saturating_add`, so no lint allowance is needed: the index is a `u8`
/// cast that cannot leave the 256-entry array, and the counter cannot
/// wrap even for a pathologically large body.
fn shannon_entropy(body: &[u8]) -> f64 {
    if body.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in body {
        if let Some(slot) = counts.get_mut(b as usize) {
            *slot = slot.saturating_add(1);
        }
    }
    let len = body.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_type_decodes_known_kinds() {
        // S_TYPE mask is the low 8 bits of section flags.
        // S_REGULAR = 0, S_CSTRING_LITERALS = 2, S_SYMBOL_STUBS = 8.
        assert!(matches!(SectionType::from_raw(0x00), SectionType::Regular));
        assert!(matches!(
            SectionType::from_raw(0x02),
            SectionType::CStringLiterals
        ));
        assert!(matches!(
            SectionType::from_raw(0x08),
            SectionType::SymbolStubs
        ));
    }

    #[test]
    fn section_type_zero_fill_predicate() {
        // S_ZEROFILL = 1, S_GB_ZEROFILL = 0xc, S_THREAD_LOCAL_ZEROFILL = 0x12.
        assert!(SectionType::from_raw(0x01).is_zero_fill());
        assert!(SectionType::from_raw(0x0c).is_zero_fill());
        assert!(SectionType::from_raw(0x12).is_zero_fill());
        assert!(!SectionType::from_raw(0x00).is_zero_fill());
        assert!(!SectionType::from_raw(0x02).is_zero_fill());
    }

    #[test]
    fn shannon_entropy_uniform_byte_pool_max_8() {
        // 256 distinct bytes occurring exactly once each ⇒ uniform
        // distribution ⇒ entropy = log2(256) = 8.
        let body: Vec<u8> = (0u16..256).map(|x| x as u8).collect();
        let h = shannon_entropy(&body);
        assert!((h - 8.0).abs() < 1e-9, "expected entropy ≈ 8, got {h}");
    }

    #[test]
    fn shannon_entropy_constant_byte_zero() {
        // Single repeated byte ⇒ 0 entropy.
        let body = [0xaau8; 1024];
        assert_eq!(shannon_entropy(&body), 0.0);
    }

    #[test]
    fn shannon_entropy_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }
}
