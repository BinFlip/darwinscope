//! `LC_DYLD_CHAINED_FIXUPS` decoder.
//!
//! Walks the on-disk
//! [`dyld_chained_fixups_header`](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h)
//! structure introduced in dyld 1042 (the chained-fixup format
//! version constant `__MACH_O_FIXUP_CHAINS__ = 7`). The header
//! reaches the per-segment `dyld_chained_starts_in_segment` blocks
//! and the `imports[]` table (with its trailing UTF-8 symbol pool).
//!
//! Per-page chain walking and individual `Rebase` / `Bind` rows are
//! decoded in subsequent PRs (`RebaseIter` / `BindIter`); this
//! module currently surfaces:
//!
//! - [`ChainedFixups`] — the header walker.
//! - [`ChainedSegment`] — per-segment metadata
//!   (`pointer_format`, `page_size`, `page_count`, ...).
//! - [`ChainedImport`] — one row of the imports table.
//! - [`PointerFormat`] — decoded `DYLD_CHAINED_PTR_*` enum.
//!
//! See `RESEARCH.md` §"`LC_DYLD_CHAINED_FIXUPS` encoding"
//! (line 2189) for the exhaustive on-disk layout.
//!
//! ## Lifetime model
//!
//! [`ChainedFixups<'a>`] borrows the binary's data slice (`'a`) and
//! that lifetime threads through every iterator and view in this
//! module. Chained fixups don't go through goblin, so there is no
//! goblin-style `&self`-bound mismatch to work around. When
//! [`MachoBinary::imports`](crate::binary::MachoBinary::imports)
//! folds chained binds into the legacy
//! [`Import<'p>`](crate::import::Import) flow, the reborrow from
//! `&'a str` to `&'p str` is automatic since the binary owns the
//! data slice for `'a` and any `&self` borrow lives `'p ⊆ 'a`.
//!
//! ## Endianness
//!
//! Every field in `LC_DYLD_CHAINED_FIXUPS` is little-endian on disk;
//! the helpers in [`crate::util`] (`read_u{16,32,64}_le_at`) read
//! them. Code-signing structures use a separate big-endian set of
//! helpers in [`crate::codesign`].

use crate::{
    ptrauth::{PacKey, PtrAuth},
    util::{read_u16_le_at, read_u32_le_at, read_u64_le_at},
};

const SIZEOF_CHAINED_FIXUPS_HEADER: usize = 28;
const SIZEOF_STARTS_IN_SEGMENT_HEADER: usize = 22;

/// Pointer format from
/// [`dyld_chained_starts_in_segment.pointer_format`](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).
///
/// The named variants are exactly the ones `darwinscope` walks;
/// other values (32-bit chains, kernel-cache, firmware, segmented)
/// are surfaced as [`PointerFormat::Other`] and produce empty
/// per-page iterators per the fail-soft rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerFormat {
    /// `DYLD_CHAINED_PTR_ARM64E` — value `1`, stride 8.
    Arm64e,
    /// `DYLD_CHAINED_PTR_64` — value `2`, stride 4.
    Ptr64,
    /// `DYLD_CHAINED_PTR_64_OFFSET` — value `6`, stride 4.
    Ptr64Offset,
    /// `DYLD_CHAINED_PTR_ARM64E_KERNEL` — value `7`, stride 4.
    Arm64eKernel,
    /// `DYLD_CHAINED_PTR_ARM64E_USERLAND` — value `9`, stride 8.
    Arm64eUserland,
    /// `DYLD_CHAINED_PTR_ARM64E_USERLAND24` — value `12`, stride 8.
    /// 24-bit bind ordinals (vs 16 in the other arm64e formats).
    Arm64eUserland24,
    /// `DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE` — value `13`, stride 8.
    Arm64eSharedCache,
    /// Any other `DYLD_CHAINED_PTR_*` value (32-bit, kernel cache,
    /// firmware, segmented). Out of v0.1 scope; chains for these
    /// segments are skipped fail-soft.
    Other(u16),
}

impl PointerFormat {
    /// Decode a raw `pointer_format` field.
    ///
    /// Inlined because each chain page calls this once via
    /// `ChainedSegmentIter::next` to dispatch the chain decoder; for
    /// a binary with hundreds of pages the indirection cost would be
    /// non-trivial.
    #[inline]
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            1 => Self::Arm64e,
            2 => Self::Ptr64,
            6 => Self::Ptr64Offset,
            7 => Self::Arm64eKernel,
            9 => Self::Arm64eUserland,
            12 => Self::Arm64eUserland24,
            13 => Self::Arm64eSharedCache,
            other => Self::Other(other),
        }
    }

    /// Whether `darwinscope` knows how to decode chains for this
    /// pointer format. `false` ⇒ all rebases / binds skip with a
    /// fail-soft (no error).
    #[inline]
    pub fn is_supported(self) -> bool {
        !matches!(self, Self::Other(_))
    }
}

/// Imports-table format from
/// [`dyld_chained_fixups_header.imports_format`](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportsFormat {
    /// `DYLD_CHAINED_IMPORT` — 4 bytes per entry.
    Plain,
    /// `DYLD_CHAINED_IMPORT_ADDEND` — 8 bytes per entry
    /// (4-byte plain + `int32_t` addend).
    Addend,
    /// `DYLD_CHAINED_IMPORT_ADDEND64` — 16 bytes per entry, used
    /// for 64-bit ordinal / 64-bit addend cases.
    Addend64,
    /// Unknown imports format. Iterators yield nothing.
    Other(u32),
}

impl ImportsFormat {
    /// Decode the raw `imports_format` field.
    #[inline]
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::Plain,
            2 => Self::Addend,
            3 => Self::Addend64,
            other => Self::Other(other),
        }
    }

    /// Stride between successive entries, in bytes. `None` for
    /// unknown formats.
    ///
    /// Inlined because the per-bind iterator multiplies this stride
    /// against an index on every yielded import.
    #[inline]
    pub fn entry_size(self) -> Option<usize> {
        match self {
            Self::Plain => Some(4),
            Self::Addend => Some(8),
            Self::Addend64 => Some(16),
            Self::Other(_) => None,
        }
    }
}

/// Per-segment chained-fixup metadata.
///
/// One [`ChainedSegment`] is yielded per segment that participates
/// in chained fixups (a segment whose
/// `dyld_chained_starts_in_image.seg_info_offset[i]` is non-zero).
#[derive(Debug, Clone, Copy)]
pub struct ChainedSegment {
    /// Index in the binary's segment table (matches the order
    /// returned by [`MachoBinary::segments`](crate::binary::MachoBinary::segments)).
    pub seg_index: u32,
    /// Total size (in bytes) of this `dyld_chained_starts_in_segment`
    /// record on disk.
    pub size: u32,
    /// `0x1000` (4 KiB) or `0x4000` (16 KiB).
    pub page_size: u16,
    /// Decoded pointer format.
    pub pointer_format: PointerFormat,
    /// Raw `pointer_format` value as read from disk.
    pub raw_pointer_format: u16,
    /// Offset of the segment's start in the in-memory image.
    pub segment_offset: u64,
    /// 32-bit-only sentinel — values above this in chains are not
    /// pointers. `0` for 64-bit segments.
    pub max_valid_pointer: u32,
    /// Number of pages the segment occupies.
    pub page_count: u16,
    /// Absolute byte offset (within the binary's data slice) of
    /// this segment's `dyld_chained_starts_in_segment` header.
    /// Internal — drives the per-page chain walk added in
    /// later PRs.
    #[allow(dead_code)]
    pub(crate) starts_offset: usize,
}

/// One row of the chained-fixup imports table.
///
/// Imports are referenced by ordinal from `Bind` chain entries.
/// The string in [`ChainedImport::name`] is interned in the symbol
/// pool that immediately follows the imports table; the `&'a str`
/// is a direct reborrow of the binary's data slice.
#[derive(Debug, Clone, Copy)]
pub struct ChainedImport<'a> {
    /// Library ordinal. Special negative values per dyld:
    /// `-1` = `BIND_SPECIAL_DYLIB_SELF`,
    /// `-2` = `BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`,
    /// `-3` = `BIND_SPECIAL_DYLIB_FLAT_LOOKUP`,
    /// `-4` = `BIND_SPECIAL_DYLIB_WEAK_LOOKUP`. Positive values
    /// are 1-based indices into the `LC_LOAD_*_DYLIB` table.
    pub lib_ordinal: i16,
    /// Weak-import flag (bit `8` of `DYLD_CHAINED_IMPORT`). When
    /// `true`, dyld tolerates the symbol being missing at runtime.
    pub weak_import: bool,
    /// Symbol name from the symbol pool. Empty when the entry's
    /// name offset overruns the pool.
    pub name: &'a str,
    /// Constant added to the resolved value at bind time. `0` for
    /// the `Plain` format (which carries no addend); sign-extended
    /// from `i32` for `Addend`; raw `u64` re-interpreted as `i64`
    /// for `Addend64`.
    pub addend: i64,
}

/// Walker over an `LC_DYLD_CHAINED_FIXUPS` payload.
///
/// Construct via
/// [`MachoBinary::chained_fixups`](crate::binary::MachoBinary::chained_fixups);
/// returns `None` when the binary has no `LC_DYLD_CHAINED_FIXUPS`
/// or the header fails the structural sanity checks.
#[derive(Debug, Clone, Copy)]
pub struct ChainedFixups<'a> {
    /// Full data slice of the parsed Mach-O slice (matches
    /// [`MachoBinary::raw`](crate::binary::MachoBinary::raw)).
    /// Chained-fixup offsets translate inside this slice — for fat
    /// binaries this is the slice's bytes, not the outer fat
    /// archive.
    data: &'a [u8],
    /// Absolute offset of the `dyld_chained_fixups_header` within
    /// `data` (i.e. `LC_DYLD_CHAINED_FIXUPS.dataoff`).
    base: usize,
    fixups_version: u32,
    starts_offset: u32,
    imports_offset: u32,
    symbols_offset: u32,
    imports_count: u32,
    imports_format: ImportsFormat,
    raw_imports_format: u32,
    symbols_format: u32,
}

impl<'a> ChainedFixups<'a> {
    /// Parse a chained-fixup header at `data[base..base+size]`.
    ///
    /// Returns `None` when the header is truncated or
    /// `starts_offset` / `imports_offset` / `symbols_offset` point
    /// outside the payload window.
    pub fn parse(data: &'a [u8], base: usize, size: usize) -> Option<Self> {
        let end = base.checked_add(size)?;
        let payload = data.get(base..end)?;
        if payload.len() < SIZEOF_CHAINED_FIXUPS_HEADER {
            return None;
        }
        let fixups_version = read_u32_le_at(payload, 0)?;
        let starts_offset = read_u32_le_at(payload, 4)?;
        let imports_offset = read_u32_le_at(payload, 8)?;
        let symbols_offset = read_u32_le_at(payload, 12)?;
        let imports_count = read_u32_le_at(payload, 16)?;
        let raw_imports_format = read_u32_le_at(payload, 20)?;
        let symbols_format = read_u32_le_at(payload, 24)?;

        // Bounds-check the three subsection offsets against the
        // payload size. A malformed header that points past the
        // payload would otherwise force every downstream `.get()`
        // to fail one slot at a time.
        let payload_len = u32::try_from(payload.len()).ok()?;
        if starts_offset >= payload_len
            || imports_offset > payload_len
            || symbols_offset > payload_len
        {
            return None;
        }

        Some(Self {
            data,
            base,
            fixups_version,
            starts_offset,
            imports_offset,
            symbols_offset,
            imports_count,
            imports_format: ImportsFormat::from_raw(raw_imports_format),
            raw_imports_format,
            symbols_format,
        })
    }

    /// `dyld_chained_fixups_header.fixups_version` — `0` for the
    /// only currently-defined version.
    pub fn version(&self) -> u32 {
        self.fixups_version
    }

    /// `dyld_chained_fixups_header.imports_count`.
    pub fn imports_count(&self) -> u32 {
        self.imports_count
    }

    /// Decoded `imports_format`.
    pub fn imports_format(&self) -> ImportsFormat {
        self.imports_format
    }

    /// Raw `imports_format` value as read from disk.
    pub fn raw_imports_format(&self) -> u32 {
        self.raw_imports_format
    }

    /// `dyld_chained_fixups_header.symbols_format` — `0` for raw
    /// UTF-8, `1` for zlib-compressed (`darwinscope` does not
    /// currently decompress; an iterator over a zlib pool yields
    /// empty names).
    pub fn symbols_format(&self) -> u32 {
        self.symbols_format
    }

    /// Iterator over the per-segment chain-start blocks.
    ///
    /// Skips segments whose `seg_info_offset` is `0` (i.e. segments
    /// that don't participate in chained fixups — `__PAGEZERO`,
    /// `__LINKEDIT`).
    pub fn segments(&self) -> ChainedSegmentIter<'a> {
        let starts_in_image_off = self.base.saturating_add(self.starts_offset as usize);
        // `seg_count` is the first u32 of `dyld_chained_starts_in_image`.
        let seg_count = read_u32_le_at(self.data, starts_in_image_off).unwrap_or(0);
        ChainedSegmentIter {
            data: self.data,
            starts_in_image_off,
            seg_count,
            cursor: 0,
        }
    }

    /// Iterator over the imports table (one row per
    /// `lib_ordinal × name × addend` triple).
    ///
    /// Yields nothing if the `imports_format` is unknown or the
    /// imports table overruns the payload.
    pub fn imports(&self) -> ChainedImportIter<'a> {
        let stride = match self.imports_format.entry_size() {
            Some(s) => s,
            None => return ChainedImportIter::empty(),
        };
        let imports_base = match self.base.checked_add(self.imports_offset as usize) {
            Some(v) => v,
            None => return ChainedImportIter::empty(),
        };
        let symbols_base = match self.base.checked_add(self.symbols_offset as usize) {
            Some(v) => v,
            None => return ChainedImportIter::empty(),
        };
        ChainedImportIter {
            data: self.data,
            imports_base,
            symbols_base,
            stride,
            format: self.imports_format,
            count: self.imports_count,
            cursor: 0,
        }
    }
}

/// Iterator over [`ChainedSegment`] entries.
pub struct ChainedSegmentIter<'a> {
    data: &'a [u8],
    starts_in_image_off: usize,
    seg_count: u32,
    cursor: u32,
}

impl<'a> Iterator for ChainedSegmentIter<'a> {
    type Item = ChainedSegment;

    fn next(&mut self) -> Option<Self::Item> {
        // Walk seg_info_offset[]; skip segments with offset 0.
        loop {
            if self.cursor >= self.seg_count {
                return None;
            }
            let i = self.cursor;
            self.cursor = self.cursor.checked_add(1)?;

            // seg_info_offset[i] starts at starts_in_image_off + 4 + 4*i.
            let entry_base = self
                .starts_in_image_off
                .checked_add(4)?
                .checked_add((i as usize).checked_mul(4)?)?;
            let seg_info_offset = read_u32_le_at(self.data, entry_base)?;
            if seg_info_offset == 0 {
                continue;
            }
            let starts_off = self
                .starts_in_image_off
                .checked_add(seg_info_offset as usize)?;
            let header = self.data.get(starts_off..)?;
            if header.len() < SIZEOF_STARTS_IN_SEGMENT_HEADER {
                continue;
            }
            // `dyld_chained_starts_in_segment` layout:
            //   u32 size, u16 page_size, u16 pointer_format,
            //   u64 segment_offset, u32 max_valid_pointer, u16 page_count,
            //   u16 page_start[page_count]
            let size = read_u32_le_at(header, 0)?;
            let page_size = read_u16_le_at(header, 4)?;
            let raw_format = read_u16_le_at(header, 6)?;
            let segment_offset = read_u64_le_at(header, 8)?;
            let max_valid_pointer = read_u32_le_at(header, 16)?;
            let page_count = read_u16_le_at(header, 20)?;

            return Some(ChainedSegment {
                seg_index: i,
                size,
                page_size,
                pointer_format: PointerFormat::from_raw(raw_format),
                raw_pointer_format: raw_format,
                segment_offset,
                max_valid_pointer,
                page_count,
                starts_offset: starts_off,
            });
        }
    }
}

/// Iterator over [`ChainedImport`] entries.
pub struct ChainedImportIter<'a> {
    data: &'a [u8],
    imports_base: usize,
    symbols_base: usize,
    stride: usize,
    format: ImportsFormat,
    count: u32,
    cursor: u32,
}

impl<'a> ChainedImportIter<'a> {
    fn empty() -> Self {
        Self {
            data: &[],
            imports_base: 0,
            symbols_base: 0,
            stride: 0,
            format: ImportsFormat::Other(0),
            count: 0,
            cursor: 0,
        }
    }
}

impl<'a> Iterator for ChainedImportIter<'a> {
    type Item = ChainedImport<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.count {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;

        let entry_base = self
            .imports_base
            .checked_add((i as usize).checked_mul(self.stride)?)?;
        let entry_end = entry_base.checked_add(self.stride)?;
        let entry = self.data.get(entry_base..entry_end)?;

        let (lib_ordinal, weak, name_off_in_pool, addend) = match self.format {
            ImportsFormat::Plain => decode_import_plain(entry)?,
            ImportsFormat::Addend => decode_import_addend(entry)?,
            ImportsFormat::Addend64 => decode_import_addend64(entry)?,
            ImportsFormat::Other(_) => return None,
        };

        let name = read_pool_string(self.data, self.symbols_base, name_off_in_pool).unwrap_or("");

        Some(ChainedImport {
            lib_ordinal,
            weak_import: weak,
            name,
            addend,
        })
    }
}

/// One decoded chained-fixup *rebase* row.
///
/// A rebase points at another address inside the *same* image —
/// dyld's job at load time is to add the slide (`actual_load_addr -
/// preferred_load_addr`) so the stored VA is correct after ASLR. By
/// contrast, a [`Bind`] resolves to a symbol in *another* image
/// (looked up via `import_ordinal`).
///
/// `target_vmaddr` is the canonical post-strip target (the arm64e
/// PAC envelope is already removed for `auth_*` formats; the
/// `_OFFSET` formats have the image base already added). `raw_slot`
/// preserves the pre-decoded 64-bit slot for callers that need the
/// exact bit pattern (e.g. forensic byte-for-byte hashing).
#[derive(Debug, Clone, Copy)]
pub struct Rebase {
    seg_index: u32,
    segment_offset: u64,
    vm_address: u64,
    target_vmaddr: u64,
    raw_slot: u64,
    ptr_auth: Option<PtrAuth>,
    high8: Option<u8>,
    pointer_format: PointerFormat,
}

impl Rebase {
    /// Index of the segment that contains this rebase site, in the
    /// binary's segment table order.
    pub fn segment_index(&self) -> u32 {
        self.seg_index
    }

    /// Byte offset of the rebase slot from the start of its segment.
    pub fn segment_offset(&self) -> u64 {
        self.segment_offset
    }

    /// VM address of the rebase slot itself
    /// (`segment.vmaddr + segment_offset`).
    pub fn vm_address(&self) -> u64 {
        self.vm_address
    }

    /// Canonical VM address the slot points at, after PAC stripping
    /// and image-base addition (for `_OFFSET` formats).
    pub fn target_vmaddr(&self) -> u64 {
        self.target_vmaddr
    }

    /// Raw 64-bit slot bytes as read from disk (pre-decode).
    pub fn raw_slot(&self) -> u64 {
        self.raw_slot
    }

    /// PAC metadata for `auth_*` slots; `None` for unauthenticated
    /// formats (`_64`, `_64_OFFSET`, plain arm64e rebase).
    pub fn ptr_auth(&self) -> Option<PtrAuth> {
        self.ptr_auth
    }

    /// `high8` field from `_64` / `_64_OFFSET` rebase slots — the
    /// top 8 bits dyld OR's into the final pointer (used for
    /// tagged-pointer support). `None` for arm64e formats.
    pub fn high8(&self) -> Option<u8> {
        self.high8
    }

    /// Pointer format of the segment that produced this row.
    pub fn pointer_format(&self) -> PointerFormat {
        self.pointer_format
    }
}

/// One decoded chained-fixup *bind* row.
///
/// A bind references an external symbol — at load time dyld
/// resolves `(name, dylib)` by walking the dylib's export trie,
/// then writes `resolved_address + addend` into the slot at
/// `vm_address`. This is the chained-fixup analogue of the legacy
/// `BIND_OPCODE_*` stream emitted in `LC_DYLD_INFO_ONLY` binaries
/// (which `darwinscope` decodes via [`crate::import`]).
///
/// `name` and `dylib` are zero-copy borrows of the binary's
/// imports symbol pool and `LC_LOAD_*_DYLIB` install-name strings
/// respectively. `is_weak` marks the bind as `BIND_WEAK_IMPORT` —
/// dyld is allowed to leave the slot zero if no exporter is found.
#[derive(Debug, Clone, Copy)]
pub struct Bind<'a> {
    seg_index: u32,
    segment_offset: u64,
    vm_address: u64,
    import_ordinal: u32,
    addend: i64,
    name: &'a str,
    dylib: &'a str,
    is_weak: bool,
    ptr_auth: Option<PtrAuth>,
    pointer_format: PointerFormat,
    raw_slot: u64,
}

impl<'a> Bind<'a> {
    /// Index of the segment that contains this bind site, in the
    /// binary's segment table order.
    pub fn segment_index(&self) -> u32 {
        self.seg_index
    }

    /// Byte offset of the bind slot from the start of its segment.
    pub fn segment_offset(&self) -> u64 {
        self.segment_offset
    }

    /// VM address of the bind slot itself.
    pub fn vm_address(&self) -> u64 {
        self.vm_address
    }

    /// Index into the imports table this bind references. Up to
    /// 24 bits in `_64` / `_USERLAND24` formats; 16 bits elsewhere.
    pub fn import_ordinal(&self) -> u32 {
        self.import_ordinal
    }

    /// Constant added to the resolved value at bind time. Sourced
    /// from both the slot's `addend` field and the imports table
    /// row's `addend` field; the two are summed during decode.
    pub fn addend(&self) -> i64 {
        self.addend
    }

    /// Symbol name dyld will resolve for this bind.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Dylib path the symbol resolves into. Returns the static
    /// strings `"self"`, `"main-executable"`, `"flat-namespace"`,
    /// or `"weak"` for the special negative ordinals.
    pub fn dylib(&self) -> &'a str {
        self.dylib
    }

    /// Weak-import flag (sourced from the imports-table row).
    pub fn is_weak(&self) -> bool {
        self.is_weak
    }

    /// PAC metadata for `auth_bind*` slots; `None` for non-auth
    /// formats.
    pub fn ptr_auth(&self) -> Option<PtrAuth> {
        self.ptr_auth
    }

    /// Pointer format of the segment that produced this row.
    pub fn pointer_format(&self) -> PointerFormat {
        self.pointer_format
    }

    /// Raw 64-bit slot bytes as read from disk (pre-decode).
    pub fn raw_slot(&self) -> u64 {
        self.raw_slot
    }
}

/// Iterator over chained-fixup rebases.
///
/// Backed by a [`Vec`] populated when the iterator is constructed —
/// the chain walk runs once eagerly so that
/// [`MachoBinary::chained_rebases`](crate::binary::MachoBinary::chained_rebases)
/// and [`MachoBinary::chained_binds`](crate::binary::MachoBinary::chained_binds)
/// can each iterate independently without forcing the caller to
/// dispatch on entry kind.
pub struct RebaseIter<'a> {
    inner: std::vec::IntoIter<Rebase>,
    _phantom: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> RebaseIter<'a> {
    /// Construct an empty iterator. Used when the binary has no
    /// chained fixups or every segment is unsupported.
    pub(crate) fn empty() -> Self {
        Self {
            inner: Vec::new().into_iter(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a> Iterator for RebaseIter<'a> {
    type Item = Rebase;
    fn next(&mut self) -> Option<Rebase> {
        self.inner.next()
    }
}

/// Iterator over chained-fixup binds.
pub struct BindIter<'a> {
    inner: std::vec::IntoIter<Bind<'a>>,
}

impl<'a> BindIter<'a> {
    /// Construct an empty iterator.
    pub(crate) fn empty() -> Self {
        Self {
            inner: Vec::new().into_iter(),
        }
    }
}

impl<'a> Iterator for BindIter<'a> {
    type Item = Bind<'a>;
    fn next(&mut self) -> Option<Bind<'a>> {
        self.inner.next()
    }
}

/// Per-segment context the chain walker needs: the chained-fixup
/// metadata plus the corresponding segment-table entry's runtime
/// fields (`vmaddr`, `fileoff`).
///
/// Constructed by `MachoBinary::chained_*` accessors before the
/// walk runs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SegmentLoc {
    pub chained: ChainedSegment,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub filesize: u64,
}

/// Construct a [`RebaseIter`] over every decoded chained rebase.
///
/// `image_base` is the lowest `vmaddr` of any segment with non-zero
/// file size (typically `__TEXT.vmaddr`). Used to resolve `_OFFSET`
/// formats whose `target` field is image-relative.
pub(crate) fn build_rebase_iter<'a>(
    data: &'a [u8],
    cf: &ChainedFixups<'a>,
    locs: &[SegmentLoc],
    image_base: u64,
) -> RebaseIter<'a> {
    let mut out: Vec<Rebase> = Vec::new();
    for loc in locs {
        decode_segment_chains(data, loc, image_base, &mut out, &mut Vec::new(), &[], &[]);
    }
    RebaseIter {
        inner: out.into_iter(),
        _phantom: core::marker::PhantomData,
    }
    .skip_unused(cf)
}

impl<'a> RebaseIter<'a> {
    fn skip_unused(self, _cf: &ChainedFixups<'a>) -> Self {
        // Keeps the `cf` parameter live for forward-compat (PR 11
        // may want to filter on `imports_format` for warnings).
        self
    }
}

/// Construct a [`BindIter`] over every decoded chained bind.
pub(crate) fn build_bind_iter<'a>(
    data: &'a [u8],
    _cf: &ChainedFixups<'a>,
    locs: &[SegmentLoc],
    image_base: u64,
    imports: &[ChainedImport<'a>],
    dylib_names: &[&'a str],
) -> BindIter<'a> {
    let mut binds: Vec<Bind<'a>> = Vec::new();
    let mut throwaway_rebases: Vec<Rebase> = Vec::new();
    for loc in locs {
        decode_segment_chains(
            data,
            loc,
            image_base,
            &mut throwaway_rebases,
            &mut binds,
            imports,
            dylib_names,
        );
    }
    BindIter {
        inner: binds.into_iter(),
    }
}

const PTR_START_NONE: u16 = 0xFFFF;
const PTR_START_MULTI: u16 = 0x8000;

/// Walk every chain in one segment, appending decoded rows into
/// `rebases_out` and `binds_out`.
///
/// Pointer formats outside the v0.1 supported set fail-soft: the
/// segment is skipped without producing rows.
fn decode_segment_chains<'a>(
    data: &'a [u8],
    loc: &SegmentLoc,
    image_base: u64,
    rebases_out: &mut Vec<Rebase>,
    binds_out: &mut Vec<Bind<'a>>,
    imports: &[ChainedImport<'a>],
    dylib_names: &[&'a str],
) {
    if !loc.chained.pointer_format.is_supported() {
        return;
    }

    // page_start[] follows the 22-byte starts_in_segment header.
    let page_starts_off = loc
        .chained
        .starts_offset
        .saturating_add(SIZEOF_STARTS_IN_SEGMENT_HEADER);

    for page_idx in 0..loc.chained.page_count {
        let entry_off = match (page_idx as usize)
            .checked_mul(2)
            .and_then(|x| page_starts_off.checked_add(x))
        {
            Some(o) => o,
            None => return,
        };
        let raw_start = match read_u16_le_at(data, entry_off) {
            Some(v) => v,
            None => return,
        };
        if raw_start == PTR_START_NONE {
            continue;
        }
        if (raw_start & PTR_START_MULTI) != 0 {
            // Multi-start pages are not exercised by 64-bit
            // userland binaries (only by 32-bit firmware in the
            // current corpus). Fail-soft skip.
            continue;
        }

        // Walk the chain on this page.
        // (The clippy `while let` suggestion only fits the first
        // exit path; the body has several other early `break`s.)
        let mut chain_off = raw_start as u64;
        #[allow(clippy::while_let_loop)]
        loop {
            let page_byte_off = match (page_idx as u64)
                .checked_mul(loc.chained.page_size as u64)
                .and_then(|x| x.checked_add(chain_off))
            {
                Some(v) => v,
                None => break,
            };
            // Bounds check against segment filesize — chain entries
            // beyond on-disk extent are not legal.
            if page_byte_off >= loc.filesize {
                break;
            }
            let abs_off = match loc.fileoff.checked_add(page_byte_off) {
                Some(v) => v,
                None => break,
            };
            let abs_off_usize = match usize::try_from(abs_off) {
                Ok(v) => v,
                Err(_) => break,
            };
            let slot = match read_u64_le_at(data, abs_off_usize) {
                Some(v) => v,
                None => break,
            };

            let segment_offset = page_byte_off;
            let vm_address = loc.vmaddr.saturating_add(segment_offset);

            let next_stride: u64;
            let ctx = SlotCtx {
                image_base,
                seg_index: loc.chained.seg_index,
                segment_offset,
                vm_address,
                imports,
                dylib_names,
            };
            match decode_chain_entry(slot, loc.chained.pointer_format, &ctx) {
                Some((entry, next)) => {
                    next_stride = next;
                    match entry {
                        Entry::Rebase(r) => rebases_out.push(r),
                        Entry::Bind(b) => binds_out.push(b),
                    }
                }
                None => break,
            }

            if next_stride == 0 {
                break;
            }
            let stride_bytes = match loc.chained.pointer_format {
                PointerFormat::Arm64e
                | PointerFormat::Arm64eUserland
                | PointerFormat::Arm64eUserland24
                | PointerFormat::Arm64eSharedCache => 8u64,
                PointerFormat::Ptr64
                | PointerFormat::Ptr64Offset
                | PointerFormat::Arm64eKernel => 4u64,
                PointerFormat::Other(_) => break,
            };
            let advance = next_stride.saturating_mul(stride_bytes);
            chain_off = chain_off.saturating_add(advance);
        }
    }
}

enum Entry<'a> {
    Rebase(Rebase),
    Bind(Bind<'a>),
}

/// Per-slot decode context. Bundles the inputs that
/// [`decode_chain_entry`] needs so its arity stays manageable.
struct SlotCtx<'a, 'b> {
    image_base: u64,
    seg_index: u32,
    segment_offset: u64,
    vm_address: u64,
    imports: &'b [ChainedImport<'a>],
    dylib_names: &'b [&'a str],
}

/// Decode one chain slot. Returns `(entry, next_field)` or `None`
/// if the format is unsupported (caller terminates the chain).
fn decode_chain_entry<'a>(
    slot: u64,
    format: PointerFormat,
    ctx: &SlotCtx<'a, '_>,
) -> Option<(Entry<'a>, u64)> {
    match format {
        PointerFormat::Ptr64 | PointerFormat::Ptr64Offset => {
            let bind_bit = (slot.wrapping_shr(63)) & 0x1;
            let next = (slot.wrapping_shr(51)) & 0x0fff;
            if bind_bit == 0 {
                let target = slot & 0x0000_000f_ffff_ffff; // 36 bits
                let high8 = ((slot.wrapping_shr(36)) & 0xff) as u8;
                let target_vmaddr = if matches!(format, PointerFormat::Ptr64Offset) {
                    ctx.image_base.saturating_add(target)
                } else {
                    target
                };
                let r = Rebase {
                    seg_index: ctx.seg_index,
                    segment_offset: ctx.segment_offset,
                    vm_address: ctx.vm_address,
                    target_vmaddr,
                    raw_slot: slot,
                    ptr_auth: None,
                    high8: Some(high8),
                    pointer_format: format,
                };
                Some((Entry::Rebase(r), next))
            } else {
                let ordinal = (slot & 0x00ff_ffff) as u32; // 24 bits
                let slot_addend = ((slot.wrapping_shr(24)) & 0xff) as u8 as i64;
                let (name, dylib, is_weak, import_addend) =
                    resolve_import(ordinal, ctx.imports, ctx.dylib_names);
                let b = Bind {
                    seg_index: ctx.seg_index,
                    segment_offset: ctx.segment_offset,
                    vm_address: ctx.vm_address,
                    import_ordinal: ordinal,
                    addend: slot_addend.saturating_add(import_addend),
                    name,
                    dylib,
                    is_weak,
                    ptr_auth: None,
                    pointer_format: format,
                    raw_slot: slot,
                };
                Some((Entry::Bind(b), next))
            }
        }
        PointerFormat::Arm64e
        | PointerFormat::Arm64eUserland
        | PointerFormat::Arm64eUserland24
        | PointerFormat::Arm64eKernel
        | PointerFormat::Arm64eSharedCache => decode_arm64e_slot(slot, format, ctx),
        PointerFormat::Other(_) => None,
    }
}

/// Decode an arm64e chain slot. The `auth` and `bind` bits select
/// between four payload shapes (rebase / bind / auth_rebase /
/// auth_bind); `pointer_format` selects which format-specific
/// rules to apply (USERLAND24 has 24-bit ordinals, ARM64E has
/// VA-not-offset rebase targets, etc.).
fn decode_arm64e_slot<'a>(
    slot: u64,
    format: PointerFormat,
    ctx: &SlotCtx<'a, '_>,
) -> Option<(Entry<'a>, u64)> {
    let auth_bit = (slot.wrapping_shr(63)) & 0x1;
    let bind_bit = (slot.wrapping_shr(62)) & 0x1;
    let next = (slot.wrapping_shr(51)) & 0x07ff; // 11 bits

    let pa = if auth_bit != 0 {
        Some(PtrAuth {
            diversity: ((slot.wrapping_shr(32)) & 0xffff) as u16,
            addr_div: ((slot.wrapping_shr(48)) & 0x1) != 0,
            key: PacKey::from_bits(((slot.wrapping_shr(49)) & 0x3) as u8),
        })
    } else {
        None
    };

    if bind_bit == 0 {
        // Rebase variants.
        let target_vmaddr = if auth_bit != 0 {
            // auth_rebase: 32-bit runtime offset.
            let target = slot & 0xffff_ffff;
            ctx.image_base.saturating_add(target)
        } else {
            // unauth rebase: 43-bit target.
            let target = slot & 0x0000_07ff_ffff_ffff;
            match format {
                PointerFormat::Arm64e => target, // direct VA
                _ => ctx.image_base.saturating_add(target),
            }
        };
        // `high8` only present in unauth rebase format (bits 43..51).
        let high8 = if auth_bit == 0 {
            Some(((slot.wrapping_shr(43)) & 0xff) as u8)
        } else {
            None
        };
        let r = Rebase {
            seg_index: ctx.seg_index,
            segment_offset: ctx.segment_offset,
            vm_address: ctx.vm_address,
            target_vmaddr,
            raw_slot: slot,
            ptr_auth: pa,
            high8,
            pointer_format: format,
        };
        Some((Entry::Rebase(r), next))
    } else {
        // Bind variants. Ordinal width depends on format.
        let (ordinal, addend_bits) = match format {
            PointerFormat::Arm64eUserland24 => (
                (slot & 0x00ff_ffff) as u32, // 24 bits
                if auth_bit != 0 {
                    0i64
                } else {
                    extract_signed_19(slot)
                },
            ),
            _ => (
                (slot & 0xffff) as u32, // 16 bits
                if auth_bit != 0 {
                    0i64
                } else {
                    extract_signed_19(slot)
                },
            ),
        };
        let (name, dylib, is_weak, import_addend) =
            resolve_import(ordinal, ctx.imports, ctx.dylib_names);
        let b = Bind {
            seg_index: ctx.seg_index,
            segment_offset: ctx.segment_offset,
            vm_address: ctx.vm_address,
            import_ordinal: ordinal,
            addend: addend_bits.saturating_add(import_addend),
            name,
            dylib,
            is_weak,
            ptr_auth: pa,
            pointer_format: format,
            raw_slot: slot,
        };
        Some((Entry::Bind(b), next))
    }
}

/// Sign-extend a 19-bit value (slot bits `32..51`) to `i64`. Used
/// for the unauth-bind `addend` field in arm64e formats.
fn extract_signed_19(slot: u64) -> i64 {
    let raw = (slot.wrapping_shr(32)) & 0x0007_ffff;
    // bit 18 is the sign bit
    if (raw & 0x0004_0000) != 0 {
        // Sign-extend by setting all bits 19..63.
        (raw | 0xffff_ffff_fff8_0000) as i64
    } else {
        raw as i64
    }
}

/// Resolve a chained-bind ordinal against the imports table and
/// the binary's `LC_LOAD_*_DYLIB` list. Returns
/// `(symbol_name, dylib_name, is_weak, import_addend)`.
fn resolve_import<'a>(
    ordinal: u32,
    imports: &[ChainedImport<'a>],
    dylib_names: &[&'a str],
) -> (&'a str, &'a str, bool, i64) {
    let idx = ordinal as usize;
    let import = match imports.get(idx) {
        Some(i) => *i,
        None => {
            return ("", "", false, 0);
        }
    };
    let dylib = resolve_lib_ordinal(import.lib_ordinal, dylib_names);
    (import.name, dylib, import.weak_import, import.addend)
}

/// Map a chained-fixup `lib_ordinal` to a dylib name. Positive
/// ordinals are 1-based indices into the binary's
/// `LC_LOAD_*_DYLIB` list; zero and negative ordinals are special
/// dyld values exposed verbatim.
pub(crate) fn resolve_lib_ordinal<'a>(ordinal: i16, dylib_names: &[&'a str]) -> &'a str {
    match ordinal {
        n if n > 0 => {
            let idx = (n as usize).saturating_sub(1);
            dylib_names.get(idx).copied().unwrap_or("")
        }
        0 => "self",
        -1 => "main-executable",
        -2 => "flat-namespace",
        -3 => "weak",
        _ => "",
    }
}

fn decode_import_plain(entry: &[u8]) -> Option<(i16, bool, u32, i64)> {
    let raw = read_u32_le_at(entry, 0)?;
    let lib_ordinal_raw = (raw & 0xff) as u8;
    let weak = (raw & 0x100) != 0;
    let name_off = raw.wrapping_shr(9);
    Some((sign_extend_i8(lib_ordinal_raw), weak, name_off, 0))
}

fn decode_import_addend(entry: &[u8]) -> Option<(i16, bool, u32, i64)> {
    let raw = read_u32_le_at(entry, 0)?;
    let lib_ordinal_raw = (raw & 0xff) as u8;
    let weak = (raw & 0x100) != 0;
    let name_off = raw.wrapping_shr(9);
    let addend = read_u32_le_at(entry, 4)? as i32 as i64;
    Some((sign_extend_i8(lib_ordinal_raw), weak, name_off, addend))
}

fn decode_import_addend64(entry: &[u8]) -> Option<(i16, bool, u32, i64)> {
    // u16 lib_ordinal, u16 (weak:1, reserved:15), u32 name_offset,
    // u64 addend.
    let lib_ordinal = read_u16_le_at(entry, 0)? as i16;
    let flags = read_u16_le_at(entry, 2)?;
    let weak = (flags & 0x1) != 0;
    let name_off = read_u32_le_at(entry, 4)?;
    let addend = read_u64_le_at(entry, 8)? as i64;
    Some((lib_ordinal, weak, name_off, addend))
}

fn sign_extend_i8(raw: u8) -> i16 {
    raw as i8 as i16
}

/// Resolve a chained-fixup import name from the symbols pool.
///
/// `pool_base` is the file-relative offset of the imports' shared
/// string table (`dyld_chained_fixups_header.symbols_offset`), and
/// `name_off` is the per-import byte offset within that pool.
/// Defers to [`crate::util::read_cstr_at`] for the actual
/// NUL-terminated UTF-8 read.
fn read_pool_string(data: &[u8], pool_base: usize, name_off: u32) -> Option<&str> {
    let start = pool_base.checked_add(name_off as usize)?;
    crate::util::read_cstr_at(data, start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_format_round_trip() {
        for (raw, want) in [
            (1u16, PointerFormat::Arm64e),
            (2, PointerFormat::Ptr64),
            (6, PointerFormat::Ptr64Offset),
            (7, PointerFormat::Arm64eKernel),
            (9, PointerFormat::Arm64eUserland),
            (12, PointerFormat::Arm64eUserland24),
            (13, PointerFormat::Arm64eSharedCache),
        ] {
            assert_eq!(PointerFormat::from_raw(raw), want);
            assert!(want.is_supported());
        }
        for raw in [0u16, 3, 4, 5, 8, 10, 11, 14, 999] {
            assert_eq!(PointerFormat::from_raw(raw), PointerFormat::Other(raw));
            assert!(!PointerFormat::Other(raw).is_supported());
        }
    }

    #[test]
    fn imports_format_entry_size() {
        assert_eq!(ImportsFormat::Plain.entry_size(), Some(4));
        assert_eq!(ImportsFormat::Addend.entry_size(), Some(8));
        assert_eq!(ImportsFormat::Addend64.entry_size(), Some(16));
        assert_eq!(ImportsFormat::Other(99).entry_size(), None);
    }

    #[test]
    fn import_plain_decodes_lib_ordinal_weak_and_name_offset() {
        // lib_ordinal=1, weak=0, name_off=5 ⇒ raw = (5 << 9) | 1 = 0x0a01
        let entry = [0x01, 0x0a, 0x00, 0x00];
        let (lib, weak, name_off, addend) = decode_import_plain(&entry).unwrap();
        assert_eq!(lib, 1);
        assert!(!weak);
        assert_eq!(name_off, 5);
        assert_eq!(addend, 0);
    }

    #[test]
    fn import_plain_sign_extends_special_lib_ordinal() {
        // lib_ordinal = -2 (BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE),
        // weak = 1, name_off = 0 ⇒ raw = (0 << 9) | (1 << 8) | 0xfe
        let entry = [0xfe, 0x01, 0x00, 0x00];
        let (lib, weak, name_off, _) = decode_import_plain(&entry).unwrap();
        assert_eq!(lib, -2);
        assert!(weak);
        assert_eq!(name_off, 0);
    }

    #[test]
    fn import_addend_carries_signed_addend() {
        // plain: lib=1, weak=0, name_off=0 ⇒ 0x0001; addend = -1 (i32)
        let entry = [0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];
        let (lib, _, _, addend) = decode_import_addend(&entry).unwrap();
        assert_eq!(lib, 1);
        assert_eq!(addend, -1);
    }

    #[test]
    fn import_addend64_decodes_full_fields() {
        let mut entry = [0u8; 16];
        entry[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        entry[2..4].copy_from_slice(&0x0001u16.to_le_bytes());
        entry[4..8].copy_from_slice(&0x10u32.to_le_bytes());
        entry[8..16].copy_from_slice(&0xdead_beef_cafe_f00du64.to_le_bytes());
        let (lib, weak, name_off, addend) = decode_import_addend64(&entry).unwrap();
        assert_eq!(lib, 0x1234i16);
        assert!(weak);
        assert_eq!(name_off, 0x10);
        assert_eq!(addend as u64, 0xdead_beef_cafe_f00d);
    }

    fn empty_ctx<'a, 'b>() -> SlotCtx<'a, 'b> {
        // Defaults for unit tests that don't exercise import
        // resolution. `imports` and `dylib_names` are empty slices;
        // any bind decode will produce ("", "", false, 0).
        SlotCtx {
            image_base: 0x1_0000_0000,
            seg_index: 3,
            segment_offset: 0x80,
            vm_address: 0x1_0001_0080,
            imports: &[],
            dylib_names: &[],
        }
    }

    #[test]
    fn arm64e_unauth_rebase_arm64e_format_uses_va_directly() {
        // ARM64E (format 1): unauth rebase target is VA, not offset.
        // target=0x10004000, high8=0, next=1, bind=0, auth=0
        // Composed: target | (1 << 51) = 0x0008_0000_1000_4000.
        let slot: u64 = 0x0008_0000_1000_4000;
        let (entry, next) = decode_arm64e_slot(slot, PointerFormat::Arm64e, &empty_ctx()).unwrap();
        match entry {
            Entry::Rebase(r) => {
                assert_eq!(r.target_vmaddr(), 0x1000_4000);
                assert_eq!(r.high8(), Some(0));
                assert!(r.ptr_auth().is_none());
            }
            _ => panic!("expected rebase"),
        }
        assert_eq!(next, 1);
    }

    #[test]
    fn arm64e_unauth_rebase_userland_adds_image_base() {
        // ARM64E_USERLAND: target is image-relative offset.
        // target=0x4000 ⇒ vmaddr = image_base + 0x4000 = 0x1_0000_4000
        let slot: u64 = 0x0008_0000_0000_4000;
        let (entry, _) =
            decode_arm64e_slot(slot, PointerFormat::Arm64eUserland, &empty_ctx()).unwrap();
        match entry {
            Entry::Rebase(r) => assert_eq!(r.target_vmaddr(), 0x1_0000_4000),
            _ => panic!("expected rebase"),
        }
    }

    #[test]
    fn arm64e_auth_rebase_extracts_pac_metadata() {
        // auth_rebase: target=0x4000 (32 bits), diversity=0xBEEF,
        // addrDiv=1, key=2 (DA), next=1, bind=0, auth=1.
        // Layout (low → high):
        //   target  (0..32)   = 0x0000_4000
        //   div     (32..48)  = 0xBEEF << 32
        //   addrDiv (48)      = 1   << 48
        //   key     (49..51)  = 2   << 49 = 0b10 << 49
        //   next    (51..62)  = 1   << 51
        //   bind    (62)      = 0
        //   auth    (63)      = 1
        let slot: u64 = (0x0000_4000u64)
            | (0xBEEFu64 << 32)
            | (1u64 << 48)
            | (0b10u64 << 49)
            | (1u64 << 51)
            | (1u64 << 63);
        let (entry, next) =
            decode_arm64e_slot(slot, PointerFormat::Arm64eUserland, &empty_ctx()).unwrap();
        match entry {
            Entry::Rebase(r) => {
                let pa = r.ptr_auth().expect("auth bit set ⇒ ptr_auth Some");
                assert_eq!(pa.diversity, 0xBEEF);
                assert!(pa.addr_div);
                assert_eq!(pa.key, PacKey::DA);
                // target 0x4000 + image_base 0x1_0000_0000.
                assert_eq!(r.target_vmaddr(), 0x1_0000_4000);
                assert!(r.high8().is_none(), "auth slots have no high8");
            }
            _ => panic!("expected rebase"),
        }
        assert_eq!(next, 1);
    }

    #[test]
    fn arm64e_auth_bind_carries_pac_and_zero_addend() {
        // auth_bind: ordinal=5 (16 bits), zero=0, diversity=0,
        // addrDiv=0, key=0 (IA), next=2, bind=1, auth=1.
        let slot: u64 = 5u64 | (2u64 << 51) | (1u64 << 62) | (1u64 << 63);
        let (entry, next) =
            decode_arm64e_slot(slot, PointerFormat::Arm64eUserland, &empty_ctx()).unwrap();
        match entry {
            Entry::Bind(b) => {
                assert_eq!(b.import_ordinal(), 5);
                assert_eq!(b.addend(), 0, "auth_bind carries no slot addend");
                let pa = b.ptr_auth().unwrap();
                assert_eq!(pa.key, PacKey::IA);
            }
            _ => panic!("expected bind"),
        }
        assert_eq!(next, 2);
    }

    #[test]
    fn arm64e_userland24_bind_uses_24_bit_ordinal() {
        // bind24: ordinal=0xABCDEF (24 bits).
        let slot: u64 = 0x00ab_cdefu64 | (1u64 << 51) | (1u64 << 62);
        let (entry, _) =
            decode_arm64e_slot(slot, PointerFormat::Arm64eUserland24, &empty_ctx()).unwrap();
        match entry {
            Entry::Bind(b) => assert_eq!(b.import_ordinal(), 0x00ab_cdef),
            _ => panic!("expected bind"),
        }
    }

    #[test]
    fn arm64e_unauth_bind_addend_sign_extends_19_bits() {
        // Negative addend: -1 in 19 bits = 0x7ffff at bits 32..51.
        let slot: u64 = 1u64 | (0x7ffffu64 << 32) | (1u64 << 51) | (1u64 << 62);
        let (entry, _) =
            decode_arm64e_slot(slot, PointerFormat::Arm64eUserland, &empty_ctx()).unwrap();
        match entry {
            Entry::Bind(b) => assert_eq!(b.addend(), -1),
            _ => panic!("expected bind"),
        }
    }

    #[test]
    fn read_pool_string_truncates_at_nul_and_handles_overrun() {
        let pool = b"hello\0world\0";
        assert_eq!(read_pool_string(pool, 0, 0), Some("hello"));
        assert_eq!(read_pool_string(pool, 0, 6), Some("world"));
        // overrun ⇒ name lands at the trailing NUL, body is empty
        assert_eq!(read_pool_string(pool, 0, 11), Some(""));
        // out-of-bounds offset ⇒ None
        assert_eq!(read_pool_string(pool, 0, 999), None);
    }
}
