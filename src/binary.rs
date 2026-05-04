//! Top-level [`MachoBinary`] view.
//!
//! Wraps `goblin::mach::MachO` and exposes typed accessors over the
//! structural layer (header, segments, sections, symbols, imports,
//! exports, dylibs, load commands) plus lazy entry points into the
//! Apple-runtime walkers.
//!
//! ## Architectural decisions
//!
//! 1. [`Header::min_os`] returns a single [`MinOsVersion`], preferring
//!    `LC_BUILD_VERSION` and falling back to the legacy
//!    `LC_VERSION_MIN_*` family.
//! 2. 32-bit Mach-O images parse through the same [`MachoBinary`]
//!    type. [`Header::is_64`] reports the container width. The
//!    Obj-C / Swift runtime walkers refuse 32-bit input.
//! 3. [`MachoBinary::fat_arch_count`] returns `1` for thin images
//!    (a thin binary is logically one slice).
//! 4. The on-disk `LC_SOURCE_VERSION` encoding
//!    (`a24.b10.c10.d10.e10` packed into u64) does not fit a
//!    3-component shape, so the public API exposes a distinct
//!    [`SourceVersion`] type instead of [`Version`].

use core::convert::TryFrom;

use goblin::mach::{
    Mach, MachO,
    load_command::{
        CommandVariant, LinkeditDataCommand, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_MACOSX,
        LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS, PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS,
        PLATFORM_WATCHOS,
    },
};

use core::marker::PhantomData;

use crate::{
    block::BlockRuntime,
    cfstring::CFStringRuntime,
    codesign::Signature,
    dylib::{DylibIter, LoadCommandIter},
    error::{Error, Result},
    export::ExportIter,
    fixup::{
        build_bind_iter, build_rebase_iter, BindIter, ChainedFixups, ChainedImport, RebaseIter,
        SegmentLoc,
    },
    import::{Import, ImportIter},
    objc::ObjcRuntime,
    segment::{SectionIter, SegmentIter},
    swift::SwiftRuntime,
    symbol::SymbolIter,
    util::{read_u32_le_at, read_uleb128, vm_to_file_offset_in},
};

const SIZEOF_BUILD_VERSION_COMMAND: usize = 24;
const SIZEOF_BUILD_TOOL_VERSION: usize = 8;

/// Sentinel `cpusubtype` accepted by [`MachoBinary::parse_with_arch`]
/// to mean "any subtype of the requested `cputype`".
///
/// Mirrors the `CPU_SUBTYPE_ANY` convention used by `lipo` and
/// `dyld`, where `-1` (i.e. `0xffff_ffff` re-interpreted as `i32`)
/// selects the architecture without further refinement.
pub const CPU_SUBTYPE_ANY: u32 = u32::MAX;

/// A parsed Mach-O image.
///
/// Construction is cheap — `parse` only does the structural decode
/// goblin requires; the runtime walkers (objc / swift) are computed
/// on-demand when their accessors are called.
///
/// For a fat (universal) wrapper, [`parse`](Self::parse) selects the
/// first slice that decodes successfully; use
/// [`parse_with_arch`](Self::parse_with_arch) to pick a specific
/// `cputype` / `cpusubtype` pair.
#[derive(Debug)]
pub struct MachoBinary<'a> {
    data: &'a [u8],
    macho: MachO<'a>,
    fat_arch_count: u32,

    // Absorbed metadata. Walked once in `new` and held by value so
    // `Header` accessors don't have to re-traverse `load_commands`
    // on every call.
    uuid: Option<[u8; 16]>,
    min_os: Option<MinOsVersion>,
    sdk_version: Option<Version>,
    source_version: Option<SourceVersion>,
    build_tools: Vec<BuildTool>,
    dylinker: Option<&'a str>,
    function_starts_cmd: Option<LinkeditDataCommand>,
    function_starts_count: Option<u32>,
    chained_fixups_cmd: Option<LinkeditDataCommand>,
    code_signature_cmd: Option<LinkeditDataCommand>,
}

impl<'a> MachoBinary<'a> {
    /// Parses a Mach-O byte slice.
    ///
    /// For fat (universal) wrappers, returns the first successfully
    /// decoded Mach-O slice. Use [`parse_with_arch`] to pick a
    /// specific CPU type / subtype.
    ///
    /// [`parse_with_arch`]: Self::parse_with_arch
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Self::parse_predicate(data, |_, _| true)
    }

    /// Parses a specific architecture slice from a Mach-O byte
    /// slice.
    ///
    /// `cpusubtype` may be [`CPU_SUBTYPE_ANY`] to match any subtype
    /// of the requested `cputype`. The CPU subtype mask
    /// (`CPU_SUBTYPE_MASK`) is stripped before comparison so callers
    /// don't have to think about the high bits.
    ///
    /// For thin binaries the call succeeds iff the requested arch
    /// matches the single slice; otherwise [`Error::NoMatchingArchSlice`]
    /// is returned.
    pub fn parse_with_arch(data: &'a [u8], cputype: u32, cpusubtype: u32) -> Result<Self> {
        Self::parse_predicate(data, |actual_cputype, actual_subtype| {
            arch_matches(actual_cputype, actual_subtype, cputype, cpusubtype)
        })
    }

    /// Internal: parse the input, picking the first arch that
    /// satisfies `pred`. Centralises the fat / thin handling and —
    /// crucially — wires `MachoBinary.data` to the *slice's* bytes,
    /// not the surrounding fat archive, so segment file offsets
    /// translate correctly.
    fn parse_predicate(
        data: &'a [u8],
        pred: impl Fn(u32, u32) -> bool,
    ) -> Result<Self> {
        match Mach::parse(data)? {
            Mach::Binary(macho) => {
                if pred(macho.header.cputype, macho.header.cpusubtype) {
                    Ok(Self::new(data, macho, 1))
                } else {
                    Err(Error::NoMatchingArchSlice)
                }
            }
            Mach::Fat(multi) => {
                let fat_count = u32_from_usize(multi.narches)?;
                for arch in multi.iter_arches() {
                    let Ok(arch) = arch else { continue };
                    let slice_bytes = arch.slice(data);
                    if slice_bytes.is_empty() {
                        continue;
                    }
                    let Ok(macho) = MachO::parse(slice_bytes, 0) else {
                        continue;
                    };
                    if pred(macho.header.cputype, macho.header.cpusubtype) {
                        return Ok(Self::new(slice_bytes, macho, fat_count));
                    }
                }
                Err(Error::NoMatchingArchSlice)
            }
        }
    }

    fn new(data: &'a [u8], macho: MachO<'a>, fat_arch_count: u32) -> Self {
        let mut uuid = None;
        let mut min_os: Option<MinOsVersion> = None;
        let mut sdk_version: Option<Version> = None;
        let mut source_version = None;
        let mut build_tools: Vec<BuildTool> = Vec::new();
        let mut dylinker = None;
        let mut function_starts_cmd = None;
        let mut chained_fixups_cmd = None;
        let mut code_signature_cmd = None;

        for lc in &macho.load_commands {
            match &lc.command {
                CommandVariant::Uuid(c) => {
                    uuid = Some(c.uuid);
                }
                CommandVariant::BuildVersion(c) => {
                    // LC_BUILD_VERSION wins over any LC_VERSION_MIN_*.
                    min_os = Some(MinOsVersion {
                        platform: c.platform,
                        version: Version::from_packed_u32(c.minos),
                    });
                    sdk_version = Some(Version::from_packed_u32(c.sdk));

                    // The `BuildToolVersion[ntools]` array follows
                    // the 24-byte BuildVersionCommand inline at
                    // lc.offset.
                    let Some(base) = lc.offset.checked_add(SIZEOF_BUILD_VERSION_COMMAND) else {
                        continue;
                    };
                    for i in 0..(c.ntools as usize) {
                        let Some(stride) = i.checked_mul(SIZEOF_BUILD_TOOL_VERSION) else {
                            break;
                        };
                        let Some(off) = base.checked_add(stride) else {
                            break;
                        };
                        let Some(off_ver) = off.checked_add(4) else {
                            break;
                        };
                        let (Some(tool), Some(version_packed)) =
                            (read_u32_le_at(data, off), read_u32_le_at(data, off_ver))
                        else {
                            break;
                        };
                        build_tools.push(BuildTool {
                            tool,
                            version: Version::from_packed_u32(version_packed),
                        });
                    }
                }
                CommandVariant::VersionMinMacosx(c)
                | CommandVariant::VersionMinIphoneos(c)
                | CommandVariant::VersionMinTvos(c)
                | CommandVariant::VersionMinWatchos(c) => {
                    if min_os.is_none() {
                        let platform = match c.cmd {
                            LC_VERSION_MIN_MACOSX => PLATFORM_MACOS,
                            LC_VERSION_MIN_IPHONEOS => PLATFORM_IOS,
                            LC_VERSION_MIN_TVOS => PLATFORM_TVOS,
                            LC_VERSION_MIN_WATCHOS => PLATFORM_WATCHOS,
                            _ => 0,
                        };
                        min_os = Some(MinOsVersion {
                            platform,
                            version: Version::from_packed_u32(c.version),
                        });
                    }
                    if sdk_version.is_none() && c.sdk != 0 {
                        sdk_version = Some(Version::from_packed_u32(c.sdk));
                    }
                }
                CommandVariant::SourceVersion(c) => {
                    source_version = Some(SourceVersion::from_packed_u64(c.version));
                }
                CommandVariant::LoadDylinker(c) => {
                    let name_off = c.name as usize;
                    let cmdsize = lc.command.cmdsize();
                    if let (Some(off), Some(end)) = (
                        lc.offset.checked_add(name_off),
                        lc.offset.checked_add(cmdsize),
                    ) {
                        if let Some(s) = read_lc_str(data, off, end) {
                            dylinker = Some(s);
                        }
                    }
                }
                CommandVariant::FunctionStarts(c) => {
                    function_starts_cmd = Some(*c);
                }
                CommandVariant::DyldChainedFixups(c) => {
                    chained_fixups_cmd = Some(*c);
                }
                CommandVariant::CodeSignature(c) => {
                    code_signature_cmd = Some(*c);
                }
                _ => {}
            }
        }

        let mut bin = Self {
            data,
            macho,
            fat_arch_count,
            uuid,
            min_os,
            sdk_version,
            source_version,
            build_tools,
            dylinker,
            function_starts_cmd,
            function_starts_count: None,
            chained_fixups_cmd,
            code_signature_cmd,
        };
        // Pre-walk the function-starts stream so Header can answer
        // `function_starts_count()` cheaply.
        bin.function_starts_count = bin
            .function_starts_cmd
            .map(|_| u32::try_from(bin.function_starts().count()).unwrap_or(u32::MAX));
        bin
    }

    /// Number of architecture slices in the originating fat
    /// container. For thin binaries this is `1`.
    pub fn fat_arch_count(&self) -> u32 {
        self.fat_arch_count
    }

    /// Returns the on-disk bytes that back this Mach-O slice.
    ///
    /// For thin binaries this is the same byte slice the caller
    /// passed to [`parse`](Self::parse). For fat (universal)
    /// wrappers it is *just* the bytes of the selected
    /// architecture slice — segment / section file offsets
    /// translate inside this slice, not inside the surrounding
    /// fat archive.
    ///
    /// Escape hatch for callers that need ungated access (e.g. to
    /// compute a digest over the file image). Most consumers should
    /// prefer the higher-level accessors.
    pub fn raw(&self) -> &'a [u8] {
        self.data
    }

    /// Iterator over `LC_SEGMENT` / `LC_SEGMENT_64` load commands
    /// in load-command order.
    pub fn segments(&self) -> SegmentIter<'a, '_> {
        SegmentIter::new(&self.macho.segments)
    }

    /// Iterator flattening every section across every segment.
    ///
    /// Order is segment-major, section-minor — matching `otool -l`
    /// output. Use [`segments`](Self::segments) and per-segment
    /// `Segment::sections` if you need to keep the segment
    /// hierarchy.
    pub fn sections(&self) -> SectionIter<'a, '_> {
        SectionIter::new(&self.macho.segments)
    }

    /// Iterator over the `LC_SYMTAB` nlist symbol table.
    ///
    /// Returns the empty iterator when the binary has no
    /// `LC_SYMTAB` (heavily stripped releases) or when goblin
    /// failed to decode it.
    pub fn symbols(&self) -> SymbolIter<'a, '_> {
        SymbolIter::new(self.macho.symbols.as_ref().map(|s| s.into_iter()))
    }

    /// Iterator over `LC_LOAD_*_DYLIB` dependencies.
    ///
    /// Excludes `LC_ID_DYLIB` (the binary's own install_name —
    /// not a dependency).
    pub fn dylibs(&self) -> DylibIter<'a, '_> {
        DylibIter::new(self.data, &self.macho.load_commands)
    }

    /// Iterator over every load command, in load-command order.
    ///
    /// Each yielded entry carries the `LC_*` id, byte offset,
    /// `cmdsize`, and a slice over the raw bytes — useful for
    /// auditing what the linker put in the image without going
    /// through goblin directly.
    pub fn load_commands(&self) -> LoadCommandIter<'a, '_> {
        LoadCommandIter::new(self.data, &self.macho.load_commands)
    }

    /// Iterator over the VM addresses encoded in `LC_FUNCTION_STARTS`.
    ///
    /// The on-disk encoding is a ULEB128 stream of *deltas* from a
    /// running address that starts at the first `__TEXT` segment's
    /// `vmaddr`; a delta of zero terminates the stream. This
    /// iterator yields each absolute address in turn.
    ///
    /// Returns the empty iterator when the binary has no
    /// `LC_FUNCTION_STARTS`, when the data slice is out of bounds,
    /// or when no `__TEXT` segment is present.
    pub fn function_starts(&self) -> FunctionStartIter<'a, '_> {
        let Some(cmd) = self.function_starts_cmd else {
            return FunctionStartIter::empty();
        };
        let dataoff = cmd.dataoff as usize;
        let datasize = cmd.datasize as usize;
        let Some(end) = dataoff.checked_add(datasize) else {
            return FunctionStartIter::empty();
        };
        let Some(stream) = self.data.get(dataoff..end) else {
            return FunctionStartIter::empty();
        };
        let Some(text_vmaddr) = self
            .macho
            .segments
            .iter()
            .find(|s| &s.segname[..7] == b"__TEXT\0")
            .map(|s| s.vmaddr)
        else {
            return FunctionStartIter::empty();
        };
        FunctionStartIter {
            stream,
            cursor: 0,
            running: text_vmaddr,
            done: false,
            _parent: PhantomData,
        }
    }

    /// Iterator over exports — symbols this image publishes to dyld.
    ///
    /// Walks both `LC_DYLD_EXPORTS_TRIE` (modern, standalone) and
    /// `LC_DYLD_INFO[_ONLY].export_*` (legacy). Returns the empty
    /// iterator when neither is present or when the trie failed to
    /// decode.
    pub fn exports(&self) -> ExportIter<'_> {
        let items = self.macho.exports().unwrap_or_default();
        ExportIter::new(items)
    }

    /// Iterator over dyld bind targets (imports).
    ///
    /// Folds two on-disk encodings into a single sequence:
    ///
    /// 1. **Legacy** `LC_DYLD_INFO[_ONLY]` bind-opcode rows
    ///    (decoded by goblin).
    /// 2. **Chained** binds from `LC_DYLD_CHAINED_FIXUPS` (decoded
    ///    in-house by [`crate::fixup`]).
    ///
    /// Order: legacy first, then chained. Real binaries ship
    /// exactly one encoding (never both), so consumers can treat
    /// the iterator as a flat list without dispatching on which
    /// encoding produced each row.
    pub fn imports(&self) -> ImportIter<'_> {
        let mut all: Vec<Import<'_>> = Vec::new();
        if let Ok(items) = self.macho.imports() {
            for g in items {
                all.push(Import {
                    name: g.name,
                    dylib: g.dylib,
                    is_lazy: g.is_lazy,
                    is_weak: g.is_weak,
                    offset: g.offset,
                    size: g.size,
                    address: g.address,
                    addend: g.addend,
                    bind_offset: g.start_of_sequence_offset,
                });
            }
        }
        for b in self.chained_binds() {
            let offset = self.vm_to_file_offset(b.vm_address()).unwrap_or(0);
            all.push(Import {
                name: b.name(),
                dylib: b.dylib(),
                // Chained binds are non-lazy by construction —
                // dyld resolves the entire chain at fix-up time.
                is_lazy: false,
                is_weak: b.is_weak(),
                offset,
                size: 8,
                address: b.vm_address(),
                addend: b.addend(),
                bind_offset: 0,
            });
        }
        ImportIter::new(all)
    }

    /// Decoded `LC_DYLD_CHAINED_FIXUPS` walker, if the load command
    /// is present and the header passes structural sanity checks.
    ///
    /// The walker exposes the per-segment chain-start blocks
    /// ([`ChainedFixups::segments`]) and the imports table
    /// ([`ChainedFixups::imports`]). Per-page chain walking and
    /// individual `Rebase` / `Bind` rows are added in subsequent
    /// PRs.
    ///
    /// Returns `None` for binaries that use the legacy
    /// `LC_DYLD_INFO[_ONLY]` bind-opcode encoding instead.
    pub fn chained_fixups(&self) -> Option<ChainedFixups<'a>> {
        let cmd = self.chained_fixups_cmd?;
        ChainedFixups::parse(self.data, cmd.dataoff as usize, cmd.datasize as usize)
    }

    /// Iterator over chained-fixup rebases (in-image pointer
    /// slides), walked across every segment that participates in
    /// chained fixups.
    ///
    /// Empty when [`chained_fixups`](Self::chained_fixups) returns
    /// `None` or when every segment uses an unsupported pointer
    /// format. Pointer formats outside the v0.1 supported set
    /// fail-soft per [`PointerFormat::Other`](crate::fixup::PointerFormat::Other).
    pub fn chained_rebases(&self) -> RebaseIter<'a> {
        let Some(cf) = self.chained_fixups() else {
            return RebaseIter::empty();
        };
        let (locs, image_base) = self.collect_chained_segments(&cf);
        if locs.is_empty() {
            return RebaseIter::empty();
        }
        build_rebase_iter(self.data, &cf, &locs, image_base)
    }

    /// Iterator over chained-fixup binds (dyld-resolved imports),
    /// walked across every segment that participates in chained
    /// fixups.
    ///
    /// Empty when [`chained_fixups`](Self::chained_fixups) returns
    /// `None` or when no chain entries are bind rows. The merge of
    /// legacy + chained binds into [`imports`](Self::imports)
    /// lands in PR 11.
    pub fn chained_binds(&self) -> BindIter<'a> {
        let Some(cf) = self.chained_fixups() else {
            return BindIter::empty();
        };
        let (locs, image_base) = self.collect_chained_segments(&cf);
        if locs.is_empty() {
            return BindIter::empty();
        }
        let imports: Vec<ChainedImport<'a>> = cf.imports().collect();
        let dylib_names: Vec<&'a str> = self.dylibs().map(|d| d.name).collect();
        build_bind_iter(self.data, &cf, &locs, image_base, &imports, &dylib_names)
    }

    /// Embedded code-signature SuperBlob, if `LC_CODE_SIGNATURE` is
    /// present and the SuperBlob magic matches.
    ///
    /// Returns `None` for unsigned binaries and for binaries whose
    /// SuperBlob is malformed (wrong magic / truncated header).
    pub fn signature(&self) -> Option<Signature<'a>> {
        let cmd = self.code_signature_cmd?;
        Signature::parse(self.data, cmd.dataoff as usize)
    }

    /// Aggregate Objective-C runtime walker.
    ///
    /// Returns `None` when the image carries no ObjC content
    /// (`__objc_imageinfo` missing) or when the slice is 32-bit —
    /// the v0.1 Obj-C walker is 64-bit only.
    ///
    /// On success the returned [`ObjcRuntime`] owns parsed-once
    /// metadata (image info, cached section lookups, segment table
    /// for VA translation, chained-fixup bind index) so iterators
    /// can drain it independently of the originating
    /// [`MachoBinary`] borrow.
    pub fn objc(&self) -> Option<ObjcRuntime<'a>> {
        ObjcRuntime::build(self)
    }

    /// Aggregate `__cfstring` walker.
    ///
    /// Returns `None` when the image carries no `__cfstring` section
    /// (no CoreFoundation constant strings emitted) or when the
    /// slice is 32-bit — the v0.1 walker is 64-bit only.
    ///
    /// On success the returned [`CFStringRuntime`]
    /// owns parsed-once metadata (section body, segment table for VA
    /// translation, chained-fixup rebase index) so the iterator can
    /// drain it independently of the originating [`MachoBinary`]
    /// borrow.
    pub fn cfstrings(&self) -> Option<CFStringRuntime<'a>> {
        CFStringRuntime::build(self)
    }

    /// Aggregate Apple Blocks-runtime walker.
    ///
    /// Returns `None` when the image binds neither
    /// `_NSConcreteGlobalBlock` nor `_NSConcreteStackBlock` (i.e.
    /// makes no use of the Blocks runtime) or when the slice is
    /// 32-bit — the v0.1 walker is 64-bit only.
    ///
    /// On success the returned [`BlockRuntime`]
    /// owns parsed-once metadata (bind site index, segment table,
    /// chained-fixup rebase index) so iterators can drain it
    /// independently of the originating [`MachoBinary`] borrow.
    pub fn blocks(&self) -> Option<BlockRuntime<'a>> {
        BlockRuntime::build(self)
    }

    /// Aggregate Swift 5 runtime walker.
    ///
    /// Returns `None` when the image carries no Swift content
    /// (none of `__swift5_types`, `__swift5_protos`, `__swift5_proto`,
    /// `__swift5_fieldmd` is present) or when the slice is 32-bit —
    /// the v0.1 Swift walker is 64-bit only.
    ///
    /// On success the returned [`SwiftRuntime`]
    /// owns parsed-once metadata (cached section lookups, segment
    /// table for VA translation, chained-fixup rebase / bind
    /// indices) so iterators can drain it independently of the
    /// originating [`MachoBinary`] borrow.
    pub fn swift(&self) -> Option<SwiftRuntime<'a>> {
        SwiftRuntime::build(self)
    }

    /// Build the per-segment chain-walk context (chained metadata
    /// joined with the binary's runtime segment fields) and return
    /// it together with the computed `image_base`.
    fn collect_chained_segments(&self, cf: &ChainedFixups<'a>) -> (Vec<SegmentLoc>, u64) {
        // Image base = lowest vmaddr of any segment with non-zero
        // file size (`__PAGEZERO` is excluded since its filesize
        // is 0). dyld uses this as the load-address baseline for
        // `_OFFSET` chained-pointer formats.
        let image_base = self
            .macho
            .segments
            .iter()
            .filter(|s| s.filesize > 0)
            .map(|s| s.vmaddr)
            .min()
            .unwrap_or(0);

        let segs: Vec<_> = self.macho.segments.iter().collect();
        let mut out: Vec<SegmentLoc> = Vec::new();
        for chained in cf.segments() {
            let idx = chained.seg_index as usize;
            let Some(seg) = segs.get(idx) else { continue };
            out.push(SegmentLoc {
                chained,
                vmaddr: seg.vmaddr,
                fileoff: seg.fileoff,
                filesize: seg.filesize,
            });
        }
        (out, image_base)
    }

    /// Translate a virtual-memory address to its on-disk file
    /// offset.
    ///
    /// Returns `None` if no segment covers the address, if the
    /// covering segment has no on-disk backing (`__PAGEZERO`,
    /// BSS-only mappings), or if the address falls in the BSS tail
    /// of a partially-on-disk segment.
    pub fn vm_to_file_offset(&self, vmaddr: u64) -> Option<u64> {
        vm_to_file_offset_in(
            self.macho
                .segments
                .iter()
                .map(|s| (s.vmaddr, s.vmsize, s.fileoff, s.filesize)),
            vmaddr,
        )
    }

    /// View over the `mach_header` plus absorbed metadata
    /// (`LC_UUID`, `LC_BUILD_VERSION` / `LC_VERSION_MIN_*`,
    /// `LC_SOURCE_VERSION`, `LC_LOAD_DYLINKER`, `LC_FUNCTION_STARTS`
    /// presence).
    pub fn header(&self) -> Header<'_> {
        Header {
            raw: &self.macho.header,
            is_64: self.macho.is_64,
            uuid: self.uuid,
            min_os: self.min_os,
            sdk_version: self.sdk_version,
            source_version: self.source_version,
            build_tools: &self.build_tools,
            dylinker: self.dylinker,
            function_starts_count: self.function_starts_count,
        }
    }
}

/// Iterator over absolute VM addresses encoded in
/// `LC_FUNCTION_STARTS`.
pub struct FunctionStartIter<'a, 'p> {
    stream: &'a [u8],
    cursor: usize,
    running: u64,
    done: bool,
    _parent: PhantomData<&'p ()>,
}

impl<'a, 'p> FunctionStartIter<'a, 'p> {
    fn empty() -> Self {
        Self {
            stream: &[],
            cursor: 0,
            running: 0,
            done: true,
            _parent: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for FunctionStartIter<'a, 'p> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.done {
            return None;
        }
        let remaining = self.stream.get(self.cursor..)?;
        let (delta, used) = read_uleb128(remaining)?;
        if delta == 0 {
            // Terminator. Mark done so subsequent calls keep
            // returning None instead of looping on truncated trailing
            // padding bytes.
            self.done = true;
            return None;
        }
        let new_cursor = self.cursor.checked_add(used)?;
        let new_running = self.running.checked_add(delta)?;
        self.cursor = new_cursor;
        self.running = new_running;
        Some(self.running)
    }
}

/// View over the Mach-O `mach_header` plus a small set of metadata
/// load commands "absorbed" into the header for caller convenience.
///
/// Returned by [`MachoBinary::header`]. The lifetime parameter is
/// the `&MachoBinary` borrow; absorbed `&str` and slice fields
/// reborrow from the binary's data lifetime, which strictly outlives
/// the borrow.
#[derive(Debug)]
pub struct Header<'p> {
    raw: &'p goblin::mach::header::Header,
    is_64: bool,
    uuid: Option<[u8; 16]>,
    min_os: Option<MinOsVersion>,
    sdk_version: Option<Version>,
    source_version: Option<SourceVersion>,
    build_tools: &'p [BuildTool],
    dylinker: Option<&'p str>,
    function_starts_count: Option<u32>,
}

impl<'p> Header<'p> {
    /// `mach_header.magic` — one of `MH_MAGIC`, `MH_MAGIC_64`,
    /// `MH_CIGAM`, `MH_CIGAM_64`.
    pub fn magic(&self) -> u32 {
        self.raw.magic
    }

    /// `mach_header.cputype` (e.g. `CPU_TYPE_ARM64 = 0x0100_000c`).
    pub fn cputype(&self) -> u32 {
        self.raw.cputype
    }

    /// `mach_header.cpusubtype`. The `CPU_SUBTYPE_MASK` high bits
    /// (capabilities, e.g. `CPU_SUBTYPE_LIB64`) are preserved.
    pub fn cpusubtype(&self) -> u32 {
        self.raw.cpusubtype
    }

    /// `mach_header.filetype` (`MH_EXECUTE`, `MH_DYLIB`,
    /// `MH_BUNDLE`, …).
    pub fn filetype(&self) -> u32 {
        self.raw.filetype
    }

    /// Number of load commands. Preserved from the on-disk u32
    /// field even though goblin internally widens it to usize.
    pub fn ncmds(&self) -> u32 {
        // ncmds came from a u32 in `mach_header_64` and is bounded
        // by `sizeofcmds / 8` in goblin's parser, so the cast can
        // never truncate.
        self.raw.ncmds as u32
    }

    /// Size in bytes of the load-command area following the header.
    pub fn sizeofcmds(&self) -> u32 {
        self.raw.sizeofcmds
    }

    /// `mach_header.flags` (`MH_*`).
    pub fn flags(&self) -> u32 {
        self.raw.flags
    }

    /// `mach_header_64.reserved` (always 0 in current toolchains;
    /// 0 for 32-bit images, which lack the field).
    pub fn reserved(&self) -> u32 {
        self.raw.reserved
    }

    /// Whether the underlying container is 64-bit
    /// (`MH_MAGIC_64` / `MH_CIGAM_64`).
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// The 128-bit `LC_UUID`, if present.
    pub fn uuid(&self) -> Option<[u8; 16]> {
        self.uuid
    }

    /// Minimum OS version this image targets.
    ///
    /// Prefers `LC_BUILD_VERSION` (modern) and falls back to
    /// `LC_VERSION_MIN_*` (legacy). Only the *first* match wins —
    /// images authored before `LC_BUILD_VERSION` exists must use the
    /// legacy commands and are surfaced verbatim.
    pub fn min_os(&self) -> Option<MinOsVersion> {
        self.min_os
    }

    /// SDK version this image was built against, sourced from
    /// `LC_BUILD_VERSION.sdk` or `LC_VERSION_MIN_*.sdk`.
    pub fn sdk_version(&self) -> Option<Version> {
        self.sdk_version
    }

    /// `LC_SOURCE_VERSION`, if present. The 5-component packed
    /// encoding does not fit [`Version`]; see [`SourceVersion`].
    pub fn source_version(&self) -> Option<SourceVersion> {
        self.source_version
    }

    /// Build tools recorded by `LC_BUILD_VERSION`. Empty when the
    /// image only carries legacy `LC_VERSION_MIN_*` or has neither.
    pub fn build_tools(&self) -> &'p [BuildTool] {
        self.build_tools
    }

    /// `LC_LOAD_DYLINKER` path (typically `/usr/lib/dyld`).
    pub fn dylinker(&self) -> Option<&'p str> {
        self.dylinker
    }

    /// Number of function entry points encoded in
    /// `LC_FUNCTION_STARTS`, if the load command is present.
    ///
    /// Returns `None` when the load command is absent. The count is
    /// computed once at parse time (by walking the ULEB128 stream)
    /// and cached on the [`MachoBinary`]; use
    /// [`MachoBinary::function_starts`] to enumerate the addresses
    /// themselves.
    pub fn function_starts_count(&self) -> Option<u32> {
        self.function_starts_count
    }
}

/// Minimum OS version recorded in `LC_BUILD_VERSION` or
/// `LC_VERSION_MIN_*`.
///
/// `platform` is one of the `goblin::mach::load_command::PLATFORM_*`
/// constants — `1` (`PLATFORM_MACOS`), `2` (`PLATFORM_IOS`), …,
/// `11` (`PLATFORM_VISIONOS`). The legacy `LC_VERSION_MIN_*`
/// commands have no on-disk platform field; this crate synthesises
/// it from the load-command code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinOsVersion {
    /// `PLATFORM_*` value.
    pub platform: u32,
    /// Decoded `major.minor.patch`.
    pub version: Version,
}

/// Three-component version (`xxxx.yy.zz`) packed into 32 bits.
///
/// On-disk layout: `major` in the high 16 bits, `minor` in the next
/// 8, `patch` in the low 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// `major` (high 16 bits).
    pub major: u16,
    /// `minor` (next 8 bits).
    pub minor: u8,
    /// `patch` (low 8 bits).
    pub patch: u8,
}

impl Version {
    /// Decodes the standard `xxxx.yy.zz` Mach-O packed-u32 layout.
    pub fn from_packed_u32(v: u32) -> Self {
        // wrapping_shr keeps clippy::arithmetic_side_effects happy;
        // the shift amounts (16, 8) are constant and below 32 so
        // wrapping is observationally equivalent to a plain shift.
        Self {
            major: v.wrapping_shr(16) as u16,
            minor: v.wrapping_shr(8) as u8,
            patch: v as u8,
        }
    }
}

/// Five-component version recorded in `LC_SOURCE_VERSION`.
///
/// On-disk layout: `A.B.C.D.E` packed as `a24.b10.c10.d10.e10` into
/// a `u64`. The field is treated by Apple's toolchain as a freeform
/// build/source identifier and is *not* the SDK or min-OS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceVersion {
    /// High 24 bits.
    pub a: u32,
    /// Next 10 bits.
    pub b: u16,
    /// Next 10 bits.
    pub c: u16,
    /// Next 10 bits.
    pub d: u16,
    /// Low 10 bits.
    pub e: u16,
}

impl SourceVersion {
    /// Decodes the `a24.b10.c10.d10.e10` packed-u64 layout.
    pub fn from_packed_u64(v: u64) -> Self {
        // Constant shift amounts < 64; wrapping_shr is exact.
        Self {
            a: (v.wrapping_shr(40) & 0x00ff_ffff) as u32,
            b: (v.wrapping_shr(30) & 0x3ff) as u16,
            c: (v.wrapping_shr(20) & 0x3ff) as u16,
            d: (v.wrapping_shr(10) & 0x3ff) as u16,
            e: (v & 0x3ff) as u16,
        }
    }
}

/// One entry of the `BuildToolVersion[]` array trailing
/// `LC_BUILD_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildTool {
    /// `TOOL_*` value (`TOOL_CLANG = 1`, `TOOL_SWIFT = 2`,
    /// `TOOL_LD = 3`, `TOOL_LLD = 4`).
    pub tool: u32,
    /// Tool version, decoded from the `xxxx.yy.zz` packed-u32 layout.
    pub version: Version,
}

fn arch_matches(actual_cputype: u32, actual_subtype: u32, want_cputype: u32, want_subtype: u32) -> bool {
    if actual_cputype != want_cputype {
        return false;
    }
    if want_subtype == CPU_SUBTYPE_ANY {
        return true;
    }
    // Strip the high `CPU_SUBTYPE_MASK` capability bits before
    // comparing — callers typically pass plain subtypes.
    const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
    (actual_subtype & !CPU_SUBTYPE_MASK) == (want_subtype & !CPU_SUBTYPE_MASK)
}

fn u32_from_usize(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| Error::Structural(format!("count {n} exceeds u32")))
}

/// Read a NUL-terminated `LcStr` body. `off` is the absolute byte
/// offset into `data` where the string begins; `end` is the
/// load-command boundary so we don't run off the edge on malformed
/// input.
pub(crate) fn read_lc_str(data: &[u8], off: usize, end: usize) -> Option<&str> {
    let limit = end.min(data.len());
    let slice = data.get(off..limit)?;
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let body = slice.get(..len)?;
    core::str::from_utf8(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_packed_decodes_max_minor_patch() {
        // 14.5.2 → 0x000e_0502
        let v = Version::from_packed_u32(0x000e_0502);
        assert_eq!(v.major, 14);
        assert_eq!(v.minor, 5);
        assert_eq!(v.patch, 2);
    }

    #[test]
    fn version_from_packed_handles_high_major() {
        // 26.4.0 — the kind of value modern Xcode emits.
        let v = Version::from_packed_u32(0x001a_0400);
        assert_eq!(v.major, 26);
        assert_eq!(v.minor, 4);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn version_from_packed_zero() {
        let v = Version::from_packed_u32(0);
        assert_eq!((v.major, v.minor, v.patch), (0, 0, 0));
    }

    #[test]
    fn source_version_round_trip_packed_u64() {
        // a=0xABCDEF (24-bit), b=0x123, c=0x234, d=0x345, e=0x3FF
        let packed: u64 = (0x00AB_CDEFu64 << 40)
            | (0x123u64 << 30)
            | (0x234u64 << 20)
            | (0x345u64 << 10)
            | 0x3FFu64;
        let sv = SourceVersion::from_packed_u64(packed);
        assert_eq!(sv.a, 0x00AB_CDEF);
        assert_eq!(sv.b, 0x123);
        assert_eq!(sv.c, 0x234);
        assert_eq!(sv.d, 0x345);
        assert_eq!(sv.e, 0x3FF);
    }

    #[test]
    fn arch_matches_strips_subtype_capability_bits() {
        // CPU_SUBTYPE_MASK = 0xff00_0000.
        const ARM64: u32 = 0x0100_000c;
        // Want subtype 0 (ARM64_ALL); actual carries lib64 capability bit.
        assert!(arch_matches(ARM64, 0x8100_0000, ARM64, 0));
        // Mismatching cputypes always reject.
        assert!(!arch_matches(ARM64, 0, 0x0100_0007, 0));
        // CPU_SUBTYPE_ANY accepts any subtype.
        assert!(arch_matches(ARM64, 0xdead_beef, ARM64, CPU_SUBTYPE_ANY));
    }

    #[test]
    fn read_lc_str_truncates_at_nul() {
        let data = b"abc\0def";
        assert_eq!(read_lc_str(data, 0, data.len()), Some("abc"));
    }

    #[test]
    fn read_lc_str_respects_end_limit() {
        let data = b"abcdefghi";
        // No NUL — entire window returned.
        assert_eq!(read_lc_str(data, 0, 5), Some("abcde"));
    }

    #[test]
    fn read_lc_str_out_of_range_returns_none() {
        let data = b"abc";
        // off > data.len(): get() returns None.
        assert_eq!(read_lc_str(data, 99, 200), None);
    }
}
