//! Exports — symbols this image makes available to other dylibs.
//!
//! Walks both the modern `LC_DYLD_EXPORTS_TRIE` (linkedit-data
//! command pointing at a standalone trie) and the legacy
//! `LC_DYLD_INFO[_ONLY].export_*` pair. Goblin handles both behind
//! the same trie walker, so this module simply adapts the result
//! to the crate's typed view-type pattern.
//!
//! Names are reconstructed from trie edges and therefore *owned*
//! `String`s rather than borrowed slices — the trie does not
//! preserve a contiguous range of bytes for each export name.
//!
//! ## Lifetime parameter
//!
//! Like [`crate::import`], this module collapses the kickoff's
//! `Export<'a, 'p>` sketch to a single `'p` — see that module's
//! doc-comment for the underlying reason (goblin ties the strings
//! to the `&self` borrow rather than to the data lifetime).

use goblin::mach::exports::{
    EXPORT_SYMBOL_FLAGS_KIND_MASK, EXPORT_SYMBOL_FLAGS_REEXPORT, EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
    EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, Export as GoblinExport, ExportInfo as GoblinExportInfo,
};

/// View over a single exported symbol resolved from the export trie.
#[derive(Debug)]
pub struct Export<'p> {
    /// Mangled symbol name (as `dyld` matches it).
    pub name: String,
    /// Symbol kind — regular, absolute, thread-local, or unknown.
    pub kind: ExportKind,
    /// Raw `EXPORT_SYMBOL_FLAGS_*` byte from the trie node.
    pub flags: u64,
    /// Whether `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION` is set.
    pub is_weak_definition: bool,
    /// Detailed payload depending on the kind / flags.
    pub info: ExportInfo<'p>,
    /// Offset / address recorded for this export — VM address for
    /// `Regular`, image-relative stub offset for `Stub`, `0` for
    /// `Reexport`.
    pub offset: u64,
}

/// Trie-node kind extracted from the low two bits of the flags
/// (`EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03`).
///
/// Cite: `mach-o/loader.h:1494-1503` (`EXPORT_SYMBOL_FLAGS_KIND_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// `EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00` — an ordinary
    /// function or data symbol whose body lives at a VM address in
    /// this image. The vast majority of trie entries are this kind.
    Regular,
    /// `EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02` — an absolute
    /// constant (e.g. `mh_execute_header`'s sentinel value); the
    /// "address" is a literal symbol value, not a VM address.
    Absolute,
    /// `EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01` — a TLS
    /// variable; the address is a thread-local offset, accessed via
    /// `__thread_vars` on launch.
    ThreadLocal,
    /// Unknown kind value — preserved for round-trip. Reserved for
    /// future `EXPORT_SYMBOL_FLAGS_KIND_*` constants.
    Other(u64),
}

impl ExportKind {
    fn from_flags(flags: u64) -> Self {
        match flags & EXPORT_SYMBOL_FLAGS_KIND_MASK {
            0x00 => Self::Regular,
            0x01 => Self::ThreadLocal,
            0x02 => Self::Absolute,
            other => Self::Other(other),
        }
    }
}

/// Per-kind / per-flag payload of an [`Export`].
///
/// Carries the *additional* fields that depend on which trie-node
/// flavor this export uses. The [`ExportKind`] tag and `flags` byte
/// already cover the common case; this enum only fires on
/// re-exports and stub-and-resolver exports.
#[derive(Debug)]
pub enum ExportInfo<'p> {
    /// Regular export: lives at `address` (VM address). The
    /// overwhelming majority of trie entries fall into this variant.
    Regular {
        /// VM address of the export's body in *this* image.
        address: u64,
    },
    /// Re-export with `EXPORT_SYMBOL_FLAGS_REEXPORT` set in the
    /// trie node — this image declares the symbol but forwards
    /// resolution to another dylib. dyld follows the chain at load
    /// time.
    Reexport {
        /// Install-name of the dylib the re-export forwards into
        /// (sourced from the trie's library ordinal). Zero-copy
        /// reborrow.
        lib: &'p str,
        /// Symbol name in the target dylib. `None` means "use this
        /// entry's own trie name", which the toolchain emits when
        /// the re-exported name matches the original — saves bytes
        /// in the trie.
        lib_symbol_name: Option<&'p str>,
    },
    /// Stub-and-resolver export
    /// (`EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`). Used by dispatch
    /// trampolines and `__attribute__((ifunc))`-style entries: the
    /// `stub_offset` is the indirect call target dyld writes into
    /// non-lazy pointers, while `resolver_offset` is invoked once
    /// per dylib load to compute the real target. This is how
    /// `libsystem_pthread.dylib` exposes per-CPU optimised builtins.
    Stub {
        /// File offset of the stub trampoline.
        stub_offset: u64,
        /// File offset of the resolver function dyld calls once.
        resolver_offset: u64,
    },
}

/// Iterator over [`Export`] rows.
///
/// Empty when the binary has no `LC_DYLD_EXPORTS_TRIE` /
/// `LC_DYLD_INFO[_ONLY]`, when the trie failed to decode, or when
/// the binary genuinely exports nothing.
pub struct ExportIter<'p> {
    items: std::vec::IntoIter<GoblinExport<'p>>,
}

impl<'p> ExportIter<'p> {
    pub(crate) fn new(items: Vec<GoblinExport<'p>>) -> Self {
        Self {
            items: items.into_iter(),
        }
    }
}

impl<'p> Iterator for ExportIter<'p> {
    type Item = Export<'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let g = self.items.next()?;
        let (kind, flags, info) = decode_export_info(&g.info);
        let is_weak_definition = flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0;
        Some(Export {
            name: g.name,
            kind,
            flags,
            is_weak_definition,
            info,
            offset: g.offset,
        })
    }
}

fn decode_export_info<'p>(g: &GoblinExportInfo<'p>) -> (ExportKind, u64, ExportInfo<'p>) {
    match *g {
        GoblinExportInfo::Regular { address, flags } => (
            ExportKind::from_flags(flags),
            flags,
            ExportInfo::Regular { address },
        ),
        GoblinExportInfo::Reexport {
            lib,
            lib_symbol_name,
            flags,
        } => (
            ExportKind::from_flags(flags),
            flags,
            ExportInfo::Reexport {
                lib,
                lib_symbol_name,
            },
        ),
        GoblinExportInfo::Stub {
            stub_offset,
            resolver_offset,
            flags,
        } => (
            ExportKind::from_flags(flags),
            flags,
            ExportInfo::Stub {
                stub_offset: u64::from(stub_offset),
                resolver_offset: u64::from(resolver_offset),
            },
        ),
    }
}

/// Re-export goblin's `EXPORT_SYMBOL_FLAGS_*` for callers that want
/// to inspect the raw flag byte.
pub mod flags {
    pub use goblin::mach::exports::{
        EXPORT_SYMBOL_FLAGS_KIND_MASK, EXPORT_SYMBOL_FLAGS_REEXPORT,
        EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
    };
}

// Suppress dead_code on the `EXPORT_SYMBOL_FLAGS_*` imports we use
// only via the `flags` re-export module.
#[allow(dead_code)]
const _USED: (u64, u64) = (
    EXPORT_SYMBOL_FLAGS_REEXPORT,
    EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
);
