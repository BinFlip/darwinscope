//! Imports — dyld bind targets.
//!
//! Decodes both binding encodings the toolchain emits:
//!
//! - **Legacy** `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` bind-opcode
//!   stream (via goblin).
//! - **Chained fixups** (`LC_DYLD_CHAINED_FIXUPS`, now the default
//!   on iOS / macOS) — decoded in [`crate::fixup`] and folded in
//!   here.
//!
//! ## Merge order
//!
//! The combined iterator yields **legacy bind rows first, then
//! chained-bind rows**, in load-command order. Real binaries ship
//! exactly one of the two encodings (never both), so de-duplication
//! is unnecessary — the order matters only as a documented
//! invariant for consumers, not as a meaningful sort.
//!
//! ## Lifetime
//!
//! `Import` carries a single lifetime `'p`. The underlying
//! `goblin::mach::MachO::imports` return type ties its strings to
//! the `&self` borrow rather than to the data lifetime, which
//! forces the collapse. Names and dylib paths are still zero-copy
//! reborrows from the input data; the only observable effect is
//! that an [`Import`] cannot outlive the
//! [`MachoBinary`](crate::binary::MachoBinary) borrow that produced
//! it.

/// View over a single dyld bind target.
///
/// One [`Import`] is one slot the dynamic linker patches at load
/// time with a symbol resolved from another image. The same logical
/// row exists in both encodings dyld accepts:
///
/// - Legacy `BIND_OPCODE_*` stream from
///   `LC_DYLD_INFO[_ONLY].bind_off / lazy_bind_off /
///   weak_bind_off` (cite: `dyld/src/ImageLoaderMachOCompressed.cpp`).
/// - Chained binds from `LC_DYLD_CHAINED_FIXUPS` (cite:
///   `dyld/include/mach-o/fixup-chains.h`'s `dyld_chained_import*`
///   structs). See [`crate::fixup::Bind`] for the chained-form view.
///
/// Both forms are normalised into this single shape — consumers do
/// not need to know which encoding the binary used.
#[derive(Debug, Clone)]
pub struct Import<'p> {
    /// Symbol name dyld will resolve (e.g. `_objc_msgSend`).
    /// Zero-copy reborrow of the binary's symbol-pool / string-pool
    /// bytes.
    pub name: &'p str,
    /// `LC_LOAD_*_DYLIB` install-name path the symbol resolves into.
    /// Two-level lookup — dyld will not search other dylibs.
    pub dylib: &'p str,
    /// Whether resolution is deferred until first use
    /// (`BIND_OPCODE_DO_BIND_ULEB_TIMES_LAZY` / lazy bind table).
    /// `false` for chained-bind rows: chained fixups have no
    /// lazy/non-lazy distinction at the encoding level.
    pub is_lazy: bool,
    /// Weak-import flag (`BIND_SYMBOL_FLAGS_WEAK_IMPORT`). When
    /// `true`, dyld tolerates the symbol being missing at runtime
    /// and writes `0` into the slot.
    pub is_weak: bool,
    /// File offset of the slot to bind. `0` for slots that have no
    /// on-disk backing (BSS / non-lazy in zerofill segments).
    pub offset: u64,
    /// Slot size in bytes — `8` for ordinary 64-bit lazy / non-lazy
    /// pointers, `0` for rebase-only entries that the legacy decoder
    /// emits without a typed size.
    pub size: usize,
    /// VM address of the slot itself (`segment.vmaddr +
    /// segment_offset`).
    pub address: u64,
    /// Constant added to the resolved value (for indirect data
    /// pointers, vtable thunks, etc.). Always `0` for ordinary
    /// function-pointer binds.
    pub addend: i64,
    /// Byte offset within the legacy bind-opcode stream where this
    /// row originated. Useful for tracing back to the raw opcodes
    /// during forensic analysis. Always `0` for chained-bind rows
    /// (chained fixups have no opcode stream).
    pub bind_offset: u64,
}

/// Iterator over [`Import`] rows.
///
/// Combines legacy bind-opcode imports (decoded by goblin) and
/// chained-fixup binds (decoded in-house by [`crate::fixup`]).
/// Yields legacy rows first, then chained rows. Empty when the
/// binary has no imports at all.
pub struct ImportIter<'p> {
    items: std::vec::IntoIter<Import<'p>>,
}

impl<'p> ImportIter<'p> {
    pub(crate) fn new(items: Vec<Import<'p>>) -> Self {
        Self {
            items: items.into_iter(),
        }
    }
}

impl<'p> Iterator for ImportIter<'p> {
    type Item = Import<'p>;
    fn next(&mut self) -> Option<Self::Item> {
        self.items.next()
    }
}
