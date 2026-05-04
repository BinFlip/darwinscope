//! Nlist symbol table iterator (`LC_SYMTAB`).
//!
//! Wraps `goblin::mach::symbols::SymbolIterator` with the typed
//! borrowed-slice view-type pattern used elsewhere.
//!
//! ## Caveat
//!
//! Per the upstream goblin docs: nlist symbols are **strippable**.
//! They are present on most ABI-stable system binaries (`/usr/bin/*`,
//! shared frameworks) but absent on the smallest stripped releases.
//! The exports trie (`crate::export`, PR 6) and bind opcodes /
//! chained fixups (`crate::import`, PR 5) are the more permanent
//! surfaces; reach for them first when a tool needs reliable symbol
//! coverage.

use core::marker::PhantomData;

use goblin::mach::symbols::{
    N_ABS, N_EXT, N_INDR, N_PBUD, N_PEXT, N_SECT, N_STAB, N_TYPE, N_UNDF, N_WEAK_DEF, N_WEAK_REF,
    Nlist, SymbolIterator as GoblinSymbolIter,
};

/// View over one entry of the `LC_SYMTAB` nlist array.
pub struct Symbol<'a, 'p> {
    name: &'a str,
    nlist: Nlist,
    _parent: PhantomData<&'p ()>,
}

impl<'a, 'p> Symbol<'a, 'p> {
    /// Symbol name from the binary's string table.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// `nlist.n_strx` — index into `LC_SYMTAB.stroff`.
    pub fn n_strx(&self) -> u32 {
        // n_strx is widened to usize in goblin; the on-disk field is
        // u32 and is bounded by stroff/strsize. Safe to narrow back.
        self.nlist.n_strx as u32
    }

    /// `nlist.n_type` — full byte (`N_STAB | N_PEXT | N_TYPE | N_EXT`).
    pub fn n_type(&self) -> u8 {
        self.nlist.n_type
    }

    /// Kind of symbol — the `N_TYPE` (0x0e) bits of `n_type`.
    pub fn kind(&self) -> SymbolKind {
        if self.is_stab() {
            return SymbolKind::Stab(self.nlist.n_type);
        }
        match self.nlist.n_type & N_TYPE {
            N_UNDF => SymbolKind::Undefined,
            N_ABS => SymbolKind::Absolute,
            N_SECT => SymbolKind::Section,
            N_PBUD => SymbolKind::PreboundUndefined,
            N_INDR => SymbolKind::Indirect,
            other => SymbolKind::Other(other),
        }
    }

    /// 1-based section ordinal where this symbol is defined, or `0`
    /// if `kind() != SymbolKind::Section`.
    pub fn n_sect(&self) -> u8 {
        // n_sect was widened to usize in goblin; on-disk it is u8
        // (0 = NO_SECT, 1..=255 inclusive).
        (self.nlist.n_sect & 0xff) as u8
    }

    /// `nlist.n_desc` — flags + library ordinal (for two-level
    /// lookups).
    pub fn n_desc(&self) -> u16 {
        self.nlist.n_desc
    }

    /// `nlist.n_value` — symbol VM address (for `Section` symbols)
    /// or stab-specific value otherwise.
    pub fn n_value(&self) -> u64 {
        self.nlist.n_value
    }

    /// Externally visible (`N_EXT` bit set).
    pub fn is_external(&self) -> bool {
        self.nlist.n_type & N_EXT != 0
    }

    /// Private external (`N_PEXT` bit set).
    pub fn is_private_external(&self) -> bool {
        self.nlist.n_type & N_PEXT != 0
    }

    /// Symbol is undefined (resolution deferred to dyld).
    pub fn is_undefined(&self) -> bool {
        self.nlist.n_type & N_TYPE == N_UNDF && self.nlist.n_sect == 0
    }

    /// Weak reference or weak definition.
    pub fn is_weak(&self) -> bool {
        self.nlist.n_desc & (N_WEAK_REF | N_WEAK_DEF) != 0
    }

    /// Symbolic-debugging entry — any of the `N_STAB` bits set.
    pub fn is_stab(&self) -> bool {
        self.nlist.n_type & N_STAB != 0
    }
}

impl core::fmt::Debug for Symbol<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Symbol")
            .field("name", &self.name)
            .field("kind", &self.kind())
            .field("external", &self.is_external())
            .field("n_sect", &self.n_sect())
            .field("n_value", &format_args!("0x{:x}", self.n_value()))
            .finish()
    }
}

/// Kind of nlist symbol — the `N_TYPE` (0x0e) bits of `n_type`,
/// extended with a `Stab` variant for symbolic-debugging entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// `N_UNDF` — undefined (resolved by dyld at load time).
    Undefined,
    /// `N_ABS` — absolute, not relocated.
    Absolute,
    /// `N_SECT` — defined in the section ordinal `n_sect`.
    Section,
    /// `N_PBUD` — prebound undefined (defined in a dylib).
    PreboundUndefined,
    /// `N_INDR` — indirect symbol.
    Indirect,
    /// Symbolic-debugging entry — the full `n_type` byte is
    /// preserved (it carries an `N_*` stab kind).
    Stab(u8),
    /// Future / unknown `N_TYPE` value.
    Other(u8),
}

/// Iterator over the nlist symbol table.
///
/// Returns the empty iterator when the binary has no `LC_SYMTAB` or
/// when goblin failed to parse the symbol table.
pub struct SymbolIter<'a, 'p> {
    inner: Option<GoblinSymbolIter<'a>>,
    _parent: PhantomData<&'p ()>,
}

impl<'a, 'p> SymbolIter<'a, 'p> {
    pub(crate) fn new(inner: Option<GoblinSymbolIter<'a>>) -> Self {
        Self {
            inner,
            _parent: PhantomData,
        }
    }
}

impl<'a, 'p> Iterator for SymbolIter<'a, 'p> {
    type Item = Symbol<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let inner = self.inner.as_mut()?;
        loop {
            match inner.next()? {
                Ok((name, nlist)) => {
                    return Some(Symbol {
                        name,
                        nlist,
                        _parent: PhantomData,
                    });
                }
                // Fail-soft: skip rows goblin couldn't decode.
                Err(_) => continue,
            }
        }
    }
}
