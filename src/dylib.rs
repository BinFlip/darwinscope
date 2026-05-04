//! Dylib graph (`LC_LOAD_*_DYLIB`) and load-command summary.
//!
//! Two iterators ride on top of the parsed `MachO.load_commands`
//! vector:
//!
//! - [`DylibIter`] — every load command of kind `LC_LOAD_DYLIB`,
//!   `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`,
//!   `LC_LOAD_UPWARD_DYLIB`, or `LC_LAZY_LOAD_DYLIB`.
//! - [`LoadCommandIter`] — flat summary of every load command (one
//!   row per `LC_*`), including the `cmd` id, byte offset, size,
//!   and a `&'a [u8]` slice over the command's raw bytes.
//!
//! `LC_ID_DYLIB` (a self-identifying dylib's own `install_name`) is
//! deliberately *not* surfaced through [`DylibIter`] — it does not
//! describe a dependency. Use [`LoadCommandIter`] to find it if
//! needed.

use core::marker::PhantomData;

use goblin::mach::load_command::{
    CommandVariant, DylibCommand, LoadCommand as GoblinLoadCommand, cmd_to_str,
};

use crate::binary::{Version, read_lc_str};

/// View over a single dylib dependency.
#[derive(Debug)]
pub struct Dylib<'a, 'p> {
    /// Path / install_name of the dylib (e.g.
    /// `/usr/lib/libSystem.B.dylib`).
    pub name: &'a str,
    /// What kind of load (regular, weak, re-export, …).
    pub kind: DylibKind,
    /// `dylib.timestamp` — historically a build timestamp; modern
    /// images frequently zero this for reproducible-build reasons.
    pub timestamp: u32,
    /// Current version of the dylib.
    pub current_version: Version,
    /// Compatibility version that consumers must be at least.
    pub compat_version: Version,
    _parent: PhantomData<&'p ()>,
}

/// Which `LC_LOAD_*_DYLIB` variant introduced this dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DylibKind {
    /// `LC_LOAD_DYLIB` — regular, must resolve at load time.
    Load,
    /// `LC_LOAD_WEAK_DYLIB` — weak; missing dylib does not abort.
    LoadWeak,
    /// `LC_REEXPORT_DYLIB` — re-export the loaded dylib's symbols.
    Reexport,
    /// `LC_LOAD_UPWARD_DYLIB` — upward dependency (cycle break).
    LoadUpward,
    /// `LC_LAZY_LOAD_DYLIB` — defer load until first reference.
    LazyLoad,
}

/// Iterator over [`Dylib`] dependencies in load-command order.
pub struct DylibIter<'a, 'p> {
    data: &'a [u8],
    inner: core::slice::Iter<'p, GoblinLoadCommand>,
}

impl<'a, 'p> DylibIter<'a, 'p> {
    pub(crate) fn new(data: &'a [u8], lcs: &'p [GoblinLoadCommand]) -> Self {
        Self {
            data,
            inner: lcs.iter(),
        }
    }
}

impl<'a, 'p> Iterator for DylibIter<'a, 'p> {
    type Item = Dylib<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        for lc in self.inner.by_ref() {
            let (kind, c): (DylibKind, &DylibCommand) = match &lc.command {
                CommandVariant::LoadDylib(c) => (DylibKind::Load, c),
                CommandVariant::LoadWeakDylib(c) => (DylibKind::LoadWeak, c),
                CommandVariant::ReexportDylib(c) => (DylibKind::Reexport, c),
                CommandVariant::LoadUpwardDylib(c) => (DylibKind::LoadUpward, c),
                CommandVariant::LazyLoadDylib(c) => (DylibKind::LazyLoad, c),
                // Skip LC_ID_DYLIB and everything else.
                _ => continue,
            };
            let Some(name) = resolve_dylib_name(self.data, lc, c) else {
                // Malformed: name offset out of bounds. Fail-soft.
                continue;
            };
            return Some(Dylib {
                name,
                kind,
                timestamp: c.dylib.timestamp,
                current_version: Version::from_packed_u32(c.dylib.current_version),
                compat_version: Version::from_packed_u32(c.dylib.compatibility_version),
                _parent: PhantomData,
            });
        }
        None
    }
}

fn resolve_dylib_name<'a>(
    data: &'a [u8],
    lc: &GoblinLoadCommand,
    c: &DylibCommand,
) -> Option<&'a str> {
    let name_off = c.dylib.name as usize;
    let total_off = lc.offset.checked_add(name_off)?;
    let end = lc.offset.checked_add(lc.command.cmdsize())?;
    read_lc_str(data, total_off, end)
}

/// Summary view over one load command.
#[derive(Debug)]
pub struct LoadCommand<'a, 'p> {
    /// `LC_*` identifier.
    pub kind: u32,
    /// Byte offset of this load command inside the binary.
    pub offset: usize,
    /// Total size in bytes (`cmdsize`).
    pub size: u32,
    /// The command's raw bytes (`data[offset..offset+size]`). Empty
    /// when bounds are violated by a malformed image.
    pub bytes: &'a [u8],
    _parent: PhantomData<&'p ()>,
}

impl<'a, 'p> LoadCommand<'a, 'p> {
    /// Human-readable `LC_*` name (e.g. `"LC_SEGMENT_64"`). Returns
    /// `"LC_UNKNOWN"` for values goblin does not recognise.
    pub fn name(&self) -> &'static str {
        cmd_to_str(self.kind)
    }
}

/// Iterator over every load command in load-command order.
pub struct LoadCommandIter<'a, 'p> {
    data: &'a [u8],
    inner: core::slice::Iter<'p, GoblinLoadCommand>,
}

impl<'a, 'p> LoadCommandIter<'a, 'p> {
    pub(crate) fn new(data: &'a [u8], lcs: &'p [GoblinLoadCommand]) -> Self {
        Self {
            data,
            inner: lcs.iter(),
        }
    }
}

impl<'a, 'p> Iterator for LoadCommandIter<'a, 'p> {
    type Item = LoadCommand<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let lc = self.inner.next()?;
        let kind = lc.command.cmd();
        let cmdsize = lc.command.cmdsize();
        let bytes = lc
            .offset
            .checked_add(cmdsize)
            .and_then(|end| self.data.get(lc.offset..end))
            .unwrap_or(&[]);
        Some(LoadCommand {
            kind,
            offset: lc.offset,
            size: cmdsize as u32,
            bytes,
            _parent: PhantomData,
        })
    }
}
