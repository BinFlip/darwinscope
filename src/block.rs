//! Apple Blocks runtime metadata.
//!
//! Decodes the literals and descriptors emitted by clang's blocks
//! lowering when an Obj-C / C / C++ source file uses the `^{}` block
//! syntax. The on-disk shape is fixed by the canonical Blocks ABI
//! (`compiler-rt/lib/BlocksRuntime/Block_private.h`):
//!
//! ```text
//! struct Block_layout {
//!     void *isa;                 // _NSConcreteGlobalBlock | _NSConcreteStackBlock | …
//!     volatile int32_t flags;    // BLOCK_* bits, see below
//!     int32_t reserved;          // 0 for global; runtime-managed for stack
//!     void (*invoke)(void *, ...);
//!     struct Block_descriptor_1 *descriptor;
//!     // captured variables follow
//! };
//!
//! struct Block_descriptor_1 {
//!     uintptr_t reserved;        // always 0 currently
//!     uintptr_t size;            // sizeof(Block_layout) + captures
//! };
//! struct Block_descriptor_2 {     // present iff BLOCK_HAS_COPY_DISPOSE
//!     void (*copy)(void *dst, const void *src);
//!     void (*dispose)(const void *);
//! };
//! struct Block_descriptor_3 {     // present iff BLOCK_HAS_SIGNATURE
//!     const char *signature;
//!     const char *layout;
//! };
//! ```
//!
//! `BLOCK_*` flag bits (from the same header):
//!
//! | Bit          | Name                       | Meaning                                |
//! |--------------|----------------------------|----------------------------------------|
//! | `1 << 25`    | `BLOCK_HAS_COPY_DISPOSE`   | descriptor has `copy` / `dispose`      |
//! | `1 << 26`    | `BLOCK_HAS_CTOR`           | helpers are C++ ctor / dtor            |
//! | `1 << 28`    | `BLOCK_IS_GLOBAL`          | block has `_NSConcreteGlobalBlock` isa |
//! | `1 << 29`    | `BLOCK_HAS_STRET`          | invoke uses sret return convention     |
//! | `1 << 30`    | `BLOCK_HAS_SIGNATURE`      | descriptor has `signature` / `layout`  |
//!
//! ## Detection strategy
//!
//! darwinscope locates blocks through the chained-fixup / classic
//! bind index, not by scanning data sections blindly. Every block —
//! global or stack — has its `isa` slot bound at link time to one of
//! the runtime's two anchor symbols:
//!
//! - `_NSConcreteGlobalBlock` — emitted by clang for blocks that
//!   capture nothing (or only consts). The bind site is the start of
//!   the literal in `__DATA_CONST,__const` / `__DATA,__data`. We
//!   walk forward 32 bytes to read flags / invoke / descriptor and
//!   follow the descriptor pointer.
//! - `_NSConcreteStackBlock` — emitted by clang for blocks that
//!   capture mutable state. The literal is built on the stack at
//!   runtime; the bind site is typically in `__DATA,__got`, so there
//!   is no fixed-address descriptor to decode. We surface its
//!   *presence* through [`BlockRuntime::has_stack_blocks`] but do
//!   not emit a literal row for it.
//!
//! Per `RESEARCH.md:2666-2669` the Stage-0 audit recorded reference
//! detection only for v0.1; per-block descriptor decoding is wired
//! in here as a v0.1 deliverable.
//!
//! ## Fail-soft posture
//!
//! [`MachoBinary::blocks`](crate::binary::MachoBinary::blocks) returns
//! `None` when the image binds neither `_NSConcreteGlobalBlock` nor
//! `_NSConcreteStackBlock` — i.e. carries no Blocks-runtime usage.
//! Per-literal decode failures (descriptor pointer outside any
//! segment, truncated body) yield [`BlockLiteral::descriptor`] =
//! `None` rather than dropping the row.

use core::marker::PhantomData;
use std::collections::HashMap;

use crate::{
    binary::MachoBinary,
    ptrauth::strip_signature,
    util::{read_cstr_at, read_u32_le_at, read_u64_le_at, vm_to_file_offset_in},
};

/// `_NSConcreteGlobalBlock` anchor symbol — `isa` of every clang-
/// emitted global block.
pub const NSCONCRETE_GLOBAL_BLOCK: &str = "_NSConcreteGlobalBlock";
/// `_NSConcreteStackBlock` anchor symbol — `isa` of every stack
/// block; literal is materialised on the stack at runtime.
pub const NSCONCRETE_STACK_BLOCK: &str = "_NSConcreteStackBlock";

/// `BLOCK_HAS_COPY_DISPOSE` — `Block_descriptor_2` is present.
pub const BLOCK_HAS_COPY_DISPOSE: u32 = 1 << 25;
/// `BLOCK_HAS_CTOR` — copy / dispose helpers are C++ ctor / dtor.
pub const BLOCK_HAS_CTOR: u32 = 1 << 26;
/// `BLOCK_IS_GLOBAL` — `isa = _NSConcreteGlobalBlock`. Set on every
/// literal we successfully decode through this walker.
pub const BLOCK_IS_GLOBAL: u32 = 1 << 28;
/// `BLOCK_HAS_STRET` — invoke function uses the sret return ABI.
pub const BLOCK_HAS_STRET: u32 = 1 << 29;
/// `BLOCK_HAS_SIGNATURE` — `Block_descriptor_3` is present.
pub const BLOCK_HAS_SIGNATURE: u32 = 1 << 30;

/// Size of `Block_layout` (`isa` + `flags` + `reserved` + `invoke` +
/// `descriptor` = 8 + 4 + 4 + 8 + 8).
const BLOCK_LAYOUT_SIZE: usize = 32;

/// Which anchor `isa` a [`BlockReference`] bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockIsa {
    /// `_NSConcreteGlobalBlock` — literal lives in `__DATA*`.
    Global,
    /// `_NSConcreteStackBlock` — literal is built on the stack at
    /// runtime; bind site is typically in `__DATA,__got`.
    Stack,
}

/// One bind site for `_NSConcreteGlobalBlock` or
/// `_NSConcreteStackBlock`.
///
/// Captures the raw bind row even when the surrounding bytes do not
/// decode as a [`BlockLiteral`] — useful for callers that just want
/// to record "this image uses Blocks" without committing to a full
/// decode.
#[derive(Debug, Clone, Copy)]
pub struct BlockReference<'a> {
    /// Which anchor symbol bound here.
    pub kind: BlockIsa,
    /// VM address of the slot that received the bind.
    pub slot_address: u64,
    /// Dylib the symbol resolves into (typically
    /// `/usr/lib/libobjc.A.dylib` or `/usr/lib/libSystem.B.dylib`
    /// depending on platform).
    pub dylib: &'a str,
}

/// Decoded `Block_layout` plus its `Block_descriptor_*` tail.
#[derive(Debug, Clone)]
pub struct BlockLiteral<'a> {
    /// VM address of the literal — same as the `isa` slot's bind
    /// site VA.
    pub address: u64,
    /// Anchor `isa` this literal binds to. Always
    /// [`BlockIsa::Global`] in the iterator output (stack blocks
    /// have no fixed-address literal); kept on the struct for the
    /// occasional caller that hand-constructs one for testing.
    pub isa: BlockIsa,
    /// Raw `flags` field. Use the named accessors for individual
    /// `BLOCK_*` bits.
    pub flags: u32,
    /// `Block_layout.reserved` — `0` for global blocks; runtime-
    /// managed retain-count for stack blocks (we never decode
    /// stack literals, so this field is informational only).
    pub reserved: u32,
    /// Canonical VM address of the `invoke` function.
    pub invoke: u64,
    /// Canonical VM address of the `Block_descriptor_*` tail. `0`
    /// when the slot was empty.
    pub descriptor_address: u64,
    /// Decoded descriptor, or `None` when the descriptor pointer
    /// could not be resolved (descriptor outside any segment, body
    /// truncated, etc.).
    pub descriptor: Option<BlockDescriptor<'a>>,
}

impl BlockLiteral<'_> {
    /// `BLOCK_IS_GLOBAL` — `flags & (1 << 28)`.
    pub fn is_global(&self) -> bool {
        self.flags & BLOCK_IS_GLOBAL != 0
    }
    /// `BLOCK_HAS_COPY_DISPOSE` — `flags & (1 << 25)`. When set the
    /// descriptor carries `copy_helper` and `dispose_helper` slots.
    pub fn has_copy_dispose(&self) -> bool {
        self.flags & BLOCK_HAS_COPY_DISPOSE != 0
    }
    /// `BLOCK_HAS_CTOR` — `flags & (1 << 26)`. Helpers are C++ ctor
    /// / dtor (only meaningful when [`Self::has_copy_dispose`]).
    pub fn has_ctor(&self) -> bool {
        self.flags & BLOCK_HAS_CTOR != 0
    }
    /// `BLOCK_HAS_STRET` — `flags & (1 << 29)`. The invoke function
    /// uses the sret (struct-return) calling convention.
    pub fn has_stret(&self) -> bool {
        self.flags & BLOCK_HAS_STRET != 0
    }
    /// `BLOCK_HAS_SIGNATURE` — `flags & (1 << 30)`. When set the
    /// descriptor carries a `signature` C-string (Obj-C type encoding
    /// of the invoke function) and a GC layout string.
    pub fn has_signature(&self) -> bool {
        self.flags & BLOCK_HAS_SIGNATURE != 0
    }
}

/// Decoded `Block_descriptor_*` chain.
///
/// `Block_descriptor_1` is always present. The optional fields
/// (`copy_helper` / `dispose_helper`, `signature` / `layout`) are
/// populated when their corresponding flag bit is set on the parent
/// [`BlockLiteral`].
#[derive(Debug, Clone)]
pub struct BlockDescriptor<'a> {
    /// VM address of the descriptor.
    pub address: u64,
    /// `Block_descriptor_1.reserved` — always `0` in current
    /// toolchains.
    pub reserved: u64,
    /// `Block_descriptor_1.size` — `sizeof(Block_layout)` plus
    /// captured-variable storage. Always `>= BLOCK_LAYOUT_SIZE`.
    pub size: u64,
    /// `Block_descriptor_2.copy` (canonical VA) when
    /// [`BlockLiteral::has_copy_dispose`].
    pub copy_helper: Option<u64>,
    /// `Block_descriptor_2.dispose` (canonical VA) when
    /// [`BlockLiteral::has_copy_dispose`].
    pub dispose_helper: Option<u64>,
    /// `Block_descriptor_3.signature` — Obj-C type encoding of the
    /// invoke function, when [`BlockLiteral::has_signature`].
    pub signature: Option<&'a str>,
    /// `Block_descriptor_3.layout` — GC layout / capture-encoding
    /// string, when [`BlockLiteral::has_signature`].
    pub layout_string: Option<&'a str>,
}

/// Aggregate Blocks-runtime walker.
///
/// Constructed via [`MachoBinary::blocks`](crate::binary::MachoBinary::blocks);
/// returns `None` for images that bind neither anchor symbol (i.e.
/// don't use the Blocks runtime).
#[derive(Debug)]
pub struct BlockRuntime<'a> {
    data: &'a [u8],
    segments: Vec<(u64, u64, u64, u64)>,
    rebases_by_va: HashMap<u64, u64>,
    /// Bind sites for `_NSConcreteGlobalBlock` (start of literals).
    global_sites: Vec<BlockReference<'a>>,
    /// Bind sites for `_NSConcreteStackBlock` (typically in __got).
    stack_sites: Vec<BlockReference<'a>>,
}

impl<'a> BlockRuntime<'a> {
    /// Build the aggregate from a parent [`MachoBinary`].
    ///
    /// Returns `None` when the image is 32-bit (the v0.1 walker is
    /// 64-bit only; the canonical Block ABI is layout-stable on
    /// 32-bit but every other walker in this crate gates on `is_64`)
    /// or when neither anchor symbol appears in the bind index.
    pub(crate) fn build(bin: &MachoBinary<'a>) -> Option<Self> {
        if !bin.header().is_64() {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::block: 32-bit Mach-O — Block walker is 64-bit only"
            );
            return None;
        }

        let data = bin.raw();
        let mut global_sites: Vec<BlockReference<'a>> = Vec::new();
        let mut stack_sites: Vec<BlockReference<'a>> = Vec::new();
        for imp in bin.imports() {
            // We need name / dylib at the data lifetime. They already
            // alias `data` (`__LINKEDIT` / `LC_SYMTAB.stroff`); we
            // re-borrow at that range so the iterator output isn't
            // tied to the goblin `&self` borrow.
            let Some(name) = reborrow_into_data(data, imp.name) else {
                continue;
            };
            let Some(dylib) = reborrow_into_data(data, imp.dylib) else {
                continue;
            };
            let kind = match name {
                NSCONCRETE_GLOBAL_BLOCK => BlockIsa::Global,
                NSCONCRETE_STACK_BLOCK => BlockIsa::Stack,
                _ => continue,
            };
            let site = BlockReference {
                kind,
                slot_address: imp.address,
                dylib,
            };
            match kind {
                BlockIsa::Global => global_sites.push(site),
                BlockIsa::Stack => stack_sites.push(site),
            }
        }
        if global_sites.is_empty() && stack_sites.is_empty() {
            return None;
        }

        let mut segments: Vec<(u64, u64, u64, u64)> = Vec::new();
        for s in bin.segments() {
            segments.push((s.vmaddr(), s.vmsize(), s.fileoff(), s.filesize()));
        }

        let mut rebases_by_va: HashMap<u64, u64> = HashMap::new();
        for r in bin.chained_rebases() {
            rebases_by_va.insert(r.vm_address(), r.target_vmaddr());
        }

        Some(Self {
            data,
            segments,
            rebases_by_va,
            global_sites,
            stack_sites,
        })
    }

    /// Whether this image binds `_NSConcreteGlobalBlock` (i.e. emits
    /// at least one global block literal).
    pub fn has_global_blocks(&self) -> bool {
        !self.global_sites.is_empty()
    }

    /// Whether this image binds `_NSConcreteStackBlock` (i.e. builds
    /// at least one stack block at runtime).
    pub fn has_stack_blocks(&self) -> bool {
        !self.stack_sites.is_empty()
    }

    /// Iterator over every Blocks-anchor bind in this image —
    /// [`BlockIsa::Global`] then [`BlockIsa::Stack`], in bind order.
    ///
    /// Useful for callers that just want to enumerate every block
    /// reference site (Stage 8.1 deliverable). For the full literal
    /// decode see [`Self::literals`].
    pub fn references(&self) -> ReferenceIter<'a, '_> {
        ReferenceIter {
            rt: self,
            phase: 0,
            cursor: 0,
            _phantom: PhantomData,
        }
    }

    /// Iterator over every decoded global block literal.
    ///
    /// Stack blocks are not represented here — their literal is
    /// built on the stack at runtime, with no fixed-address
    /// descriptor. Use [`Self::has_stack_blocks`] /
    /// [`Self::references`] to enumerate stack-block sites.
    pub fn literals(&self) -> LiteralIter<'a, '_> {
        LiteralIter {
            rt: self,
            cursor: 0,
            _phantom: PhantomData,
        }
    }

    /// Resolve a pointer slot at `slot_va` to its canonical VA.
    /// Mirrors [`crate::objc::ObjcRuntime::resolve_pointer`].
    fn resolve_pointer(&self, slot_va: u64, raw: u64) -> u64 {
        if let Some(&target) = self.rebases_by_va.get(&slot_va) {
            return target;
        }
        strip_signature(raw)
    }

    fn read_u32(&self, vmaddr: u64) -> Option<u32> {
        let off = vm_to_file_offset_in(self.segments.iter().copied(), vmaddr)? as usize;
        read_u32_le_at(self.data, off)
    }
    fn read_u64(&self, vmaddr: u64) -> Option<u64> {
        let off = vm_to_file_offset_in(self.segments.iter().copied(), vmaddr)? as usize;
        read_u64_le_at(self.data, off)
    }
    fn read_cstr(&self, vmaddr: u64) -> Option<&'a str> {
        if vmaddr == 0 {
            return None;
        }
        let off = vm_to_file_offset_in(self.segments.iter().copied(), vmaddr)? as usize;
        read_cstr_at(self.data, off)
    }

    /// Decode a global block literal whose `isa` slot is at
    /// `address`. Returns `None` only when even the fixed prefix
    /// (`flags`, `invoke`, `descriptor`) failed to read.
    fn decode_literal(&self, address: u64) -> Option<BlockLiteral<'a>> {
        let flags = self.read_u32(address.wrapping_add(0x08))?;
        let reserved = self.read_u32(address.wrapping_add(0x0c))?;
        let invoke_slot = address.wrapping_add(0x10);
        let invoke_raw = self.read_u64(invoke_slot)?;
        let invoke = self.resolve_pointer(invoke_slot, invoke_raw);
        let desc_slot = address.wrapping_add(0x18);
        let desc_raw = self.read_u64(desc_slot)?;
        let descriptor_address = self.resolve_pointer(desc_slot, desc_raw);
        let descriptor = self.decode_descriptor(descriptor_address, flags);
        Some(BlockLiteral {
            address,
            isa: BlockIsa::Global,
            flags,
            reserved,
            invoke,
            descriptor_address,
            descriptor,
        })
    }

    /// Decode `Block_descriptor_{1,2,3}` starting at `address`. The
    /// optional 2 / 3 fields are gated on the parent literal's
    /// flags bits.
    fn decode_descriptor(&self, address: u64, flags: u32) -> Option<BlockDescriptor<'a>> {
        if address == 0 {
            return None;
        }
        let reserved = self.read_u64(address)?;
        let size = self.read_u64(address.wrapping_add(0x08))?;

        // Sanity gate: the ABI guarantees `size >= sizeof(Block_layout)`.
        // Anything smaller means we followed a bogus pointer (typically
        // the bind site was actually a __got slot, not a literal).
        if size < BLOCK_LAYOUT_SIZE as u64 {
            return None;
        }

        let mut cursor: u64 = 0x10;
        let mut copy_helper = None;
        let mut dispose_helper = None;
        if flags & BLOCK_HAS_COPY_DISPOSE != 0 {
            let copy_slot = address.wrapping_add(cursor);
            let copy_raw = self.read_u64(copy_slot)?;
            copy_helper = Some(self.resolve_pointer(copy_slot, copy_raw));
            cursor = cursor.checked_add(8)?;
            let dispose_slot = address.wrapping_add(cursor);
            let dispose_raw = self.read_u64(dispose_slot)?;
            dispose_helper = Some(self.resolve_pointer(dispose_slot, dispose_raw));
            cursor = cursor.checked_add(8)?;
        }

        let mut signature = None;
        let mut layout_string = None;
        if flags & BLOCK_HAS_SIGNATURE != 0 {
            let sig_slot = address.wrapping_add(cursor);
            let sig_raw = self.read_u64(sig_slot)?;
            let sig_va = self.resolve_pointer(sig_slot, sig_raw);
            signature = self.read_cstr(sig_va);
            cursor = cursor.checked_add(8)?;
            let layout_slot = address.wrapping_add(cursor);
            let layout_raw = self.read_u64(layout_slot)?;
            let layout_va = self.resolve_pointer(layout_slot, layout_raw);
            layout_string = self.read_cstr(layout_va);
        }

        Some(BlockDescriptor {
            address,
            reserved,
            size,
            copy_helper,
            dispose_helper,
            signature,
            layout_string,
        })
    }
}

/// Iterator yielding every [`BlockReference`] — globals first, then
/// stacks, in bind order within each phase.
pub struct ReferenceIter<'a, 'p> {
    rt: &'p BlockRuntime<'a>,
    phase: u8,
    cursor: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> Iterator for ReferenceIter<'a, 'p> {
    type Item = BlockReference<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.phase {
                0 => {
                    if let Some(r) = self.rt.global_sites.get(self.cursor) {
                        self.cursor = self.cursor.checked_add(1)?;
                        return Some(*r);
                    }
                    self.phase = 1;
                    self.cursor = 0;
                }
                1 => {
                    if let Some(r) = self.rt.stack_sites.get(self.cursor) {
                        self.cursor = self.cursor.checked_add(1)?;
                        return Some(*r);
                    }
                    return None;
                }
                _ => return None,
            }
        }
    }
}

/// Iterator over every decoded global [`BlockLiteral`].
pub struct LiteralIter<'a, 'p> {
    rt: &'p BlockRuntime<'a>,
    cursor: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> Iterator for LiteralIter<'a, 'p> {
    type Item = BlockLiteral<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let site = self.rt.global_sites.get(self.cursor)?;
            self.cursor = self.cursor.checked_add(1)?;
            if let Some(lit) = self.rt.decode_literal(site.slot_address) {
                return Some(lit);
            }
            // Fail-soft: if we can't even read the prefix, skip the
            // row and continue. Don't terminate the iterator.
        }
    }
}

/// Re-borrow a `&str` slice that aliases somewhere inside `data`,
/// returning a `&'a str` whose lifetime is the data lifetime. Same
/// rationale as [`crate::objc::reborrow_into_data`].
fn reborrow_into_data<'a>(data: &'a [u8], s: &str) -> Option<&'a str> {
    let s_ptr = s.as_ptr() as usize;
    let s_len = s.len();
    let data_start = data.as_ptr() as usize;
    let data_end = data_start.checked_add(data.len())?;
    if s_ptr < data_start {
        return None;
    }
    let s_end = s_ptr.checked_add(s_len)?;
    if s_end > data_end {
        return None;
    }
    let off = s_ptr.checked_sub(data_start)?;
    let end = off.checked_add(s_len)?;
    let bytes = data.get(off..end)?;
    core::str::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_accessors_decode_combined_bits() {
        // Synthetic literal carrying every documented flag we surface.
        let lit = BlockLiteral {
            address: 0,
            isa: BlockIsa::Global,
            flags: BLOCK_IS_GLOBAL
                | BLOCK_HAS_COPY_DISPOSE
                | BLOCK_HAS_CTOR
                | BLOCK_HAS_STRET
                | BLOCK_HAS_SIGNATURE,
            reserved: 0,
            invoke: 0,
            descriptor_address: 0,
            descriptor: None,
        };
        assert!(lit.is_global());
        assert!(lit.has_copy_dispose());
        assert!(lit.has_ctor());
        assert!(lit.has_stret());
        assert!(lit.has_signature());
    }

    #[test]
    fn flag_accessors_zero_flags_all_false() {
        let lit = BlockLiteral {
            address: 0,
            isa: BlockIsa::Global,
            flags: 0,
            reserved: 0,
            invoke: 0,
            descriptor_address: 0,
            descriptor: None,
        };
        assert!(!lit.is_global());
        assert!(!lit.has_copy_dispose());
        assert!(!lit.has_ctor());
        assert!(!lit.has_stret());
        assert!(!lit.has_signature());
    }

    /// Synthetic single-segment image: lays out a `Block_layout`
    /// followed by its `Block_descriptor_{1,2,3}` and a signature /
    /// layout C-string, then exercises [`BlockRuntime::decode_literal`]
    /// against it.
    ///
    /// We hand-construct the [`BlockRuntime`] rather than going
    /// through [`MachoBinary::blocks`] because the canonical Block ABI
    /// is segment-table-only — the decode path doesn't care whether
    /// it's looking at a real Mach-O or a synthesized byte buffer, so
    /// pinning the wire format is far cheaper here than maintaining
    /// a `.o` fixture under `tests/samples/`.
    #[test]
    fn decode_literal_full_descriptor_3() {
        // VM layout — pick a single 4 KiB page mapped 1:1.
        const VMBASE: u64 = 0x1_0000_0000;
        // Buffer indices align with VM offsets relative to VMBASE.
        let mut buf = vec![0u8; 0x200];

        // Block_layout @ 0x00
        // isa: bind site (zeroed on disk; the bind index would carry the
        // global anchor name in a real image).
        // flags: HAS_COPY_DISPOSE | IS_GLOBAL | HAS_SIGNATURE
        let flags = BLOCK_HAS_COPY_DISPOSE | BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE;
        buf[0x08..0x0c].copy_from_slice(&flags.to_le_bytes());
        // reserved: 0
        // invoke: 0x1_0000_0100 (canonical VA)
        buf[0x10..0x18].copy_from_slice(&0x1_0000_0100u64.to_le_bytes());
        // descriptor: 0x1_0000_0080
        buf[0x18..0x20].copy_from_slice(&0x1_0000_0080u64.to_le_bytes());

        // Block_descriptor_1 @ 0x80
        //   reserved: 0
        //   size:     0x40 (≥ BLOCK_LAYOUT_SIZE)
        buf[0x88..0x90].copy_from_slice(&0x40u64.to_le_bytes());
        // Block_descriptor_2 @ 0x90 (HAS_COPY_DISPOSE)
        //   copy:     0x1_0000_0200
        //   dispose:  0x1_0000_0210
        buf[0x90..0x98].copy_from_slice(&0x1_0000_0200u64.to_le_bytes());
        buf[0x98..0xa0].copy_from_slice(&0x1_0000_0210u64.to_le_bytes());
        // Block_descriptor_3 @ 0xa0 (HAS_SIGNATURE)
        //   signature: 0x1_0000_00c0 → "v@?@\"NSString\""
        //   layout:    0x1_0000_00e0 → "" (empty)
        buf[0xa0..0xa8].copy_from_slice(&0x1_0000_00c0u64.to_le_bytes());
        buf[0xa8..0xb0].copy_from_slice(&0x1_0000_00e0u64.to_le_bytes());

        // C-string bodies
        let sig = b"v@?@\"NSString\"\0";
        buf[0xc0..0xc0 + sig.len()].copy_from_slice(sig);
        buf[0xe0] = 0; // empty layout string

        let segments = vec![(VMBASE, buf.len() as u64, 0u64, buf.len() as u64)];

        let rt = BlockRuntime {
            data: &buf,
            segments,
            rebases_by_va: HashMap::new(),
            global_sites: vec![BlockReference {
                kind: BlockIsa::Global,
                slot_address: VMBASE,
                dylib: "/usr/lib/libobjc.A.dylib",
            }],
            stack_sites: Vec::new(),
        };

        let lit = rt.decode_literal(VMBASE).expect("literal decodes");
        assert_eq!(lit.address, VMBASE);
        assert_eq!(lit.flags, flags);
        assert!(lit.is_global());
        assert!(lit.has_copy_dispose());
        assert!(lit.has_signature());
        assert!(!lit.has_stret());
        assert_eq!(lit.invoke, 0x1_0000_0100);
        assert_eq!(lit.descriptor_address, 0x1_0000_0080);

        let desc = lit.descriptor.expect("descriptor decodes");
        assert_eq!(desc.address, 0x1_0000_0080);
        assert_eq!(desc.reserved, 0);
        assert_eq!(desc.size, 0x40);
        assert_eq!(desc.copy_helper, Some(0x1_0000_0200));
        assert_eq!(desc.dispose_helper, Some(0x1_0000_0210));
        assert_eq!(desc.signature, Some("v@?@\"NSString\""));
        assert_eq!(desc.layout_string, Some(""));

        // Iterator produces exactly the one literal.
        let lits: Vec<_> = rt.literals().collect();
        assert_eq!(lits.len(), 1);
        assert_eq!(lits[0].invoke, 0x1_0000_0100);

        // references() yields the single global site.
        let refs: Vec<_> = rt.references().collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, BlockIsa::Global);
        assert_eq!(refs[0].slot_address, VMBASE);
    }

    /// `decode_descriptor` rejects entries whose `size` field is
    /// implausibly small — the most common signal that a bind site
    /// landed on a `__got` slot rather than a real block literal.
    #[test]
    fn decode_descriptor_rejects_size_below_block_layout() {
        const VMBASE: u64 = 0x1_0000_0000;
        let mut buf = vec![0u8; 0x40];
        // size = 16, below BLOCK_LAYOUT_SIZE (32).
        buf[0x08..0x10].copy_from_slice(&16u64.to_le_bytes());

        let rt = BlockRuntime {
            data: &buf,
            segments: vec![(VMBASE, buf.len() as u64, 0u64, buf.len() as u64)],
            rebases_by_va: HashMap::new(),
            global_sites: Vec::new(),
            stack_sites: Vec::new(),
        };
        assert!(rt.decode_descriptor(VMBASE, 0).is_none());
    }

    #[test]
    fn flag_constants_match_block_private_h() {
        // Cite: compiler-rt/lib/BlocksRuntime/Block_private.h.
        // These are the on-disk constants the entire Apple toolchain
        // writes; pin them so a refactor of the bit positions can't
        // silently break the decoder.
        assert_eq!(BLOCK_HAS_COPY_DISPOSE, 0x0200_0000);
        assert_eq!(BLOCK_HAS_CTOR,         0x0400_0000);
        assert_eq!(BLOCK_IS_GLOBAL,        0x1000_0000);
        assert_eq!(BLOCK_HAS_STRET,        0x2000_0000);
        assert_eq!(BLOCK_HAS_SIGNATURE,    0x4000_0000);
    }
}
