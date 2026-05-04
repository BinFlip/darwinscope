//! Parent-context chain walker.
//!
//! Follows the `Parent` relative pointer of a context descriptor
//! upward until the chain terminates at a top-level descriptor —
//! typically a `TargetModuleContextDescriptor` (kind=`Module`)
//! that exposes the Swift module name. Walking the chain yields
//! the fully-qualified name (e.g. `MyApp.SubModule.MyClass`).
//!
//! Layout reference: every context descriptor opens with
//! `(Flags: u32, Parent: i32 relative)` per
//! `swift/include/swift/ABI/Metadata.h:3091-3148`. Kinds that carry
//! an explicit name field place it immediately after at offset 8
//! (i32 relative pointer):
//!
//! - **Module** (kind=`0`): name is the Swift module identifier.
//!   Cite: `Metadata.h:3162-3181`.
//! - **Type kinds** (`Class`, `Struct`, `Enum`): same Name field
//!   we already read in [`crate::swift::TypeDescriptor::name`].
//! - **Protocol** (kind=`3`): name is the protocol identifier.
//! - **Extension** (kind=`1`): the +8 slot is the
//!   `ExtendedContext` mangled-type-name pointer rather than a
//!   plain identifier; we surface it as `name` for consumers that
//!   want to format the chain end-to-end.
//! - **Anonymous** (kind=`2`): no name unless the optional
//!   `HasMangledName` kind-specific flag is set; surfaced as
//!   `None`.

use crate::{
    swift::{
        context::{ContextDescriptorFlags, ContextDescriptorKind},
        SwiftRuntime,
    },
    util::{read_i32_le_at, read_u32_le_at, relative_pointer},
};

/// One context in the parent chain.
#[derive(Debug, Clone)]
pub struct ParentContext<'a> {
    /// VA of the context descriptor.
    pub address: u64,
    /// Decoded common-header flags.
    pub flags: ContextDescriptorFlags,
    /// Name string. `None` for kinds whose descriptor doesn't carry
    /// a name field (`Anonymous` without `HasMangledName`, certain
    /// `Other` kinds).
    pub name: Option<&'a str>,
}

impl<'a> ParentContext<'a> {
    /// Convenience: descriptor kind.
    pub fn kind(&self) -> ContextDescriptorKind {
        self.flags.kind()
    }
}

/// Walks up the parent chain starting from a child descriptor.
///
/// Yields one [`ParentContext`] per hop, in inside-out order
/// (innermost enclosing context first, module last). Stops when
/// the `Parent` relative pointer is null.
pub struct ParentChain<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    /// VA of the next context descriptor to read. `0` ⇒ chain
    /// exhausted.
    pub(crate) next_descriptor_va: u64,
}

impl<'a, 'p> ParentChain<'a, 'p> {
    pub(crate) fn empty(rt: &'p SwiftRuntime<'a>) -> Self {
        Self {
            rt,
            next_descriptor_va: 0,
        }
    }

    pub(crate) fn starting_at(rt: &'p SwiftRuntime<'a>, parent_va: u64) -> Self {
        Self {
            rt,
            next_descriptor_va: parent_va,
        }
    }
}

impl<'a, 'p> Iterator for ParentChain<'a, 'p> {
    type Item = ParentContext<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next_descriptor_va == 0 {
            return None;
        }
        let descriptor_va = self.next_descriptor_va;
        let header = self.rt.read_bytes(descriptor_va, 8)?;
        let flags_raw = read_u32_le_at(header, 0)?;
        let parent_rel = read_i32_le_at(header, 4)?;

        let flags = ContextDescriptorFlags(flags_raw);

        // Name resolution depends on kind. Every kind we surface a
        // name for places its `Name` (or `ExtendedContext`) field at
        // offset +8.
        let name = read_context_name(self.rt, descriptor_va, flags);

        // Advance the chain. A null relative pointer terminates.
        let parent_slot_va = descriptor_va.checked_add(4)?;
        self.next_descriptor_va = if parent_rel == 0 {
            0
        } else {
            relative_pointer(parent_slot_va, parent_rel)
        };

        Some(ParentContext {
            address: descriptor_va,
            flags,
            name,
        })
    }
}

/// Read the `Name` (or analogous string) field of a context
/// descriptor at virtual address `descriptor_va`. Returns `None`
/// when the kind has no canonical name slot or when the relative
/// pointer fails to resolve.
fn read_context_name<'a>(
    rt: &SwiftRuntime<'a>,
    descriptor_va: u64,
    flags: ContextDescriptorFlags,
) -> Option<&'a str> {
    match flags.kind() {
        ContextDescriptorKind::Module
        | ContextDescriptorKind::Class
        | ContextDescriptorKind::Struct
        | ContextDescriptorKind::Enum
        | ContextDescriptorKind::Protocol
        | ContextDescriptorKind::Extension => {
            // All of these place an i32 relative pointer at +8 that
            // resolves to a NUL-terminated UTF-8 string. Extension
            // surfaces the extended-context mangled name; consumers
            // can decide how to interpret it.
            let slot_va = descriptor_va.checked_add(8)?;
            let bytes = rt.read_bytes(slot_va, 4)?;
            let rel = read_i32_le_at(bytes, 0)?;
            if rel == 0 {
                return None;
            }
            let target = relative_pointer(slot_va, rel);
            rt.read_cstr(target)
        }
        ContextDescriptorKind::Anonymous
        | ContextDescriptorKind::OpaqueType
        | ContextDescriptorKind::Other(_) => None,
    }
}

impl<'a, 'p> crate::swift::TypeDescriptor<'a, 'p> {
    /// Walk the parent context chain.
    ///
    /// Returns an empty iterator when the descriptor has no parent
    /// (top-level type defined directly under a module that ships
    /// without a parent context — extremely rare; module-less top-
    /// level types have a parent with a null Name).
    pub fn parent(&self) -> ParentChain<'a, 'p> {
        if self.parent_va == 0 {
            return ParentChain::empty(self.runtime());
        }
        ParentChain::starting_at(self.runtime(), self.parent_va)
    }

    /// Fully-qualified name built by walking the parent chain.
    ///
    /// Format: `Module.Outer.Inner.Self`. Hops with no name
    /// (anonymous contexts, missing strings) are elided. The
    /// descriptor's own [`Self::name`] is always the trailing
    /// component.
    pub fn qualified_name(&self) -> String {
        let mut hops: Vec<&str> = Vec::new();
        for ctx in self.parent() {
            if let Some(name) = ctx.name {
                hops.push(name);
            }
        }
        hops.reverse();
        if hops.is_empty() {
            return self.name.to_owned();
        }
        let mut out = String::new();
        for hop in hops {
            out.push_str(hop);
            out.push('.');
        }
        out.push_str(self.name);
        out
    }
}

impl<'a, 'p> crate::swift::SwiftProtocol<'a, 'p> {
    /// Walk the parent context chain for this protocol.
    pub fn parent(&self) -> ParentChain<'a, 'p> {
        if self.parent_va == 0 {
            return ParentChain::empty(self.rt);
        }
        ParentChain::starting_at(self.rt, self.parent_va)
    }

    /// Fully-qualified protocol name built via the parent chain.
    pub fn qualified_name(&self) -> String {
        let mut hops: Vec<&str> = Vec::new();
        for ctx in self.parent() {
            if let Some(name) = ctx.name {
                hops.push(name);
            }
        }
        hops.reverse();
        if hops.is_empty() {
            return self.name.to_owned();
        }
        let mut out = String::new();
        for hop in hops {
            out.push_str(hop);
            out.push('.');
        }
        out.push_str(self.name);
        out
    }
}
