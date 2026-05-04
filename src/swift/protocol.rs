//! `__swift5_protos` walker.
//!
//! Decodes [`SwiftProtocol`] entries from the i32-relative pointer
//! array in `__swift5_protos`. Each row resolves to a
//! `TargetProtocolDescriptor` (per
//! `swift/include/swift/ABI/Metadata.h:3326-3414` and
//! `RESEARCH.md:1818-1832`) carrying:
//!
//! | Off | Field                          | Type                          |
//! |-----|--------------------------------|-------------------------------|
//! | 0   | Flags                          | `u32`                         |
//! | 4   | Parent                         | i32 relative                  |
//! | 8   | Name                           | i32 relative (NUL-term)       |
//! | 12  | NumRequirementsInSignature     | `u32`                         |
//! | 16  | NumRequirements                | `u32`                         |
//! | 20  | AssociatedTypeNames (nullable) | i32 relative (NUL-term)       |
//!
//! 24 bytes header. Trailing arrays
//! (`TargetGenericRequirementDescriptor[NumRequirementsInSignature]`,
//! `TargetProtocolRequirement[NumRequirements]`) live past the
//! header — counts are surfaced verbatim, structured decode of the
//! requirement tables is post-v0.1.

use crate::{
    swift::{SwiftRuntime, context::ContextDescriptorFlags},
    util::{read_i32_le_at, read_u32_le_at, relative_pointer},
};

/// One Swift protocol descriptor.
#[derive(Debug)]
pub struct SwiftProtocol<'a, 'p> {
    pub(crate) rt: &'p SwiftRuntime<'a>,
    pub(crate) address: u64,
    pub(crate) flags: ContextDescriptorFlags,
    pub(crate) parent_va: u64,
    pub(crate) name: &'a str,
    pub(crate) num_requirements_in_signature: u32,
    pub(crate) num_requirements: u32,
    pub(crate) associated_type_names: Option<&'a str>,
}

impl<'a, 'p> SwiftProtocol<'a, 'p> {
    /// Owning [`SwiftRuntime`] borrow.
    pub fn runtime(&self) -> &'p SwiftRuntime<'a> {
        self.rt
    }

    /// VA of the descriptor base.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Decoded common-header flags.
    pub fn flags(&self) -> ContextDescriptorFlags {
        self.flags
    }

    /// Resolved VA of the `Parent` context (`0` for top-level).
    pub fn parent_address(&self) -> u64 {
        self.parent_va
    }

    /// Mangled protocol name.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// `NumRequirementsInSignature` — generic requirement count in
    /// the protocol's requirement signature.
    pub fn num_requirements_in_signature(&self) -> u32 {
        self.num_requirements_in_signature
    }

    /// `NumRequirements` — total protocol-method requirement count.
    pub fn num_requirements(&self) -> u32 {
        self.num_requirements
    }

    /// Space-separated associated-type names, or `None` when the
    /// `AssociatedTypeNames` relative pointer is null.
    pub fn associated_type_names(&self) -> Option<&'a str> {
        self.associated_type_names
    }
}

/// Iterator over `__swift5_protos`.
pub struct ProtocolIter<'a, 'p> {
    rt: &'p SwiftRuntime<'a>,
    cursor: usize,
}

impl<'a, 'p> ProtocolIter<'a, 'p> {
    pub(crate) fn new(rt: &'p SwiftRuntime<'a>) -> Self {
        Self { rt, cursor: 0 }
    }
}

impl<'a, 'p> Iterator for ProtocolIter<'a, 'p> {
    type Item = SwiftProtocol<'a, 'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let section = self.rt.protos.as_ref()?;
        loop {
            let slot_off = self.cursor;
            let slot_end = slot_off.checked_add(4)?;
            if slot_end > section.body.len() {
                return None;
            }
            self.cursor = slot_end;

            let Some(rel) = read_i32_le_at(section.body, slot_off) else {
                continue;
            };
            if rel == 0 {
                continue;
            }
            let slot_va = section.vmaddr.wrapping_add(slot_off as u64);
            let descriptor_va = relative_pointer(slot_va, rel);

            if let Some(p) = decode_protocol(self.rt, descriptor_va) {
                return Some(p);
            }
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::swift: protocol descriptor at 0x{:x} (slot 0x{:x}) skipped",
                descriptor_va,
                slot_va,
            );
        }
    }
}

fn decode_protocol<'a, 'p>(
    rt: &'p SwiftRuntime<'a>,
    descriptor_va: u64,
) -> Option<SwiftProtocol<'a, 'p>> {
    let header = rt.read_bytes(descriptor_va, 24)?;
    let flags_raw = read_u32_le_at(header, 0)?;
    let parent_rel = read_i32_le_at(header, 4)?;
    let name_rel = read_i32_le_at(header, 8)?;
    let num_requirements_in_signature = read_u32_le_at(header, 12)?;
    let num_requirements = read_u32_le_at(header, 16)?;
    let associated_rel = read_i32_le_at(header, 20)?;

    let flags = ContextDescriptorFlags(flags_raw);

    let parent_slot_va = descriptor_va.checked_add(4)?;
    let parent_va = if parent_rel == 0 {
        0
    } else {
        relative_pointer(parent_slot_va, parent_rel)
    };

    let name_slot_va = descriptor_va.checked_add(8)?;
    let name_va = relative_pointer(name_slot_va, name_rel);
    let name = rt.read_cstr(name_va)?;

    let associated_type_names = if associated_rel == 0 {
        None
    } else {
        let assoc_slot = descriptor_va.checked_add(20)?;
        let assoc_va = relative_pointer(assoc_slot, associated_rel);
        rt.read_cstr(assoc_va)
    };

    Some(SwiftProtocol {
        rt,
        address: descriptor_va,
        flags,
        parent_va,
        name,
        num_requirements_in_signature,
        num_requirements,
        associated_type_names,
    })
}
