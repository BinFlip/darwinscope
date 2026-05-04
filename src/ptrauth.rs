//! Pointer authentication and chained-fixup canonicalisation.
//!
//! On arm64e binaries, runtime pointers in `__objc_*list` and
//! `__swift5_*` indirection tables can carry a Pointer Authentication
//! Code (PAC) signature in bits `48..63` of each 64-bit slot. The
//! runtime canonicalises pointers by masking to the user
//! virtual-address window
//! (`0x0000_0000_0000_0000..=0x0000_FFFF_FFFF_FFFF`).
//!
//! When `LC_DYLD_CHAINED_FIXUPS` is present, raw pointers are encoded
//! as chain entries (rebase / bind / authenticated rebase /
//! authenticated bind). The per-format decoders in [`crate::fixup`]
//! extract the canonical target field directly from the slot bits
//! and surface PAC metadata as a [`PtrAuth`] value.
//!
//! `darwinscope` is read-only — it never verifies a signature; it
//! only strips the envelope and exposes `(diversity, addr_div, key)`
//! verbatim for downstream tools that *do* care to match against
//! expected discriminator constants.
//!
//! See `RESEARCH.md` §"Pointer authentication (arm64e)" (line 886)
//! and §"Chained-fixup auth pointer formats" (line 900) for the
//! underlying format references.

/// Mask covering the user virtual-address window (low 48 bits).
///
/// A raw 64-bit pointer carrying PAC envelope bits in `48..63` masks
/// down to the canonical user-VA via this mask. The chained-fixup
/// per-format decoders in [`crate::fixup`] extract structured fields
/// directly from the slot bits; this mask is for the rarer case
/// where a caller already holds a PAC-signed pointer and only needs
/// the canonical address back.
pub const VA_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Strip PAC + chain-encoding bits, leaving the canonical 48-bit
/// user VA.
///
/// Always succeeds — for slots that aren't pointers, categorisation
/// is the caller's responsibility. This function does **not**
/// validate the signature; `darwinscope` is a parser, not a
/// validator. See module docs for the encoding it strips.
pub fn strip_signature(raw: u64) -> u64 {
    raw & VA_MASK
}

/// PAC metadata extracted from a chained-fixup auth slot
/// (`auth_rebase` / `auth_bind` / `auth_bind24` variants).
///
/// Cite: `dyld/include/mach-o/fixup-chains.h:137-194` and
/// `RESEARCH.md` §"Chained-fixup auth pointer formats" (line 900).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtrAuth {
    /// 16-bit blended discriminator (slot bits `32..47`). The
    /// compiler picks a constant per pointer site; consumers that
    /// need to validate against a known constant compare verbatim.
    pub diversity: u16,
    /// When `true`, the runtime blends the slot's address into the
    /// discriminator before signing (slot bit `48`).
    pub addr_div: bool,
    /// PAC key selecting which of the four ARMv8.3 keys signed the
    /// pointer (slot bits `49..50`).
    pub key: PacKey,
}

/// One of the four ARMv8.3 pointer-authentication keys.
///
/// `IA` is the default for signed code pointers; `DA` is typical
/// for signed data pointers. The encoding mapping is fixed by the
/// arm64e ABI — see `dyld/include/mach-o/fixup-chains.h:142`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacKey {
    /// Instruction key A — default for signed code pointers.
    IA,
    /// Instruction key B.
    IB,
    /// Data key A — default for signed data pointers.
    DA,
    /// Data key B.
    DB,
}

impl PacKey {
    /// Decode the 2-bit `key` field of an arm64e auth slot (slot
    /// bits `49..50`). Only the low two bits of `bits` are
    /// inspected; higher bits are silently masked off.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::IA,
            1 => Self::IB,
            2 => Self::DA,
            _ => Self::DB,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn va_mask_is_low_48_bits() {
        assert_eq!(VA_MASK, 0x0000_FFFF_FFFF_FFFF);
    }

    #[test]
    fn strip_clears_high_envelope_bits() {
        // High 16 bits set to a non-trivial bit pattern; low 48 must
        // pass through unchanged.
        let signed: u64 = 0xDEAD_BEEF_CAFE_F00D;
        assert_eq!(strip_signature(signed), 0x0000_BEEF_CAFE_F00D);
    }

    #[test]
    fn strip_preserves_already_canonical_va() {
        let va: u64 = 0x0000_0001_0000_4000;
        assert_eq!(strip_signature(va), va);
    }

    #[test]
    fn strip_zero_is_zero() {
        assert_eq!(strip_signature(0), 0);
    }

    #[test]
    fn pac_key_decodes_all_four() {
        assert_eq!(PacKey::from_bits(0), PacKey::IA);
        assert_eq!(PacKey::from_bits(1), PacKey::IB);
        assert_eq!(PacKey::from_bits(2), PacKey::DA);
        assert_eq!(PacKey::from_bits(3), PacKey::DB);
    }

    #[test]
    fn pac_key_ignores_high_bits() {
        // 0b1100 → low two bits are 00 → IA
        assert_eq!(PacKey::from_bits(0b1100), PacKey::IA);
        // 0b1111 → low two bits are 11 → DB
        assert_eq!(PacKey::from_bits(0b1111), PacKey::DB);
    }
}
