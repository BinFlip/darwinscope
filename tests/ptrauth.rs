//! `ptr_auth::strip_signature` + `PtrAuth` integration tests.
//!
//! Pure bit-manipulation against hand-built `u64` slots; no fixture
//! is required for arm64e binaries.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use darwinscope::ptrauth::{PacKey, PtrAuth, VA_MASK, strip_signature};

#[test]
fn va_mask_low_48_bits() {
    assert_eq!(VA_MASK, 0x0000_FFFF_FFFF_FFFF);
}

#[test]
fn strip_clears_pac_envelope_on_synthetic_auth_rebase() {
    // Hand-built `dyld_chained_ptr_arm64e_auth_rebase` slot:
    //   target    = 0x0000_4000  (bits  0..31)
    //   diversity = 0xBEEF       (bits 32..47)
    //   addrDiv   = 1            (bit  48)
    //   key       = 0 / IA       (bits 49..50)
    //   next      = 1            (bits 51..61)
    //   bind      = 0            (bit  62)
    //   auth      = 1            (bit  63)
    // Composed: 0x8009_BEEF_0000_4000.
    let raw: u64 = 0x8009_BEEF_0000_4000;
    // Low 48 bits = diversity (32..47) + target (0..31).
    assert_eq!(strip_signature(raw), 0x0000_BEEF_0000_4000);
}

#[test]
fn strip_is_idempotent() {
    let raw: u64 = 0xDEAD_BEEF_1234_5678;
    let once = strip_signature(raw);
    assert_eq!(strip_signature(once), once);
}

#[test]
fn ptr_auth_value_construction_round_trips() {
    let pa = PtrAuth {
        diversity: 0xBEEF,
        addr_div: true,
        key: PacKey::DA,
    };
    assert_eq!(pa.diversity, 0xBEEF);
    assert!(pa.addr_div);
    assert_eq!(pa.key, PacKey::DA);

    // Copy semantics — required because `Rebase::ptr_auth()` returns
    // `Option<PtrAuth>` by value.
    let pa2 = pa;
    assert_eq!(pa, pa2);
}

#[test]
fn pac_key_decoding_matches_arm64e_abi() {
    // Cite: dyld/include/mach-o/fixup-chains.h:142 — 0=IA, 1=IB,
    // 2=DA, 3=DB.
    assert_eq!(PacKey::from_bits(0), PacKey::IA);
    assert_eq!(PacKey::from_bits(1), PacKey::IB);
    assert_eq!(PacKey::from_bits(2), PacKey::DA);
    assert_eq!(PacKey::from_bits(3), PacKey::DB);
}
