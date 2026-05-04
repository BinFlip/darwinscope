//! Code-signature integration tests.
//!
//! Three fixtures plus the `/usr/bin/codesign` smoke:
//!
//! - `hello-x86_64` — unsigned (cross-arch link from arm64 host
//!   skips the auto-adhoc step). Pins the negative path.
//! - `hello-adhoc` — `codesign -s -` produces CD + Requirements
//!   + empty CMS placeholder. No entitlements.
//! - `hello-entitled` — adhoc + entitlements XML and DER blobs
//!   matching the committed `ent.plist` source.
//! - `/usr/bin/codesign` — opportunistic check that the
//!   real-CMS / real-Requirements path also decodes.
//!
//! Snapshot tests in `tests/snapshots.rs` cover per-field values
//! (CDHash, blob layout); tests here pin the slot-presence
//! contract, the `ent.plist` round-trip (XML + DER), the
//! version-gating of `exec_seg_*` accessors against a
//! hand-built v0x20100 blob, and the special-/code-hash count
//! invariants.

use std::path::Path;

use darwinscope::{
    binary::CPU_SUBTYPE_ANY,
    codesign::{cd_version, CdFlags, CodeDirectory, HashType, Signature, Slot, CSMAGIC_EMBEDDED_SIGNATURE},
    MachoBinary,
};

const ADHOC_PATH: &str = "tests/samples/synthesized/hello-cli/hello-adhoc";
const ENTITLED_PATH: &str = "tests/samples/synthesized/hello-cli/hello-entitled";
const UNSIGNED_PATH: &str = "tests/samples/synthesized/hello-cli/hello-x86_64";
const CODESIGN_PATH: &str = "/usr/bin/codesign";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(path)).unwrap()
}

#[test]
fn unsigned_binary_has_no_signature() {
    let bytes = read(UNSIGNED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(bin.signature().is_none(), "hello-x86_64 is not codesigned");
}

#[test]
fn adhoc_signature_decodes_with_expected_slots() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let sig: Signature<'_> = bin.signature().expect("hello-adhoc must have a signature");
    assert_eq!(sig.magic(), CSMAGIC_EMBEDDED_SIGNATURE);
    assert!(sig.length() > 0);
    assert!(sig.blob_count() >= 3);

    let slots: Vec<Slot> = sig.blobs().map(|b| b.slot).collect();
    assert!(slots.contains(&Slot::CodeDirectory));
    assert!(slots.contains(&Slot::Requirements));
    assert!(slots.contains(&Slot::SignatureSlot));
    assert!(!slots.contains(&Slot::Entitlements));
    assert!(!slots.contains(&Slot::DerEntitlements));
}

#[test]
fn entitled_signature_carries_entitlements_slot() {
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let sig = bin.signature().expect("hello-entitled must have a signature");
    let slots: Vec<Slot> = sig.blobs().map(|b| b.slot).collect();
    assert!(slots.contains(&Slot::CodeDirectory));
    assert!(
        slots.contains(&Slot::Entitlements),
        "hello-entitled must carry an Entitlements slot; got {slots:?}"
    );
    assert!(
        slots.contains(&Slot::DerEntitlements),
        "modern codesign emits DER entitlements alongside XML; got {slots:?}"
    );
}

#[test]
fn blob_index_offsets_are_in_range() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let sig = bin.signature().unwrap();
    for idx in sig.blobs() {
        assert!(
            (idx.offset as u64) < (sig.length() as u64),
            "blob index offset {} exceeds SuperBlob length {}",
            idx.offset,
            sig.length()
        );
    }
}

#[test]
fn adhoc_code_directory_basic_fields() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let sig = bin.signature().unwrap();
    let cd = sig.primary_code_directory().expect("primary CD must parse");

    assert!(cd.version() >= cd_version::SUPPORTS_TEAM_ID);
    assert_eq!(cd.hash_type(), HashType::Sha256);
    assert_eq!(cd.hash_size(), 32);
    assert!(cd.flags().contains(CdFlags::ADHOC));
    assert!(cd.n_code_slots() >= 1);
    assert!(cd.n_special_slots() >= 1);
}

#[test]
fn adhoc_identifier_starts_with_hello_adhoc() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    let ident = cd.identifier().expect("CD must have an identifier");
    assert!(
        ident.starts_with("hello-adhoc"),
        "identifier should start with hello-adhoc; got {ident:?}"
    );
}

#[test]
fn adhoc_has_no_team_id() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    assert!(cd.team_id().is_none(), "adhoc CD should not carry a team id");
}

#[test]
fn adhoc_cd_hash_is_sha256_size() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    let hash = cd.cd_hash();
    assert_eq!(hash.len(), 32, "SHA-256 ⇒ 32 byte digest");
    let trunc = cd.cd_hash_truncated();
    assert_eq!(&trunc[..], &hash[..20]);
}

#[test]
fn adhoc_cd_hash_matches_codesign_dvvv_recorded_value() {
    // `codesign -dvvv hello-adhoc` recorded during fixture build:
    //   CDHash=415228ae3f617310032bc592d56bbdebe2f285ea
    //   sha256=415228ae3f617310032bc592d56bbdebe2f285eaedb6fd2dfd4c449bb837491c
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    let want_full =
        hex_decode("415228ae3f617310032bc592d56bbdebe2f285eaedb6fd2dfd4c449bb837491c");
    let want_trunc = hex_decode("415228ae3f617310032bc592d56bbdebe2f285ea");
    assert_eq!(cd.cd_hash(), want_full);
    assert_eq!(&cd.cd_hash_truncated()[..], want_trunc.as_slice());
}

#[test]
fn entitled_code_directory_decodes() {
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    assert_eq!(cd.hash_type(), HashType::Sha256);
    assert!(cd.identifier().unwrap().starts_with("hello-entitled"));
    let want_full =
        hex_decode("cdc7072eb79b53163dad4a573e70497edaed421a6efedff14551c6eb9851e42e");
    assert_eq!(cd.cd_hash(), want_full);
}

#[test]
fn page_size_resolves_to_power_of_two() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    let ps = cd.page_size();
    assert!(
        ps == 0 || ps.is_power_of_two(),
        "page_size should be 0 (infinite) or a power of two; got {ps}"
    );
}

#[test]
fn exec_seg_fields_present_in_v20400_fixtures() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    assert!(cd.version() >= cd_version::SUPPORTS_EXEC_SEG);
    let base = cd.exec_seg_base().expect("v20400+ ⇒ exec_seg_base Some");
    let limit = cd.exec_seg_limit().expect("v20400+ ⇒ exec_seg_limit Some");
    let _flags = cd.exec_seg_flags().expect("v20400+ ⇒ exec_seg_flags Some");
    assert!(limit > 0, "exec_seg_limit must be non-zero");
    assert_eq!(base, 0, "__TEXT exec segment usually starts at file 0");
}

#[test]
fn exec_seg_returns_none_for_legacy_versions() {
    // Hand-built CodeDirectory blob with version 0x20100 (no
    // team_id, no exec_seg) — verify the gated accessors return
    // None.
    let mut blob = vec![
        0xfa, 0xde, 0x0c, 0x02, // magic CSMAGIC_CODEDIRECTORY
        0x00, 0x00, 0x00, 0x60, // length 96
        0x00, 0x02, 0x01, 0x00, // version 0x20100 (pre-team-id)
        0x00, 0x00, 0x00, 0x00, // flags
        0x00, 0x00, 0x00, 0x60, // hashOffset (past blob)
        0x00, 0x00, 0x00, 0x2c, // identOffset = 44
        0x00, 0x00, 0x00, 0x00, // nSpecialSlots
        0x00, 0x00, 0x00, 0x00, // nCodeSlots
        0x00, 0x00, 0x00, 0x00, // codeLimit
        0x20, 0x02, 0x00, 0x0e, // hashSize=32 hashType=2 platform=0 pageSize=14
        0x00, 0x00, 0x00, 0x00, // spare2
        0x00, 0x00, 0x00, 0x00, // scatterOffset
    ];
    blob.extend_from_slice(b"id\0");
    while blob.len() < 96 {
        blob.push(0);
    }
    let cd = CodeDirectory::parse(&blob).unwrap();
    assert_eq!(cd.version(), 0x0002_0100);
    assert!(cd.team_id().is_none(), "version 0x20100 < team_id min");
    assert!(cd.code_limit_64().is_none());
    assert!(cd.exec_seg_base().is_none());
    assert!(cd.exec_seg_limit().is_none());
    assert!(cd.exec_seg_flags().is_none());
}

#[test]
fn special_hashes_count_matches_n_special_slots() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    let n = cd.n_special_slots() as usize;
    let collected: Vec<_> = cd.special_hashes().collect();
    assert_eq!(
        collected.len(),
        n,
        "special_hashes() must yield exactly n_special_slots rows"
    );
    for (i, (slot_idx, bytes)) in collected.iter().enumerate() {
        let expected = -((i as i32) + 1);
        assert_eq!(*slot_idx, expected, "special slot ordering");
        assert_eq!(bytes.len(), cd.hash_size() as usize);
    }
}

#[test]
fn code_hashes_count_matches_n_code_slots() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    let n = cd.n_code_slots() as usize;
    let collected: Vec<_> = cd.code_hashes().collect();
    assert_eq!(collected.len(), n);
    for h in &collected {
        assert_eq!(h.len(), cd.hash_size() as usize);
    }
}

#[test]
fn entitled_special_hash_slot_for_entitlements_is_non_zero() {
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cd = bin.signature().unwrap().primary_code_directory().unwrap();
    let slot_neg5 = cd
        .special_hashes()
        .find(|(slot, _)| *slot == -5)
        .map(|(_, b)| b)
        .expect("entitled CD must have special slot -5");
    assert_eq!(slot_neg5.len(), cd.hash_size() as usize);
    assert!(
        slot_neg5.iter().any(|&b| b != 0),
        "entitlements hash slot should be non-zero"
    );
}

#[test]
fn adhoc_has_no_entitlements_blob() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(bin.signature().unwrap().entitlements().is_none());
}

#[test]
fn entitled_raw_starts_with_xml_doctype() {
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let ent = bin.signature().unwrap().entitlements().unwrap();
    let raw = ent.raw();
    let head = std::str::from_utf8(&raw[..raw.len().min(40)]).unwrap();
    assert!(
        head.starts_with("<?xml"),
        "entitlements payload should be XML; got {head:?}"
    );
}

#[test]
fn entitled_parsed_carries_known_keys() {
    // Fixture was built from ent.plist with these exact keys.
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let ent = bin.signature().unwrap().entitlements().unwrap();
    let v = ent.parsed().expect("plist must decode");
    let dict = v.as_dictionary().expect("top-level should be a dict");
    assert_eq!(
        dict.get("com.apple.security.app-sandbox")
            .and_then(|v| v.as_boolean()),
        Some(true)
    );
    assert_eq!(
        dict.get("com.apple.security.network.client")
            .and_then(|v| v.as_boolean()),
        Some(true)
    );
    assert_eq!(
        dict.get("com.apple.developer.team-identifier")
            .and_then(|v| v.as_string()),
        Some("EXAMPLE12345")
    );
}

#[test]
fn entitlements_payload_length_excludes_header() {
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let sig = bin.signature().unwrap();
    let ent = sig.entitlements().unwrap();
    for idx in sig.blobs() {
        if idx.slot != Slot::Entitlements {
            continue;
        }
        let abs_off = idx.offset as usize;
        let blob_len = u32::from_be_bytes([
            bin.raw()[abs_off + 4 + dataoff(&bin)],
            bin.raw()[abs_off + 5 + dataoff(&bin)],
            bin.raw()[abs_off + 6 + dataoff(&bin)],
            bin.raw()[abs_off + 7 + dataoff(&bin)],
        ]) as usize;
        assert_eq!(ent.raw().len(), blob_len - 8);
        return;
    }
    panic!("entitlements slot not found in superblob");
}

fn dataoff(bin: &MachoBinary<'_>) -> usize {
    bin.load_commands()
        .find(|lc| lc.kind == 0x1d) // LC_CODE_SIGNATURE
        .map(|lc| {
            let body = lc.bytes;
            u32::from_le_bytes([body[8], body[9], body[10], body[11]]) as usize
        })
        .expect("LC_CODE_SIGNATURE present")
}

#[test]
fn adhoc_requirements_is_empty_placeholder() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let req = bin.signature().unwrap().requirements().expect("adhoc has Requirements slot");
    assert_eq!(req.count(), 0, "adhoc Requirements is empty");
    assert!(req.is_empty());
    assert_eq!(req.len(), 12, "header (8) + count (4) = 12 bytes");
}

#[test]
fn adhoc_cms_is_empty_wrapper() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cms = bin.signature().unwrap().cms().expect("adhoc has SignatureSlot");
    assert!(!cms.is_present(), "adhoc CMS payload is empty");
    assert_eq!(cms.len(), 0);
    assert_eq!(cms.raw().len(), 0);
}

#[test]
fn adhoc_has_no_der_entitlements() {
    let bytes = read(ADHOC_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(bin.signature().unwrap().der_entitlements().is_none());
}

#[test]
fn entitled_der_entitlements_keys_match_plist_source() {
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let der = bin
        .signature()
        .unwrap()
        .der_entitlements()
        .expect("hello-entitled must have a DER entitlements blob");
    assert!(!der.raw().is_empty(), "DER payload should be non-empty");
    let keys = der.keys();
    assert!(keys.contains(&"com.apple.security.app-sandbox".to_string()));
    assert!(keys.contains(&"com.apple.security.network.client".to_string()));
    assert!(keys.contains(&"com.apple.developer.team-identifier".to_string()));
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted);
}

#[test]
fn entitled_requirements_is_empty_for_adhoc_signature() {
    let bytes = read(ENTITLED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let req = bin.signature().unwrap().requirements().unwrap();
    assert_eq!(req.count(), 0);
}

#[test]
fn codesign_arm64_slice_carries_real_cms() {
    if !Path::new(CODESIGN_PATH).exists() {
        eprintln!("skipping: /usr/bin/codesign not present");
        return;
    }
    let bytes = match std::fs::read(CODESIGN_PATH) {
        Ok(b) => b,
        Err(_) => return,
    };
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    let bin = match MachoBinary::parse_with_arch(&bytes, CPU_TYPE_ARM64, CPU_SUBTYPE_ANY) {
        Ok(b) => b,
        Err(_) => return,
    };
    let Some(sig) = bin.signature() else { return };
    if let Some(cms) = sig.cms() {
        assert!(
            cms.is_present(),
            "Apple-signed codesign must carry a real CMS payload"
        );
        assert!(cms.len() > 100, "CMS payload should be more than a placeholder");
    }
    if let Some(req) = sig.requirements() {
        eprintln!(
            "codesign requirements: count={} len={}",
            req.count(),
            req.len()
        );
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    assert!(bytes.len() % 2 == 0);
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nybble(pair[0]) << 4) | nybble(pair[1]));
    }
    out
}

fn nybble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("bad hex nibble: {b:?}"),
    }
}
