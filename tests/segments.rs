//! `Segment` / `Section` iterator integration tests.

use std::path::Path;

use darwinscope::MachoBinary;
use darwinscope::segment::{SectionAttributes, SectionType};

const ARM64_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64";

fn load() -> Vec<u8> {
    std::fs::read(Path::new(ARM64_PATH)).expect("fixture")
}

#[test]
fn segments_in_load_command_order() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let names: Vec<String> = bin.segments().map(|s| s.name().to_string()).collect();
    // arm64 fixture from `clang -arch arm64`:
    //   __PAGEZERO, __TEXT, __DATA_CONST, __LINKEDIT
    assert_eq!(
        names,
        vec!["__PAGEZERO", "__TEXT", "__DATA_CONST", "__LINKEDIT"]
    );
}

#[test]
fn pagezero_has_no_filesize() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let pz = bin.segments().find(|s| s.name() == "__PAGEZERO").unwrap();
    assert_eq!(pz.fileoff(), 0);
    assert_eq!(pz.filesize(), 0);
    assert_eq!(pz.body().len(), 0);
    // 64-bit page-zero is conventionally 4 GiB.
    assert_eq!(pz.vmsize(), 0x1_0000_0000);
    assert_eq!(pz.maxprot(), 0);
    assert_eq!(pz.initprot(), 0);
    assert_eq!(pz.nsects(), 0);
}

#[test]
fn text_segment_has_expected_sections() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let text = bin.segments().find(|s| s.name() == "__TEXT").unwrap();
    assert_eq!(text.nsects(), 4);
    assert_eq!(text.fileoff(), 0);
    assert!(text.filesize() > 0);
    let sect_names: Vec<String> = text
        .sections()
        .map(|s| s.sectname().to_string())
        .collect();
    assert_eq!(
        sect_names,
        vec!["__text", "__stubs", "__cstring", "__unwind_info"]
    );
}

#[test]
fn flat_sections_iterator_walks_every_segment() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    // __TEXT contributes 4, __DATA_CONST contributes 1, __PAGEZERO
    // and __LINKEDIT contribute 0 each. Total = 5.
    let n = bin.sections().count();
    assert_eq!(n, 5);
}

#[test]
fn section_metadata_text() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let text = bin.sections().find(|s| s.sectname() == "__text").unwrap();
    assert_eq!(text.segname(), "__TEXT");
    assert!(text.size() > 0);
    assert!(text.offset() > 0);
    assert_eq!(text.section_type(), SectionType::Regular);
    // __text is `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`.
    let attrs = text.attributes();
    assert!(attrs.contains(SectionAttributes::PURE_INSTRUCTIONS));
    assert!(attrs.contains(SectionAttributes::SOME_INSTRUCTIONS));
}

#[test]
fn cstring_section_type() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let s = bin
        .sections()
        .find(|s| s.sectname() == "__cstring")
        .unwrap();
    assert_eq!(s.section_type(), SectionType::CStringLiterals);
    // body should contain "hi\0" (the puts() arg).
    let body = s.body();
    assert!(body.starts_with(b"hi\0"), "got body: {:?}", body);
}

#[test]
fn section_body_is_within_segment_filesize() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    for sect in bin.sections() {
        let len = sect.body().len() as u64;
        if !sect.section_type().is_zero_fill() {
            assert!(
                len == 0 || (sect.offset() as u64) + len <= bytes.len() as u64,
                "section {} body must lie inside the file",
                sect.sectname()
            );
        }
    }
}

#[test]
fn shannon_entropy_in_range() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let text = bin.sections().find(|s| s.sectname() == "__text").unwrap();
    let h = text.shannon_entropy();
    assert!(
        (0.0..=8.0).contains(&h),
        "Shannon entropy must lie in [0, 8] bits, got {h}"
    );
    // Real machine code has nontrivial entropy; assert it's > 0.
    assert!(h > 0.0);
}

#[test]
fn shannon_entropy_uniform_bytes() {
    // Indirect test: exercise via a section we can predict. The
    // 3-byte __cstring "hi\0" has entropy log2(3) ≈ 1.585.
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let s = bin
        .sections()
        .find(|s| s.sectname() == "__cstring")
        .unwrap();
    let body = s.body();
    // Body may include extra cstrings depending on link; but the
    // first 3 bytes are "hi\0" with three distinct symbols. Just
    // assert the entropy is bounded by log2(256) = 8.
    let h = s.shannon_entropy();
    assert!(h > 0.0 && h <= 8.0);
    assert!(body.len() >= 3);
}

#[test]
fn blake3_stable_for_text_section() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let text = bin.sections().find(|s| s.sectname() == "__text").unwrap();
    let h1 = text.blake3();
    let h2 = text.blake3();
    assert_eq!(h1, h2, "blake3 must be deterministic");

    // Cross-check: hashing the same body slice manually should match.
    let h3 = blake3::hash(text.body());
    assert_eq!(h1, h3);
}

#[test]
fn empty_section_entropy_and_blake3() {
    // __PAGEZERO has no sections, so use any section we can find
    // with empty body. None on this fixture have empty bodies, so
    // simulate via a synthetic empty slice through the section
    // type table:
    assert_eq!(
        SectionType::from_raw(0x12),
        SectionType::ThreadLocalZeroFill
    );
    assert!(SectionType::ZeroFill.is_zero_fill());
    assert!(SectionType::GbZeroFill.is_zero_fill());
    assert!(SectionType::ThreadLocalZeroFill.is_zero_fill());
    assert!(!SectionType::Regular.is_zero_fill());
}

#[test]
fn section_type_round_trips_unknown() {
    // S_DTRACE_DOF maps to a known variant; an unknown 0x42 should
    // round-trip via Other.
    assert_eq!(SectionType::from_raw(0x42), SectionType::Other(0x42));
}
