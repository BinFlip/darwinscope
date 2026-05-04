//! Stage 1 PR 6 — Export trie walker.
//!
//! Both fixtures must yield the same two exports:
//! `__mh_execute_header` (image header) and `_main`.

use std::path::Path;

use darwinscope::MachoBinary;
use darwinscope::export::{ExportInfo, ExportKind};

const ARM64_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64";
const LEGACY_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64-legacy";

fn load(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(path)).unwrap()
}

fn assert_hello_exports(path: &str) {
    let bytes = load(path);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let exports: Vec<_> = bin.exports().collect();

    let header = exports
        .iter()
        .find(|e| e.name == "__mh_execute_header")
        .unwrap_or_else(|| panic!("__mh_execute_header missing in {path}"));
    assert_eq!(header.kind, ExportKind::Regular);
    assert!(matches!(header.info, ExportInfo::Regular { .. }));

    let main = exports
        .iter()
        .find(|e| e.name == "_main")
        .unwrap_or_else(|| panic!("_main missing in {path}"));
    assert_eq!(main.kind, ExportKind::Regular);
    if let ExportInfo::Regular { address } = main.info {
        // _main lives at offset 0x460 from __TEXT, but the trie
        // stores it as the offset. The ExportInfo::Regular address
        // is what dyld uses, so it should match the offset.
        assert!(address > 0);
    } else {
        panic!("_main info shape: {:?}", main.info);
    }
    // No reexports / stubs in a hello-world binary.
    assert!(
        exports
            .iter()
            .all(|e| matches!(e.info, ExportInfo::Regular { .. }))
    );
}

#[test]
fn exports_chained_fixup_fixture() {
    assert_hello_exports(ARM64_PATH);
}

#[test]
fn exports_legacy_fixture() {
    assert_hello_exports(LEGACY_PATH);
}

#[test]
fn export_count_matches() {
    let bytes = load(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let n = bin.exports().count();
    // dyld_info reports 2 exports for this binary.
    assert_eq!(n, 2);
}

#[test]
fn export_offset_field_populated_for_regular_exports() {
    let bytes = load(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    for e in bin.exports() {
        if let ExportInfo::Regular { address } = e.info {
            // Goblin's `Export.offset` is set to the ExportInfo
            // Regular address by design — they should match.
            assert_eq!(e.offset, address, "{}: offset/address mismatch", e.name);
        }
    }
}
