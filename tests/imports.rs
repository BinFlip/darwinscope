//! Imports integration tests.
//!
//! Two fixtures cover both bind encodings:
//!
//! - `hello-arm64-legacy` (built with `-Wl,-no_fixup_chains`) carries
//!   `LC_DYLD_INFO_ONLY` bind opcodes (decoded by goblin).
//! - `hello-arm64` (default modern link) carries
//!   `LC_DYLD_CHAINED_FIXUPS` (decoded by [`darwinscope::fixup`]
//!   and folded into [`MachoBinary::imports`]).
//!
//! Snapshot tests in `tests/snapshots.rs` cover the full per-row
//! values; tests here pin the merge invariants and the
//! file-offset / vm-address round-trip.

use std::path::Path;

use darwinscope::MachoBinary;

const LEGACY_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64-legacy";
const CHAINED_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(path)).unwrap()
}

#[test]
fn legacy_bind_opcodes_yield_puts() {
    let bytes = read(LEGACY_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let imports: Vec<_> = bin.imports().collect();
    assert!(
        !imports.is_empty(),
        "legacy fixture must produce >0 imports"
    );
    let puts = imports
        .iter()
        .find(|i| i.name == "_puts")
        .expect("_puts must be bound");
    assert_eq!(puts.dylib, "/usr/lib/libSystem.B.dylib");
    assert!(!puts.is_lazy || puts.size == 8); // lazy stubs are 8 bytes
}

#[test]
fn legacy_bind_addresses_translate_to_file_offsets() {
    let bytes = read(LEGACY_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    for imp in bin.imports() {
        let off = bin
            .vm_to_file_offset(imp.address)
            .expect("import address must be mappable");
        assert_eq!(
            off, imp.offset,
            "import {} offset/address disagree",
            imp.name
        );
    }
}

#[test]
fn chained_fixup_binary_imports_includes_chained_binds() {
    let bytes = read(CHAINED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let imports: Vec<_> = bin.imports().collect();
    assert!(
        imports.iter().any(|i| i.name == "_puts"),
        "chained-fixup binary must yield _puts via the chained path; got {imports:?}"
    );
}

#[test]
fn chained_binary_imports_match_chained_binds() {
    let bytes = read(CHAINED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let chained_names: Vec<&str> = bin.chained_binds().map(|b| b.name()).collect();
    let import_names: Vec<&str> = bin.imports().map(|i| i.name).collect();
    for n in &chained_names {
        assert!(
            import_names.contains(n),
            "chained bind {n:?} missing from imports(); got {import_names:?}"
        );
    }
}

#[test]
fn chained_imports_offset_matches_vm_to_file_offset() {
    let bytes = read(CHAINED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    for imp in bin.imports() {
        let computed = bin.vm_to_file_offset(imp.address).unwrap_or(0);
        assert_eq!(
            imp.offset, computed,
            "import {} address/offset mismatch",
            imp.name
        );
    }
}

#[test]
fn chained_imports_carry_dylib_path() {
    let bytes = read(CHAINED_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let mut count = 0;
    for imp in bin.imports() {
        assert!(!imp.dylib.is_empty(), "import {} has empty dylib", imp.name);
        count += 1;
    }
    assert!(count >= 1);
}
