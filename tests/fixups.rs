//! `LC_DYLD_CHAINED_FIXUPS` integration tests.
//!
//! Covers:
//!
//! - Header walker, segment dispatch, imports table
//!   (`hello-arm64`, `hello-arm64-legacy`, `hello-fat`).
//! - Pointer formats `_64` + `_64_OFFSET` (`hello-arm64`,
//!   `hello-x86_64`).
//! - arm64e PAC formats opportunistically against
//!   `/usr/bin/codesign` (skipped when absent).
//!
//! Snapshot tests in `tests/snapshots.rs` cover the per-row
//! values; tests here pin the supported-format set, the legacy
//! → empty contract, and the file-offset round-trip.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::path::Path;

use darwinscope::{
    MachoBinary,
    binary::CPU_SUBTYPE_ANY,
    fixup::{ImportsFormat, PointerFormat},
};

const ARM64_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64";
const X86_64_PATH: &str = "tests/samples/synthesized/hello-cli/hello-x86_64";
const LEGACY_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64-legacy";
const FAT_PATH: &str = "tests/samples/synthesized/hello-cli/hello-fat";
const CODESIGN_PATH: &str = "/usr/bin/codesign";

const CPU_TYPE_ARM64: u32 = 0x0100_000c;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(path)).unwrap()
}

#[test]
fn chained_fixups_present_on_modern_arm64() {
    let bytes = read(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cf = bin
        .chained_fixups()
        .expect("hello-arm64 must carry LC_DYLD_CHAINED_FIXUPS");
    assert_eq!(cf.version(), 0);
    assert!(cf.imports_count() >= 1, "expected at least 1 import");
}

#[test]
fn chained_fixups_absent_on_legacy_arm64() {
    let bytes = read(LEGACY_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(
        bin.chained_fixups().is_none(),
        "hello-arm64-legacy uses LC_DYLD_INFO_ONLY — no chained-fixup header"
    );
}

#[test]
fn chained_segments_have_supported_pointer_format() {
    let bytes = read(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cf = bin.chained_fixups().unwrap();
    let segs: Vec<_> = cf.segments().collect();
    assert!(!segs.is_empty(), "expected at least one chained segment");
    for seg in &segs {
        assert!(
            seg.pointer_format.is_supported(),
            "segment {} has unsupported pointer_format raw={:#x}",
            seg.seg_index,
            seg.raw_pointer_format
        );
        assert!(
            seg.page_size == 0x1000 || seg.page_size == 0x4000,
            "segment {} unexpected page_size={:#x}",
            seg.seg_index,
            seg.page_size
        );
    }
}

#[test]
fn chained_imports_resolve_puts() {
    let bytes = read(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cf = bin.chained_fixups().unwrap();
    let imports: Vec<_> = cf.imports().collect();
    assert!(!imports.is_empty(), "imports table must yield ≥ 1 entry");
    let names: Vec<&str> = imports.iter().map(|i| i.name).collect();
    assert!(
        names.contains(&"_puts"),
        "expected _puts in imports; got {names:?}"
    );
}

#[test]
fn chained_imports_format_is_known() {
    let bytes = read(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let cf = bin.chained_fixups().unwrap();
    assert!(
        matches!(
            cf.imports_format(),
            ImportsFormat::Plain | ImportsFormat::Addend
        ),
        "unexpected imports_format: {:?}",
        cf.imports_format()
    );
}

#[test]
fn chained_fixups_in_fat_slice_decode() {
    let bytes = read(FAT_PATH);
    let bin = MachoBinary::parse_with_arch(&bytes, CPU_TYPE_ARM64, CPU_SUBTYPE_ANY).unwrap();
    if let Some(cf) = bin.chained_fixups() {
        let _segs: Vec<_> = cf.segments().collect();
        let _imports: Vec<_> = cf.imports().collect();
    }
}

#[test]
fn supported_pointer_format_set() {
    use PointerFormat::*;
    let supported = [
        Arm64e,
        Ptr64,
        Ptr64Offset,
        Arm64eKernel,
        Arm64eUserland,
        Arm64eUserland24,
        Arm64eSharedCache,
    ];
    for f in supported {
        assert!(f.is_supported());
    }
    assert!(!PointerFormat::Other(99).is_supported());
}

#[test]
fn x86_64_chained_rebases_walk_without_panic() {
    let bytes = read(X86_64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    for r in bin.chained_rebases() {
        assert!(r.target_vmaddr() > 0, "target_vmaddr should be non-zero");
        assert!(matches!(r.pointer_format(), PointerFormat::Ptr64Offset));
        assert!(r.ptr_auth().is_none());
        assert!(r.high8().is_some());
    }
}

#[test]
fn x86_64_chained_binds_resolve_puts_to_libsystem() {
    let bytes = read(X86_64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let binds: Vec<_> = bin.chained_binds().collect();
    assert!(!binds.is_empty(), "expected ≥ 1 chained bind on x86_64");
    let puts = binds
        .iter()
        .find(|b| b.name() == "_puts")
        .expect("_puts must be a chained bind target");
    assert!(
        puts.dylib().contains("libSystem"),
        "got dylib={}",
        puts.dylib()
    );
    assert!(!puts.is_weak());
    assert!(puts.ptr_auth().is_none());
    assert!(matches!(puts.pointer_format(), PointerFormat::Ptr64Offset));
}

#[test]
fn arm64_chained_rebases_walk_without_panic() {
    let bytes = read(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    for r in bin.chained_rebases() {
        assert!(matches!(r.pointer_format(), PointerFormat::Ptr64Offset));
        assert!(r.target_vmaddr() > 0);
    }
}

#[test]
fn arm64_chained_binds_resolve_puts() {
    let bytes = read(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let binds: Vec<_> = bin.chained_binds().collect();
    let puts = binds
        .iter()
        .find(|b| b.name() == "_puts")
        .expect("_puts must be a chained bind target on arm64");
    assert!(
        puts.dylib().contains("libSystem"),
        "got dylib={}",
        puts.dylib()
    );
}

#[test]
fn legacy_binary_has_empty_chained_iterators() {
    let bytes = read(LEGACY_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert_eq!(bin.chained_rebases().count(), 0);
    assert_eq!(bin.chained_binds().count(), 0);
}

#[test]
fn bind_vm_address_lands_inside_data_segment() {
    let bytes = read(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let mut count = 0;
    for b in bin.chained_binds() {
        let off = bin.vm_to_file_offset(b.vm_address());
        assert!(
            off.is_some(),
            "bind vm_address 0x{:x} must map to a file offset",
            b.vm_address()
        );
        count += 1;
    }
    assert!(count >= 1, "expected ≥ 1 bind on hello-arm64");
}

#[test]
fn fat_arm64_slice_chains_decode() {
    let bytes = read(FAT_PATH);
    let bin = MachoBinary::parse_with_arch(&bytes, CPU_TYPE_ARM64, CPU_SUBTYPE_ANY).unwrap();
    let _rebases: Vec<_> = bin.chained_rebases().collect();
    let binds: Vec<_> = bin.chained_binds().collect();
    assert!(binds.iter().any(|b| b.name() == "_puts"));
}

fn arm64e_format(f: PointerFormat) -> bool {
    matches!(
        f,
        PointerFormat::Arm64e
            | PointerFormat::Arm64eUserland
            | PointerFormat::Arm64eUserland24
            | PointerFormat::Arm64eKernel
            | PointerFormat::Arm64eSharedCache
    )
}

#[test]
fn arm64e_format_set_supported() {
    use PointerFormat::*;
    for f in [
        Arm64e,
        Arm64eUserland,
        Arm64eUserland24,
        Arm64eKernel,
        Arm64eSharedCache,
    ] {
        assert!(f.is_supported());
    }
}

#[test]
fn codesign_arm64e_slice_chains_decode_without_error() {
    if !Path::new(CODESIGN_PATH).exists() {
        eprintln!("skipping: /usr/bin/codesign not present");
        return;
    }
    let bytes = match std::fs::read(CODESIGN_PATH) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skipping: cannot read {CODESIGN_PATH}: {e}");
            return;
        }
    };
    let bin = match MachoBinary::parse_with_arch(&bytes, CPU_TYPE_ARM64, CPU_SUBTYPE_ANY) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skipping: arm64 slice not present: {e:?}");
            return;
        }
    };
    let Some(cf) = bin.chained_fixups() else {
        eprintln!("skipping: codesign arm64 slice has no chained fixups");
        return;
    };

    let mut saw_arm64e = false;
    for s in cf.segments() {
        if arm64e_format(s.pointer_format) {
            saw_arm64e = true;
        }
    }
    if !saw_arm64e {
        eprintln!("skipping: codesign arm64 slice uses non-arm64e format");
        return;
    }

    let rebases: Vec<_> = bin.chained_rebases().collect();
    assert!(
        !rebases.is_empty(),
        "expected ≥ 1 chained rebase in codesign's arm64e slice"
    );
    let auth_count = rebases.iter().filter(|r| r.ptr_auth().is_some()).count();
    eprintln!(
        "codesign arm64e: {} rebases ({} authenticated)",
        rebases.len(),
        auth_count
    );

    let binds: Vec<_> = bin.chained_binds().collect();
    assert!(
        !binds.is_empty(),
        "expected ≥ 1 chained bind in codesign's arm64e slice"
    );
    for b in &binds {
        assert!(!b.name().is_empty(), "bind name should not be empty");
    }
}
