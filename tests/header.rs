//! `MachoBinary::parse` + `Header` view integration tests.
//!
//! Exercises every accessor against the synthesized
//! `hello-arm64` / `hello-x86_64` / `hello-fat` fixtures in
//! `tests/samples/synthesized/hello-cli/`. Snapshot tests in
//! `tests/snapshots.rs` cover per-field values; tests here pin
//! the parse-selection logic (fat slice picker, arch-mismatch
//! errors, garbage rejection) and the `Version` /
//! `SourceVersion` decoders.

use std::path::Path;

use darwinscope::binary::CPU_SUBTYPE_ANY;
use darwinscope::{Error, MachoBinary};

const ARM64_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64";
const X86_64_PATH: &str = "tests/samples/synthesized/hello-cli/hello-x86_64";
const FAT_PATH: &str = "tests/samples/synthesized/hello-cli/hello-fat";

const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_EXECUTE: u32 = 0x2;
const PLATFORM_MACOS: u32 = 1;

fn read_fixture(p: impl AsRef<Path>) -> Vec<u8> {
    std::fs::read(p.as_ref()).expect("fixture must exist")
}

#[test]
fn parse_thin_arm64() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).expect("arm64 parses");
    assert_eq!(bin.fat_arch_count(), 1);
}

#[test]
fn parse_thin_x86_64() {
    let bytes = read_fixture(X86_64_PATH);
    let bin = MachoBinary::parse(&bytes).expect("x86_64 parses");
    assert_eq!(bin.fat_arch_count(), 1);
}

#[test]
fn parse_fat_picks_first_slice() {
    let bytes = read_fixture(FAT_PATH);
    let bin = MachoBinary::parse(&bytes).expect("fat parses");
    assert_eq!(bin.fat_arch_count(), 2);
    // fixture order is x86_64 first, arm64 second
    assert_eq!(bin.header().cputype(), CPU_TYPE_X86_64);
}

#[test]
fn parse_fat_data_view_is_slice_not_full_archive() {
    // Regression: previously MachoBinary.data was the full fat
    // archive bytes, so offsets goblin emitted (relative to the
    // slice) didn't translate. This test pins the fix in place.
    let bytes = read_fixture(FAT_PATH);
    let bin = MachoBinary::parse_with_arch(&bytes, CPU_TYPE_ARM64, CPU_SUBTYPE_ANY).unwrap();
    // The slice's `raw()` must equal a contiguous sub-range of the
    // fat archive — never the full archive.
    assert!(
        bin.raw().len() < bytes.len(),
        "fat slice shouldn't equal full archive"
    );
    assert!(!bin.raw().is_empty());
    // Any function-start address must translate to a file offset
    // that lies inside `raw()` (not past it).
    for addr in bin.function_starts() {
        let off = bin
            .vm_to_file_offset(addr)
            .expect("function start must map");
        assert!(
            (off as usize) < bin.raw().len(),
            "fat slice offset 0x{off:x} must lie in raw() (len={})",
            bin.raw().len(),
        );
    }
}

#[test]
fn parse_with_arch_selects_arm64_from_fat() {
    let bytes = read_fixture(FAT_PATH);
    let bin = MachoBinary::parse_with_arch(&bytes, CPU_TYPE_ARM64, CPU_SUBTYPE_ANY)
        .expect("arm64 slice present");
    assert_eq!(bin.fat_arch_count(), 2);
    assert_eq!(bin.header().cputype(), CPU_TYPE_ARM64);
}

#[test]
fn parse_with_arch_selects_x86_from_fat() {
    let bytes = read_fixture(FAT_PATH);
    let bin = MachoBinary::parse_with_arch(&bytes, CPU_TYPE_X86_64, CPU_SUBTYPE_ANY)
        .expect("x86_64 slice present");
    assert_eq!(bin.header().cputype(), CPU_TYPE_X86_64);
}

#[test]
fn parse_with_arch_thin_match() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse_with_arch(&bytes, CPU_TYPE_ARM64, CPU_SUBTYPE_ANY)
        .expect("thin arm64 matches arm64");
    assert_eq!(bin.fat_arch_count(), 1);
}

#[test]
fn parse_with_arch_thin_mismatch_errors() {
    let bytes = read_fixture(ARM64_PATH);
    let err = MachoBinary::parse_with_arch(&bytes, CPU_TYPE_X86_64, CPU_SUBTYPE_ANY)
        .expect_err("arm64 thin must not match x86_64");
    assert!(matches!(err, Error::NoMatchingArchSlice));
}

#[test]
fn parse_garbage_rejects() {
    let bytes = vec![0u8; 16];
    let err = MachoBinary::parse(&bytes).expect_err("garbage is not Mach-O");
    // goblin returns BadMagic → wrapped into Error::Structural.
    assert!(matches!(err, Error::Structural(_)));
}

#[test]
fn raw_returns_input_slice() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert_eq!(bin.raw().as_ptr(), bytes.as_ptr());
    assert_eq!(bin.raw().len(), bytes.len());
}

#[test]
fn header_magic_arm64() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert_eq!(bin.header().magic(), MH_MAGIC_64);
}

#[test]
fn header_cputype_cpusubtype() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let h = bin.header();
    assert_eq!(h.cputype(), CPU_TYPE_ARM64);
    assert_eq!(h.cpusubtype(), 0); // CPU_SUBTYPE_ARM64_ALL
}

#[test]
fn header_filetype() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert_eq!(bin.header().filetype(), MH_EXECUTE);
}

#[test]
fn header_ncmds_sizeofcmds() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let h = bin.header();
    assert!(h.ncmds() > 0);
    assert!(h.sizeofcmds() > 0);
    // sizeofcmds is at least 8 bytes per command (LC header is 8 B)
    assert!(h.sizeofcmds() as u64 >= h.ncmds() as u64 * 8);
}

#[test]
fn header_flags_pie() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    // Modern clang produces PIE binaries (MH_PIE = 0x0020_0000).
    assert_ne!(bin.header().flags() & 0x0020_0000, 0);
}

#[test]
fn header_reserved_zero() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert_eq!(bin.header().reserved(), 0);
}

#[test]
fn header_is_64() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(bin.header().is_64());
}

#[test]
fn header_uuid_present() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let uuid = bin.header().uuid().expect("LC_UUID present");
    assert_ne!(uuid, [0u8; 16], "uuid should not be all-zero");
}

#[test]
fn header_min_os_macos() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let min_os = bin.header().min_os().expect("LC_BUILD_VERSION present");
    assert_eq!(min_os.platform, PLATFORM_MACOS);
    // clang on this host emits major >= 26.0 (otool: minos 26.0).
    assert!(min_os.version.major >= 11, "macOS major should be >= 11");
}

#[test]
fn header_sdk_version_present() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let sdk = bin
        .header()
        .sdk_version()
        .expect("LC_BUILD_VERSION sdk present");
    assert!(sdk.major >= 11);
}

#[test]
fn header_source_version_present() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    // clang emits LC_SOURCE_VERSION with version 0.0 by default;
    // presence is what we assert. The packed-u64 decode returns the
    // all-zero variant for that case.
    let src = bin
        .header()
        .source_version()
        .expect("LC_SOURCE_VERSION present");
    assert_eq!(src.a, 0);
}

#[test]
fn header_build_tools_nonempty() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let tools = bin.header().build_tools();
    // Modern ld64 records itself as TOOL_LD; clang may also be
    // present. Either way, expect at least one tool.
    assert!(!tools.is_empty(), "LC_BUILD_VERSION should record tools");
}

#[test]
fn header_dylinker() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert_eq!(bin.header().dylinker(), Some("/usr/lib/dyld"));
}

#[test]
fn header_function_starts_present() {
    let bytes = read_fixture(ARM64_PATH);
    let bin = MachoBinary::parse(&bytes).unwrap();
    // The hello-arm64 fixture has exactly one function (`_main`).
    assert_eq!(bin.header().function_starts_count(), Some(1));
}

// `Version` / `SourceVersion` decoder coverage lives as inline
// unit tests in `src/binary.rs`.
