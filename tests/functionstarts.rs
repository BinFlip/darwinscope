//! `vm_to_file_offset` + `LC_FUNCTION_STARTS` integration tests.

use std::path::Path;

use darwinscope::MachoBinary;
use darwinscope::util::{read_sleb128, read_uleb128};

const ARM64_PATH: &str = "tests/samples/synthesized/hello-cli/hello-arm64";

fn load() -> Vec<u8> {
    std::fs::read(Path::new(ARM64_PATH)).unwrap()
}

#[test]
fn uleb128_examples() {
    assert_eq!(read_uleb128(&[0x00]), Some((0, 1)));
    assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26]), Some((624_485, 3)));
    assert_eq!(read_uleb128(&[]), None);
}

#[test]
fn sleb128_examples() {
    assert_eq!(read_sleb128(&[0x00]), Some((0, 1)));
    assert_eq!(read_sleb128(&[0x7f]), Some((-1, 1)));
    assert_eq!(read_sleb128(&[0xc0, 0xbb, 0x78]), Some((-123_456, 3)));
}

#[test]
fn vm_to_file_offset_main_lands_in_text() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    // _main is at 0x1_0000_0460 according to nm; __TEXT starts at
    // 0x1_0000_0000 with fileoff 0, so file offset == 0x460.
    assert_eq!(bin.vm_to_file_offset(0x1_0000_0460), Some(0x460));
}

#[test]
fn vm_to_file_offset_pagezero_returns_none() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    // __PAGEZERO has no on-disk backing.
    assert_eq!(bin.vm_to_file_offset(0x1000), None);
}

#[test]
fn vm_to_file_offset_outside_segments_returns_none() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert_eq!(bin.vm_to_file_offset(0xdead_beef_dead_beef), None);
}

#[test]
fn function_starts_yields_main() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let starts: Vec<u64> = bin.function_starts().collect();
    assert_eq!(starts.len(), 1);
    // `_main` lives at 0x1_0000_0460.
    assert_eq!(starts[0], 0x1_0000_0460);
}

#[test]
fn function_starts_count_matches_iterator_length() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    let from_iter = bin.function_starts().count() as u32;
    let from_header = bin.header().function_starts_count().unwrap();
    assert_eq!(from_iter, from_header);
    assert_eq!(from_header, 1);
}

#[test]
fn function_starts_addresses_are_in_text() {
    let bytes = load();
    let bin = MachoBinary::parse(&bytes).unwrap();
    for addr in bin.function_starts() {
        let off = bin
            .vm_to_file_offset(addr)
            .expect("function-start address must translate");
        // Must lie inside __TEXT (file 0..16384 for this fixture).
        assert!(off < 16_384, "addr 0x{addr:x} → off {off}");
    }
}
