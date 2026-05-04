//! `__cfstring` walker integration tests.
//!
//! Exercises the CFString walker against the synthesized `objc-tiny`
//! fixture. `objc-tiny.m` contains six ASCII NSString literals
//! (`@"darwinscope"`, `@"world"`, `@"hello"`, `@"hi from %@"`,
//! `@"reversed: %@"`, `@"%C"`) which the linker emits into
//! `__DATA_CONST,__cfstring`. The negative path verifies that
//! `hello-arm64`, which carries no CoreFoundation strings, returns
//! `None`.

use std::path::Path;

use darwinscope::{CFStringBody, CFStringEncoding, MachoBinary};

const OBJC_TINY_ARM64: &str = "tests/samples/synthesized/objc-tiny/objc-tiny-arm64";
const OBJC_TINY_X86_64: &str = "tests/samples/synthesized/objc-tiny/objc-tiny-x86_64";
const HELLO_ARM64: &str = "tests/samples/synthesized/hello-cli/hello-arm64";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(path)).unwrap()
}

#[test]
fn no_cfstring_section_returns_none() {
    let bytes = read(HELLO_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(
        bin.cfstrings().is_none(),
        "hello-arm64 emits no NSString constants; cfstrings() must return None"
    );
}

#[test]
fn objc_tiny_arm64_decodes_ascii_literals() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.cfstrings().expect("objc-tiny carries __cfstring");

    let entries: Vec<_> = rt.iter().collect();
    assert!(
        !entries.is_empty(),
        "objc-tiny.m has six NSString literals — expected non-empty __cfstring"
    );

    // Every literal in this fixture is ASCII.
    for e in &entries {
        assert_eq!(
            e.encoding,
            CFStringEncoding::Ascii,
            "expected ASCII encoding for '{:?}', flags=0x{:x}",
            e.body,
            e.flags
        );
        assert!(
            matches!(e.body, CFStringBody::Ascii(_)),
            "expected resolved ASCII body, got {:?}",
            e.body
        );
        // length is in characters; for ASCII that's bytes.
        if let CFStringBody::Ascii(s) = e.body {
            assert_eq!(
                s.len() as u64,
                e.length,
                "length field must match resolved-body length for ASCII"
            );
        }
    }

    // Pin the source-level set: every literal authored in
    // objc-tiny.m must appear at least once.
    let bodies: Vec<&str> = entries
        .iter()
        .filter_map(|e| match e.body {
            CFStringBody::Ascii(s) => Some(s),
            _ => None,
        })
        .collect();
    for expected in [
        "darwinscope",
        "world",
        "hello",
        "hi from %@",
        "reversed: %@",
        "%C",
    ] {
        assert!(
            bodies.contains(&expected),
            "expected literal {expected:?} in __cfstring; got {bodies:?}"
        );
    }
}

#[test]
fn objc_tiny_x86_64_decodes_ascii_literals() {
    // x86_64 uses legacy LC_DYLD_INFO bind opcodes (not chained
    // fixups). The walker must resolve `str` slots through the
    // PAC-strip fallback path rather than the rebase index.
    let bytes = read(OBJC_TINY_X86_64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin
        .cfstrings()
        .expect("objc-tiny x86_64 carries __cfstring");
    let entries: Vec<_> = rt.iter().collect();
    assert!(!entries.is_empty());
    for e in &entries {
        assert!(
            matches!(e.body, CFStringBody::Ascii(_)),
            "x86_64 fixture: expected resolved ASCII body, got {:?}",
            e.body
        );
    }
}

#[test]
fn entry_addresses_are_section_relative_and_strided() {
    // Every CFString entry sits at an 8-byte-aligned, 32-byte-strided
    // offset inside __cfstring. This guards against an off-by-one in
    // the iterator's stride bookkeeping.
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.cfstrings().unwrap();
    let entries: Vec<_> = rt.iter().collect();
    let first = entries.first().expect("at least one entry");
    for (i, e) in entries.iter().enumerate() {
        let expected = first.address + (i as u64) * 32;
        assert_eq!(
            e.address, expected,
            "entry {i} should be at first.address + i*32"
        );
    }
}
