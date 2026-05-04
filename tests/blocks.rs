//! Apple Blocks-runtime walker integration tests.
//!
//! None of the synthesized fixtures bundled with this crate exercise
//! the Blocks runtime (the `objc-tiny.m` source uses `@autoreleasepool`
//! and Foundation calls but no `^{}` block expressions, and the
//! `hello-cli` / `swift-tiny` fixtures don't use blocks either). The
//! integration tests here therefore pin the negative path —
//! `MachoBinary::blocks()` must return `None` when neither
//! `_NSConcreteGlobalBlock` nor `_NSConcreteStackBlock` is bound.
//!
//! Positive-path coverage of the literal + descriptor decoder lives
//! in `src/block.rs`'s unit tests, which build a synthetic byte
//! buffer matching the canonical Block ABI and exercise the full
//! `decode_literal` / `decode_descriptor` chain against it.

use std::path::Path;

use darwinscope::MachoBinary;

const OBJC_TINY_ARM64: &str = "tests/samples/synthesized/objc-tiny/objc-tiny-arm64";
const HELLO_ARM64: &str = "tests/samples/synthesized/hello-cli/hello-arm64";
const SWIFT_TINY_ARM64: &str = "tests/samples/synthesized/swift-tiny/swift-tiny-arm64";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(path)).unwrap()
}

#[test]
fn hello_cli_has_no_blocks_runtime() {
    let bytes = read(HELLO_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(
        bin.blocks().is_none(),
        "hello-arm64 binds neither block anchor — blocks() must return None"
    );
}

#[test]
fn objc_tiny_has_no_blocks_runtime() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(
        bin.blocks().is_none(),
        "objc-tiny.m uses no ^{{}} expressions — blocks() must return None"
    );
}

#[test]
fn swift_tiny_has_no_blocks_runtime() {
    let bytes = read(SWIFT_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(
        bin.blocks().is_none(),
        "swift-tiny carries no Obj-C blocks — blocks() must return None"
    );
}
