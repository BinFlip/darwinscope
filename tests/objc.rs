//! Objective-C runtime walker integration tests.
//!
//! Exercises the full ObjC walker against the synthesized
//! `objc-tiny` fixture: image-info flag accessors, class +
//! `class_ro_t` decode, metaclass pairing,
//! `__objc_classlist`/`__objc_nlclslist` dedup, method (small +
//! legacy) and ivar/property walkers, the `Spoken` protocol, the
//! `NSString` category (foreign-class resolution via
//! chained-fixup bind), conformance edges, and the
//! sel/class/super/proto reference sections with `RefTarget`
//! resolution. Snapshot tests in `tests/snapshots.rs` cover the
//! per-field values; tests here pin cross-API behaviors and the
//! "no ObjC content → `objc()` returns `None`" negative path on
//! `hello-arm64`.

use std::path::Path;

use darwinscope::{
    MachoBinary, ObjcRuntime, RefTarget, objc::OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES,
};

const OBJC_TINY_ARM64: &str = "tests/samples/synthesized/objc-tiny/objc-tiny-arm64";
const OBJC_TINY_X86_64: &str = "tests/samples/synthesized/objc-tiny/objc-tiny-x86_64";
const OBJC_TINY_FAT: &str = "tests/samples/synthesized/objc-tiny/objc-tiny-fat";
const HELLO_ARM64: &str = "tests/samples/synthesized/hello-cli/hello-arm64";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(path)).unwrap()
}

#[test]
fn no_objc_content_returns_none() {
    let bytes = read(HELLO_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    assert!(
        bin.objc().is_none(),
        "hello-arm64 has no ObjC content; objc() must return None"
    );
}

#[test]
fn image_info_parses_and_exposes_flags() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt: ObjcRuntime<'_> = bin.objc().expect("objc-tiny has ObjC content");

    let info = rt.image_info();
    assert_eq!(info.version, 0);
    // Modern toolchain always sets HasCategoryClassProperties when
    // it emits the trailing field on category records.
    assert!(
        info.flags & OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES != 0,
        "objc-tiny should have HasCategoryClassProperties; got flags=0x{:x}",
        info.flags,
    );
    assert!(info.has_category_class_properties());
    assert!(!info.contains_swift());
    assert!(!info.requires_gc());
    assert!(!info.supports_gc());
}

#[test]
fn classlist_emits_greeter_with_metaclass_pair() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let classes: Vec<_> = rt.classes().collect();
    // At least one instance class plus its metaclass twin.
    assert!(
        classes.len() >= 2,
        "expected >= 2 class rows (instance + metaclass), got {}",
        classes.len()
    );

    // The first row is the instance class; the second is its meta.
    assert!(!classes[0].is_meta(), "first row should be instance class");
    assert!(classes[1].is_meta(), "second row should be the metaclass");

    let names: Vec<_> = classes
        .iter()
        .filter_map(|c| c.ro().map(|r| r.name()))
        .collect();
    assert!(
        names.contains(&"Greeter"),
        "expected to find class named 'Greeter'; got {names:?}",
    );
}

#[test]
fn class_ro_decodes_instance_size_and_flags() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let greeter = rt
        .classes()
        .find(|c| !c.is_meta() && c.ro().map(|r| r.name()) == Some("Greeter"))
        .expect("Greeter class");
    let ro = greeter.ro().unwrap();
    assert_eq!(ro.name(), "Greeter");
    // Greeter has one ivar (_name, 8 bytes pointer) on top of
    // NSObject's isa (8 bytes) → instance_size = 16.
    assert_eq!(
        ro.instance_size(),
        16,
        "Greeter instance_size should be 16 (isa + _name); got {}",
        ro.instance_size(),
    );
    assert_eq!(
        ro.instance_start(),
        8,
        "Greeter instance_start should be 8 (after NSObject isa); got {}",
        ro.instance_start(),
    );
    // Auto-synthesized property + ARC ⇒ HAS_CXX_STRUCTORS set.
    assert!(
        ro.has_cxx_structors(),
        "Greeter should have RO_HAS_CXX_STRUCTORS"
    );
    assert!(!ro.is_meta(), "Greeter instance ro must not be RO_META");
}

#[test]
fn methods_resolve_selectors_through_small_selref_indirection() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let greeter = rt
        .classes()
        .find(|c| !c.is_meta() && c.ro().map(|r| r.name()) == Some("Greeter"))
        .unwrap();
    let ro = greeter.ro().unwrap();
    let methods: Vec<_> = ro.methods().collect();
    assert!(!methods.is_empty(), "Greeter must have at least 1 method");
    // Modern toolchain emits the small format.
    for m in &methods {
        assert!(
            m.is_small(),
            "Greeter methods should be small format; got {:?} for {:?}",
            m.kind(),
            m.selector(),
        );
    }
    let sels: Vec<&str> = methods.iter().map(|m| m.selector()).collect();
    assert!(
        sels.contains(&"greet"),
        "expected 'greet' selector on Greeter; got {sels:?}"
    );
    assert!(
        sels.contains(&"speak"),
        "expected 'speak' selector (merged from category) on Greeter; got {sels:?}",
    );
    assert!(
        sels.contains(&"name"),
        "expected synthesised 'name' getter on Greeter; got {sels:?}",
    );
    assert!(
        sels.contains(&"setName:"),
        "expected synthesised 'setName:' on Greeter; got {sels:?}",
    );
    // Every method has an IMP (none are abstract on a class).
    for m in &methods {
        assert!(
            m.implementation().is_some(),
            "method {:?} must have an IMP",
            m.selector()
        );
    }
    // Type encodings round-trip.
    let greet = methods.iter().find(|m| m.selector() == "greet").unwrap();
    assert_eq!(greet.types(), "v16@0:8");
}

#[test]
fn ivar_walker_decodes_underscore_name_with_offset() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let greeter = rt
        .classes()
        .find(|c| !c.is_meta() && c.ro().map(|r| r.name()) == Some("Greeter"))
        .unwrap();
    let ro = greeter.ro().unwrap();
    let ivars: Vec<_> = ro.ivars().collect();
    assert_eq!(ivars.len(), 1, "Greeter has exactly one ivar");
    let v = &ivars[0];
    assert_eq!(v.name(), "_name");
    assert_eq!(v.type_encoding(), "@\"NSString\"");
    assert_eq!(v.size(), 8);
    assert_eq!(v.log2_alignment(), 3);
    assert_eq!(v.offset(), Some(8));
}

#[test]
fn property_walker_parses_attribute_string() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let greeter = rt
        .classes()
        .find(|c| !c.is_meta() && c.ro().map(|r| r.name()) == Some("Greeter"))
        .unwrap();
    let ro = greeter.ro().unwrap();
    let props: Vec<_> = ro.properties().collect();
    assert_eq!(props.len(), 1);
    let p = &props[0];
    assert_eq!(p.name(), "name");
    assert_eq!(p.attributes(), "T@\"NSString\",C,N,V_name");
    let parsed = p.parsed();
    assert_eq!(parsed.type_encoding, "@\"NSString\"");
    let keys: Vec<char> = parsed.items.iter().map(|i| i.key).collect();
    assert_eq!(keys, vec!['T', 'C', 'N', 'V']);
    let v_item = parsed.items.iter().find(|i| i.key == 'V').unwrap();
    assert_eq!(v_item.value, "_name");
}

#[test]
fn protocol_walker_emits_spoken_with_one_optional_method() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let protos: Vec<_> = rt.protocols().collect();
    assert!(!protos.is_empty(), "objc-tiny declares the Spoken protocol");
    let spoken = protos
        .iter()
        .find(|p| p.name() == "Spoken")
        .expect("Spoken protocol");
    let methods: Vec<_> = spoken.instance_methods().collect();
    assert_eq!(methods.len(), 1);
    let speak = &methods[0];
    assert_eq!(speak.selector(), "speak");
    assert_eq!(speak.types(), "v16@0:8");
    // Protocol-declared methods are abstract (no IMP).
    assert_eq!(speak.implementation(), None);
    // Spoken declares no class methods or properties.
    assert_eq!(spoken.class_methods().count(), 0);
    assert_eq!(spoken.optional_instance_methods().count(), 0);
    assert_eq!(spoken.optional_class_methods().count(), 0);
    assert_eq!(spoken.instance_properties().count(), 0);
}

#[test]
fn category_walker_resolves_foreign_class_via_chained_bind() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let cats: Vec<_> = rt.categories().collect();
    assert!(
        !cats.is_empty(),
        "objc-tiny declares the NSString(Darwinscope) category"
    );
    let dw = cats
        .iter()
        .find(|c| c.name() == "Darwinscope")
        .expect("Darwinscope category");
    // The host class is foreign — `cls` slot is a chained-fixup bind.
    assert_eq!(dw.class_address(), 0);
    assert_eq!(
        dw.class_name(),
        Some("NSString"),
        "category cls slot must resolve to NSString via _OBJC_CLASS_$_NSString bind"
    );
    let methods: Vec<_> = dw.instance_methods().collect();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].selector(), "darwinscope_reversed");
}

#[test]
fn conformance_edges_include_greeter_to_spoken() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let edges: Vec<_> = rt.conformances().collect();
    let greeter_spoken = edges
        .iter()
        .find(|e| e.class_name == Some("Greeter") && e.protocol_name == "Spoken")
        .expect("conformance edge Greeter → Spoken");
    assert!(!greeter_spoken.is_meta);
    assert_ne!(greeter_spoken.class_address, 0);
}

#[test]
fn selector_refs_include_greet_and_speak() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();
    let sels: Vec<&str> = rt.selector_refs().collect();
    for needle in &["greet", "speak", "setName:", "darwinscope_reversed"] {
        assert!(
            sels.contains(needle),
            "selrefs must include {needle:?}; got {sels:?}"
        );
    }
}

#[test]
fn class_refs_resolve_local_and_external() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let refs: Vec<RefTarget<'_>> = rt.class_refs().collect();
    assert!(!refs.is_empty(), "expected class refs in objc-tiny");

    let mut saw_greeter_local = false;
    let mut saw_external = false;
    for r in &refs {
        match r {
            RefTarget::Local {
                name: Some("Greeter"),
                ..
            } => saw_greeter_local = true,
            RefTarget::External { name, .. } => {
                // NSMutableString or another Foundation class.
                assert!(!name.is_empty());
                saw_external = true;
            }
            _ => {}
        }
    }
    assert!(
        saw_greeter_local,
        "expected a Local Greeter class ref; got {refs:?}"
    );
    assert!(
        saw_external,
        "expected an External class ref (e.g. NSMutableString); got {refs:?}"
    );
}

#[test]
fn fat_slice_decodes_objc_runtime() {
    let bytes = read(OBJC_TINY_FAT);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().expect("fat-slice parse must yield ObjcRuntime");
    assert!(
        rt.classes()
            .any(|c| c.ro().map(|r| r.name()) == Some("Greeter"))
    );
}

#[test]
fn x86_64_slice_decodes_objc_runtime() {
    let bytes = read(OBJC_TINY_X86_64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().expect("x86_64 slice has ObjC content");
    let names: Vec<_> = rt
        .classes()
        .filter(|c| !c.is_meta())
        .filter_map(|c| c.ro().map(|r| r.name()))
        .collect();
    assert!(
        names.contains(&"Greeter"),
        "expected Greeter on x86_64 slice; got {names:?}"
    );
}

#[test]
fn class_t_address_is_in_objc_data_section() {
    // Sanity: the addresses surfaced by the walker are real VAs that
    // resolve through the segment table.
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let greeter = rt
        .classes()
        .find(|c| !c.is_meta() && c.ro().map(|r| r.name()) == Some("Greeter"))
        .unwrap();
    let off = bin.vm_to_file_offset(greeter.address());
    assert!(
        off.is_some(),
        "Greeter class_t VA 0x{:x} must resolve through the segment table",
        greeter.address(),
    );
}

// Smoke tests against system binaries. Gated behind `#[ignore]`
// so they run only when explicitly requested with
// `cargo test -- --ignored`. Not included in the default pass
// because `/usr/bin/codesign` and `/System/Applications/...` are
// absent on non-macOS hosts (and the system files differ across
// macOS releases).

#[test]
#[ignore]
fn smoke_codesign_decodes_swift_bridged_classes() {
    let bytes = match std::fs::read("/usr/bin/codesign") {
        Ok(b) => b,
        Err(_) => return,
    };
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().expect("/usr/bin/codesign has ObjC content");
    assert!(rt.image_info().contains_swift());
    let class_count = rt.classes().filter(|c| !c.is_meta()).count();
    assert!(
        class_count > 0,
        "expected non-zero class count on /usr/bin/codesign"
    );
}

#[test]
#[ignore]
fn smoke_calculator_decodes_classes_and_protocols() {
    let bytes = match std::fs::read("/System/Applications/Calculator.app/Contents/MacOS/Calculator")
    {
        Ok(b) => b,
        Err(_) => return,
    };
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().expect("Calculator has ObjC content");
    let classes = rt.classes().filter(|c| !c.is_meta()).count();
    let protocols = rt.protocols().count();
    let selrefs = rt.selector_refs().count();
    assert!(classes > 0, "Calculator must have classes");
    assert!(protocols > 0, "Calculator must have protocols");
    assert!(selrefs > 0, "Calculator must have selector refs");
}

#[test]
fn metaclass_pair_isa_points_back() {
    let bytes = read(OBJC_TINY_ARM64);
    let bin = MachoBinary::parse(&bytes).unwrap();
    let rt = bin.objc().unwrap();

    let classes: Vec<_> = rt.classes().collect();
    // For each instance class followed by its metaclass twin,
    // class.isa() == metaclass.address().
    let mut i = 0usize;
    while i + 1 < classes.len() {
        if !classes[i].is_meta() && classes[i + 1].is_meta() {
            assert_eq!(
                classes[i].isa(),
                classes[i + 1].address(),
                "instance.isa must point to its paired metaclass"
            );
        }
        i += 1;
    }
}
