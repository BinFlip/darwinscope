//! Exhaustive textual dump of a parsed [`MachoBinary`].
//!
//! `cargo run --example dump -- <path-to-macho>` reads a Mach-O image
//! and writes a deterministic, line-oriented summary of every field,
//! accessor, and iterator the public API exposes — header, segments
//! and sections (with body length, section-type bits, Shannon
//! entropy, BLAKE3), the full symbol table, dylib graph, load
//! commands, function-starts table, the merged import list, exports,
//! every chained-fixup rebase and bind, the code-signature SuperBlob
//! (every blob, all special and code hashes, alternate code
//! directories, entitlements XML, DER entitlements key list,
//! requirements descriptor, CMS envelope), the full Objective-C
//! runtime walk (every class, metaclass, ro_t, method, ivar,
//! property, protocol, category, conformance edge, and reference
//! section), and the full Swift 5 runtime walk (every type
//! descriptor with body and trailing objects, every protocol,
//! conformance, field descriptor with records, vtable entry,
//! override entry, default-override entry, resilient superclass,
//! metadata-initialisation block, prespecialisation, invertible
//! protocol set, singleton metadata pointer, dynamic replacement
//! scope, and capture descriptor).
//!
//! The output is intentionally stable: iteration order for every
//! section is the order the underlying iterators yield, all
//! addresses are printed as fixed-width hex, and floating-point
//! values use a fixed 6-digit precision. The format is designed for
//! `assert_eq!` snapshot tests against committed golden files.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::io::{self, Write};
use std::{env, process::ExitCode};

use darwinscope::{
    binary::MachoBinary,
    codesign::{HashType, Signature},
    fixup::ChainedFixups,
    objc::{
        ImageInfo, ObjcCategory, ObjcClass, ObjcProtocol, ObjcRuntime, Property, RefTarget,
    },
    ptrauth::PtrAuth,
    swift::{
        ContextDescriptorKind, FieldDescriptor, SwiftProtocol, SwiftRuntime, TypeDescriptor,
        TypeKindBody, TypeReference,
    },
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: dump <path-to-macho>");
            return ExitCode::from(2);
        }
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let bin = match MachoBinary::parse(&bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("parse {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = dump(&bin, &mut out) {
        eprintln!("dump {path}: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Write an exhaustive textual dump of `bin` to `w`.
///
/// The output begins with a `darwinscope-dump v1` banner so future
/// format revisions can bump the integer without breaking diff
/// tooling that pins to a specific layout.
pub fn dump<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    writeln!(w, "darwinscope-dump v1")?;
    dump_file(bin, w)?;
    dump_header(bin, w)?;
    dump_segments(bin, w)?;
    dump_dylibs(bin, w)?;
    dump_load_commands(bin, w)?;
    dump_symbols(bin, w)?;
    dump_function_starts(bin, w)?;
    dump_imports(bin, w)?;
    dump_exports(bin, w)?;
    dump_chained_fixups(bin, w)?;
    dump_signature(bin, w)?;
    dump_objc(bin, w)?;
    dump_swift(bin, w)?;
    Ok(())
}

fn section_header<W: Write>(w: &mut W, title: &str) -> io::Result<()> {
    writeln!(w)?;
    writeln!(w, "=== {title} ===")
}

fn dump_file<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "file")?;
    writeln!(w, "raw_size       {}", bin.raw().len())?;
    writeln!(w, "fat_arch_count {}", bin.fat_arch_count())?;
    Ok(())
}

fn dump_header<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    let h = bin.header();
    section_header(w, "header")?;
    writeln!(w, "magic          0x{:08x}", h.magic())?;
    writeln!(w, "cputype        0x{:08x}", h.cputype())?;
    writeln!(w, "cpusubtype     0x{:08x}", h.cpusubtype())?;
    writeln!(w, "filetype       0x{:08x}", h.filetype())?;
    writeln!(w, "ncmds          {}", h.ncmds())?;
    writeln!(w, "sizeofcmds     {}", h.sizeofcmds())?;
    writeln!(w, "flags          0x{:08x}", h.flags())?;
    writeln!(w, "reserved       0x{:08x}", h.reserved())?;
    writeln!(w, "is_64          {}", h.is_64())?;
    match h.uuid() {
        Some(u) => writeln!(
            w,
            "uuid           {:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u[0], u[1], u[2], u[3],
            u[4], u[5],
            u[6], u[7],
            u[8], u[9],
            u[10], u[11], u[12], u[13], u[14], u[15],
        )?,
        None => writeln!(w, "uuid           <none>")?,
    }
    match h.min_os() {
        Some(m) => writeln!(
            w,
            "min_os         platform={} {}.{}.{}",
            m.platform, m.version.major, m.version.minor, m.version.patch
        )?,
        None => writeln!(w, "min_os         <none>")?,
    }
    match h.sdk_version() {
        Some(v) => writeln!(w, "sdk_version    {}.{}.{}", v.major, v.minor, v.patch)?,
        None => writeln!(w, "sdk_version    <none>")?,
    }
    match h.source_version() {
        Some(v) => writeln!(
            w,
            "source_version {}.{}.{}.{}.{}",
            v.a, v.b, v.c, v.d, v.e
        )?,
        None => writeln!(w, "source_version <none>")?,
    }
    match h.dylinker() {
        Some(s) => writeln!(w, "dylinker       {s}")?,
        None => writeln!(w, "dylinker       <none>")?,
    }
    match h.function_starts_count() {
        Some(n) => writeln!(w, "function_starts_count {n}")?,
        None => writeln!(w, "function_starts_count <none>")?,
    }
    let tools = h.build_tools();
    writeln!(w, "build_tools    count={}", tools.len())?;
    for (i, t) in tools.iter().enumerate() {
        writeln!(
            w,
            "  build_tool[{i}] tool=0x{:x} version={}.{}.{}",
            t.tool, t.version.major, t.version.minor, t.version.patch
        )?;
    }
    Ok(())
}

fn dump_segments<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "segments")?;
    let segments: Vec<_> = bin.segments().collect();
    writeln!(w, "segment_count {}", segments.len())?;
    for (i, seg) in segments.iter().enumerate() {
        writeln!(
            w,
            "segment[{i}] name={} vmaddr=0x{:016x} vmsize=0x{:016x} fileoff={} filesize={} maxprot={} initprot={} nsects={} flags=0x{:08x} body_len={}",
            seg.name(),
            seg.vmaddr(),
            seg.vmsize(),
            seg.fileoff(),
            seg.filesize(),
            seg.maxprot(),
            seg.initprot(),
            seg.nsects(),
            seg.flags(),
            seg.body().len(),
        )?;
        let sections: Vec<_> = seg.sections().collect();
        for (j, sect) in sections.iter().enumerate() {
            writeln!(
                w,
                "  section[{j}] segname={} sectname={} addr=0x{:016x} size=0x{:016x} offset={} align={} reloff={} nreloc={} flags=0x{:08x} type={:?} attributes=0x{:08x} body_len={}",
                sect.segname(),
                sect.sectname(),
                sect.addr(),
                sect.size(),
                sect.offset(),
                sect.align(),
                sect.reloff(),
                sect.nreloc(),
                sect.flags(),
                sect.section_type(),
                sect.attributes().bits(),
                sect.body().len(),
            )?;
            let body = sect.body();
            if !body.is_empty() {
                writeln!(
                    w,
                    "    entropy={:.6} blake3={}",
                    sect.shannon_entropy(),
                    sect.blake3().to_hex(),
                )?;
            }
        }
    }
    Ok(())
}

fn dump_dylibs<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "dylibs")?;
    let dylibs: Vec<_> = bin.dylibs().collect();
    writeln!(w, "dylib_count {}", dylibs.len())?;
    for (i, d) in dylibs.iter().enumerate() {
        writeln!(
            w,
            "dylib[{i}] kind={:?} name={} cur={}.{}.{} compat={}.{}.{} timestamp={}",
            d.kind,
            d.name,
            d.current_version.major,
            d.current_version.minor,
            d.current_version.patch,
            d.compat_version.major,
            d.compat_version.minor,
            d.compat_version.patch,
            d.timestamp,
        )?;
    }
    Ok(())
}

fn dump_load_commands<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "load_commands")?;
    let lcs: Vec<_> = bin.load_commands().collect();
    writeln!(w, "load_command_count {}", lcs.len())?;
    for (i, lc) in lcs.iter().enumerate() {
        writeln!(
            w,
            "load_command[{i}] kind=0x{:08x} name={} offset={} size={}",
            lc.kind,
            lc.name(),
            lc.offset,
            lc.size,
        )?;
    }
    Ok(())
}

fn dump_symbols<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "symbols")?;
    let syms: Vec<_> = bin.symbols().collect();
    writeln!(w, "symbol_count {}", syms.len())?;
    for (i, s) in syms.iter().enumerate() {
        let mut attrs = String::new();
        if s.is_external() {
            attrs.push_str(" external");
        }
        if s.is_private_external() {
            attrs.push_str(" private_external");
        }
        if s.is_undefined() {
            attrs.push_str(" undefined");
        }
        if s.is_weak() {
            attrs.push_str(" weak");
        }
        if s.is_stab() {
            attrs.push_str(" stab");
        }
        writeln!(
            w,
            "symbol[{i}] name={} kind={:?} n_strx={} n_type=0x{:02x} n_sect={} n_desc=0x{:04x} n_value=0x{:016x}{}",
            s.name(),
            s.kind(),
            s.n_strx(),
            s.n_type(),
            s.n_sect(),
            s.n_desc(),
            s.n_value(),
            attrs,
        )?;
    }
    Ok(())
}

fn dump_function_starts<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "function_starts")?;
    let starts: Vec<u64> = bin.function_starts().collect();
    writeln!(w, "function_starts_emitted {}", starts.len())?;
    for (i, va) in starts.iter().enumerate() {
        match bin.vm_to_file_offset(*va) {
            Some(off) => writeln!(w, "function_start[{i}] vm=0x{va:016x} file=0x{off:x}")?,
            None => writeln!(w, "function_start[{i}] vm=0x{va:016x} file=<unmapped>")?,
        }
    }
    Ok(())
}

fn dump_imports<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "imports")?;
    let imports: Vec<_> = bin.imports().collect();
    writeln!(w, "import_count {}", imports.len())?;
    for (i, imp) in imports.iter().enumerate() {
        writeln!(
            w,
            "import[{i}] name={} dylib={} address=0x{:016x} offset=0x{:x} size={} addend={} bind_offset={} lazy={} weak={}",
            imp.name,
            imp.dylib,
            imp.address,
            imp.offset,
            imp.size,
            imp.addend,
            imp.bind_offset,
            imp.is_lazy,
            imp.is_weak,
        )?;
    }
    Ok(())
}

fn dump_exports<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "exports")?;
    let exports: Vec<_> = bin.exports().collect();
    writeln!(w, "export_count {}", exports.len())?;
    for (i, e) in exports.iter().enumerate() {
        writeln!(
            w,
            "export[{i}] name={} kind={:?} offset=0x{:x}",
            e.name, e.kind, e.offset
        )?;
    }
    Ok(())
}

fn fmt_ptr_auth(p: PtrAuth) -> String {
    format!(
        "key={:?} addr_div={} diversity=0x{:04x}",
        p.key, p.addr_div, p.diversity
    )
}

fn dump_chained_fixups<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "chained_fixups")?;
    let Some(cf) = bin.chained_fixups() else {
        writeln!(w, "chained_fixups <none>")?;
        return Ok(());
    };
    write_chained_fixups_inner(bin, &cf, w)
}

fn write_chained_fixups_inner<W: Write>(
    bin: &MachoBinary<'_>,
    cf: &ChainedFixups<'_>,
    w: &mut W,
) -> io::Result<()> {
    writeln!(w, "version             {}", cf.version())?;
    writeln!(w, "imports_count       {}", cf.imports_count())?;
    writeln!(w, "imports_format      {:?}", cf.imports_format())?;
    writeln!(w, "raw_imports_format  {}", cf.raw_imports_format())?;
    writeln!(w, "symbols_format      {}", cf.symbols_format())?;

    let segs: Vec<_> = cf.segments().collect();
    writeln!(w, "chained_segment_count {}", segs.len())?;
    for (i, s) in segs.iter().enumerate() {
        writeln!(
            w,
            "chained_segment[{i}] seg_index={} pointer_format={:?} page_size=0x{:x} page_count={} segment_offset=0x{:x}",
            s.seg_index, s.pointer_format, s.page_size, s.page_count, s.segment_offset,
        )?;
    }

    let imports: Vec<_> = cf.imports().collect();
    writeln!(w, "chained_import_count {}", imports.len())?;
    for (i, imp) in imports.iter().enumerate() {
        writeln!(
            w,
            "chained_import[{i}] name={} lib_ordinal={} weak={} addend={}",
            imp.name, imp.lib_ordinal, imp.weak_import, imp.addend,
        )?;
    }

    let rebases: Vec<_> = bin.chained_rebases().collect();
    writeln!(w, "chained_rebase_count {}", rebases.len())?;
    for (i, r) in rebases.iter().enumerate() {
        let pa = r
            .ptr_auth()
            .map(fmt_ptr_auth)
            .unwrap_or_else(|| "<none>".into());
        let high8 = r
            .high8()
            .map(|h| format!("0x{h:02x}"))
            .unwrap_or_else(|| "<none>".into());
        writeln!(
            w,
            "rebase[{i}] seg={} seg_off=0x{:x} vm=0x{:016x} target=0x{:016x} raw_slot=0x{:016x} format={:?} pac={pa} high8={high8}",
            r.segment_index(),
            r.segment_offset(),
            r.vm_address(),
            r.target_vmaddr(),
            r.raw_slot(),
            r.pointer_format(),
        )?;
    }

    let binds: Vec<_> = bin.chained_binds().collect();
    writeln!(w, "chained_bind_count {}", binds.len())?;
    for (i, b) in binds.iter().enumerate() {
        let pa = b
            .ptr_auth()
            .map(fmt_ptr_auth)
            .unwrap_or_else(|| "<none>".into());
        writeln!(
            w,
            "bind[{i}] seg={} seg_off=0x{:x} vm=0x{:016x} ordinal={} addend={} weak={} name={} dylib={} format={:?} pac={pa} raw_slot=0x{:016x}",
            b.segment_index(),
            b.segment_offset(),
            b.vm_address(),
            b.import_ordinal(),
            b.addend(),
            b.is_weak(),
            b.name(),
            b.dylib(),
            b.pointer_format(),
            b.raw_slot(),
        )?;
    }
    Ok(())
}

fn fmt_hash_type(h: HashType) -> &'static str {
    match h {
        HashType::Sha1 => "Sha1",
        HashType::Sha256 => "Sha256",
        HashType::Sha256Truncated => "Sha256Truncated",
        HashType::Sha384 => "Sha384",
        HashType::Sha512 => "Sha512",
        HashType::Other(_) => "Other",
    }
}

fn dump_signature<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "code_signature")?;
    let Some(sig) = bin.signature() else {
        writeln!(w, "code_signature <none>")?;
        return Ok(());
    };
    write_signature_inner(&sig, w)
}

fn write_signature_inner<W: Write>(sig: &Signature<'_>, w: &mut W) -> io::Result<()> {
    writeln!(w, "magic       0x{:08x}", sig.magic())?;
    writeln!(w, "length      {}", sig.length())?;
    writeln!(w, "blob_count  {}", sig.blob_count())?;
    let blobs: Vec<_> = sig.blobs().collect();
    for (i, b) in blobs.iter().enumerate() {
        writeln!(
            w,
            "blob[{i}] slot={:?} raw_slot=0x{:08x} offset={}",
            b.slot, b.raw_slot, b.offset
        )?;
    }

    if let Some(cd) = sig.primary_code_directory() {
        writeln!(w, "primary_code_directory:")?;
        write_code_directory(&cd, w, "  ")?;
    } else {
        writeln!(w, "primary_code_directory <none>")?;
    }

    let alts: Vec<_> = sig.alternate_code_directories().collect();
    writeln!(w, "alternate_code_directory_count {}", alts.len())?;
    for (i, cd) in alts.iter().enumerate() {
        writeln!(w, "alternate_code_directory[{i}]:")?;
        write_code_directory(cd, w, "  ")?;
    }

    match sig.entitlements() {
        Some(e) => {
            writeln!(w, "entitlements_xml_len {}", e.raw().len())?;
            for (i, line) in core::str::from_utf8(e.raw())
                .unwrap_or("<non-utf8>")
                .lines()
                .enumerate()
            {
                writeln!(w, "  ent_xml[{i}] {line}")?;
            }
        }
        None => writeln!(w, "entitlements_xml <none>")?,
    }

    match sig.der_entitlements() {
        Some(d) => {
            let keys = d.keys();
            writeln!(
                w,
                "der_entitlements bytes={} key_count={}",
                d.raw().len(),
                keys.len()
            )?;
            for (i, k) in keys.iter().enumerate() {
                writeln!(w, "  der_key[{i}] {k}")?;
            }
        }
        None => writeln!(w, "der_entitlements <none>")?,
    }

    match sig.requirements() {
        Some(r) => writeln!(
            w,
            "requirements count={} bytes={}",
            r.count(),
            r.len()
        )?,
        None => writeln!(w, "requirements <none>")?,
    }

    match sig.cms() {
        Some(c) => writeln!(w, "cms present={} bytes={}", c.is_present(), c.len())?,
        None => writeln!(w, "cms <none>")?,
    }
    Ok(())
}

fn write_code_directory<W: Write>(
    cd: &darwinscope::codesign::CodeDirectory<'_>,
    w: &mut W,
    indent: &str,
) -> io::Result<()> {
    writeln!(w, "{indent}version=0x{:08x}", cd.version())?;
    writeln!(w, "{indent}raw_flags=0x{:08x}", cd.raw_flags())?;
    writeln!(w, "{indent}flags={:?}", cd.flags())?;
    writeln!(w, "{indent}hash_type={}", fmt_hash_type(cd.hash_type()))?;
    writeln!(w, "{indent}hash_size={}", cd.hash_size())?;
    writeln!(w, "{indent}page_size={}", cd.page_size())?;
    writeln!(w, "{indent}n_special_slots={}", cd.n_special_slots())?;
    writeln!(w, "{indent}n_code_slots={}", cd.n_code_slots())?;
    writeln!(w, "{indent}code_limit={}", cd.code_limit())?;
    writeln!(w, "{indent}platform={}", cd.platform())?;
    writeln!(
        w,
        "{indent}identifier={}",
        cd.identifier().unwrap_or("<none>")
    )?;
    writeln!(w, "{indent}team_id={}", cd.team_id().unwrap_or("<none>"))?;
    writeln!(w, "{indent}blob_bytes_len={}", cd.blob_bytes().len())?;
    writeln!(
        w,
        "{indent}code_limit_64={}",
        cd.code_limit_64()
            .map(|v| format!("0x{v:x}"))
            .unwrap_or_else(|| "<none>".into())
    )?;
    writeln!(
        w,
        "{indent}exec_seg_base={}",
        cd.exec_seg_base()
            .map(|v| format!("0x{v:x}"))
            .unwrap_or_else(|| "<none>".into())
    )?;
    writeln!(
        w,
        "{indent}exec_seg_limit={}",
        cd.exec_seg_limit()
            .map(|v| format!("0x{v:x}"))
            .unwrap_or_else(|| "<none>".into())
    )?;
    writeln!(
        w,
        "{indent}exec_seg_flags={}",
        cd.exec_seg_flags()
            .map(|v| format!("0x{v:x}"))
            .unwrap_or_else(|| "<none>".into())
    )?;
    let cdh = cd.cd_hash();
    writeln!(w, "{indent}cd_hash={}", hex(&cdh))?;
    writeln!(
        w,
        "{indent}cd_hash_truncated={}",
        hex(&cd.cd_hash_truncated())
    )?;
    let specials: Vec<_> = cd.special_hashes().collect();
    writeln!(w, "{indent}special_hash_count={}", specials.len())?;
    for (i, (slot, h)) in specials.iter().enumerate() {
        writeln!(w, "{indent}special_hash[{i}] slot={slot} {}", hex(h))?;
    }
    let codes: Vec<_> = cd.code_hashes().collect();
    writeln!(w, "{indent}code_hash_count={}", codes.len())?;
    for (i, h) in codes.iter().enumerate() {
        writeln!(w, "{indent}code_hash[{i}]={}", hex(h))?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn dump_objc<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "objc_runtime")?;
    let Some(rt) = bin.objc() else {
        writeln!(w, "objc_runtime <none>")?;
        return Ok(());
    };
    write_objc_runtime(&rt, w)
}

fn write_objc_image_info<W: Write>(info: ImageInfo, w: &mut W) -> io::Result<()> {
    writeln!(w, "image_info.version    {}", info.version)?;
    writeln!(w, "image_info.flags      0x{:08x}", info.flags)?;
    writeln!(
        w,
        "image_info.dyld_categories_optimized {}",
        info.dyld_categories_optimized()
    )?;
    writeln!(w, "image_info.supports_gc {}", info.supports_gc())?;
    writeln!(w, "image_info.requires_gc {}", info.requires_gc())?;
    writeln!(
        w,
        "image_info.optimized_by_dyld {}",
        info.optimized_by_dyld()
    )?;
    writeln!(w, "image_info.signed_class_ro {}", info.signed_class_ro())?;
    writeln!(w, "image_info.is_simulated {}", info.is_simulated())?;
    writeln!(
        w,
        "image_info.has_category_class_properties {}",
        info.has_category_class_properties()
    )?;
    writeln!(
        w,
        "image_info.optimized_by_dyld_closure {}",
        info.optimized_by_dyld_closure()
    )?;
    writeln!(
        w,
        "image_info.swift_unstable_version {}",
        info.swift_unstable_version()
    )?;
    writeln!(
        w,
        "image_info.swift_stable_version {}",
        info.swift_stable_version()
    )?;
    writeln!(w, "image_info.contains_swift {}", info.contains_swift())?;
    Ok(())
}

fn write_objc_runtime<W: Write>(rt: &ObjcRuntime<'_>, w: &mut W) -> io::Result<()> {
    write_objc_image_info(rt.image_info(), w)?;

    let classes: Vec<_> = rt.classes().collect();
    writeln!(w, "class_count {}", classes.len())?;
    for (i, c) in classes.iter().enumerate() {
        write_objc_class(c, i, w)?;
    }

    let protocols: Vec<_> = rt.protocols().collect();
    writeln!(w, "protocol_count {}", protocols.len())?;
    for (i, p) in protocols.iter().enumerate() {
        write_objc_protocol(p, i, w)?;
    }

    let categories: Vec<_> = rt.categories().collect();
    writeln!(w, "category_count {}", categories.len())?;
    for (i, c) in categories.iter().enumerate() {
        write_objc_category(c, i, w)?;
    }

    let edges: Vec<_> = rt.conformances().collect();
    writeln!(w, "conformance_edge_count {}", edges.len())?;
    for (i, e) in edges.iter().enumerate() {
        writeln!(
            w,
            "conformance_edge[{i}] class=0x{:016x} class_name={} protocol={} is_meta={}",
            e.class_address,
            e.class_name.unwrap_or("?"),
            e.protocol_name,
            e.is_meta,
        )?;
    }

    let selrefs: Vec<&str> = rt.selector_refs().collect();
    writeln!(w, "selector_ref_count {}", selrefs.len())?;
    for (i, s) in selrefs.iter().enumerate() {
        writeln!(w, "selector_ref[{i}] {s}")?;
    }

    let class_refs: Vec<_> = rt.class_refs().collect();
    writeln!(w, "class_ref_count {}", class_refs.len())?;
    for (i, r) in class_refs.iter().enumerate() {
        writeln!(w, "class_ref[{i}] {}", fmt_ref_target(*r))?;
    }
    let super_refs: Vec<_> = rt.super_refs().collect();
    writeln!(w, "super_ref_count {}", super_refs.len())?;
    for (i, r) in super_refs.iter().enumerate() {
        writeln!(w, "super_ref[{i}] {}", fmt_ref_target(*r))?;
    }
    let proto_refs: Vec<_> = rt.protocol_refs().collect();
    writeln!(w, "protocol_ref_count {}", proto_refs.len())?;
    for (i, r) in proto_refs.iter().enumerate() {
        writeln!(w, "protocol_ref[{i}] {}", fmt_ref_target(*r))?;
    }
    Ok(())
}

fn fmt_ref_target(r: RefTarget<'_>) -> String {
    match r {
        RefTarget::Local { address, name } => format!(
            "Local address=0x{address:016x} name={}",
            name.unwrap_or("<none>")
        ),
        RefTarget::External { name, dylib } => format!("External name={name} dylib={dylib}"),
        RefTarget::Unresolved {
            slot_address,
            target,
        } => format!("Unresolved slot=0x{slot_address:016x} target=0x{target:016x}"),
    }
}

fn write_objc_class<W: Write>(c: &ObjcClass<'_, '_>, i: usize, w: &mut W) -> io::Result<()> {
    writeln!(
        w,
        "class[{i}] address=0x{:016x} is_meta={} isa=0x{:016x} superclass=0x{:016x} bits=0x{:016x} fast_flags=0x{:x} is_swift={} has_default_rr={} superclass_name={}",
        c.address(),
        c.is_meta(),
        c.isa(),
        c.superclass_address(),
        c.bits(),
        c.fast_flags(),
        c.is_swift(),
        c.has_default_rr(),
        c.superclass_name().unwrap_or("<none>"),
    )?;
    let Some(ro) = c.ro() else {
        writeln!(w, "  ro <none>")?;
        return Ok(());
    };
    writeln!(
        w,
        "  ro address=0x{:016x} name={} flags=0x{:08x} instance_start={} instance_size={} is_meta={} is_root={} has_cxx_structors={} is_arc={} has_swift_initializer={} is_exception={} ivar_layout=0x{:016x} weak_ivar_layout=0x{:016x}",
        ro.address(),
        ro.name(),
        ro.flags().bits(),
        ro.instance_start(),
        ro.instance_size(),
        ro.is_meta(),
        ro.is_root(),
        ro.has_cxx_structors(),
        ro.is_arc(),
        ro.has_swift_initializer(),
        ro.is_exception(),
        ro.ivar_layout_address(),
        ro.weak_ivar_layout_address(),
    )?;
    let methods: Vec<_> = ro.methods().collect();
    writeln!(w, "  method_count {}", methods.len())?;
    for (j, m) in methods.iter().enumerate() {
        writeln!(
            w,
            "    method[{j}] selector={} types={} kind={:?} small={} imp={}",
            m.selector(),
            m.types(),
            m.kind(),
            m.is_small(),
            m.implementation()
                .map(|v| format!("0x{v:016x}"))
                .unwrap_or_else(|| "<none>".into()),
        )?;
    }
    let ivars: Vec<_> = ro.ivars().collect();
    writeln!(w, "  ivar_count {}", ivars.len())?;
    for (j, v) in ivars.iter().enumerate() {
        writeln!(
            w,
            "    ivar[{j}] name={} type={} size={} log2_align={} offset={}",
            v.name(),
            v.type_encoding(),
            v.size(),
            v.log2_alignment(),
            v.offset()
                .map(|o| format!("{o}"))
                .unwrap_or_else(|| "<none>".into()),
        )?;
    }
    let props: Vec<_> = ro.properties().collect();
    writeln!(w, "  property_count {}", props.len())?;
    for (j, p) in props.iter().enumerate() {
        write_property(p, j, w, "    ")?;
    }
    let proto_names: Vec<&str> = ro.protocols().collect();
    writeln!(w, "  conforms_to_count {}", proto_names.len())?;
    for (j, n) in proto_names.iter().enumerate() {
        writeln!(w, "    conforms_to[{j}] {n}")?;
    }
    Ok(())
}

fn write_property<W: Write>(
    p: &Property<'_>,
    j: usize,
    w: &mut W,
    indent: &str,
) -> io::Result<()> {
    let parsed = p.parsed();
    writeln!(
        w,
        "{indent}property[{j}] name={} attributes={} type_encoding={} item_count={}",
        p.name(),
        p.attributes(),
        parsed.type_encoding,
        parsed.items.len()
    )?;
    for (k, it) in parsed.items.iter().enumerate() {
        writeln!(
            w,
            "{indent}  attr[{k}] key={} value={}",
            it.key, it.value
        )?;
    }
    Ok(())
}

fn write_objc_protocol<W: Write>(
    p: &ObjcProtocol<'_, '_>,
    i: usize,
    w: &mut W,
) -> io::Result<()> {
    writeln!(
        w,
        "protocol[{i}] address=0x{:016x} name={} size={} flags=0x{:08x}",
        p.address(),
        p.name(),
        p.size(),
        p.flags(),
    )?;
    let im: Vec<_> = p.instance_methods().collect();
    writeln!(w, "  instance_method_count {}", im.len())?;
    for (j, m) in im.iter().enumerate() {
        writeln!(
            w,
            "    instance_method[{j}] selector={} types={} kind={:?}",
            m.selector(),
            m.types(),
            m.kind()
        )?;
    }
    let cm: Vec<_> = p.class_methods().collect();
    writeln!(w, "  class_method_count {}", cm.len())?;
    for (j, m) in cm.iter().enumerate() {
        writeln!(
            w,
            "    class_method[{j}] selector={} types={} kind={:?}",
            m.selector(),
            m.types(),
            m.kind()
        )?;
    }
    let oim: Vec<_> = p.optional_instance_methods().collect();
    writeln!(w, "  optional_instance_method_count {}", oim.len())?;
    for (j, m) in oim.iter().enumerate() {
        writeln!(
            w,
            "    optional_instance_method[{j}] selector={} types={} kind={:?}",
            m.selector(),
            m.types(),
            m.kind()
        )?;
    }
    let ocm: Vec<_> = p.optional_class_methods().collect();
    writeln!(w, "  optional_class_method_count {}", ocm.len())?;
    for (j, m) in ocm.iter().enumerate() {
        writeln!(
            w,
            "    optional_class_method[{j}] selector={} types={} kind={:?}",
            m.selector(),
            m.types(),
            m.kind()
        )?;
    }
    let iprops: Vec<_> = p.instance_properties().collect();
    writeln!(w, "  instance_property_count {}", iprops.len())?;
    for (j, pr) in iprops.iter().enumerate() {
        write_property(pr, j, w, "    ")?;
    }
    let cprops: Vec<_> = p.class_properties().collect();
    writeln!(w, "  class_property_count {}", cprops.len())?;
    for (j, pr) in cprops.iter().enumerate() {
        write_property(pr, j, w, "    ")?;
    }
    let inh: Vec<&str> = p.protocols().collect();
    writeln!(w, "  inherits_count {}", inh.len())?;
    for (j, n) in inh.iter().enumerate() {
        writeln!(w, "    inherits[{j}] {n}")?;
    }
    Ok(())
}

fn write_objc_category<W: Write>(
    c: &ObjcCategory<'_, '_>,
    i: usize,
    w: &mut W,
) -> io::Result<()> {
    writeln!(
        w,
        "category[{i}] address=0x{:016x} name={} class_address=0x{:016x} class_name={}",
        c.address(),
        c.name(),
        c.class_address(),
        c.class_name().unwrap_or("<none>"),
    )?;
    let im: Vec<_> = c.instance_methods().collect();
    writeln!(w, "  instance_method_count {}", im.len())?;
    for (j, m) in im.iter().enumerate() {
        writeln!(
            w,
            "    instance_method[{j}] selector={} types={} kind={:?}",
            m.selector(),
            m.types(),
            m.kind()
        )?;
    }
    let cm: Vec<_> = c.class_methods().collect();
    writeln!(w, "  class_method_count {}", cm.len())?;
    for (j, m) in cm.iter().enumerate() {
        writeln!(
            w,
            "    class_method[{j}] selector={} types={} kind={:?}",
            m.selector(),
            m.types(),
            m.kind()
        )?;
    }
    let iprops: Vec<_> = c.instance_properties().collect();
    writeln!(w, "  instance_property_count {}", iprops.len())?;
    for (j, p) in iprops.iter().enumerate() {
        write_property(p, j, w, "    ")?;
    }
    let cprops: Vec<_> = c.class_properties().collect();
    writeln!(w, "  class_property_count {}", cprops.len())?;
    for (j, p) in cprops.iter().enumerate() {
        write_property(p, j, w, "    ")?;
    }
    let protos: Vec<&str> = c.protocols().collect();
    writeln!(w, "  protocols_count {}", protos.len())?;
    for (j, n) in protos.iter().enumerate() {
        writeln!(w, "    protocol[{j}] {n}")?;
    }
    Ok(())
}

fn dump_swift<W: Write>(bin: &MachoBinary<'_>, w: &mut W) -> io::Result<()> {
    section_header(w, "swift_runtime")?;
    let Some(rt) = bin.swift() else {
        writeln!(w, "swift_runtime <none>")?;
        return Ok(());
    };
    write_swift_runtime(&rt, w)
}

fn write_swift_runtime<W: Write>(rt: &SwiftRuntime<'_>, w: &mut W) -> io::Result<()> {
    writeln!(w, "has_entry_point                    {}", rt.has_entry_point())?;
    writeln!(
        w,
        "has_builtin_descriptors            {}",
        rt.has_builtin_descriptors()
    )?;
    writeln!(
        w,
        "has_multi_payload_enum_descriptors {}",
        rt.has_multi_payload_enum_descriptors()
    )?;
    writeln!(
        w,
        "has_accessible_functions           {}",
        rt.has_accessible_functions()
    )?;
    writeln!(
        w,
        "has_associated_type_descriptors    {}",
        rt.has_associated_type_descriptors()
    )?;
    writeln!(
        w,
        "has_replacement_chain              {}",
        rt.has_replacement_chain()
    )?;

    let types: Vec<_> = rt.types().collect();
    writeln!(w, "type_count {}", types.len())?;
    for (i, t) in types.iter().enumerate() {
        write_swift_type(t, i, w)?;
    }

    let protos: Vec<_> = rt.protocols().collect();
    writeln!(w, "swift_protocol_count {}", protos.len())?;
    for (i, p) in protos.iter().enumerate() {
        write_swift_protocol(p, i, w)?;
    }

    let confs: Vec<_> = rt.conformances().collect();
    writeln!(w, "swift_conformance_count {}", confs.len())?;
    for (i, c) in confs.iter().enumerate() {
        let tref = match c.type_ref() {
            TypeReference::DirectTypeDescriptor(va) => {
                format!("DirectTypeDescriptor=0x{va:016x}")
            }
            TypeReference::IndirectTypeDescriptor(va) => {
                format!("IndirectTypeDescriptor=0x{va:016x}")
            }
            TypeReference::DirectObjCClassName(name) => {
                format!("DirectObjCClassName={name}")
            }
            TypeReference::IndirectObjCClass(va) => {
                format!("IndirectObjCClass=0x{va:016x}")
            }
            TypeReference::Other { kind, target } => {
                format!("Other kind={kind} target=0x{target:016x}")
            }
        };
        writeln!(
            w,
            "swift_conformance[{i}] address=0x{:016x} protocol_descriptor=0x{:016x} witness_table=0x{:016x} flags=0x{:08x} type_ref={tref}",
            c.address(),
            c.protocol_descriptor_address(),
            c.witness_table_address(),
            c.flags().0,
        )?;
    }

    let fields: Vec<_> = rt.field_descriptors().collect();
    writeln!(w, "field_descriptor_count {}", fields.len())?;
    for (i, fd) in fields.iter().enumerate() {
        write_swift_field(fd, i, w)?;
    }

    let replacs: Vec<_> = rt.dynamic_replacements().collect();
    writeln!(w, "dynamic_replacement_count {}", replacs.len())?;
    for (i, r) in replacs.iter().enumerate() {
        writeln!(
            w,
            "dynamic_replacement[{i}] address=0x{:016x} scope=0x{:016x} flags=0x{:08x}",
            r.address, r.scope_va, r.flags
        )?;
    }

    let captures: Vec<_> = rt.captures().collect();
    writeln!(w, "capture_count {}", captures.len())?;
    for (i, c) in captures.iter().enumerate() {
        writeln!(
            w,
            "capture[{i}] address=0x{:016x} num_capture_types={} num_metadata_sources={} num_bindings={} capture_types_at=0x{:016x} metadata_sources_at=0x{:016x} bindings_at=0x{:016x}",
            c.address,
            c.num_capture_types,
            c.num_metadata_sources,
            c.num_bindings,
            c.capture_types_address(),
            c.metadata_sources_address(),
            c.bindings_address(),
        )?;
    }
    Ok(())
}

fn fmt_kind(k: ContextDescriptorKind) -> String {
    match k {
        ContextDescriptorKind::Module => "Module".into(),
        ContextDescriptorKind::Extension => "Extension".into(),
        ContextDescriptorKind::Anonymous => "Anonymous".into(),
        ContextDescriptorKind::Protocol => "Protocol".into(),
        ContextDescriptorKind::OpaqueType => "OpaqueType".into(),
        ContextDescriptorKind::Class => "Class".into(),
        ContextDescriptorKind::Struct => "Struct".into(),
        ContextDescriptorKind::Enum => "Enum".into(),
        ContextDescriptorKind::Other(v) => format!("Other({v})"),
    }
}

fn write_swift_type<W: Write>(t: &TypeDescriptor<'_, '_>, i: usize, w: &mut W) -> io::Result<()> {
    let flags = t.flags();
    writeln!(
        w,
        "type[{i}] address=0x{:016x} kind={} name={} qualified={} parent=0x{:016x} flags=0x{:08x} kind_specific=0x{:04x} is_generic={} is_unique={} has_invertible_protocols={}",
        t.address(),
        fmt_kind(t.kind()),
        t.name(),
        t.qualified_name(),
        t.parent_address(),
        flags.0,
        flags.kind_specific(),
        flags.is_generic(),
        flags.is_unique(),
        flags.has_invertible_protocols(),
    )?;
    let tflags = t.type_flags();
    writeln!(
        w,
        "  type_flags raw=0x{:04x} metadata_init={:?} has_import_info={} class_has_vtable={} class_has_override_table={} class_has_default_override_table={} class_has_resilient_superclass={} class_is_actor={} class_is_default_actor={} class_immediate_members_negative={} has_singleton_metadata_pointer={} has_canonical_metadata_prespecializations={} has_layout_string={}",
        tflags.0,
        tflags.metadata_initialization(),
        tflags.has_import_info(),
        tflags.class_has_vtable(),
        tflags.class_has_override_table(),
        tflags.class_has_default_override_table(),
        tflags.class_has_resilient_superclass(),
        tflags.class_is_actor(),
        tflags.class_is_default_actor(),
        tflags.class_immediate_members_negative(),
        tflags.has_singleton_metadata_pointer(),
        tflags.has_canonical_metadata_prespecializations(),
        tflags.has_layout_string(),
    )?;
    match t.body() {
        TypeKindBody::Class(cb) => {
            writeln!(
                w,
                "  body=Class superclass_mangled={} num_immediate_members={} num_fields={} field_offset_vector_offset={} metadata_negative_size_words={} metadata_positive_size_words={} extra_class_flags={} resilient_metadata_bounds=0x{:016x}",
                cb.superclass_mangled_name.unwrap_or("<none>"),
                cb.num_immediate_members,
                cb.num_fields,
                cb.field_offset_vector_offset,
                cb.metadata_negative_size_words
                    .map(|v| format!("{v}"))
                    .unwrap_or_else(|| "<none>".into()),
                cb.metadata_positive_size_words
                    .map(|v| format!("{v}"))
                    .unwrap_or_else(|| "<none>".into()),
                cb.extra_class_flags
                    .map(|v| format!("0x{v:x}"))
                    .unwrap_or_else(|| "<none>".into()),
                cb.resilient_metadata_bounds_va.unwrap_or(0),
            )?;
            if let Some(va) = cb.generic_header_va {
                writeln!(w, "  generic_header_va=0x{va:016x}")?;
            }
        }
        TypeKindBody::Struct(sb) => {
            writeln!(
                w,
                "  body=Struct num_fields={} field_offset_vector_offset={} generic_header={}",
                sb.num_fields,
                sb.field_offset_vector_offset,
                sb.generic_header_va
                    .map(|v| format!("0x{v:016x}"))
                    .unwrap_or_else(|| "<none>".into()),
            )?;
        }
        TypeKindBody::Enum(eb) => {
            writeln!(
                w,
                "  body=Enum num_payload_cases={} num_empty_cases={} payload_size_offset={} generic_header={}",
                eb.num_payload_cases,
                eb.num_empty_cases,
                eb.payload_size_offset,
                eb.generic_header_va
                    .map(|v| format!("0x{v:016x}"))
                    .unwrap_or_else(|| "<none>".into()),
            )?;
        }
        TypeKindBody::NonType => {
            writeln!(w, "  body=NonType")?;
        }
    }
    if let Some(vt) = t.vtable() {
        let entries: Vec<_> = vt.collect();
        writeln!(w, "  vtable_count {}", entries.len())?;
        for (j, e) in entries.iter().enumerate() {
            writeln!(
                w,
                "    vtable[{j}] address=0x{:016x} flags=0x{:08x} kind={:?} is_instance={} is_dynamic={} is_async={} impl=0x{:016x}",
                e.address,
                e.flags.0,
                e.flags.kind(),
                e.flags.is_instance(),
                e.flags.is_dynamic(),
                e.flags.is_async(),
                e.impl_va,
            )?;
        }
    }
    if let Some(ot) = t.override_table() {
        let entries: Vec<_> = ot.collect();
        writeln!(w, "  override_table_count {}", entries.len())?;
        for (j, e) in entries.iter().enumerate() {
            writeln!(
                w,
                "    override[{j}] address=0x{:016x} class=0x{:016x} method=0x{:016x} impl=0x{:016x}",
                e.address, e.class_va, e.method_va, e.impl_va
            )?;
        }
    }
    if let Some(dot) = t.default_override_table() {
        let entries: Vec<_> = dot.collect();
        writeln!(w, "  default_override_table_count {}", entries.len())?;
        for (j, e) in entries.iter().enumerate() {
            writeln!(
                w,
                "    default_override[{j}] address=0x{:016x} method=0x{:016x} impl=0x{:016x}",
                e.address, e.method_va, e.impl_va
            )?;
        }
    }
    if let Some(rs) = t.resilient_superclass() {
        writeln!(
            w,
            "  resilient_superclass address=0x{:016x} superclass=0x{:016x}",
            rs.address, rs.superclass_va
        )?;
    }
    if let Some(fmi) = t.foreign_metadata_init() {
        writeln!(
            w,
            "  foreign_metadata_init address=0x{:016x} completion=0x{:016x}",
            fmi.address, fmi.completion_function_va
        )?;
    }
    if let Some(smi) = t.singleton_metadata_init() {
        writeln!(
            w,
            "  singleton_metadata_init address=0x{:016x} cache=0x{:016x} pattern=0x{:016x} completion=0x{:016x}",
            smi.address, smi.initialization_cache_va, smi.incomplete_metadata_va, smi.completion_function_va
        )?;
    }
    if let Some(ps) = t.prespecializations() {
        let entries: Vec<u64> = ps.collect();
        writeln!(w, "  prespecialization_count {}", entries.len())?;
        for (j, va) in entries.iter().enumerate() {
            writeln!(w, "    prespecialization[{j}] 0x{va:016x}")?;
        }
    }
    if let Some(ips) = t.invertible_protocol_set() {
        writeln!(
            w,
            "  invertible_protocol_set address=0x{:016x} bits=0x{:04x}",
            ips.address, ips.bits
        )?;
    }
    if let Some(smp) = t.singleton_metadata_pointer() {
        writeln!(
            w,
            "  singleton_metadata_pointer address=0x{:016x} metadata=0x{:016x}",
            smp.address, smp.metadata_va
        )?;
    }
    if let Some(stub) = t.objc_resilient_class_stub_info() {
        writeln!(
            w,
            "  objc_resilient_class_stub address=0x{:016x} stub=0x{:016x}",
            stub.address, stub.stub_va
        )?;
    }
    let parents: Vec<_> = t.parent().collect();
    writeln!(w, "  parent_chain_count {}", parents.len())?;
    for (j, p) in parents.iter().enumerate() {
        writeln!(
            w,
            "    parent[{j}] address=0x{:016x} kind={} name={}",
            p.address,
            fmt_kind(p.kind()),
            p.name.unwrap_or("<none>"),
        )?;
    }
    Ok(())
}

fn write_swift_protocol<W: Write>(
    p: &SwiftProtocol<'_, '_>,
    i: usize,
    w: &mut W,
) -> io::Result<()> {
    writeln!(
        w,
        "swift_protocol[{i}] address=0x{:016x} name={} qualified={} parent=0x{:016x} num_requirements={} num_requirements_in_signature={} associated_type_names={} flags=0x{:08x}",
        p.address(),
        p.name(),
        p.qualified_name(),
        p.parent_address(),
        p.num_requirements(),
        p.num_requirements_in_signature(),
        p.associated_type_names().unwrap_or("<none>"),
        p.flags().0,
    )?;
    let parents: Vec<_> = p.parent().collect();
    writeln!(w, "  parent_chain_count {}", parents.len())?;
    for (j, pc) in parents.iter().enumerate() {
        writeln!(
            w,
            "    parent[{j}] address=0x{:016x} kind={} name={}",
            pc.address,
            fmt_kind(pc.kind()),
            pc.name.unwrap_or("<none>"),
        )?;
    }
    Ok(())
}

fn write_swift_field<W: Write>(
    fd: &FieldDescriptor<'_, '_>,
    i: usize,
    w: &mut W,
) -> io::Result<()> {
    writeln!(
        w,
        "field_descriptor[{i}] address=0x{:016x} mangled_type={} superclass={} kind={:?} field_record_size={} num_fields={}",
        fd.address(),
        fd.mangled_type_name().unwrap_or("<none>"),
        fd.superclass_mangled_name().unwrap_or("<none>"),
        fd.kind(),
        fd.field_record_size(),
        fd.num_fields(),
    )?;
    let recs: Vec<_> = fd.records().collect();
    for (j, r) in recs.iter().enumerate() {
        writeln!(
            w,
            "  record[{j}] flags=0x{:08x} is_indirect_case={} is_var={} is_artificial={} mangled_type={} field_name={}",
            r.flags().0,
            r.flags().is_indirect_case(),
            r.flags().is_var(),
            r.flags().is_artificial(),
            r.mangled_type_name().unwrap_or("<none>"),
            r.field_name().unwrap_or("<none>"),
        )?;
    }
    Ok(())
}
