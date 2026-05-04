//! # darwinscope: Mach-O / Objective-C / Swift binary parser
//!
//! A Rust library for statically analyzing Mach-O binaries — the
//! container format used by macOS, iOS, watchOS, tvOS, visionOS, and
//! Mac Catalyst — and the rich Apple-runtime metadata they embed.
//!
//! Given an arbitrary byte slice, `darwinscope` decodes:
//!
//! - The Mach-O container itself: header, load commands, segments,
//!   sections, nlist symbol table, bind / export tries, fat-binary
//!   slices, dylib graph, and `LC_FUNCTION_STARTS`.
//! - The embedded **code-signature SuperBlob**: CodeDirectory
//!   identifier and Team ID, signing flags, CodeDirectory hash type,
//!   embedded CMS signature size, entitlements XML plist (key /
//!   value pairs).
//! - The **Objective-C runtime tables**: classes, metaclasses,
//!   methods (legacy and small-method-list), instance variables,
//!   properties, protocols, categories, and the cross-section
//!   reference tables (`__objc_selrefs`, `__objc_classrefs`,
//!   `__objc_superrefs`, `__objc_protorefs`).
//! - The **Swift 5 type metadata**: type descriptors
//!   (`__swift5_types`), protocol descriptors (`__swift5_protos`),
//!   field descriptors (`__swift5_fieldmd`), protocol conformances
//!   (`__swift5_proto`), and class vtable entries.
//! - **CoreFoundation constant strings** (`__cfstring`) — both
//!   ASCII / UTF-8 (`__TEXT,__cstring`) and UTF-16 LE
//!   (`__TEXT,__ustring`) bodies.
//! - **Apple Blocks-runtime metadata** — bind sites for
//!   `_NSConcrete{Global,Stack}Block` plus the full
//!   `Block_descriptor_{1,2,3}` decode for global block literals
//!   (invoke pointer, signature, layout string).
//!
//! The crate handles arm64e pointer authentication (PAC) by
//! canonicalising signed pointers before every dereference, and
//! supports both the legacy bind-opcode pointer format and
//! `LC_DYLD_CHAINED_FIXUPS` chains.
//!
//! ## Motivation
//!
//! Apple binaries are unusually rich static-analysis targets.
//! Stripped Mach-O dylibs and executables still carry:
//!
//! - **Obj-C class hierarchy + selectors** — required at runtime for
//!   message dispatch.
//! - **Swift type names + field layouts** — required for runtime
//!   reflection, generic specialization, and protocol witness lookup.
//! - **Code-signing identity** — Team ID and bundle identifier,
//!   embedded for system-wide code-signing enforcement.
//! - **Entitlements XML** — explicit list of every privileged API
//!   the binary requested.
//! - **Function entry points** — `LC_FUNCTION_STARTS` ULEB128 table,
//!   used by `dyld` for the unwinder.
//!
//! This metadata survives stripping because the OS depends on it for
//! linking, dispatch, and code-signing enforcement. See
//! [`RESEARCH.md`](https://github.com/BinFlip/darwinscope/blob/main/RESEARCH.md)
//! for the underlying format research.
//!
//! ## Architecture
//!
//! The crate is organised in layers:
//!
//! - **Container** ([`binary`]): wraps `goblin::mach::MachO` and
//!   exposes typed views over the structural layer (`Header`,
//!   `Segment`, `Section`, `Symbol`, `Import`, `Export`, `Dylib`,
//!   `LoadCommand`).
//! - **Code signing** ([`codesign`]): SuperBlob walker, CodeDirectory
//!   parser, entitlements plist decoder.
//! - **Objective-C** ([`objc`]): aggregate [`ObjcRuntime`] walker
//!   with `class_t` / `class_ro_t` / `method_list_t` (legacy +
//!   small) / `ivar_list_t` / `property_list_t` / `protocol_t` /
//!   `category_t` decoders, cross-section reference readers, and
//!   class ↔ protocol conformance edges.
//! - **Swift** ([`swift`]): type / protocol / field / conformance /
//!   vtable descriptor walkers.
//! - **Support** ([`ptrauth`], [`util`]): pointer-authentication
//!   stripping, ULEB128 decoding, virtual-to-file-offset translation.
//!
//! ## Quick start
//!
//! ```no_run
//! use darwinscope::MachoBinary;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes = std::fs::read("/usr/bin/codesign")?;
//! let binary = MachoBinary::parse(&bytes)?;
//!
//! let header = binary.header();
//! println!("cputype=0x{:x} ncmds={}", header.cputype(), header.ncmds());
//! if let Some(uuid) = header.uuid() {
//!     println!("uuid={:02x?}", uuid);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Status
//!
//! v0.1 is under active development — see
//! [`ToDo.md`](https://github.com/BinFlip/darwinscope/blob/main/ToDo.md)
//! for the roadmap. The public API will remain unstable until v0.1
//! ships.

// This crate is used for malware analysis: every input byte is
// adversarial and must not be allowed to panic the parser.
#![deny(
    missing_docs,
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

pub mod binary;
pub mod block;
pub mod cfstring;
pub mod codesign;
pub mod dylib;
pub mod error;
pub mod export;
pub mod fixup;
pub mod import;
pub mod objc;
pub mod ptrauth;
pub mod segment;
pub mod swift;
pub mod symbol;
pub mod util;

pub use binary::MachoBinary;
pub use error::{Error, Result};

// CFString constants re-exports.
pub use cfstring::{CFString, CFStringBody, CFStringEncoding, CFStringIter, CFStringRuntime};

// Apple Blocks runtime re-exports.
pub use block::{
    BlockDescriptor, BlockIsa, BlockLiteral, BlockReference, BlockRuntime, LiteralIter,
    ReferenceIter,
};

// Objective-C runtime re-exports. Visible at the crate root for
// ergonomic consumers; the full surface lives in [`crate::objc`].
pub use objc::{
    ClassIter, ClassRefIter, ConformanceEdge, ConformanceIter, ImageInfo, Ivar, IvarIter, Method,
    MethodIter, MethodKind, ObjcCategory, ObjcClass, ObjcProtocol, ObjcRuntime, ParsedAttribute,
    ParsedAttributes, Property, PropertyIter, ProtoRefIter, ProtocolIter, ProtocolNameIter,
    RefTarget, SelRefIter, SuperRefIter,
};

// Swift 5 type-metadata re-exports. Visible at the crate root for
// ergonomic consumers; the full surface lives in [`crate::swift`].
pub use swift::{
    CaptureDescriptor, CaptureIter, Conformance, ConformanceFlags,
    ConformanceIter as SwiftConformanceIter, ContextDescriptorFlags, ContextDescriptorKind,
    DefaultOverrideEntry, DefaultOverrideEntryIter, DefaultOverrideTableHeader,
    DynamicReplacementScope, FieldDescriptor, FieldDescriptorKind, FieldIter, FieldRecord,
    FieldRecordFlags, FieldRecordIter, ForeignMetadataInit, GenericContextHeader,
    InvertibleProtocolSet, MetadataInitializationKind, MethodDescriptorFlags,
    ObjcResilientClassStubInfo, OverrideEntry, OverrideEntryIter, OverrideTableHeader, ParentChain,
    ParentContext, PrespecializationIter, ProtocolIter as SwiftProtocolIter, ReplacementIter,
    ResilientSuperclass, SingletonMetadataInit, SingletonMetadataPointer, SwiftMethodKind,
    SwiftProtocol, SwiftRuntime, TypeContextDescriptorFlags, TypeDescriptor, TypeIter,
    TypeKindBody, TypeReference, TypeReferenceKind, VTableEntry, VTableHeader, VTableIter,
};
