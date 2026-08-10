# darwinscope

Static-analysis library for Mach-O binaries — including the Objective-C
and Swift runtime metadata they embed.

A single crate that reads a byte slice and surfaces every typed
structure embedded in the format: load commands, symbols, imports and
exports, code-signing data, and the full Objective-C and Swift runtime
metadata.

## What it extracts

| Surface                       | Section / load command                              |
|-------------------------------|-----------------------------------------------------|
| Header + load commands        | `mach_header_64`, all `LC_*`                        |
| Segments + sections           | `LC_SEGMENT_64`                                     |
| Symbols                       | `LC_SYMTAB`                                         |
| Imports                       | bind opcodes / `LC_DYLD_CHAINED_FIXUPS`             |
| Exports                       | export trie / `LC_DYLD_EXPORTS_TRIE`                |
| Dylibs                        | `LC_LOAD_DYLIB` family                              |
| Function entry points         | `LC_FUNCTION_STARTS` (ULEB128 deltas)               |
| Code-signing identity         | `LC_CODE_SIGNATURE` SuperBlob → CodeDirectory       |
| Entitlements                  | `LC_CODE_SIGNATURE` SuperBlob → entitlements blob   |
| Obj-C classes / metaclasses   | `__objc_classlist`, `__objc_nlclslist`              |
| Obj-C methods                 | `class_ro_t.baseMethodList` (legacy + small)        |
| Obj-C ivars                   | `class_ro_t.ivars`                                  |
| Obj-C properties              | `class_ro_t.baseProperties`                         |
| Obj-C protocols               | `__objc_protolist`                                  |
| Obj-C categories              | `__objc_catlist`, `__objc_nlcatlist`                |
| Obj-C class ↔ protocols       | `class_ro_t.baseProtocols`                          |
| Obj-C selector / class refs   | `__objc_selrefs`, `__objc_classrefs`, `__objc_superrefs`, `__objc_protorefs` |
| Obj-C image info              | `__objc_imageinfo`                                  |
| Swift types                   | `__swift5_types`                                    |
| Swift protocols               | `__swift5_protos`                                   |
| Swift conformances            | `__swift5_proto`                                    |
| Swift fields                  | `__swift5_fieldmd`                                  |
| Swift class vtables           | trailing region of class `TargetTypeContextDescriptor` |
| CFString constants            | `__cfstring`                                        |

Pointer authentication (PAC) and `LC_DYLD_CHAINED_FIXUPS` are handled
transparently — every pointer the walkers expose is the canonical
unauthenticated virtual address.

## Status

v0.1 is under active development — see [`ToDo.md`](./ToDo.md) for the
roadmap.

## License

Copyright 2026 ATRAPS LLC. Licensed under the Apache License,
Version 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
