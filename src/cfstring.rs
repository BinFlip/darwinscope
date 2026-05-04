//! CoreFoundation constant strings (`__cfstring`).
//!
//! Walks the `__cfstring` section as an array of 32-byte
//! `CFConstantString` quadruples and resolves each entry's body
//! through the segment table into either an ASCII / UTF-8 body
//! (`__TEXT,__cstring`) or a UTF-16 LE body (`__TEXT,__ustring`).
//!
//! Cite: `RESEARCH.md` §"CFString constants" (line 2149) and
//! `apple-oss-distributions/CoreFoundation`'s `CFString.c`
//! (`__CFConstStr` aka `CFConstantString`). The on-disk layout has
//! been stable for decades; cross-validated against
//! [`go-macho/cfstring.go`](https://github.com/blacktop/go-macho)
//! and `MachOView/MachOLayout.mm`.
//!
//! ## Layout (64-bit)
//!
//! | Offset | Field    | Type       | Meaning                                                         |
//! |--------|----------|------------|-----------------------------------------------------------------|
//! | `0x00` | `isa`    | `uintptr_t`| `___CFConstantStringClassReference` (chained-fixup bind)        |
//! | `0x08` | `flags`  | `uint32_t` | Encoding bits (see below)                                       |
//! | `0x0c` | `pad`    | `uint32_t` | Alignment padding                                               |
//! | `0x10` | `str`    | `const char *` | Body in `__cstring` / `__ustring` (chained-fixup rebase)    |
//! | `0x18` | `length` | `CFIndex` (`uint64_t`) | Character count (not byte count)                    |
//!
//! ## Encoding bits
//!
//! Per `RESEARCH.md:2179-2183`:
//!
//! | Pattern   | Meaning                                                |
//! |-----------|--------------------------------------------------------|
//! | `0x07c8`  | ASCII / UTF-8 body in `__TEXT,__cstring`               |
//! | `0x07d0`  | UTF-16 LE body in `__TEXT,__ustring`                   |
//!
//! ## Fail-soft posture
//!
//! [`MachoBinary::cfstrings`](crate::binary::MachoBinary::cfstrings)
//! returns `None` when the image has no `__cfstring` section. Per-row
//! decode failures (truncated quadruple, unresolvable `str` pointer,
//! invalid UTF-8 / UTF-16) yield a [`CFString`] whose [`CFString::body`]
//! is [`CFStringBody::Unresolved`] rather than dropping the row, so
//! callers can record what was on disk verbatim.

use core::marker::PhantomData;
use std::collections::HashMap;

use crate::{
    binary::MachoBinary,
    ptrauth::strip_signature,
    util::{read_cstr_at, read_u32_le_at, read_u64_le_at, vm_to_file_offset_in},
};

/// Size of one `CFConstantString` quadruple (`isa`, `flags+pad`,
/// `str`, `length` — 4 × 8 bytes).
const CFSTRING_STRIDE: usize = 32;

/// Encoding selector mask isolating ASCII (`0x07c8`) vs UTF-16
/// (`0x07d0`) — the bits CoreFoundation uses to discriminate the
/// body width.
///
/// Per `RESEARCH.md:2184`: bits beyond this selector are reserved by
/// CoreFoundation; we ignore them.
const CFSTRING_FLAG_ENCODING_MASK: u32 = 0x07f8;
/// `flags & CFSTRING_FLAG_ENCODING_MASK == CFSTRING_FLAG_ASCII` ⇒
/// body lives in `__TEXT,__cstring`.
const CFSTRING_FLAG_ASCII: u32 = 0x07c8;
/// `flags & CFSTRING_FLAG_ENCODING_MASK == CFSTRING_FLAG_UTF16` ⇒
/// body lives in `__TEXT,__ustring` (little-endian).
const CFSTRING_FLAG_UTF16: u32 = 0x07d0;

/// Encoding of a [`CFString`] body, narrowed from the raw `flags`
/// field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CFStringEncoding {
    /// ASCII / UTF-8 body in `__TEXT,__cstring` — `flags & 0x07f8 == 0x07c8`.
    Ascii,
    /// UTF-16 LE body in `__TEXT,__ustring` — `flags & 0x07f8 == 0x07d0`.
    Utf16Le,
    /// Anything else — value preserved for round-trip; we still
    /// surface the row so callers can audit unexpected encodings.
    Other(u32),
}

impl CFStringEncoding {
    /// Narrow a raw `flags` field to a known encoding.
    pub fn from_flags(flags: u32) -> Self {
        match flags & CFSTRING_FLAG_ENCODING_MASK {
            CFSTRING_FLAG_ASCII => Self::Ascii,
            CFSTRING_FLAG_UTF16 => Self::Utf16Le,
            _ => Self::Other(flags),
        }
    }
}

/// Decoded body of a [`CFString`].
///
/// `Ascii` and `Utf16` carry the resolved string. `Unresolved` means
/// the on-disk fields decoded but the `str` pointer didn't translate
/// to readable bytes (segment lookup failed, body was truncated, or
/// UTF-8 / UTF-16 decoding rejected the bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CFStringBody<'a> {
    /// ASCII / UTF-8 body, borrowed from `__TEXT,__cstring`.
    Ascii(&'a str),
    /// UTF-16 LE body, decoded into an owned `String` because
    /// host-endian / UTF-8 conversion requires materialising the
    /// code points. `length` (in chars) drives how many u16 units we
    /// read from `__TEXT,__ustring`.
    Utf16(String),
    /// Body could not be resolved or decoded. Surfaced rather than
    /// dropped so the row count stays in sync with the on-disk
    /// quadruple count.
    Unresolved,
}

/// One `__cfstring` entry.
#[derive(Debug, Clone)]
pub struct CFString<'a> {
    /// VM address of this entry's `isa` slot (start of the quadruple).
    pub address: u64,
    /// Raw `flags` field (low 32 bits of the second 8-byte slot).
    pub flags: u32,
    /// Narrowed encoding selector, derived from `flags`.
    pub encoding: CFStringEncoding,
    /// Canonical VM address of the body — `str` resolved through the
    /// chained-fixup rebases (or PAC-stripped for legacy binaries).
    /// Zero when the slot was empty.
    pub body_address: u64,
    /// `length` field in characters — code points for UTF-16, bytes
    /// for ASCII. **Not** byte count.
    pub length: u64,
    /// Decoded body, or [`CFStringBody::Unresolved`] when resolution
    /// failed.
    pub body: CFStringBody<'a>,
}

/// Aggregate `__cfstring` walker.
///
/// Constructed via [`MachoBinary::cfstrings`](crate::binary::MachoBinary::cfstrings).
/// Returns `None` when the image has no `__cfstring` section.
///
/// Carries parsed-once metadata by value (section body / vmaddr,
/// segment table for VA→file translation, chained-fixup rebase
/// index) so [`CFStringIter`] can drain it without keeping a borrow
/// on the originating [`MachoBinary`].
#[derive(Debug)]
pub struct CFStringRuntime<'a> {
    data: &'a [u8],
    segments: Vec<(u64, u64, u64, u64)>,
    section_body: &'a [u8],
    section_vmaddr: u64,
    rebases_by_va: HashMap<u64, u64>,
}

impl<'a> CFStringRuntime<'a> {
    /// Construct from a parent [`MachoBinary`].
    ///
    /// Returns `None` when the image is 32-bit (the v0.1 walker is
    /// 64-bit only — the on-disk struct is 32 bytes wide and uses
    /// 64-bit pointers) or when no `__cfstring` section is present.
    pub(crate) fn build(bin: &MachoBinary<'a>) -> Option<Self> {
        if !bin.header().is_64() {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "darwinscope::cfstring: 32-bit Mach-O — CFString walker is 64-bit only"
            );
            return None;
        }
        let mut section_body: &[u8] = &[];
        let mut section_vmaddr: u64 = 0;
        let mut found = false;
        for sect in bin.sections() {
            if sect.sectname() == "__cfstring" {
                section_body = sect.body();
                section_vmaddr = sect.addr();
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }

        let mut segments: Vec<(u64, u64, u64, u64)> = Vec::new();
        for s in bin.segments() {
            segments.push((s.vmaddr(), s.vmsize(), s.fileoff(), s.filesize()));
        }

        let mut rebases_by_va: HashMap<u64, u64> = HashMap::new();
        for r in bin.chained_rebases() {
            rebases_by_va.insert(r.vm_address(), r.target_vmaddr());
        }

        Some(Self {
            data: bin.raw(),
            segments,
            section_body,
            section_vmaddr,
            rebases_by_va,
        })
    }

    /// Iterator over every `CFConstantString` quadruple in
    /// `__cfstring`, in section order.
    pub fn iter(&self) -> CFStringIter<'a, '_> {
        CFStringIter {
            rt: self,
            cursor: 0,
            _phantom: PhantomData,
        }
    }
}

/// Iterator over [`CFString`] entries in `__cfstring`.
pub struct CFStringIter<'a, 'p> {
    rt: &'p CFStringRuntime<'a>,
    cursor: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'p> Iterator for CFStringIter<'a, 'p> {
    type Item = CFString<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let body = self.rt.section_body;
        let entry_off = self.cursor;
        let next_cursor = self.cursor.checked_add(CFSTRING_STRIDE)?;
        if next_cursor > body.len() {
            return None;
        }
        self.cursor = next_cursor;

        // flags is the low 32 bits of the second 8-byte slot
        // (offset 0x08); the high 32 bits are the `pad` field.
        let flags_off = entry_off.checked_add(0x08)?;
        let str_off = entry_off.checked_add(0x10)?;
        let length_off = entry_off.checked_add(0x18)?;

        let flags = read_u32_le_at(body, flags_off).unwrap_or(0);
        let raw_str = read_u64_le_at(body, str_off).unwrap_or(0);
        let length = read_u64_le_at(body, length_off).unwrap_or(0);

        let entry_va = self
            .rt
            .section_vmaddr
            .wrapping_add(entry_off as u64);
        let str_slot_va = self
            .rt
            .section_vmaddr
            .wrapping_add(str_off as u64);
        let body_address = resolve_pointer(self.rt, str_slot_va, raw_str);

        let encoding = CFStringEncoding::from_flags(flags);
        let body = decode_body(self.rt, encoding, body_address, length);

        Some(CFString {
            address: entry_va,
            flags,
            encoding,
            body_address,
            length,
            body,
        })
    }
}

/// Resolve a pointer slot to a canonical VM address.
///
/// Mirrors [`ObjcRuntime::resolve_pointer`](crate::objc::ObjcRuntime)
/// — the `str` slot of a `__cfstring` entry encodes the same
/// chain-format / PAC dance as Obj-C metadata pointers. For chained
/// fixups the canonical target lives in
/// [`Rebase::target_vmaddr`](crate::fixup::Rebase::target_vmaddr); for
/// legacy `LC_DYLD_INFO` images we PAC-strip the raw slot value.
fn resolve_pointer(rt: &CFStringRuntime<'_>, slot_va: u64, raw: u64) -> u64 {
    if let Some(&target) = rt.rebases_by_va.get(&slot_va) {
        return target;
    }
    strip_signature(raw)
}

/// Decode the body bytes referenced by `body_address` according to
/// `encoding` and `length`.
///
/// `length` is in *characters* per the CF convention — bytes for
/// ASCII, code units (`u16`) for UTF-16. Returns
/// [`CFStringBody::Unresolved`] for any decode failure (segment
/// lookup miss, truncated read, invalid UTF-8 / UTF-16 sequence).
fn decode_body<'a>(
    rt: &CFStringRuntime<'a>,
    encoding: CFStringEncoding,
    body_address: u64,
    length: u64,
) -> CFStringBody<'a> {
    if body_address == 0 {
        return CFStringBody::Unresolved;
    }
    let Some(off_u64) = vm_to_file_offset_in(rt.segments.iter().copied(), body_address) else {
        return CFStringBody::Unresolved;
    };
    let off = off_u64 as usize;
    match encoding {
        CFStringEncoding::Ascii => {
            // CFConstantString.length is the character count, which
            // for ASCII equals the byte count. The on-disk body is
            // also NUL-terminated, but we trust `length` so we can
            // serve callers a tight slice without scanning.
            let Ok(want) = usize::try_from(length) else {
                return CFStringBody::Unresolved;
            };
            let Some(end) = off.checked_add(want) else {
                return CFStringBody::Unresolved;
            };
            let Some(slice) = rt.data.get(off..end) else {
                // Length might over-state; fall back to a
                // NUL-terminated read so we don't drop the row on a
                // single bad byte count.
                return match read_cstr_at(rt.data, off) {
                    Some(s) => CFStringBody::Ascii(s),
                    None => CFStringBody::Unresolved,
                };
            };
            match core::str::from_utf8(slice) {
                Ok(s) => CFStringBody::Ascii(s),
                Err(_) => CFStringBody::Unresolved,
            }
        }
        CFStringEncoding::Utf16Le => {
            // Each char is 2 bytes; multiply with overflow check.
            let Ok(chars) = usize::try_from(length) else {
                return CFStringBody::Unresolved;
            };
            let Some(byte_len) = chars.checked_mul(2) else {
                return CFStringBody::Unresolved;
            };
            let Some(end) = off.checked_add(byte_len) else {
                return CFStringBody::Unresolved;
            };
            let Some(slice) = rt.data.get(off..end) else {
                return CFStringBody::Unresolved;
            };
            decode_utf16_le(slice)
                .map(CFStringBody::Utf16)
                .unwrap_or(CFStringBody::Unresolved)
        }
        CFStringEncoding::Other(_) => CFStringBody::Unresolved,
    }
}

/// Decode a little-endian UTF-16 byte sequence into an owned `String`.
///
/// Returns `None` for truncated input (odd byte length) or invalid
/// surrogate pairs. Pulled out as a free function so the iterator's
/// `next` body stays readable.
fn decode_utf16_le(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i < bytes.len() {
        let lo = *bytes.get(i)?;
        let hi = *bytes.get(i.checked_add(1)?)?;
        units.push(u16::from_le_bytes([lo, hi]));
        i = i.checked_add(2)?;
    }
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_from_flags_ascii_and_utf16() {
        // Per RESEARCH.md:2181-2182.
        assert_eq!(CFStringEncoding::from_flags(0x07c8), CFStringEncoding::Ascii);
        assert_eq!(CFStringEncoding::from_flags(0x07d0), CFStringEncoding::Utf16Le);
        // Reserved high bits beyond the encoding selector are
        // ignored — both of these still narrow to ASCII / UTF-16.
        assert_eq!(CFStringEncoding::from_flags(0xffff_07c8), CFStringEncoding::Ascii);
        assert_eq!(CFStringEncoding::from_flags(0xdead_07d0), CFStringEncoding::Utf16Le);
        // Anything else round-trips verbatim.
        assert!(matches!(
            CFStringEncoding::from_flags(0x1234),
            CFStringEncoding::Other(0x1234)
        ));
    }

    #[test]
    fn decode_utf16_le_basic() {
        // "Hi" in UTF-16 LE: 0x0048 0x0069.
        let bytes = [0x48, 0x00, 0x69, 0x00];
        assert_eq!(decode_utf16_le(&bytes).as_deref(), Some("Hi"));
    }

    #[test]
    fn decode_utf16_le_supplementary_plane() {
        // U+1F600 GRINNING FACE encoded as surrogate pair
        // 0xD83D 0xDE00 in UTF-16 LE.
        let bytes = [0x3d, 0xd8, 0x00, 0xde];
        let s = decode_utf16_le(&bytes).expect("valid surrogate pair decodes");
        assert_eq!(s, "\u{1F600}");
    }

    #[test]
    fn decode_utf16_le_rejects_odd_length() {
        assert_eq!(decode_utf16_le(&[0x48, 0x00, 0x69]), None);
    }

    #[test]
    fn decode_utf16_le_rejects_lone_surrogate() {
        // Lone high surrogate, no following low surrogate.
        let bytes = [0x3d, 0xd8, 0x00, 0x00];
        assert_eq!(decode_utf16_le(&bytes), None);
    }
}
