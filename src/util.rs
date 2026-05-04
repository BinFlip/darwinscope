//! Shared low-level helpers — ULEB128 / SLEB128 decoding,
//! virtual-to-file-offset translation, primitive byte readers.
//!
//! Used by every higher-level walker. Consumers of `darwinscope`
//! interact with the typed domain APIs in [`binary`], [`segment`],
//! [`symbol`], [`dylib`], [`objc`], [`swift`], and [`codesign`].
//!
//! [`binary`]: crate::binary
//! [`segment`]: crate::segment
//! [`symbol`]: crate::symbol
//! [`dylib`]: crate::dylib
//! [`objc`]: crate::objc
//! [`swift`]: crate::swift
//! [`codesign`]: crate::codesign

/// Decode a ULEB128-encoded unsigned integer from `bytes`.
///
/// Returns `Some((value, bytes_consumed))` on success, or `None` if
/// the slice ended mid-byte or the value would exceed 64 bits. The
/// last consumed byte is the first one with the high bit clear, per
/// the standard ULEB128 framing.
///
/// On 64-bit overflow we deliberately fail instead of saturating —
/// real Mach-O ULEB128 streams (function starts, bind opcodes,
/// export trie offsets) are always small enough to fit in `u64`,
/// and a value past that range is by definition malformed.
pub fn read_uleb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;
    for &byte in bytes {
        consumed = consumed.checked_add(1)?;
        let payload = (byte & 0x7f) as u64;
        if shift >= 64 {
            // Already at the limit — only zero payload + terminating
            // bit is acceptable. Anything else overflows u64.
            if payload != 0 || (byte & 0x80) != 0 {
                return None;
            }
            return Some((result, consumed));
        }
        let chunk = payload.checked_shl(shift)?;
        result |= chunk;
        if (byte & 0x80) == 0 {
            return Some((result, consumed));
        }
        shift = shift.checked_add(7)?;
    }
    None
}

/// Decode an SLEB128-encoded signed integer from `bytes`.
///
/// Returns `Some((value, bytes_consumed))` on success, `None` on
/// truncation or 64-bit overflow.
pub fn read_sleb128(bytes: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;
    for &byte in bytes {
        consumed = consumed.checked_add(1)?;
        let payload = (byte & 0x7f) as i64;
        if shift >= 64 {
            // Past the width — only the natural sign-extension
            // continuation is valid (all-zero or all-one trailers).
            if (byte & 0x80) != 0 {
                return None;
            }
            // Final byte: any payload bits past 63 must agree with
            // the existing sign.
            let sign_bit = (result < 0) as i64;
            let expected = if sign_bit == 1 { 0x7f } else { 0 };
            if payload != expected {
                return None;
            }
            return Some((result, consumed));
        }
        let chunk = payload.checked_shl(shift)?;
        result |= chunk;
        let high_bit = byte & 0x80;
        let sign_bit = byte & 0x40;
        let next_shift = shift.checked_add(7)?;
        if high_bit == 0 {
            // Sign-extend if the high bit of the payload (0x40) is
            // set and we haven't filled all 64 bits.
            if sign_bit != 0 && next_shift < 64 {
                let mask = i64::wrapping_shl(-1, next_shift);
                result |= mask;
            }
            return Some((result, consumed));
        }
        shift = next_shift;
    }
    None
}

/// Read a little-endian `u16` at byte offset `off` in `data`.
///
/// Returns `None` if `off + 2` overruns `data`. Used by the
/// chained-fixup decoders for `dyld_chained_starts_in_segment`
/// `page_size` / `pointer_format` / `page_count` / `page_start[]`
/// fields.
pub fn read_u16_le_at(data: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let bytes = data.get(off..end)?;
    let arr = <[u8; 2]>::try_from(bytes).ok()?;
    Some(u16::from_le_bytes(arr))
}

/// Read a little-endian `u32` at byte offset `off` in `data`.
///
/// Returns `None` if `off + 4` overruns `data`. Used everywhere
/// chained-fixup structures encode 32-bit fields.
pub fn read_u32_le_at(data: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes = data.get(off..end)?;
    let arr = <[u8; 4]>::try_from(bytes).ok()?;
    Some(u32::from_le_bytes(arr))
}

/// Read a little-endian `u64` at byte offset `off` in `data`.
///
/// Returns `None` if `off + 8` overruns `data`. Used for the
/// `segment_offset` field of `dyld_chained_starts_in_segment` and
/// for chain slot reads.
pub fn read_u64_le_at(data: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let bytes = data.get(off..end)?;
    let arr = <[u8; 8]>::try_from(bytes).ok()?;
    Some(u64::from_le_bytes(arr))
}

/// Read a little-endian `i32` at byte offset `off` in `data`.
///
/// Returns `None` if `off + 4` overruns `data`. Used by the ObjC and
/// Swift relative-pointer decoders — `RelativePointer<T>` and
/// `small_method_t` slots are signed 32-bit offsets from the address
/// of the offset itself.
pub fn read_i32_le_at(data: &[u8], off: usize) -> Option<i32> {
    let end = off.checked_add(4)?;
    let bytes = data.get(off..end)?;
    let arr = <[u8; 4]>::try_from(bytes).ok()?;
    Some(i32::from_le_bytes(arr))
}

/// Resolve an Apple-style 32-bit signed relative pointer.
///
/// `base_va` is the VM address of the offset slot itself (i.e. the
/// address `&offset` points at). Returns `base_va + sext(offset)` —
/// the absolute VM address the relative pointer references.
///
/// Cite: `objc4/runtime/objc-runtime-new.h:643-665` (`RelativePointer`),
/// `swift/include/swift/ABI/Metadata.h` (`TargetRelativeDirectPointer`).
///
/// `wrapping_add` on the sign-extended `i64` is the correct
/// arithmetic — negative offsets jump backward inside the same
/// segment, and the wrap is well-defined for any 64-bit VM address.
pub fn relative_pointer(base_va: u64, offset: i32) -> u64 {
    base_va.wrapping_add(offset as i64 as u64)
}

/// Read a NUL-terminated UTF-8 C-string starting at byte offset `off`
/// in `data`.
///
/// Returns `None` if `off` is past `data` or the string is not valid
/// UTF-8. The returned `&str` borrows from `data` and stops at the
/// first NUL — the NUL itself is *not* included.
///
/// Used everywhere ObjC stores strings — class names, method
/// selectors, type encodings, ivar names, property names, property
/// attribute strings.
pub fn read_cstr_at(data: &[u8], off: usize) -> Option<&str> {
    let tail = data.get(off..)?;
    let len = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    let body = tail.get(..len)?;
    core::str::from_utf8(body).ok()
}

/// Trim a fixed-size NUL-padded byte array into a `&str`.
///
/// Mach-O encodes segment names (`segname`), section names
/// (`sectname`), and a handful of other identifier fields as
/// fixed-width 16-byte NUL-padded ASCII buffers
/// (`load_commands.h`'s `segment_command_64.segname`,
/// `section_64.segname` / `section_64.sectname`). Returns `""` when
/// the slice up to the first NUL is not valid UTF-8 — the spec
/// constrains these fields to ASCII, so this only fires on
/// adversarial input.
///
/// The const-generic `N` lets the same helper service the 16-byte
/// `segname` / `sectname` fields and any future fixed-width name
/// fields without an extra allocation or bounds check.
pub fn cstr_from_fixed<const N: usize>(bytes: &[u8; N]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes
        .get(..len)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
}

/// Read a big-endian `u32` at byte offset `off` in `data`.
///
/// Returns `None` if `off + 4` overruns `data`. Code-signing
/// structures (`CS_SuperBlob`, `CS_BlobIndex`, `CS_CodeDirectory`)
/// are big-endian on disk in contrast to the rest of Mach-O — see
/// `RESEARCH.md` §"Code signing / Endianness" (line 991) and
/// `xnu/bsd/kern/ubc_subr.c`'s `ntohl` reads.
pub fn read_u32_be_at(data: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes = data.get(off..end)?;
    let arr = <[u8; 4]>::try_from(bytes).ok()?;
    Some(u32::from_be_bytes(arr))
}

/// Read a big-endian `u64` at byte offset `off` in `data`.
///
/// Returns `None` if `off + 8` overruns `data`. Used for the
/// `CodeDirectory.execSegBase` / `execSegLimit` / `execSegFlags`
/// fields (≥ v0x20400).
pub fn read_u64_be_at(data: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let bytes = data.get(off..end)?;
    let arr = <[u8; 8]>::try_from(bytes).ok()?;
    Some(u64::from_be_bytes(arr))
}

/// Translate a virtual-memory address to a file offset using the
/// segment table.
///
/// Returns `None` if no segment covers the address or if the segment
/// has no on-disk backing (`__PAGEZERO`, BSS-only mappings).
///
/// Re-exported from [`MachoBinary::vm_to_file_offset`] for callers
/// that already have a binary handle; provided here so other parser
/// modules in this crate can call it without importing `binary`.
///
/// [`MachoBinary::vm_to_file_offset`]: crate::binary::MachoBinary::vm_to_file_offset
pub(crate) fn vm_to_file_offset_in(
    segments: impl IntoIterator<Item = (u64, u64, u64, u64)>,
    vmaddr: u64,
) -> Option<u64> {
    // Each tuple is (vmaddr, vmsize, fileoff, filesize). We accept a
    // generic iterator so this helper does not couple to goblin or
    // to crate-internal segment view types.
    for (seg_vmaddr, seg_vmsize, seg_fileoff, seg_filesize) in segments {
        let seg_end = seg_vmaddr.checked_add(seg_vmsize)?;
        if (seg_vmaddr..seg_end).contains(&vmaddr) && seg_filesize > 0 {
            let delta = vmaddr.checked_sub(seg_vmaddr)?;
            // Reject if the address lands past the segment's
            // on-disk extent (the BSS portion of a partly-on-disk
            // segment).
            if delta >= seg_filesize {
                return None;
            }
            return seg_fileoff.checked_add(delta);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_simple() {
        assert_eq!(read_uleb128(&[0x00]), Some((0, 1)));
        assert_eq!(read_uleb128(&[0x7f]), Some((127, 1)));
        assert_eq!(read_uleb128(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26]), Some((624_485, 3)));
    }

    #[test]
    fn uleb128_truncated_returns_none() {
        // continuation bit set but no following byte
        assert_eq!(read_uleb128(&[0x80]), None);
    }

    #[test]
    fn uleb128_max_u64() {
        // 10 bytes: ff ff ff ff ff ff ff ff ff 01 → 2^64 - 1
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(read_uleb128(&max), Some((u64::MAX, 10)));
    }

    #[test]
    fn sleb128_positive() {
        assert_eq!(read_sleb128(&[0x00]), Some((0, 1)));
        assert_eq!(read_sleb128(&[0x40]), Some((-64, 1)));
        assert_eq!(read_sleb128(&[0x3f]), Some((63, 1)));
    }

    #[test]
    fn sleb128_negative_two_byte() {
        // -123456 encoded as 0xc0, 0xbb, 0x78
        assert_eq!(read_sleb128(&[0xc0, 0xbb, 0x78]), Some((-123_456, 3)));
    }

    #[test]
    fn sleb128_truncated() {
        assert_eq!(read_sleb128(&[0x80]), None);
    }

    #[test]
    fn vm_to_file_offset_translates_within_text() {
        // synthetic: __TEXT at vm 0x1_0000_0000 size 0x4000 file 0..0x4000
        let segs = [
            (0u64, 0x1_0000_0000u64, 0u64, 0u64), // __PAGEZERO (no backing)
            (0x1_0000_0000, 0x4000, 0, 0x4000),   // __TEXT
        ];
        assert_eq!(vm_to_file_offset_in(segs, 0x1_0000_0460), Some(0x460));
    }

    #[test]
    fn vm_to_file_offset_pagezero_is_none() {
        let segs = [(0u64, 0x1_0000_0000u64, 0u64, 0u64)];
        assert_eq!(vm_to_file_offset_in(segs, 0x10), None);
    }

    #[test]
    fn vm_to_file_offset_outside_any_segment() {
        let segs = [(0x1_0000_0000u64, 0x4000u64, 0u64, 0x4000u64)];
        assert_eq!(vm_to_file_offset_in(segs, 0xdead_beef), None);
    }

    #[test]
    fn read_u16_le_at_basic_and_truncation() {
        let buf = [0x34, 0x12, 0xff];
        assert_eq!(read_u16_le_at(&buf, 0), Some(0x1234));
        // bytes [0x12, 0xff] → little-endian = 0xff12
        assert_eq!(read_u16_le_at(&buf, 1), Some(0xff12));
        assert_eq!(read_u16_le_at(&buf, 2), None); // would need offsets 2..4
    }

    #[test]
    fn read_u32_le_at_basic_and_truncation() {
        let buf = [0x78, 0x56, 0x34, 0x12, 0xab];
        assert_eq!(read_u32_le_at(&buf, 0), Some(0x1234_5678));
        assert_eq!(read_u32_le_at(&buf, 2), None); // would need offsets 2..6
    }

    #[test]
    fn read_u64_le_at_basic_and_truncation() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le_at(&buf, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(read_u64_le_at(&buf, 1), None);
    }

    #[test]
    fn read_u32_be_at_basic_and_truncation() {
        let buf = [0xfa, 0xde, 0x0c, 0xc0, 0x00, 0x00, 0x00, 0x10];
        assert_eq!(read_u32_be_at(&buf, 0), Some(0xfade_0cc0));
        assert_eq!(read_u32_be_at(&buf, 4), Some(0x0000_0010));
        assert_eq!(read_u32_be_at(&buf, 5), None);
    }

    #[test]
    fn read_u64_be_at_basic_and_truncation() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_be_at(&buf, 0), Some(0x0102_0304_0506_0708));
        assert_eq!(read_u64_be_at(&buf, 1), None);
    }

    #[test]
    fn read_i32_le_at_signed_round_trip() {
        // -1 little-endian is 0xff 0xff 0xff 0xff.
        let buf = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x80];
        assert_eq!(read_i32_le_at(&buf, 0), Some(-1));
        // i32::MIN little-endian is 0x00 0x00 0x00 0x80.
        assert_eq!(read_i32_le_at(&buf, 4), Some(i32::MIN));
        assert_eq!(read_i32_le_at(&buf, 5), None);
    }

    #[test]
    fn relative_pointer_forward_and_backward() {
        // Forward jump within same segment.
        assert_eq!(relative_pointer(0x1_0000_1000, 0x40), 0x1_0000_1040);
        // Backward jump (negative offset).
        assert_eq!(relative_pointer(0x1_0000_1000, -16), 0x1_0000_0ff0);
        // Sign-extension preserves correctness across the i32 boundary.
        assert_eq!(
            relative_pointer(0x1_0000_2000, i32::MIN),
            0x1_0000_2000u64.wrapping_add(i32::MIN as i64 as u64)
        );
    }

    #[test]
    fn read_cstr_at_basic_and_truncation() {
        let buf = b"hello\0world\0\xff";
        assert_eq!(read_cstr_at(buf, 0), Some("hello"));
        assert_eq!(read_cstr_at(buf, 6), Some("world"));
        // No NUL at the end of the slice — stops at the slice tail.
        assert_eq!(read_cstr_at(buf, 12), None); // invalid UTF-8 (0xff)
        assert_eq!(read_cstr_at(buf, 99), None);
    }

    #[test]
    fn read_cstr_at_empty_string() {
        // Leading NUL ⇒ empty string, not None.
        assert_eq!(read_cstr_at(b"\0abc", 0), Some(""));
    }

    #[test]
    fn cstr_from_fixed_truncates_at_nul() {
        let mut buf = [0u8; 16];
        buf[..6].copy_from_slice(b"__TEXT");
        assert_eq!(cstr_from_fixed(&buf), "__TEXT");
    }

    #[test]
    fn cstr_from_fixed_full_window_no_nul() {
        // 16-byte buffer fully populated (no terminating NUL inside the
        // window) — Mach-O's `segname` field allows this exact case for
        // names that are exactly 16 bytes long.
        let buf = *b"__DATA_CONSTAAAA";
        assert_eq!(cstr_from_fixed(&buf), "__DATA_CONSTAAAA");
    }

    #[test]
    fn cstr_from_fixed_invalid_utf8_returns_empty() {
        let buf = [0xffu8; 16];
        assert_eq!(cstr_from_fixed(&buf), "");
    }
}
