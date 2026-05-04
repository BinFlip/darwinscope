//! `__objc_imageinfo` payload.
//!
//! Cite: `objc4/runtime/objc-abi.h:85-139` and `RESEARCH.md`
//! §"`objc_image_info`" (line 1643).
//!
//! Every image with ObjC content carries exactly one
//! `__objc_imageinfo` section, 8 bytes total: `version` (`u32`) and
//! `flags` (`u32`). The flags encode runtime-ABI capability bits
//! and the Swift ABI version of any Swift code embedded in the
//! image.

use crate::util::read_u32_le_at;

/// `__objc_imageinfo` decoded payload.
///
/// Constructed via [`ObjcRuntime::image_info`](crate::objc::ObjcRuntime::image_info).
/// Returned by value because the on-disk struct is only 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageInfo {
    /// `objc_image_info.version` — currently always `0`.
    pub version: u32,
    /// `objc_image_info.flags` — `OBJC_IMAGE_*` bits plus the packed
    /// Swift ABI version. Use the named accessors below for
    /// individual flags.
    pub flags: u32,
}

/// `OBJC_IMAGE_DYLD_CATEGORIES_OPTIMIZED` (`1 << 0`) — categories
/// have been preattached by dyld in the shared cache.
pub const OBJC_IMAGE_DYLD_CATEGORIES_OPTIMIZED: u32 = 1 << 0;
/// `OBJC_IMAGE_SUPPORTS_GC` (`1 << 1`) — image was built with
/// optional GC support (legacy).
pub const OBJC_IMAGE_SUPPORTS_GC: u32 = 1 << 1;
/// `OBJC_IMAGE_REQUIRES_GC` (`1 << 2`) — image requires GC (legacy).
pub const OBJC_IMAGE_REQUIRES_GC: u32 = 1 << 2;
/// `OBJC_IMAGE_OPTIMIZED_BY_DYLD` (`1 << 3`) — image is from an
/// optimised shared cache.
pub const OBJC_IMAGE_OPTIMIZED_BY_DYLD: u32 = 1 << 3;
/// `OBJC_IMAGE_SIGNED_CLASS_RO` (`1 << 4`) — `class_ro_t` pointers
/// in this image are PAC-signed (arm64e only).
pub const OBJC_IMAGE_SIGNED_CLASS_RO: u32 = 1 << 4;
/// `OBJC_IMAGE_IS_SIMULATED` (`1 << 5`) — image was compiled for a
/// simulator runtime.
pub const OBJC_IMAGE_IS_SIMULATED: u32 = 1 << 5;
/// `OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES` (`1 << 6`) —
/// `category_t._classProperties` field is present on disk.
pub const OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES: u32 = 1 << 6;
/// `OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE` (`1 << 7`) — set by old
/// dyld, superseded.
pub const OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE: u32 = 1 << 7;

/// Mask isolating the 1-byte unstable Swift ABI version (bits 8..15).
pub const OBJC_IMAGE_SWIFT_UNSTABLE_VERSION_MASK: u32 = 0x0000_ff00;
/// Mask isolating the 2-byte stable Swift ABI version (bits 16..31).
pub const OBJC_IMAGE_SWIFT_STABLE_VERSION_MASK: u32 = 0xffff_0000;

impl ImageInfo {
    /// Decode `__objc_imageinfo` from a section body.
    ///
    /// Returns `None` when the body is shorter than 8 bytes (every
    /// known ABI uses exactly 8).
    pub(crate) fn parse(body: &[u8]) -> Option<Self> {
        let version = read_u32_le_at(body, 0)?;
        let flags = read_u32_le_at(body, 4)?;
        Some(Self { version, flags })
    }

    /// `OBJC_IMAGE_DYLD_CATEGORIES_OPTIMIZED` (bit `0`).
    pub fn dyld_categories_optimized(&self) -> bool {
        self.flags & OBJC_IMAGE_DYLD_CATEGORIES_OPTIMIZED != 0
    }
    /// `OBJC_IMAGE_SUPPORTS_GC` (bit `1`).
    pub fn supports_gc(&self) -> bool {
        self.flags & OBJC_IMAGE_SUPPORTS_GC != 0
    }
    /// `OBJC_IMAGE_REQUIRES_GC` (bit `2`).
    pub fn requires_gc(&self) -> bool {
        self.flags & OBJC_IMAGE_REQUIRES_GC != 0
    }
    /// `OBJC_IMAGE_OPTIMIZED_BY_DYLD` (bit `3`).
    pub fn optimized_by_dyld(&self) -> bool {
        self.flags & OBJC_IMAGE_OPTIMIZED_BY_DYLD != 0
    }
    /// `OBJC_IMAGE_SIGNED_CLASS_RO` (bit `4`).
    pub fn signed_class_ro(&self) -> bool {
        self.flags & OBJC_IMAGE_SIGNED_CLASS_RO != 0
    }
    /// `OBJC_IMAGE_IS_SIMULATED` (bit `5`).
    pub fn is_simulated(&self) -> bool {
        self.flags & OBJC_IMAGE_IS_SIMULATED != 0
    }
    /// `OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES` (bit `6`).
    pub fn has_category_class_properties(&self) -> bool {
        self.flags & OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES != 0
    }
    /// `OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE` (bit `7`).
    pub fn optimized_by_dyld_closure(&self) -> bool {
        self.flags & OBJC_IMAGE_OPTIMIZED_BY_DYLD_CLOSURE != 0
    }

    /// 1-byte unstable Swift ABI version (`flags >> 8 & 0xff`).
    ///
    /// Stable-ABI binaries store `7` here (`SwiftVersion5`); the
    /// actual stable version is in [`Self::swift_stable_version`].
    pub fn swift_unstable_version(&self) -> u8 {
        ((self.flags & OBJC_IMAGE_SWIFT_UNSTABLE_VERSION_MASK) >> 8) as u8
    }

    /// 2-byte stable Swift ABI version (`flags >> 16 & 0xffff`).
    pub fn swift_stable_version(&self) -> u16 {
        ((self.flags & OBJC_IMAGE_SWIFT_STABLE_VERSION_MASK) >> 16) as u16
    }

    /// Whether the image embeds Swift code, per the `containsSwift`
    /// predicate in `objc-abi.h:135`.
    pub fn contains_swift(&self) -> bool {
        self.flags & OBJC_IMAGE_SWIFT_UNSTABLE_VERSION_MASK != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let body = [
            0x00, 0x00, 0x00, 0x00, // version = 0
            0x40, 0x00, 0x00, 0x00, // flags = 0x40 (HasCategoryClassProperties)
        ];
        let info = ImageInfo::parse(&body).unwrap();
        assert_eq!(info.version, 0);
        assert_eq!(info.flags, 0x40);
        assert!(info.has_category_class_properties());
        assert!(!info.signed_class_ro());
        assert!(!info.contains_swift());
    }

    #[test]
    fn truncated_returns_none() {
        assert_eq!(ImageInfo::parse(&[0; 7]), None);
    }

    #[test]
    fn swift_version_decode() {
        // SwiftVersion5 (unstable=7) and stable version 0x0001.
        let info = ImageInfo {
            version: 0,
            flags: (0x0001 << 16) | (7 << 8),
        };
        assert!(info.contains_swift());
        assert_eq!(info.swift_unstable_version(), 7);
        assert_eq!(info.swift_stable_version(), 1);
    }
}
