//! Apple Code Signing decoder.
//!
//! Walks the embedded `LC_CODE_SIGNATURE` payload (a `CS_SuperBlob`)
//! into typed views over its component blobs:
//!
//! - [`Signature`] — the SuperBlob walker entry point.
//! - [`BlobIndex`] / [`Slot`] — per-slot dispatch.
//! - [`CodeDirectory`] — the primary CD plus alternates.
//! - [`Entitlements`], [`DerEntitlements`] — XML and DER plists.
//! - [`Requirements`] — opaque pass-through.
//! - [`CmsSignature`] — embedded CMS size + presence.
//!
//! ## Endianness
//!
//! Code-signing structure fields are **big-endian** on disk, in
//! contrast to every other Mach-O subsystem `darwinscope` decodes.
//! The helpers in [`crate::util`] (`read_u{16,32,64}_be_at`) read
//! them. Cite: `xnu/bsd/kern/ubc_subr.c` (every field is read via
//! `ntohl` / `OSSwapBigToHostInt32`).
//!
//! ## Lifetime model
//!
//! [`Signature<'a>`] borrows the binary's data slice (`'a`) — every
//! blob view (entitlements XML, identifier strings, hash bytes) is
//! a zero-copy reborrow of the same slice.
//!
//! See `RESEARCH.md` §"Code signing" (line 979) and
//! `reference/xnu/osfmk/kern/cs_blobs.h` for the on-disk struct
//! definitions.

use bitflags::bitflags;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::util::{read_cstr_at, read_u32_be_at, read_u64_be_at};

/// `CSMAGIC_EMBEDDED_SIGNATURE` — entry point of an embedded
/// SuperBlob (cite: `cs_blobs.h:95`).
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
/// `CSMAGIC_EMBEDDED_SIGNATURE_OLD` — legacy embedded form.
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade_0b02;
/// `CSMAGIC_CODEDIRECTORY` (cite: `cs_blobs.h:94`).
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
/// `CSMAGIC_REQUIREMENT` (cite: `cs_blobs.h:92`).
pub const CSMAGIC_REQUIREMENT: u32 = 0xfade_0c00;
/// `CSMAGIC_REQUIREMENTS` — vector of requirements
/// (cite: `cs_blobs.h:93`).
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
/// `CSMAGIC_EMBEDDED_ENTITLEMENTS` — XML plist
/// (cite: `cs_blobs.h:97`).
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
/// `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` — DER plist
/// (cite: `cs_blobs.h:98`).
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
/// `CSMAGIC_BLOBWRAPPER` — CMS signature wrapper
/// (cite: `cs_blobs.h:100`).
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;

/// Header size of every blob: `magic` (BE u32) + `length` (BE u32).
#[allow(dead_code)] // used by CodeDirectory / Entitlements parsers in subsequent PRs.
pub(crate) const BLOB_HEADER_SIZE: usize = 8;
/// Size of the SuperBlob header before the index array.
const SUPERBLOB_HEADER_SIZE: usize = 12;
/// Size of one `CS_BlobIndex` entry: `type` (BE u32) + `offset`
/// (BE u32).
const BLOB_INDEX_SIZE: usize = 8;

/// Slot kind from `CS_BlobIndex.type` (cite: `cs_blobs.h:110-128`).
///
/// Each entry of a SuperBlob's index array tags its blob with one of
/// these slot numbers. Slot indices `0..=11` identify *special* slots
/// — blobs with a fixed purpose whose CD hash sits in the negative
/// indices of the CodeDirectory hash table. Slot indices in
/// `0x1000..=0x1004` are *alternate* CodeDirectories (used to ship
/// multiple hash algorithms in the same binary). Slots `≥ 0x10000`
/// are top-level wrappers (CMS signature, identification, ticket).
///
/// Special-cased so consumers can pattern-match instead of comparing
/// raw `u32`s. Unknown values are surfaced as [`Slot::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// `CSSLOT_CODEDIRECTORY = 0` — the canonical CodeDirectory the
    /// kernel hashes for the CDHash. The "primary" CD when only one
    /// hash algorithm is present.
    CodeDirectory,
    /// `CSSLOT_INFOSLOT = 1` — SHA digest of the bundle's
    /// `Info.plist`, used by Gatekeeper to detect plist tampering on
    /// `.app` bundles.
    InfoSlot,
    /// `CSSLOT_REQUIREMENTS = 2` — the internal "designated
    /// requirement" vector, encoded as a [`Requirements`]
    /// (`CSMAGIC_REQUIREMENTS`) blob.
    Requirements,
    /// `CSSLOT_RESOURCEDIR = 3` — SHA digest of
    /// `_CodeSignature/CodeResources` (the per-resource hash list
    /// for bundle resources).
    ResourceDir,
    /// `CSSLOT_APPLICATION = 4` — application-specific slot reserved
    /// for the signer; rarely populated by Apple toolchains.
    Application,
    /// `CSSLOT_ENTITLEMENTS = 5` — XML plist of the entitlements the
    /// binary requested. See [`Entitlements`].
    Entitlements,
    /// `CSSLOT_DER_ENTITLEMENTS = 7` — Apple's DER-encoded
    /// entitlement plist. Required for hardened-runtime / iOS code
    /// signatures since macOS 11 / iOS 14. See [`DerEntitlements`].
    DerEntitlements,
    /// `CSSLOT_LAUNCH_CONSTRAINT_SELF = 8` — declarative constraints
    /// the kernel enforces on *this* binary at launch (introduced
    /// macOS 13 / iOS 16, `LWCRBlob`).
    LaunchConstraintSelf,
    /// `CSSLOT_LAUNCH_CONSTRAINT_PARENT = 9` — constraints the
    /// kernel enforces on the *parent* process at launch.
    LaunchConstraintParent,
    /// `CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE = 10` — constraints on
    /// the *responsible* process (the one Privacy & Security reports
    /// the launch under).
    LaunchConstraintResponsible,
    /// `CSSLOT_LIBRARY_CONSTRAINT = 11` — constraints applied when
    /// this binary is loaded *as a library* (dlopen / linkage).
    LibraryConstraint,
    /// `CSSLOT_ALTERNATE_CODEDIRECTORIES + i` (range
    /// `0x1000..=0x1004`). Holds CodeDirectories using an alternate
    /// hash algorithm (e.g. SHA-1 alongside SHA-256), allowing one
    /// signature to satisfy multiple OS versions. The inner `u32` is
    /// the index `i`.
    AlternateCodeDirectory(u32),
    /// `CSSLOT_SIGNATURESLOT = 0x10000` — the CMS / PKCS#7
    /// SignedData wrapper (`CSMAGIC_BLOBWRAPPER`). See
    /// [`CmsSignature`].
    SignatureSlot,
    /// `CSSLOT_IDENTIFICATIONSLOT = 0x10001` — provisioning-style
    /// identification blob; used by some validation paths.
    IdentificationSlot,
    /// `CSSLOT_TICKETSLOT = 0x10002` — notarization stapled ticket
    /// (the response from Apple's notary service).
    TicketSlot,
    /// Any other slot value, surfaced verbatim. Reserved for forward
    /// compatibility with new `CSSLOT_*` constants.
    Other(u32),
}

impl Slot {
    /// Decode a raw `CS_BlobIndex.type` value.
    ///
    /// Inlined because each blob entry of the SuperBlob index calls
    /// this exactly once, and code-signing blobs typically contain
    /// a dozen or more entries.
    #[inline]
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::CodeDirectory,
            1 => Self::InfoSlot,
            2 => Self::Requirements,
            3 => Self::ResourceDir,
            4 => Self::Application,
            5 => Self::Entitlements,
            7 => Self::DerEntitlements,
            8 => Self::LaunchConstraintSelf,
            9 => Self::LaunchConstraintParent,
            10 => Self::LaunchConstraintResponsible,
            11 => Self::LibraryConstraint,
            n if (0x1000..=0x1004).contains(&n) => {
                Self::AlternateCodeDirectory(n.wrapping_sub(0x1000))
            }
            0x10000 => Self::SignatureSlot,
            0x10001 => Self::IdentificationSlot,
            0x10002 => Self::TicketSlot,
            other => Self::Other(other),
        }
    }
}

/// One entry of the SuperBlob's index array — a `(slot, offset)`
/// pair pointing at a typed blob within the SuperBlob payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobIndex {
    /// Decoded slot kind.
    pub slot: Slot,
    /// Raw `type` value as read from disk.
    pub raw_slot: u32,
    /// Offset of the blob from the start of the SuperBlob, in bytes.
    pub offset: u32,
}

/// Embedded code-signature SuperBlob walker.
///
/// Construct via [`MachoBinary::signature`](crate::binary::MachoBinary::signature).
/// Returns `None` when the binary has no `LC_CODE_SIGNATURE` or
/// the SuperBlob magic doesn't match `CSMAGIC_EMBEDDED_SIGNATURE`.
#[derive(Debug, Clone, Copy)]
pub struct Signature<'a> {
    /// The full Mach-O data slice. Blob offsets translate inside
    /// this slice, gated by `base` (the SuperBlob's start).
    data: &'a [u8],
    /// Absolute byte offset of the SuperBlob within `data`
    /// (i.e. `LC_CODE_SIGNATURE.dataoff`).
    base: usize,
    /// Decoded SuperBlob magic.
    magic: u32,
    /// Decoded SuperBlob length (in bytes, including header).
    length: u32,
    /// Decoded SuperBlob count (number of index entries).
    count: u32,
}

impl<'a> Signature<'a> {
    /// Parse the SuperBlob at `data[base..]`.
    ///
    /// Returns `None` when the magic is not `CSMAGIC_EMBEDDED_SIGNATURE`
    /// or `CSMAGIC_EMBEDDED_SIGNATURE_OLD`, or when the header
    /// overruns the available data.
    pub fn parse(data: &'a [u8], base: usize) -> Option<Self> {
        let header_end = base.checked_add(SUPERBLOB_HEADER_SIZE)?;
        let _ = data.get(base..header_end)?;
        let magic = read_u32_be_at(data, base)?;
        if magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_EMBEDDED_SIGNATURE_OLD {
            return None;
        }
        let len_off = base.checked_add(4)?;
        let count_off = base.checked_add(8)?;
        let length = read_u32_be_at(data, len_off)?;
        let count = read_u32_be_at(data, count_off)?;
        // Sanity: total length must cover the index array.
        let need =
            SUPERBLOB_HEADER_SIZE.checked_add((count as usize).checked_mul(BLOB_INDEX_SIZE)?)?;
        if (length as usize) < need {
            return None;
        }
        let blob_end = base.checked_add(length as usize)?;
        if blob_end > data.len() {
            return None;
        }
        Some(Self {
            data,
            base,
            magic,
            length,
            count,
        })
    }

    /// `CS_SuperBlob.magic` — `0xfade0cc0` for embedded signatures.
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// `CS_SuperBlob.length` — total SuperBlob length in bytes.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// `CS_SuperBlob.count` — number of index entries.
    pub fn blob_count(&self) -> u32 {
        self.count
    }

    /// Iterator over the SuperBlob's `CS_BlobIndex` entries.
    pub fn blobs(&self) -> BlobIter<'a> {
        BlobIter {
            data: self.data,
            base: self.base,
            count: self.count,
            cursor: 0,
        }
    }

    /// Find the blob slot's payload bytes (header + body), if the
    /// SuperBlob has an entry for that slot.
    #[allow(dead_code)] // used by CodeDirectory / Entitlements / Requirements parsers.
    pub(crate) fn find_blob_bytes(&self, target: Slot) -> Option<&'a [u8]> {
        for idx in self.blobs() {
            if idx.slot == target {
                return self.blob_bytes_at(idx.offset);
            }
        }
        None
    }

    #[allow(dead_code)] // used by CodeDirectory / Entitlements / Requirements parsers.
    pub(crate) fn blob_bytes_at(&self, offset: u32) -> Option<&'a [u8]> {
        let abs = self.base.checked_add(offset as usize)?;
        let header = self.data.get(abs..abs.checked_add(BLOB_HEADER_SIZE)?)?;
        let blob_len = read_u32_be_at(header, 4)? as usize;
        if blob_len < BLOB_HEADER_SIZE {
            return None;
        }
        let end = abs.checked_add(blob_len)?;
        self.data.get(abs..end)
    }
}

/// CodeDirectory version constants (cite: `cs_blobs.h:170-176`).
pub mod cd_version {
    /// Base version with all the fields up to `pageSize`.
    pub const BASE: u32 = 0x0002_0001;
    /// Adds `scatterOffset`.
    pub const SUPPORTS_SCATTER: u32 = 0x0002_0100;
    /// Adds `teamOffset`.
    pub const SUPPORTS_TEAM_ID: u32 = 0x0002_0200;
    /// Adds `codeLimit64`.
    pub const SUPPORTS_CODE_LIMIT64: u32 = 0x0002_0300;
    /// Adds `execSegBase` / `execSegLimit` / `execSegFlags`.
    pub const SUPPORTS_EXEC_SEG: u32 = 0x0002_0400;
    /// Adds linkage records.
    pub const SUPPORTS_LINKAGE: u32 = 0x0002_0500;
}

bitflags! {
    /// `CS_*` flags from `CS_CodeDirectory.flags`
    /// (cite: `cs_blobs.h:130-167`). Unknown bits are preserved on
    /// round-trip via `from_bits_retain`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CdFlags: u32 {
        /// `CS_VALID = 0x1` — dynamically valid (set by kernel).
        const VALID = 0x1;
        /// `CS_ADHOC = 0x2` — adhoc-signed (no real CMS).
        const ADHOC = 0x2;
        /// `CS_GET_TASK_ALLOW = 0x4` — `task_for_pid` allowed.
        const GET_TASK_ALLOW = 0x4;
        /// `CS_INSTALLER = 0x8`.
        const INSTALLER = 0x8;
        /// `CS_FORCED_LV = 0x10` — library validation forced.
        const FORCED_LV = 0x10;
        /// `CS_INVALID_ALLOWED = 0x20`.
        const INVALID_ALLOWED = 0x20;
        /// `CS_HARD = 0x100`.
        const HARD = 0x100;
        /// `CS_KILL = 0x200`.
        const KILL = 0x200;
        /// `CS_CHECK_EXPIRATION = 0x400`.
        const CHECK_EXPIRATION = 0x400;
        /// `CS_RESTRICT = 0x800`.
        const RESTRICT = 0x800;
        /// `CS_ENFORCEMENT = 0x1000`.
        const ENFORCEMENT = 0x1000;
        /// `CS_REQUIRE_LV = 0x2000` — library validation required.
        const REQUIRE_LV = 0x2000;
        /// `CS_ENTITLEMENTS_VALIDATED = 0x4000`.
        const ENTITLEMENTS_VALIDATED = 0x4000;
        /// `CS_NVRAM_UNRESTRICTED = 0x8000`.
        const NVRAM_UNRESTRICTED = 0x8000;
        /// `CS_RUNTIME = 0x10000` — hardened runtime.
        const RUNTIME = 0x10000;
        /// `CS_LINKER_SIGNED = 0x20000` — auto-applied by ld(1).
        const LINKER_SIGNED = 0x20000;
    }
}

/// `CS_CodeDirectory.hashType` — selects the digest algorithm
/// used for the CD's hash slots and the CDHash itself
/// (cite: `cs_blobs.h:182-187`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// SHA-1 (legacy; `kSecCodeSignatureHashSHA1 = 1`).
    Sha1,
    /// SHA-256 (`kSecCodeSignatureHashSHA256 = 2`) — modern default.
    Sha256,
    /// SHA-256 truncated to 20 bytes (`= 3`).
    Sha256Truncated,
    /// SHA-384 (`= 4`).
    Sha384,
    /// SHA-512 (`= 5`).
    Sha512,
    /// Unknown algorithm; surfaced verbatim.
    Other(u8),
}

impl HashType {
    /// Decode a raw `hashType` byte.
    #[inline]
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Sha1,
            2 => Self::Sha256,
            3 => Self::Sha256Truncated,
            4 => Self::Sha384,
            5 => Self::Sha512,
            other => Self::Other(other),
        }
    }

    /// Output digest size in bytes, if known.
    #[inline]
    pub fn digest_size(self) -> Option<usize> {
        match self {
            Self::Sha1 => Some(20),
            Self::Sha256 => Some(32),
            Self::Sha256Truncated => Some(20),
            Self::Sha384 => Some(48),
            Self::Sha512 => Some(64),
            Self::Other(_) => None,
        }
    }
}

const CD_FIELD_VERSION: usize = 8;
const CD_FIELD_FLAGS: usize = 12;
const CD_FIELD_HASH_OFFSET: usize = 16;
const CD_FIELD_IDENT_OFFSET: usize = 20;
const CD_FIELD_N_SPECIAL_SLOTS: usize = 24;
const CD_FIELD_N_CODE_SLOTS: usize = 28;
const CD_FIELD_CODE_LIMIT: usize = 32;
const CD_FIELD_HASH_SIZE: usize = 36;
const CD_FIELD_HASH_TYPE: usize = 37;
const CD_FIELD_PLATFORM: usize = 38;
const CD_FIELD_PAGE_SIZE: usize = 39;
const CD_FIELD_TEAM_OFFSET: usize = 48;
const CD_FIELD_CODE_LIMIT_64: usize = 56;
const CD_FIELD_EXEC_SEG_BASE: usize = 64;
const CD_FIELD_EXEC_SEG_LIMIT: usize = 72;
const CD_FIELD_EXEC_SEG_FLAGS: usize = 80;

/// Decoded `CS_CodeDirectory` blob.
///
/// The full blob bytes (header + identifier + team-id strings +
/// hash slots) are referenced verbatim through `&'a [u8]`. CDHash
/// is recomputed from those bytes on demand via `cd_hash` /
/// `cd_hash_truncated`.
#[derive(Debug, Clone, Copy)]
pub struct CodeDirectory<'a> {
    /// The full CD blob bytes (length = self.length).
    blob: &'a [u8],
    version: u32,
    flags: u32,
    /// Offset of code hash slot 0 from the start of the blob;
    /// special slots `-1..-n` precede it at `hash_offset - i*hash_size`,
    /// code slots follow at `hash_offset + j*hash_size`.
    hash_offset: u32,
    ident_offset: u32,
    n_special_slots: u32,
    n_code_slots: u32,
    code_limit: u32,
    hash_size: u8,
    hash_type_raw: u8,
    platform: u8,
    page_size_log2: u8,
    team_offset: u32,
}

impl<'a> CodeDirectory<'a> {
    /// Parse a CodeDirectory blob from the given header-aligned
    /// byte slice (the slice must be exactly the blob's length:
    /// `magic` through trailing hash slots).
    ///
    /// Returns `None` when the blob magic doesn't match
    /// `CSMAGIC_CODEDIRECTORY` or the header is truncated.
    pub fn parse(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < CD_FIELD_PAGE_SIZE.checked_add(1)? {
            return None;
        }
        let magic = read_u32_be_at(blob, 0)?;
        if magic != CSMAGIC_CODEDIRECTORY {
            return None;
        }
        let version = read_u32_be_at(blob, CD_FIELD_VERSION)?;
        let flags = read_u32_be_at(blob, CD_FIELD_FLAGS)?;
        let hash_offset = read_u32_be_at(blob, CD_FIELD_HASH_OFFSET)?;
        let ident_offset = read_u32_be_at(blob, CD_FIELD_IDENT_OFFSET)?;
        let n_special_slots = read_u32_be_at(blob, CD_FIELD_N_SPECIAL_SLOTS)?;
        let n_code_slots = read_u32_be_at(blob, CD_FIELD_N_CODE_SLOTS)?;
        let code_limit = read_u32_be_at(blob, CD_FIELD_CODE_LIMIT)?;
        let hash_size = *blob.get(CD_FIELD_HASH_SIZE)?;
        let hash_type_raw = *blob.get(CD_FIELD_HASH_TYPE)?;
        let platform = *blob.get(CD_FIELD_PLATFORM)?;
        let page_size_log2 = *blob.get(CD_FIELD_PAGE_SIZE)?;

        let team_offset = if version >= cd_version::SUPPORTS_TEAM_ID {
            read_u32_be_at(blob, CD_FIELD_TEAM_OFFSET).unwrap_or(0)
        } else {
            0
        };

        Some(Self {
            blob,
            version,
            flags,
            hash_offset,
            ident_offset,
            n_special_slots,
            n_code_slots,
            code_limit,
            hash_size,
            hash_type_raw,
            platform,
            page_size_log2,
            team_offset,
        })
    }

    /// `CS_CodeDirectory.version` — encodes which trailing fields
    /// are present (≥ `0x20100` ⇒ `scatterOffset`, ≥ `0x20200`
    /// ⇒ `teamOffset`, ≥ `0x20400` ⇒ `execSeg*`).
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Decoded `CS_*` flags.
    pub fn flags(&self) -> CdFlags {
        CdFlags::from_bits_retain(self.flags)
    }

    /// Raw `flags` value (for callers that need bits beyond the
    /// named [`CdFlags`] constants).
    pub fn raw_flags(&self) -> u32 {
        self.flags
    }

    /// Decoded `hashType`.
    pub fn hash_type(&self) -> HashType {
        HashType::from_raw(self.hash_type_raw)
    }

    /// `hashSize` — bytes per hash slot.
    pub fn hash_size(&self) -> u8 {
        self.hash_size
    }

    /// Resolved page size in bytes (`1 << pageSize`). Returns `0`
    /// for the legacy "infinite" sentinel (`pageSize == 0`).
    pub fn page_size(&self) -> u32 {
        if self.page_size_log2 == 0 {
            0
        } else {
            1u32.wrapping_shl(self.page_size_log2 as u32)
        }
    }

    /// `nSpecialSlots` — number of negative-index hash slots
    /// preceding slot 0 (Info.plist, Requirements, ResourceDir,
    /// Application, Entitlements, DerEntitlements).
    pub fn n_special_slots(&self) -> u32 {
        self.n_special_slots
    }

    /// `nCodeSlots` — number of ordinary page hashes following
    /// slot 0.
    pub fn n_code_slots(&self) -> u32 {
        self.n_code_slots
    }

    /// `codeLimit` — byte length of the image region covered by
    /// the code hashes.
    pub fn code_limit(&self) -> u32 {
        self.code_limit
    }

    /// `platform` — platform identifier; `0` for non-platform
    /// binaries.
    pub fn platform(&self) -> u8 {
        self.platform
    }

    /// Identifier string (`identOffset`-relative), if present and
    /// valid UTF-8.
    ///
    /// Returns `None` when `ident_offset` is `0` — the `cs_blobs.h`
    /// convention for an absent identifier — or when the offset is
    /// out of bounds or the string is not valid UTF-8.
    pub fn identifier(&self) -> Option<&'a str> {
        if self.ident_offset == 0 {
            return None;
        }
        read_cstr_at(self.blob, self.ident_offset as usize)
    }

    /// Team ID string (`teamOffset`-relative), if version ≥
    /// `0x20200` and the offset is non-zero. `None` for adhoc
    /// signatures (which lack a team identity).
    pub fn team_id(&self) -> Option<&'a str> {
        if self.version < cd_version::SUPPORTS_TEAM_ID || self.team_offset == 0 {
            return None;
        }
        read_cstr_at(self.blob, self.team_offset as usize)
    }

    /// CDHash — full digest of the canonical CD blob bytes,
    /// computed using [`hash_type`](Self::hash_type).
    ///
    /// Returns an empty `Vec` for hash types `darwinscope` does
    /// not implement (`Sha1`, `Sha256Truncated`, `Other`); the
    /// `sha2` crate covers SHA-256 / SHA-384 / SHA-512.
    pub fn cd_hash(&self) -> Vec<u8> {
        match self.hash_type() {
            HashType::Sha256 => Sha256::digest(self.blob).to_vec(),
            HashType::Sha384 => Sha384::digest(self.blob).to_vec(),
            HashType::Sha512 => Sha512::digest(self.blob).to_vec(),
            HashType::Sha1 | HashType::Sha256Truncated | HashType::Other(_) => Vec::new(),
        }
    }

    /// CDHash truncated to the first 20 bytes — the form AMFI
    /// compares against. Zero-padded if the underlying digest is
    /// shorter than 20 bytes (only possible for unimplemented hash
    /// types, where the source digest is empty).
    ///
    /// Computes the digest directly into the 20-byte output buffer
    /// rather than going through [`cd_hash`](Self::cd_hash) — avoids
    /// a heap allocation for the full digest just to copy 20 bytes
    /// out. AMFI invokes this once per binary at load time, so the
    /// allocation savings matter when batch-scanning a filesystem.
    pub fn cd_hash_truncated(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        // GenericArray from sha2 derefs to &[u8]; we copy the prefix
        // into the fixed output buffer without going through Vec.
        match self.hash_type() {
            HashType::Sha256 => copy_prefix(&mut out, &Sha256::digest(self.blob)),
            HashType::Sha384 => copy_prefix(&mut out, &Sha384::digest(self.blob)),
            HashType::Sha512 => copy_prefix(&mut out, &Sha512::digest(self.blob)),
            HashType::Sha1 | HashType::Sha256Truncated | HashType::Other(_) => {}
        }
        out
    }

    /// The canonical CD blob bytes (`magic` through trailing hash
    /// slots) — i.e. the input that hashes to CDHash. Useful for
    /// callers that want to compute the hash with their own
    /// algorithm (e.g. SHA-1, which `darwinscope` does not bundle).
    pub fn blob_bytes(&self) -> &'a [u8] {
        self.blob
    }

    /// `codeLimit64` — present only in CDs of version
    /// `≥ 0x20300`. Returns `None` for older CDs.
    pub fn code_limit_64(&self) -> Option<u64> {
        if self.version < cd_version::SUPPORTS_CODE_LIMIT64 {
            return None;
        }
        read_u64_be_at(self.blob, CD_FIELD_CODE_LIMIT_64)
    }

    /// `execSegBase` — VM offset of the first executable segment.
    /// `Some` for CDs of version `≥ 0x20400`, `None` otherwise.
    pub fn exec_seg_base(&self) -> Option<u64> {
        if self.version < cd_version::SUPPORTS_EXEC_SEG {
            return None;
        }
        read_u64_be_at(self.blob, CD_FIELD_EXEC_SEG_BASE)
    }

    /// `execSegLimit` — byte length of the executable segment
    /// region.
    pub fn exec_seg_limit(&self) -> Option<u64> {
        if self.version < cd_version::SUPPORTS_EXEC_SEG {
            return None;
        }
        read_u64_be_at(self.blob, CD_FIELD_EXEC_SEG_LIMIT)
    }

    /// `execSegFlags` — `CS_EXECSEG_*` flag bits.
    pub fn exec_seg_flags(&self) -> Option<u64> {
        if self.version < cd_version::SUPPORTS_EXEC_SEG {
            return None;
        }
        read_u64_be_at(self.blob, CD_FIELD_EXEC_SEG_FLAGS)
    }

    /// Iterator over the special hash slots (`-1, -2, ..., -n`).
    ///
    /// Each yielded entry is `(slot_index, &hash_bytes)`. Slot
    /// indices are negative because they precede slot 0 (the first
    /// code-page hash) in the on-disk layout: slot `-i` is at
    /// `hash_offset - i * hash_size`. The mapping for the first
    /// six special slots:
    ///
    /// | slot | what it hashes        |
    /// |------|------------------------|
    /// | `-1` | Info.plist             |
    /// | `-2` | Requirements blob      |
    /// | `-3` | ResourceDir            |
    /// | `-4` | Application slot       |
    /// | `-5` | XML entitlements blob  |
    /// | `-7` | DER entitlements blob  |
    pub fn special_hashes(&self) -> SpecialHashIter<'a> {
        SpecialHashIter {
            blob: self.blob,
            hash_offset: self.hash_offset,
            hash_size: self.hash_size,
            n_special: self.n_special_slots,
            cursor: 0,
        }
    }

    /// Iterator over the code hash slots (`0, 1, ..., n_code-1`).
    ///
    /// Slot `j` covers bytes `j * page_size .. (j+1) * page_size`
    /// of the image's signed range and is at byte offset
    /// `hash_offset + j * hash_size` within the CD blob.
    pub fn code_hashes(&self) -> CodeHashIter<'a> {
        CodeHashIter {
            blob: self.blob,
            hash_offset: self.hash_offset,
            hash_size: self.hash_size,
            n_code: self.n_code_slots,
            cursor: 0,
        }
    }
}

/// Iterator over special hash slots (negative indices `-1..-n`).
///
/// Yields `(slot_index, &'a [u8])` pairs in `slot_index = -1`,
/// `-2`, `-3`, ... order.
pub struct SpecialHashIter<'a> {
    blob: &'a [u8],
    hash_offset: u32,
    hash_size: u8,
    n_special: u32,
    cursor: u32,
}

impl<'a> Iterator for SpecialHashIter<'a> {
    type Item = (i32, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.n_special {
            return None;
        }
        let i = self.cursor.checked_add(1)?;
        self.cursor = i;
        // slot -i is at hash_offset - i * hash_size
        let off_back = (i as usize).checked_mul(self.hash_size as usize)?;
        let off = (self.hash_offset as usize).checked_sub(off_back)?;
        let end = off.checked_add(self.hash_size as usize)?;
        let bytes = self.blob.get(off..end)?;
        let slot_idx = i32::try_from(i).ok()?.wrapping_neg();
        Some((slot_idx, bytes))
    }
}

/// Iterator over code hash slots (non-negative indices).
pub struct CodeHashIter<'a> {
    blob: &'a [u8],
    hash_offset: u32,
    hash_size: u8,
    n_code: u32,
    cursor: u32,
}

impl<'a> Iterator for CodeHashIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.n_code {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;
        let off_fwd = (i as usize).checked_mul(self.hash_size as usize)?;
        let off = (self.hash_offset as usize).checked_add(off_fwd)?;
        let end = off.checked_add(self.hash_size as usize)?;
        self.blob.get(off..end)
    }
}

impl<'a> Signature<'a> {
    /// Primary CodeDirectory (slot `CodeDirectory = 0`), if
    /// present and parseable.
    pub fn primary_code_directory(&self) -> Option<CodeDirectory<'a>> {
        let bytes = self.find_blob_bytes(Slot::CodeDirectory)?;
        CodeDirectory::parse(bytes)
    }

    /// Iterator over alternate CodeDirectories (slots
    /// `0x1000..=0x1004`). Modern Apple-signed binaries carry
    /// 0–4 alternates plus the primary CD; adhoc binaries carry
    /// only the primary so this iterator is empty.
    pub fn alternate_code_directories(&self) -> CodeDirectoryIter<'a> {
        CodeDirectoryIter {
            sig: *self,
            cursor: 0,
        }
    }

    /// XML entitlements blob (`CSMAGIC_EMBEDDED_ENTITLEMENTS`,
    /// `0xfade7171`), if the SuperBlob has a `CSSLOT_ENTITLEMENTS`
    /// (slot `5`) entry.
    pub fn entitlements(&self) -> Option<Entitlements<'a>> {
        let blob = self.find_blob_bytes(Slot::Entitlements)?;
        Entitlements::parse(blob)
    }

    /// DER-encoded entitlements blob
    /// (`CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`, `0xfade7172`).
    /// `darwinscope` exposes the raw bytes plus a top-level key
    /// list; deeper decode is v0.2.
    pub fn der_entitlements(&self) -> Option<DerEntitlements<'a>> {
        let blob = self.find_blob_bytes(Slot::DerEntitlements)?;
        DerEntitlements::parse(blob)
    }

    /// Embedded CMS signature wrapper (`CSMAGIC_BLOBWRAPPER`,
    /// `0xfade0b01`) at slot `CSSLOT_SIGNATURESLOT`.
    /// Always returned when the slot exists — even adhoc
    /// signatures carry an empty wrapper. Use
    /// [`CmsSignature::is_present`] to distinguish empty
    /// placeholders from real CMS payloads.
    pub fn cms(&self) -> Option<CmsSignature<'a>> {
        let blob = self.find_blob_bytes(Slot::SignatureSlot)?;
        CmsSignature::parse(blob)
    }

    /// Internal-requirements vector (`CSMAGIC_REQUIREMENTS`,
    /// `0xfade0c01`). Surfaced as opaque bytes for v0.1 — the
    /// CSEL / CSCO requirement-expression DSL is a follow-up.
    pub fn requirements(&self) -> Option<Requirements<'a>> {
        let blob = self.find_blob_bytes(Slot::Requirements)?;
        Requirements::parse(blob)
    }
}

/// Iterator over alternate CodeDirectories (slots
/// `0x1000..=0x1004`).
pub struct CodeDirectoryIter<'a> {
    sig: Signature<'a>,
    /// Index into the alternate-CD slot range (0..5).
    cursor: u32,
}

impl<'a> Iterator for CodeDirectoryIter<'a> {
    type Item = CodeDirectory<'a>;
    fn next(&mut self) -> Option<CodeDirectory<'a>> {
        // Cap at 5 (CSSLOT_ALTERNATE_CODEDIRECTORY_MAX).
        while self.cursor < 5 {
            let i = self.cursor;
            self.cursor = self.cursor.checked_add(1)?;
            let target = Slot::AlternateCodeDirectory(i);
            if let Some(blob) = self.sig.find_blob_bytes(target)
                && let Some(cd) = CodeDirectory::parse(blob)
            {
                return Some(cd);
            }
        }
        None
    }
}

/// XML-form entitlements blob (`CSMAGIC_EMBEDDED_ENTITLEMENTS =
/// 0xfade7171`, cite: `cs_blobs.h:97`).
///
/// Carried in slot [`Slot::Entitlements`] of the SuperBlob. The
/// on-disk payload is a Property List in XML form — the same format
/// `codesign --entitlements` extracts and `codesign --sign` ingests.
/// The 8-byte `(magic, length)` header from the enclosing blob is
/// stripped from `payload`.
///
/// [`raw`](Self::raw) returns the verbatim XML bytes for callers
/// that want to hash or pretty-print the original;
/// [`parsed`](Self::parsed) decodes them into a [`plist::Value`] via
/// the `plist` crate. Both views borrow from the binary's data
/// slice — no allocation beyond what `plist` needs.
#[derive(Debug, Clone, Copy)]
pub struct Entitlements<'a> {
    payload: &'a [u8],
}

impl<'a> Entitlements<'a> {
    /// Parse an entitlements blob — returns `None` if the magic
    /// doesn't match or the blob is truncated.
    pub fn parse(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < BLOB_HEADER_SIZE {
            return None;
        }
        let magic = read_u32_be_at(blob, 0)?;
        if magic != CSMAGIC_EMBEDDED_ENTITLEMENTS {
            return None;
        }
        let len = read_u32_be_at(blob, 4)? as usize;
        if len < BLOB_HEADER_SIZE || len > blob.len() {
            return None;
        }
        let payload = blob.get(BLOB_HEADER_SIZE..len)?;
        Some(Self { payload })
    }

    /// Raw XML plist bytes (the blob payload, sans 8-byte header).
    pub fn raw(&self) -> &'a [u8] {
        self.payload
    }

    /// Parsed plist value, or `None` if the XML failed to parse.
    pub fn parsed(&self) -> Option<plist::Value> {
        plist::Value::from_reader(std::io::Cursor::new(self.payload)).ok()
    }
}

/// DER-encoded entitlements blob
/// (`CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172`, cite:
/// `cs_blobs.h:98`).
///
/// Carried in slot [`Slot::DerEntitlements`]. macOS 11 / iOS 14 made
/// this blob mandatory for hardened-runtime and iOS signatures —
/// AMFI parses the DER form, not the XML. An XML entitlements blob
/// without a matching DER blob will be rejected at launch on those
/// OS versions.
///
/// The on-disk encoding is Apple's container DER (Apple ASN.1):
///
/// ```text
/// [APPLICATION 16] CONSTRUCTED {
///     INTEGER version,
///     [0] CONSTRUCTED SET OF SEQUENCE {
///         UTF8String key,
///         value             -- BOOLEAN | INTEGER | UTF8String | …
///     }
/// }
/// ```
///
/// v0.1 surfaces the raw payload and a sorted top-level key list via
/// [`keys`](Self::keys); the value side (which may be Boolean,
/// Integer, String, Array, …) is left for a v0.2 typed decoder.
#[derive(Debug, Clone, Copy)]
pub struct DerEntitlements<'a> {
    payload: &'a [u8],
}

impl<'a> DerEntitlements<'a> {
    /// Parse a DER-entitlements blob — returns `None` on bad
    /// magic or truncation.
    pub fn parse(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < BLOB_HEADER_SIZE {
            return None;
        }
        let magic = read_u32_be_at(blob, 0)?;
        if magic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS {
            return None;
        }
        let len = read_u32_be_at(blob, 4)? as usize;
        if len < BLOB_HEADER_SIZE || len > blob.len() {
            return None;
        }
        let payload = blob.get(BLOB_HEADER_SIZE..len)?;
        Some(Self { payload })
    }

    /// Raw DER bytes (the blob payload, sans 8-byte header).
    pub fn raw(&self) -> &'a [u8] {
        self.payload
    }

    /// Sorted-deduplicated list of top-level entitlement keys.
    ///
    /// Walks the canonical Apple DER container shape; if the
    /// outer wrapper deviates, the walker returns whatever keys
    /// it could extract. Empty when the blob is malformed or
    /// truncated.
    pub fn keys(&self) -> Vec<String> {
        let mut out = der_collect_keys(self.payload);
        out.sort();
        out.dedup();
        out
    }
}

/// Internal-requirements vector blob (`CSMAGIC_REQUIREMENTS =
/// 0xfade0c01`, cite: `cs_blobs.h:93`).
///
/// Carried in slot [`Slot::Requirements`]. Holds the binary's
/// "designated requirement" — the predicate the kernel evaluates to
/// decide whether *this* signing identity is allowed to claim the
/// binary's Team ID / bundle ID. Each entry of the vector is itself
/// a [`CSMAGIC_REQUIREMENT`] blob using
/// the CSEL / CSCO bytecode grammar (`security cdhash` /
/// `csreq -t`).
///
/// On-disk shape: 8-byte `(magic, length)` header, then `count`
/// (BE u32), then `count` `(type, offset)` pairs each pointing at a
/// single nested Requirement blob. The structured CSEL / CSCO
/// grammar decoder is a v0.2 follow-up; v0.1 exposes the raw bytes
/// verbatim plus the entry count.
#[derive(Debug, Clone, Copy)]
pub struct Requirements<'a> {
    blob: &'a [u8],
    count: u32,
}

impl<'a> Requirements<'a> {
    /// Parse a requirements blob — returns `None` on bad magic
    /// or truncation.
    pub fn parse(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < BLOB_HEADER_SIZE {
            return None;
        }
        let magic = read_u32_be_at(blob, 0)?;
        if magic != CSMAGIC_REQUIREMENTS {
            return None;
        }
        let len = read_u32_be_at(blob, 4)? as usize;
        if len < BLOB_HEADER_SIZE || len > blob.len() {
            return None;
        }
        // count follows the 8-byte header, if present.
        let count = if len >= 12 {
            read_u32_be_at(blob, 8).unwrap_or(0)
        } else {
            0
        };
        Some(Self {
            blob: blob.get(..len)?,
            count,
        })
    }

    /// Full blob bytes (header + count + per-requirement index).
    pub fn raw(&self) -> &'a [u8] {
        self.blob
    }

    /// `count` field — number of requirement entries indexed
    /// from this vector. `0` for the empty placeholder that
    /// `codesign -s -` writes by default.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Total blob length (matches the SuperBlob's recorded
    /// length for this slot).
    pub fn len(&self) -> usize {
        self.blob.len()
    }

    /// Whether the blob carries any requirement entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Embedded CMS signature wrapper (`CSMAGIC_BLOBWRAPPER =
/// 0xfade0b01`, cite: `cs_blobs.h:100`).
///
/// Carried in slot [`Slot::SignatureSlot`]. The wrapper is just an
/// 8-byte `(magic, length)` envelope around an opaque CMS / PKCS#7
/// `SignedData` blob (RFC 5652) — the signer-chain certificates,
/// signature timestamp, and the signed CDHash digest live inside.
/// `codesign` calls into Apple's `CMSDecoder` to verify the
/// envelope; `darwinscope` v0.1 reports presence and size only,
/// leaving the signer-chain / x509 decoder for a follow-up.
///
/// **Adhoc** signatures (`codesign -s -`) carry an *empty* wrapper
/// (header only, payload length zero) — the kernel skips CMS
/// verification entirely and only checks the CDHash against the
/// in-memory pages. [`is_present`](Self::is_present) discriminates
/// the two cases.
#[derive(Debug, Clone, Copy)]
pub struct CmsSignature<'a> {
    payload: &'a [u8],
}

impl<'a> CmsSignature<'a> {
    /// Parse a CMS BlobWrapper — returns `None` on bad magic or
    /// truncation.
    pub fn parse(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < BLOB_HEADER_SIZE {
            return None;
        }
        let magic = read_u32_be_at(blob, 0)?;
        if magic != CSMAGIC_BLOBWRAPPER {
            return None;
        }
        let len = read_u32_be_at(blob, 4)? as usize;
        if len < BLOB_HEADER_SIZE || len > blob.len() {
            return None;
        }
        let payload = blob.get(BLOB_HEADER_SIZE..len)?;
        Some(Self { payload })
    }

    /// Raw CMS bytes (the wrapper payload, sans 8-byte header).
    pub fn raw(&self) -> &'a [u8] {
        self.payload
    }

    /// `true` when the wrapper carries a non-empty CMS payload.
    /// `false` for the adhoc placeholder (empty payload).
    pub fn is_present(&self) -> bool {
        !self.payload.is_empty()
    }

    /// Length of the CMS payload in bytes (excluding the 8-byte
    /// wrapper header).
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// `true` when the payload is empty (the adhoc placeholder).
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

// === Internal DER walker ===
//
// Minimal tag/length parser sufficient to extract the top-level
// key list from Apple's canonical entitlements DER shape. Not a
// general-purpose ASN.1 reader — it knows just the few tags used.

fn der_collect_keys(payload: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // The canonical Apple shape:
    //   [APPLICATION 16] CONSTRUCTED { INTEGER, [0] CONSTRUCTED SET-LIKE { ... entries ... } }
    // Some legacy variants drop the outer wrapper. Try both:
    // first, descend through the outer wrapper if present;
    // otherwise treat `payload` itself as the entries SET.
    let entries = der_locate_entries(payload).unwrap_or(payload);
    let mut cursor = 0usize;
    while cursor < entries.len() {
        let Some(remaining) = entries.get(cursor..) else {
            break;
        };
        let Some(hdr) = der_read_header(remaining) else {
            break;
        };
        let body_start = match cursor.checked_add(hdr.header_len) {
            Some(v) => v,
            None => break,
        };
        let body_end = match body_start.checked_add(hdr.length) {
            Some(v) => v,
            None => break,
        };
        if body_end > entries.len() {
            break;
        }
        // Each entry is a SEQUENCE (tag 0x30) whose first child
        // is the UTF8String key.
        if hdr.tag == 0x30
            && let Some(seq_body) = entries.get(body_start..body_end)
            && let Some(key) = der_first_utf8_string(seq_body)
        {
            out.push(key);
        }
        cursor = body_end;
    }
    out
}

/// Descend the outer Apple DER wrapper (if present) and return
/// the bytes of the inner entries SET. Returns `None` if the
/// shape is not recognised; the caller falls back to scanning
/// `payload` directly.
fn der_locate_entries(payload: &[u8]) -> Option<&[u8]> {
    // Outer: any single tag wrapping the body. Common values
    // observed: 0x70 (=APPLICATION 16, primitive class), 0x30
    // (SEQUENCE), 0x31 (SET).
    let outer = der_read_header(payload)?;
    let outer_body_start = outer.header_len;
    let outer_body_end = outer_body_start.checked_add(outer.length)?;
    let outer_body = payload.get(outer_body_start..outer_body_end)?;

    // First TLV inside the outer wrapper: optional INTEGER
    // version. Skip it.
    let mut cursor = 0usize;
    let inner = loop {
        let remaining = outer_body.get(cursor..)?;
        if remaining.is_empty() {
            return None;
        }
        let hdr = der_read_header(remaining)?;
        let body_start = cursor.checked_add(hdr.header_len)?;
        let body_end = body_start.checked_add(hdr.length)?;
        // INTEGER tag = 0x02
        if hdr.tag == 0x02 {
            cursor = body_end;
            continue;
        }
        // The entries container: [0] CONSTRUCTED (0xa0) or
        // SET (0x31) or SEQUENCE (0x30) or [16] (0xb0).
        if matches!(hdr.tag, 0x30 | 0x31 | 0xa0 | 0xb0) {
            break outer_body.get(body_start..body_end)?;
        }
        // Unknown — bail.
        return None;
    };
    Some(inner)
}

fn der_first_utf8_string(seq_body: &[u8]) -> Option<String> {
    let hdr = der_read_header(seq_body)?;
    if hdr.tag != 0x0c {
        return None;
    }
    let body_start = hdr.header_len;
    let body_end = body_start.checked_add(hdr.length)?;
    let body = seq_body.get(body_start..body_end)?;
    // Validate UTF-8 *before* allocating, so a malformed key does
    // not pay for a Vec just to have it dropped.
    core::str::from_utf8(body).ok().map(String::from)
}

/// Copy the prefix of `src` into `dst`, leaving any trailing bytes
/// in `dst` untouched.
///
/// Used by [`CodeDirectory::cd_hash_truncated`] to land a SHA-256 /
/// SHA-384 / SHA-512 digest into a fixed 20-byte AMFI buffer
/// without an intermediate `Vec`. Both halves of the
/// `copy_from_slice` are sub-sliced to the same `n`, so the call
/// can never panic (the lengths are equal by construction).
fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    let n = core::cmp::min(dst.len(), src.len());
    if let (Some(dst_head), Some(src_head)) = (dst.get_mut(..n), src.get(..n)) {
        dst_head.copy_from_slice(src_head);
    }
}

struct DerHeader {
    tag: u8,
    length: usize,
    header_len: usize,
}

fn der_read_header(buf: &[u8]) -> Option<DerHeader> {
    let tag = *buf.first()?;
    let len_byte = *buf.get(1)?;
    if len_byte < 0x80 {
        return Some(DerHeader {
            tag,
            length: len_byte as usize,
            header_len: 2,
        });
    }
    let n = (len_byte & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut length = 0usize;
    for i in 0..n {
        let b = *buf.get(2usize.checked_add(i)?)?;
        length = length.wrapping_shl(8) | (b as usize);
    }
    Some(DerHeader {
        tag,
        length,
        header_len: 2usize.checked_add(n)?,
    })
}

/// Iterator over [`BlobIndex`] entries in a SuperBlob.
pub struct BlobIter<'a> {
    data: &'a [u8],
    base: usize,
    count: u32,
    cursor: u32,
}

impl<'a> Iterator for BlobIter<'a> {
    type Item = BlobIndex;
    fn next(&mut self) -> Option<BlobIndex> {
        if self.cursor >= self.count {
            return None;
        }
        let i = self.cursor;
        self.cursor = self.cursor.checked_add(1)?;
        let entry_off = self
            .base
            .checked_add(SUPERBLOB_HEADER_SIZE)?
            .checked_add((i as usize).checked_mul(BLOB_INDEX_SIZE)?)?;
        let raw = read_u32_be_at(self.data, entry_off)?;
        let off_off = entry_off.checked_add(4)?;
        let offset = read_u32_be_at(self.data, off_off)?;
        Some(BlobIndex {
            slot: Slot::from_raw(raw),
            raw_slot: raw,
            offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_round_trip_known_values() {
        for (raw, want) in [
            (0u32, Slot::CodeDirectory),
            (1, Slot::InfoSlot),
            (2, Slot::Requirements),
            (3, Slot::ResourceDir),
            (4, Slot::Application),
            (5, Slot::Entitlements),
            (7, Slot::DerEntitlements),
            (8, Slot::LaunchConstraintSelf),
            (9, Slot::LaunchConstraintParent),
            (10, Slot::LaunchConstraintResponsible),
            (11, Slot::LibraryConstraint),
            (0x1000, Slot::AlternateCodeDirectory(0)),
            (0x1004, Slot::AlternateCodeDirectory(4)),
            (0x10000, Slot::SignatureSlot),
            (0x10001, Slot::IdentificationSlot),
            (0x10002, Slot::TicketSlot),
        ] {
            assert_eq!(Slot::from_raw(raw), want);
        }
        assert_eq!(Slot::from_raw(99), Slot::Other(99));
        assert_eq!(Slot::from_raw(0x1005), Slot::Other(0x1005));
    }

    #[test]
    fn signature_parse_rejects_wrong_magic() {
        // Header with magic 0x12345678 (not an embedded signature).
        let bytes = [
            0x12, 0x34, 0x56, 0x78, // magic
            0x00, 0x00, 0x00, 0x0c, // length
            0x00, 0x00, 0x00, 0x00, // count
        ];
        assert!(Signature::parse(&bytes, 0).is_none());
    }

    #[test]
    fn signature_parse_accepts_embedded_magic() {
        // Empty SuperBlob: magic + length=12 + count=0.
        let bytes = [
            0xfa, 0xde, 0x0c, 0xc0, // CSMAGIC_EMBEDDED_SIGNATURE
            0x00, 0x00, 0x00, 0x0c, // length
            0x00, 0x00, 0x00, 0x00, // count
        ];
        let sig = Signature::parse(&bytes, 0).unwrap();
        assert_eq!(sig.magic(), CSMAGIC_EMBEDDED_SIGNATURE);
        assert_eq!(sig.length(), 12);
        assert_eq!(sig.blob_count(), 0);
        assert_eq!(sig.blobs().count(), 0);
    }

    #[test]
    fn signature_blob_iter_returns_index_entries() {
        // SuperBlob with one index entry: slot=2 (Requirements),
        // offset=0x1c. The blob payload at 0x1c isn't required for
        // iter() to enumerate — only for blob_bytes_at().
        let mut bytes = vec![
            0xfa, 0xde, 0x0c, 0xc0, // magic
            0x00, 0x00, 0x00, 0x1c, // length = 28
            0x00, 0x00, 0x00, 0x01, // count = 1
            // index[0]:
            0x00, 0x00, 0x00, 0x02, // type=2 (Requirements)
            0x00, 0x00, 0x00, 0x14, // offset=20 (0x14)
        ];
        // pad to length 28
        bytes.extend([0; 8]);
        let sig = Signature::parse(&bytes, 0).unwrap();
        let blobs: Vec<_> = sig.blobs().collect();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].slot, Slot::Requirements);
        assert_eq!(blobs[0].raw_slot, 2);
        assert_eq!(blobs[0].offset, 20);
    }
}
