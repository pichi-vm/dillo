// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! FDT v17 header parse + validation.

use crate::cursor;
use crate::error::MalformedKind;

pub(crate) const FDT_MAGIC: u32 = 0xd00d_feed;
pub(crate) const FDT_SUPPORTED_VERSION: u32 = 17;
pub(crate) const FDT_HEADER_SIZE: usize = 40;

/// Parsed FDT v17 header. Every offset/size has been validated against
/// `blob.len()` and the canonical block ordering at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) totalsize: u32,
    pub(crate) off_dt_struct: u32,
    pub(crate) off_dt_strings: u32,
    pub(crate) off_mem_rsvmap: u32,
    pub(crate) size_dt_strings: u32,
    pub(crate) size_dt_struct: u32,
}

impl Header {
    pub(crate) fn parse(blob: &[u8]) -> Result<Self, MalformedKind> {
        if blob.len() < FDT_HEADER_SIZE {
            return Err(MalformedKind::Truncated);
        }
        // The header is 40 bytes of densely packed BE u32s — every read
        // is guaranteed in-bounds by the length check above.
        let read = |off: usize| cursor::read_u32(blob, off).ok_or(MalformedKind::Truncated);
        let magic = read(0)?;
        if magic != FDT_MAGIC {
            return Err(MalformedKind::BadMagic);
        }
        let totalsize = read(4)?;
        let off_dt_struct = read(8)?;
        let off_dt_strings = read(12)?;
        let off_mem_rsvmap = read(16)?;
        let version = read(20)?;
        let last_comp_version = read(24)?;
        let size_dt_strings = read(32)?;
        let size_dt_struct = read(36)?;

        if version != FDT_SUPPORTED_VERSION || last_comp_version > FDT_SUPPORTED_VERSION {
            return Err(MalformedKind::UnsupportedVersion);
        }

        let total = totalsize as usize;
        if total > blob.len() || total < FDT_HEADER_SIZE {
            return Err(MalformedKind::Truncated);
        }

        let memrsv = off_mem_rsvmap as usize;
        if !memrsv.is_multiple_of(8) {
            return Err(MalformedKind::BadAlignment);
        }
        let memrsv_min_end = memrsv.checked_add(16).ok_or(MalformedKind::Truncated)?;
        if memrsv < FDT_HEADER_SIZE || memrsv_min_end > total {
            return Err(MalformedKind::Truncated);
        }

        let struct_off = off_dt_struct as usize;
        let struct_size = size_dt_struct as usize;
        if !struct_off.is_multiple_of(4) || !struct_size.is_multiple_of(4) {
            return Err(MalformedKind::BadAlignment);
        }
        let struct_end = struct_off
            .checked_add(struct_size)
            .ok_or(MalformedKind::Truncated)?;
        if struct_off < FDT_HEADER_SIZE || struct_end > total {
            return Err(MalformedKind::Truncated);
        }

        let strings_off = off_dt_strings as usize;
        let strings_size = size_dt_strings as usize;
        let strings_end = strings_off
            .checked_add(strings_size)
            .ok_or(MalformedKind::Truncated)?;
        if strings_off < FDT_HEADER_SIZE || strings_end > total {
            return Err(MalformedKind::Truncated);
        }

        // Canonical ordering: header | memrsv | struct | strings.
        // dtc and libfdt both emit this layout; requiring it eliminates
        // parser-divergence attacks where a blob places overlapping
        // blocks so different consumers read different bytes.
        if struct_off < memrsv_min_end {
            return Err(MalformedKind::Truncated);
        }
        if strings_off < struct_end {
            return Err(MalformedKind::Truncated);
        }

        Ok(Header {
            totalsize,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            size_dt_strings,
            size_dt_struct,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Build a minimal valid header. struct/strings blocks are zero-length.
    /// Layout: header (40) | memrsv terminator (16) | struct (0) | strings (0).
    fn minimal_blob() -> [u8; 56] {
        let mut blob = [0u8; 56];
        blob[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        blob[4..8].copy_from_slice(&56u32.to_be_bytes());
        blob[8..12].copy_from_slice(&56u32.to_be_bytes());
        blob[12..16].copy_from_slice(&56u32.to_be_bytes());
        blob[16..20].copy_from_slice(&40u32.to_be_bytes());
        blob[20..24].copy_from_slice(&17u32.to_be_bytes());
        blob[24..28].copy_from_slice(&16u32.to_be_bytes());
        blob
    }

    #[test]
    fn parses_minimal_header() {
        let blob = minimal_blob();
        let h = Header::parse(&blob).unwrap();
        assert_eq!(h.totalsize, 56);
        assert_eq!(h.off_dt_struct, 56);
        assert_eq!(h.off_mem_rsvmap, 40);
        assert_eq!(h.size_dt_struct, 0);
    }

    #[test]
    fn rejects_too_short() {
        assert_eq!(Header::parse(&[0u8; 10]), Err(MalformedKind::Truncated));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = minimal_blob();
        blob[0] = 0;
        assert_eq!(Header::parse(&blob), Err(MalformedKind::BadMagic));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut blob = minimal_blob();
        blob[20..24].copy_from_slice(&16u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::UnsupportedVersion));
    }

    #[test]
    fn rejects_last_comp_version_above_17() {
        let mut blob = minimal_blob();
        blob[24..28].copy_from_slice(&18u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::UnsupportedVersion));
    }

    #[test]
    fn rejects_totalsize_past_blob() {
        let mut blob = minimal_blob();
        blob[4..8].copy_from_slice(&100u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::Truncated));
    }

    #[test]
    fn rejects_struct_out_of_bounds() {
        let mut blob = minimal_blob();
        blob[8..12].copy_from_slice(&60u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::Truncated));
    }

    #[test]
    fn rejects_struct_misaligned() {
        let mut blob = minimal_blob();
        blob[8..12].copy_from_slice(&41u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::BadAlignment));
    }

    #[test]
    fn rejects_memrsv_misaligned() {
        let mut blob = minimal_blob();
        blob[16..20].copy_from_slice(&41u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::BadAlignment));
    }

    #[test]
    fn rejects_strings_out_of_bounds() {
        let mut blob = minimal_blob();
        blob[12..16].copy_from_slice(&50u32.to_be_bytes());
        blob[32..36].copy_from_slice(&100u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::Truncated));
    }

    #[test]
    fn rejects_struct_overlapping_memrsv() {
        let mut blob = [0u8; 72];
        blob[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        blob[4..8].copy_from_slice(&72u32.to_be_bytes());
        blob[8..12].copy_from_slice(&48u32.to_be_bytes());
        blob[12..16].copy_from_slice(&72u32.to_be_bytes());
        blob[16..20].copy_from_slice(&40u32.to_be_bytes());
        blob[20..24].copy_from_slice(&17u32.to_be_bytes());
        blob[24..28].copy_from_slice(&16u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::Truncated));
    }

    #[test]
    fn rejects_strings_overlapping_struct() {
        let mut blob = [0u8; 80];
        blob[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        blob[4..8].copy_from_slice(&80u32.to_be_bytes());
        blob[8..12].copy_from_slice(&56u32.to_be_bytes());
        blob[12..16].copy_from_slice(&60u32.to_be_bytes());
        blob[16..20].copy_from_slice(&40u32.to_be_bytes());
        blob[20..24].copy_from_slice(&17u32.to_be_bytes());
        blob[24..28].copy_from_slice(&16u32.to_be_bytes());
        blob[32..36].copy_from_slice(&0u32.to_be_bytes());
        blob[36..40].copy_from_slice(&8u32.to_be_bytes());
        assert_eq!(Header::parse(&blob), Err(MalformedKind::Truncated));
    }
}
