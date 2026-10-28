// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! System Locality Information Table.
//!
//! ACPI 6.5 §5.2.17. Header is SDT header + 8-byte number-of-localities
//! (44 bytes). Body is an N×N row-major distance matrix of bytes.
//!
//! Emission consumes the [`Domains`] table built by [`crate::count::run`]
//! (proximity domains in first-occurrence order: cpus first, then
//! memory-only) so `pd → matrix-index` resolution is an O(1) lookup
//! rather than a per-cell re-walk of `/cpus` and `/memory@…`. Then
//! walks `/distance-map`'s `distance-matrix` property and writes
//! per-cell distance values directly into the matrix region of the
//! slot. Unwritten cells receive the ACPI defaults (10 on the
//! diagonal, 20 off-diagonal).

use devtree::{NodeView, TreeView};
use zerocopy::IntoBytes;
use zerocopy::little_endian::U64;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use super::sdt::SdtHeader;
use super::set_sdt_checksum;
use crate::count::Domains;
use crate::dtb::{DtbNode, cells_as_u32s};
use crate::error::{DtbError, Site};
use crate::oem::OemIdentity;

/// SLIT revision per ACPI 6.5.
pub(crate) const REVISION: u8 = 1;

/// SLIT header — SDT header + number of localities.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct SlitHeader {
    pub header: SdtHeader,
    pub number_of_localities: U64,
}

impl SlitHeader {
    pub(crate) const SIZE: usize = 44;

    /// Total SLIT byte cost: header + N×N distance matrix.
    pub(crate) fn total_size(n_domains: u8) -> Result<usize, DtbError> {
        let n = usize::from(n_domains);
        let matrix_bytes = n.checked_mul(n).ok_or(DtbError::Internal)?;
        Self::SIZE
            .checked_add(matrix_bytes)
            .ok_or(DtbError::Internal)
    }
}

/// Emit a complete, checksummed SLIT into `slot`. Walks the
/// `distance-map`'s `distance-matrix` property; validates symmetry,
/// diagonal == 10, and value range as it goes. `pd → matrix-index`
/// resolution is O(1) via [`Domains`] built at count time.
pub(crate) fn emit<T: TreeView>(
    slot: &mut [u8],
    oem: &OemIdentity,
    tree: &T,
    domains: &Domains,
) -> Result<(), DtbError> {
    let n = usize::from(domains.len());
    let matrix_bytes = n.checked_mul(n).ok_or(DtbError::Internal)?;
    let length = super::sdt_length_from_slot(slot)?;
    let header = SlitHeader {
        header: SdtHeader::new(*b"SLIT", length, REVISION, oem),
        number_of_localities: U64::new(u64::from(domains.len())),
    };
    super::write_header(slot, &header)?;

    // Initialize matrix: diagonals = 10, off-diagonals = 0 (sentinel
    // for "unwritten"; ACPI distances are 10..=255 so 0 cannot collide
    // with an explicit value).
    let matrix_end = SlitHeader::SIZE
        .checked_add(matrix_bytes)
        .ok_or(DtbError::Internal)?;
    if let Some(dst) = slot.get_mut(SlitHeader::SIZE..matrix_end) {
        for v in dst.iter_mut() {
            *v = 0;
        }
        for i in 0..n {
            let idx = i
                .checked_mul(n)
                .and_then(|v| v.checked_add(i))
                .ok_or(DtbError::Internal)?;
            if let Some(cell) = dst.get_mut(idx) {
                *cell = 10;
            }
        }
    }

    let root = DtbNode::root_of(tree.root());
    let map_node = root
        .child("distance-map", Site::DistanceMap)?
        .ok_or(DtbError::Internal)?;
    let prop = map_node
        .node
        .property("distance-matrix")
        .ok_or(DtbError::MissingProperty {
            site: Site::DistanceMap,
            property: "distance-matrix",
        })?;

    let malformed = || DtbError::MalformedProperty {
        site: Site::DistanceMap,
        property: "distance-matrix",
    };
    // Each entry is a (from, to, val) triple = 3 u32 cells = 12 bytes.
    // Trailing sub-cell bytes would otherwise be silently dropped by
    // chunks_exact(4); a present-but-empty matrix would otherwise be
    // silently filled with the off-diagonal default.
    let raw = prop.as_ref();
    if raw.is_empty() || !raw.len().is_multiple_of(12) {
        return Err(malformed());
    }
    let mut cells = cells_as_u32s(raw);
    loop {
        let (from, to, val) = match (cells.next(), cells.next(), cells.next()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            (None, None, None) => break,
            _ => return Err(malformed()),
        };
        let i = domains.index_of(from).ok_or_else(malformed)?;
        let j = domains.index_of(to).ok_or_else(malformed)?;
        let val_u8 = u8::try_from(val).map_err(|_| DtbError::ValueOutOfRange {
            site: Site::DistanceMap,
            property: "distance-matrix",
        })?;
        let i_us = usize::from(i);
        let j_us = usize::from(j);
        if i_us == j_us {
            if val_u8 != 10 {
                return Err(malformed());
            }
            continue;
        }
        // ACPI 6.5 §5.2.17: off-diagonal distances are >= 10 (with
        // 0xFF the documented "unreachable" sentinel; we pass it
        // through). < 10 is invalid AND would collide with the
        // "unwritten" sentinel (0) used during matrix initialization.
        if val_u8 < 10 {
            return Err(malformed());
        }
        let idx_ij = i_us
            .checked_mul(n)
            .and_then(|v| v.checked_add(j_us))
            .ok_or(DtbError::Internal)?;
        let idx_ji = j_us
            .checked_mul(n)
            .and_then(|v| v.checked_add(i_us))
            .ok_or(DtbError::Internal)?;
        let matrix_slice = slot
            .get_mut(SlitHeader::SIZE..matrix_end)
            .unwrap_or(&mut []);
        let existing_ij = matrix_slice.get(idx_ij).copied().unwrap_or(0);
        let existing_ji = matrix_slice.get(idx_ji).copied().unwrap_or(0);
        if (existing_ij != 0 && existing_ij != val_u8)
            || (existing_ji != 0 && existing_ji != val_u8)
        {
            return Err(malformed());
        }
        if let Some(cell) = matrix_slice.get_mut(idx_ij) {
            *cell = val_u8;
        }
        if let Some(cell) = matrix_slice.get_mut(idx_ji) {
            *cell = val_u8;
        }
    }

    // Final fill: any cell still at the sentinel 0 gets the
    // off-diagonal default 20. (Diagonals were initialized to 10.)
    if let Some(matrix_slice) = slot.get_mut(SlitHeader::SIZE..matrix_end) {
        for cell in matrix_slice.iter_mut() {
            if *cell == 0 {
                *cell = 20;
            }
        }
    }

    set_sdt_checksum(slot)
}
