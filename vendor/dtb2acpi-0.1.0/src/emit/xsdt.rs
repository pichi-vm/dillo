// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Extended System Description Table.
//!
//! ACPI 6.5 §5.2.8. The XSDT is the table directory: an SDT header
//! followed by a packed array of 64-bit GPAs pointing at every other
//! SDT (FADT, MADT, MCFG, SRAT, SLIT).
//!
//! The RSDP points at the XSDT; the XSDT points at everything else.
//! Entries stream directly from `&Offsets` into the slot — no
//! intermediate array.

use zerocopy::IntoBytes;
use zerocopy::little_endian::U64;

use super::sdt::SdtHeader;
use super::set_sdt_checksum;
use crate::count::Offsets;
use crate::error::DtbError;
use crate::oem::OemIdentity;

/// XSDT revision per ACPI 6.5.
pub(crate) const REVISION: u8 = 1;

/// Size of one XSDT entry (one u64 GPA).
pub(crate) const ENTRY_SIZE: usize = 8;

/// Total XSDT byte cost: SDT header + N entries.
pub(crate) fn total_size(n_entries: usize) -> Result<usize, DtbError> {
    let entries_bytes = n_entries
        .checked_mul(ENTRY_SIZE)
        .ok_or(DtbError::Internal)?;
    SdtHeader::SIZE
        .checked_add(entries_bytes)
        .ok_or(DtbError::Internal)
}

/// Emit a complete, checksummed XSDT into `slot`. Streams entries
/// from `offsets` (FADT, MADT, then any of MCFG/SRAT/SLIT that are
/// present) directly into the slot — no intermediate array.
pub(crate) fn emit(
    slot: &mut [u8],
    oem: &OemIdentity,
    base_gpa: u64,
    offsets: &Offsets,
) -> Result<(), DtbError> {
    let length = super::sdt_length_from_slot(slot)?;
    super::write_header(slot, &SdtHeader::new(*b"XSDT", length, REVISION, oem))?;

    let mut pos = SdtHeader::SIZE;
    for target in offsets.xsdt_targets() {
        pos = append_gpa(slot, pos, target.gpa(base_gpa)?)?;
    }
    let _ = pos;

    set_sdt_checksum(slot)
}

/// Write `gpa` (little-endian u64) into `slot[pos..pos+8]` and return
/// the new position. Caller-supplied `pos` is bounded by `slot.len()`
/// via the layout (XSDT slot is sized for exactly the entries we emit).
#[inline]
fn append_gpa(slot: &mut [u8], pos: usize, gpa: u64) -> Result<usize, DtbError> {
    let end = pos.checked_add(ENTRY_SIZE).ok_or(DtbError::Internal)?;
    let entry = U64::new(gpa);
    if let Some(dst) = slot.get_mut(pos..end) {
        dst.copy_from_slice(entry.as_bytes());
    }
    Ok(end)
}
