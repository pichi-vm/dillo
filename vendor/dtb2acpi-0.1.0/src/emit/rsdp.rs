// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Root System Description Pointer (ACPI 2.0+ extended, 36 bytes).
//!
//! ACPI 6.5 §5.2.5.3. The RSDP is the OS's entry point into the ACPI
//! tables — finding the RSDP yields the XSDT GPA, from which every
//! other table is reachable via the XSDT directory.
//!
//! Two checksums:
//! - "Short" checksum covers the first 20 bytes (ACPI 1.0 compat).
//! - "Extended" checksum covers the full 36 bytes.
//!
//! Both must be patched after the fields are set.

use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::checksum;
use crate::error::DtbError;
use crate::oem::OemIdentity;

/// Root System Description Pointer, ACPI 2.0+ extended form.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Rsdp {
    /// `b"RSD PTR "` (trailing space). 8 bytes.
    pub signature: [u8; 8],
    /// Patched so the first 20 bytes sum to zero mod 256.
    pub checksum: u8,
    /// OEM identifier.
    pub oem_id: [u8; 6],
    /// `2` for the extended form.
    pub revision: u8,
    /// 32-bit RSDT pointer; `0` for the extended form (XSDT used instead).
    pub rsdt_address: U32,
    /// Total bytes: `36`.
    pub length: U32,
    /// GPA of the XSDT.
    pub xsdt_address: U64,
    /// Patched so all 36 bytes sum to zero mod 256.
    pub extended_checksum: u8,
    /// Reserved; zero.
    pub reserved: [u8; 3],
}

impl Rsdp {
    /// Total bytes.
    pub(crate) const SIZE: usize = 36;
}

/// Emit a complete, checksummed RSDP into `slot` pointing at `xsdt_gpa`.
///
/// Precondition: `slot.len() == Rsdp::SIZE`. The orchestrator carves
/// slots from a pre-validated layout; `write_header` surfaces
/// `DtbError::Internal` if that precondition is ever violated.
pub(crate) fn emit(slot: &mut [u8], xsdt_gpa: u64, oem: &OemIdentity) -> Result<(), DtbError> {
    let length = u32::try_from(Rsdp::SIZE).unwrap_or(u32::MAX);
    let mut r = Rsdp {
        signature: *b"RSD PTR ",
        checksum: 0,
        oem_id: oem.oem_id,
        revision: 2,
        rsdt_address: U32::new(0),
        length: U32::new(length),
        xsdt_address: U64::new(xsdt_gpa),
        extended_checksum: 0,
        reserved: [0; 3],
    };
    // ACPI 1.0 checksum covers the first 20 bytes only.
    let bytes_for_short = r.as_bytes().get(..20).unwrap_or(&[]);
    r.checksum = checksum(bytes_for_short);
    // Extended checksum covers all 36 bytes (after short checksum is set).
    r.extended_checksum = checksum(r.as_bytes());

    super::write_header(slot, &r)
}
