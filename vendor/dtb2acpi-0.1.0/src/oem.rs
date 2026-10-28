// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Caller-supplied OEM identity stamped into every emitted table.
//!
//! ACPI lets the platform firmware author pick vendor-identifying
//! strings that appear in every SDT header plus the RSDP. They show up
//! in guest-OS diagnostics (e.g. Linux `dmesg | grep ACPI`).
//!
//! Every call to [`crate::AcpiBuffer::populate`] requires an explicit
//! [`OemIdentity`] — this crate ships no defaults, because a generic
//! library can't sensibly pick a vendor string on the caller's behalf.

/// OEM identity stamped into every emitted ACPI table.
///
/// All fields are fixed-width byte arrays per the SDT header layout
/// (ACPI 6.5 §5.2.6 Table 5.32); the array types make over-long inputs
/// a compile error. Strings shorter than the field width should be
/// zero-padded to the right.
///
/// Not `#[non_exhaustive]`: the ACPI SDT header is a closed layout, so
/// no new identity fields will appear. Callers may construct via
/// struct literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OemIdentity {
    /// 6-byte OEM identifier. Stamped into every SDT header and into
    /// the RSDP. Convention: an all-caps vendor abbreviation,
    /// zero-padded to 6 bytes.
    pub oem_id: [u8; 6],
    /// 8-byte OEM table identifier. Stamped into every SDT header
    /// (not the RSDP).
    pub oem_table_id: [u8; 8],
    /// OEM-specific revision of the OEM table content.
    pub oem_revision: u32,
    /// 4-byte identifier of the utility that created the table.
    pub creator_id: [u8; 4],
    /// Revision of the creator utility.
    pub creator_revision: u32,
}
