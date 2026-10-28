// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-table ACPI byte emitters.
//!
//! Each table type has its own module with a small zerocopy struct
//! for its header (plus any entry types) and an `emit` function that
//! takes an exact-sized destination slice plus the parameters it
//! needs, and writes bytes into the slice.
//!
//! Orchestration lives in [`crate::acpi_buffer::AcpiBuffer::populate`]
//! — the emit modules know nothing about each other or about the
//! overall layout. They each receive their slot pre-sized by
//! [`crate::count::run`].

pub(crate) mod aml;
pub(crate) mod fadt;
pub(crate) mod madt;
pub(crate) mod mcfg;
pub(crate) mod motherboard_resource;
pub(crate) mod pci_host;
pub(crate) mod rsdp;
pub(crate) mod sdt;
pub(crate) mod serial_device;
pub(crate) mod slit;
pub(crate) mod spcr;
pub(crate) mod srat;
pub(crate) mod virtio_mmio;
pub(crate) mod xsdt;

/// Define a `#[repr(transparent)]` flag-set newtype over a zerocopy
/// little-endian primitive (`U32` or `U16`). Generates named bit
/// constants, `empty()`, `BitOr` / `BitOrAssign`, and the zerocopy
/// derives needed for storage inside a `#[repr(C)]` table.
///
/// Each flag space is its own type, so the compiler rejects mixing
/// bits from unrelated tables (e.g. ORing a MADT processor flag into
/// a SRAT memory affinity field).
macro_rules! flag_type {
    (
        $(#[$type_attr:meta])*
        $type_vis:vis struct $name:ident: $repr:ty as $prim:ty {
            $(
                $(#[$const_attr:meta])*
                const $const_name:ident = $value:expr;
            )*
        }
    ) => {
        $(#[$type_attr])*
        #[repr(transparent)]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Default,
            zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout,
            zerocopy::Immutable, zerocopy::Unaligned,
        )]
        $type_vis struct $name($repr);

        impl $name {
            $(
                #[allow(dead_code)]
                $(#[$const_attr])*
                $type_vis const $const_name: Self = Self(<$repr>::new($value));
            )*

            /// All bits cleared.
            #[allow(dead_code)]
            #[inline]
            $type_vis const fn empty() -> Self {
                Self(<$repr>::new(0))
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            #[inline]
            fn bitor(self, rhs: Self) -> Self {
                Self(<$repr>::new(self.0.get() | rhs.0.get()))
            }
        }

        impl core::ops::BitOrAssign for $name {
            #[inline]
            fn bitor_assign(&mut self, rhs: Self) {
                *self = *self | rhs;
            }
        }
    };
}
pub(crate) use flag_type;

/// Compute the SDT `length` field for a table whose body fills `slot`.
/// Errors via [`crate::error::DtbError::Internal`] only if `slot.len()`
/// exceeds `u32::MAX` — unreachable on any practical target.
#[inline]
pub(super) fn sdt_length_from_slot(slot: &[u8]) -> Result<u32, crate::error::DtbError> {
    u32::try_from(slot.len()).map_err(|_| crate::error::DtbError::Internal)
}

/// Compute the ACPI 8-bit checksum byte that, when placed in the
/// structure, makes the sum of all bytes (including the checksum)
/// equal zero mod 256. ACPI 6.5 §5.2.6.
#[inline]
pub(super) fn checksum(bytes: &[u8]) -> u8 {
    let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    0u8.wrapping_sub(sum)
}

/// Patch an SDT's checksum field (byte 9, per ACPI 6.5 §5.2.6) so
/// the whole table sums to zero mod 256. Zeros the slot first.
///
/// Returns `DtbError::Internal` if the slot is shorter than the SDT
/// header — unreachable on a count-validated slot; surfacing the
/// error turns a silent partial-write into a layout-accounting bug
/// report.
#[inline]
pub(super) fn set_sdt_checksum(slot: &mut [u8]) -> Result<(), crate::error::DtbError> {
    *slot.get_mut(9).ok_or(crate::error::DtbError::Internal)? = 0;
    let c = checksum(slot);
    *slot.get_mut(9).ok_or(crate::error::DtbError::Internal)? = c;
    Ok(())
}

/// Copy a header's bytes into `slot[..size_of::<H>()]`. Returns
/// `DtbError::Internal` if the slot is shorter than the header —
/// unreachable on a count-validated slot.
#[inline]
pub(super) fn write_header<H: zerocopy::IntoBytes + zerocopy::Immutable>(
    slot: &mut [u8],
    h: &H,
) -> Result<(), crate::error::DtbError> {
    let bytes = h.as_bytes();
    let dst = slot
        .get_mut(..bytes.len())
        .ok_or(crate::error::DtbError::Internal)?;
    dst.copy_from_slice(bytes);
    Ok(())
}

/// Copy `bytes` into `slot[pos..pos + bytes.len()]` and return the
/// new position. Used by per-table emitters to append variable-length
/// entry sequences after a fixed header. Returns `DtbError::Internal`
/// on bounds failure — unreachable on a count-validated slot.
#[inline]
pub(super) fn write_entry(
    slot: &mut [u8],
    pos: usize,
    bytes: &[u8],
) -> Result<usize, crate::error::DtbError> {
    let end = pos
        .checked_add(bytes.len())
        .ok_or(crate::error::DtbError::Internal)?;
    let dst = slot
        .get_mut(pos..end)
        .ok_or(crate::error::DtbError::Internal)?;
    dst.copy_from_slice(bytes);
    Ok(end)
}
