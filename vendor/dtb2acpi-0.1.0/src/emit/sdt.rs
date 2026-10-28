// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ACPI System Description Table common header + Generic Address.
//!
//! Per ACPI 6.5 §5.2.6: every ACPI table except the RSDP begins with
//! a 36-byte SDT header. The `length` field covers the header AND
//! the body; the `checksum` slot is patched after the body is written.
//!
//! Per ACPI 6.5 §5.2.3.2: the Generic Address Structure (GAS) is a
//! 12-byte uniform descriptor used by FADT to describe MMIO/IO
//! registers (sleep, reset, PM blocks).

use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::oem::OemIdentity;

/// ACPI System Description Table common header. 36 bytes.
///
/// Per ACPI 6.5 §5.2.6.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct SdtHeader {
    /// Four-character table signature (e.g. `b"FACP"`).
    pub signature: [u8; 4],
    /// Total length in bytes, including this header.
    pub length: U32,
    /// Revision of the specific table being described.
    pub revision: u8,
    /// Patched after assembly so the whole table sums to zero mod 256.
    pub checksum: u8,
    /// OEM identifier.
    pub oem_id: [u8; 6],
    /// OEM-assigned table identifier.
    pub oem_table_id: [u8; 8],
    /// OEM revision.
    pub oem_revision: U32,
    /// Creator identifier.
    pub creator_id: [u8; 4],
    /// Creator revision.
    pub creator_revision: U32,
}

impl SdtHeader {
    /// Size of the header in bytes.
    pub(crate) const SIZE: usize = 36;

    /// DSDT revision; ≥ 2 means 64-bit integer compliance. Per ACPI 6.5
    /// §5.2.11.2.
    const DSDT_REVISION: u8 = 2;

    /// Construct a header stamped with `oem`'s identity and a zero
    /// checksum slot (patched later by [`super::set_sdt_checksum`]).
    pub(crate) fn new(signature: [u8; 4], length: u32, revision: u8, oem: &OemIdentity) -> Self {
        Self {
            signature,
            length: U32::new(length),
            revision,
            checksum: 0,
            oem_id: oem.oem_id,
            oem_table_id: oem.oem_table_id,
            oem_revision: U32::new(oem.oem_revision),
            creator_id: oem.creator_id,
            creator_revision: U32::new(oem.creator_revision),
        }
    }

    /// Write a DSDT (signature `b"DSDT"`, revision 2) into `slot`. The
    /// body carries:
    ///
    /// 1. `\_S5_` (13 bytes) — so Linux installs `acpi_power_off` as
    ///    `pm_power_off`. Without it `reboot(RB_POWER_OFF)` returns to
    ///    userspace instead of writing to `SLEEP_CONTROL_REG`. The
    ///    SLP_TYP value is derived from the syscon-poweroff `value`
    ///    byte (per ACPI 6.5 §4.8.3.7 Linux writes
    ///    `(SLP_TYP << ACPI_X_SLEEP_TYPE_POSITION) |
    ///    ACPI_X_SLEEP_ENABLE`, so `SLP_TYP = (sleep_value >> 2) & 0x7`
    ///    makes the byte the guest emits equal the byte the syscon
    ///    matches).
    /// 2. One `Device(MBR<n>)` `PNP0C02` block per
    ///    `pci-host-ecam-generic` root child — so Linux's late MCFG
    ///    validation sees each ECAM window as an ACPI motherboard
    ///    resource.
    /// 3. One `Device(PCI<n>)` block per `pci-host-ecam-generic` root
    ///    child — so `acpi_pci_root_add` registers each PCI root bus.
    ///    Without these, MCFG alone is not enough: Linux scans the
    ///    namespace for PNP0A03/PNP0A08 devices to know which bridges
    ///    exist, and falls through to legacy CF8/CFC port-IO when none
    ///    are present.
    /// 4. One `Device(SER0)` block when the DTB declares a `ns16550a`
    ///    serial node — so Linux creates a normal 8250 `ttyS*` device
    ///    for the MMIO UART instead of only parsing SPCR metadata.
    ///
    /// `slot.len()` MUST equal [`Self::SIZE`] + [`S5_AML_LEN`] +
    /// `pci_host::dsdt_total_bytes(tree)` — the same arithmetic
    /// [`crate::count::Offsets::new`] uses to size the slot.
    pub(crate) fn write_dsdt_into<T: devtree::TreeView>(
        slot: &mut [u8],
        oem: &OemIdentity,
        sleep_value: u8,
        tree: &T,
    ) -> Result<(), crate::error::DtbError> {
        let length = u32::try_from(slot.len()).unwrap_or(u32::MAX);
        super::write_header(slot, &Self::new(*b"DSDT", length, Self::DSDT_REVISION, oem))?;
        let body_start = Self::SIZE;
        let s5_end = body_start
            .checked_add(S5_AML_LEN)
            .ok_or(crate::error::DtbError::Internal)?;
        slot.get_mut(body_start..s5_end)
            .ok_or(crate::error::DtbError::Internal)?
            .copy_from_slice(&s5_aml(sleep_value));
        let after_motherboard = super::motherboard_resource::emit(slot, s5_end, tree)?;
        let after_pci = super::pci_host::emit(slot, after_motherboard, tree)?;
        let after_serial = super::serial_device::emit(slot, after_pci, tree)?;
        let end = super::virtio_mmio::emit(slot, after_serial, tree)?;
        if end != slot.len() {
            // Layout-accounting mismatch — count and emit disagreed.
            // Surface as Internal so the test suite catches it.
            return Err(crate::error::DtbError::Internal);
        }
        super::set_sdt_checksum(slot)
    }
}

/// Byte length of the `\_S5_` AML object emitted into the DSDT body.
///
/// Layout (13 bytes, ACPI 6.5 §20.2.5 — DefName + DefPackage):
///
/// | Off | Bytes              | Meaning                                  |
/// |-----|--------------------|------------------------------------------|
/// | 0   | `08`               | NameOp                                   |
/// | 1   | `5C`               | RootChar (`\`)                           |
/// | 2..6| `5F 53 35 5F`      | NameSeg `_S5_`                           |
/// | 6   | `12`               | PackageOp                                |
/// | 7   | `06`               | PkgLength = 6 (covers PkgLength..end)    |
/// | 8   | `03`               | NumElements = 3                          |
/// | 9..11| `0A xx`           | BytePrefix + SLP_TYP                     |
/// | 11  | `00`               | ZeroOp (SLP_TYPb — unused)               |
/// | 12  | `00`               | ZeroOp (Reserved)                        |
pub(crate) const S5_AML_LEN: usize = 13;

/// Build the 13-byte `\_S5_` AML blob for a given SLP_TYP-encoded byte.
#[inline]
const fn s5_aml(sleep_value: u8) -> [u8; S5_AML_LEN] {
    let slp_typ = (sleep_value >> 2) & 0x7;
    [
        0x08, 0x5C, 0x5F, 0x53, 0x35, 0x5F, 0x12, 0x06, 0x03, 0x0A, slp_typ, 0x00, 0x00,
    ]
}

/// ACPI Generic Address Structure (GAS). 12 bytes.
///
/// Per ACPI 6.5 §5.2.3.2. Used by FADT to describe register locations
/// (sleep control/status, reset, PM blocks). An all-zero GAS denotes
/// "not implemented".
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct GenericAddress {
    /// 0 = System Memory, 1 = System I/O, 2 = PCI Config, 0x7F = FFH.
    pub address_space_id: u8,
    /// Register width in bits.
    pub register_bit_width: u8,
    /// Register bit offset from `address`.
    pub register_bit_offset: u8,
    /// 0 = undefined / 1 = byte / 2 = word / 3 = dword / 4 = qword.
    pub access_size: u8,
    /// Register address.
    pub address: U64,
}

/// All-zero GAS — the "not implemented" form. Used by FADT for the
/// many PM/timer/GPE blocks dtb2acpi does not emit.
pub(crate) const GAS_ZERO: GenericAddress = GenericAddress {
    address_space_id: 0,
    register_bit_width: 0,
    register_bit_offset: 0,
    access_size: 0,
    address: U64::new(0),
};

/// `address_space_id` for System Memory per ACPI 6.5 §5.2.3.2 Table 5.1.
pub(crate) const SYSTEM_MEMORY: u8 = 0x00;

impl GenericAddress {
    /// A single 8-bit byte register in system memory at `address` —
    /// the shape of FADT's `sleep_control_reg`, `sleep_status_reg`,
    /// and `reset_reg` for a HW-Reduced ACPI guest.
    pub(crate) const fn system_memory_byte(address: u64) -> Self {
        Self {
            address_space_id: SYSTEM_MEMORY,
            register_bit_width: 8,
            register_bit_offset: 0,
            access_size: 1,
            address: U64::new(address),
        }
    }
}
