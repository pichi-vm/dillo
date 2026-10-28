// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! DSDT `Device(SER0)` emitter for the MMIO ns16550a UART.
//!
//! SPCR tells the OS where firmware console redirection points, but it
//! does not create a normal enumerable serial device on Linux. This
//! DSDT device gives the ACPI serial driver an MMIO window and GSI so
//! the 8250 stack can bind a `ttyS*` port without any legacy ISA I/O.

use devtree::{NodeView, TreeView};

use super::aml;
use crate::dtb::DtbNode;
use crate::emit::spcr;
use crate::error::DtbError;

/// Fixed body bytes per Device(SER0) before `_CRS` / `_DSD`:
/// `_HID` (string-valued name) + `_UID` (Byte-valued name).
const FIXED_NAMES_BYTES: usize = (1 + 4 + aml::string_bytes(8)) + (1 + 4 + 1 + 1);

/// QWordMemory(serial MMIO) + ExtendedInterrupt(GSI) + EndTag.
const CRS_DESCRIPTOR_BYTES: usize =
    aml::QWORD_MEMORY_BYTES + aml::EXTENDED_INTERRUPT_BYTES + aml::END_TAG_BYTES;

const DSD_UUID_BYTES: usize = aml::byte_buffer_bytes(16);
const CLOCK_FREQUENCY_PROP_BYTES: usize =
    property_package_bytes(aml::string_bytes("clock-frequency".len()));
const REG_SHIFT_PROP_BYTES: usize = property_package_bytes(aml::string_bytes("reg-shift".len()));
const REG_IO_WIDTH_PROP_BYTES: usize =
    property_package_bytes(aml::string_bytes("reg-io-width".len()));
const DSD_PROPERTIES_BYTES: usize =
    package_bytes(CLOCK_FREQUENCY_PROP_BYTES + REG_SHIFT_PROP_BYTES + REG_IO_WIDTH_PROP_BYTES);
const DSD_PACKAGE_BYTES: usize = package_bytes(DSD_UUID_BYTES + DSD_PROPERTIES_BYTES);
const DSD_BYTES: usize = 1 + 4 + DSD_PACKAGE_BYTES;

/// Total bytes occupied by the serial ACPI device when present.
pub(crate) const DEVICE_BYTES: usize = {
    let crs = aml::CRS_WRAPPER_BYTES + CRS_DESCRIPTOR_BYTES;
    let body = FIXED_NAMES_BYTES + crs + DSD_BYTES;
    // DeviceOp(2) + PkgLength(2) + NameSeg(4) + body
    2 + aml::PKG_LENGTH_BYTES + 4 + body
};

const fn package_bytes(elements_bytes: usize) -> usize {
    elements_bytes
        .saturating_add(aml::PKG_LENGTH_BYTES)
        .saturating_add(2)
}

const fn property_package_bytes(name_bytes: usize) -> usize {
    package_bytes(name_bytes.saturating_add(5)) // DWordPrefix + u32
}

/// Return the DSDT byte cost for the serial device.
pub(crate) fn dsdt_total_bytes<T: TreeView>(tree: &T) -> Result<usize, DtbError> {
    Ok(if spcr::find_serial(tree)?.is_some() {
        DEVICE_BYTES
    } else {
        0
    })
}

/// Emit `Device(SER0)` if the DTB declares an ns16550a serial node.
/// Returns the new write position.
pub(crate) fn emit<T: TreeView>(slot: &mut [u8], pos: usize, tree: &T) -> Result<usize, DtbError> {
    let Some(node) = spcr::find_serial(tree)? else {
        return Ok(pos);
    };
    write_device(slot, pos, &node)
}

fn write_device<N: NodeView + Copy>(
    slot: &mut [u8],
    pos: usize,
    node: &DtbNode<N>,
) -> Result<usize, DtbError> {
    let (base, _access_size, gsi) = spcr::decode_serial(node)?;
    let size = node
        .reg(crate::error::Site::Serial)?
        .next()
        .ok_or(DtbError::Internal)?
        .1;
    let reg_shift = node.property_u32("reg-shift", crate::error::Site::Serial)?;
    let reg_io_width = node.property_u32("reg-io-width", crate::error::Site::Serial)?;
    let clock_frequency = node.property_u32("clock-frequency", crate::error::Site::Serial)?;

    let pos = aml::write_device_header(slot, pos, b"SER0", DEVICE_BYTES)?;

    // RSCV0003 is the generic ACPI 16550A UART ID matched by Linux's
    // serial8250 ACPI platform driver. It is MMIO because _CRS below exposes
    // a QWordMemory resource, not an I/O-port resource.
    let pos = aml::write_name_string(slot, pos, b"_HID", b"RSCV0003")?;
    let pos = aml::write_name_byte(slot, pos, b"_UID", 0)?;

    let pos = aml::write_crs_buffer_header(slot, pos, CRS_DESCRIPTOR_BYTES)?;

    let (_pin, sense) = node.decode_interrupts_2(crate::error::Site::Serial)?;

    let pos = aml::write_qword_memory(slot, pos, base, size)?;
    let pos = aml::write_extended_interrupt(slot, pos, gsi, sense)?;
    let pos = aml::write_end_tag(slot, pos)?;

    write_dsd(slot, pos, clock_frequency, reg_shift, reg_io_width)
}

fn write_dsd(
    slot: &mut [u8],
    pos: usize,
    clock_frequency: u32,
    reg_shift: u32,
    reg_io_width: u32,
) -> Result<usize, DtbError> {
    // Device Properties UUID: daffd814-6eba-4d8c-8a91-bc9bbf4aa301.
    const DEVICE_PROPERTIES_UUID: [u8; 16] = [
        0x14, 0xd8, 0xff, 0xda, 0xba, 0x6e, 0x8c, 0x4d, 0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3,
        0x01,
    ];

    let pos = aml::write_bytes(slot, pos, &[aml::NAME_OP])?;
    let pos = aml::write_name_seg(slot, pos, b"_DSD")?;
    let pos = aml::write_bytes(slot, pos, &[aml::PACKAGE_OP])?;
    let pos = aml::write_pkg_length(
        slot,
        pos,
        aml::PKG_LENGTH_BYTES + 1 + DSD_UUID_BYTES + DSD_PROPERTIES_BYTES,
    )?;
    let pos = aml::write_bytes(slot, pos, &[2])?;
    let pos = aml::write_byte_buffer(slot, pos, &DEVICE_PROPERTIES_UUID)?;

    let pos = aml::write_bytes(slot, pos, &[aml::PACKAGE_OP])?;
    let pos = aml::write_pkg_length(
        slot,
        pos,
        aml::PKG_LENGTH_BYTES
            + 1
            + CLOCK_FREQUENCY_PROP_BYTES
            + REG_SHIFT_PROP_BYTES
            + REG_IO_WIDTH_PROP_BYTES,
    )?;
    let pos = aml::write_bytes(slot, pos, &[3])?;

    let pos = write_dword_property(slot, pos, b"clock-frequency", clock_frequency)?;
    let pos = write_dword_property(slot, pos, b"reg-shift", reg_shift)?;
    write_dword_property(slot, pos, b"reg-io-width", reg_io_width)
}

fn write_dword_property(
    slot: &mut [u8],
    pos: usize,
    name: &[u8],
    value: u32,
) -> Result<usize, DtbError> {
    let elements_bytes = aml::string_bytes(name.len())
        .checked_add(5)
        .ok_or(DtbError::Internal)?;
    let pos = aml::write_bytes(slot, pos, &[aml::PACKAGE_OP])?;
    let pkg = aml::PKG_LENGTH_BYTES
        .checked_add(1)
        .and_then(|v| v.checked_add(elements_bytes))
        .ok_or(DtbError::Internal)?;
    let pos = aml::write_pkg_length(slot, pos, pkg)?;
    let pos = aml::write_bytes(slot, pos, &[2])?;
    let pos = aml::write_string(slot, pos, name)?;
    let pos = aml::write_bytes(slot, pos, &[aml::DWORD_PREFIX])?;
    aml::write_bytes(slot, pos, &value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_device_size_pinned() {
        assert_eq!(DEVICE_BYTES, 201);
    }
}
