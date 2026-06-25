// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Virtio PCI capability helpers.
//!
//! Builds the vendor-specific (0x09) capability structures that virtio PCI
//! devices expose in config space. Each capability identifies a BAR region
//! by cfg_type, bar index, offset, and length.
//!
//! Virtio PCI capability layout (16 bytes minimum):
//! ```text
//! Byte 0: cap_vndr (0x09 = vendor-specific)
//! Byte 1: cap_next (pointer to next cap, filled by add_capability)
//! Byte 2: cap_len  (total bytes: 16 for standard, 20 for notify)
//! Byte 3: cfg_type (1=common, 2=notify, 3=ISR, 4=device, 5=PCI cfg)
//! Byte 4: bar      (BAR index 0-5)
//! Bytes 5-7: padding
//! Bytes 8-11: offset (LE u32, byte offset within BAR)
//! Bytes 12-15: length (LE u32, region size)
//! Bytes 16-19: notify_off_multiplier (only for cfg_type=2, 20-byte cap)
//! ```

use dillo_pci::{CAP_ID_VENDOR, PciConfiguration};

/// Add a standard virtio PCI capability (16 bytes) to the config space.
///
/// Returns the register index (dword index) of the capability start.
pub(crate) fn add_virtio_cap(
    config: &mut PciConfiguration,
    cfg_type: u8,
    bar: u8,
    offset: u32,
    length: u32,
) -> usize {
    let cap_reg = config.add_capability(CAP_ID_VENDOR, 16);

    // Dword 0: cap_vndr(8) | cap_next(8) | cap_len(8) | cfg_type(8)
    // add_capability already set cap_vndr and cap_next. We need to set cap_len and cfg_type.
    let dw0 = config.read_reg(cap_reg);
    config.set_reg(
        cap_reg,
        (dw0 & 0x0000_FFFF) | (16u32 << 16) | ((cfg_type as u32) << 24),
    );

    // Dword 1: bar(8) | padding(24)
    config.set_reg(cap_reg + 1, bar as u32);

    // Dword 2: offset within BAR
    config.set_reg(cap_reg + 2, offset);

    // Dword 3: length
    config.set_reg(cap_reg + 3, length);

    cap_reg
}

/// Add a virtio notify capability (20 bytes) with notify_off_multiplier.
///
/// Returns the register index (dword index) of the capability start.
pub(crate) fn add_virtio_notify_cap(
    config: &mut PciConfiguration,
    bar: u8,
    offset: u32,
    length: u32,
    notify_off_multiplier: u32,
) -> usize {
    let cap_reg = config.add_capability(CAP_ID_VENDOR, 20);

    // Dword 0: cap_vndr(8) | cap_next(8) | cap_len(8) | cfg_type(8)
    let dw0 = config.read_reg(cap_reg);
    config.set_reg(
        cap_reg,
        (dw0 & 0x0000_FFFF) | (20u32 << 16) | (2u32 << 24), // cfg_type=2 (notify)
    );

    // Dword 1: bar(8) | padding(24)
    config.set_reg(cap_reg + 1, bar as u32);

    // Dword 2: offset within BAR
    config.set_reg(cap_reg + 2, offset);

    // Dword 3: length
    config.set_reg(cap_reg + 3, length);

    // Dword 4: notify_off_multiplier
    config.set_reg(cap_reg + 4, notify_off_multiplier);

    cap_reg
}
