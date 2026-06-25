// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Portions derived from Firecracker (https://github.com/firecracker-microvm/firecracker),
// licensed under Apache-2.0 OR BSD-3-Clause.

//! ECAM MMIO address decoding for PCI config space.

/// Parse an ECAM (PCIe enhanced config) byte offset into BDF + register offset.
///
/// Returns `(bus, device, function, register_byte_offset)`.
/// ECAM layout: each function gets 4KB (4096 bytes).
/// Offset bits: [27:20] = bus, [19:15] = device, [14:12] = function, [11:0] = register offset.
pub fn parse_ecam_offset(offset: u64) -> (u8, u8, u8, u16) {
    let bus = ((offset >> 20) & 0xFF) as u8;
    let device = ((offset >> 15) & 0x1F) as u8;
    let function = ((offset >> 12) & 0x07) as u8;
    let register = (offset & 0xFFF) as u16;
    (bus, device, function, register)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ecam_offset_zero() {
        assert_eq!(parse_ecam_offset(0), (0, 0, 0, 0));
    }

    #[test]
    fn ecam_offset_device1() {
        // Device 1: offset = 1 << 15 = 0x8000 = 32768
        assert_eq!(parse_ecam_offset(0x8000), (0, 1, 0, 0));
    }

    #[test]
    fn ecam_offset_with_register() {
        assert_eq!(parse_ecam_offset(4), (0, 0, 0, 4));
    }
}
