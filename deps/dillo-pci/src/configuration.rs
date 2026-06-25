// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Portions derived from Firecracker (https://github.com/firecracker-microvm/firecracker),
// licensed under Apache-2.0 OR BSD-3-Clause.

//! 256-byte PCI Type 0 configuration space with BAR management and capability list.

/// Number of 32-bit registers in PCI configuration space (256 bytes / 4).
const NUM_CONFIGURATION_REGISTERS: usize = 64;

/// Register indices for standard PCI Type 0 header fields.
const VENDOR_DEVICE_REG: usize = 0;
const COMMAND_STATUS_REG: usize = 1;
const CLASS_REG: usize = 2;
const HEADER_TYPE_REG: usize = 3;
const BAR0_REG: usize = 4;
const CAPABILITY_POINTER_REG: usize = 13; // byte offset 0x34, dword index 13

/// First usable byte offset for capabilities (after 64-byte standard header).
const FIRST_CAPABILITY_OFFSET: usize = 64;

/// PCI configuration space (Type 0 header, 256 bytes = 64 dwords).
///
/// Each register has a parallel `writable_bits` mask controlling which bits
/// the guest is allowed to modify via config writes.
#[derive(Debug)]
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS],
    /// Next free byte offset for capability linked-list allocation.
    next_cap_offset: usize,
    /// Byte offset of the last capability added (for forward-linked list).
    last_cap_offset: Option<usize>,
}

impl PciConfiguration {
    /// Create a new zeroed PCI configuration space.
    ///
    /// The Command register (register 1, low 16 bits) is writable by default;
    /// the Status register (high 16 bits) is read-only.
    pub fn new() -> Self {
        let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];
        // Command register: low 16 bits writable, Status: read-only
        writable_bits[COMMAND_STATUS_REG] = 0x0000_FFFF;
        Self {
            registers: [0u32; NUM_CONFIGURATION_REGISTERS],
            writable_bits,
            next_cap_offset: FIRST_CAPABILITY_OFFSET,
            last_cap_offset: None,
        }
    }

    /// Read a configuration register by dword index.
    ///
    /// Returns `0xFFFF_FFFF` for out-of-bounds indices (mimics empty slot).
    pub fn read_reg(&self, reg_idx: usize) -> u32 {
        if reg_idx >= NUM_CONFIGURATION_REGISTERS {
            return 0xFFFF_FFFF;
        }
        self.registers[reg_idx]
    }

    /// Write to a configuration register with byte-level merge and writable-bits masking.
    ///
    /// `offset` is the byte offset within the dword (0-3). `data` contains 1-4 bytes
    /// to write starting at that offset. Only bits marked writable in `writable_bits`
    /// will actually change.
    pub fn write_reg(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if reg_idx >= NUM_CONFIGURATION_REGISTERS {
            return;
        }

        let offset = offset as usize;
        if offset >= 4 {
            return;
        }

        // Build new dword value by placing data bytes at the correct offset
        let old_val = self.registers[reg_idx];
        let mut new_val = old_val;
        for (i, &byte) in data.iter().enumerate() {
            let byte_pos = offset + i;
            if byte_pos >= 4 {
                break;
            }
            let shift = byte_pos * 8;
            // Clear the byte position, then set the new value
            new_val &= !(0xFF << shift);
            new_val |= (byte as u32) << shift;
        }

        // Apply writable-bits mask: only change bits that are marked writable
        let mask = self.writable_bits[reg_idx];
        self.registers[reg_idx] = (new_val & mask) | (old_val & !mask);
    }

    /// Set vendor and device ID (register 0). Marks as read-only.
    pub fn set_vendor_device(&mut self, vendor: u16, device: u16) {
        self.registers[VENDOR_DEVICE_REG] = (device as u32) << 16 | vendor as u32;
        self.writable_bits[VENDOR_DEVICE_REG] = 0; // read-only
    }

    /// Set class code, subclass, prog_if, and revision (register 2). Marks as read-only.
    pub fn set_class(&mut self, class: u8, subclass: u8, prog_if: u8, revision: u8) {
        self.registers[CLASS_REG] = (class as u32) << 24
            | (subclass as u32) << 16
            | (prog_if as u32) << 8
            | revision as u32;
        self.writable_bits[CLASS_REG] = 0; // read-only
    }

    /// Set the header type byte (byte 14 of register 3, i.e., bits 23:16).
    pub fn set_header_type(&mut self, hdr_type: u8) {
        let old = self.registers[HEADER_TYPE_REG];
        self.registers[HEADER_TYPE_REG] = (old & 0xFF00_FFFF) | ((hdr_type as u32) << 16);
    }

    /// Set a BAR value. `bar_idx` is 0-5, corresponding to registers 4-9.
    pub fn set_bar(&mut self, bar_idx: usize, value: u32) {
        if bar_idx < 6 {
            self.registers[BAR0_REG + bar_idx] = value;
        }
    }

    /// Set the writable-bits mask for a BAR. `bar_idx` is 0-5.
    pub fn set_bar_writable_bits(&mut self, bar_idx: usize, mask: u32) {
        if bar_idx < 6 {
            self.writable_bits[BAR0_REG + bar_idx] = mask;
        }
    }

    /// Set a register's raw value, bypassing writable-bits mask.
    ///
    /// Used during device initialization to set capability fields that are
    /// read-only to the guest but must be configured by the VMM.
    pub fn set_reg(&mut self, reg_idx: usize, value: u32) {
        if reg_idx < NUM_CONFIGURATION_REGISTERS {
            self.registers[reg_idx] = value;
        }
    }

    /// Set the writable-bits mask for a register.
    ///
    /// Used to mark capability register fields (like MSI-X msg_ctl enable/mask
    /// bits) as guest-writable.
    pub fn set_reg_writable_bits(&mut self, reg_idx: usize, mask: u32) {
        if reg_idx < NUM_CONFIGURATION_REGISTERS {
            self.writable_bits[reg_idx] = mask;
        }
    }

    /// Add a capability to the capability linked list.
    ///
    /// `cap_id` is the capability ID byte. `cap_size` is the total size in bytes
    /// (must be >= 2 for the ID + next-pointer header, and will be rounded up to
    /// a dword boundary).
    ///
    /// Returns the register index where the capability was placed.
    ///
    /// # Panics
    ///
    /// Panics if there is not enough space in the config space for the capability.
    pub fn add_capability(&mut self, cap_id: u8, cap_size: usize) -> usize {
        assert!(cap_size >= 2, "capability must be at least 2 bytes");

        // Round up to dword boundary
        let cap_size_aligned = (cap_size + 3) & !3;
        let cap_offset = self.next_cap_offset;

        assert!(
            cap_offset + cap_size_aligned <= 256,
            "no space for capability in config space"
        );

        let cap_reg = cap_offset / 4;

        // Set this capability's header: ID in byte 0, next-pointer = 0 (end of list)
        self.registers[cap_reg] = cap_id as u32;

        // Update the previous capability's next pointer to point to this one,
        // or set the capabilities pointer if this is the first capability.
        if let Some(last_offset) = self.last_cap_offset {
            let last_reg = last_offset / 4;
            // Next pointer is byte 1 of the capability's first dword
            self.registers[last_reg] =
                (self.registers[last_reg] & 0xFFFF_00FF) | ((cap_offset as u32 & 0xFF) << 8);
        } else {
            // First capability: set the capabilities pointer (register 13, low byte)
            let cap_ptr_old = self.registers[CAPABILITY_POINTER_REG];
            self.registers[CAPABILITY_POINTER_REG] =
                (cap_ptr_old & 0xFFFF_FF00) | (cap_offset as u32 & 0xFF);
        }

        // Set capabilities list bit in Status register (bit 4 of status = bit 20 of reg 1)
        self.registers[COMMAND_STATUS_REG] |= 1 << 20;

        // Track this as the last capability and advance the next free offset
        self.last_cap_offset = Some(cap_offset);
        self.next_cap_offset = cap_offset + cap_size_aligned;

        cap_reg
    }
}

impl Default for PciConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_zeroed_config_space() {
        let cfg = PciConfiguration::new();
        for i in 0..64 {
            assert_eq!(cfg.read_reg(i), 0, "register {i} should be zero");
        }
    }

    #[test]
    fn read_reg_oob_returns_all_ones() {
        let cfg = PciConfiguration::new();
        assert_eq!(cfg.read_reg(64), 0xFFFF_FFFF);
        assert_eq!(cfg.read_reg(100), 0xFFFF_FFFF);
    }

    #[test]
    fn write_reg_applies_writable_bits_mask() {
        let mut cfg = PciConfiguration::new();
        cfg.write_reg(1, 0, &[0xFF, 0xFF, 0xFF, 0xFF]);
        let val = cfg.read_reg(1);
        assert_eq!(val & 0x0000_FFFF, 0x0000_FFFF);
        assert_eq!(val & 0xFFFF_0000, 0x0000_0000);
    }

    #[test]
    fn set_vendor_device_sets_reg0() {
        let mut cfg = PciConfiguration::new();
        cfg.set_vendor_device(0x8086, 0x1237);
        let val = cfg.read_reg(0);
        assert_eq!(val & 0xFFFF, 0x8086, "vendor ID");
        assert_eq!(val >> 16, 0x1237, "device ID");
    }

    #[test]
    fn vendor_device_is_read_only_after_set() {
        let mut cfg = PciConfiguration::new();
        cfg.set_vendor_device(0x8086, 0x1237);
        cfg.write_reg(0, 0, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            cfg.read_reg(0),
            0x1237_8086,
            "vendor/device should be read-only"
        );
    }

    #[test]
    fn set_class_sets_reg2() {
        let mut cfg = PciConfiguration::new();
        cfg.set_class(0x06, 0x00, 0x00, 0x02);
        let val = cfg.read_reg(2);
        assert_eq!(val & 0xFF, 0x02, "revision");
        assert_eq!((val >> 8) & 0xFF, 0x00, "prog_if");
        assert_eq!((val >> 16) & 0xFF, 0x00, "subclass");
        assert_eq!((val >> 24) & 0xFF, 0x06, "class");
    }

    #[test]
    fn set_header_type_sets_byte14() {
        let mut cfg = PciConfiguration::new();
        cfg.set_header_type(0x00);
        let val = cfg.read_reg(3);
        assert_eq!((val >> 16) & 0xFF, 0x00, "header type byte");
    }

    #[test]
    fn write_reg_byte_level_merge() {
        let mut cfg = PciConfiguration::new();
        cfg.write_reg(1, 0, &[0x07]);
        assert_eq!(cfg.read_reg(1) & 0xFF, 0x07);
        cfg.write_reg(1, 1, &[0x06]);
        assert_eq!(cfg.read_reg(1) & 0xFFFF, 0x0607);
    }

    #[test]
    fn add_capability_creates_linked_list() {
        let mut cfg = PciConfiguration::new();
        cfg.set_header_type(0x00);
        let cap1_reg = cfg.add_capability(0x11, 12);
        let cap2_reg = cfg.add_capability(0x09, 8);

        let cap1_val = cfg.read_reg(cap1_reg);
        assert_eq!(cap1_val & 0xFF, 0x11, "cap1 ID should be MSI-X");

        let cap2_val = cfg.read_reg(cap2_reg);
        assert_eq!(cap2_val & 0xFF, 0x09, "cap2 ID should be Vendor");
        assert_eq!(
            (cap2_val >> 8) & 0xFF,
            0,
            "cap2 next should be 0 (end of list)"
        );

        assert_ne!((cap1_val >> 8) & 0xFF, 0, "cap1 next should point to cap2");
    }
}
