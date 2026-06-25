// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Portions derived from Firecracker (https://github.com/firecracker-microvm/firecracker),
// licensed under Apache-2.0 OR BSD-3-Clause.

//! PCI Bus/Device/Function (BDF) address encoding and display.

use std::fmt;

/// PCI Bus-Device-Function address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PciBdf {
    /// PCI bus number (0-255).
    pub bus: u8,
    /// Device number on the bus (0-31).
    pub device: u8,
    /// Function number within the device (0-7).
    pub function: u8,
}

impl PciBdf {
    /// Create a new BDF address from bus, device, and function numbers.
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// Device number as a usize, for array indexing.
    pub fn slot_index(&self) -> usize {
        self.device as usize
    }
}

impl fmt::Display for PciBdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_and_fields() {
        let bdf = PciBdf::new(0, 1, 2);
        assert_eq!(bdf.bus, 0);
        assert_eq!(bdf.device, 1);
        assert_eq!(bdf.function, 2);
    }

    #[test]
    fn display_format() {
        let bdf = PciBdf::new(0, 0, 0);
        assert_eq!(format!("{bdf}"), "00:00.0");

        let bdf2 = PciBdf::new(0xFF, 0x1F, 7);
        assert_eq!(format!("{bdf2}"), "ff:1f.7");
    }

    #[test]
    fn slot_index() {
        let bdf = PciBdf::new(0, 5, 0);
        assert_eq!(bdf.slot_index(), 5);
    }
}
