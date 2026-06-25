// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Portions derived from Firecracker (https://github.com/firecracker-microvm/firecracker),
// licensed under Apache-2.0 OR BSD-3-Clause.

//! BAR (Base Address Register) type definitions and decoding.

/// BAR (Base Address Register) type decoded from a register value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    /// 32-bit memory-mapped BAR.
    Memory32,
    /// 64-bit memory-mapped BAR (consumes two BAR slots).
    Memory64,
    /// I/O port BAR.
    Io,
    /// BAR is not configured (zero value).
    None,
}

/// Decode a BAR type from its register value.
pub fn decode_bar_type(value: u32) -> BarType {
    if value == 0 {
        return BarType::None;
    }
    if value & 0x01 != 0 {
        return BarType::Io;
    }
    match (value >> 1) & 0x03 {
        0b10 => BarType::Memory64,
        _ => BarType::Memory32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_none() {
        assert_eq!(decode_bar_type(0), BarType::None);
    }

    #[test]
    fn io_bar() {
        assert_eq!(decode_bar_type(0x01), BarType::Io);
    }

    #[test]
    fn memory32_bar() {
        assert_eq!(decode_bar_type(0xFFFF_FFF0), BarType::Memory32);
    }

    #[test]
    fn memory64_bar() {
        assert_eq!(decode_bar_type(0xFFFF_FFF4), BarType::Memory64);
    }
}
