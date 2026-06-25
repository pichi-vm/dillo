// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! x86 syscon power devices declared by the base DTB.
//!
//! These are VM-owned substrate MMIO devices: the guest writes the declared
//! value to the declared register and the run loop observes the resulting
//! structured action.

use crate::{MmioDevice, MmioError, MmioWindow, MmioWriteOutcome};

const WINDOW_SIZE: u64 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysconAction {
    Poweroff,
    Reboot,
}

#[derive(Debug)]
pub struct SysconDevice {
    window: MmioWindow,
    offset: u64,
    value: u32,
    mask: u32,
    action: SysconAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysconRegister {
    pub base: u64,
    pub offset: u64,
    pub value: u32,
    pub mask: u32,
}

impl SysconDevice {
    pub fn new(syscon: SysconRegister, action: SysconAction) -> Self {
        Self {
            window: MmioWindow {
                base: syscon.base,
                size: WINDOW_SIZE,
            },
            offset: syscon.offset,
            value: syscon.value,
            mask: syscon.mask,
            action,
        }
    }

    fn matches(&self, offset: u64, data: &[u8]) -> bool {
        if offset != self.offset {
            return false;
        }
        let value = match data.len() {
            1 => u32::from(data[0]),
            2 => u32::from(u16::from_le_bytes([data[0], data[1]])),
            4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            _ => return false,
        };
        (value & self.mask) == (self.value & self.mask)
    }

    pub fn matches_poweroff(poweroff: SysconRegister, addr: u64, data: &[u8]) -> bool {
        let device = Self::new(poweroff, SysconAction::Poweroff);
        addr.checked_sub(poweroff.base)
            .is_some_and(|offset| device.matches(offset, data))
    }
}

impl MmioDevice for SysconDevice {
    fn windows(&self) -> &[MmioWindow] {
        std::slice::from_ref(&self.window)
    }

    fn read(&self, _window: MmioWindow, _offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
        data.fill(0);
        Ok(())
    }

    fn write(
        &self,
        _window: MmioWindow,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError> {
        if self.matches(offset, data) {
            log::info!("guest issued {:?}", self.action);
            return Ok(match self.action {
                SysconAction::Poweroff => MmioWriteOutcome::GuestPoweroff,
                SysconAction::Reboot => MmioWriteOutcome::GuestReset,
            });
        }
        Ok(MmioWriteOutcome::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syscon() -> SysconRegister {
        SysconRegister {
            base: 0x901_0000,
            offset: 0x10,
            value: 0xCAFE,
            mask: 0xFFFF,
        }
    }

    #[test]
    fn matching_write_records_action() {
        let device = SysconDevice::new(syscon(), SysconAction::Poweroff);
        let window = device.windows()[0];

        let outcome = device
            .write(window, 0x10, &0xCAFEu32.to_le_bytes())
            .expect("syscon write");

        assert_eq!(outcome, MmioWriteOutcome::GuestPoweroff);
    }

    #[test]
    fn non_matching_write_is_claimed_without_action() {
        let device = SysconDevice::new(syscon(), SysconAction::Reboot);
        let window = device.windows()[0];

        let outcome = device
            .write(window, 0x14, &0xCAFEu32.to_le_bytes())
            .expect("syscon write");

        assert_eq!(outcome, MmioWriteOutcome::Continue);
    }
}
