// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! x86 syscon power devices declared by the base DTB.
//!
//! These are VM-owned substrate MMIO devices: the guest writes the declared
//! value to the declared register and the run loop observes the resulting
//! structured action.

use crate::{MmioDevice, MmioError, MmioWindow, MmioWriteOutcome};

/// Invalid syscon register declaration.
#[derive(Debug, thiserror::Error)]
pub enum SysconError {
    #[error("syscon extent overflows the guest address space")]
    AddressOverflow,

    #[error("syscon extent does not contain the 32-bit trigger register")]
    RegisterOutOfBounds,
}

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
    pub size: u64,
    pub offset: u64,
    pub value: u32,
    pub mask: u32,
}

impl SysconDevice {
    pub fn new(syscon: SysconRegister, action: SysconAction) -> Result<Self, SysconError> {
        syscon
            .base
            .checked_add(syscon.size)
            .ok_or(SysconError::AddressOverflow)?;
        if syscon
            .offset
            .checked_add(4)
            .is_none_or(|end| end > syscon.size)
        {
            return Err(SysconError::RegisterOutOfBounds);
        }
        Ok(Self {
            window: MmioWindow {
                base: syscon.base,
                size: syscon.size,
            },
            offset: syscon.offset,
            value: syscon.value,
            mask: syscon.mask,
            action,
        })
    }

    fn contains_access(&self, offset: u64, len: usize) -> bool {
        u64::try_from(len)
            .ok()
            .and_then(|len| offset.checked_add(len))
            .is_some_and(|end| end <= self.window.size)
    }

    fn matches(&self, offset: u64, data: &[u8]) -> bool {
        if offset != self.offset || !self.contains_access(offset, data.len()) {
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
        let Ok(device) = Self::new(poweroff, SysconAction::Poweroff) else {
            return false;
        };
        addr.checked_sub(poweroff.base)
            .is_some_and(|offset| device.matches(offset, data))
    }
}

impl MmioDevice for SysconDevice {
    fn windows(&self) -> &[MmioWindow] {
        std::slice::from_ref(&self.window)
    }

    fn read(&self, window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
        if window != self.window || !self.contains_access(offset, data.len()) {
            return Err(MmioError::Unsupported);
        }
        data.fill(0);
        Ok(())
    }

    fn write(
        &self,
        window: MmioWindow,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError> {
        if window != self.window || !self.contains_access(offset, data.len()) {
            return Err(MmioError::Unsupported);
        }
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
            size: 0x20,
            offset: 0x10,
            value: 0xCAFE,
            mask: 0xFFFF,
        }
    }

    #[test]
    fn matching_write_records_action() {
        let device = SysconDevice::new(syscon(), SysconAction::Poweroff).expect("valid syscon");
        let window = device.windows()[0];

        let outcome = device
            .write(window, 0x10, &0xCAFEu32.to_le_bytes())
            .expect("syscon write");

        assert_eq!(outcome, MmioWriteOutcome::GuestPoweroff);
    }

    #[test]
    fn non_matching_write_is_claimed_without_action() {
        let device = SysconDevice::new(syscon(), SysconAction::Reboot).expect("valid syscon");
        let window = device.windows()[0];

        let outcome = device
            .write(window, 0x14, &0xCAFEu32.to_le_bytes())
            .expect("syscon write");

        assert_eq!(outcome, MmioWriteOutcome::Continue);
    }

    #[test]
    fn declared_extents_bound_direct_accesses() {
        for size in [4, 0x24, 0x2000] {
            let register = SysconRegister {
                size,
                offset: size - 4,
                ..syscon()
            };
            for (action, outcome) in [
                (SysconAction::Poweroff, MmioWriteOutcome::GuestPoweroff),
                (SysconAction::Reboot, MmioWriteOutcome::GuestReset),
            ] {
                let device = SysconDevice::new(register, action).expect("valid syscon");
                let window = MmioWindow {
                    base: register.base,
                    size,
                };
                assert_eq!(device.windows(), &[window]);
                assert_eq!(
                    device
                        .write(window, register.offset, &register.value.to_le_bytes())
                        .unwrap(),
                    outcome
                );
                let mut data = [0xff; 4];
                device.read(window, size - 4, &mut data).unwrap();
                assert_eq!(data, [0; 4]);
                for (offset, len) in [(size - 1, 2), (size, 1), (u64::MAX, 4)] {
                    let mut data = vec![0xff; len];
                    assert!(device.read(window, offset, &mut data).is_err());
                    assert_eq!(data, vec![0xff; len]);
                    assert!(device.write(window, offset, &data).is_err());
                }
            }
        }
    }

    #[test]
    fn invalid_extents_and_offsets_are_refused() {
        for (size, offset) in [(0, 0), (1, 0), (3, 0), (4, 1), (4, 4), (4, u64::MAX)] {
            let register = SysconRegister {
                size,
                offset,
                ..syscon()
            };
            assert!(matches!(
                SysconDevice::new(register, SysconAction::Poweroff),
                Err(SysconError::RegisterOutOfBounds)
            ));
            assert!(!SysconDevice::matches_poweroff(
                register,
                register.base,
                &[0xfe, 0xca]
            ));
        }
        let register = SysconRegister {
            base: u64::MAX - 3,
            size: 4,
            offset: 0,
            ..syscon()
        };
        assert!(matches!(
            SysconDevice::new(register, SysconAction::Poweroff),
            Err(SysconError::AddressOverflow)
        ));
    }

    #[test]
    fn poweroff_match_checks_address_and_access_bounds() {
        let register = SysconRegister {
            size: 4,
            offset: 0,
            ..syscon()
        };
        for data in [&[0xfe][..], &[0xfe, 0xca][..], &[0xfe, 0xca, 0, 0][..]] {
            let expected = data.len() >= 2;
            assert_eq!(
                SysconDevice::matches_poweroff(register, register.base, data),
                expected
            );
        }
        for addr in [register.base - 1, register.base + 4, u64::MAX] {
            assert!(!SysconDevice::matches_poweroff(
                register,
                addr,
                &[0xfe, 0xca]
            ));
        }
        assert!(!SysconDevice::matches_poweroff(
            register,
            register.base,
            &[0xfe, 0xca, 0, 0, 0]
        ));
    }
}
