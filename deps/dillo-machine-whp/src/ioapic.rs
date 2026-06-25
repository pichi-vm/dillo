// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use dillo_mmio::{MmioDevice, MmioError, MmioWindow, MmioWriteOutcome};

/// Minimal x86 IOAPIC register model used by the WHP backend.
///
/// WHP does not provide an in-kernel IOAPIC for this machine model, so the
/// backend exposes the DTB-declared IOAPIC register window and uses the
/// programmed redirection table when injecting wired interrupts.
#[derive(Debug)]
pub(crate) struct IoApic {
    window: MmioWindow,
    select: Mutex<u32>,
    redirection: Mutex<[u64; 24]>,
}

impl IoApic {
    pub(crate) fn new(window: MmioWindow) -> Self {
        Self {
            window,
            select: Mutex::new(0),
            redirection: Mutex::new([1 << 16; 24]),
        }
    }

    pub(crate) fn route(&self, gsi: u32) -> Option<IoApicRoute> {
        let idx = usize::try_from(gsi).ok()?;
        let redirection = self.redirection.lock().expect("ioapic redir poisoned");
        let entry = *redirection.get(idx)?;
        decode_route(entry)
    }

    fn read_register(&self, offset: u64, data: &mut [u8]) -> bool {
        let value = match offset {
            0x00..=0x03 => *self.select.lock().expect("ioapic select poisoned"),
            0x10..=0x13 => self.read_selected(),
            _ => 0,
        };
        let bytes = value.to_le_bytes();
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = *bytes.get(i).unwrap_or(&0);
        }
        true
    }

    fn write_register(&self, offset: u64, data: &[u8]) -> bool {
        let value = match data.len() {
            1 => u32::from(data[0]),
            2 => u32::from(u16::from_le_bytes([data[0], data[1]])),
            4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            _ => return true,
        };
        match offset {
            0x00..=0x03 => {
                *self.select.lock().expect("ioapic select poisoned") = value;
            }
            0x10..=0x13 => self.write_selected(value),
            _ => {}
        }
        true
    }

    fn read_selected(&self) -> u32 {
        let select = *self.select.lock().expect("ioapic select poisoned");
        // Registers 0x00 (ID) and 0x02 (arbitration) are kept as explicit arms
        // to document the IOAPIC register map, even though both read back 0 like
        // the default arm.
        #[allow(clippy::match_same_arms)]
        match select {
            0x00 => 0,
            0x01 => (23 << 16) | 0x11,
            0x02 => 0,
            reg @ 0x10..=0x3f => {
                let idx = ((reg - 0x10) / 2) as usize;
                let high = (reg - 0x10) % 2 == 1;
                let redirection = self.redirection.lock().expect("ioapic redir poisoned");
                let Some(entry) = redirection.get(idx) else {
                    return 0;
                };
                if high {
                    (*entry >> 32) as u32
                } else {
                    *entry as u32
                }
            }
            _ => 0,
        }
    }

    fn write_selected(&self, value: u32) {
        let select = *self.select.lock().expect("ioapic select poisoned");
        if !(0x10..=0x3f).contains(&select) {
            return;
        }
        let idx = ((select - 0x10) / 2) as usize;
        let high = (select - 0x10) % 2 == 1;
        let mut redirection = self.redirection.lock().expect("ioapic redir poisoned");
        let Some(entry) = redirection.get_mut(idx) else {
            return;
        };
        if high {
            *entry = (*entry & 0x0000_0000_FFFF_FFFF) | (u64::from(value) << 32);
        } else {
            *entry = (*entry & 0xFFFF_FFFF_0000_0000) | u64::from(value);
        }
    }
}

impl MmioDevice for IoApic {
    fn windows(&self) -> &[MmioWindow] {
        std::slice::from_ref(&self.window)
    }

    fn read(&self, _window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
        self.read_register(offset, data)
            .then_some(())
            .ok_or(MmioError::Unsupported)
    }

    fn write(
        &self,
        _window: MmioWindow,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError> {
        self.write_register(offset, data)
            .then_some(MmioWriteOutcome::Continue)
            .ok_or(MmioError::Unsupported)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoApicRoute {
    pub(crate) destination: u32,
    pub(crate) vector: u8,
}

fn decode_route(entry: u64) -> Option<IoApicRoute> {
    const VECTOR_MASK: u64 = 0xFF;
    const DELIVERY_MODE_MASK: u64 = 0x700;
    const DELIVERY_MODE_SHIFT: u64 = 8;
    const DESTINATION_MODE_LOGICAL: u64 = 1 << 11;
    const MASKED: u64 = 1 << 16;
    const DESTINATION_SHIFT: u64 = 56;
    const DESTINATION_MASK: u64 = 0xFF;

    if entry & MASKED != 0 {
        return None;
    }
    // Fixed (0) and Lowest-Priority (1) both deliver a fixed vector; Linux uses
    // lowest-priority with a logical destination for its IOAPIC-routed IRQs.
    let delivery = (entry & DELIVERY_MODE_MASK) >> DELIVERY_MODE_SHIFT;
    if delivery != 0 && delivery != 1 {
        log::warn!("x86 IOAPIC route uses unsupported delivery mode {delivery} entry={entry:#x}");
        return None;
    }

    let dest_field = ((entry >> DESTINATION_SHIFT) & DESTINATION_MASK) as u32;
    let destination = if entry & DESTINATION_MODE_LOGICAL != 0 {
        resolve_logical_destination(dest_field)
    } else {
        dest_field
    };

    Some(IoApicRoute {
        destination,
        vector: (entry & VECTOR_MASK) as u8,
    })
}

/// Resolve a logical-flat APIC destination bitmask to a physical APIC ID.
///
/// Linux uses logical-flat mode for <= 8 CPUs: CPU `i` carries logical bit `i`.
/// WHP injects a fixed interrupt to a single physical APIC, so deliver to the
/// lowest CPU in the set (a valid resolution of both fixed and lowest-priority
/// delivery). An empty mask falls back to the boot CPU.
pub(crate) fn resolve_logical_destination(mask: u32) -> u32 {
    if mask == 0 { 0 } else { mask.trailing_zeros() }
}

#[cfg(test)]
mod tests {
    use super::{IoApic, IoApicRoute, decode_route};
    use dillo_mmio::{MmioDevice, MmioWindow};

    fn ioapic() -> IoApic {
        IoApic::new(MmioWindow {
            base: 0xFEC0_0000,
            size: 0x1000,
        })
    }

    #[test]
    fn reports_24_redirection_entries() {
        let ioapic = ioapic();
        let window = ioapic.windows()[0];
        ioapic
            .write(window, 0, &1u32.to_le_bytes())
            .expect("IOAPIC select version register");
        let mut data = [0; 4];
        ioapic.read(window, 0x10, &mut data).expect("IOAPIC read");
        assert_eq!(u32::from_le_bytes(data), (23 << 16) | 0x11);
    }

    #[test]
    fn stores_redirection_entry_halves() {
        let ioapic = ioapic();
        let window = ioapic.windows()[0];
        ioapic
            .write(window, 0, &0x10u32.to_le_bytes())
            .expect("IOAPIC select redirection low register");
        ioapic
            .write(window, 0x10, &0x31u32.to_le_bytes())
            .expect("IOAPIC write redirection low register");
        ioapic
            .write(window, 0, &0x11u32.to_le_bytes())
            .expect("IOAPIC select redirection high register");
        ioapic
            .write(window, 0x10, &0x0200_0000u32.to_le_bytes())
            .expect("IOAPIC write redirection high register");

        let mut data = [0; 4];
        ioapic
            .write(window, 0, &0x10u32.to_le_bytes())
            .expect("IOAPIC select redirection low register");
        ioapic.read(window, 0x10, &mut data).expect("IOAPIC read");
        assert_eq!(u32::from_le_bytes(data), 0x31);
        ioapic
            .write(window, 0, &0x11u32.to_le_bytes())
            .expect("IOAPIC select redirection high register");
        ioapic.read(window, 0x10, &mut data).expect("IOAPIC read");
        assert_eq!(u32::from_le_bytes(data), 0x0200_0000);
    }

    #[test]
    fn decodes_unmasked_fixed_physical_route() {
        assert_eq!(
            decode_route((2u64 << 56) | 0x31),
            Some(IoApicRoute {
                destination: 2,
                vector: 0x31
            })
        );
    }

    #[test]
    fn masked_route_does_not_inject() {
        assert_eq!(decode_route((2u64 << 56) | (1 << 16) | 0x31), None);
    }
}
