// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Native BSP payloads access a failing device before writing a RAM marker.
// Native wrappers must supervise and join both owners before checking results;
// the second owner remains parked and makes no guest-progress claim.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use dillo_machine::memory::{AddressRange, SharedRegion};
use dillo_mmio::{MmioDevice, MmioError, MmioWriteOutcome};

const WINDOW: AddressRange = AddressRange {
    base: 0x0b00_0000,
    size: 0x1000,
};
const MARKER: u64 = 0x80;
const VALUE: u32 = 0x1234_5678;

#[derive(Clone, Copy, Debug)]
pub(super) enum Fault {
    Read,
    Write,
}

pub(super) struct FailingDevice {
    reads: AtomicUsize,
    writes: AtomicUsize,
    value: AtomicU32,
}

impl MmioDevice for FailingDevice {
    fn windows(&self) -> &[AddressRange] {
        &[WINDOW]
    }

    fn read(&self, _: AddressRange, _: u64, data: &mut [u8]) -> Result<(), MmioError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        // A failed read may already have modified part of the host output.
        // The native owner must not complete that output as guest data.
        if let Some(first) = data.first_mut() {
            *first = 0xa5;
        }
        Err(MmioError::Device(Box::new(std::io::Error::other(
            "distinct mapped read failure",
        ))))
    }

    fn write(&self, _: AddressRange, _: u64, data: &[u8]) -> Result<MmioWriteOutcome, MmioError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if let Ok(bytes) = data.try_into() {
            self.value
                .store(u32::from_le_bytes(bytes), Ordering::SeqCst);
        }
        // This effect precedes the error: supervision cannot undo or replay it.
        Err(MmioError::Device(Box::new(std::io::Error::other(
            "distinct mapped write failure",
        ))))
    }
}

pub(super) struct Fixture {
    ram: SharedRegion,
    device: Arc<FailingDevice>,
    fault: Fault,
}

impl Fixture {
    pub(super) fn new(ram: SharedRegion, base: u64, fault: Fault) -> Self {
        ram.store_u32_le(MARKER, 0).unwrap();

        #[cfg(target_arch = "x86_64")]
        {
            // PMI's fixed BSP entry is flat 32-bit protected mode. Jump from
            // its short reset-vector tail into the same retained RAM mapping.
            let code_address = base.checked_add(0x100).unwrap();
            let displacement = i32::try_from(i128::from(code_address) - 0xffff_fff5i128)
                .expect("reset trampoline is within rel32 reach");
            let mut trampoline = vec![0xe9];
            trampoline.extend_from_slice(&displacement.to_le_bytes());
            ram.write(0xffff_fff0u64.checked_sub(base).unwrap(), &trampoline)
                .unwrap();

            let mut code = match fault {
                Fault::Read => vec![0xa1],        // mov eax, moffs32
                Fault::Write => vec![0xc7, 0x05], // mov dword ptr [disp32], imm32
            };
            code.extend_from_slice(&u32::try_from(WINDOW.base).unwrap().to_le_bytes());
            if matches!(fault, Fault::Write) {
                code.extend_from_slice(&VALUE.to_le_bytes());
            }
            code.extend_from_slice(&[0xc7, 0x05]);
            code.extend_from_slice(&u32::try_from(base + MARKER).unwrap().to_le_bytes());
            code.extend_from_slice(&1u32.to_le_bytes());
            code.extend_from_slice(&[0xeb, 0xfe]); // spin after the forbidden marker
            ram.write(0x100, &code).unwrap();
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(base, 0, "PMI's fixed Arm BSP entry is GPA 0");
            let access = match fault {
                Fault::Read => 0xb940_0001,  // ldr w1, [x0]
                Fault::Write => 0xb900_0001, // str w1, [x0]
            };
            let code: [u32; 8] = [
                0xd2a1_6000, // mov x0, #0x0b000000
                0x528a_cf01, // mov w1, #0x5678
                0x72a2_4681, // movk w1, #0x1234, lsl #16
                access,
                0xd280_1002, // mov x2, #0x80 (RAM marker)
                0x5280_0021, // mov w1, #1
                0xb900_0041, // str w1, [x2]
                0x1400_0000, // spin after the forbidden marker
            ];
            let bytes: Vec<_> = code.into_iter().flat_map(u32::to_le_bytes).collect();
            ram.write(0, &bytes).unwrap();
        }

        Self {
            ram,
            device: Arc::new(FailingDevice {
                reads: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
                value: AtomicU32::new(0),
            }),
            fault,
        }
    }

    pub(super) fn device(&self) -> Arc<FailingDevice> {
        Arc::clone(&self.device)
    }

    pub(super) fn verify(&self, error: &str) {
        let (operation, reads, writes, value) = match self.fault {
            Fault::Read => ("read", 1, 0, 0),
            Fault::Write => ("write", 0, 1, VALUE),
        };
        assert!(
            error.contains(&format!("distinct mapped {operation} failure")),
            "original device cause: {error}"
        );
        assert!(
            error.contains(&format!("MMIO {operation} at 0xb000000 (4 bytes")),
            "routed access context: {error}"
        );
        assert_eq!(self.device.reads.load(Ordering::SeqCst), reads);
        assert_eq!(self.device.writes.load(Ordering::SeqCst), writes);
        assert_eq!(self.device.value.load(Ordering::SeqCst), value);
        assert_eq!(
            self.ram.load_u32_le(MARKER).unwrap(),
            0,
            "guest must not execute the instruction after the failed access"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_machine::memory::{MappedSharedMemory, SharedAccess, SharedMemory, SharedRange};
    use dillo_mmio::MmioBus;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn fixture(fault: Fault) -> Fixture {
        #[cfg(target_arch = "x86_64")]
        let base = 0xffff_f000;
        #[cfg(target_arch = "aarch64")]
        let base = 0;
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(base), 0x1000)]).unwrap();
        let shared = MappedSharedMemory::for_guest_memory(memory, SharedAccess::ReadWrite);
        let ram = shared
            .region(SharedRange {
                gpa: base,
                size: 0x1000,
                access: SharedAccess::ReadWrite,
            })
            .unwrap();
        Fixture::new(ram, base, fault)
    }

    #[test]
    fn fixture_read_exposes_partial_output_and_original_failure() {
        let fixture = fixture(Fault::Read);
        let mut bus = MmioBus::new();
        bus.register_device(fixture.device());
        let mut output = [0xcc; 4];
        let error = bus.read(WINDOW.base, &mut output).unwrap_err();
        assert_eq!(output, [0xa5, 0xcc, 0xcc, 0xcc]);
        assert_eq!(error.window, WINDOW);
        fixture.verify(&error.to_string());
    }

    #[test]
    fn fixture_write_records_effect_before_original_failure() {
        let fixture = fixture(Fault::Write);
        let mut bus = MmioBus::new();
        bus.register_device(fixture.device());
        let error = bus.write(WINDOW.base, &VALUE.to_le_bytes()).unwrap_err();
        assert_eq!(error.window, WINDOW);
        fixture.verify(&error.to_string());
    }
}
