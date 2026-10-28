// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use dillo_mmio::{Interrupt, InterruptError, MmioDevice, MmioWindow};
use dillo_pci::{
    MessageInterrupt, MessageInterruptDomain, MmioAttachment, MmioDeviceHandle, MmioDeviceRun,
    MmioInterrupt, MmioInterruptRequirement, MmioSpawnError, PciRoot, SharedMemory,
};
use dillo_pci_virtio::{VirtioPciAdapter, VirtioPciDevice};
use dillo_virtio::{
    ActivateError, VIRTIO_F_VERSION_1, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
};

#[derive(Default)]
struct RecordingDomain {
    lookups: Mutex<Vec<u16>>,
    signals: Arc<Mutex<Vec<u16>>>,
}

impl MessageInterruptDomain for RecordingDomain {
    fn update(&self, _vector: u16, _message: MessageInterrupt) -> Result<(), InterruptError> {
        Ok(())
    }

    fn enabled(&self, _enabled: bool) -> Result<(), InterruptError> {
        Ok(())
    }

    fn interrupt(&self, vector: u16) -> Option<Interrupt> {
        self.lookups.lock().unwrap().push(vector);
        if vector >= 4 {
            return None;
        }
        let signals = Arc::clone(&self.signals);
        Some(Interrupt::from_fn(move || {
            signals.lock().unwrap().push(vector);
        }))
    }
}

#[derive(Debug)]
struct Attachment(Vec<MmioInterrupt>);

impl MmioAttachment for Attachment {
    fn interrupts(&self) -> &[MmioInterrupt] {
        &self.0
    }

    fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
        &[]
    }

    fn spawn(self: Arc<Self>, _run: MmioDeviceRun) -> Result<MmioDeviceHandle, MmioSpawnError> {
        Ok(MmioDeviceHandle::noop())
    }
}

struct SignalingDevice {
    activations: Arc<Mutex<Vec<bool>>>,
}

impl VirtioDevice for SignalingDevice {
    fn device_type(&self) -> u32 {
        3
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[256]
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn activate(
        &mut self,
        activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let interrupt = activation.queue_interrupt(0);
        self.activations.lock().unwrap().push(interrupt.is_some());
        if let Some(interrupt) = interrupt {
            interrupt.signal();
        }
        Ok(VirtioDeviceHandle::noop())
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {}

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
}

#[test]
fn queue_vectors_stay_within_each_function_on_activation() {
    const QUEUE_MSIX_VECTOR: u64 = 0x1a;

    // Two adjacent two-vector functions: A local 2 used to signal B global 2.
    for locals in [
        [0u16, 0],
        [1, 1],
        [2, 0],
        [3, 1],
        [0, 2],
        [1, 3],
        [u16::MAX - 1, 1],
        [1, u16::MAX - 1],
        [u16::MAX, 0],
        [0, u16::MAX],
    ] {
        let domain = Arc::new(RecordingDomain::default());
        let activations = Arc::new(Mutex::new(Vec::new()));
        let mut root = PciRoot::with_interrupt_requirement(
            MmioWindow {
                base: 0x3000_0000,
                size: 0x1000_0000,
            },
            MmioInterruptRequirement::MessageDomain {
                source: None,
                vectors: 0,
            },
        );
        for slot in 1..=2 {
            let device: Box<dyn VirtioDevice> = Box::new(SignalingDevice {
                activations: Arc::clone(&activations),
            });
            let bar0 = 0xd000_0000 + u64::from(slot) * 0x2000;
            root.register(
                slot,
                Box::new(VirtioPciAdapter::new(VirtioPciDevice::new(
                    Arc::new(Mutex::new(device)),
                    2,
                    bar0,
                    bar0 + 0x1000,
                ))),
            );
        }
        assert!(matches!(
            root.interrupts(),
            [MmioInterruptRequirement::MessageDomain { vectors: 4, .. }]
        ));
        root.set_attachment(Arc::new(Attachment(vec![MmioInterrupt::MessageDomain(
            domain.clone(),
        )])));

        let mut expected = Vec::new();
        for (slot, local) in (1..=2).zip(locals) {
            // Negotiate VERSION_1 and enable queue 0 through the actual BAR path.
            root.bar_write(slot, 0, 0x08, &1u32.to_le_bytes()).unwrap();
            root.bar_write(slot, 0, 0x0c, &1u32.to_le_bytes()).unwrap();
            root.bar_write(slot, 0, QUEUE_MSIX_VECTOR, &local.to_le_bytes())
                .unwrap();
            root.bar_write(slot, 0, 0x1c, &1u16.to_le_bytes()).unwrap();
            root.bar_write(slot, 0, 0x14, &[1 | 2 | 8 | 4]).unwrap();
            let mut readback = [0; 2];
            root.bar_read(slot, 0, QUEUE_MSIX_VECTOR, &mut readback)
                .unwrap();
            assert_eq!(
                u16::from_le_bytes(readback),
                if local < 2 { local } else { u16::MAX }
            );
            if local < 2 {
                expected.push(u16::from(slot - 1) * 2 + local);
            }
        }

        assert_eq!(*activations.lock().unwrap(), locals.map(|local| local < 2));
        assert_eq!(
            *domain.lookups.lock().unwrap(),
            expected,
            "locals {locals:?}"
        );
        assert_eq!(
            *domain.signals.lock().unwrap(),
            expected,
            "locals {locals:?}"
        );
    }
}
