// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use dillo_mmio::{Interrupt, InterruptError};

// Model the delivery checks used by HVF/WHP, including handles obtained before
// later enable/mask changes. KVM currently only logs enable notifications.
#[derive(Default)]
struct TestDomain {
    vectors: Arc<Mutex<Vec<(MessageInterrupt, bool)>>>,
    delivered: Arc<Mutex<Vec<u32>>>,
}

impl MessageInterruptDomain for TestDomain {
    fn update(&self, vector: u16, message: MessageInterrupt) -> Result<(), InterruptError> {
        self.vectors.lock().unwrap()[usize::from(vector)].0 = message;
        Ok(())
    }

    fn enabled(&self, vector: u16, enabled: bool) -> Result<(), InterruptError> {
        self.vectors.lock().unwrap()[usize::from(vector)].1 = enabled;
        Ok(())
    }

    fn interrupt(&self, vector: u16) -> Option<Interrupt> {
        let vectors = Arc::clone(&self.vectors);
        let delivered = Arc::clone(&self.delivered);
        Some(Interrupt::from_fn(move || {
            let (message, enabled) = vectors.lock().unwrap()[usize::from(vector)];
            if enabled && !message.masked {
                delivered.lock().unwrap().push(message.data);
            }
        }))
    }
}

struct TestFunction {
    table: Mutex<MsixTable>,
    notifier: Mutex<Option<Arc<dyn MsixNotifier>>>,
}

impl std::fmt::Debug for TestFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestFunction").finish_non_exhaustive()
    }
}

impl PciDevice for TestFunction {
    fn config_read(&self, _reg_idx: usize) -> u32 {
        0
    }

    fn config_write(&self, _reg_idx: usize, _offset: u64, data: &[u8]) -> Result<(), PciError> {
        let notifier = self.notifier.lock().unwrap();
        self.table.lock().unwrap().write_msg_ctl(
            u16::from_le_bytes(data.try_into().unwrap()),
            notifier.as_ref().unwrap().as_ref(),
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "msix-test"
    }

    fn msix_vectors(&self) -> u16 {
        self.table.lock().unwrap().num_vectors()
    }

    fn set_host(&self, host: Arc<dyn PciDeviceHost>) {
        *self.notifier.lock().unwrap() = host.msix_notifier();
    }

    fn bar_write(&self, bar_idx: u8, offset: u64, data: &[u8]) -> Result<(), PciError> {
        let notifier = self.notifier.lock().unwrap();
        assert!(self.table.lock().unwrap().bar_write(
            bar_idx,
            offset,
            data,
            notifier.as_ref().unwrap().as_ref(),
        ));
        Ok(())
    }
}

#[derive(Debug)]
struct TestAttachment(Vec<MmioInterrupt>);

impl MmioAttachment for TestAttachment {
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

fn assert_delivery(domain: &TestDomain, handles: &[Interrupt], expected: &[u32]) {
    domain.delivered.lock().unwrap().clear();
    for handle in handles {
        handle.signal();
    }
    assert_eq!(*domain.delivered.lock().unwrap(), expected);
}

#[test]
fn shared_domain_keeps_function_enable_and_masks_independent() {
    let domain = Arc::new(TestDomain {
        vectors: Arc::new(Mutex::new(vec![
            (
                MessageInterrupt {
                    address: 0,
                    data: 0,
                    masked: true
                },
                false
            );
            4
        ])),
        ..TestDomain::default()
    });
    let mut root = PciRoot::new(MmioWindow {
        base: 0,
        size: 0x1000_0000,
    });
    for slot in [1, 2] {
        root.register(
            slot,
            Box::new(TestFunction {
                table: Mutex::new(MsixTable::new(2, 0, 0, 0, 0x1000)),
                notifier: Mutex::new(None),
            }),
        );
    }
    root.set_attachment(Arc::new(TestAttachment(vec![
        MmioInterrupt::MessageDomain(domain.clone()),
    ])));

    // Program both functions while disabled, unmasking both local vectors.
    for slot in [1, 2] {
        for vector in 0..2 {
            let offset = vector * 16;
            root.bus
                .bar_write(slot, 0, offset, &0xFEE0_0000u64.to_le_bytes())
                .unwrap();
            root.bus
                .bar_write(
                    slot,
                    0,
                    offset + 8,
                    &(u32::from(slot) * 10 + vector as u32).to_le_bytes(),
                )
                .unwrap();
            root.bus
                .bar_write(slot, 0, offset + 12, &0u32.to_le_bytes())
                .unwrap();
        }
    }
    let handles: Vec<_> = (0..4).map(|v| domain.interrupt(v).unwrap()).collect();
    assert_delivery(&domain, &handles, &[]);
    let control = |slot, value: u16| {
        root.bus
            .config_write(0, slot, 0, 0, 0, &value.to_le_bytes());
    };
    control(1, 0x8000);
    control(2, 0x8000);
    assert_delivery(&domain, &handles, &[10, 11, 20, 21]);

    // Disabling A cannot suppress B, and enabling B cannot override A.
    control(1, 0);
    assert_delivery(&domain, &handles, &[20, 21]);
    control(2, 0);
    assert_delivery(&domain, &handles, &[]);
    control(2, 0x8000);
    assert_delivery(&domain, &handles, &[20, 21]);
    control(1, 0x8000);
    assert_delivery(&domain, &handles, &[10, 11, 20, 21]);
    control(2, 0);
    assert_delivery(&domain, &handles, &[10, 11]);
    control(1, 0);
    control(1, 0x8000);
    assert_delivery(&domain, &handles, &[10, 11]);

    // Function masks work in both directions while sibling vectors deliver.
    control(2, 0x8000);
    control(1, 0xC000);
    assert_delivery(&domain, &handles, &[20, 21]);
    control(2, 0);
    control(2, 0x8000);
    assert_delivery(&domain, &handles, &[20, 21]);
    control(1, 0x8000);
    control(2, 0xC000);
    assert_delivery(&domain, &handles, &[10, 11]);

    // A vector mask survives disable/re-enable and function-mask transitions.
    root.bus.bar_write(1, 0, 12, &1u32.to_le_bytes()).unwrap();
    control(1, 0);
    control(1, 0xC000);
    control(1, 0x8000);
    control(2, 0x8000);
    assert_delivery(&domain, &handles, &[11, 20, 21]);
    root.bus.bar_write(1, 0, 12, &0u32.to_le_bytes()).unwrap();
    root.bus.bar_write(2, 0, 28, &1u32.to_le_bytes()).unwrap();
    control(2, 0xC000);
    control(2, 0x8000);
    assert_delivery(&domain, &handles, &[10, 11, 20]);
}
