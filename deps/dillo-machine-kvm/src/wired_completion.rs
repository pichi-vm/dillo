// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Experimental activation-scoped irqfd, with EOI resampling for wired levels.

use std::io;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use dillo_machine::worker::NotificationState;
use dillo_mmio::{InterruptError, InterruptLine};
use vmm_sys_util::eventfd::EventFd;

use crate::hypervisor::Vm;

pub(crate) fn bind(
    vm: Vm,
    gsi: u32,
    level: bool,
    state: Arc<NotificationState>,
) -> Result<Arc<Completion>, InterruptError> {
    let event = EventFd::new(libc::EFD_CLOEXEC | libc::EFD_NONBLOCK).map_err(delivery)?;
    let resample = level
        .then(|| EventFd::new(libc::EFD_CLOEXEC))
        .transpose()
        .map_err(delivery)?;
    let owner = Arc::new(Completion {
        vm,
        gsi,
        event,
        resample,
        stopped: Arc::new(AtomicBool::new(false)),
        binding: Mutex::new(Binding {
            registered: false,
            resampler: None,
        }),
        #[cfg(test)]
        resamples: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    });
    {
        let mut binding = owner.binding.lock().unwrap();
        if let Some(resample) = &owner.resample {
            owner
                .vm
                .fd()
                .register_irqfd_with_resample(&owner.event, resample, gsi)
                .map_err(delivery)?;
        } else {
            owner
                .vm
                .fd()
                .register_irqfd(&owner.event, gsi)
                .map_err(delivery)?;
        }
        binding.registered = true;
        if let Some(resample) = &owner.resample {
            let read = resample.try_clone().map_err(delivery)?;
            let signal = owner.event.try_clone().map_err(delivery)?;
            let stopped = Arc::clone(&owner.stopped);
            #[cfg(test)]
            let resamples = Arc::clone(&owner.resamples);
            binding.resampler = Some(
                std::thread::Builder::new()
                    .name("mmio-resample".into())
                    .spawn(move || {
                        loop {
                            match read.read() {
                                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                                result => {
                                    result?;
                                }
                            }
                            if stopped.load(Ordering::Acquire) {
                                return Ok(());
                            }
                            // EOI clears the native level. Reassert only while
                            // the transport's event latch still requires service.
                            if state.load() != 0 {
                                signal.write(1)?;
                            }
                            #[cfg(test)]
                            resamples.fetch_add(1, Ordering::Release);
                        }
                    })
                    .map_err(delivery)?,
            );
        }
    }
    Ok(owner)
}

#[derive(Debug)]
struct Binding {
    registered: bool,
    resampler: Option<JoinHandle<io::Result<()>>>,
}

#[derive(Debug)]
pub(crate) struct Completion {
    vm: Vm,
    gsi: u32,
    event: EventFd,
    resample: Option<EventFd>,
    stopped: Arc<AtomicBool>,
    binding: Mutex<Binding>,
    #[cfg(test)]
    resamples: Arc<std::sync::atomic::AtomicU64>,
}

impl InterruptLine for Completion {
    fn signal(&self) {
        if let Err(error) = self.set_level(true) {
            log::error!("MMIO irqfd completion: {error}");
        }
    }

    fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        if level && !self.stopped.load(Ordering::Acquire) {
            self.event.write(1).map_err(delivery)?;
        }
        Ok(())
    }

    fn export(&self) -> io::Result<Option<dillo_machine::worker::Resource>> {
        let event = self.event.try_clone()?;
        // SAFETY: the new descriptor transfers ownership exactly once.
        #[allow(unsafe_code)]
        Ok(Some(unsafe { OwnedFd::from_raw_fd(event.into_raw_fd()) }))
    }

    fn retire(&self) -> Result<(), InterruptError> {
        let mut binding = self.binding.lock().unwrap();
        self.stopped.store(true, Ordering::Release);
        let resampled = if binding.resampler.is_some() {
            self.resample.as_ref().unwrap().write(1).map_err(delivery)?;
            binding
                .resampler
                .take()
                .unwrap()
                .join()
                .map_err(|_| delivery("MMIO resampler panicked"))
                .and_then(|result| result.map_err(delivery))
        } else {
            Ok(())
        };
        if binding.registered {
            // KVM deassignment flushes delivery. Retained worker duplicates
            // then refer to an ordinary eventfd with no native authority.
            self.vm
                .fd()
                .unregister_irqfd(&self.event, self.gsi)
                .map_err(delivery)?;
            binding.registered = false;
        }
        resampled
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        if let Err(error) = self.retire() {
            log::error!("retire MMIO irqfd completion: {error}");
        }
    }
}

fn delivery(error: impl std::fmt::Display) -> InterruptError {
    InterruptError::Delivery(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_machine::worker::WorkerHost;
    use kvm_ioctls::{VcpuExit, VcpuFd};
    use std::time::{Duration, Instant};

    fn wait(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !ready() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(ready());
    }

    #[cfg(target_arch = "x86_64")]
    fn pending(cpu: &VcpuFd) -> bool {
        cpu.get_lapic().unwrap().regs[0x220] as u8 & 2 != 0
    }

    #[cfg(target_arch = "x86_64")]
    fn eoi(cpu: &mut VcpuFd) {
        // Accept vector 0x41 without installing a guest interrupt handler.
        // The guest then performs the actual LAPIC EOI write through KVM.
        let mut lapic = cpu.get_lapic().unwrap();
        lapic.regs[0x220] &= !2;
        lapic.regs[0x120] |= 2;
        cpu.set_lapic(&lapic).unwrap();
        cpu.set_regs(&kvm_bindings::kvm_regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(cpu.run().unwrap(), VcpuExit::IoOut(0x42, _)));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn level_reasserts_until_ack_and_retired_exports_cannot_signal() {
        if !crate::hypervisor::memory_registration_tests::native_cpu_test_child(
            "wired_completion::tests::level_reasserts_until_ack_and_retired_exports_cannot_signal",
        ) {
            return;
        }
        let vm = Vm::test_new().unwrap();
        let memory = Arc::new(crate::memory::MappedMemory::test_backing(&[(0, 0x10000)]).unwrap());
        vm.attach_memory(Arc::clone(&memory)).unwrap();
        memory
            .write(
                0x1000,
                &[
                    0xc7, 0x05, 0xb0, 0x00, 0xe0, 0xfe, 0, 0, 0, 0, // LAPIC EOI
                    0xe6, 0x42, 0xf4, // out 0x42, al; hlt
                ],
            )
            .unwrap();
        let mut cpu = vm.fd().create_vcpu(0).unwrap();
        let mut sregs = cpu.get_sregs().unwrap();
        sregs.cs = kvm_bindings::kvm_segment {
            base: 0,
            limit: u32::MAX,
            selector: 8,
            type_: 11,
            present: 1,
            db: 1,
            s: 1,
            g: 1,
            ..Default::default()
        };
        sregs.ds = kvm_bindings::kvm_segment {
            type_: 3,
            selector: 16,
            ..sregs.cs
        };
        sregs.cr0 |= 1;
        cpu.set_sregs(&sregs).unwrap();
        let mut lapic = cpu.get_lapic().unwrap();
        lapic.regs[0xf0] = -1;
        lapic.regs[0xf1] = 1;
        cpu.set_lapic(&lapic).unwrap();
        let mut chip = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        vm.fd().get_irqchip(&mut chip).unwrap();
        // SAFETY: get_irqchip populated the union member selected by chip_id.
        #[allow(unsafe_code)]
        unsafe {
            chip.chip.ioapic.redirtbl[16].bits = 0x41 | (1 << 15);
        }
        vm.fd().set_irqchip(&chip).unwrap();
        let state = crate::worker::Worker::create_notification_state().unwrap();
        let event = bind(vm.clone(), 16, true, Arc::clone(&state)).unwrap();
        state.used();
        event.signal();
        wait(|| pending(&cpu));
        eoi(&mut cpu);
        wait(|| event.resamples.load(Ordering::Acquire) == 1 && pending(&cpu));
        state.acknowledge(1);
        eoi(&mut cpu);
        wait(|| event.resamples.load(Ordering::Acquire) == 2);
        assert!(!pending(&cpu));
        let stale = crate::worker::Worker::notification(event.export().unwrap().unwrap()).unwrap();
        event.retire().unwrap();
        event.retire().unwrap();
        let replacement_state = crate::worker::Worker::create_notification_state().unwrap();
        let replacement = bind(vm, 16, true, Arc::clone(&replacement_state)).unwrap();
        state.used();
        stale.write(1).unwrap();
        assert_eq!(replacement_state.load(), 0);
        assert!(!pending(&cpu));
        replacement_state.used();
        replacement.signal();
        wait(|| pending(&cpu));
        replacement.retire().unwrap();
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn arm_level_reasserts_until_ack_and_retired_exports_cannot_signal() {
        use kvm_bindings::*;
        if !crate::hypervisor::memory_registration_tests::native_cpu_test_child(
            "wired_completion::tests::arm_level_reasserts_until_ack_and_retired_exports_cannot_signal",
        ) {
            return;
        }
        let vm = Vm::new_with_gic(&crate::imp::Aarch64Substrate {
            dist_base: 0x0800_0000,
            redist_base: 0x0810_0000,
            spi_count: 64,
        })
        .unwrap();
        let memory = Arc::new(crate::memory::MappedMemory::test_backing(&[(0, 0x10000)]).unwrap());
        vm.attach_memory(Arc::clone(&memory)).unwrap();
        let code: &[u32] = &[
            // Enable group 1; SPI 48 is level-triggered, unmasked and routed to CPU 0.
            0xd2a10000, 0x52800241, 0xb9000001, 0x52a00021, 0xb9008401, 0xb9010401, 0x91401803,
            0xf900c07f, 0xd2a10200, 0xb900141f,
            // Wake GICR, PMR=255, combined EOI/deactivate, enable ICC group 1.
            0xd2801fe1, 0xd5184601, 0xd538cc81, 0x927ef821, 0xd518cc81, 0xd2800021, 0xd518cce1,
            0xd5033fdf,
            // Report 0x1111 at unmapped GPA 0x100000; read commands at GPA 0x800.
            0xd2a00202, 0xd2822220, 0xf9000040, 0xd2810003,
            // Command 2 reads IAR1; 3 writes EOIR1 with the last accepted ID.
            // Other commands read HPPIR1. Every command reports through MMIO.
            0xb9400061, 0x7100083f, 0x540000a0, 0x71000c3f, 0x540000a0, 0xd538cc40, 0x14000006,
            0xd538cc00, 0x14000004, 0xd518cc24, 0xd5033fdf, 0xd2844440, 0xaa0003e4, 0xf9000040,
            0x17fffff2,
        ];
        memory
            .write(
                0,
                &code
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let mut cpu = vm.fd().create_vcpu(0).unwrap();
        let mut init = kvm_vcpu_init::default();
        vm.fd().get_preferred_target(&mut init).unwrap();
        cpu.vcpu_init(&init).unwrap();
        let core = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | u64::from(KVM_REG_ARM_CORE);
        cpu.set_one_reg(core | 64, &0u64.to_le_bytes()).unwrap();
        cpu.set_one_reg(core | 66, &0x3c5u64.to_le_bytes()).unwrap();
        let mut manager = crate::irq::IrqManager::new(vm.clone()).unwrap();
        let _original = manager.register_spi_irqfd(16).unwrap();
        vm.init_gic().unwrap();
        manager.flush_pending_wired().unwrap();
        let report = |cpu: &mut VcpuFd| match cpu.run().unwrap() {
            VcpuExit::MmioWrite(0x100000, bytes) => u64::from_le_bytes(bytes.try_into().unwrap()),
            exit => panic!("unexpected fixture exit: {exit:?}"),
        };
        assert_eq!(report(&mut cpu), 0x1111);
        let command = |cpu: &mut VcpuFd, command: u32| {
            memory.write(0x800, &command.to_le_bytes()).unwrap();
            report(cpu)
        };
        let (_, gsi) = manager.wired_binding(16).unwrap();
        let state = crate::worker::Worker::create_notification_state().unwrap();
        let event = bind(vm.clone(), gsi, true, Arc::clone(&state)).unwrap();
        state.used();
        event.signal();
        wait(|| command(&mut cpu, 1) == 48);
        assert_eq!(command(&mut cpu, 2), 48);
        assert_eq!(command(&mut cpu, 3), 0x2222);
        wait(|| event.resamples.load(Ordering::Acquire) == 1 && command(&mut cpu, 1) == 48);
        assert_eq!(command(&mut cpu, 2), 48);
        state.acknowledge(1);
        assert_eq!(command(&mut cpu, 3), 0x2222);
        wait(|| event.resamples.load(Ordering::Acquire) == 2);
        assert_eq!(command(&mut cpu, 1), 1023);
        let stale = crate::worker::Worker::notification(event.export().unwrap().unwrap()).unwrap();
        event.retire().unwrap();
        event.retire().unwrap();
        let replacement_state = crate::worker::Worker::create_notification_state().unwrap();
        let replacement = bind(vm, gsi, true, Arc::clone(&replacement_state)).unwrap();
        state.used();
        stale.write(1).unwrap();
        assert_eq!(replacement_state.load(), 0);
        assert_eq!(command(&mut cpu, 1), 1023);
        replacement_state.used();
        replacement.signal();
        wait(|| command(&mut cpu, 1) == 48);
        replacement.retire().unwrap();
    }
}
