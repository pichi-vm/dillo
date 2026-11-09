// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::Arc;

use dillo_mmio::{MmioWindow, WriteNotification};
use kvm_ioctls::{IoEventAddress, VmFd};
use vmm_sys_util::eventfd::EventFd;

/// Registration authority restricted to the attached device's declared windows.
pub(crate) struct Notifications {
    vm: Arc<VmFd>,
    windows: Vec<MmioWindow>,
}

impl Notifications {
    pub(crate) fn new(vm: Arc<VmFd>, windows: Vec<MmioWindow>) -> Self {
        Self { vm, windows }
    }

    pub(crate) fn register(
        &self,
        window: MmioWindow,
        offset: u64,
        value: u32,
    ) -> io::Result<Option<Arc<dyn WriteNotification>>> {
        if !self.windows.contains(&window)
            || offset.checked_add(4).is_none_or(|end| end > window.size)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let address = window
            .base
            .checked_add(offset)
            .filter(|address| address.checked_add(4).is_some())
            .ok_or(io::ErrorKind::InvalidInput)?;
        if self
            .vm
            .check_extension_raw(kvm_bindings::KVM_CAP_IOEVENTFD.into())
            <= 0
        {
            return Ok(None);
        }
        let event = EventFd::new(libc::EFD_CLOEXEC)?;
        let address = IoEventAddress::Mmio(address);
        self.vm
            .register_ioevent(&event, &address, value)
            .map_err(|error| io::Error::from_raw_os_error(error.errno()))?;
        Ok(Some(Arc::new(Notification {
            vm: Arc::clone(&self.vm),
            event,
            address,
            value,
        })))
    }
}

#[derive(Debug)]
struct Notification {
    vm: Arc<VmFd>,
    event: EventFd,
    address: IoEventAddress,
    value: u32,
}

impl WriteNotification for Notification {
    fn read(&self) -> io::Result<u64> {
        loop {
            match self.event.read() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }

    fn write(&self, count: u64) -> io::Result<()> {
        loop {
            match self.event.write(count) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

impl Drop for Notification {
    fn drop(&mut self) {
        if let Err(error) = self
            .vm
            .unregister_ioevent(&self.event, &self.address, self.value)
        {
            log::error!("KVM write-notification unregister failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(window: MmioWindow) -> Notifications {
        let kvm = kvm_ioctls::Kvm::new().expect("open /dev/kvm");
        Notifications::new(Arc::new(kvm.create_vm().unwrap()), vec![window])
    }

    #[test]
    fn registration_enforces_owned_window_and_complete_write_extent() {
        let window = MmioWindow {
            base: 0x1000,
            size: 0x1000,
        };
        let owner = authority(window);
        for (requested, offset) in [
            (
                MmioWindow {
                    base: 0x2000,
                    ..window
                },
                0,
            ),
            (window, 0xffd),
            (window, u64::MAX),
        ] {
            assert_eq!(
                owner.register(requested, offset, 0).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let overflowing = MmioWindow {
            base: u64::MAX - 1,
            size: 16,
        };
        assert_eq!(
            authority(overflowing)
                .register(overflowing, 0, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn counter_wakes_and_registration_lasts_until_final_clone() {
        let window = MmioWindow {
            base: 0x1000,
            size: 0x1000,
        };
        let owner = authority(window);
        let notification = owner
            .register(window, 0x50, 0)
            .unwrap()
            .expect("ioeventfd supported");
        let clone = Arc::clone(&notification);
        assert!(owner.register(window, 0x50, 0).is_err());
        // Different queue values may share the same notify address.
        let other = owner.register(window, 0x50, 1).unwrap().unwrap();
        notification.write(2).unwrap();
        notification.write(3).unwrap();
        assert_eq!(clone.read().unwrap(), 5);
        drop(notification);
        assert!(owner.register(window, 0x50, 0).is_err());
        let reader = Arc::clone(&clone);
        let waiting = std::thread::spawn(move || reader.read().unwrap());
        clone.write(1).unwrap();
        assert_eq!(waiting.join().unwrap(), 1);
        drop(clone);
        let replacement = owner.register(window, 0x50, 0).unwrap().unwrap();
        replacement.write(1).unwrap();
        assert_eq!(replacement.read().unwrap(), 1);
        drop(other);
    }
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn guest_writes_match_address_width_and_queue_value() {
        let ram = vm_memory::MmapRegion::<()>::new(0x1000).unwrap();
        // Real-mode stores: matched dword, wrong value, wrong width,
        // wrong address, then halt. Only the first may bypass userspace.
        let code = [
            0x66, 0xc7, 0x06, 0x50, 0x10, 0x01, 0x00, 0x00, 0x00, 0x66, 0xc7, 0x06, 0x50, 0x10,
            0x02, 0x00, 0x00, 0x00, 0xc7, 0x06, 0x50, 0x10, 0x01, 0x00, 0x66, 0xc7, 0x06, 0x54,
            0x10, 0x01, 0x00, 0x00, 0x00, 0xf4,
        ];
        // SAFETY: ram owns a writable mapping larger than code, and the
        // vCPU has not been created yet.
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), ram.as_ptr(), code.len());
        };
        let window = MmioWindow {
            base: 0x1000,
            size: 0x1000,
        };
        let owner = authority(window);
        // SAFETY: ram remains allocated until after the VM and vCPU drop.
        #[allow(unsafe_code)]
        unsafe {
            owner
                .vm
                .set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                    slot: 0,
                    guest_phys_addr: 0,
                    memory_size: 0x1000,
                    userspace_addr: ram.as_ptr() as u64,
                    flags: 0,
                })
                .unwrap();
        }
        let notification = owner.register(window, 0x50, 1).unwrap().unwrap();
        let mut vcpu = owner.vm.create_vcpu(0).unwrap();
        let mut sregs = vcpu.get_sregs().unwrap();
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        vcpu.set_sregs(&sregs).unwrap();
        vcpu.set_regs(&kvm_bindings::kvm_regs {
            rip: 0,
            rflags: 2,
            ..Default::default()
        })
        .unwrap();
        for (address, expected) in [
            (0x1050, &[2, 0, 0, 0][..]),
            (0x1050, &[1, 0][..]),
            (0x1054, &[1, 0, 0, 0][..]),
        ] {
            match vcpu.run().unwrap() {
                kvm_ioctls::VcpuExit::MmioWrite(actual, data) => {
                    assert_eq!(actual, address);
                    assert_eq!(data, expected);
                }
                exit => panic!("unexpected exit: {exit:?}"),
            }
        }
        assert!(matches!(vcpu.run().unwrap(), kvm_ioctls::VcpuExit::Hlt));
        // Add a userspace wake so a missed guest notification fails instead
        // of blocking forever. Exactly one guest write must have arrived.
        notification.write(1).unwrap();
        assert_eq!(notification.read().unwrap(), 2);
    }
}
