// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Message-interrupt → KVM irqfd bridge.

use std::sync::{Arc, Mutex};

use dillo_mmio::{
    Interrupt, InterruptError, InterruptLine, MessageInterrupt, MessageInterruptDomain,
    MessageInterruptEvent,
};
use vmm_sys_util::eventfd::EventFd;

use crate::irq::IrqManager;

/// Message-interrupt domain backed by KVM irqfd routes.
///
/// Each vector maps to a KVM GSI with an irqfd. On first programming, a fresh
/// irqfd is allocated via `IrqManager::allocate_irqfd`. On re-programming, the
/// existing GSI route is updated to the new address/data.
pub(crate) struct KvmMessageInterruptDomain {
    irq_manager: Arc<Mutex<IrqManager>>,
    /// Per-vector: (gsi, eventfd clone for signaling).
    vectors: Mutex<Vec<Option<(u32, EventFd)>>>,
}

impl std::fmt::Debug for KvmMessageInterruptDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmMessageInterruptDomain")
            .field("num_vectors", &self.vectors.lock().map_or(0, |v| v.len()))
            .finish_non_exhaustive()
    }
}

impl KvmMessageInterruptDomain {
    /// Create with `num_vectors` empty slots. Slots fill in lazily as
    /// the guest programs each message-interrupt vector.
    pub(crate) fn new(irq_manager: Arc<Mutex<IrqManager>>, num_vectors: u16) -> Self {
        let mut vectors = Vec::with_capacity(num_vectors as usize);
        for _ in 0..num_vectors {
            vectors.push(None);
        }
        Self {
            irq_manager,
            vectors: Mutex::new(vectors),
        }
    }

    fn eventfd_for_vector(&self, vector: u16) -> Option<EventFd> {
        let vectors = self.vectors.lock().ok()?;
        let slot = vectors.get(vector as usize)?.as_ref()?;
        slot.1.try_clone().ok()
    }

    fn interrupt_for_vector(&self, vector: u16) -> Option<Interrupt> {
        let eventfd = self.eventfd_for_vector(vector)?;
        Some(Interrupt::from_fn(move || {
            if let Err(e) = eventfd.write(1) {
                log::warn!("KVM message irqfd signal for vector {vector} failed: {e}");
            }
        }))
    }

    fn update_message(&self, vector: u16, msg: MessageInterrupt) {
        log::info!(
            "KvmMessageInterruptDomain::update: vector={vector} addr={:#x} data={:#x} ctl={:#x}",
            msg.address,
            msg.data,
            i32::from(msg.masked)
        );
        if msg.masked {
            return;
        }

        let Ok(mut vectors) = self.vectors.lock() else {
            return;
        };
        let idx = vector as usize;
        if idx >= vectors.len() {
            return;
        }

        let Ok(mut mgr) = self.irq_manager.lock() else {
            return;
        };

        if let Some((gsi, _)) = &vectors[idx] {
            let gsi = *gsi;
            if let Err(e) = mgr.update_route(
                gsi,
                msg.address as u32,
                (msg.address >> 32) as u32,
                msg.data,
            ) {
                log::error!(
                    "KvmMessageInterruptDomain: failed to update route for vector {vector}: {e}"
                );
            } else {
                log::debug!(
                    "KvmMessageInterruptDomain: updated vector {vector} gsi={gsi} addr={:#x} data={:#x}",
                    msg.address,
                    msg.data
                );
            }
        } else {
            match mgr.allocate_irqfd(msg.address as u32, (msg.address >> 32) as u32, msg.data) {
                Ok((gsi, fd)) => {
                    log::debug!(
                        "KvmMessageInterruptDomain: allocated vector {vector} gsi={gsi} addr={:#x} data={:#x}",
                        msg.address,
                        msg.data
                    );
                    vectors[idx] = Some((gsi, fd));
                }
                Err(e) => {
                    log::error!(
                        "KvmMessageInterruptDomain: failed to allocate irqfd for vector {vector}: {e}"
                    );
                }
            }
        }
    }

    // KVM currently only logs enable changes; irqfd gating is not implemented.
    // Unlike HVF/WHP, there is no shared enable flag suppressing sibling vectors.
    fn set_enabled(vector: u16, enabled: bool) {
        log::info!("KvmMessageInterruptDomain: vector={vector} enabled={enabled}");
    }
}

impl MessageInterruptDomain for KvmMessageInterruptDomain {
    fn event(&self) -> Result<Option<Arc<dyn MessageInterruptEvent>>, InterruptError> {
        let event = EventFd::new(libc::EFD_CLOEXEC | libc::EFD_NONBLOCK).map_err(delivery_error)?;
        Ok(Some(Arc::new(QueueEvent {
            event,
            manager: Arc::clone(&self.irq_manager),
            route: Mutex::new(None),
        })))
    }

    fn update(&self, vector: u16, msg: MessageInterrupt) -> Result<(), InterruptError> {
        self.update_message(vector, msg);
        Ok(())
    }

    fn enabled(&self, vector: u16, enabled: bool) -> Result<(), InterruptError> {
        Self::set_enabled(vector, enabled);
        Ok(())
    }

    fn interrupt(&self, vector: u16) -> Option<Interrupt> {
        self.interrupt_for_vector(vector)
    }
}

fn delivery_error(error: impl std::fmt::Display) -> InterruptError {
    InterruptError::Delivery(error.to_string())
}

#[derive(Debug)]
struct QueueEvent {
    event: EventFd,
    manager: Arc<Mutex<IrqManager>>,
    route: Mutex<Option<(MessageInterrupt, u32)>>,
}

impl InterruptLine for QueueEvent {
    fn signal(&self) {
        if let Err(error) = self.set_level(true) {
            log::error!("signal queue irqfd: {error}");
        }
    }

    fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        if level {
            loop {
                match self.event.write(1) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => return result.map_err(delivery_error),
                }
            }
        }
        Ok(())
    }

    fn export(&self) -> std::io::Result<Option<dillo_machine::worker::Resource>> {
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
        let event = self.event.try_clone()?;
        // SAFETY: transfer a freshly duplicated eventfd into its owned type.
        #[allow(unsafe_code)]
        Ok(Some(unsafe { OwnedFd::from_raw_fd(event.into_raw_fd()) }))
    }
}

impl MessageInterruptEvent for QueueEvent {
    fn configure(&self, message: Option<MessageInterrupt>) -> Result<(), InterruptError> {
        let message = message.filter(|message| !message.masked);
        let mut route = self.route.lock().expect("queue irqfd route poisoned");
        if route.as_ref().map(|(message, _)| *message) == message {
            return Ok(());
        }
        let mut manager = self.manager.lock().expect("KVM IRQ manager poisoned");
        if let Some((_, gsi)) = *route {
            manager.release_irqfd(gsi).map_err(delivery_error)?;
            *route = None;
        }
        if let Some(message) = message {
            let gsi = manager
                .bind_irqfd(
                    &self.event,
                    message.address as u32,
                    (message.address >> 32) as u32,
                    message.data,
                )
                .map_err(delivery_error)?;
            *route = Some((message, gsi));
        }
        Ok(())
    }

    fn pending(&self) -> Result<bool, InterruptError> {
        let route = self.route.lock().expect("queue irqfd route poisoned");
        if route.is_some() {
            return Ok(false);
        }
        loop {
            match self.event.read() {
                Ok(count) => return Ok(count != 0),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(delivery_error(error)),
            }
        }
    }
}

impl Drop for QueueEvent {
    fn drop(&mut self) {
        if let Err(error) = self.configure(None) {
            log::error!("release queue irqfd: {error}");
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use dillo_machine::worker::WorkerHost;
    use std::time::{Duration, Instant};

    #[test]
    fn queue_event_masks_retargets_and_revokes_exported_endpoints() {
        let vm = crate::hypervisor::Vm::test_new().unwrap();
        let cpu = vm.fd().create_vcpu(0).unwrap();
        let mut lapic = cpu.get_lapic().unwrap();
        for (slot, byte) in lapic.regs[0xf0..0xf4]
            .iter_mut()
            .zip(0x1ffu32.to_le_bytes())
        {
            *slot = byte.cast_signed();
        }
        cpu.set_lapic(&lapic).unwrap();
        let pending = |vector: u32| {
            let lapic = cpu.get_lapic().unwrap();
            let offset = 0x200 + (vector as usize / 32) * 16;
            let word = u32::from_le_bytes(std::array::from_fn(|i| lapic.regs[offset + i] as u8));
            word & (1 << (vector % 32)) != 0
        };
        let wait = |vector| {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !pending(vector) && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(pending(vector), "missing vector {vector}");
        };
        let domain =
            KvmMessageInterruptDomain::new(Arc::new(Mutex::new(IrqManager::new(vm).unwrap())), 1);
        let event = domain.event().unwrap().unwrap();
        let message = |data| {
            Some(MessageInterrupt {
                address: 0xfee0_0000,
                data,
                masked: false,
            })
        };
        event.signal();
        assert!(event.pending().unwrap());
        assert!(!event.pending().unwrap());
        event.configure(message(0x41)).unwrap();
        event.signal();
        wait(0x41);
        event.configure(None).unwrap();
        event.signal();
        assert!(event.pending().unwrap());
        event.configure(message(0x42)).unwrap();
        event.signal();
        wait(0x42);
        event.configure(message(0x43)).unwrap();
        let exported =
            crate::worker::Worker::notification(event.export().unwrap().unwrap()).unwrap();
        drop(event);
        let replacement = domain.event().unwrap().unwrap();
        replacement.configure(message(0x44)).unwrap();
        exported.write(1).unwrap();
        assert!(!pending(0x43));
        assert!(!pending(0x44));
        replacement.signal();
        wait(0x44);
        assert!(!pending(0x43));
    }
}
