// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Message-interrupt → KVM irqfd bridge.

use std::sync::{Arc, Mutex};

use dillo_mmio::{Interrupt, InterruptError, MessageInterrupt, MessageInterruptDomain};
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

    fn set_enabled(enabled: bool) {
        log::info!("KvmMessageInterruptDomain: enabled={enabled}");
    }
}

impl MessageInterruptDomain for KvmMessageInterruptDomain {
    fn update(&self, vector: u16, msg: MessageInterrupt) -> Result<(), InterruptError> {
        self.update_message(vector, msg);
        Ok(())
    }

    fn enabled(&self, enabled: bool) -> Result<(), InterruptError> {
        Self::set_enabled(enabled);
        Ok(())
    }

    fn interrupt(&self, vector: u16) -> Option<Interrupt> {
        self.interrupt_for_vector(vector)
    }
}
