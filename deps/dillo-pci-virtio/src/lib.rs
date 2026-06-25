// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Virtio PCI transport layer.
//!
//! This crate bridges the virtio device model and the PCI bus. It wraps any
//! [`VirtioDevice`](dillo_virtio::VirtioDevice) as a PCI device with all 5 virtio
//! PCI capabilities (common cfg, notify, ISR, device cfg, PCI cfg access),
//! MSI-X interrupts, device status FSM, feature negotiation, and queue
//! notification.
//!
//! # Composition chain
//!
//! `VirtioPciDevice` wraps any `Arc<Mutex<dyn VirtioDevice>>`. The concrete
//! device implementation remains portable; the Machine attachment supplies
//! memory, interrupt, and host-thread capabilities during activation.
//!
//! [`VirtioPciAdapter`] wraps `VirtioPciDevice` as
//! [`dillo_pci::PciDevice`], and `PciBus` dispatches config-space and BAR
//! accesses to it.
//!
//! This layering keeps PCI transport concerns separate from device I/O.
//!
//! # BAR 0 layout
//!
//! All virtio PCI regions are mapped into a single 4 KiB BAR:
//! - `0x000..0x038`: Common configuration (device status, feature bits, queues)
//! - `0x038..0x03C`: ISR status
//! - `0x040..0x080`: Device-specific configuration
//! - `0x100..`:      Per-queue notify registers (2-byte stride)
//!
//! MSI-X uses BAR 1 for the table and BAR 2 for the PBA.

/// Virtio PCI capability structure helpers for config space registration.
pub(crate) mod capabilities;
/// PCI transport implementation: device status FSM, feature negotiation, BAR I/O.
pub mod transport;

pub use transport::VirtioPciDevice;

use std::sync::Mutex;

use dillo_pci::{BarRegion, PciDevice, PciDeviceHost, PciError};

use crate::transport::PciVirtioHost;

/// Adapter wrapping a [`VirtioPciDevice`] as a [`PciDevice`].
pub struct VirtioPciAdapter {
    inner: Mutex<VirtioPciDevice>,
    bar_regions: Vec<BarRegion>,
    msix_vectors: u16,
}

impl std::fmt::Debug for VirtioPciAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioPciAdapter")
            .field("bar_regions", &self.bar_regions)
            .finish_non_exhaustive()
    }
}

impl VirtioPciAdapter {
    pub fn new(inner: VirtioPciDevice) -> Self {
        let bar_regions = inner
            .bar_regions()
            .into_iter()
            .map(|(bar_idx, base_gpa, size)| BarRegion {
                bar_idx,
                base_gpa,
                size,
            })
            .collect();
        let msix_vectors = inner.msix_vectors();
        Self {
            inner: Mutex::new(inner),
            bar_regions,
            msix_vectors,
        }
    }
}

impl PciDevice for VirtioPciAdapter {
    fn config_read(&self, reg_idx: usize) -> u32 {
        self.inner
            .lock()
            .expect("virtio PCI transport poisoned")
            .config_read(reg_idx)
    }

    fn config_write(&self, reg_idx: usize, offset: u64, data: &[u8]) -> Result<(), PciError> {
        self.inner
            .lock()
            .expect("virtio PCI transport poisoned")
            .config_write(reg_idx, offset, data);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "virtio-pci"
    }

    fn bar_regions(&self) -> &[BarRegion] {
        &self.bar_regions
    }

    fn msix_vectors(&self) -> u16 {
        self.msix_vectors
    }

    fn bar_read(&self, bar_idx: u8, offset: u64, data: &mut [u8]) -> Result<(), PciError> {
        self.inner
            .lock()
            .expect("virtio PCI transport poisoned")
            .bar_read(bar_idx, offset, data)
            .then_some(())
            .ok_or(PciError::Unsupported)
    }

    fn bar_write(&self, bar_idx: u8, offset: u64, data: &[u8]) -> Result<(), PciError> {
        self.inner
            .lock()
            .expect("virtio PCI transport poisoned")
            .bar_write(bar_idx, offset, data)
            .then_some(())
            .ok_or(PciError::Unsupported)
    }

    fn set_host(&self, host: std::sync::Arc<dyn PciDeviceHost>) {
        let mut inner = self.inner.lock().expect("virtio PCI transport poisoned");
        if let Some(notifier) = host.msix_notifier() {
            inner.set_notifier(notifier);
        }
        inner.set_host(std::sync::Arc::new(PciVirtioHost::new(host)));
    }
}
