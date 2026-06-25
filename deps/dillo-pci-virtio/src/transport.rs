// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! VirtioPciDevice: PCI transport for virtio devices.
//!
//! Wraps a VirtioDevice and presents it as a PCI device with virtio
//! capabilities, common config BAR, MSI-X, device status FSM, feature
//! negotiation, and queue notification.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use dillo_mmio::SharedMemory;
use dillo_pci::{CAP_ID_MSIX, MsixNotifier, MsixTable, NoopNotifier, PciConfiguration};
use dillo_pci::{MmioJoinError, PciDeviceHost};
use dillo_virtio::Kick;
use dillo_virtio::queue::Queue;
use dillo_virtio::{
    ActivateError, DeviceJoinError, VIRTIO_F_VERSION_1, VirtioActivate, VirtioDevice,
    VirtioDeviceHandle, VirtioDeviceHost, VirtioRunToken,
};
use vm_memory::GuestAddress;

use crate::capabilities::{add_virtio_cap, add_virtio_notify_cap};

// BAR 0 layout offsets.
const COMMON_CFG_OFFSET: u64 = 0x000;
const COMMON_CFG_LENGTH: u32 = 0x38; // 56 bytes
const ISR_CFG_OFFSET: u64 = 0x038;
const ISR_CFG_LENGTH: u32 = 4;
const DEVICE_CFG_OFFSET: u64 = 0x040;
const DEVICE_CFG_LENGTH: u32 = 64;
const NOTIFY_CFG_OFFSET: u64 = 0x100;
const NOTIFY_OFF_MULTIPLIER: u32 = 2;

const BAR0_SIZE: u64 = 4096;
const BAR2_SIZE: u64 = 4096; // MSI-X BAR

// Common config register offsets (byte offsets within common config).
const CC_DEVICE_FEATURE_SELECT: u64 = 0x00;
const CC_DEVICE_FEATURE: u64 = 0x04;
const CC_DRIVER_FEATURE_SELECT: u64 = 0x08;
const CC_DRIVER_FEATURE: u64 = 0x0C;
const CC_MSIX_CONFIG: u64 = 0x10;
const CC_NUM_QUEUES: u64 = 0x12;
const CC_DEVICE_STATUS: u64 = 0x14;
const CC_CONFIG_GENERATION: u64 = 0x15;
const CC_QUEUE_SELECT: u64 = 0x16;
const CC_QUEUE_SIZE: u64 = 0x18;
const CC_QUEUE_MSIX_VECTOR: u64 = 0x1A;
const CC_QUEUE_ENABLE: u64 = 0x1C;
const CC_QUEUE_NOTIFY_OFF: u64 = 0x1E;
const CC_QUEUE_DESC_LO: u64 = 0x20;
const CC_QUEUE_DESC_HI: u64 = 0x24;
const CC_QUEUE_AVAIL_LO: u64 = 0x28;
const CC_QUEUE_AVAIL_HI: u64 = 0x2C;
const CC_QUEUE_USED_LO: u64 = 0x30;
const CC_QUEUE_USED_HI: u64 = 0x34;

// Device status bits.
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_DRIVER_OK: u8 = 4;

/// Per-queue state tracked by the transport layer.
#[derive(Debug)]
struct QueueConfig {
    queue: Queue,
    msix_vector: u16,
    desc_lo: u32,
    desc_hi: u32,
    avail_lo: u32,
    avail_hi: u32,
    used_lo: u32,
    used_hi: u32,
    enabled: bool,
}

impl QueueConfig {
    fn new(max_size: u16) -> Self {
        Self {
            queue: Queue::new(max_size),
            msix_vector: 0xFFFF, // VIRTIO_MSI_NO_VECTOR
            desc_lo: 0,
            desc_hi: 0,
            avail_lo: 0,
            avail_hi: 0,
            used_lo: 0,
            used_hi: 0,
            enabled: false,
        }
    }

    /// Materialize the Queue from stored GPAs for activation.
    fn to_queue(&self) -> Queue {
        let mut q = Queue::new(self.queue.max_size);
        q.size = self.queue.size;
        q.ready = self.enabled;
        q.desc_table = GuestAddress((self.desc_hi as u64) << 32 | self.desc_lo as u64);
        q.avail_ring = GuestAddress((self.avail_hi as u64) << 32 | self.avail_lo as u64);
        q.used_ring = GuestAddress((self.used_hi as u64) << 32 | self.used_lo as u64);
        q.msix_vector = self.msix_vector;
        q
    }
}

/// Virtio PCI transport device.
///
/// Wraps any `VirtioDevice` and exposes it as a PCI device with all 5 virtio
/// capabilities, common config BAR (BAR 0), MSI-X BAR (BAR 2), device status
/// FSM, feature negotiation, and queue notification at `DRIVER_OK`.
///
/// The `device` field is `Arc<Mutex<Box<dyn VirtioDevice>>>` (boxed) so that
/// the console soft-reconnect path can replace the inner `VhostUserFrontendDevice`
/// in-place via `*guard = Box::new(new_device)` without touching the PCIe device tree.
pub struct VirtioPciDevice {
    device: Arc<Mutex<Box<dyn VirtioDevice>>>,
    config: PciConfiguration,
    msix_table: MsixTable,
    msix_cap_reg: usize,

    // Common config state.
    device_feature_select: u32,
    driver_feature_select: u32,
    driver_features: u64,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    msix_config_vector: u16,

    // Queue configs.
    queues: Vec<QueueConfig>,

    // ISR status (atomic for read-and-clear from &self).
    isr_status: AtomicU8,

    // BAR GPAs.
    bar0_gpa: u64,
    bar2_gpa: u64,

    // Activation state.
    activated: bool,
    activation: Option<VirtioDeviceHandle>,
    host: Option<Arc<dyn VirtioDeviceHost>>,

    // MSI-X notifier (VMM provides real implementation, tests use NoopNotifier).
    notifier: Arc<dyn MsixNotifier>,

    // Retained kick clones so the MMIO notify path can signal queue workers.
    queue_kicks: Vec<Kick>,

    // Cached device features.
    device_features: u64,
    num_queues: u16,
}

impl std::fmt::Debug for VirtioPciDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioPciDevice")
            .field("config", &self.config)
            .field("msix_table", &self.msix_table)
            .field("msix_cap_reg", &self.msix_cap_reg)
            .field("device_feature_select", &self.device_feature_select)
            .field("driver_feature_select", &self.driver_feature_select)
            .field("driver_features", &self.driver_features)
            .field("device_status", &self.device_status)
            .field("config_generation", &self.config_generation)
            .field("queue_select", &self.queue_select)
            .field("msix_config_vector", &self.msix_config_vector)
            .field("queues", &self.queues)
            .field("isr_status", &self.isr_status)
            .field("bar0_gpa", &self.bar0_gpa)
            .field("bar2_gpa", &self.bar2_gpa)
            .field("activated", &self.activated)
            .field("device_features", &self.device_features)
            .field("num_queues", &self.num_queues)
            .finish_non_exhaustive()
    }
}

impl VirtioPciDevice {
    /// Create a new VirtioPciDevice wrapping the given VirtioDevice.
    ///
    /// `msix_vectors`: number of MSI-X table entries (typically num_queues + 1).
    /// `bar0_gpa`: guest physical address for BAR 0 (virtio config, 4KB).
    /// `bar2_gpa`: guest physical address for BAR 2 (MSI-X table + PBA, 4KB).
    pub fn new(
        device: Arc<Mutex<Box<dyn VirtioDevice>>>,
        msix_vectors: u16,
        bar0_gpa: u64,
        bar2_gpa: u64,
    ) -> Self {
        Self::new_with_notifier(
            device,
            msix_vectors,
            bar0_gpa,
            bar2_gpa,
            Arc::new(NoopNotifier),
        )
    }

    pub fn new_with_notifier(
        device: Arc<Mutex<Box<dyn VirtioDevice>>>,
        msix_vectors: u16,
        bar0_gpa: u64,
        bar2_gpa: u64,
        notifier: Arc<dyn MsixNotifier>,
    ) -> Self {
        let (device_type, num_queues, queue_max_sizes, device_features) = {
            let dev = device.lock().expect("VirtioDevice mutex poisoned");
            let dt = dev.device_type();
            let nq = dev.num_queues();
            let qms: Vec<u16> = dev.queue_max_sizes().to_vec();
            let feats = dev.features();
            (dt, nq, qms, feats)
        };

        let mut config = PciConfiguration::new();
        // Vendor 0x1AF4 (Red Hat), device 0x1040+device_type (modern virtio).
        config.set_vendor_device(0x1AF4, 0x1040 + device_type as u16);
        // Subsystem: vendor=0x1AF4, device=device_type (register 11).
        config.set_reg(11, 0x1AF4 | (device_type << 16));
        config.set_class(0xFF, 0x00, 0x00, 0x00);
        config.set_header_type(0x00);

        // BAR 0: 64-bit memory BAR (F5) for virtio config regions. The
        // device-model PCI window is 64-bit-only and sits high (e.g. 32 GiB),
        // so a 32-bit BAR can't address it — the low dword carries the 64-bit
        // type bits (bits[2:1]=10 ⇒ 0x4) and BAR1 the high dword.
        config.set_bar(0, (bar0_gpa as u32 & 0xFFFF_F000) | 0x4);
        config.set_bar_writable_bits(0, 0xFFFF_F000);
        config.set_bar(1, (bar0_gpa >> 32) as u32);
        config.set_bar_writable_bits(1, 0xFFFF_FFFF);

        // BAR 2: 64-bit memory BAR for MSI-X table + PBA (BAR2 low + BAR3 high).
        config.set_bar(2, (bar2_gpa as u32 & 0xFFFF_F000) | 0x4);
        config.set_bar_writable_bits(2, 0xFFFF_F000);
        config.set_bar(3, (bar2_gpa >> 32) as u32);
        config.set_bar_writable_bits(3, 0xFFFF_FFFF);

        // Notify region size = 2 * num_queues.
        let notify_length = (NOTIFY_OFF_MULTIPLIER * num_queues as u32).max(4);

        // Add 5 virtio PCI capabilities.
        // 1. Common config (cfg_type=1)
        add_virtio_cap(
            &mut config,
            1,
            0,
            COMMON_CFG_OFFSET as u32,
            COMMON_CFG_LENGTH,
        );
        // 2. Notify (cfg_type=2) -- 20-byte cap with notify_off_multiplier
        add_virtio_notify_cap(
            &mut config,
            0,
            NOTIFY_CFG_OFFSET as u32,
            notify_length,
            NOTIFY_OFF_MULTIPLIER,
        );
        // 3. ISR (cfg_type=3)
        add_virtio_cap(&mut config, 3, 0, ISR_CFG_OFFSET as u32, ISR_CFG_LENGTH);
        // 4. Device config (cfg_type=4)
        add_virtio_cap(
            &mut config,
            4,
            0,
            DEVICE_CFG_OFFSET as u32,
            DEVICE_CFG_LENGTH,
        );
        // 5. PCI cfg access (cfg_type=5) -- no BAR mapping
        add_virtio_cap(&mut config, 5, 0, 0, 0);

        // MSI-X capability on BAR 2.
        // Table at offset 0, PBA at offset 0x800 (both in BAR 2).
        let msix_table = MsixTable::new(msix_vectors, 2, 0, 2, 0x800);
        let msix_cap = msix_table.cap();

        let msix_cap_reg = config.add_capability(CAP_ID_MSIX, 12);
        let dw0 = config.read_reg(msix_cap_reg);
        config.set_reg(
            msix_cap_reg,
            (dw0 & 0x0000_FFFF) | ((msix_cap.msg_ctl as u32) << 16),
        );
        config.set_reg_writable_bits(msix_cap_reg, 0xC000_0000);
        config.set_reg(msix_cap_reg + 1, msix_cap.table_offset_bir);
        config.set_reg(msix_cap_reg + 2, msix_cap.pba_offset_bir);

        // Initialize per-queue configs.
        let queues: Vec<QueueConfig> = queue_max_sizes
            .iter()
            .map(|&max_size| QueueConfig::new(max_size))
            .collect();

        Self {
            device,
            config,
            msix_table,
            msix_cap_reg,
            device_feature_select: 0,
            driver_feature_select: 0,
            driver_features: 0,
            device_status: 0,
            config_generation: 0,
            queue_select: 0,
            msix_config_vector: 0xFFFF,
            queues,
            isr_status: AtomicU8::new(0),
            bar0_gpa,
            bar2_gpa,
            activated: false,
            activation: None,
            host: None,
            notifier,
            queue_kicks: Vec::new(),
            device_features,
            num_queues: num_queues as u16,
        }
    }

    /// Set the host service inherited from the attached PCI root.
    pub fn set_host(&mut self, host: Arc<dyn VirtioDeviceHost>) {
        self.host = Some(host);
    }

    pub fn set_notifier(&mut self, notifier: Arc<dyn MsixNotifier>) {
        self.notifier = notifier;
    }

    /// Return a clone of the inner `Arc<Mutex<Box<dyn VirtioDevice>>>`.
    ///
    /// Used by the HotplugCoordinator to store the Arc at hot-add time so that
    /// `soft_reconnect` can later replace the inner `Box<dyn VirtioDevice>` in-place
    /// without touching the PCIe device tree.
    pub fn device_arc(&self) -> Arc<Mutex<Box<dyn VirtioDevice>>> {
        Arc::clone(&self.device)
    }

    /// Reset transport state for console soft reconnect.
    ///
    /// Clears activation state so that the guest driver's next `DRIVER_OK` write
    /// triggers a fresh `activate_device()` call with new queue kicks.
    ///
    /// Does NOT touch the PCIe config space, MSI-X table, or BAR addresses — the
    /// guest driver continues to see the same PCI device without re-enumeration.
    pub fn reset_for_reconnect(&mut self) {
        self.activation.take();
        self.activated = false;
        self.device_status = 0;
        self.queue_kicks.clear();
    }

    /// Set the ISR status bits (used by device to signal interrupts).
    pub fn set_isr(&self, value: u8) {
        self.isr_status.store(value, Ordering::Release);
    }

    /// Read from the PCI configuration space (dword index).
    pub fn config_read(&self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    /// Write to the PCI configuration space.
    pub fn config_write(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.config.write_reg(reg_idx, offset, data);

        // Intercept MSI-X msg_ctl writes.
        // The msg_ctl field occupies bytes 2-3 of the capability DW. Linux may
        // write the entire DW at offset 0 (4-byte write) or just the upper bytes
        // (2-byte write at offset 2). Handle both cases: any write to this DW
        // that could affect bytes 2-3 should re-read msg_ctl and notify.
        // Simplest correct condition: the write touches any byte at offset >= 2,
        // OR it's a multi-byte write starting at offset 0 that reaches byte 2+.
        if reg_idx == self.msix_cap_reg {
            let write_end = offset as usize + data.len();
            if write_end > 2 {
                let msg_ctl = (self.config.read_reg(self.msix_cap_reg) >> 16) as u16;
                self.msix_table.write_msg_ctl(msg_ctl, &*self.notifier);
            }
        }
    }

    /// Handle a BAR MMIO read.
    pub fn bar_read(&self, bar_idx: u8, offset: u64, data: &mut [u8]) -> bool {
        match bar_idx {
            0 => {
                self.bar0_read(offset, data);
                true
            }
            2 => self.msix_table.bar_read(2, offset, data),
            _ => false,
        }
    }

    /// Handle a BAR MMIO write.
    pub fn bar_write(&mut self, bar_idx: u8, offset: u64, data: &[u8]) -> bool {
        log::trace!("virtio-pci: bar_write bar={bar_idx} offset={offset:#x} data={data:02x?}");
        match bar_idx {
            0 => {
                self.bar0_write(offset, data);
                true
            }
            2 => self.msix_table.bar_write(2, offset, data, &*self.notifier),
            _ => false,
        }
    }

    /// Query BAR regions for MMIO routing.
    pub fn bar_regions(&self) -> Vec<(u8, u64, u64)> {
        vec![(0, self.bar0_gpa, BAR0_SIZE), (2, self.bar2_gpa, BAR2_SIZE)]
    }

    /// Number of MSI-X table entries this device exposes. The PCI root sums
    /// these across slots to size the shared message-interrupt domain.
    pub fn msix_vectors(&self) -> u16 {
        self.msix_table.num_vectors()
    }

    // --- BAR 0 dispatch ---

    fn bar0_read(&self, offset: u64, data: &mut [u8]) {
        if offset < COMMON_CFG_OFFSET + COMMON_CFG_LENGTH as u64 {
            self.common_cfg_read(offset - COMMON_CFG_OFFSET, data);
        } else if offset >= ISR_CFG_OFFSET && offset < ISR_CFG_OFFSET + ISR_CFG_LENGTH as u64 {
            self.isr_read(offset - ISR_CFG_OFFSET, data);
        } else if offset >= DEVICE_CFG_OFFSET
            && offset < DEVICE_CFG_OFFSET + DEVICE_CFG_LENGTH as u64
        {
            self.device_cfg_read(offset - DEVICE_CFG_OFFSET, data);
        } else if offset >= NOTIFY_CFG_OFFSET {
            // Notify region reads are not typical, fill zero.
            data.fill(0);
        } else {
            data.fill(0);
        }
    }

    fn bar0_write(&mut self, offset: u64, data: &[u8]) {
        if offset < COMMON_CFG_OFFSET + COMMON_CFG_LENGTH as u64 {
            self.common_cfg_write(offset - COMMON_CFG_OFFSET, data);
        } else if offset >= ISR_CFG_OFFSET && offset < ISR_CFG_OFFSET + ISR_CFG_LENGTH as u64 {
            // ISR is read-only from guest perspective.
        } else if offset >= DEVICE_CFG_OFFSET
            && offset < DEVICE_CFG_OFFSET + DEVICE_CFG_LENGTH as u64
        {
            self.device_cfg_write(offset - DEVICE_CFG_OFFSET, data);
        } else if offset >= NOTIFY_CFG_OFFSET {
            self.notify_write(offset - NOTIFY_CFG_OFFSET, data);
        }
    }

    // --- Common config read (byte-granularity) ---

    fn common_cfg_read(&self, offset: u64, data: &mut [u8]) {
        // Read 1/2/4 bytes depending on data length, byte-aligned.
        let val = match offset {
            CC_DEVICE_FEATURE_SELECT => self.device_feature_select,
            CC_DEVICE_FEATURE => {
                // Return low or high 32 bits of device features.
                if self.device_feature_select == 0 {
                    self.device_features as u32
                } else if self.device_feature_select == 1 {
                    (self.device_features >> 32) as u32
                } else {
                    0
                }
            }
            CC_DRIVER_FEATURE_SELECT => self.driver_feature_select,
            CC_DRIVER_FEATURE => {
                if self.driver_feature_select == 0 {
                    self.driver_features as u32
                } else if self.driver_feature_select == 1 {
                    (self.driver_features >> 32) as u32
                } else {
                    0
                }
            }
            CC_MSIX_CONFIG => self.msix_config_vector as u32,
            CC_NUM_QUEUES => self.num_queues as u32,
            CC_DEVICE_STATUS => self.device_status as u32,
            CC_CONFIG_GENERATION => self.config_generation as u32,
            CC_QUEUE_SELECT => self.queue_select as u32,
            _ => self.queue_cfg_read(offset),
        };

        // Fill data from value at byte granularity.
        let bytes = val.to_le_bytes();
        // The offset within a register determines which bytes to return.
        // For fields that start at their own offset, we return from byte 0.
        for (i, d) in data.iter_mut().enumerate() {
            *d = if i < 4 { bytes[i] } else { 0 };
        }
    }

    fn queue_cfg_read(&self, offset: u64) -> u32 {
        let qi = self.queue_select as usize;
        if qi >= self.queues.len() {
            return 0;
        }
        let qc = &self.queues[qi];
        match offset {
            CC_QUEUE_SIZE => qc.queue.size as u32,
            CC_QUEUE_MSIX_VECTOR => qc.msix_vector as u32,
            CC_QUEUE_ENABLE => qc.enabled as u32,
            CC_QUEUE_NOTIFY_OFF => qi as u32,
            CC_QUEUE_DESC_LO => qc.desc_lo,
            CC_QUEUE_DESC_HI => qc.desc_hi,
            CC_QUEUE_AVAIL_LO => qc.avail_lo,
            CC_QUEUE_AVAIL_HI => qc.avail_hi,
            CC_QUEUE_USED_LO => qc.used_lo,
            CC_QUEUE_USED_HI => qc.used_hi,
            _ => 0,
        }
    }

    // --- Common config write (byte-granularity) ---

    fn common_cfg_write(&mut self, offset: u64, data: &[u8]) {
        // Read full value depending on write width.
        let val = match data.len() {
            1 => data[0] as u32,
            2 => u16::from_le_bytes([data[0], data[1]]) as u32,
            4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            _ => return,
        };

        match offset {
            CC_DEVICE_FEATURE_SELECT => self.device_feature_select = val,
            CC_DRIVER_FEATURE_SELECT => self.driver_feature_select = val,
            CC_DRIVER_FEATURE => {
                // AND with device-offered features.
                if self.driver_feature_select == 0 {
                    let accepted = val as u64 & (self.device_features & 0xFFFF_FFFF);
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF_0000_0000) | accepted;
                } else if self.driver_feature_select == 1 {
                    let accepted = val as u64 & (self.device_features >> 32);
                    self.driver_features =
                        (self.driver_features & 0x0000_0000_FFFF_FFFF) | (accepted << 32);
                }
            }
            CC_MSIX_CONFIG => self.msix_config_vector = val as u16,
            CC_DEVICE_STATUS => self.write_device_status(val as u8),
            CC_QUEUE_SELECT => {
                self.queue_select = val as u16;
            }
            _ => self.queue_cfg_write(offset, val),
        }
    }

    fn queue_cfg_write(&mut self, offset: u64, val: u32) {
        let qi = self.queue_select as usize;
        if qi >= self.queues.len() {
            return;
        }
        let qc = &mut self.queues[qi];
        match offset {
            CC_QUEUE_SIZE => qc.queue.size = val as u16,
            CC_QUEUE_MSIX_VECTOR => qc.msix_vector = val as u16,
            CC_QUEUE_ENABLE if val != 0 => {
                qc.enabled = true;
                qc.queue.ready = true;
            }
            CC_QUEUE_DESC_LO => qc.desc_lo = val,
            CC_QUEUE_DESC_HI => qc.desc_hi = val,
            CC_QUEUE_AVAIL_LO => qc.avail_lo = val,
            CC_QUEUE_AVAIL_HI => qc.avail_hi = val,
            CC_QUEUE_USED_LO => qc.used_lo = val,
            CC_QUEUE_USED_HI => qc.used_hi = val,
            _ => {}
        }
    }

    // --- Device status FSM ---

    fn write_device_status(&mut self, new_status: u8) {
        log::debug!(
            "virtio-pci: status write new={new_status:#x} old={:#x} activated={}",
            self.device_status,
            self.activated
        );
        if new_status == 0 {
            // Device reset: clear all transport state so the driver can
            // re-initialize from scratch (e.g. after module reload).
            log::info!("virtio-pci: device reset");
            self.device_status = 0;
            self.driver_features = 0;
            self.device_feature_select = 0;
            self.driver_feature_select = 0;
            self.queue_select = 0;
            self.activation.take();
            self.activated = false;
            for qc in &mut self.queues {
                *qc = QueueConfig::new(qc.queue.max_size);
            }
            return;
        }

        self.device_status = new_status;

        // Validate FEATURES_OK transition.
        if new_status & STATUS_FEATURES_OK != 0 && self.driver_features & VIRTIO_F_VERSION_1 == 0 {
            // Must negotiate VERSION_1 for modern virtio.
            log::warn!("virtio-pci: FEATURES_OK rejected -- VIRTIO_F_VERSION_1 not set");
            self.device_status &= !STATUS_FEATURES_OK;
        }

        // DRIVER_OK transition -- activate device.
        if new_status & STATUS_DRIVER_OK != 0 && !self.activated {
            self.activate_device();
        }
    }

    fn activate_device(&mut self) {
        log::info!(
            "virtio-pci: activate_device bar0={:#x} bar2={:#x}",
            self.bar0_gpa,
            self.bar2_gpa
        );
        // Collect queues and create portable queue kicks.
        let enabled_queues: Vec<&QueueConfig> =
            self.queues.iter().filter(|qc| qc.enabled).collect();
        let queues: Vec<Queue> = enabled_queues
            .iter()
            .map(|qc| QueueConfig::to_queue(qc))
            .collect();
        let queue_interrupts = enabled_queues
            .iter()
            .map(|qc| self.notifier.interrupt_for(qc.msix_vector))
            .collect();

        let mut kicks: Vec<Kick> = Vec::new();
        for _ in &queues {
            match Kick::new() {
                Ok(k) => kicks.push(k),
                Err(e) => {
                    log::error!("virtio-pci: failed to create kick: {e}");
                    return;
                }
            }
        }

        self.queue_kicks.clear();
        for kick in &kicks {
            if let Ok(clone) = kick.try_clone() {
                self.queue_kicks.push(clone);
            }
        }

        let Some(host) = self.host.as_ref().map(Arc::clone) else {
            log::error!("virtio-pci: activate failed: no PCI attachment host");
            return;
        };

        let handle = match self.device.lock().expect("device mutex").activate(
            VirtioActivate::with_host_and_queue_interrupts(queues, kicks, host, queue_interrupts),
        ) {
            Ok(handle) => handle,
            Err(e) => {
                log::error!("virtio-pci: device activation failed: {e}");
                return;
            }
        };

        self.activation = Some(handle);
        self.activated = true;
        log::info!("virtio-pci: device activated");
    }

    // --- ISR ---

    fn isr_read(&self, _offset: u64, data: &mut [u8]) {
        // Reading ISR atomically swaps and clears (read-and-clear per spec).
        if !data.is_empty() {
            data[0] = self.isr_status.swap(0, Ordering::AcqRel);
        }
        for d in data.iter_mut().skip(1) {
            *d = 0;
        }
    }

    // --- Device config ---

    fn device_cfg_read(&self, offset: u64, data: &mut [u8]) {
        self.device
            .lock()
            .expect("device mutex")
            .read_config(offset, data);
    }

    fn device_cfg_write(&mut self, offset: u64, data: &[u8]) {
        self.device
            .lock()
            .expect("device mutex")
            .write_config(offset, data);
    }

    // --- Notify ---

    fn notify_write(&self, offset: u64, _data: &[u8]) {
        let queue_idx = offset / NOTIFY_OFF_MULTIPLIER as u64;
        log::debug!("virtio-pci: notify queue {queue_idx}");
        if let Some(kick) = self.queue_kicks.get(queue_idx as usize)
            && let Err(e) = kick.write(1)
        {
            log::warn!("virtio-pci: failed to signal kick for queue {queue_idx}: {e}");
        }
    }
}

#[derive(Debug)]
pub(crate) struct PciVirtioHost {
    host: Arc<dyn PciDeviceHost>,
}

impl PciVirtioHost {
    pub(crate) fn new(host: Arc<dyn PciDeviceHost>) -> Self {
        Self { host }
    }
}

impl VirtioDeviceHost for PciVirtioHost {
    fn shared_memory(&self) -> Vec<Arc<dyn SharedMemory>> {
        self.host.shared_memory().to_vec()
    }

    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let handle = self
            .host
            .spawn(Box::new(move |token| {
                run(VirtioRunToken::from_fn(move || {
                    token.is_shutdown_requested()
                }))
                .map_err(|e| MmioJoinError::Host(e.to_string()))
            }))
            .map_err(|e| ActivateError::InvalidConfig(format!("spawn virtio worker: {e}")))?;
        let handle = Arc::new(Mutex::new(Some(handle)));
        let shutdown_handle = Arc::clone(&handle);
        let join_handle = Arc::clone(&handle);
        Ok(VirtioDeviceHandle::new(
            move || {
                if let Some(handle) = shutdown_handle
                    .lock()
                    .expect("virtio handle poisoned")
                    .as_ref()
                {
                    let _ = handle.shutdown();
                }
            },
            move || {
                if let Some(handle) = join_handle.lock().expect("virtio handle poisoned").take() {
                    handle
                        .join()
                        .map_err(|e| DeviceJoinError::Worker(e.to_string()))?;
                }
                Ok(())
            },
        ))
    }
}

impl Drop for VirtioPciDevice {
    fn drop(&mut self) {
        self.activation.take();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use dillo_virtio::{
        ActivateError, VIRTIO_F_VERSION_1, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
    };

    // --- Mock VirtioDevice for testing ---

    struct MockVirtioDevice {
        device_type: u32,
        queue_max_sizes: Vec<u16>,
        features: u64,
        config_data: Vec<u8>,
        activated: bool,
    }

    impl MockVirtioDevice {
        fn new(device_type: u32, num_queues: usize, features: u64) -> Self {
            Self {
                device_type,
                queue_max_sizes: vec![256; num_queues],
                features,
                config_data: vec![0u8; 64],
                activated: false,
            }
        }
    }

    impl VirtioDevice for MockVirtioDevice {
        fn device_type(&self) -> u32 {
            self.device_type
        }

        fn num_queues(&self) -> usize {
            self.queue_max_sizes.len()
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &self.queue_max_sizes
        }

        fn features(&self) -> u64 {
            self.features
        }

        fn activate(
            &mut self,
            _activation: VirtioActivate,
        ) -> Result<VirtioDeviceHandle, ActivateError> {
            self.activated = true;
            Ok(VirtioDeviceHandle::noop())
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let off = offset as usize;
            for (i, d) in data.iter_mut().enumerate() {
                *d = if off + i < self.config_data.len() {
                    self.config_data[off + i]
                } else {
                    0
                };
            }
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let off = offset as usize;
            for (i, &b) in data.iter().enumerate() {
                if off + i < self.config_data.len() {
                    self.config_data[off + i] = b;
                }
            }
        }
    }

    // --- Helper to create a VirtioPciDevice for testing ---

    use super::VirtioPciDevice;

    const BAR0_GPA: u64 = 0xD000_0000;
    const BAR2_GPA: u64 = 0xD000_1000;

    fn make_test_device(num_queues: usize) -> VirtioPciDevice {
        let features = VIRTIO_F_VERSION_1 | (1 << 29); // VERSION_1 + EVENT_IDX
        let mock = MockVirtioDevice::new(3, num_queues, features); // console device
        let device = Arc::new(Mutex::new(Box::new(mock) as Box<dyn VirtioDevice>));
        let msix_vectors = num_queues as u16 + 1; // one per queue + config
        VirtioPciDevice::new(device, msix_vectors, BAR0_GPA, BAR2_GPA)
    }

    // Helper to read a u16 from BAR 0
    fn bar0_read_u16(dev: &VirtioPciDevice, offset: u64) -> u16 {
        let mut buf = [0u8; 2];
        dev.bar_read(0, offset, &mut buf);
        u16::from_le_bytes(buf)
    }

    // Helper to write a u16 to BAR 0
    fn bar0_write_u16(dev: &mut VirtioPciDevice, offset: u64, val: u16) {
        dev.bar_write(0, offset, &val.to_le_bytes());
    }

    // Helper to read a u32 from BAR 0
    fn bar0_read_u32(dev: &VirtioPciDevice, offset: u64) -> u32 {
        let mut buf = [0u8; 4];
        dev.bar_read(0, offset, &mut buf);
        u32::from_le_bytes(buf)
    }

    // Helper to write a u32 to BAR 0
    fn bar0_write_u32(dev: &mut VirtioPciDevice, offset: u64, val: u32) {
        dev.bar_write(0, offset, &val.to_le_bytes());
    }

    // Helper to read a u8 from BAR 0
    fn bar0_read_u8(dev: &VirtioPciDevice, offset: u64) -> u8 {
        let mut buf = [0u8; 1];
        dev.bar_read(0, offset, &mut buf);
        buf[0]
    }

    // Helper to write a u8 to BAR 0
    fn bar0_write_u8(dev: &mut VirtioPciDevice, offset: u64, val: u8) {
        dev.bar_write(0, offset, &[val]);
    }

    // Common config offsets (from virtio spec 4.1.4.3)
    // Note: these shadow the module-level constants; only those used in tests are kept.
    const CC_DEVICE_FEATURE_SELECT: u64 = 0x00; // u32
    const CC_DEVICE_FEATURE: u64 = 0x04; // u32
    const CC_DRIVER_FEATURE_SELECT: u64 = 0x08; // u32
    const CC_DRIVER_FEATURE: u64 = 0x0C; // u32
    const CC_NUM_QUEUES: u64 = 0x12; // u16
    const CC_DEVICE_STATUS: u64 = 0x14; // u8
    const CC_QUEUE_SELECT: u64 = 0x16; // u16
    const CC_QUEUE_SIZE: u64 = 0x18; // u16
    const CC_QUEUE_NOTIFY_OFF: u64 = 0x1E; // u16
    const CC_QUEUE_DESC_LO: u64 = 0x20; // u32
    const CC_QUEUE_DESC_HI: u64 = 0x24; // u32
    const CC_QUEUE_AVAIL_LO: u64 = 0x28; // u32
    const CC_QUEUE_AVAIL_HI: u64 = 0x2C; // u32
    const CC_QUEUE_USED_LO: u64 = 0x30; // u32
    const CC_QUEUE_USED_HI: u64 = 0x34; // u32

    // BAR 0 region offsets
    const COMMON_CFG_OFFSET: u64 = 0x000;
    const ISR_CFG_OFFSET: u64 = 0x038;
    const DEVICE_CFG_OFFSET: u64 = 0x040;
    const NOTIFY_CFG_OFFSET: u64 = 0x100;

    // Device status bits
    const STATUS_ACKNOWLEDGE: u8 = 1;
    const STATUS_DRIVER: u8 = 2;
    const STATUS_FEATURES_OK: u8 = 8;
    const STATUS_DRIVER_OK: u8 = 4;

    // ==================== Capability Tests ====================

    #[test]
    fn capabilities_five_vendor_caps_present() {
        let dev = make_test_device(2);

        // Walk the capability linked list and collect cfg_type values
        let mut cfg_types = Vec::new();
        let cap_ptr = (dev.config_read(13) & 0xFF) as usize;
        assert!(cap_ptr >= 64, "cap pointer should be in extended space");

        let mut offset = cap_ptr;
        let mut count = 0;
        while offset != 0 && count < 20 {
            let dw0 = dev.config_read(offset / 4);
            let cap_id = dw0 & 0xFF;
            let next = ((dw0 >> 8) & 0xFF) as usize;

            if cap_id == 0x09 {
                // Vendor-specific capability: cfg_type is in byte 3 of dword 0
                // Actually, for virtio caps: dword 0 has cap_vndr(8) + cap_next(8) + cap_len(8) + cfg_type(8)
                let cfg_type = ((dw0 >> 24) & 0xFF) as u8;
                cfg_types.push(cfg_type);
            }

            offset = next;
            count += 1;
        }

        // Must have all 5 virtio capability types
        assert!(cfg_types.contains(&1), "missing common config cap (type 1)");
        assert!(cfg_types.contains(&2), "missing notify cap (type 2)");
        assert!(cfg_types.contains(&3), "missing ISR cap (type 3)");
        assert!(cfg_types.contains(&4), "missing device config cap (type 4)");
        assert!(
            cfg_types.contains(&5),
            "missing PCI cfg access cap (type 5)"
        );
        assert_eq!(cfg_types.len(), 5, "should have exactly 5 vendor caps");
    }

    #[test]
    fn capability_bar_offsets_correct() {
        let dev = make_test_device(2);

        // Walk caps and check BAR/offset/length for each cfg_type
        let cap_ptr = (dev.config_read(13) & 0xFF) as usize;
        let mut offset = cap_ptr;
        let mut count = 0;

        while offset != 0 && count < 20 {
            let dw0 = dev.config_read(offset / 4);
            let cap_id = dw0 & 0xFF;
            let next = ((dw0 >> 8) & 0xFF) as usize;

            if cap_id == 0x09 {
                let cfg_type = ((dw0 >> 24) & 0xFF) as u8;
                // dword 1: bar(8) + padding(24)
                let dw1 = dev.config_read(offset / 4 + 1);
                let bar = (dw1 & 0xFF) as u8;
                // dword 2: offset within BAR
                let bar_offset = dev.config_read(offset / 4 + 2);
                // dword 3: length
                let length = dev.config_read(offset / 4 + 3);

                match cfg_type {
                    1 => {
                        // Common config
                        assert_eq!(bar, 0, "common config should be in BAR 0");
                        assert_eq!(bar_offset, COMMON_CFG_OFFSET as u32);
                        assert_eq!(length, 0x38, "common config is 56 bytes");
                    }
                    2 => {
                        // Notify
                        assert_eq!(bar, 0, "notify should be in BAR 0");
                        assert_eq!(bar_offset, NOTIFY_CFG_OFFSET as u32);
                    }
                    3 => {
                        // ISR
                        assert_eq!(bar, 0, "ISR should be in BAR 0");
                        assert_eq!(bar_offset, ISR_CFG_OFFSET as u32);
                        assert_eq!(length, 4);
                    }
                    4 => {
                        // Device config
                        assert_eq!(bar, 0, "device config should be in BAR 0");
                        assert_eq!(bar_offset, DEVICE_CFG_OFFSET as u32);
                        assert_eq!(length, 64);
                    }
                    5 => {
                        // PCI cfg access -- no BAR mapping expected
                    }
                    _ => panic!("unexpected cfg_type {cfg_type}"),
                }
            }

            offset = next;
            count += 1;
        }
    }

    #[test]
    fn notify_cap_has_20_byte_length() {
        let dev = make_test_device(2);

        // Find notify cap (cfg_type=2) and check it has 20-byte cap_len
        let cap_ptr = (dev.config_read(13) & 0xFF) as usize;
        let mut offset = cap_ptr;
        let mut found = false;

        while offset != 0 {
            let dw0 = dev.config_read(offset / 4);
            let cap_id = dw0 & 0xFF;
            let next = ((dw0 >> 8) & 0xFF) as usize;

            if cap_id == 0x09 {
                let cap_len = ((dw0 >> 16) & 0xFF) as u8;
                let cfg_type = ((dw0 >> 24) & 0xFF) as u8;

                if cfg_type == 2 {
                    assert_eq!(
                        cap_len, 20,
                        "notify cap should be 20 bytes (16 base + 4 multiplier)"
                    );
                    // dword 4 (5th dword) is notify_off_multiplier
                    let multiplier = dev.config_read(offset / 4 + 4);
                    assert_eq!(multiplier, 2, "notify_off_multiplier should be 2");
                    found = true;
                }
            }
            offset = next;
        }
        assert!(found, "notify capability not found");
    }

    // ==================== Common Config Tests ====================

    #[test]
    fn common_config_num_queues() {
        let dev = make_test_device(2);
        let num_queues = bar0_read_u16(&dev, CC_NUM_QUEUES);
        assert_eq!(num_queues, 2);
    }

    #[test]
    fn common_config_device_status_initial() {
        let dev = make_test_device(2);
        let status = bar0_read_u8(&dev, CC_DEVICE_STATUS);
        assert_eq!(status, 0, "initial device status should be 0");
    }

    #[test]
    fn common_config_device_features_low() {
        let mut dev = make_test_device(2);
        // Select feature page 0 (low 32 bits)
        bar0_write_u32(&mut dev, CC_DEVICE_FEATURE_SELECT, 0);
        let features_lo = bar0_read_u32(&dev, CC_DEVICE_FEATURE);
        // Should have EVENT_IDX bit (bit 29)
        assert!(
            features_lo & (1 << 29) != 0,
            "EVENT_IDX should be in low features"
        );
    }

    #[test]
    fn common_config_device_features_high() {
        let mut dev = make_test_device(2);
        // Select feature page 1 (high 32 bits)
        bar0_write_u32(&mut dev, CC_DEVICE_FEATURE_SELECT, 1);
        let features_hi = bar0_read_u32(&dev, CC_DEVICE_FEATURE);
        // Should have VERSION_1 bit (bit 32 overall = bit 0 of high word)
        assert!(features_hi & 1 != 0, "VERSION_1 should be in high features");
    }

    // ==================== Feature Negotiation Tests ====================

    #[test]
    fn feature_negotiation_accepts_version_1() {
        let mut dev = make_test_device(2);

        // ACKNOWLEDGE
        bar0_write_u8(&mut dev, CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        // DRIVER
        bar0_write_u8(
            &mut dev,
            CC_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER,
        );

        // Write driver features: set VERSION_1 (high word bit 0)
        bar0_write_u32(&mut dev, CC_DRIVER_FEATURE_SELECT, 1);
        bar0_write_u32(&mut dev, CC_DRIVER_FEATURE, 1); // VERSION_1

        // Write FEATURES_OK
        bar0_write_u8(
            &mut dev,
            CC_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );

        // Should retain FEATURES_OK
        let status = bar0_read_u8(&dev, CC_DEVICE_STATUS);
        assert!(
            status & STATUS_FEATURES_OK != 0,
            "FEATURES_OK should be set with VERSION_1"
        );
    }

    #[test]
    fn feature_negotiation_rejects_missing_version_1() {
        let mut dev = make_test_device(2);

        // ACKNOWLEDGE + DRIVER
        bar0_write_u8(&mut dev, CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        bar0_write_u8(
            &mut dev,
            CC_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER,
        );

        // Don't set any driver features (VERSION_1 missing)

        // Write FEATURES_OK
        bar0_write_u8(
            &mut dev,
            CC_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );

        // FEATURES_OK should be cleared
        let status = bar0_read_u8(&dev, CC_DEVICE_STATUS);
        assert!(
            status & STATUS_FEATURES_OK == 0,
            "FEATURES_OK should be cleared without VERSION_1"
        );
    }

    #[test]
    fn driver_features_anded_with_device_features() {
        let mut dev = make_test_device(2);

        // Try to set a feature bit NOT offered by device (e.g., bit 5)
        bar0_write_u32(&mut dev, CC_DRIVER_FEATURE_SELECT, 0);
        bar0_write_u32(&mut dev, CC_DRIVER_FEATURE, 0xFFFF_FFFF); // all bits

        // Read back -- should be AND'd with device features
        bar0_write_u32(&mut dev, CC_DRIVER_FEATURE_SELECT, 0);
        let accepted = bar0_read_u32(&dev, CC_DRIVER_FEATURE);
        // Device offers VIRTIO_F_RING_EVENT_IDX (bit 29) in low word
        // Other bits should NOT be set
        let device_features_lo = (VIRTIO_F_VERSION_1 | (1 << 29)) as u32;
        assert_eq!(accepted, device_features_lo);
    }

    // ==================== Device Status FSM Tests ====================

    #[test]
    fn status_fsm_full_sequence() {
        let mut dev = make_test_device(2);

        // ACKNOWLEDGE
        bar0_write_u8(&mut dev, CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        assert_eq!(bar0_read_u8(&dev, CC_DEVICE_STATUS), STATUS_ACKNOWLEDGE);

        // DRIVER
        bar0_write_u8(
            &mut dev,
            CC_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER,
        );
        assert_eq!(
            bar0_read_u8(&dev, CC_DEVICE_STATUS),
            STATUS_ACKNOWLEDGE | STATUS_DRIVER
        );

        // Set VERSION_1 feature
        bar0_write_u32(&mut dev, CC_DRIVER_FEATURE_SELECT, 1);
        bar0_write_u32(&mut dev, CC_DRIVER_FEATURE, 1);

        // FEATURES_OK
        bar0_write_u8(
            &mut dev,
            CC_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        let status = bar0_read_u8(&dev, CC_DEVICE_STATUS);
        assert!(status & STATUS_FEATURES_OK != 0);

        // DRIVER_OK -- no backend notifier in unit tests, but status should be set.
        bar0_write_u8(
            &mut dev,
            CC_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        let status = bar0_read_u8(&dev, CC_DEVICE_STATUS);
        assert!(status & STATUS_DRIVER_OK != 0);
    }

    // ==================== Queue Config Tests ====================

    #[test]
    fn queue_select_switches_active_queue() {
        let mut dev = make_test_device(2);

        // Queue 0 max size
        bar0_write_u16(&mut dev, CC_QUEUE_SELECT, 0);
        let q0_size = bar0_read_u16(&dev, CC_QUEUE_SIZE);
        assert_eq!(q0_size, 256);

        // Queue 1 max size
        bar0_write_u16(&mut dev, CC_QUEUE_SELECT, 1);
        let q1_size = bar0_read_u16(&dev, CC_QUEUE_SIZE);
        assert_eq!(q1_size, 256);
    }

    #[test]
    fn queue_gpas_stored_per_queue() {
        let mut dev = make_test_device(2);

        // Set queue 0 GPAs
        bar0_write_u16(&mut dev, CC_QUEUE_SELECT, 0);
        bar0_write_u32(&mut dev, CC_QUEUE_DESC_LO, 0x1000);
        bar0_write_u32(&mut dev, CC_QUEUE_DESC_HI, 0);
        bar0_write_u32(&mut dev, CC_QUEUE_AVAIL_LO, 0x2000);
        bar0_write_u32(&mut dev, CC_QUEUE_AVAIL_HI, 0);
        bar0_write_u32(&mut dev, CC_QUEUE_USED_LO, 0x3000);
        bar0_write_u32(&mut dev, CC_QUEUE_USED_HI, 0);

        // Set queue 1 GPAs to different values
        bar0_write_u16(&mut dev, CC_QUEUE_SELECT, 1);
        bar0_write_u32(&mut dev, CC_QUEUE_DESC_LO, 0xA000);

        // Switch back to queue 0 and verify GPAs preserved
        bar0_write_u16(&mut dev, CC_QUEUE_SELECT, 0);
        assert_eq!(bar0_read_u32(&dev, CC_QUEUE_DESC_LO), 0x1000);
        assert_eq!(bar0_read_u32(&dev, CC_QUEUE_AVAIL_LO), 0x2000);
        assert_eq!(bar0_read_u32(&dev, CC_QUEUE_USED_LO), 0x3000);

        // Switch to queue 1 and verify its GPA
        bar0_write_u16(&mut dev, CC_QUEUE_SELECT, 1);
        assert_eq!(bar0_read_u32(&dev, CC_QUEUE_DESC_LO), 0xA000);
    }

    #[test]
    fn queue_notify_off_matches_queue_index() {
        let mut dev = make_test_device(4);

        for i in 0..4u16 {
            bar0_write_u16(&mut dev, CC_QUEUE_SELECT, i);
            let notify_off = bar0_read_u16(&dev, CC_QUEUE_NOTIFY_OFF);
            assert_eq!(
                notify_off, i,
                "queue {i} notify_off should equal queue index"
            );
        }
    }

    // ==================== ISR Tests ====================

    #[test]
    fn isr_read_clears_status() {
        let dev = make_test_device(2);

        // Set ISR status (via device internal method -- set_isr takes &self)
        dev.set_isr(0x03);

        // First read should return the value
        let mut buf = [0u8; 4];
        dev.bar_read(0, ISR_CFG_OFFSET, &mut buf);
        assert_eq!(buf[0], 0x03);

        // Second read should return 0 (cleared)
        dev.bar_read(0, ISR_CFG_OFFSET, &mut buf);
        assert_eq!(buf[0], 0x00);
    }

    // ==================== Device Config Tests ====================

    #[test]
    fn device_config_read_delegates_to_device() {
        let dev = make_test_device(2);

        // MockVirtioDevice returns 0 for all config reads initially
        let mut buf = [0xFFu8; 4];
        dev.bar_read(0, DEVICE_CFG_OFFSET, &mut buf);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn device_config_write_delegates_to_device() {
        let mut dev = make_test_device(2);

        // Write to device config region
        dev.bar_write(0, DEVICE_CFG_OFFSET, &[0xAA, 0xBB, 0xCC, 0xDD]);

        // Read it back
        let mut buf = [0u8; 4];
        dev.bar_read(0, DEVICE_CFG_OFFSET, &mut buf);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    // ==================== BAR Region Tests ====================

    #[test]
    fn bar_regions_returns_bar0_and_bar2() {
        let dev = make_test_device(2);
        let regions = dev.bar_regions();
        assert_eq!(regions.len(), 2);

        let bar0 = regions.iter().find(|r| r.0 == 0).unwrap();
        assert_eq!(bar0.1, BAR0_GPA);
        assert_eq!(bar0.2, 4096);

        let bar2 = regions.iter().find(|r| r.0 == 2).unwrap();
        assert_eq!(bar2.1, BAR2_GPA);
        assert_eq!(bar2.2, 4096);
    }

    // ==================== PCI Config Space Tests ====================

    #[test]
    fn pci_vendor_device_id() {
        let dev = make_test_device(2);
        let val = dev.config_read(0);
        // Vendor: 0x1AF4 (Red Hat)
        assert_eq!(val & 0xFFFF, 0x1AF4, "vendor ID");
        // Device: 0x1040 + device_type (3 for console) = 0x1043
        assert_eq!(val >> 16, 0x1043, "device ID for console");
    }

    #[test]
    fn config_write_dispatches() {
        let mut dev = make_test_device(2);
        // Write to command register (reg 1) -- should be writable
        dev.config_write(1, 0, &[0x07, 0x00]);
        let val = dev.config_read(1);
        assert_eq!(val & 0xFFFF, 0x0007);
    }

    // ==================== Byte-Granularity Access Tests ====================

    #[test]
    fn common_config_byte_access() {
        let mut dev = make_test_device(2);

        // Write device_status as single byte
        bar0_write_u8(&mut dev, CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        assert_eq!(bar0_read_u8(&dev, CC_DEVICE_STATUS), STATUS_ACKNOWLEDGE);

        // Write queue_select as u16
        bar0_write_u16(&mut dev, CC_QUEUE_SELECT, 1);
        assert_eq!(bar0_read_u16(&dev, CC_QUEUE_SELECT), 1);
    }
}
