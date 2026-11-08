// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! virtio-mmio (modern, version 2) transport — the microVM profile's
//! device-attach path (F6). Mirrors the virtio-pci transport's role but over a
//! flat MMIO register file at the DTB's `virtio_mmio@…` window, with a wired
//! interrupt instead of MSI-X.
//!
//! The register file is driven from the vCPU thread (via the MMIO bus); the
//! backing [`VirtioDevice`]'s I/O worker runs on its own thread and raises the
//! injected wired IRQ when it completes buffers. On `DRIVER_OK` the configured
//! queues are handed to `activate`; a `QueueNotify` write kicks the matching
//! queue's [`Kick`].

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use dillo_mmio::{
    Interrupt, MmioAttachment, MmioDevice, MmioError, MmioInterrupt, MmioInterruptRequirement,
    MmioJoinError, MmioWindow, MmioWriteOutcome, SharedMemory,
};
use dillo_virtio::queue::Queue;
use dillo_virtio::{
    ActivateError, DeviceJoinError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
    VirtioDeviceHost, VirtioRunToken,
};
use vm_memory::GuestAddress;

// Register offsets (virtio-mmio v2; see the virtio spec §4.2.2).
const MAGIC: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR_ID: u64 = 0x00c;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_DRIVER_LOW: u64 = 0x090;
const QUEUE_DRIVER_HIGH: u64 = 0x094;
const QUEUE_DEVICE_LOW: u64 = 0x0a0;
const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
const SHM_LEN_LOW: u64 = 0x0b0;
const SHM_LEN_HIGH: u64 = 0x0b4;
const SHM_BASE_LOW: u64 = 0x0b8;
const SHM_BASE_HIGH: u64 = 0x0bc;
const CONFIG_GENERATION: u64 = 0x0fc;
const CONFIG: u64 = 0x100;

const MAGIC_VALUE: u32 = 0x7472_6976; // "virt"
const STATUS_DRIVER_OK: u32 = 0x4;
/// InterruptStatus bit: used-buffer notification (a virtqueue completed).
const INT_VRING: u32 = 0x1;

/// An unoccupied, declared virtio-mmio slot (Virtio 1.2, section 4.2.2).
#[derive(Debug)]
pub struct EmptySlot {
    pub window: MmioWindow,
}

impl MmioDevice for EmptySlot {
    fn windows(&self) -> &[MmioWindow] {
        std::slice::from_ref(&self.window)
    }

    fn read(&self, _window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
        let value: u32 = match offset {
            MAGIC => MAGIC_VALUE,
            VERSION => 2,
            _ => 0,
        };
        let bytes = value.to_le_bytes();
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = bytes.get(index).copied().unwrap_or(0);
        }
        Ok(())
    }

    fn write(
        &self,
        _window: MmioWindow,
        _offset: u64,
        _data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError> {
        Ok(MmioWriteOutcome::Continue)
    }
}

#[derive(Clone)]
pub struct WiredIrq {
    intid: u32,
    interrupt: Arc<RwLock<Option<Interrupt>>>,
}

impl std::fmt::Debug for WiredIrq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WiredIrq")
            .field("intid", &self.intid)
            .finish_non_exhaustive()
    }
}

impl WiredIrq {
    pub fn new(intid: u32, interrupt: Interrupt) -> Self {
        Self {
            intid,
            interrupt: Arc::new(RwLock::new(Some(interrupt))),
        }
    }

    pub fn unresolved(intid: u32) -> Self {
        Self {
            intid,
            interrupt: Arc::new(RwLock::new(None)),
        }
    }

    pub fn intid(&self) -> u32 {
        self.intid
    }

    pub fn set_interrupt(&self, interrupt: Interrupt) {
        *self
            .interrupt
            .write()
            .expect("virtio-mmio IRQ lock poisoned") = Some(interrupt);
    }

    fn set(&self, level: bool) {
        if let Some(interrupt) = self
            .interrupt
            .read()
            .expect("virtio-mmio IRQ lock poisoned")
            .as_ref()
            && let Err(e) = interrupt.set_level(level)
        {
            log::warn!(
                "virtio-mmio wired IRQ {} set_level({level}) failed: {e}",
                self.intid
            );
        }
    }
}

#[derive(Clone, Copy, Default)]
struct QueueCfg {
    max: u16,
    num: u16,
    ready: bool,
    desc: u64,
    avail: u64,
    used: u64,
}

struct Inner {
    device: Box<dyn VirtioDevice>,
    device_id: u32,
    device_features: u64,
    driver_features: u64,
    dev_feat_sel: u32,
    drv_feat_sel: u32,
    queue_sel: usize,
    queues: Vec<QueueCfg>,
    status: u32,
    activated: bool,
    activation: Option<VirtioDeviceHandle>,
    host: Option<Arc<MmioVirtioHost>>,
    /// One per queue after activation; `QueueNotify` writes kick these.
    kicks: Vec<Kick>,
}

/// A single virtio-mmio transport slot bound to one [`VirtioDevice`].
pub struct VirtioMmio {
    window: MmioWindow,
    interrupts: Vec<MmioInterruptRequirement>,
    inner: Mutex<Inner>,
    /// Shared with the device's interrupt closure (raised on the worker thread,
    /// read here on `INTERRUPT_STATUS`).
    int_status: std::sync::Arc<AtomicU32>,
    /// Wired interrupt number from the DTB node's `interrupts`.
    irq: WiredIrq,
}

impl std::fmt::Debug for VirtioMmio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioMmio")
            .field("window", &self.window)
            .field("int_status", &self.int_status)
            .field("irq", &self.irq)
            .finish_non_exhaustive()
    }
}

impl VirtioMmio {
    pub fn new(
        window: MmioWindow,
        device: Box<dyn VirtioDevice>,
        int_status: std::sync::Arc<AtomicU32>,
        irq: WiredIrq,
    ) -> Self {
        Self::with_interrupt_requirements(window, device, int_status, irq, Vec::new())
    }

    pub fn with_interrupt_requirement(
        window: MmioWindow,
        device: Box<dyn VirtioDevice>,
        int_status: std::sync::Arc<AtomicU32>,
        irq: WiredIrq,
        interrupt: MmioInterruptRequirement,
    ) -> Self {
        Self::with_interrupt_requirements(window, device, int_status, irq, vec![interrupt])
    }

    fn with_interrupt_requirements(
        window: MmioWindow,
        device: Box<dyn VirtioDevice>,
        int_status: std::sync::Arc<AtomicU32>,
        irq: WiredIrq,
        interrupts: Vec<MmioInterruptRequirement>,
    ) -> Self {
        let device_id = device.device_type();
        let device_features = device.features();
        let maxs = device.queue_max_sizes().to_vec();
        let queues = maxs
            .iter()
            .map(|&m| QueueCfg {
                max: m,
                num: m,
                ..Default::default()
            })
            .collect();
        Self {
            window,
            interrupts,
            inner: Mutex::new(Inner {
                device,
                device_id,
                device_features,
                driver_features: 0,
                dev_feat_sel: 0,
                drv_feat_sel: 0,
                queue_sel: 0,
                queues,
                status: 0,
                activated: false,
                activation: None,
                host: None,
                kicks: Vec::new(),
            }),
            int_status,
            irq,
        }
    }

    pub fn set_attachment(&self, attachment: Arc<dyn MmioAttachment>) {
        if let Some(MmioInterrupt::Line(interrupt)) = attachment.interrupts().first() {
            self.irq.set_interrupt(interrupt.clone());
        }
        self.inner
            .lock()
            .expect("virtio-mmio poisoned")
            .host
            .replace(Arc::new(MmioVirtioHost { attachment }));
    }

    pub fn read(&self, offset: u64, data: &mut [u8]) -> bool {
        let g = self.inner.lock().expect("virtio-mmio poisoned");
        if offset >= CONFIG {
            g.device.read_config(offset - CONFIG, data);
            return true;
        }
        let sel = g.queue_sel;
        let val: u32 = match offset {
            MAGIC => MAGIC_VALUE,
            VERSION => 2,
            DEVICE_ID => g.device_id,
            VENDOR_ID => 0x554d_4551, // "QEMU" — arbitrary
            DEVICE_FEATURES => {
                if g.dev_feat_sel == 1 {
                    (g.device_features >> 32) as u32
                } else {
                    g.device_features as u32
                }
            }
            QUEUE_NUM_MAX => g.queues.get(sel).map_or(0, |q| u32::from(q.max)),
            QUEUE_READY => g.queues.get(sel).map_or(0, |q| u32::from(q.ready)),
            INTERRUPT_STATUS => self.int_status.load(Ordering::SeqCst),
            STATUS => g.status,
            // Config never changes mid-flight, so the generation is always 0.
            // Kept as a named arm (not folded into the wildcard) to document the
            // register map; its body coincides with the unhandled-register case.
            #[allow(clippy::match_same_arms)]
            CONFIG_GENERATION => 0,
            // No shared memory regions: virtio 1.2 §4.2.2 requires all ones.
            SHM_LEN_LOW | SHM_LEN_HIGH | SHM_BASE_LOW | SHM_BASE_HIGH => u32::MAX,
            _ => 0,
        };
        let bytes = val.to_le_bytes();
        for (i, b) in data.iter_mut().enumerate() {
            *b = bytes.get(i).copied().unwrap_or(0);
        }
        true
    }

    pub fn write(&self, offset: u64, data: &[u8]) -> bool {
        let mut g = self.inner.lock().expect("virtio-mmio poisoned");
        if offset >= CONFIG {
            g.device.write_config(offset - CONFIG, data);
            return true;
        }
        let mut le = [0u8; 4];
        for (i, b) in data.iter().take(4).enumerate() {
            le[i] = *b;
        }
        let val = u32::from_le_bytes(le);
        let sel = g.queue_sel;
        match offset {
            DEVICE_FEATURES_SEL => g.dev_feat_sel = val,
            DRIVER_FEATURES_SEL => g.drv_feat_sel = val,
            DRIVER_FEATURES => {
                if g.drv_feat_sel <= 1 {
                    let shift = g.drv_feat_sel * 32;
                    let mask = 0xffff_ffffu64 << shift;
                    g.driver_features = (g.driver_features & !mask)
                        | ((u64::from(val) << shift) & g.device_features);
                }
            }
            QUEUE_SEL => g.queue_sel = val as usize,
            QUEUE_NUM => {
                if let Some(q) = g.queues.get_mut(sel) {
                    q.num = val as u16;
                }
            }
            QUEUE_READY => {
                if let Some(q) = g.queues.get_mut(sel) {
                    q.ready = val & 1 != 0;
                }
            }
            QUEUE_DESC_LOW => set_lo(&mut g, sel, |q| &mut q.desc, val),
            QUEUE_DESC_HIGH => set_hi(&mut g, sel, |q| &mut q.desc, val),
            QUEUE_DRIVER_LOW => set_lo(&mut g, sel, |q| &mut q.avail, val),
            QUEUE_DRIVER_HIGH => set_hi(&mut g, sel, |q| &mut q.avail, val),
            QUEUE_DEVICE_LOW => set_lo(&mut g, sel, |q| &mut q.used, val),
            QUEUE_DEVICE_HIGH => set_hi(&mut g, sel, |q| &mut q.used, val),
            QUEUE_NOTIFY => {
                if let Some(k) = g.kicks.get(val as usize) {
                    let _ = k.write(1);
                }
            }
            INTERRUPT_ACK => {
                self.int_status.fetch_and(!val, Ordering::SeqCst);
                if self.int_status.load(Ordering::SeqCst) == 0 {
                    self.irq.set(false);
                }
            }
            STATUS => {
                g.status = val;
                if val == 0 {
                    // Reset: the driver will re-negotiate. Devices stay; a real
                    // re-activation path is out of scope for the boot console.
                    g.activation.take();
                    g.kicks.clear();
                    g.activated = false;
                    g.driver_features = 0;
                    g.drv_feat_sel = 0;
                } else {
                    maybe_activate(
                        &mut g,
                        self.window,
                        Self::interrupt(Arc::clone(&self.int_status), self.irq.clone()),
                    );
                }
            }
            _ => {}
        }
        true
    }

    /// An interrupt closure for the backing device: sets the used-buffer status
    /// bit and asserts the wired IRQ. Clone of `int_status`/`irq` so it can run
    /// on the device's worker thread.
    pub fn interrupt(
        int_status: std::sync::Arc<AtomicU32>,
        irq: WiredIrq,
    ) -> dillo_mmio::Interrupt {
        dillo_mmio::Interrupt::from_fn(move || {
            int_status.fetch_or(INT_VRING, Ordering::SeqCst);
            irq.set(true);
        })
    }
}

impl Drop for VirtioMmio {
    fn drop(&mut self) {
        self.inner
            .lock()
            .expect("virtio-mmio poisoned")
            .activation
            .take();
    }
}

impl MmioDevice for VirtioMmio {
    fn windows(&self) -> &[MmioWindow] {
        std::slice::from_ref(&self.window)
    }

    fn interrupts(&self) -> &[MmioInterruptRequirement] {
        &self.interrupts
    }

    fn read(&self, _window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
        Self::read(self, offset, data)
            .then_some(())
            .ok_or(MmioError::Unsupported)
    }

    fn write(
        &self,
        _window: MmioWindow,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError> {
        Self::write(self, offset, data)
            .then_some(MmioWriteOutcome::Continue)
            .ok_or(MmioError::Unsupported)
    }
}

fn set_lo(g: &mut Inner, sel: usize, field: impl Fn(&mut QueueCfg) -> &mut u64, val: u32) {
    if let Some(q) = g.queues.get_mut(sel) {
        let f = field(q);
        *f = (*f & 0xFFFF_FFFF_0000_0000) | u64::from(val);
    }
}

fn set_hi(g: &mut Inner, sel: usize, field: impl Fn(&mut QueueCfg) -> &mut u64, val: u32) {
    if let Some(q) = g.queues.get_mut(sel) {
        let f = field(q);
        *f = (*f & 0x0000_0000_FFFF_FFFF) | (u64::from(val) << 32);
    }
}

fn maybe_activate(g: &mut Inner, window: MmioWindow, interrupt: Interrupt) {
    if g.activated || g.status & STATUS_DRIVER_OK == 0 {
        return;
    }
    let Some(host) = g.host.as_ref().map(Arc::clone) else {
        log::error!("virtio-mmio: activate failed: no MMIO attachment host");
        return;
    };
    let queues: Vec<Queue> = g
        .queues
        .iter()
        .map(|qc| {
            let mut q = Queue::new(qc.max);
            q.size = qc.num;
            q.ready = qc.ready;
            q.desc_table = GuestAddress(qc.desc);
            q.avail_ring = GuestAddress(qc.avail);
            q.used_ring = GuestAddress(qc.used);
            q
        })
        .collect();
    let kicks: Vec<Kick> = match (0..queues.len())
        .map(|index| {
            let value = u32::try_from(index).map_err(|_| std::io::ErrorKind::InvalidInput)?;
            match host
                .attachment
                .write_notification(window, QUEUE_NOTIFY, value)?
            {
                Some(notification) => Ok(Kick::from_notification(notification)),
                None => Kick::new(),
            }
        })
        .collect::<std::io::Result<Vec<_>>>()
    {
        Ok(k) => k,
        Err(e) => {
            log::error!("virtio-mmio: kick alloc failed: {e}");
            return;
        }
    };
    g.kicks = kicks.iter().filter_map(|k| k.try_clone().ok()).collect();
    let queue_interrupts = queues.iter().map(|_| Some(interrupt.clone())).collect();
    let negotiated = g.driver_features;
    let handle = match g.device.activate(
        VirtioActivate::with_host_and_queue_interrupts(queues, kicks, host, queue_interrupts)
            .with_negotiated_features(negotiated),
    ) {
        Ok(handle) => handle,
        Err(e) => {
            log::error!("virtio-mmio: activate failed: {e}");
            g.kicks.clear();
            return;
        }
    };
    g.activation = Some(handle);
    g.activated = true;
    log::info!("virtio-mmio: device-id {} activated", g.device_id);
}

#[derive(Debug)]
struct MmioVirtioHost {
    attachment: Arc<dyn MmioAttachment>,
}

impl VirtioDeviceHost for MmioVirtioHost {
    fn shared_memory(&self) -> Vec<Arc<dyn SharedMemory>> {
        self.attachment.shared_memory().to_vec()
    }

    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let handle = Arc::clone(&self.attachment)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestAttachment {
        notifications: Mutex<Vec<std::sync::Weak<TestNotification>>>,
        accelerate: bool,
        registration_error: bool,
    }

    #[derive(Debug)]
    struct TestNotification(Kick);

    impl dillo_mmio::WriteNotification for TestNotification {
        fn read(&self) -> std::io::Result<u64> {
            self.0.read()
        }
        fn write(&self, count: u64) -> std::io::Result<()> {
            self.0.write(count)
        }
    }

    impl MmioAttachment for TestAttachment {
        fn interrupts(&self) -> &[MmioInterrupt] {
            &[]
        }
        fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
            &[]
        }
        fn spawn(
            self: Arc<Self>,
            _: dillo_mmio::MmioDeviceRun,
        ) -> Result<dillo_mmio::MmioDeviceHandle, dillo_mmio::MmioSpawnError> {
            unreachable!("test device starts no workers")
        }
        fn write_notification(
            &self,
            window: MmioWindow,
            offset: u64,
            value: u32,
        ) -> std::io::Result<Option<Arc<dyn dillo_mmio::WriteNotification>>> {
            if self.registration_error {
                return Err(std::io::ErrorKind::OutOfMemory.into());
            }
            if !self.accelerate {
                return Ok(None);
            }
            assert_eq!(window.base, 0x1000);
            assert_eq!(offset, QUEUE_NOTIFY);
            assert_eq!(value, 0);
            let mut registrations = self.notifications.lock().unwrap();
            assert!(registrations.iter().all(|weak| weak.strong_count() == 0));
            let notification = Arc::new(TestNotification(Kick::new()?));
            registrations.push(Arc::downgrade(&notification));
            Ok(Some(notification))
        }
    }

    struct TestDevice {
        fail: bool,
    }

    impl VirtioDevice for TestDevice {
        fn device_type(&self) -> u32 {
            2
        }
        fn num_queues(&self) -> usize {
            1
        }
        fn queue_max_sizes(&self) -> &[u16] {
            &[16]
        }
        fn features(&self) -> u64 {
            1 << 32
        }
        fn activate(
            &mut self,
            mut activation: VirtioActivate,
        ) -> Result<VirtioDeviceHandle, ActivateError> {
            if self.fail {
                return Err(ActivateError::InvalidConfig("test failure".into()));
            }
            let kick = activation.take_queue_evts().remove(0);
            let reader = kick.clone();
            let worker = std::thread::spawn(move || {
                assert_eq!(reader.read().unwrap(), 1);
            });
            Ok(VirtioDeviceHandle::new(
                move || kick.write(1).unwrap(),
                move || {
                    worker.join().unwrap();
                    Ok(())
                },
            ))
        }
        fn read_config(&self, _: u64, _: &mut [u8]) {}
        fn write_config(&mut self, _: u64, _: &[u8]) {}
    }

    #[test]
    fn accelerated_notifications_are_released_on_reset_and_failed_activation() {
        for fail in [false, true] {
            let attachment = Arc::new(TestAttachment {
                accelerate: true,
                ..Default::default()
            });
            let transport = VirtioMmio::new(
                MmioWindow {
                    base: 0x1000,
                    size: 0x1000,
                },
                Box::new(TestDevice { fail }),
                Arc::new(AtomicU32::new(0)),
                WiredIrq::unresolved(1),
            );
            transport.set_attachment(attachment.clone());
            for _ in 0..2 {
                transport.write(STATUS, &STATUS_DRIVER_OK.to_le_bytes());
                let weak = attachment
                    .notifications
                    .lock()
                    .unwrap()
                    .last()
                    .unwrap()
                    .clone();
                assert_eq!(weak.strong_count() > 0, !fail);
                transport.write(STATUS, &0u32.to_le_bytes());
                assert_eq!(weak.strong_count(), 0);
            }
        }
    }

    #[test]
    fn unsupported_notifications_activate_but_registration_errors_do_not() {
        for registration_error in [false, true] {
            let attachment = Arc::new(TestAttachment {
                registration_error,
                ..Default::default()
            });
            let transport = VirtioMmio::new(
                MmioWindow {
                    base: 0x1000,
                    size: 0x1000,
                },
                Box::new(TestDevice { fail: false }),
                Arc::new(AtomicU32::new(0)),
                WiredIrq::unresolved(1),
            );
            transport.set_attachment(attachment);
            transport.write(STATUS, &STATUS_DRIVER_OK.to_le_bytes());
            assert_eq!(
                transport.inner.lock().unwrap().activated,
                !registration_error
            );
            transport.write(STATUS, &0u32.to_le_bytes());
            assert!(transport.inner.lock().unwrap().kicks.is_empty());
        }
    }

    #[test]
    fn empty_slot_passes_transport_probe_without_a_device() {
        let slot = EmptySlot {
            window: MmioWindow {
                base: 0x1000,
                size: 0x1000,
            },
        };
        assert_eq!(slot.windows(), &[slot.window]);
        assert!(slot.interrupts().is_empty());
        assert!(slot.shared_memory().is_empty());
        for (offset, expected) in [(0, 0x7472_6976), (4, 2), (8, 0)] {
            let mut value = [0xff; 4];
            slot.read(slot.window, offset, &mut value).unwrap();
            assert_eq!(u32::from_le_bytes(value), expected);
        }
        slot.write(slot.window, STATUS, &4u32.to_le_bytes())
            .unwrap();
        let mut status = [0xff; 4];
        slot.read(slot.window, STATUS, &mut status).unwrap();
        assert_eq!(status, [0; 4]);
    }
}
