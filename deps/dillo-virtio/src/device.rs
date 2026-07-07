// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! VirtioDevice trait defining the device contract for transport layers.

use dillo_mmio::Interrupt;
use dillo_mmio::SharedMemory;

use crate::kick::Kick;
use crate::memory::{NullVirtioMemory, SharedVirtioMemory, VirtioMemory};
use crate::queue::{NullQueueMemory, Queue, QueueMemory, SharedQueueMemory};

use std::sync::Arc;

/// Transport-resolved activation inputs for one virtio device.
pub struct VirtioActivate {
    shared_memory: Vec<Arc<dyn SharedMemory>>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queues: Vec<Queue>,
    queue_evts: Vec<Kick>,
    queue_interrupts: Vec<Option<Interrupt>>,
    host: Option<Arc<dyn VirtioDeviceHost>>,
}

impl std::fmt::Debug for VirtioActivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioActivate")
            .field("shared_memory_count", &self.shared_memory.len())
            .field("queue_memory", &"QueueMemory")
            .field("buffer_memory", &"VirtioMemory")
            .field("queues", &self.queues)
            .field("queue_evts", &self.queue_evts)
            .field("queue_interrupt_count", &self.queue_interrupts.len())
            .field("has_host", &self.host.is_some())
            .finish()
    }
}

impl VirtioActivate {
    pub fn new(queues: Vec<Queue>, queue_evts: Vec<Kick>) -> Self {
        Self {
            shared_memory: Vec::new(),
            queue_memory: Arc::new(NullQueueMemory),
            buffer_memory: Arc::new(NullVirtioMemory),
            queues,
            queue_evts,
            queue_interrupts: Vec::new(),
            host: None,
        }
    }

    pub fn with_host(
        queues: Vec<Queue>,
        queue_evts: Vec<Kick>,
        host: Arc<dyn VirtioDeviceHost>,
    ) -> Self {
        let shared_memory = host.shared_memory();
        let queue_memory = Self::make_queue_memory(&shared_memory);
        let buffer_memory = Self::make_buffer_memory(&shared_memory);
        Self {
            shared_memory,
            queue_memory,
            buffer_memory,
            queues,
            queue_evts,
            queue_interrupts: Vec::new(),
            host: Some(host),
        }
    }

    pub fn with_host_and_queue_interrupts(
        queues: Vec<Queue>,
        queue_evts: Vec<Kick>,
        host: Arc<dyn VirtioDeviceHost>,
        queue_interrupts: Vec<Option<Interrupt>>,
    ) -> Self {
        let shared_memory = host.shared_memory();
        let queue_memory = Self::make_queue_memory(&shared_memory);
        let buffer_memory = Self::make_buffer_memory(&shared_memory);
        Self {
            shared_memory,
            queue_memory,
            buffer_memory,
            queues,
            queue_evts,
            queue_interrupts,
            host: Some(host),
        }
    }

    pub fn with_shared_memory(
        shared_memory: Vec<Arc<dyn SharedMemory>>,
        queues: Vec<Queue>,
        queue_evts: Vec<Kick>,
        host: Arc<dyn VirtioDeviceHost>,
    ) -> Self {
        let queue_memory = Self::make_queue_memory(&shared_memory);
        let buffer_memory = Self::make_buffer_memory(&shared_memory);
        Self {
            shared_memory,
            queue_memory,
            buffer_memory,
            queues,
            queue_evts,
            queue_interrupts: Vec::new(),
            host: Some(host),
        }
    }

    fn make_queue_memory(shared_memory: &[Arc<dyn SharedMemory>]) -> Arc<dyn QueueMemory> {
        if shared_memory.is_empty() {
            Arc::new(NullQueueMemory)
        } else {
            Arc::new(SharedQueueMemory::new(shared_memory.to_vec()))
        }
    }

    fn make_buffer_memory(shared_memory: &[Arc<dyn SharedMemory>]) -> Arc<dyn VirtioMemory> {
        if shared_memory.is_empty() {
            Arc::new(NullVirtioMemory)
        } else {
            Arc::new(SharedVirtioMemory::new(shared_memory.to_vec()))
        }
    }

    pub fn queue_memory(&self) -> Arc<dyn QueueMemory> {
        Arc::clone(&self.queue_memory)
    }

    pub fn buffer_memory(&self) -> Arc<dyn VirtioMemory> {
        Arc::clone(&self.buffer_memory)
    }

    pub fn host(&self) -> Result<Arc<dyn VirtioDeviceHost>, ActivateError> {
        self.host
            .as_ref()
            .map(Arc::clone)
            .ok_or(ActivateError::MissingHost)
    }

    pub fn queue_interrupt(&self, index: usize) -> Option<Interrupt> {
        self.queue_interrupts
            .get(index)
            .and_then(std::clone::Clone::clone)
    }

    pub fn take_queues(&mut self) -> Vec<Queue> {
        std::mem::take(&mut self.queues)
    }

    pub fn take_queue_evts(&mut self) -> Vec<Kick> {
        std::mem::take(&mut self.queue_evts)
    }
}

/// Errors returned by [`VirtioDevice::activate`].
#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    /// The transport attempted to activate a device before machine attachment.
    #[error("virtio activation requires a machine-provided device host")]
    MissingHost,

    /// The device received an invalid configuration.
    #[error("invalid device configuration: {0}")]
    InvalidConfig(String),

    /// An internal I/O error occurred during activation.
    #[error("activation I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Error returned when joining a running virtio device host.
#[derive(Debug, thiserror::Error)]
pub enum DeviceJoinError {
    /// A worker thread panicked.
    #[error("virtio device worker panicked")]
    Panicked,

    /// Device-specific worker failure.
    #[error("virtio device worker failed: {0}")]
    Worker(String),
}

/// Token passed to a virtio device worker started by the transport host.
#[derive(Clone)]
pub struct VirtioRunToken {
    is_shutdown_requested: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for VirtioRunToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioRunToken").finish_non_exhaustive()
    }
}

impl VirtioRunToken {
    pub fn from_fn(is_shutdown_requested: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            is_shutdown_requested: Arc::new(is_shutdown_requested),
        }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        (self.is_shutdown_requested)()
    }
}

/// Host-side execution service for virtio device workers.
pub trait VirtioDeviceHost: Send + Sync + std::fmt::Debug {
    fn shared_memory(&self) -> Vec<Arc<dyn SharedMemory>> {
        Vec::new()
    }

    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError>;
}

/// Runtime handle for workers started by one virtio device activation.
pub struct VirtioDeviceHandle {
    shutdown: Option<Box<dyn FnOnce() + Send>>,
    join: Option<Box<dyn FnOnce() -> Result<(), DeviceJoinError> + Send>>,
}

impl std::fmt::Debug for VirtioDeviceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioDeviceHandle").finish_non_exhaustive()
    }
}

impl VirtioDeviceHandle {
    pub fn new(
        shutdown: impl FnOnce() + Send + 'static,
        join: impl FnOnce() -> Result<(), DeviceJoinError> + Send + 'static,
    ) -> Self {
        Self {
            shutdown: Some(Box::new(shutdown)),
            join: Some(Box::new(join)),
        }
    }

    pub fn noop() -> Self {
        Self::new(|| {}, || Ok(()))
    }

    pub fn shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            shutdown();
        }
    }

    pub fn join(mut self) -> Result<(), DeviceJoinError> {
        self.shutdown();
        if let Some(join) = self.join.take() {
            join()
        } else {
            Ok(())
        }
    }

    fn log_join_error(e: &DeviceJoinError) {
        log::warn!("virtio device worker join failed during drop: {e}");
    }
}

impl Drop for VirtioDeviceHandle {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(join) = self.join.take()
            && let Err(e) = join()
        {
            Self::log_join_error(&e);
        }
    }
}

/// Transport-agnostic virtio device contract.
///
/// Implementors define device-specific behaviour; the transport layer
/// handles capability layout, feature
/// negotiation, and queue setup before calling [`activate`](Self::activate).
pub trait VirtioDevice: Send {
    /// Virtio device type identifier (e.g. 1 = net, 2 = block, 3 = console).
    fn device_type(&self) -> u32;

    /// Number of virtqueues this device uses.
    fn num_queues(&self) -> usize;

    /// Maximum queue size for each virtqueue.
    fn queue_max_sizes(&self) -> &[u16];

    /// Device feature bits (including `VIRTIO_F_VERSION_1`).
    fn features(&self) -> u64;

    /// Activate the device with negotiated queues and notification kicks.
    ///
    /// The transport calls this after feature negotiation and queue setup are
    /// complete. The device typically spawns an I/O thread that blocks on
    /// `queue_evts` and processes descriptors via the provided queues.
    ///
    /// Queue notifications are [`Kick`]s. Backends may accelerate the guest
    /// notify path internally, but devices only observe target-neutral kicks.
    fn activate(&mut self, activation: VirtioActivate)
    -> Result<VirtioDeviceHandle, ActivateError>;

    /// Read device-specific configuration space.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Write device-specific configuration space.
    fn write_config(&mut self, offset: u64, data: &[u8]);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;

    #[derive(Debug)]
    struct TestDeviceHost;

    impl VirtioDeviceHost for TestDeviceHost {
        fn spawn(
            &self,
            run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
        ) -> Result<VirtioDeviceHandle, ActivateError> {
            let shutdown = Arc::new(AtomicBool::new(false));
            let token_shutdown = Arc::clone(&shutdown);
            let token = VirtioRunToken::from_fn(move || token_shutdown.load(Ordering::Acquire));
            let join = std::thread::spawn(move || run(token));
            Ok(VirtioDeviceHandle::new(
                move || shutdown.store(true, Ordering::Release),
                move || match join.join() {
                    Ok(result) => result,
                    Err(_) => Err(DeviceJoinError::Panicked),
                },
            ))
        }
    }

    #[test]
    fn handle_shutdown_runs_once_before_join() {
        let stopped = Arc::new(AtomicBool::new(false));
        let shutdown_stopped = Arc::clone(&stopped);
        let join_stopped = Arc::clone(&stopped);
        let mut handle = VirtioDeviceHandle::new(
            move || shutdown_stopped.store(true, Ordering::Release),
            move || {
                assert!(join_stopped.load(Ordering::Acquire));
                Ok(())
            },
        );

        handle.shutdown();
        assert!(stopped.load(Ordering::Acquire));
        handle.join().expect("joined");
    }

    #[test]
    fn noop_handle_joins() {
        VirtioDeviceHandle::noop().join().expect("noop join");
    }

    #[test]
    fn thread_host_reports_shutdown_to_worker() {
        let host = TestDeviceHost;
        let handle = host
            .spawn(Box::new(|token| {
                while !token.is_shutdown_requested() {
                    std::thread::yield_now();
                }
                Ok(())
            }))
            .expect("spawned");
        let mut handle = handle;
        handle.shutdown();
        handle.join().expect("joined");
    }

    #[test]
    fn activation_queue_memory_without_shared_memory_fails_closed() {
        let activation = VirtioActivate::new(Vec::new(), Vec::new());

        assert!(
            activation
                .queue_memory()
                .write_u16(GuestAddress(0x1000), 7)
                .is_none()
        );
        assert!(
            activation
                .queue_memory()
                .read_u16(GuestAddress(0x1000))
                .is_none()
        );
    }

    #[test]
    fn activation_buffer_memory_without_shared_memory_fails_closed() {
        let activation = VirtioActivate::new(Vec::new(), Vec::new());

        let mut data = [0; 3];
        assert!(
            activation
                .buffer_memory()
                .write(GuestAddress(0x1000), &[1, 2, 3])
                .is_err()
        );
        assert!(
            activation
                .buffer_memory()
                .read(GuestAddress(0x1000), &mut data)
                .is_err()
        );
    }

    #[test]
    fn activation_queue_memory_uses_shared_memory_when_present() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x2000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let activation = VirtioActivate::with_shared_memory(
            vec![shared],
            Vec::new(),
            Vec::new(),
            Arc::new(TestDeviceHost),
        );

        activation
            .queue_memory()
            .write_u16(GuestAddress(0x2000), 9)
            .expect("write inside shared capability limits");
        assert_eq!(
            activation.queue_memory().read_u16(GuestAddress(0x2000)),
            Some(9)
        );
        assert!(
            activation
                .queue_memory()
                .read_u16(GuestAddress(0x1000))
                .is_none()
        );
    }

    #[test]
    fn activation_buffer_memory_uses_shared_memory_when_present() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x2000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let activation = VirtioActivate::with_shared_memory(
            vec![shared],
            Vec::new(),
            Vec::new(),
            Arc::new(TestDeviceHost),
        );

        activation
            .buffer_memory()
            .write(GuestAddress(0x2000), &[9])
            .expect("write inside shared capability limits");
        let mut data = [0];
        Bytes::read(&mem, &mut data, GuestAddress(0x2000)).unwrap();
        assert_eq!(data, [9]);
        let mut outside = [0];
        assert!(
            activation
                .buffer_memory()
                .read(GuestAddress(0x1000), &mut outside)
                .is_err()
        );
    }
}
