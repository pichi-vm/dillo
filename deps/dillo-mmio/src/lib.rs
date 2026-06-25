// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MMIO device boundary for dillo.
//!
//! This crate owns the narrow device-facing MMIO traits and resource shapes.
//! The current `MmioBus` remains a compatibility dispatcher while machine-owned
//! routing is introduced in later stages.

use std::sync::Arc;
use std::sync::RwLock;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

pub mod syscon;

/// A guest-physical MMIO window owned by one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioWindow {
    pub base: u64,
    pub size: u64,
}

/// A guest-physical address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    pub base: u64,
    pub size: u64,
}

impl AddressRange {
    pub fn contains(&self, base: u64, size: u64) -> bool {
        let Some(container_end) = self.base.checked_add(self.size) else {
            return false;
        };
        let Some(end) = base.checked_add(size) else {
            return false;
        };
        base >= self.base && end <= container_end
    }

    fn end(&self) -> Option<u64> {
        self.base.checked_add(self.size)
    }

    fn subtract(&self, removed: AddressRange) -> Vec<AddressRange> {
        let Some(end) = self.end() else {
            return vec![*self];
        };
        let Some(removed_end) = removed.end() else {
            return vec![*self];
        };
        if removed_end <= self.base || removed.base >= end {
            return vec![*self];
        }

        let mut remaining = Vec::with_capacity(2);
        if removed.base > self.base {
            remaining.push(AddressRange {
                base: self.base,
                size: removed.base - self.base,
            });
        }
        if removed_end < end {
            remaining.push(AddressRange {
                base: removed_end,
                size: end - removed_end,
            });
        }
        remaining
    }
}

/// Access allowed through a shared-memory capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedAccess {
    ReadOnly,

    WriteOnly,

    ReadWrite,
}

impl SharedAccess {
    fn permits_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    fn permits_write(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }

    fn includes(self, requested: Self) -> bool {
        match requested {
            Self::ReadOnly => self.permits_read(),
            Self::WriteOnly => self.permits_write(),
            Self::ReadWrite => self.permits_read() && self.permits_write(),
        }
    }
}

/// Fixed shared-memory requirement declared by a device.
///
/// This is for device-owned shared ranges whose bounds are known at attach
/// time. Runtime virtio descriptor-buffer DMA is instead requested through
/// [`SharedMemory::region`] using guest-supplied GPAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedMemoryRequirement {
    pub range: AddressRange,
    pub access: SharedAccess,
}

/// DTB-derived interrupt source for one wired interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptSource {
    pub controller: u32,
    pub cells: [u32; 4],
    pub cell_count: u8,
}

/// DTB-derived interrupt source for one message-interrupt domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInterruptSource {
    pub controller: u32,
}

/// One DTB-derived interrupt requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioInterruptRequirement {
    Line {
        source: InterruptSource,
    },

    MessageDomain {
        source: Option<MessageInterruptSource>,
        vectors: u16,
    },
}

/// Error returned by a routed MMIO device access.
#[derive(Debug, thiserror::Error)]
pub enum MmioError {
    #[error("MMIO access is unsupported by the routed device")]
    Unsupported,
}

/// Device-visible outcome of one guest MMIO write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioWriteOutcome {
    Continue,

    GuestPoweroff,

    GuestReset,
}

/// A device with one or more guest-visible MMIO windows.
pub trait MmioDevice: Send + Sync {
    fn windows(&self) -> &[MmioWindow];

    fn interrupts(&self) -> &[MmioInterruptRequirement] {
        &[]
    }

    fn shared_memory(&self) -> &[SharedMemoryRequirement] {
        &[]
    }

    fn read(&self, window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError>;

    fn write(
        &self,
        window: MmioWindow,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError>;
}

/// Generic registration into a constructed owner.
pub trait Attach<T> {
    type Error: std::error::Error + Send + Sync + 'static;
    type Output;

    fn attach(&mut self, item: T) -> Result<Self::Output, Self::Error>;
}

/// Runtime shared range requested by a device protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedRange {
    pub gpa: u64,
    pub size: u64,
    pub access: SharedAccess,
}

/// Error from attachment-scoped shared-memory access.
#[derive(Debug, thiserror::Error)]
pub enum SharedMemoryError {
    #[error("shared-memory range is outside the capability limits")]
    OutOfLimits,

    #[error("shared-memory range is not currently shared")]
    NotShared,

    #[error("shared-memory access is not permitted by the capability")]
    AccessDenied,

    #[error("shared-memory region access is outside the claimed range")]
    OutOfRange,

    #[error("shared-memory backing access failed: {0}")]
    Backing(String),

    #[error("shared-memory access is unsupported")]
    Unsupported,
}

/// Backend implementation for one claimed shared-memory region.
pub trait SharedRegionAccess: Send + Sync + std::fmt::Debug {
    fn read(&self, offset: u64, data: &mut [u8]) -> Result<(), SharedMemoryError>;

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), SharedMemoryError>;
}

/// Opaque shared-memory region handle.
#[derive(Clone, Debug)]
pub struct SharedRegion {
    access: Arc<dyn SharedRegionAccess>,
}

impl SharedRegion {
    pub fn new(access: Arc<dyn SharedRegionAccess>) -> Self {
        Self { access }
    }

    pub fn read(&self, offset: u64, data: &mut [u8]) -> Result<(), SharedMemoryError> {
        self.access.read(offset, data)
    }

    pub fn write(&self, offset: u64, data: &[u8]) -> Result<(), SharedMemoryError> {
        self.access.write(offset, data)
    }
}

#[derive(Debug)]
struct MappedSharedRegion {
    memory: GuestMemoryMmap,
    gpa: u64,
    size: u64,
    access: SharedAccess,
}

impl SharedRegionAccess for MappedSharedRegion {
    fn read(&self, offset: u64, data: &mut [u8]) -> Result<(), SharedMemoryError> {
        if !self.access.permits_read() {
            return Err(SharedMemoryError::AccessDenied);
        }
        let addr = self.checked_access(offset, data.len())?;
        self.memory
            .read(data, GuestAddress(addr))
            .map_err(|e| SharedMemoryError::Backing(e.to_string()))
            .map(|_| ())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), SharedMemoryError> {
        if !self.access.permits_write() {
            return Err(SharedMemoryError::AccessDenied);
        }
        let addr = self.checked_access(offset, data.len())?;
        self.memory
            .write(data, GuestAddress(addr))
            .map_err(|e| SharedMemoryError::Backing(e.to_string()))
            .map(|_| ())
    }
}

impl MappedSharedRegion {
    fn checked_access(&self, offset: u64, len: usize) -> Result<u64, SharedMemoryError> {
        let len = u64::try_from(len).map_err(|_| SharedMemoryError::OutOfRange)?;
        let end = offset
            .checked_add(len)
            .ok_or(SharedMemoryError::OutOfRange)?;
        if end > self.size {
            return Err(SharedMemoryError::OutOfRange);
        }
        self.gpa
            .checked_add(offset)
            .ok_or(SharedMemoryError::OutOfRange)
    }
}

/// Attachment-scoped shared-memory capability.
pub trait SharedMemory: Send + Sync {
    fn region(&self, range: SharedRange) -> Result<SharedRegion, SharedMemoryError>;
}

/// Backend-owned shared/private page state for one memory capability.
#[derive(Debug, Clone, Default)]
pub struct SharedMemoryState {
    shared: Arc<RwLock<Vec<AddressRange>>>,
}

impl SharedMemoryState {
    pub fn new(shared: Vec<AddressRange>) -> Self {
        Self {
            shared: Arc::new(RwLock::new(shared)),
        }
    }

    pub fn set_shared_ranges(&self, shared: Vec<AddressRange>) {
        *self.shared.write().expect("shared-memory state poisoned") = shared;
    }

    pub fn mark_shared(&self, range: AddressRange) {
        self.shared
            .write()
            .expect("shared-memory state poisoned")
            .push(range);
    }

    pub fn mark_private(&self, range: AddressRange) {
        let mut shared = self.shared.write().expect("shared-memory state poisoned");
        *shared = shared
            .iter()
            .flat_map(|existing| existing.subtract(range))
            .collect();
    }

    fn contains(&self, base: u64, size: u64) -> bool {
        self.shared
            .read()
            .expect("shared-memory state poisoned")
            .iter()
            .any(|shared| shared.contains(base, size))
    }
}

/// Standard-VM shared-memory capability over mapped guest RAM.
///
/// Confidential backends may use a different implementation that updates
/// `shared` when guest shared/private conversion exits are handled internally.
#[derive(Debug, Clone)]
pub struct MappedSharedMemory {
    memory: GuestMemoryMmap,
    limits: Vec<AddressRange>,
    access: SharedAccess,
    shared: SharedMemoryState,
}

impl MappedSharedMemory {
    pub fn new(memory: GuestMemoryMmap, requirement: SharedMemoryRequirement) -> Self {
        Self {
            memory,
            limits: vec![requirement.range],
            access: requirement.access,
            shared: SharedMemoryState::new(vec![requirement.range]),
        }
    }

    pub fn for_guest_memory(memory: GuestMemoryMmap, access: SharedAccess) -> Self {
        let limits = Self::guest_memory_ranges(&memory);
        Self {
            memory,
            access,
            shared: SharedMemoryState::new(limits.clone()),
            limits,
        }
    }

    pub fn with_shared_ranges(
        memory: GuestMemoryMmap,
        requirement: SharedMemoryRequirement,
        shared: Vec<AddressRange>,
    ) -> Self {
        Self {
            memory,
            limits: vec![requirement.range],
            access: requirement.access,
            shared: SharedMemoryState::new(shared),
        }
    }

    pub fn with_shared_state(
        memory: GuestMemoryMmap,
        requirement: SharedMemoryRequirement,
        shared: SharedMemoryState,
    ) -> Self {
        Self {
            memory,
            limits: vec![requirement.range],
            access: requirement.access,
            shared,
        }
    }

    fn guest_memory_ranges(memory: &GuestMemoryMmap) -> Vec<AddressRange> {
        memory
            .iter()
            .filter_map(|region| {
                let size = region.len();
                (size > 0).then(|| AddressRange {
                    base: region.start_addr().raw_value(),
                    size,
                })
            })
            .collect()
    }
}

impl SharedMemory for MappedSharedMemory {
    fn region(&self, range: SharedRange) -> Result<SharedRegion, SharedMemoryError> {
        if !self.access.includes(range.access) {
            return Err(SharedMemoryError::AccessDenied);
        }
        if !self
            .limits
            .iter()
            .any(|limit| limit.contains(range.gpa, range.size))
        {
            return Err(SharedMemoryError::OutOfLimits);
        }
        if !self.shared.contains(range.gpa, range.size) {
            return Err(SharedMemoryError::NotShared);
        }
        Ok(SharedRegion::new(Arc::new(MappedSharedRegion {
            memory: self.memory.clone(),
            gpa: range.gpa,
            size: range.size,
            access: range.access,
        })))
    }
}

/// Resolved interrupt handle.
#[derive(Clone)]
pub struct Interrupt(Arc<dyn InterruptLine>);

impl std::fmt::Debug for Interrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Interrupt").finish()
    }
}

impl Interrupt {
    pub fn new(line: Arc<dyn InterruptLine>) -> Self {
        Self(line)
    }

    pub fn from_fn(signal: impl Fn() + Send + Sync + 'static) -> Self {
        Self::new(Arc::new(FnInterruptLine {
            signal: Box::new(signal),
        }))
    }

    pub fn signal(&self) {
        self.0.signal();
    }

    pub fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        self.0.set_level(level)
    }
}

struct FnInterruptLine {
    signal: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for FnInterruptLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnInterruptLine").finish_non_exhaustive()
    }
}

impl InterruptLine for FnInterruptLine {
    fn signal(&self) {
        (self.signal)();
    }

    fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        if level {
            self.signal();
        }
        Ok(())
    }
}

/// Backend-resolved line interrupt.
pub trait InterruptLine: Send + Sync + std::fmt::Debug {
    fn signal(&self);

    fn set_level(&self, level: bool) -> Result<(), InterruptError>;
}

/// Error from interrupt delivery.
#[derive(Debug, thiserror::Error)]
pub enum InterruptError {
    #[error("interrupt deassert is unsupported")]
    UnsupportedDeassert,

    #[error("interrupt delivery failed: {0}")]
    Delivery(String),
}

/// Resolved message interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInterrupt {
    pub address: u64,
    pub data: u32,
    pub masked: bool,
}

/// Backend-resolved message-interrupt domain.
pub trait MessageInterruptDomain: Send + Sync {
    fn update(&self, vector: u16, msg: MessageInterrupt) -> Result<(), InterruptError>;

    fn enabled(&self, enabled: bool) -> Result<(), InterruptError>;

    fn interrupt(&self, vector: u16) -> Option<Interrupt>;
}

/// Backend-resolved interrupt resource for an attached MMIO device.
#[derive(Clone)]
pub enum MmioInterrupt {
    Line(Interrupt),

    MessageDomain(Arc<dyn MessageInterruptDomain>),
}

impl std::fmt::Debug for MmioInterrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Line(line) => f.debug_tuple("Line").field(line).finish(),
            Self::MessageDomain(_) => f.debug_tuple("MessageDomain").finish(),
        }
    }
}

pub type MmioDeviceRun =
    Box<dyn FnOnce(MmioRunToken) -> Result<(), MmioJoinError> + Send + 'static>;

/// Token passed to a running MMIO thread host.
#[derive(Clone)]
pub struct MmioRunToken {
    is_shutdown_requested: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for MmioRunToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmioRunToken").finish_non_exhaustive()
    }
}

impl MmioRunToken {
    pub fn from_fn(is_shutdown_requested: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            is_shutdown_requested: Arc::new(is_shutdown_requested),
        }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        (self.is_shutdown_requested)()
    }
}

/// Handle for one running MMIO device host.
pub struct MmioDeviceHandle {
    shutdown: Box<dyn Fn() -> Result<(), MmioShutdownError> + Send + Sync>,
    join: Option<Box<dyn FnOnce() -> Result<(), MmioJoinError> + Send>>,
}

impl std::fmt::Debug for MmioDeviceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmioDeviceHandle").finish_non_exhaustive()
    }
}

impl MmioDeviceHandle {
    pub fn new(
        shutdown: impl Fn() -> Result<(), MmioShutdownError> + Send + Sync + 'static,
        join: impl FnOnce() -> Result<(), MmioJoinError> + Send + 'static,
    ) -> Self {
        Self {
            shutdown: Box::new(shutdown),
            join: Some(Box::new(join)),
        }
    }

    pub fn noop() -> Self {
        Self::new(|| Ok(()), || Ok(()))
    }

    pub fn shutdown(&self) -> Result<(), MmioShutdownError> {
        (self.shutdown)()
    }

    pub fn join(mut self) -> Result<(), MmioJoinError> {
        let _ = self.shutdown();
        if let Some(join) = self.join.take() {
            join()
        } else {
            Ok(())
        }
    }
}

/// Error from spawning an MMIO device worker.
#[derive(Debug, thiserror::Error)]
pub struct MmioSpawnError;

impl std::fmt::Display for MmioSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MMIO device worker spawn failed")
    }
}

/// Error from requesting MMIO device worker shutdown.
#[derive(Debug, thiserror::Error)]
pub enum MmioShutdownError {
    #[error("MMIO device worker shutdown is unsupported")]
    Unsupported,

    #[error("MMIO device worker shutdown I/O failed: {0}")]
    Io(std::io::Error),
}

/// Error from joining an MMIO device host.
#[derive(Debug, thiserror::Error)]
pub enum MmioJoinError {
    #[error("MMIO device host panicked")]
    Panicked,

    #[error("MMIO device host failed: {0}")]
    Host(String),
}

/// Backend-owned services for one successfully attached MMIO device.
pub trait MmioAttachment: Send + Sync + std::fmt::Debug {
    fn interrupts(&self) -> &[MmioInterrupt];

    fn shared_memory(&self) -> &[Arc<dyn SharedMemory>];

    fn spawn(self: Arc<Self>, run: MmioDeviceRun) -> Result<MmioDeviceHandle, MmioSpawnError>;
}

struct Range {
    window: MmioWindow,
    device: Arc<dyn MmioDevice>,
}

/// Compatibility MMIO bus.
///
/// Built at startup via [`MmioBus::register_device`] and queried per guest exit.
/// Later machine crates will own this routing state behind `Attach`.
#[derive(Default)]
pub struct MmioBus {
    ranges: Vec<Range>,
}

impl std::fmt::Debug for MmioBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmioBus")
            .field("range_count", &self.ranges.len())
            .finish()
    }
}

impl MmioBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an MMIO device.
    pub fn register_device<D>(&mut self, device: Arc<D>)
    where
        D: MmioDevice + 'static,
    {
        let device: Arc<dyn MmioDevice> = device;
        let windows = device.windows();
        assert!(
            !windows.is_empty(),
            "MMIO device must expose at least one window"
        );
        for window in windows {
            let new_end = window
                .base
                .checked_add(window.size)
                .expect("MMIO range size overflow");
            for r in &self.ranges {
                let end = r.window.base + r.window.size;
                let overlap = window.base < end && r.window.base < new_end;
                assert!(
                    !overlap,
                    "MMIO range overlap: new [{:#x}..{:#x}) collides with [{:#x}..{:#x})",
                    window.base, new_end, r.window.base, end,
                );
            }
            self.ranges.push(Range {
                window: *window,
                device: Arc::clone(&device),
            });
        }
    }

    /// Dispatch a guest MMIO read.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some(r) = self.find(addr, data.len() as u64) {
            return r.device.read(r.window, addr - r.window.base, data).is_ok();
        }
        false
    }

    /// Dispatch a guest MMIO write.
    pub fn write(&self, addr: u64, data: &[u8]) -> Option<MmioWriteOutcome> {
        if let Some(r) = self.find(addr, data.len() as u64) {
            return r.device.write(r.window, addr - r.window.base, data).ok();
        }
        None
    }

    fn find(&self, addr: u64, len: u64) -> Option<&Range> {
        let end = addr.checked_add(len)?;
        self.ranges
            .iter()
            .find(|r| r.window.base <= addr && end <= r.window.base + r.window.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use vm_memory::{Bytes, GuestAddress};

    struct TestDevice {
        window: [MmioWindow; 1],
        written: AtomicU64,
    }

    impl TestDevice {
        fn new(base: u64, size: u64) -> Self {
            Self {
                window: [MmioWindow { base, size }],
                written: AtomicU64::new(0),
            }
        }
    }

    impl MmioDevice for TestDevice {
        fn windows(&self) -> &[MmioWindow] {
            &self.window
        }

        fn read(&self, _window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
            data.fill(offset as u8);
            Ok(())
        }

        fn write(
            &self,
            _window: MmioWindow,
            offset: u64,
            data: &[u8],
        ) -> Result<MmioWriteOutcome, MmioError> {
            let mut buf = [0u8; 8];
            let n = data.len().min(8);
            buf[..n].copy_from_slice(&data[..n]);
            self.written
                .store(offset | (u64::from_le_bytes(buf) << 32), Ordering::SeqCst);
            Ok(MmioWriteOutcome::Continue)
        }
    }

    #[test]
    fn read_dispatches_with_offset() {
        let mut bus = MmioBus::new();
        bus.register_device(Arc::new(TestDevice::new(0x1000, 0x100)));
        let mut buf = [0u8; 4];
        assert!(bus.read(0x1042, &mut buf));
        assert_eq!(buf, [0x42; 4]);
        assert!(!bus.read(0x900, &mut buf));
    }

    #[test]
    fn write_dispatches() {
        let device = Arc::new(TestDevice::new(0x2000, 0x100));
        let mut bus = MmioBus::new();
        bus.register_device(Arc::clone(&device));
        assert_eq!(
            bus.write(0x2080, &[0xAA, 0xBB]),
            Some(MmioWriteOutcome::Continue)
        );
        assert_eq!(device.written.load(Ordering::SeqCst) & 0xFFFF_FFFF, 0x80);
    }

    #[test]
    fn device_read_dispatches_with_offset() {
        let mut bus = MmioBus::new();
        bus.register_device(Arc::new(TestDevice::new(0x3000, 0x100)));

        let mut buf = [0u8; 4];
        assert!(bus.read(0x3042, &mut buf));
        assert_eq!(buf, [0x42; 4]);
        assert!(!bus.read(0x2fff, &mut buf));
    }

    #[test]
    fn device_write_dispatches_with_offset() {
        let device = Arc::new(TestDevice::new(0x4000, 0x100));
        let mut bus = MmioBus::new();
        bus.register_device(Arc::clone(&device));

        assert_eq!(
            bus.write(0x4080, &[0xAA, 0xBB]),
            Some(MmioWriteOutcome::Continue)
        );
        assert_eq!(device.written.load(Ordering::SeqCst) & 0xFFFF_FFFF, 0x80);
    }

    #[test]
    #[should_panic(expected = "MMIO range overlap")]
    fn overlap_panics() {
        let mut bus = MmioBus::new();
        bus.register_device(Arc::new(TestDevice::new(0x1000, 0x100)));
        bus.register_device(Arc::new(TestDevice::new(0x1080, 0x100)));
    }

    #[test]
    #[should_panic(expected = "MMIO range overlap")]
    fn device_overlap_panics() {
        let mut bus = MmioBus::new();
        bus.register_device(Arc::new(TestDevice::new(0x1000, 0x100)));
        bus.register_device(Arc::new(TestDevice::new(0x1080, 0x100)));
    }

    #[test]
    fn mapped_shared_memory_reads_and_writes_claimed_region() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        memory.write(&[1, 2, 3, 4], GuestAddress(0x1200)).unwrap();
        let shared = MappedSharedMemory::new(
            memory,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x1000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        );

        let region = shared
            .region(SharedRange {
                gpa: 0x1200,
                size: 4,
                access: SharedAccess::ReadWrite,
            })
            .unwrap();
        let mut buf = [0; 4];
        region.read(0, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);

        region.write(1, &[9, 8]).unwrap();
        region.read(0, &mut buf).unwrap();
        assert_eq!(buf, [1, 9, 8, 4]);
    }

    #[test]
    fn mapped_shared_memory_rejects_outside_capability_limits() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let shared = MappedSharedMemory::new(
            memory,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x1000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        );

        let err = shared
            .region(SharedRange {
                gpa: 0x1ff0,
                size: 0x20,
                access: SharedAccess::ReadOnly,
            })
            .expect_err("range crosses capability limits");
        assert!(matches!(err, SharedMemoryError::OutOfLimits));
    }

    #[test]
    fn mapped_shared_memory_can_limit_claims_to_guest_ram() {
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x1000), 0x1000),
            (GuestAddress(0x4000), 0x1000),
        ])
        .unwrap();
        memory.write(&[1, 2], GuestAddress(0x4100)).unwrap();
        let shared = MappedSharedMemory::for_guest_memory(memory, SharedAccess::ReadWrite);

        let region = shared
            .region(SharedRange {
                gpa: 0x4100,
                size: 2,
                access: SharedAccess::ReadOnly,
            })
            .expect("runtime claim inside guest RAM");
        let mut buf = [0; 2];
        region.read(0, &mut buf).unwrap();
        assert_eq!(buf, [1, 2]);

        let err = shared
            .region(SharedRange {
                gpa: 0x3000,
                size: 0x10,
                access: SharedAccess::ReadOnly,
            })
            .expect_err("runtime claim outside guest RAM");
        assert!(matches!(err, SharedMemoryError::OutOfLimits));
    }

    #[test]
    fn mapped_shared_memory_rejects_private_range() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let shared = MappedSharedMemory::with_shared_ranges(
            memory,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x1000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
            vec![AddressRange {
                base: 0x1000,
                size: 0x100,
            }],
        );

        let err = shared
            .region(SharedRange {
                gpa: 0x1200,
                size: 0x10,
                access: SharedAccess::ReadOnly,
            })
            .expect_err("range is not currently shared");
        assert!(matches!(err, SharedMemoryError::NotShared));
    }

    #[test]
    fn mapped_shared_memory_observes_runtime_private_shared_updates() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let state = SharedMemoryState::new(vec![AddressRange {
            base: 0x1000,
            size: 0x1000,
        }]);
        let shared = MappedSharedMemory::with_shared_state(
            memory,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x1000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
            state.clone(),
        );

        shared
            .region(SharedRange {
                gpa: 0x1200,
                size: 0x10,
                access: SharedAccess::ReadOnly,
            })
            .expect("range starts shared");

        state.mark_private(AddressRange {
            base: 0x1100,
            size: 0x200,
        });
        let err = shared
            .region(SharedRange {
                gpa: 0x1200,
                size: 0x10,
                access: SharedAccess::ReadOnly,
            })
            .expect_err("range became private");
        assert!(matches!(err, SharedMemoryError::NotShared));

        state.mark_shared(AddressRange {
            base: 0x1200,
            size: 0x10,
        });
        shared
            .region(SharedRange {
                gpa: 0x1200,
                size: 0x10,
                access: SharedAccess::ReadOnly,
            })
            .expect("range became shared again");
    }

    #[test]
    fn mapped_shared_memory_enforces_access_mode() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let shared = MappedSharedMemory::new(
            memory,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x1000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadOnly,
            },
        );

        let err = shared
            .region(SharedRange {
                gpa: 0x1100,
                size: 0x10,
                access: SharedAccess::ReadWrite,
            })
            .expect_err("capability is read-only");
        assert!(matches!(err, SharedMemoryError::AccessDenied));

        let region = shared
            .region(SharedRange {
                gpa: 0x1100,
                size: 0x10,
                access: SharedAccess::ReadOnly,
            })
            .unwrap();
        let err = region.write(0, &[1]).expect_err("region is read-only");
        assert!(matches!(err, SharedMemoryError::AccessDenied));
    }

    #[test]
    fn mapped_shared_memory_region_bounds_are_enforced() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let shared = MappedSharedMemory::new(
            memory,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x1000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        );
        let region = shared
            .region(SharedRange {
                gpa: 0x1100,
                size: 4,
                access: SharedAccess::ReadWrite,
            })
            .unwrap();

        let err = region.write(3, &[1, 2]).expect_err("write crosses region");
        assert!(matches!(err, SharedMemoryError::OutOfRange));
    }

    #[test]
    fn handle_shutdown_and_join_are_invoked() {
        let shutdown_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let join_seen = Arc::clone(&shutdown_seen);
        let handle = MmioDeviceHandle::new(
            {
                let shutdown_seen = Arc::clone(&shutdown_seen);
                move || {
                    shutdown_seen.store(true, std::sync::atomic::Ordering::Release);
                    Ok(())
                }
            },
            move || {
                assert!(join_seen.load(std::sync::atomic::Ordering::Acquire));
                Ok(())
            },
        );

        handle.shutdown().expect("shutdown requested");
        handle.join().expect("joined");
    }

    #[test]
    fn handle_error_reaches_join() {
        let handle = MmioDeviceHandle::new(|| Ok(()), || Err(MmioJoinError::Host("boom".into())));

        let err = handle.join().expect_err("host error");
        assert_eq!(err.to_string(), "MMIO device host failed: boom");
    }

    #[test]
    fn noop_handle_shutdown_and_join_are_harmless() {
        let handle = MmioDeviceHandle::noop();

        handle.shutdown().expect("noop shutdown");
        handle.join().expect("noop join");
    }
}
