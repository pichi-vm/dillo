// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MMIO register interfaces, routing and syscon substrate devices.

use std::sync::Arc;

use dillo_machine::interrupt::InterruptRequirement;
use dillo_machine::memory::{AddressRange, SharedMemoryRequirement};

pub mod syscon;

/// Error returned by a routed MMIO device access.
#[derive(Debug, thiserror::Error)]
pub enum MmioError {
    #[error("MMIO access is unsupported by the routed device")]
    Unsupported,

    #[error("{0}")]
    Device(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Failure of an access to a routed device, including its original cause.
#[derive(Debug, thiserror::Error)]
#[error("MMIO {operation} at {address:#x} ({size} bytes, window {window:?}): {source}")]
pub struct AccessError {
    pub operation: &'static str,
    pub address: u64,
    pub size: usize,
    pub window: AddressRange,
    #[source]
    pub source: MmioError,
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
    fn windows(&self) -> &[AddressRange];

    fn interrupts(&self) -> &[InterruptRequirement] {
        &[]
    }

    fn shared_memory(&self) -> &[SharedMemoryRequirement] {
        &[]
    }

    fn read(&self, window: AddressRange, offset: u64, data: &mut [u8]) -> Result<(), MmioError>;

    fn write(
        &self,
        window: AddressRange,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError>;
}

struct Range {
    window: AddressRange,
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

    /// Dispatch a guest MMIO read; `Ok(None)` means no routed window.
    /// A mapped error may follow a partial output update and must not be completed.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<Option<()>, AccessError> {
        let Some(r) = self.find(addr, data.len() as u64) else {
            return Ok(None);
        };
        r.device
            .read(r.window, addr - r.window.base, data)
            .map(Some)
            .map_err(|source| AccessError {
                operation: "read",
                address: addr,
                size: data.len(),
                window: r.window,
                source,
            })
    }

    /// Dispatch a guest MMIO write; `Ok(None)` means no routed window.
    /// A mapped error may follow accepted effects and does not permit replay.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<Option<MmioWriteOutcome>, AccessError> {
        let Some(r) = self.find(addr, data.len() as u64) else {
            return Ok(None);
        };
        r.device
            .write(r.window, addr - r.window.base, data)
            .map(Some)
            .map_err(|source| AccessError {
                operation: "write",
                address: addr,
                size: data.len(),
                window: r.window,
                source,
            })
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

    struct TestDevice {
        window: [AddressRange; 1],
        written: AtomicU64,
    }

    impl TestDevice {
        fn new(base: u64, size: u64) -> Self {
            Self {
                window: [AddressRange { base, size }],
                written: AtomicU64::new(0),
            }
        }
    }

    impl MmioDevice for TestDevice {
        fn windows(&self) -> &[AddressRange] {
            &self.window
        }

        fn read(
            &self,
            _window: AddressRange,
            offset: u64,
            data: &mut [u8],
        ) -> Result<(), MmioError> {
            data.fill(offset as u8);
            Ok(())
        }

        fn write(
            &self,
            _window: AddressRange,
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
        assert!(bus.read(0x1042, &mut buf).unwrap().is_some());
        assert_eq!(buf, [0x42; 4]);
        assert!(bus.read(0x900, &mut buf).unwrap().is_none());
    }

    #[test]
    fn write_dispatches() {
        let device = Arc::new(TestDevice::new(0x2000, 0x100));
        let mut bus = MmioBus::new();
        bus.register_device(Arc::clone(&device));
        assert_eq!(
            bus.write(0x2080, &[0xAA, 0xBB]).unwrap(),
            Some(MmioWriteOutcome::Continue)
        );
        assert_eq!(device.written.load(Ordering::SeqCst) & 0xFFFF_FFFF, 0x80);
    }

    #[test]
    fn device_read_dispatches_with_offset() {
        let mut bus = MmioBus::new();
        bus.register_device(Arc::new(TestDevice::new(0x3000, 0x100)));

        let mut buf = [0u8; 4];
        assert!(bus.read(0x3042, &mut buf).unwrap().is_some());
        assert_eq!(buf, [0x42; 4]);
        assert!(bus.read(0x2fff, &mut buf).unwrap().is_none());
    }

    #[test]
    fn device_write_dispatches_with_offset() {
        let device = Arc::new(TestDevice::new(0x4000, 0x100));
        let mut bus = MmioBus::new();
        bus.register_device(Arc::clone(&device));

        assert_eq!(
            bus.write(0x4080, &[0xAA, 0xBB]).unwrap(),
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
}
