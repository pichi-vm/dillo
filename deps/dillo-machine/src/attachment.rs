// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Registration and the services supplied to an attached device.

use std::sync::Arc;

use crate::execution::{DeviceHandle, DeviceRun, SpawnError};
use crate::interrupt::InterruptResource;
use crate::memory::{AddressRange, SharedMemory};
use crate::notification::WriteNotification;

/// Generic registration into a constructed owner.
pub trait Attach<T> {
    type Error: std::error::Error + Send + Sync + 'static;
    type Output;

    fn attach(&mut self, item: T) -> Result<Self::Output, Self::Error>;
}

/// Backend-owned services for one successfully attached device.
pub trait DeviceAttachment: Send + Sync + std::fmt::Debug {
    fn interrupts(&self) -> &[InterruptResource];

    fn shared_memory(&self) -> &[Arc<dyn SharedMemory>];

    /// Optionally accelerate an exact four-byte write in this device's window.
    /// Unsupported backends retain ordinary MMIO dispatch.
    fn write_notification(
        &self,
        _window: AddressRange,
        _offset: u64,
        _value: u32,
    ) -> std::io::Result<Option<Arc<dyn WriteNotification>>> {
        Ok(None)
    }

    fn spawn(self: Arc<Self>, run: DeviceRun) -> Result<DeviceHandle, SpawnError>;
}
