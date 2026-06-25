// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Virtio descriptor-buffer memory access.

use std::sync::Arc;

use dillo_mmio::{SharedAccess, SharedMemory, SharedMemoryError, SharedRange};
use vm_memory::{Address, GuestAddress};

/// Error returned by virtio descriptor-buffer memory access.
#[derive(Debug, thiserror::Error)]
pub enum VirtioMemoryError {
    #[error("guest memory access failed: {0}")]
    Guest(String),

    #[error("shared memory access failed: {0}")]
    Shared(#[from] SharedMemoryError),
}

/// Memory access needed by virtio descriptor payload buffers.
pub trait VirtioMemory: Send + Sync {
    fn read(&self, addr: GuestAddress, data: &mut [u8]) -> Result<usize, VirtioMemoryError>;

    fn write(&self, addr: GuestAddress, data: &[u8]) -> Result<usize, VirtioMemoryError>;
}

/// Fail-closed descriptor-buffer memory used when no backend capability exists.
#[derive(Debug, Clone, Copy)]
pub struct NullVirtioMemory;

impl VirtioMemory for NullVirtioMemory {
    fn read(&self, _addr: GuestAddress, _data: &mut [u8]) -> Result<usize, VirtioMemoryError> {
        Err(VirtioMemoryError::Shared(SharedMemoryError::Unsupported))
    }

    fn write(&self, _addr: GuestAddress, _data: &[u8]) -> Result<usize, VirtioMemoryError> {
        Err(VirtioMemoryError::Shared(SharedMemoryError::Unsupported))
    }
}

impl<T: VirtioMemory + ?Sized> VirtioMemory for Arc<T> {
    fn read(&self, addr: GuestAddress, data: &mut [u8]) -> Result<usize, VirtioMemoryError> {
        (**self).read(addr, data)
    }

    fn write(&self, addr: GuestAddress, data: &[u8]) -> Result<usize, VirtioMemoryError> {
        (**self).write(addr, data)
    }
}

/// Virtio descriptor-buffer access backed by attachment-scoped shared memory.
#[derive(Clone)]
pub struct SharedVirtioMemory {
    capabilities: Vec<Arc<dyn SharedMemory>>,
}

impl std::fmt::Debug for SharedVirtioMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedVirtioMemory")
            .field("capability_count", &self.capabilities.len())
            .finish()
    }
}

impl SharedVirtioMemory {
    pub fn new(capabilities: Vec<Arc<dyn SharedMemory>>) -> Self {
        Self { capabilities }
    }

    fn region(
        &self,
        addr: GuestAddress,
        size: usize,
        access: SharedAccess,
    ) -> Result<dillo_mmio::SharedRegion, SharedMemoryError> {
        let mut last = SharedMemoryError::Unsupported;
        for capability in &self.capabilities {
            match capability.region(SharedRange {
                gpa: addr.raw_value(),
                size: size as u64,
                access,
            }) {
                Ok(region) => return Ok(region),
                Err(err) => last = err,
            }
        }
        Err(last)
    }
}

impl VirtioMemory for SharedVirtioMemory {
    fn read(&self, addr: GuestAddress, data: &mut [u8]) -> Result<usize, VirtioMemoryError> {
        let region = self.region(addr, data.len(), SharedAccess::ReadOnly)?;
        region.read(0, data)?;
        Ok(data.len())
    }

    fn write(&self, addr: GuestAddress, data: &[u8]) -> Result<usize, VirtioMemoryError> {
        let region = self.region(addr, data.len(), SharedAccess::WriteOnly)?;
        region.write(0, data)?;
        Ok(data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedMemoryRequirement};
    use vm_memory::{Bytes, GuestMemoryMmap};

    #[test]
    fn shared_virtio_memory_reads_inside_capability_limits() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        Bytes::write(&mem, &[1, 2, 3], GuestAddress(0x5000)).unwrap();
        let shared = SharedVirtioMemory::new(vec![Arc::new(MappedSharedMemory::new(
            mem,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x5000,
                    size: 0x100,
                },
                access: SharedAccess::ReadWrite,
            },
        ))]);

        let mut data = [0; 3];
        assert_eq!(shared.read(GuestAddress(0x5000), &mut data).unwrap(), 3);
        assert_eq!(data, [1, 2, 3]);
    }

    #[test]
    fn shared_virtio_memory_rejects_access_outside_capability_limits() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let shared = SharedVirtioMemory::new(vec![Arc::new(MappedSharedMemory::new(
            mem,
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x5000,
                    size: 0x100,
                },
                access: SharedAccess::ReadWrite,
            },
        ))]);

        let mut data = [0; 1];
        assert!(matches!(
            shared.read(GuestAddress(0x4fff), &mut data),
            Err(VirtioMemoryError::Shared(SharedMemoryError::OutOfLimits))
        ));
    }
}
