// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared guest-memory access and mapped-memory adapters.

use std::sync::{Arc, RwLock};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
