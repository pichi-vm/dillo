// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test fixtures for guarded guest-memory access and queue fault injection.

use crate::QueueMemory;
use dillo_machine::memory::{
    MappedRam, MappedSharedMemory, SharedAccess, SharedMemory, SharedMemoryError, SharedRange,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use vm_memory::{Address, ByteValued, GuestAddress, GuestMemoryError, GuestMemoryMmap};

/// Guest RAM for fixtures that access the same bytes as device capabilities.
#[derive(Clone, Debug)]
pub struct TestGuestMemory {
    owner: Arc<MappedRam>,
    shared: MappedSharedMemory,
}

impl TestGuestMemory {
    pub fn from_ranges(
        ranges: &[(GuestAddress, usize)],
    ) -> Result<Self, vm_memory::mmap::FromRangesError> {
        let guest = GuestMemoryMmap::from_ranges(ranges)?;
        // SAFETY: fresh anonymous mappings never leave this owner.
        #[allow(unsafe_code)]
        let owner = unsafe { MappedRam::adopt(guest) };
        Ok(Self::from_owner(owner))
    }

    pub fn from_owner(owner: Arc<MappedRam>) -> Self {
        let shared =
            MappedSharedMemory::for_guest_memory(Arc::clone(&owner), SharedAccess::ReadOnly);
        Self { owner, shared }
    }

    pub fn owner(&self) -> Arc<MappedRam> {
        Arc::clone(&self.owner)
    }

    pub fn read_slice(&self, data: &mut [u8], addr: GuestAddress) -> Result<(), SharedMemoryError> {
        self.shared
            .region(SharedRange {
                gpa: addr.raw_value(),
                size: data.len() as u64,
                access: SharedAccess::ReadOnly,
            })?
            .read(0, data)
    }

    pub fn read_obj<T: ByteValued>(&self, addr: GuestAddress) -> Result<T, SharedMemoryError> {
        let mut object = T::zeroed();
        self.read_slice(object.as_mut_slice(), addr)?;
        Ok(object)
    }

    pub fn write_slice(&self, data: &[u8], addr: GuestAddress) -> Result<(), GuestMemoryError> {
        self.owner.write_slice(data, addr)
    }

    pub fn write_obj<T: ByteValued>(
        &self,
        object: T,
        addr: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        self.write_slice(object.as_slice(), addr)
    }
}

pub struct FaultQueueMemory {
    memory: Arc<dyn QueueMemory>,
    fail_on: usize,
    attempts: AtomicUsize,
}

impl std::fmt::Debug for FaultQueueMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultQueueMemory")
            .field("fail_on", &self.fail_on)
            .field("attempts", &self.attempts())
            .finish_non_exhaustive()
    }
}

impl FaultQueueMemory {
    pub fn new(memory: Arc<dyn QueueMemory>, fail_on: usize) -> Self {
        Self {
            memory,
            fail_on,
            attempts: AtomicUsize::new(0),
        }
    }
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Relaxed)
    }
    fn before_store(&self) -> Result<(), SharedMemoryError> {
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == self.fail_on {
            Err(SharedMemoryError::Backing(format!(
                "injected publication write {attempt}"
            )))
        } else {
            Ok(())
        }
    }
}

impl QueueMemory for FaultQueueMemory {
    fn read_u16(&self, addr: GuestAddress) -> Option<u16> {
        self.memory.read_u16(addr)
    }
    fn read_u32(&self, addr: GuestAddress) -> Option<u32> {
        self.memory.read_u32(addr)
    }
    fn read_u64(&self, addr: GuestAddress) -> Option<u64> {
        self.memory.read_u64(addr)
    }
    fn write_u16(&self, addr: GuestAddress, value: u16) -> Result<(), SharedMemoryError> {
        self.before_store()?;
        self.memory.write_u16(addr, value)
    }
    fn write_u32(&self, addr: GuestAddress, value: u32) -> Result<(), SharedMemoryError> {
        self.before_store()?;
        self.memory.write_u32(addr, value)
    }
}
