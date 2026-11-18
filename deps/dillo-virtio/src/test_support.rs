// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test-only fault injection over real queue memory, before one scalar store.

use crate::QueueMemory;
use dillo_machine::memory::SharedMemoryError;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use vm_memory::GuestAddress;

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
