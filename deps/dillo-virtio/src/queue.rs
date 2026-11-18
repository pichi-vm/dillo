// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Split virtqueue implementation for virtio devices.
//!
//! Provides the [`Queue`] struct for descriptor chain walking, available ring
//! consumption, and used ring production against guest memory.

use std::num::Wrapping;
use std::sync::Arc;
use std::sync::atomic::{Ordering, fence};

use dillo_machine::memory::{
    SharedAccess, SharedMemory, SharedMemoryError, SharedRange, SharedRegion,
};
use vm_memory::{Address, GuestAddress};

/// Descriptor flag: buffer continues via `next` field.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;

/// Descriptor flag: buffer is device-writable (otherwise device-readable).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// A single descriptor chain entry popped from the available ring.
#[derive(Debug, Clone)]
pub struct DescriptorChain {
    /// Index of this descriptor in the descriptor table (head index for `add_used`).
    pub index: u16,
    /// Guest physical address of the buffer.
    pub addr: GuestAddress,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (`VIRTQ_DESC_F_NEXT`, `VIRTQ_DESC_F_WRITE`).
    pub flags: u16,
    /// Index of the next descriptor if `VIRTQ_DESC_F_NEXT` is set.
    pub next: u16,
    /// Base GPA of the descriptor table (for following chains).
    pub desc_table: GuestAddress,
}

impl DescriptorChain {
    /// Follow the chain to the next descriptor, if `VIRTQ_DESC_F_NEXT` is set.
    pub fn next_desc<M: QueueMemory>(&self, mem: &M) -> Option<DescriptorChain> {
        if self.flags & VIRTQ_DESC_F_NEXT == 0 {
            return None;
        }
        let desc_offset = (self.next as u64) * 16;
        let desc_addr = self.desc_table.unchecked_add(desc_offset);
        let addr = mem.read_u64(desc_addr)?;
        let len = mem.read_u32(desc_addr.unchecked_add(8))?;
        let flags = mem.read_u16(desc_addr.unchecked_add(12))?;
        let next = mem.read_u16(desc_addr.unchecked_add(14))?;
        Some(DescriptorChain {
            index: self.next,
            addr: GuestAddress(addr),
            len,
            flags,
            next,
            desc_table: self.desc_table,
        })
    }
}

/// Memory access needed by split virtqueue metadata.
///
/// Successful scalar operations are indivisible little-endian accesses with
/// relaxed ordering. A failed scalar store leaves that scalar unchanged.
/// The queue supplies the protocol's publication barriers.
pub trait QueueMemory: Send + Sync {
    fn read_u16(&self, addr: GuestAddress) -> Option<u16>;

    fn read_u32(&self, addr: GuestAddress) -> Option<u32>;

    fn read_u64(&self, addr: GuestAddress) -> Option<u64>;

    fn write_u16(&self, addr: GuestAddress, value: u16) -> Result<(), SharedMemoryError>;

    fn write_u32(&self, addr: GuestAddress, value: u32) -> Result<(), SharedMemoryError>;
}

/// Fail-closed virtqueue metadata memory used when no backend capability exists.
#[derive(Debug, Clone, Copy)]
pub struct NullQueueMemory;

impl QueueMemory for NullQueueMemory {
    fn read_u16(&self, _addr: GuestAddress) -> Option<u16> {
        None
    }

    fn read_u32(&self, _addr: GuestAddress) -> Option<u32> {
        None
    }

    fn read_u64(&self, _addr: GuestAddress) -> Option<u64> {
        None
    }

    fn write_u16(&self, _addr: GuestAddress, _value: u16) -> Result<(), SharedMemoryError> {
        Err(SharedMemoryError::Unsupported)
    }

    fn write_u32(&self, _addr: GuestAddress, _value: u32) -> Result<(), SharedMemoryError> {
        Err(SharedMemoryError::Unsupported)
    }
}

impl<T: QueueMemory + ?Sized> QueueMemory for Arc<T> {
    fn read_u16(&self, addr: GuestAddress) -> Option<u16> {
        (**self).read_u16(addr)
    }

    fn read_u32(&self, addr: GuestAddress) -> Option<u32> {
        (**self).read_u32(addr)
    }

    fn read_u64(&self, addr: GuestAddress) -> Option<u64> {
        (**self).read_u64(addr)
    }

    fn write_u16(&self, addr: GuestAddress, value: u16) -> Result<(), SharedMemoryError> {
        (**self).write_u16(addr, value)
    }

    fn write_u32(&self, addr: GuestAddress, value: u32) -> Result<(), SharedMemoryError> {
        (**self).write_u32(addr, value)
    }
}

/// Virtqueue metadata access backed by attachment-scoped shared memory.
#[derive(Clone)]
pub struct SharedQueueMemory {
    capabilities: Vec<Arc<dyn SharedMemory>>,
}

impl std::fmt::Debug for SharedQueueMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedQueueMemory")
            .field("capability_count", &self.capabilities.len())
            .finish()
    }
}

impl SharedQueueMemory {
    pub fn new(capabilities: Vec<Arc<dyn SharedMemory>>) -> Self {
        Self { capabilities }
    }

    fn read_region(&self, addr: GuestAddress, size: u64) -> Option<SharedRegion> {
        self.capabilities.iter().find_map(|capability| {
            capability
                .region(SharedRange {
                    gpa: addr.raw_value(),
                    size,
                    access: SharedAccess::ReadOnly,
                })
                .ok()
        })
    }

    fn write_region(
        &self,
        addr: GuestAddress,
        size: u64,
    ) -> Result<SharedRegion, SharedMemoryError> {
        let mut refusal = None;
        for capability in &self.capabilities {
            match capability.region(SharedRange {
                gpa: addr.raw_value(),
                size,
                access: SharedAccess::WriteOnly,
            }) {
                Ok(region) => return Ok(region),
                Err(
                    error @ (SharedMemoryError::OutOfLimits
                    | SharedMemoryError::AccessDenied
                    | SharedMemoryError::NotShared),
                ) => {
                    // Capabilities may cover different ranges/access rights.
                    // Retain the first refusal if none admits this access.
                    refusal.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(refusal.unwrap_or(SharedMemoryError::Unsupported))
    }
}

impl QueueMemory for SharedQueueMemory {
    fn read_u16(&self, addr: GuestAddress) -> Option<u16> {
        self.read_region(addr, 2)?.load_u16_le(0).ok()
    }

    fn read_u32(&self, addr: GuestAddress) -> Option<u32> {
        self.read_region(addr, 4)?.load_u32_le(0).ok()
    }

    fn read_u64(&self, addr: GuestAddress) -> Option<u64> {
        self.read_region(addr, 8)?.load_u64_le(0).ok()
    }

    fn write_u16(&self, addr: GuestAddress, value: u16) -> Result<(), SharedMemoryError> {
        self.write_region(addr, 2)?.store_u16_le(0, value)
    }

    fn write_u32(&self, addr: GuestAddress, value: u32) -> Result<(), SharedMemoryError> {
        self.write_region(addr, 4)?.store_u32_le(0, value)
    }
}

/// Scalar write whose failure ended a used-ring publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationStage {
    Id,
    Length,
    Index,
    AvailEvent,
}

/// Publication can fail after external I/O or earlier scalar writes committed.
/// This error never authorizes retrying the original device operation.
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    #[error("invalid used-ring publication geometry: {0}")]
    Geometry(&'static str),
    #[error("used-ring {stage:?} write at {address:#x} failed: {source}")]
    Write {
        stage: PublicationStage,
        address: u64,
        #[source]
        source: SharedMemoryError,
    },
}

impl PublicationError {
    /// The used index committed before the following event write failed.
    pub fn is_published(&self) -> bool {
        matches!(
            self,
            Self::Write {
                stage: PublicationStage::AvailEvent,
                ..
            }
        )
    }
}

impl From<PublicationError> for std::io::Error {
    fn from(error: PublicationError) -> Self {
        Self::other(error)
    }
}

/// Split virtqueue state.
///
/// Tracks guest-provided ring GPAs, queue size, and read/write cursors for
/// the available and used rings.
#[derive(Clone, Debug)]
pub struct Queue {
    /// Maximum queue size supported by the device.
    pub max_size: u16,
    /// Negotiated queue size (must be <= max_size, power of 2).
    pub size: u16,
    /// Whether the guest has enabled this queue.
    pub ready: bool,

    /// GPA of the descriptor table (16-byte aligned).
    pub desc_table: GuestAddress,
    /// GPA of the available ring (2-byte aligned).
    pub avail_ring: GuestAddress,
    /// GPA of the used ring (4-byte aligned).
    pub used_ring: GuestAddress,

    /// Next available ring index to consume.
    pub next_avail: Wrapping<u16>,
    /// Next used ring index to produce.
    pub next_used: Wrapping<u16>,

    /// Whether event index suppression is enabled.
    pub uses_notif_suppression: bool,

    /// MSI-X vector assigned to this queue by the guest (0xFFFF = no vector).
    pub msix_vector: u16,
}

impl Queue {
    /// Create a new queue with the given maximum size.
    pub fn new(max_size: u16) -> Self {
        Self {
            max_size,
            size: max_size,
            ready: false,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            uses_notif_suppression: false,
            msix_vector: 0xFFFF,
        }
    }

    /// Validate that the queue configuration is usable.
    ///
    /// Checks: size is non-zero and power of 2, size <= max_size, ring GPAs
    /// are non-zero and properly aligned, all ring regions fit within
    /// `mem_size`.
    pub fn is_valid(&self, mem_size: u64) -> bool {
        let size = self.size as u64;

        // Size must be non-zero, power of 2, and within max.
        if self.size == 0 || (self.size & (self.size - 1)) != 0 || self.size > self.max_size {
            return false;
        }

        // GPAs must be non-zero.
        let desc = self.desc_table.raw_value();
        let avail = self.avail_ring.raw_value();
        let used = self.used_ring.raw_value();

        if desc == 0 || avail == 0 || used == 0 {
            return false;
        }

        // Alignment: desc 16-byte, avail 2-byte, used 4-byte.
        if !desc.is_multiple_of(16) || !avail.is_multiple_of(2) || !used.is_multiple_of(4) {
            return false;
        }

        // Ring regions must fit within guest memory.
        // Descriptor table: 16 bytes per entry.
        let desc_end = desc.saturating_add(size * 16);
        // Available ring: flags(2) + idx(2) + ring[size](2*size) + used_event(2).
        let avail_end = avail.saturating_add(6 + 2 * size);
        // Used ring: flags(2) + idx(2) + ring[size](8*size) + avail_event(2).
        let used_end = used.saturating_add(6 + 8 * size);

        desc_end <= mem_size && avail_end <= mem_size && used_end <= mem_size
    }

    /// Pop the next available descriptor chain, if any.
    ///
    /// Returns `None` if the available ring is empty (next_avail == avail_idx).
    pub fn pop<M: QueueMemory>(&mut self, mem: &M) -> Option<DescriptorChain> {
        // Read avail_idx from avail ring (offset 2).
        let avail_idx = mem.read_u16(self.avail_ring.unchecked_add(2))?;

        // Nothing available.
        if self.next_avail == Wrapping(avail_idx) {
            return None;
        }

        // Observe the driver's descriptor and buffer writes before consuming them.
        fence(Ordering::Acquire);

        // Read descriptor index from the available ring.
        // ring[] starts at offset 4, each entry is u16.
        let ring_offset = 4 + 2 * (self.next_avail.0 % self.size) as u64;
        let desc_idx = mem.read_u16(self.avail_ring.unchecked_add(ring_offset))?;

        // Read the descriptor from the descriptor table.
        // Each descriptor is 16 bytes: addr(8) + len(4) + flags(2) + next(2).
        let desc_offset = (desc_idx as u64) * 16;
        let desc_addr = self.desc_table.unchecked_add(desc_offset);

        let addr = mem.read_u64(desc_addr)?;
        let len = mem.read_u32(desc_addr.unchecked_add(8))?;
        let flags = mem.read_u16(desc_addr.unchecked_add(12))?;
        let next = mem.read_u16(desc_addr.unchecked_add(14))?;

        self.next_avail += Wrapping(1);

        Some(DescriptorChain {
            index: desc_idx,
            addr: GuestAddress(addr),
            len,
            flags,
            next,
            desc_table: self.desc_table,
        })
    }

    /// Publish completion, preserving the exact successful scalar-write prefix.
    pub fn add_used<M: QueueMemory>(
        &mut self,
        mem: &M,
        desc_index: u16,
        len: u32,
    ) -> Result<(), PublicationError> {
        if self.size == 0 || !self.size.is_power_of_two() || self.size > self.max_size {
            return Err(PublicationError::Geometry("invalid queue size"));
        }
        if !self.used_ring.raw_value().is_multiple_of(4) {
            return Err(PublicationError::Geometry(
                "used ring is not four-byte aligned",
            ));
        }
        let base = self.used_ring.raw_value();
        let event_offset = 4 + 8 * u64::from(self.size);
        let extent = event_offset + if self.uses_notif_suppression { 2 } else { 0 };
        base.checked_add(extent)
            .ok_or(PublicationError::Geometry("used ring address overflows"))?;
        let element = base + 4 + 8 * u64::from(self.next_used.0 % self.size);
        let failure = |stage, address, source| PublicationError::Write {
            stage,
            address,
            source,
        };
        mem.write_u32(GuestAddress(element), u32::from(desc_index))
            .map_err(|error| failure(PublicationStage::Id, element, error))?;
        mem.write_u32(GuestAddress(element + 4), len)
            .map_err(|error| failure(PublicationStage::Length, element + 4, error))?;
        let next_used = self.next_used + Wrapping(1);
        // Publish payload and used element before the driver observes used_idx.
        fence(Ordering::Release);
        mem.write_u16(GuestAddress(base + 2), next_used.0)
            .map_err(|error| failure(PublicationStage::Index, base + 2, error))?;
        self.next_used = next_used;
        if self.uses_notif_suppression {
            mem.write_u16(GuestAddress(base + event_offset), self.next_avail.0)
                .map_err(|error| {
                    failure(PublicationStage::AvailEvent, base + event_offset, error)
                })?;
        }
        // Order event rearming before the next avail_idx read (lost-kick race).
        fence(Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestGuestMemory;
    use dillo_machine::memory::{
        AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement,
    };
    use vm_memory::Address;

    const QUEUE_SIZE: u16 = 16;

    /// Build guest memory and return (mem, desc_table_gpa, avail_ring_gpa, used_ring_gpa).
    fn setup_queue_memory(
        _queue_size: u16,
    ) -> (TestGuestMemory, GuestAddress, GuestAddress, GuestAddress) {
        // Layout: desc_table at 0x100 (16-byte aligned), avail at 0x1000, used at 0x2000
        let mem_size: u64 = 0x10000;
        let mem = TestGuestMemory::from_ranges(&[(GuestAddress(0), mem_size as usize)]).unwrap();
        let desc = GuestAddress(0x100);
        let avail = GuestAddress(0x1000);
        let used = GuestAddress(0x2000);
        (mem, desc, avail, used)
    }

    fn make_valid_queue(queue_size: u16) -> Queue {
        let mut q = Queue::new(queue_size);
        q.size = queue_size;
        q.ready = true;
        // Non-zero, properly aligned GPAs that fit within 0x10000
        q.desc_table = GuestAddress(0x100); // 16-byte aligned
        q.avail_ring = GuestAddress(0x1000); // 2-byte aligned
        q.used_ring = GuestAddress(0x2000); // 4-byte aligned
        q
    }

    fn shared_queue_memory(mem: &TestGuestMemory, base: u64, size: u64) -> SharedQueueMemory {
        SharedQueueMemory::new(vec![Arc::new(MappedSharedMemory::new(
            mem.owner(),
            SharedMemoryRequirement {
                range: AddressRange { base, size },
                access: SharedAccess::ReadWrite,
            },
        ))])
    }

    // --- Queue::new tests ---

    #[test]
    fn publication_failure_preserves_exact_prefix_cursor_and_effect() {
        use crate::test_support::FaultQueueMemory;
        for initial in [0, u16::MAX] {
            for fail in 0..4 {
                let (mem, _, _, _) = setup_queue_memory(16);
                let shared: Arc<dyn QueueMemory> =
                    Arc::new(SharedQueueMemory::new(vec![Arc::new(
                        MappedSharedMemory::for_guest_memory(mem.owner(), SharedAccess::ReadWrite),
                    )]));
                let fault = FaultQueueMemory::new(shared, fail);
                let mut queue = make_valid_queue(16);
                queue.uses_notif_suppression = true;
                queue.next_used = Wrapping(initial);
                queue.next_avail = Wrapping(7);
                let element = queue
                    .used_ring
                    .unchecked_add(4 + 8 * u64::from(initial % 16));
                let error = queue.add_used(&fault, 3, 77).unwrap_err();
                let expected = [
                    PublicationStage::Id,
                    PublicationStage::Length,
                    PublicationStage::Index,
                    PublicationStage::AvailEvent,
                ][fail];
                assert!(
                    matches!(&error, PublicationError::Write { stage, source: SharedMemoryError::Backing(_), .. } if *stage == expected)
                );
                assert_eq!(fault.attempts(), fail + 1, "no write after the failure");
                assert_eq!(
                    queue.next_used,
                    Wrapping(initial) + Wrapping(u16::from(fail == 3))
                );
                assert_eq!(queue.next_avail, Wrapping(7));
                assert_eq!(error.is_published(), fail == 3);
                assert_eq!(
                    mem.read_obj::<u32>(element).unwrap(),
                    if fail > 0 { 3 } else { 0 }
                );
                assert_eq!(
                    mem.read_obj::<u32>(element.unchecked_add(4)).unwrap(),
                    if fail > 1 { 77 } else { 0 }
                );
                assert_eq!(
                    mem.read_obj::<u16>(queue.used_ring.unchecked_add(2))
                        .unwrap(),
                    if fail == 3 {
                        initial.wrapping_add(1)
                    } else {
                        0
                    }
                );
                assert_eq!(
                    mem.read_obj::<u16>(queue.used_ring.unchecked_add(4 + 8 * 16))
                        .unwrap(),
                    0
                );
            }
        }
    }

    #[test]
    fn publication_without_event_idx_only_accesses_the_used_metadata_grant() {
        use crate::test_support::FaultQueueMemory;
        // RAM includes the reserved trailing bytes, but the write capability
        // grants only the flags, index and elements used without EVENT_IDX.
        let (mem, _, _, used) = setup_queue_memory(16);
        let event = used.unchecked_add(4 + 8 * 16);
        mem.write_obj::<u16>(0xbeef, event).unwrap();
        let memory: Arc<dyn QueueMemory> =
            Arc::new(shared_queue_memory(&mem, used.raw_value(), 4 + 8 * 16));
        let fault = FaultQueueMemory::new(memory, usize::MAX);
        let mut queue = make_valid_queue(16);
        queue.next_avail = Wrapping(7);
        queue.uses_notif_suppression = true;
        let mut queue = crate::device::VirtioActivate::new(vec![queue], vec![])
            .with_negotiated_features(crate::VIRTIO_F_VERSION_1)
            .take_queues()
            .pop()
            .unwrap();
        queue.add_used(&fault, 3, 77).unwrap();
        assert_eq!(fault.attempts(), 3);
        assert_eq!(queue.next_used, Wrapping(1));
        assert_eq!(mem.read_obj::<u16>(used.unchecked_add(2)).unwrap(), 1);
        assert_eq!(mem.read_obj::<u32>(used.unchecked_add(4)).unwrap(), 3);
        assert_eq!(mem.read_obj::<u32>(used.unchecked_add(8)).unwrap(), 77);
        assert_eq!(mem.read_obj::<u16>(event).unwrap(), 0xbeef);

        let mut queue = crate::device::VirtioActivate::new(vec![queue], vec![])
            .with_negotiated_features(crate::VIRTIO_F_VERSION_1 | crate::VIRTIO_F_RING_EVENT_IDX)
            .take_queues()
            .pop()
            .unwrap();
        let error = queue.add_used(&fault, 4, 88).unwrap_err();
        assert!(matches!(
            error,
            PublicationError::Write {
                stage: PublicationStage::AvailEvent,
                source: SharedMemoryError::OutOfLimits,
                ..
            }
        ));
        assert!(error.is_published());
        assert_eq!(fault.attempts(), 7);
        assert_eq!(queue.next_used, Wrapping(2));
        assert_eq!(mem.read_obj::<u16>(event).unwrap(), 0xbeef);
    }

    #[test]
    fn read_admission_preserves_fallback_after_provider_errors() {
        struct Refused(bool);
        impl SharedMemory for Refused {
            fn region(&self, _: SharedRange) -> Result<SharedRegion, SharedMemoryError> {
                Err(if self.0 {
                    SharedMemoryError::Unsupported
                } else {
                    SharedMemoryError::Backing("lost backing".into())
                })
            }
        }
        let (mem, _, _, _) = setup_queue_memory(16);
        mem.write_obj::<u64>(0x1234, GuestAddress(0x2000)).unwrap();
        for unsupported in [false, true] {
            let memory = SharedQueueMemory::new(vec![
                Arc::new(Refused(unsupported)),
                Arc::new(MappedSharedMemory::for_guest_memory(
                    mem.owner(),
                    SharedAccess::ReadWrite,
                )),
            ]);
            assert_eq!(memory.read_u16(GuestAddress(0x2000)), Some(0x1234));
            assert_eq!(memory.read_u32(GuestAddress(0x2000)), Some(0x1234));
            assert_eq!(memory.read_u64(GuestAddress(0x2000)), Some(0x1234));
            assert!(memory.write_u16(GuestAddress(0x2000), 9).is_err());
            assert_eq!(mem.read_obj::<u64>(GuestAddress(0x2000)).unwrap(), 0x1234);
        }
    }

    #[test]
    fn invalid_publication_geometry_is_rejected_before_any_store() {
        use crate::test_support::FaultQueueMemory;
        for (size, base) in [
            (0, 0x2000),
            (3, 0x2000),
            (32, 0x2000),
            (16, 0x2002),
            (16, u64::MAX - 3),
        ] {
            let fault = FaultQueueMemory::new(Arc::new(NullQueueMemory), 0);
            let mut queue = make_valid_queue(16);
            queue.size = size;
            queue.used_ring = GuestAddress(base);
            assert!(matches!(
                queue.add_used(&fault, 0, 0),
                Err(PublicationError::Geometry(_))
            ));
            assert_eq!(fault.attempts(), 0);
            assert_eq!(queue.next_used, Wrapping(0));
        }
    }

    #[test]
    fn write_admission_does_not_hide_backing_failure_behind_another_capability() {
        struct FailedBacking;
        impl SharedMemory for FailedBacking {
            fn region(&self, _: SharedRange) -> Result<SharedRegion, SharedMemoryError> {
                Err(SharedMemoryError::Backing("lost backing".into()))
            }
        }
        let (mem, _, _, _) = setup_queue_memory(16);
        let healthy: Arc<dyn SharedMemory> = Arc::new(MappedSharedMemory::for_guest_memory(
            mem.owner(),
            SharedAccess::ReadWrite,
        ));
        let memory = SharedQueueMemory::new(vec![Arc::new(FailedBacking), healthy]);
        assert!(
            matches!(memory.write_u32(GuestAddress(0x2004), 99), Err(SharedMemoryError::Backing(message)) if message == "lost backing")
        );
        assert_eq!(mem.read_obj::<u32>(GuestAddress(0x2004)).unwrap(), 0);
        let denied = SharedQueueMemory::new(vec![Arc::new(MappedSharedMemory::for_guest_memory(
            mem.owner(),
            SharedAccess::ReadOnly,
        ))]);
        assert!(matches!(
            denied.write_u16(GuestAddress(0x2002), 1),
            Err(SharedMemoryError::AccessDenied)
        ));
        assert!(matches!(
            SharedQueueMemory::new(vec![]).write_u16(GuestAddress(0x2002), 1),
            Err(SharedMemoryError::Unsupported)
        ));
    }

    #[test]
    fn shared_queue_scalars_use_atomic_service_and_refuse_misalignment() {
        let memory = TestGuestMemory::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        memory
            .write_slice(&[0x5a; 32], GuestAddress(0x100))
            .unwrap();
        memory
            .write_slice(&0x8877_6655_4433_2211u64.to_le_bytes(), GuestAddress(0x110))
            .unwrap();
        let queue_memory = shared_queue_memory(&memory, 0, 0x1000);
        assert!(queue_memory.write_u16(GuestAddress(0x102), 0x00ff).is_ok());
        assert!(
            queue_memory
                .write_u32(GuestAddress(0x104), 0x89ab_cdef)
                .is_ok()
        );
        assert_eq!(queue_memory.read_u16(GuestAddress(0x102)), Some(0x00ff));
        assert_eq!(
            queue_memory.read_u32(GuestAddress(0x104)),
            Some(0x89ab_cdef)
        );
        assert_eq!(
            queue_memory.read_u64(GuestAddress(0x110)),
            Some(0x8877_6655_4433_2211)
        );
        assert!(queue_memory.write_u16(GuestAddress(0x101), 0).is_err());
        assert!(queue_memory.write_u32(GuestAddress(0x106), 0).is_err());
        assert_eq!(queue_memory.read_u16(GuestAddress(0x101)), None);
        assert_eq!(queue_memory.read_u32(GuestAddress(0x106)), None);
        assert_eq!(queue_memory.read_u64(GuestAddress(0x114)), None);
        let mut bytes = [0; 8];
        memory.read_slice(&mut bytes, GuestAddress(0x100)).unwrap();
        assert_eq!(bytes, [0x5a, 0x5a, 0xff, 0, 0xef, 0xcd, 0xab, 0x89]);
    }

    #[test]
    fn test_new_defaults() {
        let q = Queue::new(256);
        assert_eq!(q.max_size, 256);
        assert_eq!(q.size, 256);
        assert!(!q.ready);
        assert_eq!(q.desc_table, GuestAddress(0));
        assert_eq!(q.avail_ring, GuestAddress(0));
        assert_eq!(q.used_ring, GuestAddress(0));
        assert_eq!(q.next_avail, Wrapping(0));
        assert_eq!(q.next_used, Wrapping(0));
    }

    // --- Queue::is_valid tests ---

    #[test]
    fn test_valid_queue() {
        let q = make_valid_queue(QUEUE_SIZE);
        // mem_size = 0x10000, all addresses fit
        assert!(q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_zero_size() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.size = 0;
        assert!(!q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_non_power_of_2() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.size = 3; // not a power of 2
        assert!(!q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_size_exceeds_max() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.size = QUEUE_SIZE + 1; // > max_size (also not power of 2, but tests max check)
        assert!(!q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_zero_desc_gpa() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = GuestAddress(0);
        // desc_table at 0 should be invalid (zero GPA)
        assert!(!q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_desc_alignment() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = GuestAddress(0x1001); // not 16-byte aligned
        assert!(!q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_avail_alignment() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.avail_ring = GuestAddress(0x1001); // not 2-byte aligned
        assert!(!q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_used_alignment() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.used_ring = GuestAddress(0x2001); // not 4-byte aligned
        assert!(!q.is_valid(0x10000));
    }

    #[test]
    fn test_invalid_gpa_exceeds_mem() {
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = GuestAddress(0x10000); // at the edge, ring extends past
        assert!(!q.is_valid(0x10000));
    }

    // --- Queue::pop tests ---

    #[test]
    fn test_pop_empty() {
        let (mem, desc, avail, used) = setup_queue_memory(QUEUE_SIZE);
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = desc;
        q.avail_ring = avail;
        q.used_ring = used;

        // avail_idx is 0, next_avail is 0 -> empty
        // Write avail_idx = 0 at avail_ring + 2
        mem.write_obj::<u16>(0, avail.unchecked_add(2)).unwrap();

        let shared = shared_queue_memory(&mem, 0, 0x4000);
        assert!(q.pop(&shared).is_none());
    }

    #[test]
    fn test_pop_returns_descriptor() {
        let (mem, desc, avail, used) = setup_queue_memory(QUEUE_SIZE);
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = desc;
        q.avail_ring = avail;
        q.used_ring = used;

        // Write a descriptor at index 0: addr=0x5000, len=128, flags=WRITE, next=0
        let desc_addr: u64 = 0x5000;
        let desc_len: u32 = 128;
        let desc_flags: u16 = VIRTQ_DESC_F_WRITE;
        let desc_next: u16 = 0;

        mem.write_obj(desc_addr, desc.unchecked_add(0)).unwrap(); // addr
        mem.write_obj(desc_len, desc.unchecked_add(8)).unwrap(); // len
        mem.write_obj(desc_flags, desc.unchecked_add(12)).unwrap(); // flags
        mem.write_obj(desc_next, desc.unchecked_add(14)).unwrap(); // next

        // Write avail ring: ring[0] = 0 (descriptor index), idx = 1
        mem.write_obj::<u16>(0, avail.unchecked_add(4)).unwrap(); // ring[0] = desc idx 0
        mem.write_obj::<u16>(1, avail.unchecked_add(2)).unwrap(); // avail_idx = 1

        let shared = shared_queue_memory(&mem, 0, 0x4000);
        let chain = q.pop(&shared).expect("should return a descriptor");
        assert_eq!(chain.addr, GuestAddress(0x5000));
        assert_eq!(chain.len, 128);
        assert_eq!(chain.flags, VIRTQ_DESC_F_WRITE);
        assert_eq!(q.next_avail, Wrapping(1));
    }

    #[test]
    fn test_pop_returns_descriptor_through_shared_memory() {
        let (mem, desc, avail, used) = setup_queue_memory(QUEUE_SIZE);
        let shared = SharedQueueMemory::new(vec![Arc::new(MappedSharedMemory::new(
            mem.owner(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0,
                    size: 0x4000,
                },
                access: SharedAccess::ReadWrite,
            },
        ))]);
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = desc;
        q.avail_ring = avail;
        q.used_ring = used;

        mem.write_obj::<u64>(0x5000, desc).unwrap();
        mem.write_obj::<u32>(128, desc.unchecked_add(8)).unwrap();
        mem.write_obj::<u16>(VIRTQ_DESC_F_WRITE, desc.unchecked_add(12))
            .unwrap();
        mem.write_obj::<u16>(0, desc.unchecked_add(14)).unwrap();
        mem.write_obj::<u16>(0, avail.unchecked_add(4)).unwrap();
        mem.write_obj::<u16>(1, avail.unchecked_add(2)).unwrap();

        let chain = q.pop(&shared).expect("shared queue memory should pop");
        assert_eq!(chain.addr, GuestAddress(0x5000));
        assert_eq!(chain.len, 128);
        assert_eq!(chain.flags, VIRTQ_DESC_F_WRITE);
        assert_eq!(q.next_avail, Wrapping(1));
    }

    #[test]
    fn test_pop_rejects_metadata_outside_shared_memory() {
        let (mem, desc, avail, used) = setup_queue_memory(QUEUE_SIZE);
        let shared = SharedQueueMemory::new(vec![Arc::new(MappedSharedMemory::new(
            mem.owner(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x1000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        ))]);
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = desc;
        q.avail_ring = avail;
        q.used_ring = used;

        mem.write_obj::<u16>(0, avail.unchecked_add(4)).unwrap();
        mem.write_obj::<u16>(1, avail.unchecked_add(2)).unwrap();

        assert!(q.pop(&shared).is_none());
        assert_eq!(q.next_avail, Wrapping(0));
    }

    // --- Queue::add_used tests ---

    #[test]
    fn test_add_used() {
        let (mem, desc, avail, used) = setup_queue_memory(QUEUE_SIZE);
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = desc;
        q.avail_ring = avail;
        q.used_ring = used;

        let shared = shared_queue_memory(&mem, 0x2000, 0x1000);
        q.add_used(&shared, 0, 64).unwrap();

        // used ring layout: flags(2) + idx(2) + ring[](id(4)+len(4))
        // After add_used: used_idx should be 1
        let used_idx: u16 = mem.read_obj(used.unchecked_add(2)).unwrap();
        assert_eq!(used_idx, 1);

        // Check ring[0]: id = 0, len = 64
        let ring_id: u32 = mem.read_obj(used.unchecked_add(4)).unwrap();
        let ring_len: u32 = mem.read_obj(used.unchecked_add(8)).unwrap();
        assert_eq!(ring_id, 0);
        assert_eq!(ring_len, 64);

        assert_eq!(q.next_used, Wrapping(1));
    }

    #[test]
    fn test_add_used_writes_through_shared_memory() {
        let (mem, desc, avail, used) = setup_queue_memory(QUEUE_SIZE);
        let shared = SharedQueueMemory::new(vec![Arc::new(MappedSharedMemory::new(
            mem.owner(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x2000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        ))]);
        let mut q = make_valid_queue(QUEUE_SIZE);
        q.desc_table = desc;
        q.avail_ring = avail;
        q.used_ring = used;

        q.add_used(&shared, 0, 64).unwrap();

        let used_idx: u16 = mem.read_obj(used.unchecked_add(2)).unwrap();
        let ring_id: u32 = mem.read_obj(used.unchecked_add(4)).unwrap();
        let ring_len: u32 = mem.read_obj(used.unchecked_add(8)).unwrap();
        assert_eq!(used_idx, 1);
        assert_eq!(ring_id, 0);
        assert_eq!(ring_len, 64);
        assert_eq!(q.next_used, Wrapping(1));
    }

    // --- Feature constants tests ---

    #[test]
    fn test_feature_constants() {
        use crate::features::*;
        assert_eq!(VIRTIO_F_VERSION_1, 1u64 << 32);
        assert_eq!(VIRTIO_F_RING_EVENT_IDX, 1u64 << 29);
        assert_eq!(TYPE_NET, 1);
        assert_eq!(TYPE_BLOCK, 2);
        assert_eq!(TYPE_CONSOLE, 3);
    }

    // --- VirtioDevice trait tests ---

    #[test]
    fn test_virtio_device_trait_is_object_safe() {
        // Verify VirtioDevice can be used as trait object
        fn _assert_object_safe(_: &dyn crate::device::VirtioDevice) {}
    }
}
