// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Split virtqueue implementation for virtio devices.
//!
//! Provides the [`Queue`] struct for descriptor chain walking, available ring
//! consumption, and used ring production against guest memory.

use std::num::Wrapping;
use std::sync::Arc;

use dillo_mmio::{SharedAccess, SharedMemory, SharedMemoryError, SharedRange};
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
pub trait QueueMemory: Send + Sync {
    fn read_u16(&self, addr: GuestAddress) -> Option<u16>;

    fn read_u32(&self, addr: GuestAddress) -> Option<u32>;

    fn read_u64(&self, addr: GuestAddress) -> Option<u64>;

    fn write_u16(&self, addr: GuestAddress, value: u16) -> Option<()>;

    fn write_u32(&self, addr: GuestAddress, value: u32) -> Option<()>;
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

    fn write_u16(&self, _addr: GuestAddress, _value: u16) -> Option<()> {
        None
    }

    fn write_u32(&self, _addr: GuestAddress, _value: u32) -> Option<()> {
        None
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

    fn write_u16(&self, addr: GuestAddress, value: u16) -> Option<()> {
        (**self).write_u16(addr, value)
    }

    fn write_u32(&self, addr: GuestAddress, value: u32) -> Option<()> {
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

    fn read<const N: usize>(&self, addr: GuestAddress) -> Result<[u8; N], SharedMemoryError> {
        let mut last = SharedMemoryError::Unsupported;
        for capability in &self.capabilities {
            match capability.region(SharedRange {
                gpa: addr.raw_value(),
                size: N as u64,
                access: SharedAccess::ReadOnly,
            }) {
                Ok(region) => {
                    let mut data = [0u8; N];
                    region.read(0, &mut data)?;
                    return Ok(data);
                }
                Err(err) => last = err,
            }
        }
        Err(last)
    }

    fn write(&self, addr: GuestAddress, data: &[u8]) -> Result<(), SharedMemoryError> {
        let mut last = SharedMemoryError::Unsupported;
        for capability in &self.capabilities {
            match capability.region(SharedRange {
                gpa: addr.raw_value(),
                size: data.len() as u64,
                access: SharedAccess::WriteOnly,
            }) {
                Ok(region) => return region.write(0, data),
                Err(err) => last = err,
            }
        }
        Err(last)
    }
}

impl QueueMemory for SharedQueueMemory {
    fn read_u16(&self, addr: GuestAddress) -> Option<u16> {
        self.read(addr).ok().map(u16::from_le_bytes)
    }

    fn read_u32(&self, addr: GuestAddress) -> Option<u32> {
        self.read(addr).ok().map(u32::from_le_bytes)
    }

    fn read_u64(&self, addr: GuestAddress) -> Option<u64> {
        self.read(addr).ok().map(u64::from_le_bytes)
    }

    fn write_u16(&self, addr: GuestAddress, value: u16) -> Option<()> {
        self.write(addr, &value.to_le_bytes()).ok()
    }

    fn write_u32(&self, addr: GuestAddress, value: u32) -> Option<()> {
        self.write(addr, &value.to_le_bytes()).ok()
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

    /// Write a completed descriptor back to the used ring.
    pub fn add_used<M: QueueMemory>(&mut self, mem: &M, desc_index: u16, len: u32) {
        // Used ring layout: flags(2) + idx(2) + ring[size](id(4)+len(4)) + avail_event(2).
        // Each used element is 8 bytes: id (u32) + len (u32).
        let ring_offset = 4 + 8 * (self.next_used.0 % self.size) as u64;
        let elem_addr = self.used_ring.unchecked_add(ring_offset);

        // Write used element: id then len.
        let _ = mem.write_u32(elem_addr, desc_index as u32);
        let _ = mem.write_u32(elem_addr.unchecked_add(4), len);

        self.next_used += Wrapping(1);

        // Write updated used_idx at offset 2.
        let _ = mem.write_u16(self.used_ring.unchecked_add(2), self.next_used.0);

        // Update avail_event: tell the driver to notify us when it adds more
        // descriptors past what we've already seen. Without this, drivers using
        // VIRTIO_F_RING_EVENT_IDX suppress kicks after the first descriptor.
        let avail_event_offset = 4 + 8 * self.size as u64;
        let _ = mem.write_u16(
            self.used_ring.unchecked_add(avail_event_offset),
            self.next_avail.0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use vm_memory::{Address, Bytes, GuestMemoryMmap};

    const QUEUE_SIZE: u16 = 16;

    /// Build guest memory and return (mem, desc_table_gpa, avail_ring_gpa, used_ring_gpa).
    fn setup_queue_memory(
        _queue_size: u16,
    ) -> (GuestMemoryMmap, GuestAddress, GuestAddress, GuestAddress) {
        // Layout: desc_table at 0x100 (16-byte aligned), avail at 0x1000, used at 0x2000
        let mem_size: u64 = 0x10000;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size as usize)]).unwrap();
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

    fn shared_queue_memory(mem: &GuestMemoryMmap, base: u64, size: u64) -> SharedQueueMemory {
        SharedQueueMemory::new(vec![Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange { base, size },
                access: SharedAccess::ReadWrite,
            },
        ))])
    }

    // --- Queue::new tests ---

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
            mem.clone(),
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
            mem.clone(),
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
        q.add_used(&shared, 0, 64);

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
            mem.clone(),
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

        q.add_used(&shared, 0, 64);

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
