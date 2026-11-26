// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use dillo_ipc::block::Geometry;
use dillo_virtio::queue::Queue;
use vm_memory::{Address, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

pub(crate) fn describe(queue: &Queue) -> Geometry {
    Geometry {
        size: queue.size,
        desc: queue.desc_table.raw_value(),
        avail: queue.avail_ring.raw_value(),
        used: queue.used_ring.raw_value(),
    }
}

pub(crate) fn admit(
    geometry: Geometry,
    max: u16,
    memory: &GuestMemoryMmap,
) -> std::io::Result<Queue> {
    let mut queue = Queue::new(max);
    queue.size = geometry.size;
    queue.ready = true;
    queue.desc_table = GuestAddress(geometry.desc);
    queue.avail_ring = GuestAddress(geometry.avail);
    queue.used_ring = GuestAddress(geometry.used);
    if !queue.is_valid(u64::MAX)
        || ![
            (geometry.desc, 16 * usize::from(geometry.size)),
            (geometry.avail, 6 + 2 * usize::from(geometry.size)),
            (geometry.used, 6 + 8 * usize::from(geometry.size)),
        ]
        .into_iter()
        .all(|(gpa, len)| memory.check_range(GuestAddress(gpa), len))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "queue lies outside exported RAM",
        ));
    }
    Ok(queue)
}
