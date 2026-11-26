// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{Bytes, Duration, GuestAddress, GuestMemoryMmap, Instant, Ordering, io};

pub(super) fn base(queue: u64) -> u64 {
    0x1000 + queue * 0x4000
}

pub(super) fn submit(
    memory: &GuestMemoryMmap,
    queue: u64,
    sequence: u16,
    bytes: &[u8],
    write: bool,
) {
    let base = base(queue);
    let address = 0x10_0000 + queue * 0x1000;
    memory.write_slice(bytes, GuestAddress(address)).unwrap();
    memory
        .write_obj(address.to_le(), GuestAddress(base))
        .unwrap();
    memory
        .write_obj((bytes.len() as u32).to_le(), GuestAddress(base + 8))
        .unwrap();
    memory
        .write_obj(
            if write { 2u16.to_le() } else { 0 },
            GuestAddress(base + 12),
        )
        .unwrap();
    memory
        .write_obj(
            0u16,
            GuestAddress(base + 0x1004 + u64::from((sequence - 1) % 16) * 2),
        )
        .unwrap();
    std::sync::atomic::fence(Ordering::Release);
    memory
        .write_obj(sequence.to_le(), GuestAddress(base + 0x1002))
        .unwrap();
}

pub(super) fn wait_used(memory: &GuestMemoryMmap, queue: u64, count: u16) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while u16::from_le(
        memory
            .read_obj::<u16>(GuestAddress(base(queue) + 0x2002))
            .unwrap(),
    ) != count
    {
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!("queue {queue} did not complete")));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}
