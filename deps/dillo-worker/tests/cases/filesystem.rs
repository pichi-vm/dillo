// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! FUSE queue and reset semantics, independent of native directory grants.

use super::{
    Arc, AtomicUsize, Bytes, Duration, GuestAddress, GuestMemoryMmap, Host, Instant, Kick,
    Ordering, Queue, VirtioActivate, VirtioDevice, Worker, io, memory,
};

pub(super) fn device() -> Box<dyn VirtioDevice> {
    let tree = dillo_virtio_fs::MapFs::new().with_file("hello", b"worker".to_vec());
    Box::new(dillo_virtio_fs::VirtioFs::new("vhost", Arc::new(tree), true).unwrap())
}

fn request(
    memory: &GuestMemoryMmap,
    kick: &Kick,
    sequence: u16,
    opcode: u32,
    node: u64,
    body: &[u8],
) -> io::Result<Vec<u8>> {
    let mut input = vec![0; 40];
    input[..4].copy_from_slice(&(40 + body.len() as u32).to_le_bytes());
    input[4..8].copy_from_slice(&opcode.to_le_bytes());
    input[8..16].copy_from_slice(&u64::from(sequence).to_le_bytes());
    input[16..24].copy_from_slice(&node.to_le_bytes());
    input.extend(body);
    memory.write_slice(&input, GuestAddress(0x10_0000)).unwrap();
    for (index, address, len, flags, next) in [
        (0u64, 0x10_0000u64, input.len() as u32, 1u16, 1u16),
        (1, 0x10_1000, 512, 2, 0),
    ] {
        let mut desc = Vec::new();
        desc.extend(address.to_le_bytes());
        desc.extend(len.to_le_bytes());
        desc.extend(flags.to_le_bytes());
        desc.extend(next.to_le_bytes());
        memory
            .write_slice(&desc, GuestAddress(0x5000 + index * 16))
            .unwrap();
    }
    memory
        .write_obj(
            0u16,
            GuestAddress(0x6004 + u64::from((sequence - 1) % 16) * 2),
        )
        .unwrap();
    std::sync::atomic::fence(Ordering::Release);
    memory
        .write_obj(sequence.to_le(), GuestAddress(0x6002))
        .unwrap();
    kick.write(1)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while u16::from_le(memory.read_obj(GuestAddress(0x7002)).unwrap()) != sequence {
        assert!(Instant::now() < deadline, "FUSE request deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
    let len = u32::from_le(memory.read_obj(GuestAddress(0x10_1000)).unwrap());
    assert!((16..=512).contains(&len));
    let mut reply = vec![0; len as usize];
    memory
        .read_slice(&mut reply, GuestAddress(0x10_1000))
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(reply[8..16].try_into().unwrap()),
        u64::from(sequence)
    );
    Ok(reply)
}

pub(super) fn exercise() -> io::Result<()> {
    eprintln!("vhost process: in-memory filesystem");
    let (memory, export) = memory()?;
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 26,
            queues: vec![128; 2],
            config_len: 40,
        },
        &serde_json::json!({"mode":"filesystem"}),
        Vec::new(),
    )?;
    let (mut proxy, control) = prepared.start::<Worker>(export, || {})?;
    let mut config = [0; 40];
    proxy.read_config(0, &mut config);
    assert_eq!(&config[..5], b"vhost");
    assert_eq!(u32::from_le_bytes(config[36..40].try_into().unwrap()), 1);
    let mut old_handle = None;
    for _ in 0..2 {
        let mut queues = Vec::new();
        for base in [0x1000, 0x5000] {
            memory
                .write_slice(&[0; 0x3000], GuestAddress(base))
                .unwrap();
            let mut queue = Queue::new(128);
            queue.size = 16;
            queue.ready = true;
            queue.desc_table = GuestAddress(base);
            queue.avail_ring = GuestAddress(base + 0x1000);
            queue.used_ring = GuestAddress(base + 0x2000);
            queues.push(queue);
        }
        let kicks = vec![Kick::new()?, Kick::new()?];
        let active = proxy
            .activate(
                VirtioActivate::with_host_and_queue_interrupts(
                    queues,
                    kicks.clone(),
                    Arc::new(Host(AtomicUsize::new(usize::MAX))),
                    vec![None; 2],
                )
                .with_negotiated_features(proxy.features()),
            )
            .map_err(io::Error::other)?;
        let mut sequence = 1;
        if let Some(handle) = old_handle {
            let reply = request(&memory, &kicks[1], sequence, 15, 2, &read_args(handle))?;
            assert_eq!(i32::from_le_bytes(reply[4..8].try_into().unwrap()), -9);
            sequence += 1;
        }
        let reply = request(&memory, &kicks[1], sequence, 1, 1, b"hello\0")?;
        assert_eq!(&reply[4..8], &[0; 4]);
        let node = u64::from_le_bytes(reply[16..24].try_into().unwrap());
        let reply = request(&memory, &kicks[1], sequence + 1, 14, node, &[0; 8])?;
        assert_eq!(&reply[4..8], &[0; 4]);
        let handle = u64::from_le_bytes(reply[16..24].try_into().unwrap());
        let reply = request(
            &memory,
            &kicks[1],
            sequence + 2,
            15,
            node,
            &read_args(handle),
        )?;
        assert_eq!(&reply[4..8], &[0; 4]);
        assert_eq!(&reply[16..], b"worker");
        old_handle = Some(handle);
        active.join().map_err(io::Error::other)?;
    }
    control.shutdown()
}

fn read_args(handle: u64) -> [u8; 40] {
    let mut body = [0; 40];
    body[..8].copy_from_slice(&handle.to_le_bytes());
    body[16..20].copy_from_slice(&6u32.to_le_bytes());
    body
}
