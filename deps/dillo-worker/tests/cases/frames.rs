// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;

use super::{
    Arc, AtomicUsize, Bytes, Duration, GuestAddress, Host, Kick, Queue, VirtioActivate,
    VirtioDevice, Worker, io, memory,
    queues::{base, submit, wait_used},
};

pub(super) fn exercise() -> io::Result<()> {
    eprintln!("vhost process: native frame endpoint and reset");
    let (peer, endpoint) = UnixDatagram::pair()?;
    peer.set_read_timeout(Some(Duration::from_secs(5)))?;
    endpoint.set_nonblocking(true)?;
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 1,
            queues: vec![256; 2],
            config_len: 8,
        },
        &serde_json::json!({"mode":"frames"}),
        vec![std::fs::File::from(OwnedFd::from(endpoint))],
    )?;
    let (memory, export) = memory()?;
    let (mut proxy, control) = prepared.start::<Worker>(export, || {})?;
    for _ in 0..2 {
        let queues = (0..2)
            .map(|index| {
                let base = base(index);
                memory
                    .write_slice(&[0; 0x3000], GuestAddress(base))
                    .unwrap();
                let mut queue = Queue::new(256);
                queue.size = 16;
                queue.ready = true;
                queue.desc_table = GuestAddress(base);
                queue.avail_ring = GuestAddress(base + 0x1000);
                queue.used_ring = GuestAddress(base + 0x2000);
                queue
            })
            .collect();
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
        submit(&memory, 0, 1, &[0; 128], true);
        kicks[0].write(1)?;
        peer.send(b"incoming frame")?;
        wait_used(&memory, 0, 1)?;
        let mut received = [0; 14];
        memory
            .read_slice(&mut received, GuestAddress(0x10_0000 + 12))
            .unwrap();
        assert_eq!(&received, b"incoming frame");
        let mut packet = vec![0; 12];
        packet.extend(b"outgoing frame");
        submit(&memory, 1, 1, &packet, false);
        kicks[1].write(1)?;
        wait_used(&memory, 1, 1)?;
        assert_eq!(peer.recv(&mut received)?, 14);
        assert_eq!(&received, b"outgoing frame");
        active.join().map_err(io::Error::other)?;
    }
    control.shutdown()
}
