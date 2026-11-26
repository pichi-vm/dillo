// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in privileged native vmnet bootstrap and confined queue exercise.

use super::{
    Arc, AtomicUsize, Bytes, GuestAddress, Host, Kick, Queue, VirtioActivate, VirtioDevice, Worker,
    io, memory,
    queues::{base, submit, wait_used},
};

pub(super) fn prepare(interface: &str) -> io::Result<Arc<dyn dillo_virtio_net::NetBackend>> {
    Ok(Arc::new(dillo_virtio_net::VmnetBackend::open(interface)?))
}

pub(super) fn exercise(interface: &str) -> io::Result<()> {
    eprintln!("vhost process: privileged native vmnet on {interface}");
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 1,
            queues: vec![256; 2],
            config_len: 8,
        },
        &serde_json::json!({"mode":"vmnet", "interface":interface}),
        Vec::new(),
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
        let mut packet = vec![0; 12 + 64];
        packet[12..18].fill(0xff);
        packet[18..24].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        packet[24..26].copy_from_slice(&0x88b5u16.to_be_bytes());
        submit(&memory, 1, 1, &packet, false);
        kicks[1].write(1)?;
        wait_used(&memory, 1, 1)?;
        active.join().map_err(io::Error::other)?;
        control.check()?;
    }
    control.shutdown()
}
