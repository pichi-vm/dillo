// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exercise legal frontend sequences independently of the production proxy.

use super::{Bytes, Duration, GuestAddress, Read, Worker, Write, io, memory};
use dillo_ipc::vhost_user::{
    self as wire, Frame,
    request::{
        ADD_MEM_REG, GET_FEATURES, GET_PROTOCOL_FEATURES, GET_VRING_BASE, REM_MEM_REG,
        SET_FEATURES, SET_MEM_TABLE, SET_OWNER, SET_PROTOCOL_FEATURES, SET_VRING_ADDR,
        SET_VRING_BASE, SET_VRING_ENABLE, SET_VRING_KICK, SET_VRING_NUM,
    },
};
use dillo_machine::worker::{
    BorrowedResource, Channel, MemoryExport, Message, Policy, Process, Resource, WorkerHost,
};
use std::sync::mpsc;

#[cfg(unix)]
use std::os::fd::AsFd as AsResource;
#[cfg(windows)]
use std::os::windows::io::AsHandle as AsResource;

struct Frontend {
    process: Box<dyn Process>,
    channel: Box<dyn Channel>,
    replies: mpsc::Receiver<io::Result<Message>>,
    reader: Option<std::thread::JoinHandle<()>>,
    handoff: Option<Resource>,
}

impl Drop for Frontend {
    fn drop(&mut self) {
        self.handoff.take();
        let _ = self.process.terminate();
        let _ = self.process.wait();
        self.reader.take().unwrap().join().unwrap();
    }
}

impl Frontend {
    fn command(
        &mut self,
        request: u32,
        payload: Vec<u8>,
        resources: &[BorrowedResource<'_>],
    ) -> io::Result<()> {
        let reply = self.exchange(
            Frame {
                request,
                flags: wire::VERSION | wire::NEED_REPLY,
                payload,
            },
            resources,
        )?;
        assert_eq!(reply.payload, 0u64.to_ne_bytes());
        Ok(())
    }

    fn exchange(&mut self, frame: Frame, resources: &[BorrowedResource<'_>]) -> io::Result<Frame> {
        self.channel.send(&frame.encode()?, resources)?;
        let message = self
            .replies
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)??;
        let reply = Frame::decode(&message.bytes)?;
        assert_eq!(reply.request, frame.request);
        assert_eq!(reply.flags, wire::VERSION | wire::REPLY);
        assert!(message.resources.is_empty());
        Ok(reply)
    }

    fn get(&mut self, request: u32, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        Ok(self
            .exchange(
                Frame {
                    request,
                    flags: wire::VERSION,
                    payload,
                },
                &[],
            )?
            .payload)
    }

    fn configure(&mut self, index: u32, region: u64) -> io::Result<()> {
        let base = super::queues::base(region);
        self.command(SET_VRING_NUM, wire::state(index, 16), &[])?;
        self.command(SET_VRING_BASE, wire::state(index, 0), &[])?;
        let mut address = wire::state(index, 0);
        for value in [base, base + 0x2000, base + 0x1000, 0] {
            address.extend(value.to_ne_bytes());
        }
        self.command(SET_VRING_ADDR, address, &[])
    }

    fn map(&mut self, export: &MemoryExport) -> io::Result<()> {
        let mut table = wire::state(export.views.len() as u32, 0);
        for view in &export.views {
            for value in [view.gpa, view.len, view.gpa, view.offset] {
                table.extend(value.to_ne_bytes());
            }
        }
        #[cfg(unix)]
        let resources = export
            .resources
            .iter()
            .map(|r| r.as_fd())
            .collect::<Vec<_>>();
        #[cfg(windows)]
        let resources = export
            .resources
            .iter()
            .map(|r| r.as_handle())
            .collect::<Vec<_>>();
        self.command(SET_MEM_TABLE, table, &resources)
    }

    fn start(&mut self, index: u64) -> io::Result<()> {
        // An absent kick FD explicitly requests polling, not a stopped ring.
        self.command(SET_VRING_KICK, (0x100 | index).to_ne_bytes().to_vec(), &[])
    }

    fn stop(&mut self, index: u32, base: u32) -> io::Result<()> {
        assert_eq!(
            self.get(GET_VRING_BASE, wire::state(index, 0))?,
            wire::state(index, base)
        );
        Ok(())
    }
}

pub(super) fn exercise() -> io::Result<()> {
    eprintln!("vhost process: independent ring start, stop, disable and relocation");
    let (memory, export) = memory()?;
    let mut input = tempfile::tempfile()?;
    input.write_all(b"rx")?;
    std::io::Seek::rewind(&mut input)?;
    let output = tempfile::tempfile()?;
    let (process, mut bootstrap) = Worker::spawn(&std::env::current_exe()?, Policy::default())?;
    let (channel, endpoint) = bootstrap.pair()?;
    let mut incoming = channel.try_clone()?;
    let (send, replies) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        loop {
            let message = incoming.receive();
            let done = message.is_err();
            if send.send(message).is_err() || done {
                break;
            }
        }
    });
    let mut peer = Frontend {
        process,
        channel,
        replies,
        reader: Some(reader),
        handoff: Some(endpoint),
    };
    #[cfg(unix)]
    let files = [
        input.as_fd(),
        output.as_fd(),
        peer.handoff.as_ref().unwrap().as_fd(),
    ];
    #[cfg(windows)]
    let files = [
        input.as_handle(),
        output.as_handle(),
        peer.handoff.as_ref().unwrap().as_handle(),
    ];
    bootstrap.send(
        &dillo_ipc::encode(&dillo_ipc::bootstrap::Init {
            version: 3,
            files: 2,
            grants: false,
            backend: serde_json::json!({"mode":"rings"}),
            policy: Policy::default(),
        })?,
        &files,
    )?;
    let features = u64::from_ne_bytes(peer.get(GET_FEATURES, vec![])?.try_into().unwrap());
    assert_ne!(features & wire::PROTOCOL_FEATURES, 0);
    peer.handoff.take();
    drop(bootstrap);
    let protocols = wire::REPLY_ACK | wire::GPA_ADDRESSES | wire::CONFIGURE_MEM_SLOTS;
    let available =
        u64::from_ne_bytes(peer.get(GET_PROTOCOL_FEATURES, vec![])?.try_into().unwrap());
    assert_eq!(available & protocols, protocols);
    peer.channel.send(
        &Frame {
            request: SET_PROTOCOL_FEATURES,
            flags: wire::VERSION,
            payload: protocols.to_ne_bytes().to_vec(),
        }
        .encode()?,
        &[],
    )?;
    peer.command(SET_OWNER, vec![], &[])?;
    peer.command(
        SET_FEATURES,
        ((1u64 << 32) | wire::PROTOCOL_FEATURES)
            .to_ne_bytes()
            .to_vec(),
        &[],
    )?;
    peer.map(&export)?;

    // TX can start while RX has never been configured. Initially disabled,
    // it consumes the request without producing host output.
    peer.configure(1, 1)?;
    peer.start(1)?;
    super::queues::submit(&memory, 1, 1, b"discard", false);
    super::queues::wait_used(&memory, 1, 1)?;
    assert_eq!(output.metadata()?.len(), 0);
    peer.command(SET_VRING_ENABLE, wire::state(1, 1), &[])?;
    super::queues::submit(&memory, 1, 2, b"keep", false);
    super::queues::wait_used(&memory, 1, 2)?;
    peer.stop(1, 2)?;
    super::queues::submit(&memory, 1, 3, b"stopped", false);

    // Disabled RX does not deliver input. Enabling RX progresses it while TX
    // remains stopped; stopping one queue must not suspend the other.
    peer.configure(0, 0)?;
    peer.start(0)?;
    super::queues::submit(&memory, 0, 1, &[0; 2], true);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(memory.read_obj::<u16>(GuestAddress(0x3002)).unwrap(), 0);
    peer.command(SET_VRING_ENABLE, wire::state(0, 1), &[])?;
    super::queues::wait_used(&memory, 0, 1)?;
    let mut received = [0; 2];
    memory
        .read_slice(&mut received, GuestAddress(0x10_0000))
        .unwrap();
    assert_eq!(&received, b"rx");
    assert_eq!(
        u16::from_le(memory.read_obj::<u16>(GuestAddress(0x7002)).unwrap()),
        2
    );

    // Replace RAM while RX is running. Preserve its queue state in the new
    // backing, then add and remove an unused slot through the same live map.
    let (replacement, new_export) = super::memory()?;
    let mut ring_bytes = vec![0; 0x10_000];
    memory.read_slice(&mut ring_bytes, GuestAddress(0)).unwrap();
    replacement
        .write_slice(&ring_bytes, GuestAddress(0))
        .unwrap();
    peer.map(&new_export)?;
    #[cfg(unix)]
    let resource = export.resources[0].as_fd();
    #[cfg(windows)]
    let resource = export.resources[0].as_handle();
    let slot: Vec<_> = [0u64, 0x4000_0000, 2 << 20, 0x4000_0000, 0]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect();
    peer.command(ADD_MEM_REG, slot.clone(), &[resource])?;
    peer.command(REM_MEM_REG, slot, &[])?;

    // Reconfigure only the stopped TX ring, leaving RX and the console state
    // intact. Its old pending descriptor must never be consumed.
    peer.configure(1, 3)?;
    peer.start(1)?;
    super::queues::submit(&replacement, 3, 1, b"moved", false);
    super::queues::wait_used(&replacement, 3, 1)?;
    peer.stop(1, 1)?;
    peer.stop(0, 1)?;
    assert_eq!(
        u16::from_le(memory.read_obj::<u16>(GuestAddress(0x7002)).unwrap()),
        2
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while output.metadata()?.len() != 9 {
        assert!(
            std::time::Instant::now() < deadline,
            "console output deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut output = output;
    std::io::Seek::rewind(&mut output)?;
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"keepmoved");
    Ok(())
}
