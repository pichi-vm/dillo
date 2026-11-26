// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::net::UnixListener;

use super::{
    Arc, AtomicUsize, Bytes, Duration, GuestAddress, Host, Instant, Kick, Queue, Read,
    VirtioActivate, VirtioDevice, Worker, Write, io, memory,
    queues::{base, submit, wait_used},
};

pub(super) fn device(mut grants: dillo_worker::grant::Client) -> Box<dyn VirtioDevice> {
    // A malformed resource request grants nothing and leaves the session usable.
    assert!(grants.request(&[0], |_| Ok(())).is_err());
    Box::new(dillo_virtio_vsock::VirtioVsock::with_connector(
        3,
        move |port| {
            grants.request(&port.to_ne_bytes(), |mut message| {
                assert!(message.bytes.is_empty());
                assert_eq!(message.resources.len(), 1);
                Ok(message.resources.pop().unwrap().into())
            })
        },
    ))
}

fn packet(operation: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(3u64.to_le_bytes()); // guest CID
    bytes.extend(2u64.to_le_bytes()); // host CID
    bytes.extend(1234u32.to_le_bytes());
    bytes.extend(42u32.to_le_bytes());
    bytes.extend((data.len() as u32).to_le_bytes());
    bytes.extend(1u16.to_le_bytes()); // stream
    bytes.extend(operation.to_le_bytes());
    bytes.extend(0u32.to_le_bytes()); // flags
    bytes.extend(65536u32.to_le_bytes()); // receive credit
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(data);
    bytes
}

pub(super) fn exercise() -> io::Result<()> {
    eprintln!("vhost process: vsock native grants and reset");
    let (_, export) = memory()?;
    let failed = Arc::new(super::AtomicBool::new(false));
    let observed = Arc::clone(&failed);
    let started = Instant::now();
    let bad = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 19,
            queues: vec![128; 3],
            config_len: 8,
        },
        &serde_json::json!({"mode":"vsock"}),
        Vec::new(),
    )?
    .with_grants(|_, _| panic!("injected resource service failure"));
    assert!(
        bad.start::<Worker>(export, move || observed
            .store(true, super::Ordering::Release))
            .is_err()
    );
    assert!(failed.load(super::Ordering::Acquire));
    assert!(started.elapsed() < Duration::from_secs(6));
    // The checkout is writable even when the runner denies global /tmp.
    // Use a relative socket name to stay within sockaddr_un's path limit.
    let directory = tempfile::tempdir_in(".")?;
    let path = std::path::PathBuf::from(directory.path().file_name().unwrap());
    let listener = UnixListener::bind(path.join("42.sock"))?;
    listener.set_nonblocking(true)?;
    let echo = std::thread::spawn(move || -> io::Result<()> {
        for _ in 0..2 {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            // Darwin inherits O_NONBLOCK from the listener; the echo peer uses
            // bounded blocking reads on each accepted stream.
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes)?;
            assert_eq!(&bytes, b"ping");
            stream.write_all(&bytes)?;
            assert_eq!(stream.read(&mut bytes)?, 0, "reset retained the old stream");
        }
        Ok(())
    });
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 19,
            queues: vec![128; 3],
            config_len: 8,
        },
        &serde_json::json!({"mode":"vsock"}),
        Vec::new(),
    )?
    .with_grants(move |request, _channel| {
        let port = u32::from_ne_bytes(
            request
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidInput)?,
        );
        let stream = dillo_virtio_vsock::connect_port(&path, port)?;
        Ok(dillo_machine::worker::Message {
            bytes: Vec::new(),
            resources: vec![stream.into()],
        }
        .into())
    });
    let (memory, export) = memory()?;
    let (mut proxy, control) = prepared.start::<Worker>(export, || {})?;
    for _ in 0..2 {
        let queues = (0..3)
            .map(|index| {
                let base = base(index);
                memory
                    .write_slice(&[0; 0x3000], GuestAddress(base))
                    .unwrap();
                let mut queue = Queue::new(128);
                queue.size = 16;
                queue.ready = true;
                queue.desc_table = GuestAddress(base);
                queue.avail_ring = GuestAddress(base + 0x1000);
                queue.used_ring = GuestAddress(base + 0x2000);
                queue
            })
            .collect();
        let kicks = vec![Kick::new()?, Kick::new()?, Kick::new()?];
        let active = proxy
            .activate(
                VirtioActivate::with_host_and_queue_interrupts(
                    queues,
                    kicks.clone(),
                    Arc::new(Host(AtomicUsize::new(usize::MAX))),
                    vec![None; 3],
                )
                .with_negotiated_features(proxy.features()),
            )
            .map_err(io::Error::other)?;
        for (sequence, operation, data) in [(1, 1, &[][..]), (2, 5, &b"ping"[..])] {
            eprintln!("vsock operation {operation}, sequence {sequence}");
            submit(&memory, 0, sequence, &[0; 128], true);
            kicks[0].write(1)?;
            submit(&memory, 1, sequence, &packet(operation, data), false);
            kicks[1].write(1)?;
            wait_used(&memory, 1, sequence)?;
            wait_used(&memory, 0, sequence)?;
            let mut reply = [0; 48];
            memory
                .read_slice(&mut reply, GuestAddress(0x10_0000))
                .unwrap();
            assert_eq!(
                u16::from_le_bytes(reply[30..32].try_into().unwrap()),
                if operation == 1 { 2 } else { 5 }
            );
            if operation == 5 {
                assert_eq!(&reply[44..48], b"ping");
            }
        }
        active.join().map_err(io::Error::other)?;
    }
    control.shutdown()?;
    echo.join().unwrap()
}
