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

pub(super) fn native(
    client: dillo_worker::grant::Client,
    readonly: bool,
) -> io::Result<Box<dyn VirtioDevice>> {
    use dillo_virtio_fs::{FsBackend, LinuxErrno, SetAttr};
    use std::path::Path;

    let backend = super::filesystem_resources::GrantedFs::new(client);
    let source = Path::new("seed");
    assert_eq!(backend.read(source, 0, 6)?, b"worker");
    assert_eq!(backend.stat(source)?.size, 6);
    let error = backend.read(Path::new("../outside"), 0, 10).unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<LinuxErrno>()
            .unwrap()
            .linux,
        13
    );
    // Long names make each page exceed one native control frame. Pagination
    // bounds the authority's memory while the worker assembles FUSE metadata.
    assert_eq!(backend.readdir(Path::new("many"))?.len(), 300);
    if readonly {
        for result in [
            backend.write(source, 0, b"bad").map(|_| ()),
            backend.create(Path::new("denied"), 0o600).map(|_| ()),
        ] {
            assert_eq!(
                result
                    .unwrap_err()
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<LinuxErrno>()
                    .unwrap()
                    .linux,
                30
            );
        }
    } else {
        let data = vec![0xa5; 96 * 1024];
        let path = Path::new("created");
        backend.create(path, 0o600)?;
        assert_eq!(backend.write(path, 0, &data)?, data.len() as u32);
        assert_eq!(backend.read(path, 0, data.len() as u32)?, data);
        backend.create(Path::new("copy"), 0o600)?;
        assert_eq!(
            backend.copy_file_range(path, 0, Path::new("copy"), 0, data.len() as u64, 0)?,
            data.len() as u32
        );
        backend.setattr(
            path,
            &SetAttr {
                size: Some(3),
                ..Default::default()
            },
        )?;
        backend.rename(path, Path::new("renamed"), 0)?;
        backend.link(Path::new("renamed"), Path::new("alias"))?;
        assert_eq!(
            backend.stat(Path::new("alias"))?.ino,
            backend.stat(Path::new("renamed"))?.ino
        );
        backend.unlink(Path::new("alias"))?;
        backend.mkdir(Path::new("dir"), 0o700)?;
        backend.rmdir(Path::new("dir"))?;
        #[cfg(unix)]
        {
            backend.symlink(Path::new("link"), b"renamed")?;
            assert_eq!(backend.readlink(Path::new("link"))?, b"renamed");
            // Exercise the native xattr buffer's growth beyond its first read.
            let value = vec![255; 1024];
            backend.set_xattr(Path::new("renamed"), "user.vhost", &value, 0)?;
            assert_eq!(
                backend.get_xattr(Path::new("renamed"), "user.vhost")?,
                value
            );
            backend.remove_xattr(Path::new("renamed"), "user.vhost")?;
        }
    }
    Ok(Box::new(
        dillo_virtio_fs::VirtioFs::new("native", Arc::new(backend), readonly).unwrap(),
    ))
}

pub(super) fn native_exercise() -> io::Result<()> {
    eprintln!("vhost process: native filesystem grants, contents and read-only policy");
    for readonly in [false, true] {
        let directory = tempfile::tempdir()?;
        let share = directory.path().join("share");
        std::fs::create_dir(&share)?;
        std::fs::write(directory.path().join("outside"), b"private")?;
        std::fs::write(share.join("seed"), b"worker")?;
        std::fs::create_dir(share.join("many"))?;
        for i in 0..300 {
            std::fs::File::create(
                share
                    .join("many")
                    .join(format!("{i:03}-{}", "x".repeat(235))),
            )?;
        }
        let mut authority = super::filesystem_resources::Authority::new(&share, readonly)?;
        let prepared = dillo_worker::Prepared::new(
            dillo_worker::DeviceInfo {
                kind: 26,
                queues: vec![128; 2],
                config_len: 40,
            },
            &serde_json::json!({"mode":"filesystem-native", "readonly":readonly}),
            Vec::new(),
        )?
        .with_grants(move |bytes, _| authority.serve(bytes));
        let (_, export) = memory()?;
        let (_, control) = prepared.start::<Worker>(export, || {})?;
        control.shutdown()?;
        assert_eq!(std::fs::read(share.join("seed"))?, b"worker");
        assert!(!share.join("denied").exists());
        if !readonly {
            assert_eq!(std::fs::read(share.join("renamed"))?, [0xa5; 3]);
            assert_eq!(std::fs::read(share.join("copy"))?, vec![0xa5; 96 * 1024]);
        }
    }
    Ok(())
}
