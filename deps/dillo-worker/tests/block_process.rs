// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the real executable/process boundary without requiring a native VM.

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use dillo_ipc::MemoryExport;
#[cfg(not(target_os = "macos"))]
use dillo_ipc::RamView;
#[cfg(not(target_os = "macos"))]
use dillo_machine::worker::WorkerHost;
use dillo_mmio::Interrupt;
use dillo_storage::{BlockBacking, Qcow2Backing, WritableBlockBacking};
use dillo_virtio::queue::Queue;
use dillo_virtio::{
    ActivateError, DeviceJoinError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
    VirtioDeviceHost, VirtioRunToken,
};
use dillo_virtio_blk::{RawImageBacking, VirtioBlk};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[cfg(target_os = "macos")]
use dillo_machine_hvf::worker::Worker;
#[cfg(target_os = "linux")]
use dillo_machine_kvm::worker::Worker;
#[cfg(target_os = "windows")]
use dillo_machine_whp::worker::Worker;

#[derive(Debug)]
struct Host(bool);

impl VirtioDeviceHost for Host {
    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        if self.0 {
            return Err(io::Error::other("injected relay spawn failure").into());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let token = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            run(VirtioRunToken::from_fn(move || {
                token.load(Ordering::Acquire)
            }))
        });
        Ok(VirtioDeviceHandle::new(
            move || stop.store(true, Ordering::Release),
            move || thread.join().unwrap(),
        ))
    }
}

struct Backend {
    device: VirtioBlk,
    mode: String,
}

impl VirtioDevice for Backend {
    fn device_type(&self) -> u32 {
        self.device.device_type()
    }
    fn num_queues(&self) -> usize {
        self.device.num_queues()
    }
    fn queue_max_sizes(&self) -> &[u16] {
        self.device.queue_max_sizes()
    }
    fn features(&self) -> u64 {
        self.device.features()
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.device.read_config(offset, data);
    }
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.device.write_config(offset, data);
    }
    fn reset(&mut self) -> Result<(), ActivateError> {
        self.device.reset()
    }
    fn quiesce(&mut self) -> Result<(), ActivateError> {
        self.device.quiesce()
    }
    fn resume(&mut self) -> Result<(), ActivateError> {
        self.device.resume()
    }
    fn activate(
        &mut self,
        activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        match self.mode.as_str() {
            "crash" => std::process::exit(42),
            "hang" => std::thread::sleep(Duration::from_secs(300)),
            _ => {}
        }
        self.device.activate(activation)
    }
}

// Hold one real backing call open so a control acknowledgement cannot pass
// merely because the worker happened to be idle when the request arrived.
struct GatedBacking {
    disk: RawImageBacking,
    gate: Mutex<Option<(File, File)>>,
}

impl WritableBlockBacking for GatedBacking {
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if let Some((mut entered, mut release)) = self.gate.lock().unwrap().take() {
            entered.write_all(&[1])?;
            release.read_exact(&mut [0])?;
        }
        self.disk.write_at(offset, data)
    }
}

impl BlockBacking for GatedBacking {
    fn writer(&self) -> Option<&dyn WritableBlockBacking> {
        Some(self)
    }
    fn len_bytes(&self) -> u64 {
        self.disk.len_bytes()
    }
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<usize> {
        self.disk.read_at(offset, bytes)
    }
    fn flush(&self) -> io::Result<()> {
        self.disk.flush()
    }
    fn get_id(&self) -> [u8; 20] {
        self.disk.get_id()
    }
    fn is_read_only(&self) -> bool {
        false
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--dillo-block-worker")
    {
        return dillo_worker::run::<Worker>(|config, mut files| {
            let forbidden = config["forbidden"].as_str().unwrap();
            assert!(
                File::open(forbidden).is_err(),
                "worker opened an unrelated host file"
            );
            assert!(
                std::net::TcpListener::bind("127.0.0.1:0").is_err(),
                "worker created a network socket"
            );
            assert!(
                std::process::Command::new(std::env::args_os().next().unwrap())
                    .arg("--not-a-worker")
                    .status()
                    .is_err(),
                "worker created a descendant"
            );
            let mode = config["mode"].as_str().unwrap();
            let backing: Arc<dyn BlockBacking> = if mode == "qcow2" {
                Arc::new(Qcow2Backing::open(storage(files.remove(0))?, false)?)
            } else if mode == "gated" {
                Arc::new(GatedBacking {
                    disk: RawImageBacking::new(files.remove(0), false)?,
                    gate: Mutex::new(Some((files.remove(0), files.remove(0)))),
                })
            } else {
                Arc::new(RawImageBacking::new(files.remove(0), false)?)
            };
            Ok(Box::new(Backend {
                device: VirtioBlk::new(backing, false),
                mode: mode.to_owned(),
            }))
        })
        .map_err(Into::into);
    }
    for mode in ["normal", "qcow2", "gated", "crash", "hang"]
        .into_iter()
        .chain(cfg!(target_os = "linux").then_some("native"))
    {
        exercise(mode)?;
    }
    println!(
        "block process: confinement, raw/qcow2 I/O, quiescence, reset, crash and deadline passed"
    );
    Ok(())
}

fn memory() -> io::Result<(GuestMemoryMmap, MemoryExport)> {
    #[cfg(target_os = "macos")]
    {
        let memory = dillo_machine_unix::allocate_memory(&[(GuestAddress(0), 2 << 20)])?;
        let export = dillo_machine_unix::export_memory(&memory)?;
        // Darwin POSIX shm fixes its size on the first ftruncate; even the
        // owner cannot shrink it after handing out writable views.
        let fd = export.resources[0].try_clone()?;
        assert!(nix::unistd::ftruncate(&fd, 0).is_err());
        return Ok((memory, export));
    }
    #[cfg(target_os = "linux")]
    let resource = {
        use nix::fcntl::{FcntlArg, SealFlag, fcntl};
        use nix::sys::memfd::{MFdFlags, memfd_create};
        let fd = memfd_create(
            c"block-process-test",
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )?;
        nix::unistd::ftruncate(&fd, 2 << 20)?;
        fcntl(
            &fd,
            FcntlArg::F_ADD_SEALS(
                SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_SEAL,
            ),
        )?;
        assert!(nix::unistd::ftruncate(&fd, 0).is_err());
        fd
    };
    #[cfg(target_os = "windows")]
    let resource = {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            System::Memory::{CreateFileMappingW, PAGE_READWRITE, SEC_COMMIT},
        };
        // SAFETY: a fresh committed pagefile section owned only by this fixture.
        #[allow(unsafe_code)]
        unsafe {
            let handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE | SEC_COMMIT,
                0,
                2 << 20,
                std::ptr::null(),
            );
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            OwnedHandle::from_raw_handle(handle)
        }
    };
    #[cfg(not(target_os = "macos"))]
    {
        let views = vec![RamView {
            gpa: 0,
            len: 2 << 20,
            offset: 0,
            resource: 0,
        }];
        let memory = Worker::map_memory(MemoryExport {
            views: views.clone(),
            resources: vec![resource.try_clone()?],
        })?;
        Ok((
            memory,
            MemoryExport {
                views,
                resources: vec![resource],
            },
        ))
    }
}

fn activation(
    interrupts: Arc<AtomicUsize>,
    fail_spawn: bool,
    mode: &str,
) -> (VirtioActivate, Kick) {
    let kick = if mode == "native" {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::eventfd::{EfdFlags, EventFd};
            let counter = EventFd::from_flags(EfdFlags::EFD_CLOEXEC).unwrap();
            Kick::from_notification(Worker::notification(counter.into()).unwrap())
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!("native counter fixture is Linux-only")
    } else {
        Kick::new().unwrap()
    };
    let mut queue = Queue::new(256);
    queue.size = 16;
    queue.ready = true;
    queue.desc_table = GuestAddress(0x1000);
    queue.avail_ring = GuestAddress(0x2000);
    queue.used_ring = GuestAddress(0x3000);
    let interrupt = Interrupt::from_fn(move || {
        interrupts.fetch_add(1, Ordering::Release);
    });
    (
        VirtioActivate::with_host_and_queue_interrupts(
            vec![queue],
            vec![kick.clone()],
            Arc::new(Host(fail_spawn)),
            vec![Some(interrupt)],
        )
        .with_negotiated_features((1 << 32) | (1 << 9)),
        kick,
    )
}

fn exercise(mode: &str) -> io::Result<()> {
    let forbidden = tempfile::NamedTempFile::new()?;
    let disk = tempfile::tempfile()?;
    if mode == "qcow2" {
        use imago::FormatCreateBuilder;
        imago::qcow2::Qcow2::<imago::file::File>::create_builder(storage(disk.try_clone()?)?)
            .cluster_size(65536)
            .size(4096)
            .create()?;
    } else {
        disk.set_len(4096)?;
    }
    let (memory, export) =
        memory().map_err(|e| io::Error::new(e.kind(), format!("prepare test RAM: {e}")))?;
    let failed = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&failed);
    let mut files = vec![disk.try_clone()?];
    let gate = if mode == "gated" {
        let (entered, notice) = std::io::pipe()?;
        let (release, proceed) = std::io::pipe()?;
        files.push(File::from(dillo_ipc::Resource::from(notice)));
        files.push(File::from(dillo_ipc::Resource::from(release)));
        Some((entered, proceed))
    } else {
        None
    };
    let prepared = dillo_worker::Prepared::new(
        &serde_json::json!({"mode":mode,"forbidden":forbidden.path()}),
        files,
    )?;
    let (mut proxy, control) = prepared
        .start::<Worker>(export, move || signal.store(true, Ordering::Release))
        .map_err(|e| io::Error::new(e.kind(), format!("start block worker: {e}")))?;
    let control = Arc::new(control);
    let interrupts = Arc::new(AtomicUsize::new(0));
    if mode == "normal" {
        let (activate, _) = activation(Arc::clone(&interrupts), true, mode);
        assert!(proxy.activate(activate).is_err());
        control.check()?;
    }
    let (activate, kick) = activation(Arc::clone(&interrupts), mode == "native", mode);
    let start = Instant::now();
    let result = proxy.activate(activate);
    if matches!(mode, "crash" | "hang") {
        assert!(result.is_err(), "bad child activated");
        assert!(
            failed.load(Ordering::Acquire),
            "failure did not wake the supervisor"
        );
        assert!(
            control.shutdown().is_err(),
            "failure was lost on retirement"
        );
        assert!(start.elapsed() < Duration::from_secs(15));
        return Ok(());
    }
    let old_activation = result.map_err(io::Error::other)?;
    request(&memory, 1, 1, 0x6a);
    kick.write(1)?;
    if let Some((mut entered, mut proceed)) = gate {
        let (send, receive) = std::sync::mpsc::channel();
        let notice = std::thread::spawn(move || send.send(entered.read_exact(&mut [0])));
        receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)??;
        notice.join().unwrap().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let pause = Arc::clone(&control);
        let waiter = std::thread::spawn(move || send.send(pause.quiesce()));
        let early = receive.recv_timeout(Duration::from_millis(30));
        // Release before asserting, including when an incorrect early ack was
        // observed, so a failed test cannot strand its backing operation.
        proceed.write_all(&[1])?;
        assert!(
            matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
            "quiescence acknowledged an outstanding backing call"
        );
        receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)??;
        waiter.join().unwrap().unwrap();
        complete(&memory, 1)?;
        control.resume()?;
    }
    complete(&memory, 1)?;
    let mut bytes = [0u8; 512];
    if mode == "normal" {
        read_at(&disk, &mut bytes, 512)?;
        assert_eq!(bytes, [0x6a; 512]);
    }

    request(&memory, 2, 0, 0);
    kick.write(1)?;
    complete(&memory, 2)?;
    memory.read_slice(&mut bytes, GuestAddress(0x5000)).unwrap();
    assert_eq!(bytes, [0x6a; 512]);
    assert!(interrupts.load(Ordering::Acquire) > 0);

    control.quiesce()?;
    let before = interrupts.load(Ordering::Acquire);
    request(&memory, 3, 1, 0x3c);
    kick.write(1)?;
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(
        memory
            .read_obj::<u16>(GuestAddress(0x3002))
            .unwrap()
            .to_le(),
        2
    );
    assert_eq!(memory.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0xff);
    assert_eq!(interrupts.load(Ordering::Acquire), before);
    if mode == "gated" {
        // Reset must join a parked worker without processing the queued write.
        control.reset()?;
        read_at(&disk, &mut bytes, 512)?;
        assert_eq!(bytes, [0x6a; 512]);
        assert_eq!(
            memory
                .read_obj::<u16>(GuestAddress(0x3002))
                .unwrap()
                .to_le(),
            2
        );
    } else {
        control.resume()?;
        complete(&memory, 3)?;
    }

    control.reset()?;
    memory.write_slice(&[0; 64], GuestAddress(0x2000)).unwrap();
    memory.write_slice(&[0; 256], GuestAddress(0x3000)).unwrap();
    let (activate, kick) = activation(interrupts, mode == "native", mode);
    let active = proxy.activate(activate).map_err(io::Error::other)?;
    // An old activation's eventual Drop must not stop the replacement epoch.
    drop(old_activation);
    request(&memory, 1, 1, 0xa5);
    kick.write(1)?;
    complete(&memory, 1)?;
    active.join().map_err(io::Error::other)?;
    control.shutdown()?;
    assert!(!failed.load(Ordering::Acquire));
    if mode == "qcow2" {
        Qcow2Backing::open(storage(disk)?, true)?.read_at(512, &mut bytes)?;
    } else {
        read_at(&disk, &mut bytes, 512)?;
    }
    assert_eq!(bytes, [0xa5; 512]);
    Ok(())
}

fn storage(file: File) -> io::Result<imago::file::File> {
    imago::file::File::from_open_file(file, imago::StorageOpenOptions::new().write(true))
}

fn request(memory: &GuestMemoryMmap, index: u16, operation: u32, fill: u8) {
    let descriptor = |offset, address: u64, len: u32, flags: u16, next: u16| {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&address.to_le_bytes());
        bytes[8..12].copy_from_slice(&len.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[14..].copy_from_slice(&next.to_le_bytes());
        memory.write_slice(&bytes, GuestAddress(offset)).unwrap();
    };
    descriptor(0x1000, 0x4000, 16, 1, 1);
    descriptor(0x1010, 0x5000, 512, if operation == 0 { 3 } else { 1 }, 2);
    descriptor(0x1020, 0x6000, 1, 2, 0);
    memory
        .write_slice(&operation.to_le_bytes(), GuestAddress(0x4000))
        .unwrap();
    memory
        .write_slice(&1u64.to_le_bytes(), GuestAddress(0x4008))
        .unwrap();
    memory
        .write_slice(&[fill; 512], GuestAddress(0x5000))
        .unwrap();
    memory.write_slice(&[0xff], GuestAddress(0x6000)).unwrap();
    memory
        .write_slice(
            &0u16.to_le_bytes(),
            GuestAddress(0x2004 + 2 * u64::from(index - 1)),
        )
        .unwrap();
    std::sync::atomic::fence(Ordering::Release);
    memory
        .write_slice(&index.to_le_bytes(), GuestAddress(0x2002))
        .unwrap();
}

fn complete(memory: &GuestMemoryMmap, index: u16) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while memory
        .read_obj::<u16>(GuestAddress(0x3002))
        .unwrap()
        .to_le()
        != index
    {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "used ring did not advance",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    std::sync::atomic::fence(Ordering::Acquire);
    assert_eq!(memory.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0);
    Ok(())
}

fn read_at(file: &File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, bytes, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, bytes, offset)
    }
}
