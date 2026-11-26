// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exercise the real executable/process boundary and its resource confinement.

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use dillo_machine::worker::MemoryExport;
#[cfg(not(target_os = "macos"))]
use dillo_machine::worker::RamView;
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
struct Host(AtomicUsize);

impl VirtioDeviceHost for Host {
    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        if self
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_err()
        {
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

enum FirstWrite {
    Wait(File, File),
    Crash,
}

// Intervene inside a real backing call, after activation has succeeded.
struct ControlledBacking {
    disk: RawImageBacking,
    first: Mutex<Option<FirstWrite>>,
}

impl WritableBlockBacking for ControlledBacking {
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        match self.first.lock().unwrap().take() {
            Some(FirstWrite::Wait(mut entered, mut release)) => {
                entered.write_all(&[1])?;
                release.read_exact(&mut [0])?;
            }
            Some(FirstWrite::Crash) => std::process::exit(42),
            None => {}
        }
        self.disk.write_at(offset, data)
    }
}

impl BlockBacking for ControlledBacking {
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

#[path = "cases/bad_peer.rs"]
mod bad_peer;
#[path = "cases/console.rs"]
mod console;
#[cfg(windows)]
#[path = "cases/windows_sockets.rs"]
mod windows_sockets;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--dillo-block-worker")
    {
        let factory = |config: serde_json::Value,
                       mut files: Vec<File>|
         -> io::Result<Box<dyn VirtioDevice>> {
            if config["mode"] == "console" {
                return Ok(console::device(files));
            }
            let forbidden = config["forbidden"].as_str().unwrap();
            assert!(
                File::open(forbidden).is_err(),
                "worker opened an unrelated host file"
            );
            #[cfg(target_os = "linux")]
            {
                use nix::libc;
                use std::os::fd::AsRawFd;

                let path = std::ffi::CString::new(forbidden).unwrap();
                let mut metadata = std::mem::MaybeUninit::<libc::statx>::uninit();
                // SAFETY: the path and output storage remain valid for the
                // syscall; no output is read. An absolute path ignores dirfd.
                #[allow(unsafe_code)]
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_statx,
                        files[0].as_raw_fd(),
                        path.as_ptr(),
                        libc::AT_EMPTY_PATH,
                        libc::STATX_BASIC_STATS,
                        metadata.as_mut_ptr(),
                    )
                };
                assert_eq!(result, -1, "worker queried unrelated host file metadata");
            }
            let address = config["network"].as_str().unwrap().parse().unwrap();
            let network = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1));
            if config["mode"] == "network-grant" {
                network.expect("authorized host networking must include localhost");
            } else {
                assert!(network.is_err(), "worker reached an unauthorized endpoint");
            }
            assert!(
                std::process::Command::new(std::env::args_os().next().unwrap())
                    .arg("--not-a-worker")
                    .status()
                    .is_err(),
                "worker created a descendant"
            );
            let mode = config["mode"].as_str().unwrap();
            #[cfg(windows)]
            if mode == "network-broker" {
                windows_sockets::use_grant(&mut files)?;
            }
            if bad_peer::configure(mode, &mut files) {
                return Ok(Box::new(dillo_virtio_console::VirtioConsole::new()));
            }
            let backing: Arc<dyn BlockBacking> = if mode == "qcow2" {
                Arc::new(Qcow2Backing::open(storage(files.remove(0))?, false)?)
            } else if mode.starts_with("gated") || mode == "crash-io" {
                Arc::new(ControlledBacking {
                    disk: RawImageBacking::new(files.remove(0), false)?,
                    first: Mutex::new(Some(if mode == "crash-io" {
                        FirstWrite::Crash
                    } else {
                        FirstWrite::Wait(files.remove(0), files.remove(0))
                    })),
                })
            } else {
                Arc::new(RawImageBacking::new(files.remove(0), false)?)
            };
            Ok(Box::new(Backend {
                device: VirtioBlk::new(backing, false),
                mode: mode.to_owned(),
            }))
        };
        // SAFETY: the fixture enters before creating threads or other owned
        // handles; its parent supplies fixed shared RAM to a fresh process.
        #[allow(unsafe_code)]
        return unsafe { dillo_worker::run::<bad_peer::Host>(factory) }.map_err(Into::into);
    }
    if std::env::args().any(|arg| arg == "--network-probe") {
        return exercise("network-grant").map_err(Into::into);
    }
    #[cfg(windows)]
    if std::env::args().any(|arg| arg == "--socket-probe") {
        return exercise("network-broker").map_err(Into::into);
    }
    for mode in [
        "normal",
        "qcow2",
        "gated",
        "gated-reset",
        "gated-shutdown",
        "pci",
        "crash",
        "crash-io",
        "hang",
        "bad-flags",
        "bad-request",
        "reply-resource",
    ]
    .into_iter()
    .chain(cfg!(target_os = "linux").then_some("native"))
    .chain(cfg!(target_os = "macos").then_some("inherited-fd"))
    {
        eprintln!("block process: {mode}");
        exercise(mode)?;
    }
    console::exercise()?;
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
        // SAFETY: fixed, cacheable RAM with no existing host aliases. Later
        // child views are external accessors; this is the parent's sole mapping.
        #[allow(unsafe_code)]
        let memory = unsafe {
            Worker::map_memory(MemoryExport {
                views: views.clone(),
                resources: vec![resource.try_clone()?],
            })
        }?;
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
            // A native kick needs only the call-notification receiver. A
            // second spawn would reveal an unintended kick relay.
            Arc::new(Host(AtomicUsize::new(if fail_spawn {
                usize::from(mode == "native")
            } else {
                usize::MAX
            }))),
            vec![Some(interrupt)],
        )
        .with_negotiated_features((1 << 32) | (1 << 9)),
        kick,
    )
}

fn exercise(mode: &str) -> io::Result<()> {
    let forbidden = tempfile::NamedTempFile::new()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let network = listener.local_addr()?;
    // Establish a live endpoint, so refusal cannot pass through lack of a
    // listener. AppContainer enforces communication rather than socket creation.
    drop(std::net::TcpStream::connect(network)?);
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
    #[cfg(windows)]
    let socket_probe = (mode == "network-broker")
        .then(|| windows_sockets::serve(&mut files))
        .transpose()?;
    let gate = if mode.starts_with("gated") {
        let (entered, notice) = std::io::pipe()?;
        let (release, proceed) = std::io::pipe()?;
        files.push(File::from(dillo_machine::worker::Resource::from(notice)));
        files.push(File::from(dillo_machine::worker::Resource::from(release)));
        Some((entered, proceed))
    } else {
        None
    };
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 2,
            queues: vec![256],
            config_len: 48,
        },
        &serde_json::json!({"mode":mode,"forbidden":forbidden.path(),"network":network}),
        files,
    )?
    .with_policy(dillo_machine::worker::Policy {
        network: mode == "network-grant",
    });
    let startup = Instant::now();
    let start = || prepared.start::<Worker>(export, move || signal.store(true, Ordering::Release));
    #[cfg(target_os = "macos")]
    let result = if mode == "inherited-fd" {
        without_inherited_reader(start)
    } else {
        start()
    };
    #[cfg(not(target_os = "macos"))]
    let result = start();
    #[cfg(windows)]
    if let Some(probe) = socket_probe {
        probe.join().unwrap()?;
    }
    if matches!(mode, "bad-flags" | "bad-request" | "reply-resource") {
        assert!(result.is_err(), "malformed worker was admitted");
        let error = result.err().unwrap().to_string();
        assert!(
            error.contains(match mode {
                "bad-flags" => "invalid",
                "bad-request" => "unexpected vhost-user reply",
                _ => "unexpected backend reply resources",
            }),
            "{mode}: {error}"
        );
        assert!(failed.load(Ordering::Acquire));
        assert!(startup.elapsed() < Duration::from_secs(5));
        return Ok(());
    }
    let (mut proxy, control) =
        result.map_err(|e| io::Error::new(e.kind(), format!("start block worker: {e}")))?;
    if mode == "pci" {
        return pci_interrupts(proxy, control, &memory);
    }
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
    if mode == "crash-io" {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !failed.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            failed.load(Ordering::Acquire),
            "live failure was not reported"
        );
        assert!(control.check().is_err());
        assert!(control.shutdown().is_err());
        assert_eq!(memory.read_obj::<u16>(GuestAddress(0x3002)).unwrap(), 0);
        return Ok(());
    }
    if let Some((mut entered, mut proceed)) = gate {
        let (send, receive) = std::sync::mpsc::channel();
        let notice = std::thread::spawn(move || send.send(entered.read_exact(&mut [0])));
        receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)??;
        notice.join().unwrap().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let barrier = Arc::clone(&control);
        let action = mode.to_owned();
        let waiter = std::thread::spawn(move || {
            send.send(match action.as_str() {
                "gated-reset" => barrier.reset(),
                "gated-shutdown" => barrier.shutdown(),
                _ => barrier.quiesce(),
            })
        });
        let early = receive.recv_timeout(Duration::from_millis(30));
        // Release before asserting, including when an incorrect early ack was
        // observed, so a failed test cannot strand its backing operation.
        proceed.write_all(&[1])?;
        assert!(
            matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
            "{mode} acknowledged an outstanding backing call"
        );
        receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)??;
        waiter.join().unwrap().unwrap();
        complete(&memory, 1)?;
        if mode != "gated" {
            let mut bytes = [0; 512];
            read_at(&disk, &mut bytes, 512)?;
            assert_eq!(bytes, [0x6a; 512]);
            drop(old_activation);
            control.shutdown()?;
            assert!(!failed.load(Ordering::Acquire));
            return Ok(());
        }
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

    // Keep notifications arriving while control makes progress. Counts coalesce
    // and are not request counts; the queue is authoritative.
    let stop = Arc::new(AtomicBool::new(false));
    let pumping = Arc::clone(&stop);
    let notifications = kick.clone();
    let ready = Arc::new(std::sync::Barrier::new(2));
    let started = Arc::clone(&ready);
    let pump = std::thread::spawn(move || -> io::Result<()> {
        started.wait();
        while !pumping.load(Ordering::Acquire) {
            notifications.write(1)?;
            std::thread::yield_now();
        }
        Ok(())
    });
    ready.wait();
    let paused = control.quiesce();
    stop.store(true, Ordering::Release);
    pump.join().unwrap()?;
    paused?;
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

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn without_inherited_reader<T>(start: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    use nix::libc;
    use std::os::fd::{FromRawFd, OwnedFd};

    let (reader, writer) = nix::unistd::pipe()?;
    // Deliberately leave this descriptor inheritable, above the child's new
    // limit. The worker must close it before reporting readiness.
    let fd = nix::fcntl::fcntl(&reader, nix::fcntl::FcntlArg::F_DUPFD(128))?;
    // SAFETY: fcntl created this unique owned descriptor.
    let inherited = unsafe { OwnedFd::from_raw_fd(fd) };
    drop(reader);
    let mut saved = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the pointer is writable; this standalone fixture has no active
    // workers when it adjusts its own soft limit. The hard limit is preserved.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut saved) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let lower = libc::rlimit {
        rlim_cur: 64,
        rlim_max: saved.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lower) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = start();
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const saved) } != 0 {
        return Err(io::Error::last_os_error());
    }
    drop(inherited);
    let ready = result?;
    assert_eq!(
        nix::unistd::write(&writer, b"x"),
        Err(nix::errno::Errno::EPIPE)
    );
    Ok(ready)
}

// The native notifier intentionally does not filter masks. The parent transport
// must retain pending work and select the current route before reaching it.
#[derive(Default)]
struct PciSignals {
    entries: Mutex<[dillo_pci::MsixTableEntry; 2]>,
    delivered: Arc<Mutex<Vec<(u16, u32)>>>,
}

impl dillo_pci::MsixNotifier for PciSignals {
    fn vector_updated(&self, vector: u16, entry: &dillo_pci::MsixTableEntry) {
        self.entries.lock().unwrap()[usize::from(vector)] = *entry;
    }
    fn msix_enabled(&self, _: u16, _: bool) {}
    fn interrupt_for(&self, vector: u16) -> Option<Interrupt> {
        let data = self
            .entries
            .lock()
            .unwrap()
            .get(usize::from(vector))?
            .msg_data;
        let delivered = Arc::clone(&self.delivered);
        Some(Interrupt::from_fn(move || {
            delivered.lock().unwrap().push((vector, data));
        }))
    }
}

fn pci_interrupts(
    proxy: dillo_worker::Proxy,
    control: dillo_worker::Control,
    memory: &GuestMemoryMmap,
) -> io::Result<()> {
    use dillo_pci_virtio::VirtioPciDevice;
    let signals = Arc::new(PciSignals::default());
    let mut pci = VirtioPciDevice::new_with_notifier(
        Arc::new(Mutex::new(Box::new(proxy))),
        2,
        0x1000_0000,
        0x1000_1000,
        signals.clone(),
    );
    pci.set_host(Arc::new(Host(AtomicUsize::new(usize::MAX))));
    let mut cap = pci.config_read(0x34 / 4) & 0xff;
    while cap != 0 && pci.config_read(cap as usize / 4) as u8 != dillo_pci::CAP_ID_MSIX {
        cap = (pci.config_read(cap as usize / 4) >> 8) & 0xff;
    }
    assert_ne!(cap, 0);
    let cap = cap as usize / 4;
    pci.config_write(cap, 2, &0x8000u16.to_le_bytes());
    for (offset, value) in [
        (0x08, 1u32),
        (0x0c, 1),
        (0x20, 0x1000),
        (0x28, 0x2000),
        (0x30, 0x3000),
    ] {
        assert!(pci.bar_write(0, offset, &value.to_le_bytes()));
    }
    for (offset, value) in [(0x18, 16u16), (0x1a, 0), (0x1c, 1)] {
        assert!(pci.bar_write(0, offset, &value.to_le_bytes()));
    }
    assert!(pci.bar_write(0, 0x14, &[15]));
    let pending = |pci: &VirtioPciDevice| {
        let mut bytes = [0; 8];
        assert!(pci.bar_read(2, 0x800, &mut bytes));
        u64::from_le_bytes(bytes)
    };
    let submit = |pci: &mut VirtioPciDevice, index| -> io::Result<()> {
        request(memory, index, 1, 0x6a);
        assert!(pci.bar_write(0, 0x100, &0u16.to_le_bytes()));
        complete(memory, index)?;
        control.quiesce() // Also orders the parent's completion callback.
    };

    submit(&mut pci, 1)?;
    assert_eq!(pending(&pci), 1);
    assert!(signals.delivered.lock().unwrap().is_empty());
    // A changed route must be installed before releasing a masked completion.
    pci.bar_write(2, 8, &0x56u32.to_le_bytes());
    pci.bar_write(2, 12, &0u32.to_le_bytes());
    assert_eq!(*signals.delivered.lock().unwrap(), [(0, 0x56)]);
    assert_eq!(pending(&pci), 0);

    // Function masking also retains work; repeated masks cannot replay it.
    pci.config_write(cap, 2, &0xc000u16.to_le_bytes());
    control.resume()?;
    submit(&mut pci, 2)?;
    assert_eq!(pending(&pci), 1);
    assert_eq!(signals.delivered.lock().unwrap().len(), 1);
    pci.config_write(cap, 2, &0x8000u16.to_le_bytes());
    pci.config_write(cap, 2, &0x8000u16.to_le_bytes());
    assert_eq!(signals.delivered.lock().unwrap().len(), 2);

    // Queue-vector selection remains parent state after activation.
    pci.bar_write(2, 24, &0x78u32.to_le_bytes());
    pci.bar_write(2, 28, &0u32.to_le_bytes());
    pci.bar_write(0, 0x1a, &1u16.to_le_bytes());
    control.resume()?;
    submit(&mut pci, 3)?;
    assert_eq!(signals.delivered.lock().unwrap().last(), Some(&(1, 0x78)));

    pci.config_write(cap, 2, &0xc000u16.to_le_bytes());
    control.resume()?;
    submit(&mut pci, 4)?;
    assert_eq!(pending(&pci), 2);
    let delivered = signals.delivered.lock().unwrap().len();
    pci.bar_write(0, 0x14, &[0]);
    assert_eq!(pending(&pci), 0);
    pci.config_write(cap, 2, &0x8000u16.to_le_bytes());
    assert_eq!(signals.delivered.lock().unwrap().len(), delivered);
    control.shutdown()
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
