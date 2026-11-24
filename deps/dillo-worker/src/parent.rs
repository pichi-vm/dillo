// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::thread::JoinHandle;
use std::time::Duration;

use dillo_ipc::{Channel, MemoryExport, Process, Resource, encode};
use dillo_machine::worker::WorkerHost;
use dillo_mmio::Interrupt;
use dillo_virtio::{
    ActivateError, DeviceJoinError, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
};

use crate::protocol::{CONFIG_LEN, Command, Geometry, Init, QUEUE_MAX, Request, Response};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Authorized files and backend parameters, before a native Machine exists.
#[derive(Debug)]
pub struct Prepared {
    backend: serde_json::Value,
    files: Vec<Resource>,
}

impl Prepared {
    pub fn new(backend: &impl serde::Serialize, files: Vec<File>) -> io::Result<Self> {
        Ok(Self {
            backend: serde_json::to_value(backend).map_err(io::Error::other)?,
            files: files.into_iter().map(Into::into).collect(),
        })
    }

    /// Bind to this Machine's RAM and admit the child only after its Ready
    /// response. The callback wakes the Machine supervisor on a sticky failure.
    pub fn start<H: WorkerHost>(
        self,
        memory: MemoryExport,
        failed: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<(Proxy, Control)> {
        let (process, mut channel) = H::spawn(&std::env::current_exe()?)?;
        let shared = Arc::new(Shared {
            failure: Mutex::new(None),
            failed: Box::new(failed),
            retiring: AtomicBool::new(false),
            interrupt: Mutex::new(None),
            active: AtomicU64::new(0),
        });
        let (responses, receiver) = mpsc::sync_channel(1);
        let input = channel.try_clone()?;
        let reader_shared = Arc::clone(&shared);
        let reader = std::thread::Builder::new()
            .name("block-events".into())
            .spawn(move || receive(input, &reader_shared, &responses))?;
        let init = Init {
            version: 1,
            files: self.files.len(),
            memory: memory.views,
            backend: self.backend,
        };
        let resources = Arc::new(
            self.files
                .into_iter()
                .chain(memory.resources)
                .collect::<Vec<_>>(),
        );
        let (commands, outgoing) = mpsc::sync_channel::<Request>(1);
        let init = encode(&init)?;
        let startup_resources = Arc::clone(&resources);
        let writer_shared = Arc::clone(&shared);
        let writer = std::thread::Builder::new()
            .name("block-controls".into())
            .spawn(move || {
                #[cfg(unix)]
                let borrowed = {
                    use std::os::fd::AsFd;
                    startup_resources
                        .iter()
                        .map(AsFd::as_fd)
                        .collect::<Vec<_>>()
                };
                #[cfg(windows)]
                let borrowed = {
                    use std::os::windows::io::AsHandle;
                    startup_resources
                        .iter()
                        .map(AsHandle::as_handle)
                        .collect::<Vec<_>>()
                };
                if let Err(error) = channel.send(&init, &borrowed) {
                    writer_shared.fail(error.to_string());
                    return;
                }
                while let Ok(request) = outgoing.recv() {
                    if let Err(error) = encode(&request).and_then(|bytes| channel.send(&bytes, &[]))
                    {
                        writer_shared.fail(error.to_string());
                        break;
                    }
                }
            })?;
        let session = Arc::new(Session {
            shared,
            process: Mutex::new(process),
            commands: Mutex::new(Some(commands)),
            replies: Mutex::new(receiver),
            serial: Mutex::new(()),
            next: AtomicU64::new(1),
            threads: Mutex::new(vec![reader, writer]),
            retired: AtomicBool::new(false),
            _resources: resources,
        });
        let response = session.response().map_err(|error| {
            // A failed child's last pipe may close before its process becomes
            // signalled. Allow that short interval to retain the native exit
            // status in the startup error, without an unbounded wait.
            let mut status = session.process.lock().unwrap().try_wait();
            for _ in 0..20 {
                if !matches!(status, Ok(None)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
                status = session.process.lock().unwrap().try_wait();
            }
            let failure = session.shared.failure.lock().unwrap().clone();
            io::Error::other(format!(
                "worker readiness: {error}; status={status:?}; failure={failure:?}"
            ))
        })?;
        let Response::Ready { features, config } = response else {
            return Err(io::Error::other("worker did not report readiness"));
        };
        if config.len() != CONFIG_LEN || features & (1 << 32) == 0 {
            return Err(io::Error::other("invalid block worker capabilities"));
        }
        let control = Control(Arc::clone(&session));
        Ok((
            Proxy {
                session,
                features,
                config,
                next_epoch: 1,
            },
            control,
        ))
    }
}

struct Shared {
    failure: Mutex<Option<String>>,
    failed: Box<dyn Fn() + Send + Sync>,
    retiring: AtomicBool,
    interrupt: Mutex<Option<(u64, Interrupt)>>,
    active: AtomicU64,
}

impl Shared {
    fn fail(&self, error: String) {
        if !self.retiring.load(Ordering::Acquire) {
            self.failure.lock().unwrap().get_or_insert(error);
            (self.failed)();
        }
    }
}

fn receive(mut input: Box<dyn Channel>, shared: &Shared, replies: &mpsc::SyncSender<Response>) {
    let result = (|| -> io::Result<()> {
        loop {
            let frame = input.receive()?;
            if !frame.resources.is_empty() {
                return Err(io::Error::other("worker returned unauthorized resources"));
            }
            let response: Response = frame.decode()?;
            match response {
                Response::Used { epoch } => {
                    let interrupt = shared
                        .interrupt
                        .lock()
                        .unwrap()
                        .as_ref()
                        .filter(|(active, _)| *active == epoch)
                        .map(|(_, interrupt)| interrupt.clone());
                    // Never hold the session mutex while entering native IRQ
                    // code. Reset and control replies cannot depend on it.
                    if let Some(interrupt) = interrupt {
                        interrupt.signal();
                    }
                }
                Response::Failed(error) => return Err(io::Error::other(error)),
                response => replies.try_send(response).map_err(io::Error::other)?,
            }
        }
    })();
    if let Err(error) = result {
        shared.fail(error.to_string());
    }
}

struct Session {
    // Retain the parent's file locks until the child has retired.
    _resources: Arc<Vec<Resource>>,
    shared: Arc<Shared>,
    process: Mutex<Box<dyn Process>>,
    commands: Mutex<Option<mpsc::SyncSender<Request>>>,
    replies: Mutex<mpsc::Receiver<Response>>,
    serial: Mutex<()>,
    next: AtomicU64,
    retired: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Session {
    fn response(&self) -> io::Result<Response> {
        self.replies
            .lock()
            .unwrap()
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(io::Error::other)
    }

    fn request(&self, command: Command) -> io::Result<()> {
        let _serial = self.serial.lock().unwrap();
        if let Command::Kick { epoch } = &command
            && self.shared.active.load(Ordering::Acquire) != *epoch
        {
            return Ok(());
        }
        let result = (|| {
            if let Some(error) = &*self.shared.failure.lock().unwrap() {
                return Err(io::Error::other(error.clone()));
            }
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            self.commands
                .lock()
                .unwrap()
                .as_ref()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .try_send(Request { id, command })
                .map_err(io::Error::other)?;
            match self.response()? {
                Response::Reply { id: reply, error } if id == reply => {
                    error.map_or(Ok(()), |error| Err(io::Error::other(error)))
                }
                _ => Err(io::Error::other("unexpected worker reply")),
            }
        })();
        if let Err(error) = &result {
            self.shared.fail(error.to_string());
            let _ = self.process.lock().unwrap().terminate();
        }
        result
    }

    fn reset(&self, epoch: u64) -> io::Result<()> {
        if self
            .shared
            .active
            .compare_exchange(epoch, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        let result = self.request(Command::Reset { epoch });
        self.shared.interrupt.lock().unwrap().take();
        result
    }

    fn reap(&self) -> io::Result<()> {
        if self.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        self.shared.retiring.store(true, Ordering::Release);
        let mut process = self.process.lock().unwrap();
        if process.try_wait()?.is_none() {
            process.terminate()?;
        }
        process.wait()?;
        self.retired.store(true, Ordering::Release);
        self.commands.lock().unwrap().take();
        for thread in self.threads.lock().unwrap().drain(..) {
            thread
                .join()
                .map_err(|_| io::Error::other("worker relay panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.reap() {
            log::error!("block worker retirement: {error}");
        }
    }
}

/// Supervisor ownership is separate from the transport's proxy/activation.
pub struct Control(Arc<Session>);

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control").finish_non_exhaustive()
    }
}

impl Control {
    pub fn check(&self) -> io::Result<()> {
        self.0
            .shared
            .failure
            .lock()
            .unwrap()
            .as_ref()
            .map_or(Ok(()), |error| Err(io::Error::other(error.clone())))
    }

    pub fn reset(&self) -> io::Result<()> {
        let epoch = self.0.shared.active.load(Ordering::Acquire);
        if epoch == 0 {
            Ok(())
        } else {
            self.0.reset(epoch)
        }
    }

    pub fn shutdown(&self) -> io::Result<()> {
        if self.0.retired.load(Ordering::Acquire) {
            return self.check();
        }
        self.0.shared.retiring.store(true, Ordering::Release);
        let stopped = self.0.request(Command::Shutdown);
        let reaped = self.0.reap();
        self.check().and(stopped).and(reaped)
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        // Covers launch errors and unwinding before the explicit supervisor
        // shutdown. This owner is created after the Machine and drops first.
        if !self.0.retired.load(Ordering::Acquire)
            && let Err(error) = self.shutdown()
        {
            log::error!("block worker shutdown: {error}");
        }
    }
}

/// Cached block configuration plus the lifecycle connection. Guest register
/// reads remain in the parent, independent of child scheduling.
pub struct Proxy {
    session: Arc<Session>,
    features: u64,
    config: Vec<u8>,
    next_epoch: u64,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

impl VirtioDevice for Proxy {
    fn device_type(&self) -> u32 {
        2
    }
    fn num_queues(&self) -> usize {
        1
    }
    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX]
    }
    fn features(&self) -> u64 {
        self.features
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = usize::try_from(offset)
                .ok()
                .and_then(|offset| offset.checked_add(i))
                .and_then(|offset| self.config.get(offset))
                .copied()
                .unwrap_or(0);
        }
    }
    fn write_config(&mut self, _: u64, _: &[u8]) {}

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let host = activation.host()?;
        let mut queues = activation.take_queues();
        let mut kicks = activation.take_queue_evts();
        if queues.len() != 1
            || kicks.len() != 1
            || self.session.shared.active.load(Ordering::Acquire) != 0
        {
            return Err(ActivateError::InvalidConfig(
                "invalid block activation".into(),
            ));
        }
        let epoch = self.next_epoch;
        self.next_epoch = epoch
            .checked_add(1)
            .ok_or_else(|| ActivateError::InvalidConfig("activation epoch exhausted".into()))?;
        if let Some(interrupt) = activation.queue_interrupt(0) {
            *self.session.shared.interrupt.lock().unwrap() = Some((epoch, interrupt));
        }
        let queue = queues.remove(0);
        self.session.shared.active.store(epoch, Ordering::Release);
        if let Err(error) = self.session.request(Command::Activate {
            epoch,
            features: activation.negotiated_features(),
            queue: Geometry::from_queue(&queue),
        }) {
            self.session.shared.active.store(0, Ordering::Release);
            self.session.shared.interrupt.lock().unwrap().take();
            return Err(error.into());
        }
        let kick = kicks.remove(0);
        let wake = kick.clone();
        let session = Arc::clone(&self.session);
        let relay = match host.spawn(Box::new(move |token| {
            loop {
                kick.read()
                    .map_err(|error| DeviceJoinError::Worker(error.to_string()))?;
                if token.is_shutdown_requested() {
                    return Ok(());
                }
                session
                    .request(Command::Kick { epoch })
                    .map_err(|error| DeviceJoinError::Worker(error.to_string()))?;
            }
        })) {
            Ok(relay) => relay.with_shutdown_wake(wake),
            Err(error) => {
                self.session.reset(epoch)?;
                return Err(error);
            }
        };
        let relay = Arc::new(Mutex::new(Some(relay)));
        let stop_relay = Arc::clone(&relay);
        let session = Arc::clone(&self.session);
        Ok(VirtioDeviceHandle::new(
            move || {
                if let Some(relay) = stop_relay.lock().unwrap().as_mut() {
                    relay.shutdown();
                }
                if let Err(error) = session.reset(epoch) {
                    session.shared.fail(error.to_string());
                }
            },
            move || {
                relay
                    .lock()
                    .unwrap()
                    .take()
                    .map_or(Ok(()), VirtioDeviceHandle::join)
            },
        ))
    }
}
