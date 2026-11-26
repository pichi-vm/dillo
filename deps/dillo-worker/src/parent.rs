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
use std::time::{Duration, Instant};

use dillo_ipc::bootstrap::Init;
use dillo_ipc::vhost_user::{
    self as wire, Frame,
    request::{
        ADD_MEM_REG, GET_CONFIG, GET_FEATURES, GET_MAX_MEM_SLOTS, GET_PROTOCOL_FEATURES,
        GET_QUEUE_NUM, GET_VRING_BASE, RESET_DEVICE, SET_FEATURES, SET_MEM_TABLE, SET_OWNER,
        SET_PROTOCOL_FEATURES, SET_VRING_ADDR, SET_VRING_BASE, SET_VRING_CALL, SET_VRING_ENABLE,
        SET_VRING_KICK, SET_VRING_NUM,
    },
};
use dillo_machine::worker::{
    BorrowedResource, Channel, MemoryExport, NotificationRole, Policy, Process, Resource,
    WorkerHost, WriteNotification,
};
use dillo_virtio::{
    ActivateError, DeviceJoinError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
};

#[cfg(unix)]
use std::os::fd::AsFd as AsResource;
#[cfg(windows)]
use std::os::windows::io::AsHandle as AsResource;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const PROTOCOL: u64 = wire::MQ
    | wire::REPLY_ACK
    | wire::CONFIG
    | wire::RESET_DEVICE
    | wire::CONFIGURE_MEM_SLOTS
    | wire::GPA_ADDRESSES;

struct Outgoing {
    frame: Frame,
    resources: Vec<Resource>,
    sent: Option<mpsc::SyncSender<()>>,
}

/// Frontend metadata comes from the device model selected by the launcher.
/// Vhost-user negotiates its features and queue state, not its virtio type.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub kind: u32,
    pub queues: Vec<u16>,
    pub config_len: usize,
}

#[must_use]
pub struct Prepared {
    info: DeviceInfo,
    backend: serde_json::Value,
    files: Vec<Resource>,
    config_poll: Option<Box<dyn FnMut() -> io::Result<()> + Send>>,
    retained: Vec<Box<dyn Send>>,
    policy: Policy,
    grants: Option<crate::grant::Service>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl Prepared {
    pub fn new(
        info: DeviceInfo,
        backend: &impl serde::Serialize,
        files: Vec<File>,
    ) -> io::Result<Self> {
        Ok(Self {
            info,
            backend: serde_json::to_value(backend).map_err(io::Error::other)?,
            files: files.into_iter().map(Into::into).collect(),
            config_poll: None,
            retained: Vec::new(),
            policy: Policy::default(),
            grants: None,
        })
    }

    pub fn num_queues(&self) -> usize {
        self.info.queues.len()
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Grant native resources through a dedicated connection. The service must
    /// restrict requests to its configured resources and bound native calls;
    /// it is joined after the worker has exited, including startup failures.
    pub fn with_grants(
        mut self,
        service: impl FnMut(&[u8], &dyn Channel) -> io::Result<crate::grant::Grant> + Send + 'static,
    ) -> Self {
        self.grants = Some(Box::new(service));
        self
    }

    /// Retain a launcher-owned host adapter until the worker is retired.
    pub fn retain(mut self, resource: impl Send + 'static) -> Self {
        self.retained.push(Box::new(resource));
        self
    }

    /// Refresh dynamic configuration with GET_CONFIG. Poll the native adapter
    /// first, allowing terminal-size input to reach its granted worker pipe.
    pub fn with_config_poll(
        mut self,
        poll: impl FnMut() -> io::Result<()> + Send + 'static,
    ) -> Self {
        self.config_poll = Some(Box::new(poll));
        self
    }

    pub fn start<H: WorkerHost>(
        self,
        memory: MemoryExport,
        failed: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<(Proxy, Control)> {
        let (process, mut bootstrap) = H::spawn(&std::env::current_exe()?, self.policy)?;
        let (mut channel, endpoint) = bootstrap.pair()?;
        let grants = self
            .grants
            .map(|service| {
                bootstrap
                    .pair()
                    .map(|(channel, endpoint)| (service, channel, endpoint))
            })
            .transpose()?;
        let mut handoff = vec![endpoint.try_clone()?];
        if let Some((_, _, endpoint)) = &grants {
            handoff.push(endpoint.try_clone()?);
        }
        let input = channel.try_clone()?;
        let shared = Arc::new(Shared {
            failure: Mutex::new(None),
            failed: Box::new(failed),
            retiring: AtomicBool::new(false),
            active: AtomicU64::new(0),
        });
        let (responses, replies) = mpsc::sync_channel(1);
        let reader_shared = Arc::clone(&shared);
        let reader = std::thread::Builder::new()
            .name("vhost-replies".into())
            .spawn(move || receive(input, &reader_shared, &responses))?;
        let init = dillo_ipc::encode(&Init {
            version: 3,
            files: self.files.len(),
            grants: grants.is_some(),
            backend: self.backend,
            policy: self.policy,
        })?;
        let files = Arc::new(self.files);
        let startup_files = Arc::clone(&files);
        let (commands, outgoing) = mpsc::sync_channel::<Outgoing>(1);
        let writer_shared = Arc::clone(&shared);
        let (service, grant_endpoint) = match grants {
            Some((service, channel, endpoint)) => (Some((service, channel)), Some(endpoint)),
            None => (None, None),
        };
        let writer = std::thread::Builder::new()
            .name("vhost-controls".into())
            .spawn(move || {
                let mut borrowed = borrow_resources(&startup_files);
                if let Some(endpoint) = &grant_endpoint {
                    borrowed.extend(borrow_resources(std::slice::from_ref(endpoint)));
                }
                borrowed.extend(borrow_resources(std::slice::from_ref(&endpoint)));
                let result = bootstrap.send(&init, &borrowed);
                // Keeping the peer endpoint here would prevent EOF after the child
                // exits. Only backend file locks survive bootstrap in the parent.
                drop(borrowed);
                drop(endpoint);
                drop(grant_endpoint);
                drop(bootstrap);
                if let Err(error) = result {
                    writer_shared.fail(error.to_string());
                    return;
                }
                while let Ok(outgoing) = outgoing.recv() {
                    let borrowed = borrow_resources(&outgoing.resources);
                    if let Err(error) = outgoing
                        .frame
                        .encode()
                        .and_then(|bytes| channel.send(&bytes, &borrowed))
                    {
                        writer_shared.fail(error.to_string());
                        break;
                    }
                    if let Some(sent) = outgoing.sent {
                        let _ = sent.send(());
                    }
                }
            })?;
        let session = Arc::new(Session {
            shared,
            process: Mutex::new(process),
            commands: Mutex::new(Some(commands)),
            replies: Mutex::new(replies),
            serial: Mutex::new(()),
            lifecycle: Mutex::new(()),
            threads: Mutex::new(vec![reader, writer]),
            retired: AtomicBool::new(false),
            kicks: Mutex::new(Vec::new()),
            pair: H::notification_pair,
            endpoint: H::notification_endpoint,
            _files: files,
            retained: Mutex::new(self.retained),
        });
        if let Some((service, channel)) = service {
            let shared = Arc::clone(&session.shared);
            let thread = std::thread::Builder::new()
                .name("worker-grants".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        crate::grant::serve(channel, service)
                    }))
                    .unwrap_or_else(|_| Err(io::Error::other("resource service panicked")));
                    if let Err(error) = result {
                        shared.fail(format!("worker resource grant: {error}"));
                    }
                });
            let thread = match thread {
                Ok(thread) => thread,
                Err(error) => {
                    drop(handoff);
                    return Err(error);
                }
            };
            session.threads.lock().unwrap().push(thread);
        }
        let features = session.get(GET_FEATURES, Vec::new());
        // Keep the transferred socket reachable until the receiver has adopted
        // it. Darwin's Unix-socket GC can flush a socket whose only remaining
        // reference is an in-flight SCM_RIGHTS message. The first standard
        // reply proves adoption; also release on failure before joining I/O.
        drop(handoff);
        let features = wire::scalar(&features?)?;
        if features & (wire::PROTOCOL_FEATURES | (1 << 32)) != wire::PROTOCOL_FEATURES | (1 << 32) {
            return Err(io::Error::other(
                "backend lacks modern virtio/protocol negotiation",
            ));
        }
        let offered = wire::scalar(&session.get(GET_PROTOCOL_FEATURES, Vec::new())?)?;
        if offered & PROTOCOL != PROTOCOL {
            return Err(io::Error::other(
                "backend lacks required vhost-user features",
            ));
        }
        session.exchange(
            SET_PROTOCOL_FEATURES,
            PROTOCOL.to_ne_bytes().to_vec(),
            Vec::new(),
            Reply::None,
        )?;
        session.set(SET_OWNER, Vec::new(), Vec::new())?;
        if wire::scalar(&session.get(GET_QUEUE_NUM, Vec::new())?)? != self.info.queues.len() as u64
        {
            return Err(io::Error::other("unexpected backend queue count"));
        }
        let slots = wire::scalar(&session.get(GET_MAX_MEM_SLOTS, Vec::new())?)?;
        if memory.views.is_empty() || memory.views.len() as u64 > slots {
            return Err(io::Error::other("backend cannot map this RAM layout"));
        }
        session.set(SET_MEM_TABLE, wire::state(0, 0), Vec::new())?;
        for view in memory.views {
            let resource = memory
                .resources
                .get(view.resource as usize)
                .ok_or(io::ErrorKind::InvalidInput)?
                .try_clone()?;
            let payload = [0, view.gpa, view.len, view.gpa, view.offset]
                .into_iter()
                .flat_map(u64::to_ne_bytes)
                .collect();
            session.set(ADD_MEM_REG, payload, vec![resource])?;
        }
        let mut config_request = wire::state(0, self.info.config_len as u32);
        config_request.extend(0u32.to_ne_bytes());
        config_request.resize(12 + self.info.config_len, 0);
        let config = session.get(GET_CONFIG, config_request.clone())?;
        if config.len() != config_request.len() || config[..12] != config_request[..12] {
            return Err(io::Error::other("invalid backend configuration reply"));
        }
        let config = Arc::new(Mutex::new(config[12..].to_vec()));
        if let Some(mut poll) = self.config_poll {
            let weak = Arc::downgrade(&session);
            let config = Arc::clone(&config);
            let thread = std::thread::Builder::new()
                .name("vhost-config".into())
                .spawn(move || {
                    while let Some(session) = weak.upgrade() {
                        if session.shared.retiring.load(Ordering::Acquire) {
                            break;
                        }
                        let result = poll().and_then(|()| {
                            let reply = session.get(GET_CONFIG, config_request.clone())?;
                            if reply.len() != config_request.len()
                                || reply[..12] != config_request[..12]
                            {
                                return Err(io::Error::other(
                                    "invalid backend configuration reply",
                                ));
                            }
                            config.lock().unwrap().copy_from_slice(&reply[12..]);
                            Ok(())
                        });
                        if let Err(error) = result {
                            session.shared.fail(error.to_string());
                            break;
                        }
                        drop(session);
                        std::thread::sleep(Duration::from_millis(5));
                    }
                })?;
            session.threads.lock().unwrap().push(thread);
        }
        Ok((
            Proxy {
                session: Arc::clone(&session),
                info: self.info,
                features: features & !wire::PROTOCOL_FEATURES,
                config,
                next_epoch: 1,
            },
            Control(session),
        ))
    }
}

pub(crate) fn borrow_resources(resources: &[Resource]) -> Vec<BorrowedResource<'_>> {
    resources
        .iter()
        .map(|resource| {
            #[cfg(unix)]
            {
                resource.as_fd()
            }
            #[cfg(windows)]
            {
                resource.as_handle()
            }
        })
        .collect()
}

struct Shared {
    failure: Mutex<Option<String>>,
    failed: Box<dyn Fn() + Send + Sync>,
    retiring: AtomicBool,
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

fn receive(mut channel: Box<dyn Channel>, shared: &Shared, replies: &mpsc::SyncSender<Frame>) {
    let result = (|| -> io::Result<()> {
        loop {
            let message = channel
                .receive()
                .map_err(|e| io::Error::new(e.kind(), format!("vhost reply receive: {e}")))?;
            if !message.resources.is_empty() {
                return Err(io::Error::other("unexpected backend reply resources"));
            }
            let frame = Frame::decode(&message.bytes)?;
            if frame.flags != wire::VERSION | wire::REPLY {
                return Err(io::Error::other("invalid backend reply flags"));
            }
            replies.try_send(frame).map_err(io::Error::other)?;
        }
    })();
    if let Err(error) = result {
        shared.fail(error.to_string());
    }
}

#[derive(Clone, Copy)]
enum Reply {
    None,
    Ack,
    Data,
}

type NotificationPair = fn() -> io::Result<(Resource, Resource)>;
type NotificationEndpoint =
    fn(Resource, NotificationRole) -> io::Result<Arc<dyn WriteNotification>>;

struct Session {
    _files: Arc<Vec<Resource>>,
    retained: Mutex<Vec<Box<dyn Send>>>,
    shared: Arc<Shared>,
    process: Mutex<Box<dyn Process>>,
    commands: Mutex<Option<mpsc::SyncSender<Outgoing>>>,
    replies: Mutex<mpsc::Receiver<Frame>>,
    serial: Mutex<()>,
    lifecycle: Mutex<()>,
    retired: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
    kicks: Mutex<Vec<Resource>>,
    pair: NotificationPair,
    endpoint: NotificationEndpoint,
}

impl Session {
    fn get(&self, request: u32, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        self.exchange(request, payload, Vec::new(), Reply::Data)
    }
    fn set(&self, request: u32, payload: Vec<u8>, resources: Vec<Resource>) -> io::Result<()> {
        self.exchange(request, payload, resources, Reply::Ack)
            .map(|_| ())
    }
    fn exchange(
        &self,
        request: u32,
        payload: Vec<u8>,
        resources: Vec<Resource>,
        reply: Reply,
    ) -> io::Result<Vec<u8>> {
        let _serial = self.serial.lock().unwrap();
        let result = (|| {
            if let Some(error) = &*self.shared.failure.lock().unwrap() {
                return Err(io::Error::other(error.clone()));
            }
            let mut frame = Frame::request(request, payload);
            if matches!(reply, Reply::Ack) {
                frame.flags |= wire::NEED_REPLY;
            }
            let completion = matches!(reply, Reply::None).then(|| mpsc::sync_channel(1));
            let (sent, completed) =
                completion.map_or((None, None), |(send, receive)| (Some(send), Some(receive)));
            self.commands
                .lock()
                .unwrap()
                .as_ref()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .try_send(Outgoing {
                    frame,
                    resources,
                    sent,
                })
                .map_err(io::Error::other)?;
            if let Some(completed) = completed {
                completed
                    .recv_timeout(CONTROL_TIMEOUT)
                    .map_err(io::Error::other)?;
                return Ok(Vec::new());
            }
            let deadline = Instant::now() + CONTROL_TIMEOUT;
            let replies = self.replies.lock().unwrap();
            let frame = loop {
                match replies.recv_timeout(Duration::from_millis(50)) {
                    Ok(frame) => break frame,
                    Err(error) => {
                        if let Some(failure) = &*self.shared.failure.lock().unwrap() {
                            return Err(io::Error::other(failure.clone()));
                        }
                        // During the initial socket handoff, the parent's
                        // retained descriptor deliberately prevents EOF.
                        if let Some(status) = self.process.lock().unwrap().try_wait()? {
                            return Err(io::Error::other(format!("worker exited: {status}")));
                        }
                        if Instant::now() >= deadline
                            || error == mpsc::RecvTimeoutError::Disconnected
                        {
                            return Err(io::Error::other(error));
                        }
                    }
                }
            };
            if frame.request != request {
                return Err(io::Error::other("unexpected vhost-user reply"));
            }
            if matches!(reply, Reply::Ack) && wire::scalar(&frame.payload)? != 0 {
                return Err(io::Error::other(format!(
                    "backend rejected vhost-user request {request}"
                )));
            }
            Ok(frame.payload)
        })();
        if let Err(error) = &result {
            self.shared
                .fail(format!("vhost-user request {request}: {error}"));
            let _ = self.process.lock().unwrap().terminate();
        }
        result
    }

    fn reset(&self, epoch: u64) -> io::Result<()> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        if self
            .shared
            .active
            .compare_exchange(epoch, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        let result = self.set(RESET_DEVICE, Vec::new(), Vec::new());
        self.kicks.lock().unwrap().clear();
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
        drop(process);
        self.retired.store(true, Ordering::Release);
        self.commands.lock().unwrap().take();
        for thread in self.threads.lock().unwrap().drain(..) {
            thread
                .join()
                .map_err(|_| io::Error::other("worker relay panicked"))?;
        }
        self.retained.lock().unwrap().clear();
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.reap() {
            log::error!("virtio worker retirement: {error}");
        }
    }
}

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
    pub fn quiesce(&self) -> io::Result<()> {
        let _lifecycle = self.0.lifecycle.lock().unwrap();
        if self.0.shared.active.load(Ordering::Acquire) != 0 {
            for index in 0..self.0.kicks.lock().unwrap().len() {
                let reply = self.0.get(GET_VRING_BASE, wire::state(index as u32, 0))?;
                let mut data = reply.as_slice();
                if wire::take_u32(&mut data)? != index as u32
                    || wire::take_u32(&mut data)? > u32::from(u16::MAX)
                    || !data.is_empty()
                {
                    return Err(io::Error::other("invalid stopped queue index"));
                }
            }
        }
        Ok(())
    }
    pub fn resume(&self) -> io::Result<()> {
        let _lifecycle = self.0.lifecycle.lock().unwrap();
        if self.0.shared.active.load(Ordering::Acquire) != 0 {
            for (index, kick) in self.0.kicks.lock().unwrap().iter().enumerate() {
                self.0.set(
                    SET_VRING_KICK,
                    (index as u64).to_ne_bytes().to_vec(),
                    vec![kick.try_clone()?],
                )?;
            }
        }
        Ok(())
    }
    pub fn shutdown(&self) -> io::Result<()> {
        if self.0.retired.load(Ordering::Acquire) {
            return self.check();
        }
        self.0.shared.retiring.store(true, Ordering::Release);
        let stopped = self.reset();
        let reaped = self.0.reap();
        self.check().and(stopped).and(reaped)
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        if !self.0.retired.load(Ordering::Acquire)
            && let Err(error) = self.shutdown()
        {
            log::error!("virtio worker shutdown: {error}");
        }
    }
}

pub struct Proxy {
    session: Arc<Session>,
    info: DeviceInfo,
    features: u64,
    config: Arc<Mutex<Vec<u8>>>,
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
        self.info.kind
    }
    fn num_queues(&self) -> usize {
        self.info.queues.len()
    }
    fn queue_max_sizes(&self) -> &[u16] {
        &self.info.queues
    }
    fn features(&self) -> u64 {
        self.features
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = self.config.lock().unwrap();
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = usize::try_from(offset)
                .ok()
                .and_then(|offset| offset.checked_add(i))
                .and_then(|offset| config.get(offset))
                .copied()
                .unwrap_or(0);
        }
    }
    fn write_config(&mut self, _: u64, _: &[u8]) {}

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let session = Arc::clone(&self.session);
        let lifecycle = session.lifecycle.lock().unwrap();
        let host = activation.host()?;
        let queues = activation.take_queues();
        let kicks = activation.take_queue_evts();
        if queues.len() != self.num_queues()
            || kicks.len() != queues.len()
            || session.shared.active.load(Ordering::Acquire) != 0
        {
            return Err(ActivateError::InvalidConfig(
                "invalid backend activation".into(),
            ));
        }
        let epoch = self.next_epoch;
        self.next_epoch = epoch
            .checked_add(1)
            .ok_or_else(|| ActivateError::InvalidConfig("activation epoch exhausted".into()))?;
        session.shared.active.store(epoch, Ordering::Release);
        let mut relays = Vec::new();
        let mut retained_kicks = Vec::new();
        let result = (|| -> io::Result<()> {
            session.set(
                SET_FEATURES,
                (activation.negotiated_features() | wire::PROTOCOL_FEATURES)
                    .to_ne_bytes()
                    .to_vec(),
                Vec::new(),
            )?;
            for (index, (queue, kick)) in queues.into_iter().zip(kicks).enumerate() {
                let index = index as u32;
                let geometry = crate::queue::describe(&queue);
                session.set(
                    SET_VRING_NUM,
                    wire::state(index, u32::from(geometry.size)),
                    Vec::new(),
                )?;
                let mut address = wire::state(index, 0);
                address.extend(
                    [geometry.desc, geometry.used, geometry.avail, 0]
                        .into_iter()
                        .flat_map(u64::to_ne_bytes),
                );
                session.set(SET_VRING_ADDR, address, Vec::new())?;
                session.set(
                    SET_VRING_BASE,
                    wire::state(index, u32::from(queue.next_avail.0)),
                    Vec::new(),
                )?;
                let (read, write) = (session.pair)()?;
                let call = (session.endpoint)(read, NotificationRole::Wait)?;
                let wake = Kick::from_notification(Arc::clone(&call));
                let shared = Arc::clone(&session.shared);
                let interrupt = activation.queue_interrupt(index as usize);
                let relay = host
                    .spawn(Box::new(move |token| {
                        loop {
                            let result = call.read();
                            if token.is_shutdown_requested()
                                || shared.active.load(Ordering::Acquire) != epoch
                            {
                                return Ok(());
                            }
                            result.map_err(|error| DeviceJoinError::Worker(error.to_string()))?;
                            if shared.active.load(Ordering::Acquire) == epoch
                                && let Some(interrupt) = &interrupt
                            {
                                interrupt.signal();
                            }
                        }
                    }))
                    .map_err(io::Error::other)?
                    .with_shutdown_wake(wake);
                relays.push(relay);
                session.set(
                    SET_VRING_CALL,
                    u64::from(index).to_ne_bytes().to_vec(),
                    vec![write],
                )?;
                let resource = if let Some(resource) = kick.export()? {
                    retained_kicks.push(kick);
                    resource
                } else {
                    let (read, write) = (session.pair)()?;
                    let signal = (session.endpoint)(write, NotificationRole::Signal)?;
                    let wake = kick.clone();
                    let shared = Arc::clone(&session.shared);
                    let relay = host
                        .spawn(Box::new(move |token| {
                            loop {
                                let result = kick.read();
                                if token.is_shutdown_requested()
                                    || shared.active.load(Ordering::Acquire) != epoch
                                {
                                    return Ok(());
                                }
                                result
                                    .map_err(|error| DeviceJoinError::Worker(error.to_string()))?;
                                if let Err(error) = signal.write(1) {
                                    // Reset may close the receiving pipe after
                                    // the epoch check above.
                                    if shared.active.load(Ordering::Acquire) != epoch {
                                        return Ok(());
                                    }
                                    return Err(DeviceJoinError::Worker(error.to_string()));
                                }
                            }
                        }))
                        .map_err(io::Error::other)?
                        .with_shutdown_wake(wake);
                    relays.push(relay);
                    read
                };
                session.kicks.lock().unwrap().push(resource);
                session.set(SET_VRING_ENABLE, wire::state(index, 1), Vec::new())?;
            }
            for (index, kick) in session.kicks.lock().unwrap().iter().enumerate() {
                session.set(
                    SET_VRING_KICK,
                    (index as u64).to_ne_bytes().to_vec(),
                    vec![kick.try_clone()?],
                )?;
            }
            Ok(())
        })();
        drop(lifecycle);
        if let Err(error) = result {
            let _ = session.reset(epoch);
            for relay in &mut relays {
                relay.shutdown();
            }
            for relay in relays {
                let _ = relay.join();
            }
            return Err(error.into());
        }
        let relays = Arc::new(Mutex::new(Some(relays)));
        let stop_relays = Arc::clone(&relays);
        Ok(VirtioDeviceHandle::new(
            move || {
                if let Err(error) = session.reset(epoch) {
                    session.shared.fail(error.to_string());
                }
                if let Some(relays) = stop_relays.lock().unwrap().as_mut() {
                    for relay in relays {
                        relay.shutdown();
                    }
                }
            },
            move || {
                let mut result = Ok(());
                for relay in relays.lock().unwrap().take().unwrap_or_default() {
                    let joined = relay.join();
                    if result.is_ok() {
                        result = joined;
                    }
                }
                drop(retained_kicks);
                result
            },
        ))
    }
}
