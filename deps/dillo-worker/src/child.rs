// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::num::Wrapping;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::queue::Geometry;
use dillo_ipc::bootstrap::Init;
use dillo_ipc::vhost_user::{
    self as wire, Frame,
    request::{
        ADD_MEM_REG, GET_CONFIG, GET_FEATURES, GET_MAX_MEM_SLOTS, GET_PROTOCOL_FEATURES,
        GET_QUEUE_NUM, GET_VRING_BASE, REM_MEM_REG, RESET_DEVICE, RESET_OWNER, SET_FEATURES,
        SET_MEM_TABLE, SET_OWNER, SET_PROTOCOL_FEATURES, SET_VRING_ADDR, SET_VRING_BASE,
        SET_VRING_CALL, SET_VRING_ENABLE, SET_VRING_ERR, SET_VRING_KICK, SET_VRING_NUM,
    },
};
use dillo_machine::worker::{
    MAX_RESOURCES, MemoryExport, NotificationRole, RamView, Resource, WorkerHost, WriteNotification,
};
use dillo_mmio::{
    Interrupt, MappedSharedMemory, SharedAccess, SharedMemory, SharedMemoryError, SharedRange,
    SharedRegion,
};
use dillo_virtio::queue::{Queue, QueueControl};
use dillo_virtio::{
    ActivateError, DeviceJoinError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
    VirtioDeviceHost, VirtioRunToken,
};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const PROTOCOL: u64 = wire::MQ
    | wire::REPLY_ACK
    | wire::CONFIG
    | wire::RESET_DEVICE
    | wire::CONFIGURE_MEM_SLOTS
    | wire::GPA_ADDRESSES
    | wire::EXPERIMENT_SHARED_ISR;

/// Publish a new map after draining in-flight requests. Region capabilities
/// retain their old view until released; ordinary accesses take no update lock.
struct Memory(arc_swap::ArcSwap<MappedSharedMemory>);

impl Memory {
    fn publish(&self, memory: GuestMemoryMmap) {
        self.0.store(Arc::new(MappedSharedMemory::for_guest_memory(
            memory,
            SharedAccess::ReadWrite,
        )));
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self(arc_swap::ArcSwap::from_pointee(
            MappedSharedMemory::for_guest_memory(GuestMemoryMmap::new(), SharedAccess::ReadWrite),
        ))
    }
}

impl SharedMemory for Memory {
    fn region(&self, range: SharedRange) -> Result<SharedRegion, SharedMemoryError> {
        self.0.load().region(range)
    }
}

struct Host {
    memory: Arc<dyn SharedMemory>,
    pause: Arc<crate::pause::Barrier>,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

impl VirtioDeviceHost for Host {
    fn shared_memory(&self) -> Vec<Arc<dyn SharedMemory>> {
        vec![Arc::clone(&self.memory)]
    }

    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let stopping = Arc::new(AtomicBool::new(false));
        let token = Arc::clone(&stopping);
        let paused_token = Arc::clone(&stopping);
        let barrier = Arc::clone(&self.pause);
        let participant = barrier.register();
        let thread = std::thread::Builder::new()
            .name("virtio-queue".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(
                        VirtioRunToken::from_fn(move || token.load(Ordering::Acquire))
                            .with_checkpoint(move || participant.checkpoint(&paused_token)),
                    )
                }))
                .unwrap_or(Err(DeviceJoinError::Panicked));
                if let Err(error) = &result {
                    // Closing the backend connection is the vhost-user failure
                    // signal. No private failure message enters that stream.
                    log::error!("virtio worker failed: {error}");
                    std::process::exit(1);
                }
                result
            })?;
        Ok(VirtioDeviceHandle::new(
            move || {
                stopping.store(true, Ordering::Release);
                barrier.wake();
            },
            move || thread.join().unwrap_or(Err(DeviceJoinError::Panicked)),
        ))
    }
}

#[derive(Debug, Default)]
struct Endpoint(Mutex<Option<Arc<dyn WriteNotification>>>);

impl WriteNotification for Endpoint {
    fn read(&self) -> io::Result<u64> {
        let endpoint = self.0.lock().unwrap().clone();
        if let Some(endpoint) = endpoint {
            endpoint.read()
        } else {
            // No kick descriptor requests polling. This also keeps not-yet
            // configured queues available for their first start.
            std::thread::sleep(std::time::Duration::from_millis(5));
            Ok(0)
        }
    }
    fn write(&self, count: u64) -> io::Result<()> {
        let endpoint = self.0.lock().unwrap().clone();
        endpoint.map_or(Ok(()), |endpoint| endpoint.write(count))
    }
}

struct Ring {
    max: u16,
    geometry: Geometry,
    base: u16,
    control: Arc<QueueControl>,
    dirty: bool,
    kick: Arc<Endpoint>,
    call: Arc<Endpoint>,
}

impl Ring {
    fn new(max: u16) -> Self {
        Self {
            max,
            geometry: Geometry::default(),
            base: 0,
            control: Arc::default(),
            dirty: true,
            kick: Arc::default(),
            call: Arc::default(),
        }
    }
}

struct Backend {
    active: Option<VirtioDeviceHandle>,
    notification_state: Option<Arc<dillo_machine::worker::NotificationState>>,
    device: Box<dyn VirtioDevice>,
    rings: Vec<Ring>,
    memory: GuestMemoryMmap,
    shared: Arc<Memory>,
    regions: Vec<(RamView, u64)>,
    owner: bool,
    protocol: u64,
    features: u64,
    paused: bool,
    barrier: Arc<crate::pause::Barrier>,
}

impl Backend {
    fn pause(&mut self) -> io::Result<()> {
        if self.active.is_some() && !self.paused {
            self.barrier.requested.store(true, Ordering::Release);
            for ring in &self.rings {
                ring.kick.write(1)?;
            }
            self.barrier.wait();
            self.paused = true;
        }
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        if let Some(active) = self.active.take() {
            active.join().map_err(io::Error::other)?;
        }
        self.device.reset().map_err(io::Error::other)?;
        self.notification_state = None;
        self.barrier.resume();
        self.rings = self
            .device
            .queue_max_sizes()
            .iter()
            .copied()
            .map(Ring::new)
            .collect();
        self.features = 0;
        self.paused = false;
        Ok(())
    }

    fn start(&mut self) -> io::Result<()> {
        if !self.rings.iter().any(|ring| ring.control.started()) {
            return Ok(());
        }
        if self.active.is_some() {
            if self.paused {
                self.barrier.resume();
                self.paused = false;
                for ring in &self.rings {
                    ring.kick.write(1)?;
                }
            }
            return Ok(());
        }
        require(self.owner && self.features & (1 << 32) != 0)?;
        let mut queues = Vec::new();
        let mut kicks = Vec::new();
        let mut interrupts = Vec::new();
        for ring in &mut self.rings {
            let mut queue = Queue::new(ring.max);
            queue.control_with(Arc::clone(&ring.control));
            queue.pause_with(Arc::clone(&self.barrier.requested));
            queues.push(queue);
            kicks.push(Kick::from_notification(ring.kick.clone()));
            let call = Arc::clone(&ring.call);
            let state = self.notification_state.clone();
            interrupts.push(Some(Interrupt::from_fn(move || {
                if let Some(state) = &state {
                    state.used();
                }
                if let Err(error) = call.write(1) {
                    log::error!("virtio call notification: {error}");
                    std::process::exit(1);
                }
            })));
        }
        let host: Arc<dyn VirtioDeviceHost> = Arc::new(Host {
            memory: self.shared.clone(),
            pause: Arc::clone(&self.barrier),
        });
        self.active = Some(
            self.device
                .activate(
                    VirtioActivate::with_host_and_queue_interrupts(queues, kicks, host, interrupts)
                        .with_negotiated_features(self.features & !wire::PROTOCOL_FEATURES),
                )
                .map_err(io::Error::other)?,
        );
        // Process descriptors already published before SET_VRING_KICK.
        for ring in &self.rings {
            ring.kick.write(1)?;
        }
        Ok(())
    }

    fn translate(&self, address: u64) -> io::Result<u64> {
        if self.protocol & wire::GPA_ADDRESSES != 0 {
            return Ok(address);
        }
        self.regions
            .iter()
            .find_map(|(region, user)| {
                address
                    .checked_sub(*user)
                    .filter(|offset| *offset < region.len)
                    .and_then(|offset| region.gpa.checked_add(offset))
            })
            .ok_or(io::ErrorKind::InvalidInput.into())
    }

    fn dispatch<H: WorkerHost>(
        &mut self,
        frame: &Frame,
        mut resources: Vec<Resource>,
    ) -> io::Result<Option<Vec<u8>>> {
        let mut data = frame.payload.as_slice();
        let mut reply = None;
        let resource_request = matches!(
            frame.request,
            SET_MEM_TABLE
                | ADD_MEM_REG
                | SET_VRING_KICK
                | SET_VRING_CALL
                | SET_VRING_ERR
                | wire::EXPERIMENT_SET_ISR
        );
        require(resource_request || resources.is_empty())?;
        match frame.request {
            wire::EXPERIMENT_SET_ISR => {
                require(
                    self.owner
                        && self.active.is_none()
                        && self.protocol & wire::EXPERIMENT_SHARED_ISR != 0
                        && resources.len() == 1,
                )?;
                self.notification_state = Some(H::adopt_notification_state(resources.remove(0))?);
            }
            GET_FEATURES => {
                reply = Some(
                    (self.device.features() | wire::PROTOCOL_FEATURES)
                        .to_ne_bytes()
                        .to_vec(),
                );
            }
            GET_PROTOCOL_FEATURES => reply = Some(PROTOCOL.to_ne_bytes().to_vec()),
            SET_PROTOCOL_FEATURES => {
                let features = wire::take_u64(&mut data)?;
                require(features & !PROTOCOL == 0 && self.active.is_none())?;
                self.protocol = features;
            }
            SET_OWNER => {
                require(!self.owner)?;
                self.owner = true;
            }
            // Deprecated; ignoring it preserves the connection state, as
            // recommended by vhost-user. RESET_DEVICE performs device reset.
            RESET_OWNER => {}
            SET_FEATURES => {
                let features = wire::take_u64(&mut data)?;
                require(
                    self.owner
                        && self.active.is_none()
                        && features & !(self.device.features() | wire::PROTOCOL_FEATURES) == 0,
                )?;
                self.features = features;
                if features & wire::PROTOCOL_FEATURES == 0 {
                    for ring in &mut self.rings {
                        ring.control.set_enabled(true);
                    }
                }
            }
            GET_QUEUE_NUM => {
                require(self.protocol & wire::MQ != 0)?;
                reply = Some((self.rings.len() as u64).to_ne_bytes().to_vec());
            }
            GET_MAX_MEM_SLOTS => {
                require(self.protocol & wire::CONFIGURE_MEM_SLOTS != 0)?;
                reply = Some((MAX_RESOURCES as u64).to_ne_bytes().to_vec());
            }
            SET_MEM_TABLE | ADD_MEM_REG => {
                require(self.owner)?;
                self.pause()?;
                let count = if frame.request == SET_MEM_TABLE {
                    let count = wire::take_u32(&mut data)? as usize;
                    require(wire::take_u32(&mut data)? == 0 && count <= 8)?;
                    count
                } else {
                    require(
                        self.protocol & wire::CONFIGURE_MEM_SLOTS != 0
                            && wire::take_u64(&mut data)? == 0,
                    )?;
                    1
                };
                require(
                    count == resources.len()
                        && (frame.request == SET_MEM_TABLE || self.regions.len() < MAX_RESOURCES),
                )?;
                let mut regions = Vec::with_capacity(count);
                for index in 0..count {
                    let gpa = wire::take_u64(&mut data)?;
                    let len = wire::take_u64(&mut data)?;
                    let user = wire::take_u64(&mut data)?;
                    let offset = wire::take_u64(&mut data)?;
                    require(
                        len != 0
                            && gpa.checked_add(len).is_some()
                            && user.checked_add(len).is_some()
                            && (self.protocol & wire::GPA_ADDRESSES == 0 || user == gpa),
                    )?;
                    require(regions.iter().all(|(other, other_user): &(RamView, u64)| {
                        user + len <= *other_user || other_user + other.len <= user
                    }))?;
                    regions.push((
                        RamView {
                            gpa,
                            len,
                            offset,
                            resource: index as u32,
                        },
                        user,
                    ));
                }
                require(data.is_empty())?;
                // SAFETY: bootstrap's trusted parent grants stable RAM; the
                // native mapper validates extents and retains owning views.
                #[allow(unsafe_code)]
                let mapped = if count == 0 {
                    GuestMemoryMmap::new()
                } else {
                    unsafe {
                        H::map_memory(MemoryExport {
                            views: regions.iter().map(|(view, _)| *view).collect(),
                            resources,
                        })
                    }?
                };
                if frame.request == SET_MEM_TABLE {
                    self.memory = mapped;
                    self.regions = regions;
                } else {
                    let (region, user) = regions[0];
                    require(self.regions.iter().all(|(other, other_user)| {
                        user + region.len <= *other_user || other_user + other.len <= user
                    }))?;
                    let (_, mapped) = mapped
                        .remove_region(GuestAddress(region.gpa), region.len)
                        .map_err(io::Error::other)?;
                    self.memory = self
                        .memory
                        .insert_region(mapped)
                        .map_err(io::Error::other)?;
                    self.regions.push((region, user));
                }
                self.publish_memory()?;
            }
            REM_MEM_REG => {
                require(
                    self.protocol & wire::CONFIGURE_MEM_SLOTS != 0
                        && self.owner
                        && wire::take_u64(&mut data)? == 0,
                )?;
                let gpa = wire::take_u64(&mut data)?;
                let len = wire::take_u64(&mut data)?;
                let user = wire::take_u64(&mut data)?;
                let _offset = wire::take_u64(&mut data)?;
                let index = self
                    .regions
                    .iter()
                    .position(|(region, base)| {
                        region.gpa == gpa && region.len == len && *base == user
                    })
                    .ok_or(io::ErrorKind::InvalidInput)?;
                self.pause()?;
                self.memory = self
                    .memory
                    .remove_region(GuestAddress(gpa), len)
                    .map_err(io::Error::other)?
                    .0;
                self.regions.remove(index);
                self.publish_memory()?;
            }
            GET_CONFIG => {
                require(self.protocol & wire::CONFIG != 0)?;
                let offset = wire::take_u32(&mut data)?;
                let size = wire::take_u32(&mut data)? as usize;
                let flags = wire::take_u32(&mut data)?;
                require(size == data.len() && size <= 256 && flags <= 1)?;
                let mut config = frame.payload.clone();
                self.device
                    .read_config(u64::from(offset), &mut config[12..]);
                reply = Some(config);
                data = &[];
            }
            SET_VRING_NUM | SET_VRING_BASE | GET_VRING_BASE | SET_VRING_ENABLE => {
                let index = wire::take_u32(&mut data)? as usize;
                let value = wire::take_u32(&mut data)?;
                require(index < self.rings.len())?;
                if frame.request == GET_VRING_BASE {
                    require(value == 0)?;
                }
                if matches!(frame.request, GET_VRING_BASE | SET_VRING_ENABLE) {
                    self.pause()?;
                }
                let ring = &mut self.rings[index];
                match frame.request {
                    SET_VRING_NUM => {
                        require(
                            !ring.control.started()
                                && value != 0
                                && value.is_power_of_two()
                                && value <= u32::from(ring.max),
                        )?;
                        ring.geometry.size = value as u16;
                        ring.dirty = true;
                    }
                    SET_VRING_BASE => {
                        require(!ring.control.started())?;
                        ring.base = u16::try_from(value).map_err(io::Error::other)?;
                        ring.dirty = true;
                    }
                    GET_VRING_BASE => {
                        ring.control.set_started(false);
                        if !ring.dirty {
                            ring.base = ring.control.base();
                        }
                        reply = Some(wire::state(index as u32, u32::from(ring.base)));
                    }
                    SET_VRING_ENABLE => {
                        require(value <= 1 && self.features & wire::PROTOCOL_FEATURES != 0)?;
                        ring.control.set_enabled(value != 0);
                    }
                    _ => unreachable!(),
                }
            }
            SET_VRING_ADDR => {
                let index = wire::take_u32(&mut data)? as usize;
                require(wire::take_u32(&mut data)? == 0)?;
                let desc = self.translate(wire::take_u64(&mut data)?)?;
                let used = self.translate(wire::take_u64(&mut data)?)?;
                let avail = self.translate(wire::take_u64(&mut data)?)?;
                require(wire::take_u64(&mut data)? == 0)?;
                let ring = self
                    .rings
                    .get_mut(index)
                    .ok_or(io::ErrorKind::InvalidInput)?;
                require(!ring.control.started())?;
                ring.dirty = true;
                ring.geometry.desc = desc;
                ring.geometry.used = used;
                ring.geometry.avail = avail;
            }
            SET_VRING_KICK | SET_VRING_CALL | SET_VRING_ERR => {
                let value = wire::take_u64(&mut data)?;
                require(value & !0x1ff == 0)?;
                let present = value & 0x100 == 0;
                let index = (value & 0xff) as usize;
                require(index < self.rings.len() && resources.len() == usize::from(present))?;
                if frame.request == SET_VRING_KICK {
                    self.pause()?;
                }
                let endpoint = if present {
                    Some(H::notification_endpoint(
                        resources.remove(0),
                        if frame.request == SET_VRING_KICK {
                            NotificationRole::Wait
                        } else {
                            NotificationRole::Signal
                        },
                    )?)
                } else {
                    None
                };
                let ring = &mut self.rings[index];
                if frame.request == SET_VRING_KICK {
                    *ring.kick.0.lock().unwrap() = endpoint;
                    if ring.dirty {
                        let mut queue =
                            crate::queue::admit(ring.geometry.clone(), ring.max, &self.memory)?;
                        queue.next_avail = Wrapping(ring.base);
                        queue.next_used = Wrapping(u16::from_le(
                            self.memory
                                .read_obj::<u16>(GuestAddress(ring.geometry.used + 2))
                                .map_err(io::Error::other)?,
                        ));
                        ring.control.configure(queue);
                        ring.dirty = false;
                    }
                    ring.control.set_started(true);
                } else if frame.request == SET_VRING_CALL {
                    *ring.call.0.lock().unwrap() = endpoint;
                }
                // This backend reports fatal queue errors by closing its
                // connection. An optional error endpoint is owned then closed.
            }
            RESET_DEVICE => {
                require(self.protocol & wire::RESET_DEVICE != 0)?;
                self.reset()?;
            }
            _ => return Err(io::ErrorKind::Unsupported.into()),
        }
        require(data.is_empty())?;
        self.start()?;
        Ok(reply)
    }

    fn publish_memory(&self) -> io::Result<()> {
        for ring in self.rings.iter().filter(|ring| ring.control.started()) {
            crate::queue::admit(ring.geometry.clone(), ring.max, &self.memory)?;
        }
        self.shared.publish(self.memory.clone());
        Ok(())
    }
}

fn require(valid: bool) -> io::Result<()> {
    if valid {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidInput.into())
    }
}

/// Run the vhost-user backend after the private process bootstrap.
///
/// # Safety
/// Requires `WorkerHost::bootstrap`'s entry contract and stable RAM grants
/// satisfying `WorkerHost::map_memory`. This fresh process has no other aliases.
#[allow(unsafe_code)]
pub unsafe fn run<H: WorkerHost>(
    factory: impl FnOnce(
        serde_json::Value,
        Vec<File>,
        Option<crate::grant::Client>,
    ) -> io::Result<Box<dyn VirtioDevice>>,
) -> io::Result<()> {
    // SAFETY: this entry preserves the caller's dedicated process contract.
    unsafe {
        run_prepared::<H, ()>(
            |_| Ok(()),
            |(), value, files, grants| factory(value, files, grants),
        )
    }
}

/// Acquire non-transferable native resources from trusted launch configuration,
/// then confine the process before constructing or running the guest device.
/// `prepare` must not parse backing files, guest data, or vhost-user messages.
///
/// # Safety
/// Requires [`run`]'s dedicated process contract. The preparation callback may
/// use ambient authority only for the resources the launcher explicitly names.
#[allow(unsafe_code)]
pub unsafe fn run_prepared<H: WorkerHost, T>(
    prepare: impl FnOnce(&serde_json::Value) -> io::Result<T>,
    factory: impl FnOnce(
        T,
        serde_json::Value,
        Vec<File>,
        Option<crate::grant::Client>,
    ) -> io::Result<Box<dyn VirtioDevice>>,
) -> io::Result<()> {
    let mut bootstrap = unsafe { H::bootstrap() }?;
    let mut message = bootstrap
        .receive()
        .map_err(|e| io::Error::new(e.kind(), format!("worker bootstrap receive: {e}")))?;
    let init: Init = dillo_ipc::decode(&message)?;
    require(
        init.version == 3 && message.resources.len() == init.files + 1 + usize::from(init.grants),
    )?;
    let mut channel = H::channel(message.resources.pop().unwrap())?;
    let grants = if init.grants {
        Some(crate::grant::Client::new(H::channel(
            message.resources.pop().unwrap(),
        )?))
    } else {
        None
    };
    let files = message
        .resources
        .into_iter()
        .map(File::from)
        .collect::<Vec<_>>();
    let prepared = prepare(&init.backend)?;
    #[cfg(unix)]
    let borrowed = {
        use std::os::fd::AsFd;
        files.iter().map(AsFd::as_fd).collect::<Vec<_>>()
    };
    #[cfg(windows)]
    let borrowed = {
        use std::os::windows::io::AsHandle;
        files.iter().map(AsHandle::as_handle).collect::<Vec<_>>()
    };
    H::confine(&borrowed, init.policy)?;
    let device = factory(prepared, init.backend, files, grants)?;
    drop(bootstrap);
    let rings = device
        .queue_max_sizes()
        .iter()
        .copied()
        .map(Ring::new)
        .collect();
    let mut backend = Backend {
        active: None,
        notification_state: None,
        device,
        rings,
        memory: GuestMemoryMmap::new(),
        shared: Arc::default(),
        regions: Vec::new(),
        owner: false,
        protocol: 0,
        features: 0,
        paused: false,
        barrier: Arc::default(),
    };
    loop {
        let message = channel
            .receive()
            .map_err(|e| io::Error::new(e.kind(), format!("vhost backend receive: {e}")))?;
        let frame = Frame::decode(&message.bytes)?;
        require(
            frame.flags & wire::REPLY == 0
                && (frame.flags & wire::NEED_REPLY == 0 || backend.protocol & wire::REPLY_ACK != 0),
        )?;
        let result = backend.dispatch::<H>(&frame, message.resources);
        match result {
            Ok(Some(payload)) => channel.send(&frame.reply(payload).encode()?, &[])?,
            Ok(None) if frame.flags & wire::NEED_REPLY != 0 => {
                channel.send(&frame.reply(0u64.to_ne_bytes().to_vec()).encode()?, &[])?;
            }
            Ok(None) => {}
            Err(error) => {
                if frame.flags & wire::NEED_REPLY != 0 {
                    channel.send(&frame.reply(1u64.to_ne_bytes().to_vec()).encode()?, &[])?;
                }
                return Err(io::Error::new(
                    error.kind(),
                    format!("vhost-user request {}: {error}", frame.request),
                ));
            }
        }
    }
}
