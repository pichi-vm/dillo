// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::num::Wrapping;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU16, Ordering},
};

use dillo_ipc::block::{Geometry, Init};
use dillo_ipc::vhost_user::{self as wire, Frame, request::*};
use dillo_machine::worker::{
    MAX_RESOURCES, MemoryExport, NotificationRole, RamView, Resource, WorkerHost, WriteNotification,
};
use dillo_mmio::{Interrupt, MappedSharedMemory, SharedAccess, SharedMemory};
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
    | wire::GPA_ADDRESSES;

struct Host(Arc<dyn SharedMemory>);

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

impl VirtioDeviceHost for Host {
    fn shared_memory(&self) -> Vec<Arc<dyn SharedMemory>> {
        vec![Arc::clone(&self.0)]
    }

    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let stopping = Arc::new(AtomicBool::new(false));
        let token = Arc::clone(&stopping);
        let thread = std::thread::Builder::new()
            .name("virtio-queue".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(VirtioRunToken::from_fn(move || {
                        token.load(Ordering::Acquire)
                    }))
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
            move || stopping.store(true, Ordering::Release),
            move || thread.join().unwrap_or(Err(DeviceJoinError::Panicked)),
        ))
    }
}

#[derive(Debug, Default)]
struct Endpoint(Mutex<Option<Arc<dyn WriteNotification>>>);

impl WriteNotification for Endpoint {
    fn read(&self) -> io::Result<u64> {
        let endpoint = self
            .0
            .lock()
            .unwrap()
            .clone()
            .ok_or(io::ErrorKind::NotConnected)?;
        endpoint.read()
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
    progress: Option<Arc<AtomicU16>>,
    enabled: bool,
    started: bool,
    kick: Arc<Endpoint>,
    call: Arc<Endpoint>,
}

impl Ring {
    fn new(max: u16) -> Self {
        Self {
            max,
            geometry: Geometry::default(),
            base: 0,
            progress: None,
            enabled: false,
            started: false,
            kick: Arc::default(),
            call: Arc::default(),
        }
    }
    fn base(&self) -> u16 {
        self.progress
            .as_ref()
            .map_or(self.base, |progress| progress.load(Ordering::Acquire))
    }
}

struct Backend {
    active: Option<VirtioDeviceHandle>,
    device: Box<dyn VirtioDevice>,
    rings: Vec<Ring>,
    memory: GuestMemoryMmap,
    regions: Vec<(RamView, u64)>,
    owner: bool,
    protocol: u64,
    features: u64,
    paused: bool,
}

impl Backend {
    fn pause(&mut self) -> io::Result<()> {
        if self.active.is_some() && !self.paused {
            self.device.quiesce().map_err(io::Error::other)?;
            self.paused = true;
        }
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        if let Some(active) = self.active.take() {
            active.join().map_err(io::Error::other)?;
        }
        self.device.reset().map_err(io::Error::other)?;
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
        if !self.rings.iter().all(|ring| ring.started && ring.enabled) {
            return Ok(());
        }
        if self.active.is_some() {
            if self.paused {
                self.device.resume().map_err(io::Error::other)?;
                self.paused = false;
            }
            return Ok(());
        }
        require(self.owner && self.features & (1 << 32) != 0)?;
        let mut queues = Vec::new();
        let mut kicks = Vec::new();
        let mut interrupts = Vec::new();
        for ring in &mut self.rings {
            let mut queue = crate::queue::admit(ring.geometry.clone(), ring.max, &self.memory)?;
            queue.next_avail = Wrapping(ring.base);
            queue.next_used = Wrapping(u16::from_le(
                self.memory
                    .read_obj::<u16>(GuestAddress(ring.geometry.used + 2))
                    .map_err(io::Error::other)?,
            ));
            ring.progress = Some(queue.track_progress());
            queues.push(queue);
            kicks.push(Kick::from_notification(ring.kick.clone()));
            let call = Arc::clone(&ring.call);
            interrupts.push(Some(Interrupt::from_fn(move || {
                if let Err(error) = call.write(1) {
                    log::error!("virtio call notification: {error}");
                    std::process::exit(1);
                }
            })));
        }
        let host: Arc<dyn VirtioDeviceHost> = Arc::new(Host(Arc::new(
            MappedSharedMemory::for_guest_memory(self.memory.clone(), SharedAccess::ReadWrite),
        )));
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
            SET_MEM_TABLE | ADD_MEM_REG | SET_VRING_KICK | SET_VRING_CALL | SET_VRING_ERR
        );
        require(resource_request || resources.is_empty())?;
        match frame.request {
            GET_FEATURES => {
                reply = Some(
                    (self.device.features() | wire::PROTOCOL_FEATURES)
                        .to_ne_bytes()
                        .to_vec(),
                )
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
            RESET_OWNER => {
                self.reset()?;
                self.owner = false;
            }
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
                        ring.enabled = true;
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
                require(self.owner && self.active.is_none())?;
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
            }
            REM_MEM_REG => {
                require(
                    self.protocol & wire::CONFIGURE_MEM_SLOTS != 0
                        && self.active.is_none()
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
                self.memory = self
                    .memory
                    .remove_region(GuestAddress(gpa), len)
                    .map_err(io::Error::other)?
                    .0;
                self.regions.remove(index);
            }
            GET_CONFIG | SET_CONFIG => {
                require(self.protocol & wire::CONFIG != 0)?;
                let offset = wire::take_u32(&mut data)?;
                let size = wire::take_u32(&mut data)? as usize;
                let flags = wire::take_u32(&mut data)?;
                require(size == data.len() && size <= 256 && flags <= 1)?;
                if frame.request == GET_CONFIG {
                    let mut config = frame.payload.clone();
                    self.device
                        .read_config(u64::from(offset), &mut config[12..]);
                    reply = Some(config);
                } else {
                    self.device.write_config(u64::from(offset), data);
                }
                data = &[];
            }
            SET_VRING_NUM | SET_VRING_BASE | GET_VRING_BASE | SET_VRING_ENABLE => {
                let index = wire::take_u32(&mut data)? as usize;
                let value = wire::take_u32(&mut data)?;
                require(index < self.rings.len())?;
                if frame.request == GET_VRING_BASE {
                    require(value == 0)?;
                    self.pause()?;
                }
                let ring = &mut self.rings[index];
                match frame.request {
                    SET_VRING_NUM => {
                        require(
                            self.active.is_none()
                                && value != 0
                                && value.is_power_of_two()
                                && value <= u32::from(ring.max),
                        )?;
                        ring.geometry.size = value as u16;
                    }
                    SET_VRING_BASE => {
                        require(self.active.is_none() && value <= u32::from(u16::MAX))?;
                        ring.base = value as u16;
                    }
                    GET_VRING_BASE => {
                        ring.started = false;
                        reply = Some(wire::state(index as u32, u32::from(ring.base())));
                    }
                    SET_VRING_ENABLE => {
                        require(value <= 1 && self.active.is_none())?;
                        ring.enabled = value != 0;
                    }
                    _ => unreachable!(),
                }
            }
            SET_VRING_ADDR => {
                require(self.active.is_none())?;
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
                    require(present)?;
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
                    ring.started = true;
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
    factory: impl FnOnce(serde_json::Value, Vec<File>) -> io::Result<Box<dyn VirtioDevice>>,
) -> io::Result<()> {
    let mut bootstrap = unsafe { H::bootstrap() }?;
    let mut message = bootstrap.receive()?;
    let init: Init = dillo_ipc::decode(&message)?;
    require(init.version == 2 && message.resources.len() == init.files + 1)?;
    let mut channel = H::channel(message.resources.pop().unwrap())?;
    let files = message
        .resources
        .into_iter()
        .map(File::from)
        .collect::<Vec<_>>();
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
    H::confine(&borrowed)?;
    let device = factory(init.backend, files)?;
    drop(bootstrap);
    let rings = device
        .queue_max_sizes()
        .iter()
        .copied()
        .map(Ring::new)
        .collect();
    let mut backend = Backend {
        active: None,
        device,
        rings,
        memory: GuestMemoryMmap::new(),
        regions: Vec::new(),
        owner: false,
        protocol: 0,
        features: 0,
        paused: false,
    };
    loop {
        let message = channel.receive()?;
        let frame = Frame::decode(&message.bytes)?;
        require(
            frame.flags & wire::REPLY == 0
                && (frame.flags & wire::NEED_REPLY == 0 || backend.protocol & wire::REPLY_ACK != 0),
        )?;
        let result = backend.dispatch::<H>(&frame, message.resources);
        match result {
            Ok(Some(payload)) => channel.send(&frame.reply(payload).encode()?, &[])?,
            Ok(None) if frame.flags & wire::NEED_REPLY != 0 => {
                channel.send(&frame.reply(0u64.to_ne_bytes().to_vec()).encode()?, &[])?
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
