// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Local messages and owned Windows resources, independent of device protocols.
//!
//! A listener authorizes one Windows user or AppContainer identity. A pipe owns
//! each connection's lifetime; closing one never requires terminating the server. The
//! process shares one local RPC endpoint, while listeners and connections have
//! independent lifetimes. The payload remains opaque to this crate.

#![cfg(windows)]

mod native;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::windows::io::{BorrowedHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

use native::{Event, Handle, Remote};

pub const MAX_MESSAGE: usize = 65536;
pub const MAX_RESOURCES: usize = 240;

/// Out-of-band rendezvous information. Neither field grants authority: the
/// server still checks the connecting process's Windows identity.
#[derive(Clone, Debug)]
pub struct Address {
    pub endpoint: String,
    pub listener: uuid::Uuid,
}

#[derive(Debug)]
pub struct Message {
    pub bytes: Vec<u8>,
    pub resources: Vec<OwnedHandle>,
}

#[derive(Debug)]
struct Envelope {
    bytes: Vec<u8>,
    resources: Vec<Handle>,
}

impl From<Envelope> for Message {
    fn from(value: Envelope) -> Self {
        Self {
            bytes: value.bytes,
            resources: value.resources.into_iter().map(|h| h.handle).collect(),
        }
    }
}

/// The kernel identity of a process, using its AppContainer SID when confined.
/// No duplication or execution authority over the process is required.
pub fn identity(process: BorrowedHandle<'_>) -> io::Result<Vec<u8>> {
    native::identity(process)
}

type Id = [u8; 16];
type Listeners = Mutex<HashMap<Id, Weak<Endpoint>>>;
static LISTENERS: OnceLock<Listeners> = OnceLock::new();
static CONTEXTS: OnceLock<Mutex<HashMap<Id, Context>>> = OnceLock::new();

fn listeners() -> &'static Listeners {
    LISTENERS.get_or_init(Mutex::default)
}

#[derive(Debug)]
struct Endpoint {
    id: Id,
    identity: Vec<u8>,
    incoming: Mutex<Option<VecDeque<Arc<State>>>>,
    arrived: Condvar,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        listeners().lock().unwrap().remove(&self.id);
    }
}

#[derive(Debug)]
struct Context {
    endpoint: Arc<Endpoint>,
    state: Arc<State>,
}

#[derive(Debug)]
pub struct Listener(Arc<Endpoint>);

impl Listener {
    pub fn bind(identity: Vec<u8>) -> io::Result<Self> {
        native::server_endpoint()?;
        if identity.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let endpoint = Arc::new(Endpoint {
            id: uuid::Uuid::new_v4().to_bytes_le(),
            identity,
            incoming: Mutex::new(Some(VecDeque::new())),
            arrived: Condvar::new(),
        });
        listeners()
            .lock()
            .unwrap()
            .insert(endpoint.id, Arc::downgrade(&endpoint));
        Ok(Self(endpoint))
    }

    pub fn descriptor(&self) -> io::Result<OwnedHandle> {
        native::descriptor(native::server_endpoint()?, self.0.id)
    }

    pub fn address(&self) -> Address {
        let endpoint = native::server_endpoint().expect("listener registered its endpoint");
        Address {
            endpoint: String::from_utf16(&endpoint[..endpoint.len() - 1]).unwrap(),
            listener: uuid::Uuid::from_bytes_le(self.0.id),
        }
    }

    pub fn accept(&self) -> io::Result<Connection> {
        self.accept_until(None)
    }

    pub fn accept_timeout(&self, timeout: std::time::Duration) -> io::Result<Connection> {
        self.accept_until(Some(std::time::Instant::now() + timeout))
    }

    fn accept_until(&self, deadline: Option<std::time::Instant>) -> io::Result<Connection> {
        let mut incoming = self.0.incoming.lock().unwrap();
        loop {
            let queue = incoming.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
            if let Some(state) = queue.pop_front() {
                return Ok(Connection(Arc::new(Side::Local(state))));
            }
            incoming = if let Some(deadline) = deadline {
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or(io::ErrorKind::TimedOut)?;
                self.0.arrived.wait_timeout(incoming, remaining).unwrap().0
            } else {
                self.0.arrived.wait(incoming).unwrap()
            };
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(queue) = self.0.incoming.lock().unwrap().take() {
            for state in queue {
                state.close();
            }
        }
        self.0.arrived.notify_all();
    }
}

#[derive(Debug)]
enum Side {
    Local(Arc<State>),
    Remote(Remote),
}

impl Drop for Side {
    fn drop(&mut self) {
        if let Self::Local(state) = self {
            state.close();
        }
    }
}

/// A duplex connection. Each direction is ordered by its caller. Clones share
/// connection ownership; shutdown wakes all operations without killing a peer.
#[derive(Clone, Debug)]
pub struct Connection(Arc<Side>);

impl Connection {
    pub fn connect_at(address: &Address) -> io::Result<Self> {
        Remote::connect_at(address).map(|remote| Self(Arc::new(Side::Remote(remote))))
    }

    pub fn connect(descriptor: BorrowedHandle<'_>) -> io::Result<Self> {
        Remote::connect(descriptor).map(|remote| Self(Arc::new(Side::Remote(remote))))
    }

    pub fn shutdown(&self) {
        match self.0.as_ref() {
            Side::Local(state) => state.close(),
            Side::Remote(remote) => remote.shutdown(),
        }
    }

    pub fn send(&self, bytes: &[u8], handles: &[BorrowedHandle<'_>]) -> io::Result<()> {
        if bytes.len() > MAX_MESSAGE || handles.len() > MAX_RESOURCES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let result = match self.0.as_ref() {
            Side::Remote(remote) => remote.send(bytes, handles),
            Side::Local(state) => {
                let resources = handles
                    .iter()
                    .map(|handle| Handle::copy(*handle))
                    .collect::<io::Result<_>>()?;
                state.outbound.push(
                    Envelope {
                        bytes: bytes.to_vec(),
                        resources,
                    },
                    state,
                    &[],
                )
            }
        };
        if result.is_err() {
            self.shutdown();
        }
        result
    }

    pub fn receive(&self) -> io::Result<Message> {
        let result = match self.0.as_ref() {
            Side::Remote(remote) => remote.receive(),
            Side::Local(state) => state.inbound.pop(state, &[]),
        };
        if result.is_err() {
            self.shutdown();
        }
        result.map(Into::into)
    }
}

#[derive(Debug)]
struct Queue {
    packet: Mutex<Option<Envelope>>,
    ready: Event,
    space: Event,
}

impl Queue {
    fn new() -> io::Result<Self> {
        Ok(Self {
            packet: Mutex::new(None),
            ready: Event::new(false)?,
            space: Event::new(true)?,
        })
    }

    fn push(
        &self,
        value: Envelope,
        state: &State,
        cancelled: &[BorrowedHandle<'_>],
    ) -> io::Result<()> {
        loop {
            let mut packet = self.packet.lock().unwrap();
            if state.stopped.load(Ordering::Acquire) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if packet.is_none() {
                *packet = Some(value);
                self.space.reset()?;
                self.ready.set()?;
                return Ok(());
            }
            drop(packet);
            self.space.wait(&state.closed, cancelled)?;
        }
    }

    fn pop(&self, state: &State, cancelled: &[BorrowedHandle<'_>]) -> io::Result<Envelope> {
        loop {
            let mut packet = self.packet.lock().unwrap();
            if state.stopped.load(Ordering::Acquire) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if let Some(value) = packet.take() {
                self.ready.reset()?;
                self.space.set()?;
                return Ok(value);
            }
            drop(packet);
            self.ready.wait(&state.closed, cancelled)?;
        }
    }
}

#[derive(Debug)]
struct State {
    inbound: Queue,
    outbound: Queue,
    closed: Event,
    stopped: AtomicBool,
}

impl State {
    fn new() -> io::Result<Self> {
        Ok(Self {
            inbound: Queue::new()?,
            outbound: Queue::new()?,
            closed: Event::new(false)?,
            stopped: AtomicBool::new(false),
        })
    }
    fn close(&self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.closed.set();
        self.inbound.packet.lock().unwrap().take();
        self.outbound.packet.lock().unwrap().take();
    }
}

fn endpoint(id: Id) -> Option<Arc<Endpoint>> {
    listeners().lock().unwrap().get(&id).and_then(Weak::upgrade)
}

fn open(id: Id) -> io::Result<(Id, OwnedHandle)> {
    let endpoint = endpoint(id).ok_or(io::ErrorKind::PermissionDenied)?;
    let mut incoming = endpoint.incoming.lock().unwrap();
    let queue = incoming.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
    if queue.len() >= 16 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let state = Arc::new(State::new()?);
    let (reader, writer) = native::lifetime_pipe()?;
    let id = uuid::Uuid::new_v4().to_bytes_le();
    CONTEXTS.get_or_init(Mutex::default).lock().unwrap().insert(
        id,
        Context {
            endpoint: Arc::clone(&endpoint),
            state: Arc::clone(&state),
        },
    );
    queue.push_back(Arc::clone(&state));
    drop(incoming);
    if let Err(error) = std::thread::Builder::new()
        .name("channel-lifetime".into())
        .spawn(move || {
            native::watch_lifetime(reader, &state.closed);
            close(id);
        })
    {
        close(id);
        return Err(error);
    }
    endpoint.arrived.notify_one();
    Ok((id, writer))
}

fn state(id: Id) -> io::Result<Arc<State>> {
    CONTEXTS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap()
        .get(&id)
        .map(|context| Arc::clone(&context.state))
        .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
}

fn close(id: Id) {
    let context = CONTEXTS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap()
        .remove(&id);
    if let Some(context) = context {
        context.state.close();
        if let Some(queue) = context.endpoint.incoming.lock().unwrap().as_mut() {
            queue.retain(|state| !Arc::ptr_eq(state, &context.state));
        }
    }
}
