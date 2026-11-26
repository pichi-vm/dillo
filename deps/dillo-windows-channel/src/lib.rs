// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Local ALPC messages with kernel-mediated Windows resources.
//!
//! A listener authorizes one Windows user or AppContainer identity. Each native
//! connection owns its lifetime independently of other connections and peers.
//! A listener dispatcher routes native messages; payloads remain opaque here.

#![cfg(windows)]

mod native;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::windows::io::{BorrowedHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use native::{Port, Received};

// The complete native message, including PORT_MESSAGE, must fit in u16.
pub const MAX_MESSAGE: usize = 60 * 1024;
pub const MAX_RESOURCES: usize = 240;

/// An endpoint address. The listener checks the kernel-supplied peer identity.
#[derive(Clone, Debug)]
pub struct Address {
    pub endpoint: String,
}

#[derive(Debug)]
pub struct Message {
    pub bytes: Vec<u8>,
    pub resources: Vec<OwnedHandle>,
}

/// Query a process's AppContainer SID, or its user SID when unconfined.
/// No handle-table duplication or execution authority is required.
pub fn identity(process: BorrowedHandle<'_>) -> io::Result<Vec<u8>> {
    native::identity(process)
}

#[derive(Debug)]
struct Incoming {
    accepting: bool,
    next: usize,
    pending: VecDeque<Connection>,
    connections: HashMap<usize, Weak<Session>>,
}

#[derive(Debug)]
struct Server {
    port: Arc<Port>,
    identity: Vec<u8>,
    incoming: Mutex<Incoming>,
    arrived: Condvar,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.port.disconnect();
    }
}

impl Server {
    fn dispatch(self: &Arc<Self>, message: Received) {
        match message {
            Received::Connect(mut header, valid) => {
                let identity = self.port.peer_identity(&mut header);
                let mut incoming = self.incoming.lock().unwrap();
                incoming
                    .pending
                    .retain(|connection| !connection.0.closed.load(Ordering::Acquire));
                incoming
                    .connections
                    .retain(|_, connection| connection.strong_count() != 0);
                let context = incoming.next;
                let allow = valid
                    && incoming.accepting
                    && incoming.pending.len() < 16
                    && context != usize::MAX
                    && identity.is_ok_and(|sid| sid == self.identity);
                if let Ok(Some(port)) = self.port.accept(&mut header, context, allow) {
                    incoming.next += 1;
                    let session = Arc::new(Session::new(port, Some(Arc::clone(self))));
                    incoming
                        .connections
                        .insert(context, Arc::downgrade(&session));
                    incoming.pending.push_back(Connection(session));
                    self.arrived.notify_one();
                }
            }
            Received::Data(context, message) => {
                let session = self
                    .incoming
                    .lock()
                    .unwrap()
                    .connections
                    .get(&context)
                    .and_then(Weak::upgrade);
                if let Some(session) = session
                    && !session.enqueue(message)
                {
                    session.shutdown();
                }
            }
            Received::Closed(context) => {
                let session = self
                    .incoming
                    .lock()
                    .unwrap()
                    .connections
                    .remove(&context)
                    .and_then(|w| w.upgrade());
                if let Some(session) = session {
                    session.shutdown();
                }
            }
            Received::Cancelled => {}
        }
    }

    fn fail(&self) {
        let sessions = {
            let mut incoming = self.incoming.lock().unwrap();
            incoming.accepting = false;
            incoming
                .connections
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        for session in sessions {
            session.shutdown();
        }
        self.arrived.notify_all();
    }
}

#[derive(Debug)]
pub struct Listener {
    address: Address,
    server: Arc<Server>,
}

impl Listener {
    pub fn bind(identity: Vec<u8>) -> io::Result<Self> {
        let address = Address {
            endpoint: format!("vhost-alpc-{}", uuid::Uuid::new_v4().simple()),
        };
        let port = Arc::new(Port::listen(&address, &identity)?);
        let server = Arc::new(Server {
            port: Arc::clone(&port),
            identity,
            incoming: Mutex::new(Incoming {
                accepting: true,
                next: 1,
                pending: VecDeque::new(),
                connections: HashMap::new(),
            }),
            arrived: Condvar::new(),
        });
        let weak = Arc::downgrade(&server);
        std::thread::Builder::new()
            .name("alpc-listener".into())
            .spawn(move || {
                // Do not retain Server across the wait: its final owner signals the
                // event, waking this dispatcher and releasing the native listener.
                loop {
                    let message = port.receive();
                    let Some(server) = weak.upgrade() else {
                        break;
                    };
                    if let Ok(message) = message {
                        server.dispatch(message);
                    } else {
                        server.fail();
                        break;
                    }
                }
            })?;
        Ok(Self { address, server })
    }
    pub fn descriptor(&self) -> io::Result<OwnedHandle> {
        native::descriptor(&self.address)
    }
    pub fn address(&self) -> Address {
        self.address.clone()
    }
    pub fn accept(&self) -> io::Result<Connection> {
        self.accept_until(None)
    }
    pub fn accept_timeout(&self, timeout: Duration) -> io::Result<Connection> {
        self.accept_until(Some(Instant::now() + timeout))
    }
    fn accept_until(&self, deadline: Option<Instant>) -> io::Result<Connection> {
        let mut incoming = self.server.incoming.lock().unwrap();
        loop {
            if !incoming.accepting {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            while let Some(connection) = incoming.pending.pop_front() {
                if !connection.0.closed.load(Ordering::Acquire) {
                    return Ok(connection);
                }
            }
            incoming = if let Some(deadline) = deadline {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(io::ErrorKind::TimedOut)?;
                self.server
                    .arrived
                    .wait_timeout(incoming, remaining)
                    .unwrap()
                    .0
            } else {
                self.server.arrived.wait(incoming).unwrap()
            };
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let pending = {
            let mut incoming = self.server.incoming.lock().unwrap();
            incoming.accepting = false;
            std::mem::take(&mut incoming.pending)
        };
        for connection in pending {
            connection.shutdown();
        }
        self.server.arrived.notify_all();
    }
}

#[derive(Debug, Default)]
struct Queue {
    messages: VecDeque<Message>,
    bytes: usize,
    handles: usize,
}

#[derive(Debug)]
struct Session {
    port: Port,
    // Accepted connections keep their shared listener/dispatcher alive.
    server: Option<Arc<Server>>,
    closed: AtomicBool,
    sending: Mutex<()>,
    receiving: Mutex<()>,
    queue: Mutex<Queue>,
    arrived: Condvar,
}

impl Session {
    fn new(port: Port, server: Option<Arc<Server>>) -> Self {
        Self {
            port,
            server,
            closed: AtomicBool::new(false),
            sending: Mutex::new(()),
            receiving: Mutex::new(()),
            queue: Mutex::new(Queue::default()),
            arrived: Condvar::new(),
        }
    }
    fn shutdown(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.port.disconnect();
            *self.queue.lock().unwrap() = Queue::default();
            self.arrived.notify_all();
        }
    }
    fn enqueue(&self, message: Message) -> bool {
        let mut queue = self.queue.lock().unwrap();
        // Bound receiver-owned storage independently per connection. A peer
        // exhausting its allowance is disconnected rather than blocking other
        // clients of the same listener. These are implementation resource limits.
        if self.closed.load(Ordering::Acquire)
            || queue.messages.len() == 1024
            || queue.bytes + message.bytes.len() > 32 * 1024 * 1024
            || queue.handles + message.resources.len() > 16 * MAX_RESOURCES
        {
            return false;
        }
        queue.bytes += message.bytes.len();
        queue.handles += message.resources.len();
        queue.messages.push_back(message);
        self.arrived.notify_one();
        true
    }
    fn receive(&self) -> io::Result<Message> {
        if self.server.is_some() {
            let mut queue = self.queue.lock().unwrap();
            loop {
                if self.closed.load(Ordering::Acquire) {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                if let Some(message) = queue.messages.pop_front() {
                    queue.bytes -= message.bytes.len();
                    queue.handles -= message.resources.len();
                    return Ok(message);
                }
                queue = self.arrived.wait(queue).unwrap();
            }
        } else {
            loop {
                match self.port.receive()? {
                    Received::Data(_, message) => return Ok(message),
                    Received::Cancelled => continue,
                    _ => return Err(io::ErrorKind::BrokenPipe.into()),
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Ordered duplex messages. Clones share connection ownership; shutdown
/// interrupts operations without terminating either peer process.
#[derive(Clone, Debug)]
pub struct Connection(Arc<Session>);

impl Connection {
    pub fn connect_at(address: &Address) -> io::Result<Self> {
        Ok(Self(Arc::new(Session::new(Port::connect(address)?, None))))
    }
    pub fn connect(descriptor: BorrowedHandle<'_>) -> io::Result<Self> {
        Self::connect_at(&native::read_descriptor(descriptor)?)
    }
    pub fn shutdown(&self) {
        self.0.shutdown();
    }
    pub fn send(&self, bytes: &[u8], handles: &[BorrowedHandle<'_>]) -> io::Result<()> {
        let _sending = self.0.sending.lock().unwrap();
        if self.0.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = self.0.port.send(bytes, handles);
        if result.is_err() {
            self.shutdown();
        }
        result
    }
    pub fn receive(&self) -> io::Result<Message> {
        let _receiving = self.0.receiving.lock().unwrap();
        if self.0.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = self.0.receive();
        if result.is_err() {
            self.shutdown();
        }
        result
    }
}
