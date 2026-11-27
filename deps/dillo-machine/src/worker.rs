// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native process facilities selected with the Machine family.

use std::io;
use std::path::Path;
use vm_memory::GuestMemoryMmap;

#[cfg(unix)]
pub use std::os::fd::{BorrowedFd as BorrowedResource, OwnedFd as Resource};
#[cfg(windows)]
pub use std::os::windows::io::{BorrowedHandle as BorrowedResource, OwnedHandle as Resource};

#[cfg(unix)]
pub use std::os::fd::{BorrowedFd as BorrowedSocket, OwnedFd as Socket};
#[cfg(windows)]
pub use std::os::windows::io::{BorrowedSocket, OwnedSocket as Socket};

/// Bound allocations before decoding a control message. Guest buffers never
/// travel in these messages.
// Leaves space for the native ALPC header within its 16-bit message length.
pub const MAX_MESSAGE: usize = 60 * 1024;
// Stay below Linux's SCM_MAX_FD (253) for one startup message.
pub const MAX_RESOURCES: usize = 240;

/// Native authority selected by the launcher, outside vhost-user negotiation.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Permit host IP networking for the network backend, including forwards.
    /// This does not grant access to additional host files or processes.
    pub network: bool,
}

/// One region in an exported RAM allocation. `resource` indexes the resources
/// accompanying this description, never the receiver's native handle table.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RamView {
    pub gpa: u64,
    pub len: u64,
    pub offset: u64,
    pub resource: u32,
}

/// Raw RAM descriptions and owning native resources. This bundle does not
/// establish the backing or aliasing guarantees required by `map_memory`.
#[derive(Debug)]
pub struct MemoryExport {
    pub views: Vec<RamView>,
    pub resources: Vec<Resource>,
}

/// One framed message plus the native objects received with that frame.
#[derive(Debug)]
pub struct Message {
    pub bytes: Vec<u8>,
    pub resources: Vec<Resource>,
}

/// A private parent/child connection. Implementations enforce message/resource
/// bounds before allocation and close received objects on every error path.
pub trait Channel: Send + std::fmt::Debug {
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()>;
    fn receive(&mut self) -> io::Result<Message>;
    fn try_clone(&self) -> io::Result<Box<dyn Channel>>;

    /// Export a socket to this channel's pinned peer. Keep the source alive
    /// until the receiver has imported it; Windows uses Winsock protocol data,
    /// not DuplicateHandle. This native grant is not a vhost-user message.
    fn share_socket(&self, socket: BorrowedSocket<'_>) -> io::Result<Message> {
        #[cfg(unix)]
        {
            Ok(Message {
                bytes: Vec::new(),
                resources: vec![socket.try_clone_to_owned()?],
            })
        }
        #[cfg(windows)]
        {
            let _ = socket;
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// Create a vhost-user connection for this same peer. The returned resource
    /// is transferred through bootstrap (or SET_BACKEND_REQ_FD), never opened
    /// by name by the worker. Windows retains this connection's pinned peer.
    fn pair(&self) -> io::Result<(Box<dyn Channel>, Resource)> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The parent retains process termination and reaping authority. None of these
/// operations grants a child authority over the parent or a sibling.
pub trait Process: Send + std::fmt::Debug {
    fn terminate(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<std::process::ExitStatus>;
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>>;
}

/// A bound notification counter, without native registration authority.
pub trait WriteNotification: Send + Sync + std::fmt::Debug {
    fn read(&self) -> io::Result<u64>;
    fn write(&self, count: u64) -> io::Result<()>;

    /// Duplicate the endpoint for a worker in this same native family.
    /// The caller must retain the registration owner until that worker stops.
    fn export(&self) -> io::Result<Option<Resource>> {
        Ok(None)
    }
}

/// Experimental host-only notification latch. Never mapped into the guest.
/// This is a measurement aid, not an assigned vhost-user interface.
#[derive(Debug)]
pub struct NotificationState {
    mapping: vm_memory::MmapRegion<()>,
    #[cfg(windows)]
    section: Option<Resource>,
}

impl NotificationState {
    /// # Safety
    /// The file must retain at least 4096 committed writable bytes while mapped.
    /// Every alias of its first word must use aligned AtomicU32 accesses only.
    #[allow(unsafe_code)]
    pub unsafe fn from_file(file: std::fs::File) -> io::Result<Self> {
        let mapping = vm_memory::MmapRegion::from_file(vm_memory::FileOffset::new(file, 0), 4096)
            .map_err(io::Error::other)?;
        Ok(Self {
            mapping,
            #[cfg(windows)]
            section: None,
        })
    }

    /// # Safety
    /// The handle must name a committed, cacheable, writable pagefile section
    /// of at least 4096 bytes. Every alias of its first word must use aligned
    /// AtomicU32 accesses only. The returned view retains the backing.
    #[cfg(windows)]
    #[allow(unsafe_code)]
    pub unsafe fn from_section(section: Resource) -> io::Result<Self> {
        use std::os::windows::io::AsHandle;
        // SAFETY: the caller supplies the section's backing/aliasing contract.
        let mapping =
            unsafe { vm_memory::MmapRegion::from_mapping_handle(section.as_handle(), 0, 4096) }
                .map_err(io::Error::other)?;
        Ok(Self {
            mapping,
            section: Some(section),
        })
    }

    fn word(&self) -> &std::sync::atomic::AtomicU32 {
        use vm_memory::VolatileMemory;
        self.mapping
            .get_atomic_ref(0)
            .expect("aligned mapped status word")
    }

    pub fn load(&self) -> u32 {
        self.word().load(std::sync::atomic::Ordering::SeqCst) & 3
    }

    pub fn used(&self) -> bool {
        self.word().fetch_or(1, std::sync::atomic::Ordering::SeqCst) & 1 == 0
    }

    pub fn acknowledge(&self, bits: u32) {
        self.word()
            .fetch_and(!(bits & 3), std::sync::atomic::Ordering::SeqCst);
    }

    pub fn export(&self) -> io::Result<Resource> {
        #[cfg(windows)]
        if let Some(section) = &self.section {
            return section.try_clone();
        }
        Ok(self
            .mapping
            .file_offset()
            .expect("file-backed status")
            .file()
            .try_clone()?
            .into())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NotificationRole {
    Wait,
    Signal,
}

#[derive(Debug)]
struct QueueNotification {
    wait: std::sync::Arc<dyn WriteNotification>,
    signal: std::sync::Arc<dyn WriteNotification>,
    receiver: Resource,
}

impl WriteNotification for QueueNotification {
    fn read(&self) -> io::Result<u64> {
        self.wait.read()
    }

    fn write(&self, count: u64) -> io::Result<()> {
        self.signal.write(count)
    }

    fn export(&self) -> io::Result<Option<Resource>> {
        self.receiver.try_clone().map(Some)
    }
}

/// Facilities available to a device worker. This interface deliberately has no
/// native VM, vCPU, debugger, or arbitrary process-handle operation.
pub trait WorkerHost {
    fn create_notification_state() -> io::Result<std::sync::Arc<NotificationState>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// # Safety
    /// The resource must be created by this family's `create_notification_state`
    /// or exported from that state. Retained aliases must follow the
    /// NotificationState atomic-access contract; the resource is not guest RAM.
    #[allow(unsafe_code)]
    unsafe fn adopt_notification_state(
        _resource: Resource,
    ) -> io::Result<std::sync::Arc<NotificationState>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Import a socket granted by the parent, without creating a connection or
    /// selecting a native process. The returned object owns its local socket.
    fn import_socket(mut message: Message) -> io::Result<Socket> {
        #[cfg(unix)]
        {
            if !message.bytes.is_empty() || message.resources.len() != 1 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(message.resources.pop().unwrap())
        }
        #[cfg(windows)]
        {
            let _ = &mut message;
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    /// Start the same executable at its private worker entry point, returning a
    /// channel whose peer is that child. Startup is not a readiness report.
    fn spawn(executable: &Path, policy: Policy)
    -> io::Result<(Box<dyn Process>, Box<dyn Channel>)>;

    /// Adopt the private bootstrap connection in the child, once.
    ///
    /// # Safety
    /// Call only at the entry of a dedicated worker process, before creating
    /// threads or owning other resources. Bootstrap may close inherited handles
    /// and takes exclusive ownership of its standard input/output handles.
    #[allow(unsafe_code)]
    unsafe fn bootstrap() -> io::Result<Box<dyn Channel>>;

    /// Adopt a vhost-user endpoint explicitly granted by the parent.
    fn channel(_resource: Resource) -> io::Result<Box<dyn Channel>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Map only RAM exported by the parent. The export retains its backing for
    /// at least as long as the returned owning views.
    ///
    /// # Safety
    /// Resources must back committed, cacheable, readable/writable RAM that
    /// cannot be truncated, decommitted or otherwise invalidated while mapped.
    /// Conflicting accesses through other aliases in this process must be
    /// synchronized, unless both are atomic over exactly the same bytes.
    /// External guest/process mutation follows vm-memory's access discipline.
    #[allow(unsafe_code)]
    unsafe fn map_memory(memory: MemoryExport) -> io::Result<GuestMemoryMmap>;

    /// Adopt a counter endpoint granted by the parent from this native family.
    fn notification(_resource: Resource) -> io::Result<std::sync::Arc<dyn WriteNotification>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Create native notification endpoints in wait/signal order. Both refer
    /// to the same event; its count is a wake hint, not a request count.
    fn notification_pair() -> io::Result<(Resource, Resource)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// One queue wake usable locally or by an exported worker receiver.
    /// Software notify dispatch signals the same object in either case.
    fn queue_notification() -> io::Result<std::sync::Arc<dyn WriteNotification>> {
        let (receiver, signal) = Self::notification_pair()?;
        Ok(std::sync::Arc::new(QueueNotification {
            wait: Self::notification_endpoint(receiver.try_clone()?, NotificationRole::Wait)?,
            signal: Self::notification_endpoint(signal, NotificationRole::Signal)?,
            receiver,
        }))
    }

    fn notification_endpoint(
        resource: Resource,
        _role: NotificationRole,
    ) -> io::Result<std::sync::Arc<dyn WriteNotification>> {
        Self::notification(resource)
    }

    /// Remove ambient authority except the launcher's explicit resource policy.
    /// Must succeed before any worker reports readiness or reads a guest queue.
    fn confine(files: &[BorrowedResource<'_>], policy: Policy) -> io::Result<()>;
}

/// Machines without process services refuse worker startup.
impl WorkerHost for () {
    fn spawn(_: &Path, _: Policy) -> io::Result<(Box<dyn Process>, Box<dyn Channel>)> {
        Err(io::ErrorKind::Unsupported.into())
    }
    #[allow(unsafe_code)]
    unsafe fn bootstrap() -> io::Result<Box<dyn Channel>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    #[allow(unsafe_code)]
    unsafe fn map_memory(_: MemoryExport) -> io::Result<GuestMemoryMmap> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn confine(_: &[BorrowedResource<'_>], _: Policy) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
