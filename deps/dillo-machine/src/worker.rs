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

/// Bound allocations before decoding a control message. Guest buffers never
/// travel in these messages.
pub const MAX_MESSAGE: usize = 64 * 1024;
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

#[derive(Clone, Copy, Debug)]
pub enum NotificationRole {
    Wait,
    Signal,
}

/// Facilities available to a device worker. This interface deliberately has no
/// native VM, vCPU, debugger, or arbitrary process-handle operation.
pub trait WorkerHost {
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
