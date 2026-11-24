// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native process facilities selected with the Machine family.

use std::io;
use std::path::Path;

use dillo_ipc::{Channel, MemoryExport, Process};
use vm_memory::GuestMemoryMmap;

/// Facilities available to a device worker. This interface deliberately has no
/// native VM, vCPU, debugger, or arbitrary process-handle operation.
pub trait WorkerHost {
    /// Start the same executable at its private worker entry point, returning a
    /// channel whose peer is that child. Startup is not a readiness report.
    fn spawn(executable: &Path) -> io::Result<(Box<dyn Process>, Box<dyn Channel>)>;

    /// Adopt the private bootstrap connection in the child, once.
    fn bootstrap() -> io::Result<Box<dyn Channel>>;

    /// Map only RAM exported by the parent. The export retains its backing for
    /// at least as long as the returned owning views.
    fn map_memory(memory: MemoryExport) -> io::Result<GuestMemoryMmap>;

    /// Permanently remove ambient filesystem, network and process authority.
    /// Must succeed before any worker reports readiness or reads a guest queue.
    fn confine(files: &[dillo_ipc::BorrowedResource<'_>]) -> io::Result<()>;
}

/// Machines without process services refuse worker startup.
impl WorkerHost for () {
    fn spawn(_: &Path) -> io::Result<(Box<dyn Process>, Box<dyn Channel>)> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn bootstrap() -> io::Result<Box<dyn Channel>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn map_memory(_: MemoryExport) -> io::Result<GuestMemoryMmap> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn confine(_: &[dillo_ipc::BorrowedResource<'_>]) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
