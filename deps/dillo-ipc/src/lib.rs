// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Worker controls carry descriptions; OS-transferred resources carry authority.

use std::io;

#[cfg(unix)]
pub use std::os::fd::{BorrowedFd as BorrowedResource, OwnedFd as Resource};
#[cfg(windows)]
pub use std::os::windows::io::{BorrowedHandle as BorrowedResource, OwnedHandle as Resource};

/// Bound allocations before decoding a control message. Guest buffers never
/// travel in these messages.
pub const MAX_MESSAGE: usize = 64 * 1024;
// Stay below Linux's SCM_MAX_FD (253) for one startup message.
pub const MAX_RESOURCES: usize = 240;

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

/// Owned native resources and the regions they back. Native Machine code alone
/// constructs these exports; the child receives independent owning handles.
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

impl Message {
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> io::Result<T> {
        serde_json::from_slice(&self.bytes).map_err(io::Error::other)
    }
}

/// A private parent/child connection. Implementations enforce message/resource
/// bounds before allocation and close received objects on every error path.
pub trait Channel: Send + std::fmt::Debug {
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()>;
    fn receive(&mut self) -> io::Result<Message>;
    fn try_clone(&self) -> io::Result<Box<dyn Channel>>;
}

pub fn encode(value: &impl serde::Serialize) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker message too large",
        ));
    }
    Ok(bytes)
}

/// The parent retains process termination and reaping authority. None of these
/// operations grants a child authority over the parent or a sibling.
pub trait Process: Send + std::fmt::Debug {
    fn terminate(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<std::process::ExitStatus>;
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>>;
}
