// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Private native endpoint, polled by the existing virtio control worker.

#![forbid(unsafe_code)]

use dillo_config::ConsoleSize;
use interprocess::local_socket::{
    GenericFilePath, Listener, ListenerNonblockingMode, ListenerOptions, Stream, prelude::*,
};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use crate::pipe::{Direction, PipeEnd, Transfer};

/// A granted pipe carries the same four-byte sizes as the public endpoint.
#[derive(Debug)]
pub(crate) enum Input {
    Local(Receiver),
    Pipe {
        pipe: PipeEnd,
        bytes: [u8; 4],
        read: usize,
        current: Arc<AtomicU32>,
    },
}

impl Input {
    pub(crate) fn pipe(file: File, current: Arc<AtomicU32>) -> Self {
        Self::Pipe {
            pipe: PipeEnd::from_file("resize", Direction::Rx, file),
            bytes: [0; 4],
            read: 0,
            current,
        }
    }

    pub(crate) fn poll(&mut self) -> io::Result<Option<ConsoleSize>> {
        let (pipe, bytes, read, current) = match self {
            Self::Local(receiver) => return receiver.poll(),
            Self::Pipe {
                pipe,
                bytes,
                read,
                current,
            } => (pipe, bytes, read, current),
        };
        match pipe.read(&mut bytes[*read..])? {
            Transfer::Moved(count) => *read += count,
            Transfer::WouldBlock => return Ok(None),
            Transfer::Closed => return Err(io::ErrorKind::BrokenPipe.into()),
        }
        if *read != bytes.len() {
            return Ok(None);
        }
        *read = 0;
        let Ok(size) = ConsoleSize::try_from(*bytes) else {
            return Ok(None);
        };
        let packed = u32::from_le_bytes(*bytes);
        Ok((current.swap(packed, Ordering::AcqRel) != packed).then_some(size))
    }
}

/// Forward the caller's local endpoint into an explicitly granted worker pipe.
/// Both sides are nonblocking; backpressure retains at most one complete size.
#[derive(Debug)]
pub struct Forwarder {
    receiver: Receiver,
    pipe: PipeEnd,
    bytes: [u8; 4],
    written: usize,
}

impl Forwarder {
    pub fn bind(path: &Path) -> io::Result<(Self, File)> {
        #[cfg(unix)]
        use std::os::fd::OwnedFd as Resource;
        #[cfg(windows)]
        use std::os::windows::io::OwnedHandle as Resource;
        let (rx, tx) = io::pipe()?;
        let rx = PipeEnd::nonblocking("resize", Direction::Rx, Resource::from(rx).into())?;
        let pipe = PipeEnd::nonblocking("resize", Direction::Tx, Resource::from(tx).into())?;
        Ok((
            Self {
                receiver: Receiver::bind(path, Arc::new(AtomicU32::new(0)))?,
                pipe,
                bytes: [0; 4],
                written: 4,
            },
            rx.into_file(),
        ))
    }

    pub fn poll(&mut self) -> io::Result<()> {
        if self.written == self.bytes.len() {
            let Some(size) = self.receiver.poll()? else {
                return Ok(());
            };
            self.bytes[..2].copy_from_slice(&size.cols.get().to_le_bytes());
            self.bytes[2..].copy_from_slice(&size.rows.get().to_le_bytes());
            self.written = 0;
        }
        match self.pipe.write(&self.bytes[self.written..])? {
            Transfer::Moved(count) => self.written += count,
            Transfer::WouldBlock => {}
            Transfer::Closed => return Err(io::ErrorKind::BrokenPipe.into()),
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Receiver {
    listener: Listener,
    pending: Option<Pending>,
    current: Arc<AtomicU32>,
}

#[derive(Debug)]
struct Pending {
    stream: Stream,
    bytes: [u8; 4],
    read: usize,
    deadline: Instant,
}

impl Receiver {
    pub fn bind(path: &Path, current: Arc<AtomicU32>) -> io::Result<Self> {
        let options = ListenerOptions::new()
            .name(path.to_fs_name::<GenericFilePath>()?)
            .nonblocking(ListenerNonblockingMode::Both);
        // Unix authorization uses kernel peer credentials below. Socket-file
        // permissions are not a portable authentication mechanism on macOS.
        #[cfg(windows)]
        let options = {
            use interprocess::os::windows::{
                local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
            };
            let sid = win_custody::current_user_sid_string()?;
            let sddl = widestring::U16CString::from_str(format!("D:P(A;;GA;;;{sid})"))
                .map_err(io::Error::other)?;
            options.security_descriptor(SecurityDescriptor::deserialize(&sddl)?)
        };
        Ok(Self {
            listener: options.create_sync()?,
            pending: None,
            current,
        })
    }

    /// At most one accept and one nonblocking read per control-worker turn.
    /// A partial or idle client owns four bytes and one connection for ≤1 s.
    pub fn poll(&mut self) -> io::Result<Option<ConsoleSize>> {
        if self.pending.is_none() {
            match self.listener.accept() {
                Ok(stream) => {
                    #[cfg(unix)]
                    if stream.peer_creds().ok().and_then(|peer| peer.euid())
                        != Some(nix::unistd::geteuid().as_raw())
                    {
                        return Ok(None);
                    }
                    self.pending = Some(Pending {
                        stream,
                        bytes: [0; 4],
                        read: 0,
                        deadline: Instant::now() + Duration::from_secs(1),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        match pending.stream.read(&mut pending.bytes[pending.read..]) {
            // Windows PIPE_NOWAIT can return zero for a live empty pipe.
            // Only a complete update counts; the deadline bounds either case.
            Ok(count) => pending.read += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => {
                self.pending = None;
                return Ok(None);
            }
        }
        if pending.read == 4 {
            let bytes = pending.bytes;
            self.pending = None;
            if let Ok(size) = ConsoleSize::try_from(bytes) {
                let packed = u32::from_le_bytes(bytes);
                if self.current.swap(packed, Ordering::AcqRel) != packed {
                    return Ok(Some(size));
                }
            }
        } else if Instant::now() >= pending.deadline {
            self.pending = None;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn forwarded_updates_and_stalled_clients_remain_bounded() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        let endpoint = root.path().join("resize.sock");
        #[cfg(windows)]
        let endpoint = std::path::PathBuf::from(format!(
            r"\\.\pipe\dillo-resize-{}-{}",
            std::process::id(),
            root.path()
                .file_name()
                .ok_or_else(|| io::Error::other("temporary name"))?
                .to_string_lossy()
        ));
        let current = Arc::new(AtomicU32::new(0));
        let (mut forwarder, pipe) = Forwarder::bind(&endpoint)?;
        let mut input = Input::pipe(pipe, Arc::clone(&current));
        let mut receive = move || {
            forwarder.poll()?;
            input.poll()
        };
        let mut first = Stream::connect(endpoint.as_path().to_fs_name::<GenericFilePath>()?)?;
        first.write_all(&[44, 1])?; // 300 columns; rows have not arrived yet.
        assert_eq!(receive()?, None);
        first.write_all(&[77, 0])?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let size = loop {
            if let Some(size) = receive()? {
                break size;
            }
            assert!(Instant::now() < deadline, "fragmented resize deadline");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!((size.cols.get(), size.rows.get()), (300, 77));
        drop(first);

        // An abandoned partial message cannot hold the next caller forever.
        let mut stalled = Stream::connect(endpoint.as_path().to_fs_name::<GenericFilePath>()?)?;
        stalled.write_all(&[1])?;
        assert_eq!(receive()?, None);
        let mut next = Stream::connect(endpoint.as_path().to_fs_name::<GenericFilePath>()?)?;
        next.write_all(&[120, 0, 41, 0])?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let size = loop {
            if let Some(size) = receive()? {
                break size;
            }
            assert!(
                Instant::now() < deadline,
                "stalled resize client blocked reconnect"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!((size.cols.get(), size.rows.get()), (120, 41));
        assert_eq!(
            current.load(Ordering::Acquire).to_le_bytes(),
            [120, 0, 41, 0]
        );
        drop((stalled, next, receive));
        #[cfg(unix)]
        assert!(!endpoint.exists(), "resize endpoint survived teardown");
        Ok(())
    }
}
