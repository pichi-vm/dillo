// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Private native endpoint, polled by the existing virtio control worker.

#![forbid(unsafe_code)]

use dillo_config::ConsoleSize;
use interprocess::local_socket::{
    GenericFilePath, Listener, ListenerNonblockingMode, ListenerOptions, Stream, prelude::*,
};
use std::{
    io::{self, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(super) struct Receiver {
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
    pub(super) fn bind(path: &Path, current: Arc<AtomicU32>) -> io::Result<Self> {
        let options = ListenerOptions::new()
            .name(path.to_fs_name::<GenericFilePath>()?)
            .nonblocking(ListenerNonblockingMode::Both);
        // Interprocess's atomic pre-bind mode is Linux-only. Every Unix
        // connection is authenticated by kernel peer UID below, including macOS.
        #[cfg(target_os = "linux")]
        let options = {
            use interprocess::os::unix::local_socket::ListenerOptionsExt;
            options.mode(0o600)
        };
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
    pub(super) fn poll(&mut self) -> io::Result<Option<ConsoleSize>> {
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
    fn fragmented_updates_and_stalled_clients_remain_bounded() -> io::Result<()> {
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
        let mut receiver = Receiver::bind(&endpoint, Arc::clone(&current))?;
        let mut first = Stream::connect(endpoint.as_path().to_fs_name::<GenericFilePath>()?)?;
        first.write_all(&[44, 1])?; // 300 columns; rows have not arrived yet.
        assert_eq!(receiver.poll()?, None);
        first.write_all(&[77, 0])?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let size = loop {
            if let Some(size) = receiver.poll()? {
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
        assert_eq!(receiver.poll()?, None);
        let mut next = Stream::connect(endpoint.as_path().to_fs_name::<GenericFilePath>()?)?;
        next.write_all(&[120, 0, 41, 0])?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let size = loop {
            if let Some(size) = receiver.poll()? {
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
        drop((stalled, next, receiver));
        #[cfg(unix)]
        assert!(!endpoint.exists(), "resize endpoint survived teardown");
        Ok(())
    }
}
