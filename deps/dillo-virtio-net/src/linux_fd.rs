// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Shared frame I/O over a Linux character-device fd (the TAP `/dev/net/tun`
//! handle and a macvtap `/dev/tapN` handle behave identically: raw Ethernet
//! frames, one per `read`/`write`). Both [`TapBackend`](crate::TapBackend) and
//! [`MacvtapBackend`](crate::MacvtapBackend) wrap a [`FrameFd`].

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

use crate::backend::RECV_POLL;

/// A non-blocking fd carrying one raw Ethernet frame per read/write.
#[derive(Debug)]
pub(crate) struct FrameFd {
    file: File,
}

impl FrameFd {
    pub(crate) fn new(file: File) -> Self {
        Self { file }
    }

    /// Write one Ethernet frame to the device.
    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        // `&File` implements `Write`, so no `&mut self` is needed (the backend
        // is shared across worker threads behind an `Arc`).
        match (&self.file).write(frame) {
            Ok(_) => Ok(()),
            // A momentarily full device queue is not fatal; drop like a NIC.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Block up to [`RECV_POLL`] for one inbound frame.
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        if !self.poll_readable()? {
            return Ok(None);
        }
        match (&self.file).read(buf) {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `poll(2)` the fd for readability with a bounded timeout. Returns `true`
    /// when a frame is waiting.
    fn poll_readable(&self) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = RECV_POLL.as_millis() as libc::c_int;
        // SAFETY: `pfd` is a single valid, initialized `pollfd`; `poll` only
        // reads `nfds` entries (1) and writes `revents`.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(rc > 0 && (pfd.revents & libc::POLLIN) != 0)
    }
}
