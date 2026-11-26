// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket backend for virtio-vsock.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Open the configured port endpoint with bounded connect and data I/O. This
/// runs in the resource owner; the worker receives only the connected stream.
pub fn connect_port(directory: &Path, port: u32) -> std::io::Result<UnixStream> {
    let address = socket2::SockAddr::unix(directory.join(format!("{port}.sock")))?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.connect_timeout(&address, std::time::Duration::from_secs(5))?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(25)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    Ok(std::os::fd::OwnedFd::from(socket).into())
}

use crate::csm::VsockBackend;

/// A vsock backend that maps each guest port to a Unix domain socket file.
///
/// When the guest connects to port N, the backend connects to `uds_dir/N.sock`.
pub(crate) struct UdsBackend {
    connect: Box<dyn FnMut(u32) -> std::io::Result<UnixStream> + Send>,
    streams: HashMap<(u32, u32), UnixStream>,
}

impl UdsBackend {
    /// Create a new UDS backend with the given directory for socket files.
    pub(crate) fn new(uds_dir: PathBuf) -> Self {
        Self::with_connector(move |port| connect_port(&uds_dir, port))
    }

    pub(crate) fn with_connector(
        connect: impl FnMut(u32) -> std::io::Result<UnixStream> + Send + 'static,
    ) -> Self {
        Self {
            connect: Box::new(connect),
            streams: HashMap::new(),
        }
    }
}

impl VsockBackend for UdsBackend {
    fn reset(&mut self) {
        self.streams.clear();
    }

    fn on_connection_request(&mut self, local_port: u32, peer_port: u32) -> bool {
        match (self.connect)(local_port) {
            Ok(stream) => {
                log::info!("vsock-uds: connected port {local_port}:{peer_port}");
                self.streams.insert((local_port, peer_port), stream);
                true
            }
            Err(e) => {
                log::warn!("vsock-uds: failed to connect port {local_port}:{peer_port}: {e}");
                false
            }
        }
    }

    fn on_data_received(&mut self, local_port: u32, peer_port: u32, data: &[u8]) {
        if let Some(stream) = self.streams.get_mut(&(local_port, peer_port))
            && let Err(e) = stream.write_all(data)
        {
            log::warn!("vsock-uds: write failed for {local_port}:{peer_port}: {e}");
        }
    }

    fn on_connection_closed(&mut self, local_port: u32, peer_port: u32) {
        if let Some(stream) = self.streams.remove(&(local_port, peer_port)) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            log::info!("vsock-uds: closed connection {local_port}:{peer_port}");
        }
    }

    fn poll_data(&mut self) -> Option<(u32, u32, Vec<u8>)> {
        // Streams arrive with bounded read/write timeouts. The RX worker holds
        // the connection-manager lock here, so an idle peer must yield to TX.
        for (&(local_port, peer_port), stream) in &mut self.streams {
            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(0) => {
                    // EOF — peer closed.
                }
                Ok(n) => {
                    return Some((local_port, peer_port, buf[..n].to_vec()));
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // No data within timeout — nothing to send to guest now.
                }
                Err(_) => {}
            }
        }
        None
    }

    fn has_data(&self) -> bool {
        // UDS backend can't cheaply peek; assume data may be available
        // if any streams are open.
        !self.streams.is_empty()
    }
}
