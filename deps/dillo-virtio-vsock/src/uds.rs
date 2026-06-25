// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket backend for virtio-vsock.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::csm::VsockBackend;

/// A vsock backend that maps each guest port to a Unix domain socket file.
///
/// When the guest connects to port N, the backend connects to `uds_dir/N.sock`.
pub(crate) struct UdsBackend {
    uds_dir: PathBuf,
    streams: HashMap<(u32, u32), UnixStream>,
}

impl UdsBackend {
    /// Create a new UDS backend with the given directory for socket files.
    pub(crate) fn new(uds_dir: PathBuf) -> Self {
        Self {
            uds_dir,
            streams: HashMap::new(),
        }
    }
}

impl VsockBackend for UdsBackend {
    fn on_connection_request(&mut self, local_port: u32, peer_port: u32) -> bool {
        let sock_path = self.uds_dir.join(format!("{local_port}.sock"));
        match UnixStream::connect(&sock_path) {
            Ok(stream) => {
                log::info!(
                    "vsock-uds: connected to {} for port {local_port}:{peer_port}",
                    sock_path.display(),
                );
                self.streams.insert((local_port, peer_port), stream);
                true
            }
            Err(e) => {
                log::warn!(
                    "vsock-uds: failed to connect to {}: {e}",
                    sock_path.display(),
                );
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
        // Read timeout: local UDS echo latency is typically <1ms. The RX worker
        // holds the ConnectionManager lock across this call, so keep it short to
        // avoid stalling the TX worker; the RX worker re-polls every poll tick.
        let timeout = std::time::Duration::from_millis(25);

        for (&(local_port, peer_port), stream) in &mut self.streams {
            // Apply read timeout; skip on error (stream may be in unexpected state).
            if stream.set_read_timeout(Some(timeout)).is_err() {
                continue;
            }

            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(0) => {
                    // EOF — peer closed.
                    let _ = stream.set_read_timeout(None);
                }
                Ok(n) => {
                    // Restore blocking mode for future writes.
                    let _ = stream.set_read_timeout(None);
                    return Some((local_port, peer_port, buf[..n].to_vec()));
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // No data within timeout — nothing to send to guest now.
                    let _ = stream.set_read_timeout(None);
                }
                Err(_) => {
                    let _ = stream.set_read_timeout(None);
                }
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
