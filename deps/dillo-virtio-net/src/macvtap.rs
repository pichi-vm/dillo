// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Linux macvtap backend.
//!
//! macvtap is Linux-specific: it stacks a virtual L2 endpoint directly on a
//! physical (or other) interface, exposing a character device `/dev/tap<ifindex>`
//! that delivers/accepts raw Ethernet frames — no `TUNSETIFF`, no bridge, and
//! the guest gets its own MAC on the parent's segment. The operator creates the
//! link out of band:
//!
//! ```text
//! ip link add link eth0 name macvtap0 type macvtap mode bridge
//! ip link set macvtap0 address 52:54:00:ab:cd:ef up
//! ```
//!
//! dillo then attaches to it by name. [`MacvtapBackend::open`] resolves the
//! interface's `ifindex` from sysfs and opens the matching `/dev/tap<ifindex>`.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;

use crate::backend::NetBackend;
use crate::linux_fd::FrameFd;

/// A macvtap-backed virtio-net L2 transport.
#[derive(Debug)]
pub struct MacvtapBackend {
    fd: FrameFd,
    name: String,
}

impl MacvtapBackend {
    /// Attach to an existing macvtap interface by name (e.g. `"macvtap0"`).
    pub fn open(name: &str) -> io::Result<Self> {
        let ifindex_path = format!("/sys/class/net/{name}/ifindex");
        let ifindex: u32 = std::fs::read_to_string(&ifindex_path)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("reading {ifindex_path} (is {name:?} a macvtap link?): {e}"),
                )
            })?
            .trim()
            .parse()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{ifindex_path}: {e}"))
            })?;

        let dev = format!("/dev/tap{ifindex}");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&dev)
            .map_err(|e| io::Error::new(e.kind(), format!("opening {dev} for {name:?}: {e}")))?;

        log::info!("virtio-net: opened macvtap {name:?} via {dev}");
        Ok(Self {
            fd: FrameFd::new(file),
            name: name.to_owned(),
        })
    }

    /// The macvtap interface name this backend is attached to.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl NetBackend for MacvtapBackend {
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        self.fd.send(frame)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        self.fd.recv(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A nonexistent interface resolves cleanly to an error (no panic).
    #[test]
    fn missing_interface_errors() {
        let err = MacvtapBackend::open("definitely-not-an-iface-xyz").unwrap_err();
        // NotFound from the missing sysfs ifindex file.
        assert!(
            matches!(err.kind(), io::ErrorKind::NotFound | io::ErrorKind::Other),
            "unexpected error kind: {err:?}"
        );
    }
}
