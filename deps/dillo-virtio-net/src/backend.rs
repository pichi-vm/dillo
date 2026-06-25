// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! The host-side network backend contract for virtio-net.
//!
//! [`VirtioNet`](crate::VirtioNet) is transport- and host-agnostic: it moves
//! L2 Ethernet frames between the guest's RX/TX virtqueues and a
//! [`NetBackend`]. The backend is what actually delivers those frames to the
//! outside world — a Linux TAP device, a macvtap endpoint, or (on every host) a
//! [`NullBackend`] sink that gives the guest a link-up NIC with no peer.
//!
//! Backends only ever see raw Ethernet frames — never the 12-byte
//! `virtio_net_hdr`, which the frontend strips on TX and prepends on RX.

use std::io;
use std::time::Duration;

/// How long a backend's [`recv`](NetBackend::recv) blocks before returning
/// `Ok(None)` so the RX worker can re-check its shutdown flag. Bounds worker
/// shutdown latency without an out-of-band wakeup primitive.
pub const RECV_POLL: Duration = Duration::from_millis(200);

/// Largest Ethernet frame (incl. 802.1Q tag, excl. the virtio-net header) a
/// backend is expected to hand back from [`recv`](NetBackend::recv). The RX
/// worker sizes its scratch buffer to this.
pub const MAX_FRAME_LEN: usize = 65_535;

/// A host-side L2 frame transport for one virtio-net device.
///
/// Implementations are shared across the RX and TX worker threads behind an
/// `Arc`, so every method takes `&self` and must be `Send + Sync`.
pub trait NetBackend: Send + Sync + std::fmt::Debug {
    /// Guest → host: transmit one Ethernet frame (no virtio-net header).
    fn send(&self, frame: &[u8]) -> io::Result<()>;

    /// Host → guest: block up to [`RECV_POLL`] for one inbound Ethernet frame.
    ///
    /// Returns `Ok(Some(n))` with the frame in `buf[..n]`, or `Ok(None)` on
    /// timeout (the caller re-checks shutdown and calls again). `buf` is at
    /// least [`MAX_FRAME_LEN`] bytes.
    fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>>;

    /// Whether the device should advertise link-up in its config status. The
    /// default is `true` (a freshly attached backend has a usable link).
    fn link_up(&self) -> bool {
        true
    }
}

/// Portable do-nothing backend: drops every transmitted frame and never
/// delivers one. Present on all hosts so a virtio-net device can always be
/// attached — the guest sees a NIC with the configured MAC and a link-up
/// status, which is enough to validate the full frontend (PCI/MMIO attach,
/// feature negotiation, queue setup, config-space MAC) on platforms without a
/// native L2 backend.
#[derive(Debug, Default)]
pub struct NullBackend;

impl NullBackend {
    pub fn new() -> Self {
        Self
    }
}

impl NetBackend for NullBackend {
    fn send(&self, _frame: &[u8]) -> io::Result<()> {
        // Sink: the guest's transmit completes, the frame goes nowhere.
        Ok(())
    }

    fn recv(&self, _buf: &mut [u8]) -> io::Result<Option<usize>> {
        // No peer ever produces inbound frames; block briefly so the RX worker
        // stays responsive to shutdown without spinning.
        std::thread::sleep(RECV_POLL);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_backend_sinks_tx_and_yields_no_rx() {
        let b = NullBackend::new();
        b.send(&[1, 2, 3]).expect("send is infallible");
        let mut buf = vec![0u8; MAX_FRAME_LEN];
        assert_eq!(b.recv(&mut buf).expect("recv ok"), None);
        assert!(b.link_up());
    }
}
