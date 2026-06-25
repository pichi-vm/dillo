// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! A [`smoltcp::phy::Device`] adapter over two in-memory frame queues.
//!
//! The user-mode stack owns one of these. Its two queues are the seam between
//! smoltcp and the virtio device's RX/TX workers:
//!
//! - `rx` — frames the guest transmitted (handed in via the backend's `send`),
//!   waiting to be consumed by `iface.poll`.
//! - `tx` — frames smoltcp produced for the guest, waiting to be drained into
//!   the backend's outbound queue (delivered to the guest by the RX worker).
//!
//! smoltcp's `Device::receive` hands back a *pair* of tokens (an RX token to
//! read the inbound frame and a TX token to immediately reply). The classic
//! borrow hazard — both tokens aliasing `self` — is avoided here by having the
//! RX token *own* the popped frame (so it borrows nothing) while only the TX
//! token borrows `self.tx`.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use super::ETH_FRAME_MTU;

/// Bounds the stack's internal frame backlog in each direction, so a wedged
/// peer can't grow memory without limit. Frames past the cap are dropped, which
/// is exactly how a real NIC behaves under overrun.
pub(super) const MAX_QUEUE_FRAMES: usize = 1024;

/// smoltcp `phy::Device` backed by two `VecDeque`s of raw Ethernet frames.
pub(super) struct ProxyDevice {
    /// Guest → stack: frames awaiting `iface.poll` consumption.
    pub(super) rx: VecDeque<Vec<u8>>,
    /// Stack → guest: frames smoltcp emitted, awaiting delivery.
    pub(super) tx: VecDeque<Vec<u8>>,
}

impl ProxyDevice {
    pub(super) fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }

    /// Enqueue a guest frame for smoltcp to receive (dropping it if the backlog
    /// is full, like a NIC under overrun).
    pub(super) fn push_rx(&mut self, frame: Vec<u8>) {
        if self.rx.len() < MAX_QUEUE_FRAMES {
            self.rx.push_back(frame);
        }
    }
}

impl Device for ProxyDevice {
    type RxToken<'a> = ProxyRxToken;
    type TxToken<'a> = ProxyTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx.pop_front()?;
        // The RX token owns `frame`, so it borrows nothing; only the TX token
        // borrows `self.tx`. No aliasing.
        Some((ProxyRxToken(frame), ProxyTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(ProxyTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        // smoltcp's `max_transmission_unit` for an Ethernet medium is the full
        // L2 frame size (header included); 1514 yields the standard 1500-byte
        // IP MTU.
        caps.max_transmission_unit = ETH_FRAME_MTU;
        caps.max_burst_size = Some(MAX_QUEUE_FRAMES);
        caps
    }
}

/// Owns one received frame; `consume` hands smoltcp a read-only view of it.
pub(super) struct ProxyRxToken(Vec<u8>);

impl RxToken for ProxyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Borrows the stack's TX queue; `consume` allocates the frame, lets smoltcp
/// fill it, and enqueues it for the guest.
pub(super) struct ProxyTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for ProxyTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        if self.0.len() < MAX_QUEUE_FRAMES {
            self.0.push_back(buf);
        }
        result
    }
}
