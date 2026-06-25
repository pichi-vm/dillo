// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! One proxied UDP destination: a single smoltcp UDP socket (bound to the
//! guest's intended `(dst_ip, dst_port)`) bridged to **one host socket per
//! distinct guest source endpoint**.
//!
//! smoltcp delivers every guest datagram for a `(dst_ip, dst_port)` to the same
//! socket and tags it with the guest's source endpoint, so a destination needs
//! exactly one smoltcp socket. The host side, though, must be one socket *per
//! guest source*: each guest source gets its own host source port, so the
//! destination's replies demux back to the right guest source. A single shared
//! host socket could not tell two guest sources apart (the prior limitation).
//!
//! Idle sources are reclaimed after [`UDP_IDLE_TIMEOUT`](super::UDP_IDLE_TIMEOUT);
//! a destination with no remaining sources is reaped by the stack.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use mio::net::UdpSocket;
use smoltcp::wire::IpEndpoint;

/// One host-side socket serving a single guest source endpoint.
pub(super) struct UdpSource {
    /// Host socket, connected to the destination; its ephemeral source port is
    /// unique to this guest source so replies route back unambiguously.
    pub(super) sock: UdpSocket,
    /// Last time a datagram moved in either direction (for idle reclaim).
    last_active: Instant,
}

/// State for one bridged UDP destination: the host target plus a host socket per
/// guest source endpoint.
pub(super) struct UdpFlow {
    /// Where every source for this destination connects (the masqueraded host
    /// address, or loopback for the gateway fold).
    target: SocketAddr,
    /// Host sockets keyed by guest source endpoint.
    sources: HashMap<IpEndpoint, UdpSource>,
    /// Last activity across any source, so a destination that briefly has no
    /// sources (e.g. host socket creation failed) is still eventually reaped.
    last_active: Instant,
}

impl std::fmt::Debug for UdpFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpFlow")
            .field("target", &self.target)
            .field("sources", &self.sources.len())
            .finish_non_exhaustive()
    }
}

impl UdpFlow {
    pub(super) fn new(target: SocketAddr) -> Self {
        Self {
            target,
            sources: HashMap::new(),
            last_active: Instant::now(),
        }
    }

    /// The host address every source for this destination connects to.
    pub(super) fn target(&self) -> SocketAddr {
        self.target
    }

    /// Whether a host socket already exists for this guest source.
    pub(super) fn has_source(&self, src: &IpEndpoint) -> bool {
        self.sources.contains_key(src)
    }

    /// Register a freshly created, connected+mio-registered host socket for a
    /// guest source. The stack owns poll/token allocation, so it builds the
    /// socket and hands it in here.
    pub(super) fn add_source(&mut self, src: IpEndpoint, sock: UdpSocket) {
        self.sources.insert(
            src,
            UdpSource {
                sock,
                last_active: Instant::now(),
            },
        );
        self.last_active = Instant::now();
    }

    /// Forward one guest datagram out the host socket for `src` (which must
    /// already exist via [`add_source`](Self::add_source)).
    pub(super) fn send_to_host(&mut self, src: &IpEndpoint, payload: &[u8]) {
        if let Some(s) = self.sources.get_mut(src) {
            let _ = s.sock.send(payload);
            s.last_active = Instant::now();
            self.last_active = Instant::now();
        }
    }

    /// Drain every host source's pending replies, handing each `(guest_source,
    /// payload)` to `emit` (which the stack uses to send back on the smoltcp
    /// socket). Returns `true` if any datagram was read.
    pub(super) fn drain_host<F: FnMut(IpEndpoint, &[u8])>(&mut self, mut emit: F) -> bool {
        let mut worked = false;
        let mut buf = vec![0u8; 65_535];
        let now = Instant::now();
        for (src, s) in &mut self.sources {
            loop {
                match s.sock.recv(&mut buf) {
                    Ok(n) => {
                        emit(*src, &buf[..n]);
                        s.last_active = now;
                        worked = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        if worked {
            self.last_active = now;
        }
        worked
    }

    /// Remove host sources idle longer than `timeout`, returning them so the
    /// stack can deregister their mio sockets. The destination itself is reaped
    /// separately once it is both source-less and idle.
    pub(super) fn reap_idle_sources(&mut self, now: Instant, timeout: Duration) -> Vec<UdpSource> {
        let idle: Vec<IpEndpoint> = self
            .sources
            .iter()
            .filter(|(_, s)| now.saturating_duration_since(s.last_active) >= timeout)
            .map(|(k, _)| *k)
            .collect();
        idle.into_iter()
            .filter_map(|k| self.sources.remove(&k))
            .collect()
    }

    /// Whether this destination has no sources and has itself been idle past
    /// `timeout` — safe to reap (along with its smoltcp socket).
    pub(super) fn is_reapable(&self, now: Instant, timeout: Duration) -> bool {
        self.sources.is_empty() && now.saturating_duration_since(self.last_active) >= timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reapable_only_when_sourceless_and_idle() {
        let flow = UdpFlow::new("127.0.0.1:9".parse().unwrap());
        let t0 = flow.last_active;
        // Source-less and fresh: not yet reapable.
        assert!(!flow.is_reapable(t0, Duration::from_secs(60)));
        // Source-less and idle: reapable.
        assert!(flow.is_reapable(t0 + Duration::from_secs(60), Duration::from_secs(60)));
    }
}
