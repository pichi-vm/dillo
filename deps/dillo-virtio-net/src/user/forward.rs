// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Inbound port forwarding: host listeners that originate guest connections.
//!
//! The guest has no routable address, so the only way traffic initiates from
//! *outside* is an explicit rule. Each [`Forward`] binds a host socket; when a
//! connection (TCP) or datagram (UDP) arrives, the stack originates the
//! matching flow into the guest (`10.0.2.15:<guest_port>`) and bridges it.
//!
//! This module owns the type the rest of dillo passes in (translated from the
//! config's `ForwardSpec`) and the bound, mio-registered listeners. The
//! accept/relay orchestration lives in [`stack`](super::stack), which owns the
//! smoltcp interface needed to originate guest-side sockets.

use std::net::IpAddr;

use mio::Token;
use mio::net::{TcpListener, UdpSocket};

/// Transport for a forward rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// One inbound port-forward rule: host `(ip, port)` → guest `guest_port`.
///
/// This is the backend's own type (not the config's `ForwardSpec`), so the net
/// crate stays independent of `dillo-config`; `main.rs` translates between them.
#[derive(Debug, Clone)]
pub struct Forward {
    pub proto: Proto,
    pub host_ip: IpAddr,
    pub host_port: u16,
    pub guest_port: u16,
}

/// A bound, mio-registered host listener for one forward rule.
pub(super) enum ForwardListener {
    Tcp {
        listener: TcpListener,
        guest_port: u16,
        token: Token,
    },
    Udp {
        sock: UdpSocket,
        guest_port: u16,
        token: Token,
        /// The most recent outside sender, where guest replies are returned.
        outside: Option<std::net::SocketAddr>,
        /// The smoltcp UDP socket originating datagrams toward the guest, set
        /// up lazily on the first datagram.
        guest_socket: Option<smoltcp::iface::SocketHandle>,
    },
}

impl std::fmt::Debug for ForwardListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardListener::Tcp {
                guest_port, token, ..
            } => f
                .debug_struct("ForwardListener::Tcp")
                .field("guest_port", guest_port)
                .field("token", token)
                .finish_non_exhaustive(),
            ForwardListener::Udp {
                guest_port, token, ..
            } => f
                .debug_struct("ForwardListener::Udp")
                .field("guest_port", guest_port)
                .field("token", token)
                .finish_non_exhaustive(),
        }
    }
}
