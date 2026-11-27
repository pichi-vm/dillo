// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host sockets are supplied independently of packet/connection processing.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};

/// Native network resources. All returned sockets must be nonblocking and
/// unregistered: the stack owns their readiness registration and all data I/O.
/// DNS may block; it runs on the backend's bounded resolver-thread pool.
pub trait NetworkResources: Send + Sync {
    fn connect_tcp(&self, address: SocketAddr) -> io::Result<TcpStream>;
    fn connect_udp(&self, address: SocketAddr) -> io::Result<UdpSocket>;
    fn listen_tcp(&self, address: SocketAddr) -> io::Result<TcpListener>;
    fn bind_udp(&self, address: SocketAddr) -> io::Result<UdpSocket>;
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>>;
}

/// Direct native access, for callers which already own network authority.
#[derive(Debug)]
pub struct HostNetwork;

impl NetworkResources for HostNetwork {
    fn connect_tcp(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let stream = mio::net::TcpStream::connect(address)?;
        // Configure before granting the socket to a confined worker.
        stream.set_nodelay(true)?;
        Ok(stream.into())
    }

    fn connect_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(address)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    fn listen_tcp(&self, address: SocketAddr) -> io::Result<TcpListener> {
        mio::net::TcpListener::bind(address).map(Into::into)
    }

    fn bind_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        mio::net::UdpSocket::bind(address).map(Into::into)
    }

    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        (name, 0)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|a| a.ip()).collect())
    }
}
