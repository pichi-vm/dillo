// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Layer-1 datapath harness: the user-mode backend exercised end to end with a
//! **second smoltcp stack standing in for the guest**, and ordinary in-process
//! `std::net` servers standing in for the outside world. No VM, no privilege,
//! deterministic, and identical on every platform — so this is what proves the
//! any-ip + per-flow demux mechanism (the one real unknown) actually works.
//!
//! The guest stack's frames go in via [`NetBackend::send`]; the frames the
//! backend produces come back via [`NetBackend::recv`] (drained by a small pump
//! thread so the driver never blocks). Each test drives the guest stack until a
//! condition holds or a deadline expires.

#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, UdpPacket, UdpRepr,
};

use crate::backend::NetBackend;

use super::{
    DNS_IP, ETH_FRAME_MTU, Forward, GATEWAY_IP, GUEST_IP, Proto, SUBNET_PREFIX, UserNetBackend,
};

const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC];
const DEADLINE: Duration = Duration::from_secs(15);

// --- guest-side smoltcp stack ---------------------------------------------

/// A `phy::Device` whose two queues are shuttled to/from the backend by the
/// test driver: `tx` frames are sent into the backend, `rx` frames are the ones
/// the backend produced for the guest.
struct GuestDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl Device for GuestDevice {
    type RxToken<'a> = GuestRx;
    type TxToken<'a> = GuestTx<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((GuestRx(frame), GuestTx(&mut self.tx)))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(GuestTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = ETH_FRAME_MTU;
        caps
    }
}

struct GuestRx(Vec<u8>);
impl RxToken for GuestRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct GuestTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for GuestTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

/// The guest stack plus the backend under test and the rx-pump plumbing.
struct Harness {
    backend: Arc<UserNetBackend>,
    iface: Interface,
    sockets: SocketSet<'static>,
    device: GuestDevice,
    rx_from_backend: Arc<Mutex<VecDeque<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    pump: Option<JoinHandle<()>>,
}

impl Harness {
    fn new(forwards: Vec<Forward>) -> Self {
        let backend = Arc::new(UserNetBackend::new(forwards).unwrap());

        let mut config = Config::new(EthernetAddress(GUEST_MAC).into());
        config.random_seed = 0x1234_5678;
        let mut device = GuestDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        };
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(GUEST_IP, SUBNET_PREFIX));
            // A static guest v6 address in the gateway's ULA prefix, so the
            // datapath tests can exercise IPv6 without driving SLAAC here.
            let _ = addrs.push(IpCidr::new(
                IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 0x15),
                64,
            ));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2));
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        let sockets = SocketSet::new(Vec::new());

        // Drain the backend's outbound frames on a thread so the driver never
        // blocks in `recv` (which waits up to RECV_POLL when idle).
        let rx_from_backend = Arc::new(Mutex::new(VecDeque::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let pump = {
            let backend = Arc::clone(&backend);
            let queue = Arc::clone(&rx_from_backend);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65_535];
                while !stop.load(Ordering::Acquire) {
                    if let Ok(Some(n)) = backend.recv(&mut buf) {
                        queue.lock().unwrap().push_back(buf[..n].to_vec());
                    }
                }
            })
        };

        Self {
            backend,
            iface,
            sockets,
            device,
            rx_from_backend,
            stop,
            pump: Some(pump),
        }
    }

    /// One shuttle round: feed backend-produced frames into the guest stack,
    /// poll it, and hand its outbound frames to the backend.
    fn step(&mut self) {
        {
            let mut q = self.rx_from_backend.lock().unwrap();
            while let Some(frame) = q.pop_front() {
                self.device.rx.push_back(frame);
            }
        }
        self.iface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);
        for frame in self.device.tx.drain(..) {
            let _ = self.backend.send(&frame);
        }
    }

    /// Drive until `cond` holds, returning `true`, or the deadline expires.
    fn run_until<F: FnMut(&mut Self) -> bool>(&mut self, mut cond: F) -> bool {
        let deadline = StdInstant::now() + DEADLINE;
        loop {
            self.step();
            if cond(self) {
                return true;
            }
            if StdInstant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn add_tcp(&mut self) -> SocketHandle {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        );
        self.sockets.add(socket)
    }

    fn connect(&mut self, dst: IpEndpoint, local_port: u16) -> SocketHandle {
        let handle = self.add_tcp();
        let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
        socket
            .connect(self.iface.context(), dst, local_port)
            .unwrap();
        handle
    }

    fn listen(&mut self, port: u16) -> SocketHandle {
        let handle = self.add_tcp();
        let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
        socket.listen(port).unwrap();
        handle
    }

    fn tcp(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket<'static>>(handle)
    }

    /// Hand a fully-formed Ethernet frame straight to the backend, bypassing the
    /// guest `iface`. Used by the raw ICMP/ARP test that builds frames by hand.
    fn send_raw(&self, frame: &[u8]) {
        let _ = self.backend.send(frame);
    }

    /// Drain every frame the backend has produced for the guest so far (the pump
    /// thread moves them into `rx_from_backend`). The raw counterpart to `step`.
    fn drain_raw(&self) -> Vec<Vec<u8>> {
        let mut q = self.rx_from_backend.lock().unwrap();
        q.drain(..).collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(p) = self.pump.take() {
            let _ = p.join();
        }
    }
}

// --- in-process servers ----------------------------------------------------

/// A loopback TCP echo server bound to `bind_addr` that echoes every byte until
/// EOF, then closes. Returns the bound port and the accept thread.
fn spawn_tcp_echo_on(bind_addr: &str) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind(bind_addr).unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Ok(_) | Err(_) => break,
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    (port, handle)
}

/// The common IPv4-loopback TCP echo server.
fn spawn_tcp_echo() -> (u16, JoinHandle<()>) {
    spawn_tcp_echo_on("127.0.0.1:0")
}

/// A loopback UDP echo server that echoes `want` datagrams back to their
/// senders, then exits (so `join` is quick). Each datagram is echoed to its own
/// `peer`, so a single server correctly serves multiple distinct guest sources.
fn spawn_udp_echo_n(want: usize) -> (u16, JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let port = sock.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let deadline = StdInstant::now() + DEADLINE;
        let mut echoed = 0;
        while echoed < want && StdInstant::now() < deadline {
            match sock.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    let _ = sock.send_to(&buf[..n], peer);
                    echoed += 1;
                }
                Err(_) => continue,
            }
        }
    });
    (port, handle)
}

/// The common single-datagram echo server.
fn spawn_udp_echo() -> (u16, JoinHandle<()>) {
    spawn_udp_echo_n(1)
}

/// A port that was bound then released — almost certainly free, so connecting
/// to it yields a connection-refused.
fn likely_closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
    IpAddress::Ipv4(Ipv4Address::new(a, b, c, d))
}

/// Unwrap an `IpAddress` known to be IPv4 (the addressing constants used by the
/// raw-frame tests are v4). Panics on a v6 address — a test-only assumption.
fn expect_v4(addr: IpAddress) -> Ipv4Address {
    match addr {
        IpAddress::Ipv4(a) => a,
        IpAddress::Ipv6(_) => panic!("expected an IPv4 address"),
    }
}

/// Build one Ethernet frame: header + a `payload_len`-byte payload filled by
/// `fill`. Used by the raw ICMP/ARP test that crafts frames by hand.
fn eth_frame(
    src: EthernetAddress,
    dst: EthernetAddress,
    ethertype: EthernetProtocol,
    payload_len: usize,
    fill: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let mut buf = vec![0u8; EthernetFrame::<&[u8]>::header_len() + payload_len];
    let mut frame = EthernetFrame::new_unchecked(&mut buf);
    frame.set_src_addr(src);
    frame.set_dst_addr(dst);
    frame.set_ethertype(ethertype);
    fill(frame.payload_mut());
    buf
}

/// Drive the backend (draining raw frames each round) until `f` returns `Some`
/// for one of them, or the deadline expires. The raw analogue of `run_until`.
fn wait_for<T>(h: &Harness, mut f: impl FnMut(&[u8]) -> Option<T>) -> Option<T> {
    let deadline = StdInstant::now() + DEADLINE;
    loop {
        for frame in h.drain_raw() {
            if let Some(v) = f(&frame) {
                return Some(v);
            }
        }
        if StdInstant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Send `payload` on `handle`, half-close, and collect the echo until we have
/// `payload.len()` bytes back (or the deadline expires). Returns the bytes read.
fn echo_exchange(h: &mut Harness, handle: SocketHandle, payload: &[u8]) -> Vec<u8> {
    let mut sent = 0usize;
    let mut closed = false;
    let mut got: Vec<u8> = Vec::new();
    let want = payload.len();
    let _ = h.run_until(|h| {
        let socket = h.tcp(handle);
        while socket.can_send() && sent < payload.len() {
            match socket.send_slice(&payload[sent..]) {
                Ok(n) if n > 0 => sent += n,
                Ok(_) | Err(_) => break,
            }
        }
        if sent == payload.len() && !closed {
            socket.close();
            closed = true;
        }
        while socket.can_recv() {
            if let Ok(chunk) = socket.recv(|b| (b.len(), b.to_vec())) {
                got.extend_from_slice(&chunk);
            } else {
                break;
            }
        }
        got.len() >= want
    });
    got
}

// --- tests -----------------------------------------------------------------

/// Outbound TCP to an arbitrary destination (masquerade): the guest dials
/// `127.0.0.1:port` off-subnet (routed via the gateway); the proxy terminates
/// it and re-originates to that literal destination — the in-process echo.
#[test]
fn outbound_tcp_masquerade() {
    let (port, server) = spawn_tcp_echo();
    let mut h = Harness::new(vec![]);
    let handle = h.connect(IpEndpoint::new(ipv4(127, 0, 0, 1), port), 49001);
    let got = echo_exchange(&mut h, handle, b"hello-masquerade");
    assert_eq!(
        got, b"hello-masquerade",
        "masquerade echo round-trip failed"
    );
    drop(h);
    let _ = server.join();
}

/// guest → host redirect: dialing the gateway IP folds to host loopback.
#[test]
fn gateway_to_host_redirect() {
    let (port, server) = spawn_tcp_echo();
    let mut h = Harness::new(vec![]);
    // Dial the gateway IP on the host server's port; the proxy maps it to
    // 127.0.0.1:port.
    let handle = h.connect(IpEndpoint::new(GATEWAY_IP, port), 49002);
    let got = echo_exchange(&mut h, handle, b"hello-gateway");
    assert_eq!(got, b"hello-gateway", "gateway→host redirect failed");
    drop(h);
    let _ = server.join();
}

/// Inbound port forward: an outside host connection lands on a guest listener.
#[test]
fn inbound_forward_tcp() {
    const GUEST_PORT: u16 = 4242;
    let host_port = likely_closed_port();
    let forwards = vec![Forward {
        proto: Proto::Tcp,
        host_ip: "127.0.0.1".parse().unwrap(),
        host_port,
        guest_port: GUEST_PORT,
    }];
    let mut h = Harness::new(forwards);
    let listen = h.listen(GUEST_PORT);

    // From the outside, connect to the forwarded host port and exchange data.
    let payload = b"hello-into-guest";
    let outside: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let echoed = Arc::clone(&outside);
    let client = std::thread::spawn(move || {
        // Retry briefly: the listener is bound, but give the stack a moment.
        let deadline = StdInstant::now() + DEADLINE;
        let mut stream = loop {
            match TcpStream::connect(("127.0.0.1", host_port)) {
                Ok(s) => break s,
                Err(_) if StdInstant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("forward connect failed: {e}"),
            }
        };
        stream.set_read_timeout(Some(DEADLINE)).ok();
        stream.write_all(payload).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        *echoed.lock().unwrap() = buf;
    });

    // The guest side: accept the forwarded connection, echo it back, then keep
    // driving until the *outside* peer has actually received the echo (the
    // guest's frames only leave its stack while we keep stepping).
    let mut accepted = false;
    let mut relayed = 0usize;
    let mut inbuf: Vec<u8> = Vec::new();
    let mut closed = false;
    let done = h.run_until(|h| {
        let socket = h.tcp(listen);
        if socket.is_active() {
            accepted = true;
        }
        while socket.can_recv() {
            if let Ok(chunk) = socket.recv(|b| (b.len(), b.to_vec())) {
                inbuf.extend_from_slice(&chunk);
            } else {
                break;
            }
        }
        while socket.can_send() && relayed < inbuf.len() {
            match socket.send_slice(&inbuf[relayed..]) {
                Ok(n) if n > 0 => relayed += n,
                Ok(_) | Err(_) => break,
            }
        }
        if !closed && relayed == payload.len() && inbuf.len() == payload.len() {
            socket.close();
            closed = true;
        }
        outside.lock().unwrap().len() >= payload.len()
    });
    assert!(accepted, "guest listener never became active");
    assert!(done, "outside peer never received the guest's echo");

    let _ = client.join();
    assert_eq!(
        &*outside.lock().unwrap(),
        payload,
        "outside peer did not get the guest's echo back"
    );
}

/// UDP outbound + reply through the gateway.
#[test]
fn udp_outbound_and_reply() {
    let (port, server) = spawn_udp_echo();
    let mut h = Harness::new(vec![]);
    let handle = h.sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
    ));
    {
        let socket = h.sockets.get_mut::<udp::Socket<'_>>(handle);
        socket
            .bind(IpListenEndpoint {
                addr: None,
                port: 49003,
            })
            .unwrap();
    }

    let mut sent = false;
    let mut got: Vec<u8> = Vec::new();
    let ok = h.run_until(|h| {
        let socket = h.sockets.get_mut::<udp::Socket<'_>>(handle);
        if !sent && socket.can_send() {
            socket
                .send_slice(b"udp-ping", IpEndpoint::new(GATEWAY_IP, port))
                .unwrap();
            sent = true;
        }
        if socket.can_recv()
            && let Ok((payload, _meta)) = socket.recv()
        {
            got = payload.to_vec();
        }
        got == b"udp-ping"
    });
    assert!(ok, "UDP echo via gateway did not round-trip: got {got:?}");
    drop(h);
    let _ = server.join();
}

/// Two distinct guest source endpoints to the *same* destination each get their
/// own reply. Previously the backend kept a single guest endpoint per
/// destination, so the second source clobbered the first's reply path; now each
/// source has its own host socket. Drives both sources concurrently and asserts
/// both receive the echo.
#[test]
fn udp_two_sources_same_dest() {
    // One server, two datagrams to echo (one per source).
    let (port, server) = spawn_udp_echo_n(2);
    let mut h = Harness::new(vec![]);

    let mk = |h: &mut Harness, local_port: u16| -> SocketHandle {
        let handle = h.sockets.add(udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
        ));
        h.sockets
            .get_mut::<udp::Socket<'_>>(handle)
            .bind(IpListenEndpoint {
                addr: None,
                port: local_port,
            })
            .unwrap();
        handle
    };
    // Two guest sources (distinct local ports) → the same loopback dest, dialed
    // off-subnet so it goes through masquerade (not the gateway fold).
    let a = mk(&mut h, 49010);
    let b = mk(&mut h, 49011);
    let dest = IpEndpoint::new(ipv4(127, 0, 0, 1), port);

    let mut sent_a = false;
    let mut sent_b = false;
    let mut got_a: Vec<u8> = Vec::new();
    let mut got_b: Vec<u8> = Vec::new();
    let ok = h.run_until(|h| {
        {
            let sa = h.sockets.get_mut::<udp::Socket<'_>>(a);
            if !sent_a && sa.can_send() {
                sa.send_slice(b"from-a", dest).unwrap();
                sent_a = true;
            }
            if got_a.is_empty()
                && sa.can_recv()
                && let Ok((p, _)) = sa.recv()
            {
                got_a = p.to_vec();
            }
        }
        {
            let sb = h.sockets.get_mut::<udp::Socket<'_>>(b);
            if !sent_b && sb.can_send() {
                sb.send_slice(b"from-b", dest).unwrap();
                sent_b = true;
            }
            if got_b.is_empty()
                && sb.can_recv()
                && let Ok((p, _)) = sb.recv()
            {
                got_b = p.to_vec();
            }
        }
        !got_a.is_empty() && !got_b.is_empty()
    });
    assert!(
        ok,
        "both sources should get their own echo: got_a={got_a:?} got_b={got_b:?}"
    );
    assert_eq!(got_a, b"from-a", "source A got the wrong datagram");
    assert_eq!(got_b, b"from-b", "source B got the wrong datagram");
    drop(h);
    let _ = server.join();
}

/// A connect to a refused host port resets the guest connection (RST).
///
/// The target port is one that only a *UDP* socket holds: a TCP connect to it
/// is refused on every platform (separate port spaces, no TCP listener), and
/// holding the socket keeps the port from being reused. This is deterministic
/// where the bind-then-drop trick is not — on Windows a just-closed listener
/// port briefly still accepts connects.
#[test]
fn connection_refused_resets_guest() {
    // Hold a UDP socket so the TCP port stays free of any TCP listener.
    let guard = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_port = guard.local_addr().unwrap().port();

    let mut h = Harness::new(vec![]);
    let handle = h.connect(IpEndpoint::new(ipv4(127, 0, 0, 1), dead_port), 49004);
    let reset = h.run_until(|h| {
        let socket = h.tcp(handle);
        // The host connect is refused; the proxy RSTs the guest (immediately on
        // Unix, via the connect-timeout backstop on Windows) → Closed.
        matches!(socket.state(), tcp::State::Closed) && !socket.is_active()
    });
    drop(guard);
    assert!(reset, "guest connection to a refused port was not reset");
}

/// Half-close: the guest sends, closes its write half, and still receives the
/// echo of everything it sent.
#[test]
fn half_close_preserves_inbound() {
    let (port, server) = spawn_tcp_echo();
    let mut h = Harness::new(vec![]);
    let handle = h.connect(IpEndpoint::new(GATEWAY_IP, port), 49005);
    // `echo_exchange` closes after sending, then reads — i.e. a half-close.
    let got = echo_exchange(&mut h, handle, b"data-before-fin");
    assert_eq!(
        got, b"data-before-fin",
        "half-closed guest lost its inbound echo"
    );
    drop(h);
    let _ = server.join();
}

/// A multi-segment transfer (well beyond one MSS) round-trips intact, proving
/// windowing/backpressure in both directions.
#[test]
fn multi_segment_transfer() {
    let (port, server) = spawn_tcp_echo();
    let mut h = Harness::new(vec![]);
    let handle = h.connect(IpEndpoint::new(GATEWAY_IP, port), 49006);

    // 256 KiB of a recognizable pattern.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let got = echo_exchange(&mut h, handle, &payload);
    assert_eq!(got.len(), payload.len(), "multi-segment length mismatch");
    assert_eq!(got, payload, "multi-segment payload corrupted");
    drop(h);
    let _ = server.join();
}

/// Fast, VM-free reproduction of the masquerade-to-real-external-host path: the
/// guest-stack dials a well-known public IP, which the proxy masquerades onto a
/// real host socket. A working masquerade keeps the connection up; a broken one
/// (the Windows-only bug under investigation — see WINDOWS-MASQUERADE-HANDOFF.md)
/// resets the guest to `Closed` within the proxy's connect-timeout window.
///
/// `#[ignore]`d: needs outbound internet on 443, so it never runs in CI. Run it
/// manually while debugging — it reproduces in seconds instead of a 10-minute
/// VM boot:
///
/// ```text
/// cargo test -p dillo-virtio-net -- --ignored masquerade_holds_to_real_internet
/// ```
#[test]
#[ignore = "needs outbound internet on 443; manual repro for masquerade-to-external"]
fn masquerade_holds_to_real_internet() {
    // Cloudflare anycast; 443 is the port CI/firewalls reliably permit.
    let mut h = Harness::new(vec![]);
    let handle = h.connect(IpEndpoint::new(ipv4(1, 1, 1, 1), 443), 49100);

    // The guest establishes with the proxy immediately (the proxy accepts the
    // SYN before its own host connect resolves).
    let established = h.run_until(|h| h.tcp(handle).may_send());
    assert!(established, "guest never established with the proxy");

    // Drive past the proxy's 5s host-connect timeout. A reachable host keeps the
    // bridged connection open; the bug resets it to Closed.
    let start = StdInstant::now();
    let mut closed = false;
    while start.elapsed() < Duration::from_secs(8) {
        h.step();
        if matches!(h.tcp(handle).state(), tcp::State::Closed) {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !closed,
        "masquerade to a real external host was reset (reproduces the Windows bug)"
    );
}

/// A minimal DNS query for `A example.com`, sent as the guest's UDP payload.
/// Hand-rolled so the test pulls in no DNS crate: a 12-byte header (id `0x1234`,
/// RD set, 1 question) followed by the QNAME `example.com`, QTYPE=A, QCLASS=IN.
const DNS_QUERY_EXAMPLE_COM: &[u8] = &[
    0x12, 0x34, // id
    0x01, 0x00, // flags: RD
    0x00, 0x01, // qdcount = 1
    0x00, 0x00, // ancount
    0x00, 0x00, // nscount
    0x00, 0x00, // arcount
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // 7"example"
    0x03, b'c', b'o', b'm', // 3"com"
    0x00, // root label
    0x00, 0x01, // qtype = A
    0x00, 0x01, // qclass = IN
];

/// Fast, VM-free reproduction of **UDP** masquerade to a real external host: the
/// guest-stack sends a real DNS query to a public resolver (`1.1.1.1:53`) and the
/// proxy masquerades it onto a real host UDP socket. A working masquerade relays
/// the resolver's reply back to the guest; a broken external-UDP path (the same
/// class of Windows-only masquerade bug tracked in WINDOWS-MASQUERADE-HANDOFF.md,
/// but for UDP rather than TCP) yields no reply.
///
/// This is the UDP analogue of [`masquerade_holds_to_real_internet`] and exists
/// because the in-process UDP test (`udp_outbound_and_reply`) only exercises the
/// gateway→loopback fold, never a non-loopback external destination — the exact
/// dimension where the TCP masquerade bug lived. DNS is the natural self-checking
/// external-UDP traffic: a valid response proves the full outbound+reply round
/// trip through the proxy.
///
/// `#[ignore]`d: needs outbound DNS (UDP/53), so it never runs in CI. Run it
/// manually while debugging:
///
/// ```text
/// cargo test -p dillo-virtio-net -- --ignored dns_masquerade_to_real_resolver
/// ```
#[test]
#[ignore = "needs outbound UDP/53; manual repro for UDP masquerade-to-external"]
fn dns_masquerade_to_real_resolver() {
    let mut h = Harness::new(vec![]);
    let handle = h.sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
    ));
    {
        let socket = h.sockets.get_mut::<udp::Socket<'_>>(handle);
        socket
            .bind(IpListenEndpoint {
                addr: None,
                port: 49101,
            })
            .unwrap();
    }

    // Dial the public resolver directly (off-subnet → masquerade), not the
    // gateway, so this exercises the non-loopback external UDP path.
    let resolver = IpEndpoint::new(ipv4(1, 1, 1, 1), 53);
    let mut sent = false;
    let mut reply: Vec<u8> = Vec::new();
    let ok = h.run_until(|h| {
        let socket = h.sockets.get_mut::<udp::Socket<'_>>(handle);
        if !sent && socket.can_send() {
            socket.send_slice(DNS_QUERY_EXAMPLE_COM, resolver).unwrap();
            sent = true;
        }
        if socket.can_recv()
            && let Ok((payload, _meta)) = socket.recv()
        {
            reply = payload.to_vec();
        }
        !reply.is_empty()
    });

    assert!(
        ok,
        "UDP masquerade to a real external resolver got no reply (external-UDP path broken)"
    );
    // A DNS response echoes the query id and has the QR (response) bit set, so we
    // know the bytes came from the resolver and not some stray datagram.
    assert!(
        reply.len() >= 12,
        "DNS reply too short: {} bytes",
        reply.len()
    );
    assert_eq!(&reply[0..2], &[0x12, 0x34], "DNS reply id mismatch");
    assert_eq!(reply[2] & 0x80, 0x80, "DNS reply QR bit not set");
}

/// The guest can ping the gateway: smoltcp's `auto-icmp-echo-reply` makes the
/// interface answer ICMP echo requests to its own addresses. Build the request
/// frames by hand (the test stack has no ICMP socket) and drive them straight
/// through the backend: first ARP for the gateway MAC, then an echo request,
/// then assert a matching echo reply comes back.
///
/// External ping is intentionally unsupported (see the module docs), so this
/// covers the only ICMP path the backend offers.
#[test]
fn gateway_ping_replies() {
    let h = Harness::new(vec![]);
    let guest_ip = expect_v4(GUEST_IP);
    let gw_ip = expect_v4(GATEWAY_IP);
    let guest_mac = EthernetAddress(GUEST_MAC);
    let bcast = EthernetAddress([0xff; 6]);

    // 1. ARP request for the gateway's MAC, then read the ARP reply to learn it.
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: guest_mac,
        source_protocol_addr: guest_ip,
        target_hardware_addr: EthernetAddress([0; 6]),
        target_protocol_addr: gw_ip,
    };
    h.send_raw(&eth_frame(
        guest_mac,
        bcast,
        EthernetProtocol::Arp,
        arp.buffer_len(),
        |p| {
            arp.emit(&mut ArpPacket::new_unchecked(p));
        },
    ));

    let gw_mac = wait_for(&h, |frame| {
        let eth = EthernetFrame::new_checked(frame).ok()?;
        if eth.ethertype() != EthernetProtocol::Arp {
            return None;
        }
        let rep = ArpRepr::parse(&ArpPacket::new_checked(eth.payload()).ok()?).ok()?;
        match rep {
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr,
                source_protocol_addr,
                ..
            } if source_protocol_addr == gw_ip => Some(source_hardware_addr),
            _ => None,
        }
    })
    .expect("gateway never answered ARP");

    // 2. ICMP echo request to the gateway, now that we have its MAC.
    let echo = Icmpv4Repr::EchoRequest {
        ident: 0xABCD,
        seq_no: 1,
        data: b"dillo-ping",
    };
    let icmp_len = echo.buffer_len();
    let ip = Ipv4Repr {
        src_addr: guest_ip,
        dst_addr: gw_ip,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_len,
        hop_limit: 64,
    };
    let frame = eth_frame(
        guest_mac,
        gw_mac,
        EthernetProtocol::Ipv4,
        ip.buffer_len() + icmp_len,
        |p| {
            let mut pkt = Ipv4Packet::new_unchecked(&mut *p);
            ip.emit(&mut pkt, &ChecksumCapabilities::default());
            let mut icmp = Icmpv4Packet::new_unchecked(pkt.payload_mut());
            echo.emit(&mut icmp, &ChecksumCapabilities::default());
        },
    );
    h.send_raw(&frame);

    // 3. The reply: an ICMP echo reply from the gateway with our ident/seq/data.
    let got = wait_for(&h, |frame| {
        let eth = EthernetFrame::new_checked(frame).ok()?;
        if eth.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }
        let ipp = Ipv4Packet::new_checked(eth.payload()).ok()?;
        if ipp.next_header() != IpProtocol::Icmp || ipp.src_addr() != gw_ip {
            return None;
        }
        let icmp = Icmpv4Packet::new_checked(ipp.payload()).ok()?;
        let rep = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::default()).ok()?;
        match rep {
            Icmpv4Repr::EchoReply {
                ident,
                seq_no,
                data,
            } if ident == 0xABCD && seq_no == 1 && data == b"dillo-ping" => Some(()),
            _ => None,
        }
    });
    assert!(got.is_some(), "gateway did not answer ICMP echo");
}

/// Build a DNS query for `name` with the given QTYPE (1=A, 28=AAAA), id 0x4869.
fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![
        0x48, 0x69, // id
        0x01, 0x00, // flags: RD
        0x00, 0x01, // qdcount = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar = 0
    ];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    q
}

/// Send a DNS query to the gateway DNS responder and return its reply (or `None`
/// if none arrives before the deadline). Drives the harness throughout.
fn dns_exchange(h: &mut Harness, query: &[u8]) -> Option<Vec<u8>> {
    let handle = h.sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16 * 1024]),
    ));
    h.sockets
        .get_mut::<udp::Socket<'_>>(handle)
        .bind(IpListenEndpoint {
            addr: None,
            port: 49200,
        })
        .unwrap();
    let server = IpEndpoint::new(DNS_IP, 53);
    let mut sent = false;
    let mut reply: Option<Vec<u8>> = None;
    h.run_until(|h| {
        let socket = h.sockets.get_mut::<udp::Socket<'_>>(handle);
        if !sent && socket.can_send() {
            socket.send_slice(query, server).unwrap();
            sent = true;
        }
        if socket.can_recv()
            && let Ok((payload, _)) = socket.recv()
        {
            reply = Some(payload.to_vec());
        }
        reply.is_some()
    });
    reply
}

/// The gateway DNS responder resolves an `A` query via the host resolver.
/// `localhost` is used so the test needs no network and is deterministic.
#[test]
fn dns_a_query_resolved() {
    let mut h = Harness::new(vec![]);
    let reply = dns_exchange(&mut h, &dns_query("localhost", 1)).expect("no DNS reply");
    assert!(reply.len() >= 12, "reply too short");
    assert_eq!(&reply[0..2], &[0x48, 0x69], "id echoed");
    assert_eq!(reply[2] & 0x80, 0x80, "QR set");
    assert_eq!(reply[3] & 0x0F, 0, "rcode NOERROR");
    let ancount = u16::from_be_bytes([reply[6], reply[7]]);
    assert!(
        ancount >= 1,
        "expected at least one A answer, got {ancount}"
    );
    // The final answer's rdata should be 127.0.0.1 (localhost resolves to it).
    assert_eq!(
        &reply[reply.len() - 4..],
        &[127, 0, 0, 1],
        "localhost A record should be 127.0.0.1"
    );
}

/// A name that cannot resolve yields NXDOMAIN with no answers. `.invalid` is
/// reserved by RFC 6761 to always fail, so this is offline-deterministic.
#[test]
fn dns_nxdomain() {
    let mut h = Harness::new(vec![]);
    let reply = dns_exchange(&mut h, &dns_query("nonexistent.invalid", 1)).expect("no DNS reply");
    assert_eq!(reply[3] & 0x0F, 3, "rcode should be NXDOMAIN");
    assert_eq!(
        u16::from_be_bytes([reply[6], reply[7]]),
        0,
        "NXDOMAIN must have no answers"
    );
}

/// An unsupported record type (MX=15) returns an empty NOERROR — the documented
/// scope limit (we synthesize only A/AAAA).
#[test]
fn dns_unsupported_qtype_is_empty_noerror() {
    let mut h = Harness::new(vec![]);
    let reply = dns_exchange(&mut h, &dns_query("localhost", 15)).expect("no DNS reply");
    assert_eq!(reply[3] & 0x0F, 0, "rcode NOERROR");
    assert_eq!(
        u16::from_be_bytes([reply[6], reply[7]]),
        0,
        "unsupported qtype must have no answers"
    );
}

/// DNS resolution runs off the stack thread, so a slow lookup must not stall
/// other flows. Drive a TCP echo round-trip *while* a DNS query is outstanding;
/// the TCP exchange must complete regardless of the resolver.
#[test]
fn dns_does_not_stall_other_flows() {
    let (port, server) = spawn_tcp_echo();
    let mut h = Harness::new(vec![]);

    // Fire a DNS query for a real name (may be slow / may fail — we don't care
    // about its result here, only that it doesn't block the TCP flow).
    let dns_handle = h.sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16 * 1024]),
    ));
    h.sockets
        .get_mut::<udp::Socket<'_>>(dns_handle)
        .bind(IpListenEndpoint {
            addr: None,
            port: 49201,
        })
        .unwrap();
    let query = dns_query("slow.example.com", 1);
    // Kick the query out in the first few steps.
    let mut dns_sent = false;
    for _ in 0..5 {
        h.step();
        let s = h.sockets.get_mut::<udp::Socket<'_>>(dns_handle);
        if !dns_sent && s.can_send() {
            s.send_slice(&query, IpEndpoint::new(DNS_IP, 53)).unwrap();
            dns_sent = true;
        }
    }

    // Now the TCP echo must still round-trip promptly.
    let tcp_handle = h.connect(IpEndpoint::new(ipv4(127, 0, 0, 1), port), 49202);
    let got = echo_exchange(&mut h, tcp_handle, b"not-stalled");
    assert_eq!(
        got, b"not-stalled",
        "TCP flow stalled behind DNS resolution"
    );
    drop(h);
    let _ = server.join();
}

/// Real-network: the gateway DNS responder resolves a public name through the
/// host's resolver. `#[ignore]`d (needs working DNS); manual repro:
///
/// ```text
/// cargo test -p dillo-virtio-net -- --ignored dns_resolves_real_name
/// ```
#[test]
#[ignore = "needs working host DNS; manual repro for the gateway DNS responder"]
fn dns_resolves_real_name() {
    let mut h = Harness::new(vec![]);
    let reply = dns_exchange(&mut h, &dns_query("example.com", 1)).expect("no DNS reply");
    assert_eq!(reply[3] & 0x0F, 0, "rcode NOERROR for a resolvable name");
    assert!(
        u16::from_be_bytes([reply[6], reply[7]]) >= 1,
        "expected at least one A record for example.com"
    );
}

/// Build a DHCP DISCOVER/REQUEST payload (BOOTP header + magic cookie + the
/// message-type option), as a guest client would send it.
fn dhcp_payload(msg_type: u8) -> Vec<u8> {
    let mut p = vec![0u8; 240]; // 236 header + 4 magic cookie
    p[0] = 1; // op = BOOTREQUEST
    p[1] = 1; // htype = Ethernet
    p[2] = 6; // hlen
    p[4..8].copy_from_slice(&[0xCA, 0xFE, 0xF0, 0x0D]); // xid
    p[10] = 0x80; // flags: broadcast
    p[28..34].copy_from_slice(&GUEST_MAC); // chaddr
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    p.extend_from_slice(&[53, 1, msg_type]); // option 53: message type
    p.push(255); // end
    p
}

/// Wrap a UDP payload from `0.0.0.0:68` to `255.255.255.255:67` in an
/// Ethernet+IPv4 broadcast frame (how a guest DHCP client emits a DISCOVER).
fn dhcp_broadcast_frame(payload: &[u8]) -> Vec<u8> {
    let src_ip = IpAddress::Ipv4(Ipv4Address::UNSPECIFIED);
    let dst_ip = IpAddress::Ipv4(Ipv4Address::BROADCAST);
    let udp = UdpRepr {
        src_port: 68,
        dst_port: 67,
    };
    let udp_len = udp.header_len() + payload.len();
    let ip = Ipv4Repr {
        src_addr: Ipv4Address::UNSPECIFIED,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    };
    eth_frame(
        EthernetAddress(GUEST_MAC),
        EthernetAddress([0xff; 6]),
        EthernetProtocol::Ipv4,
        ip.buffer_len() + udp_len,
        |buf| {
            let mut ipp = Ipv4Packet::new_unchecked(&mut *buf);
            ip.emit(&mut ipp, &ChecksumCapabilities::default());
            let mut udpp = UdpPacket::new_unchecked(ipp.payload_mut());
            udp.emit(
                &mut udpp,
                &src_ip,
                &dst_ip,
                payload.len(),
                |p| p.copy_from_slice(payload),
                &ChecksumCapabilities::default(),
            );
        },
    )
}

/// Parse a DHCP reply broadcast back to the guest, returning `(yiaddr, msg_type,
/// router, dns, mask)` if it is a well-formed BOOTREPLY for our client.
fn parse_dhcp_reply(frame: &[u8]) -> Option<([u8; 4], u8, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let ipp = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if ipp.next_header() != IpProtocol::Udp {
        return None;
    }
    let udpp = UdpPacket::new_checked(ipp.payload()).ok()?;
    if udpp.dst_port() != 68 || udpp.src_port() != 67 {
        return None;
    }
    let dhcp = udpp.payload();
    if dhcp.len() < 240 || dhcp[0] != 2 {
        return None; // not a BOOTREPLY
    }
    let yiaddr: [u8; 4] = dhcp[16..20].try_into().ok()?;
    // Walk options for type/router/dns/mask.
    let mut pos = 240;
    let (mut mt, mut router, mut dns, mut mask) = (0u8, Vec::new(), Vec::new(), Vec::new());
    while pos < dhcp.len() {
        let code = dhcp[pos];
        if code == 255 {
            break;
        }
        if code == 0 {
            pos += 1;
            continue;
        }
        let len = *dhcp.get(pos + 1)? as usize;
        let val = dhcp.get(pos + 2..pos + 2 + len)?;
        match code {
            53 => mt = val[0],
            3 => router = val.to_vec(),
            6 => dns = val.to_vec(),
            1 => mask = val.to_vec(),
            _ => {}
        }
        pos += 2 + len;
    }
    Some((yiaddr, mt, router, dns, mask))
}

/// The gateway DHCP responder answers a broadcast DISCOVER with an OFFER and a
/// REQUEST with an ACK, advertising the static lease (guest IP, router, DNS,
/// mask). This also de-risks the key unknown: that a smoltcp UDP socket bound to
/// `:67` actually receives the guest's broadcast.
#[test]
fn dhcp_discover_offers_and_request_acks() {
    let h = Harness::new(vec![]);

    // DISCOVER → OFFER.
    h.send_raw(&dhcp_broadcast_frame(&dhcp_payload(1)));
    let offer = wait_for(&h, parse_dhcp_reply).expect("no DHCP OFFER");
    let (yiaddr, mt, router, dns, mask) = offer;
    assert_eq!(mt, 2, "first reply should be OFFER");
    assert_eq!(yiaddr, [10, 0, 2, 15], "offered the guest IP");
    assert_eq!(router, vec![10, 0, 2, 2], "router is the gateway");
    assert_eq!(dns, vec![10, 0, 2, 3], "DNS is the gateway DNS alias");
    assert_eq!(mask, vec![255, 255, 255, 0], "/24 mask");

    // REQUEST → ACK.
    h.send_raw(&dhcp_broadcast_frame(&dhcp_payload(3)));
    let ack = wait_for(&h, |f| {
        let (_, mt, ..) = parse_dhcp_reply(f)?;
        // Skip any duplicate OFFERs still queued; we want the ACK.
        if mt == 5 { Some(mt) } else { None }
    });
    assert_eq!(ack, Some(5), "REQUEST should be ACKed");
}

/// guest → host redirect over IPv6: dialing the v6 gateway IP folds to `::1`,
/// reaching an in-process v6 echo server. This is the v6 analogue of
/// [`gateway_to_host_redirect`] and the in-process proof of the **v6 host-socket
/// datapath** (demux → v6 gateway fold → host v6 `TcpStream` → echo → back).
///
/// Note: the literal-masquerade case (guest dials an arbitrary external v6 like
/// `[::1]` directly) is *not* testable in-process — smoltcp special-cases IPv6
/// loopback on the guest side (`is_loopback()` in its v6 routing), so a guest
/// SYN to `::1` never leaves the guest stack. (IPv4 has no such special-case, so
/// `outbound_tcp_masquerade` can dial `127.0.0.1` directly.) The literal v6
/// masquerade path is covered by the `#[ignore]`d real-internet test
/// [`masquerade_holds_to_real_internet_v6`].
#[test]
fn gateway6_to_host_redirect() {
    let (port, server) = spawn_tcp_echo_on("[::1]:0");
    let mut h = Harness::new(vec![]);
    // Dial the v6 gateway on the host server's port; the proxy maps it to [::1].
    let handle = h.connect(IpEndpoint::new(super::GATEWAY_IP6, port), 49301);
    let got = echo_exchange(&mut h, handle, b"hello-v6-gateway");
    assert_eq!(got, b"hello-v6-gateway", "v6 gateway→host redirect failed");
    drop(h);
    let _ = server.join();
}

/// UDP outbound + reply over IPv6 through the gateway fold to host loopback.
#[test]
fn udp_outbound_and_reply_v6() {
    // Bind the UDP echo server on v6 loopback.
    let sock = UdpSocket::bind("[::1]:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let port = sock.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let deadline = StdInstant::now() + DEADLINE;
        while StdInstant::now() < deadline {
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&buf[..n], peer);
                break;
            }
        }
    });

    let mut h = Harness::new(vec![]);
    let handle = h.sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 64 * 1024]),
    ));
    h.sockets
        .get_mut::<udp::Socket<'_>>(handle)
        .bind(IpListenEndpoint {
            addr: None,
            port: 49302,
        })
        .unwrap();

    // Dial the v6 gateway (folds to [::1]) on the server's port.
    let dst = IpEndpoint::new(super::GATEWAY_IP6, port);
    let mut sent = false;
    let mut got: Vec<u8> = Vec::new();
    let ok = h.run_until(|h| {
        let socket = h.sockets.get_mut::<udp::Socket<'_>>(handle);
        if !sent && socket.can_send() {
            socket.send_slice(b"udp-v6-ping", dst).unwrap();
            sent = true;
        }
        if socket.can_recv()
            && let Ok((payload, _)) = socket.recv()
        {
            got = payload.to_vec();
        }
        got == b"udp-v6-ping"
    });
    assert!(
        ok,
        "v6 UDP echo via gateway did not round-trip: got {got:?}"
    );
    drop(h);
    let _ = server.join();
}

/// Real-network: the guest reaches the v6 internet through masquerade. Mirrors
/// `masquerade_holds_to_real_internet` but dials Cloudflare's v6 anycast on 443.
/// `#[ignore]`d (needs outbound v6); the Windows v6 cross-check.
///
/// ```text
/// cargo test -p dillo-virtio-net -- --ignored masquerade_holds_to_real_internet_v6
/// ```
#[test]
#[ignore = "needs outbound IPv6 on 443; manual repro for v6 masquerade-to-external"]
fn masquerade_holds_to_real_internet_v6() {
    // Cloudflare v6 anycast: 2606:4700:4700::1111.
    let mut h = Harness::new(vec![]);
    let dst = IpAddress::Ipv6(Ipv6Address::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    let handle = h.connect(IpEndpoint::new(dst, 443), 49303);

    let established = h.run_until(|h| h.tcp(handle).may_send());
    assert!(established, "guest never established with the proxy");

    let start = StdInstant::now();
    let mut closed = false;
    while start.elapsed() < Duration::from_secs(8) {
        h.step();
        if matches!(h.tcp(handle).state(), tcp::State::Closed) {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!closed, "v6 masquerade to a real external host was reset");
}

/// Zero-config IPv6: a guest Router Solicitation is answered with a Router
/// Advertisement that carries the ULA prefix with the SLAAC (ADDRCONF) flag and
/// a non-zero router lifetime, so a stock guest autoconfigures a v6 address and
/// default route with no static setup. smoltcp has no RA server, so this proves
/// the hand-rolled responder in the `ndp` module end to end through the backend.
#[test]
fn router_solicitation_gets_advertisement() {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::time::Duration as SmolDuration;
    use smoltcp::wire::{Icmpv6Packet, Icmpv6Repr, NdiscRepr, RawHardwareAddress};

    let h = Harness::new(vec![]);

    // Build a guest Router Solicitation (link-local source → all-routers).
    let src = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x15);
    let dst = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    let rs = Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit {
        lladdr: Some(RawHardwareAddress::from(EthernetAddress(GUEST_MAC))),
    });
    let ip = smoltcp::wire::Ipv6Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 255,
        payload_len: rs.buffer_len(),
    };
    let frame = eth_frame(
        EthernetAddress(GUEST_MAC),
        EthernetAddress([0x33, 0x33, 0, 0, 0, 2]),
        EthernetProtocol::Ipv6,
        ip.buffer_len() + rs.buffer_len(),
        |buf| {
            let mut ipp = smoltcp::wire::Ipv6Packet::new_unchecked(&mut *buf);
            ip.emit(&mut ipp);
            let mut icmp = Icmpv6Packet::new_unchecked(ipp.payload_mut());
            rs.emit(&src, &dst, &mut icmp, &ChecksumCapabilities::default());
        },
    );
    h.send_raw(&frame);

    // Expect a Router Advertisement back with our prefix + SLAAC flag.
    let got = wait_for(&h, |frame| {
        let eth = EthernetFrame::new_checked(frame).ok()?;
        if eth.ethertype() != EthernetProtocol::Ipv6 {
            return None;
        }
        let ipp = smoltcp::wire::Ipv6Packet::new_checked(eth.payload()).ok()?;
        if ipp.next_header() != IpProtocol::Icmpv6 {
            return None;
        }
        let icmp = Icmpv6Packet::new_checked(ipp.payload()).ok()?;
        let repr = Icmpv6Repr::parse(
            &ipp.src_addr(),
            &ipp.dst_addr(),
            &icmp,
            &ChecksumCapabilities::default(),
        )
        .ok()?;
        match repr {
            Icmpv6Repr::Ndisc(NdiscRepr::RouterAdvert {
                prefix_info: Some(pi),
                router_lifetime,
                ..
            }) if router_lifetime > SmolDuration::ZERO => Some(pi.prefix),
            _ => None,
        }
    });
    assert_eq!(
        got,
        Some(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)),
        "RA should advertise the ULA prefix for SLAAC"
    );
}
