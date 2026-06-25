// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! The user-mode stack thread: the single owner of the smoltcp [`Interface`],
//! the [`SocketSet`], the [`ProxyDevice`] queues, the mio [`Poll`], and every
//! per-flow host socket. Nothing else touches these, so no locking is needed
//! around them — the only cross-thread state is the two frame queues and the
//! stop flag, all behind their own synchronization.
//!
//! Each iteration: ingest guest frames (demuxing new flows into freshly
//! provisioned smoltcp sockets), drive smoltcp + the host sockets to quiescence,
//! reap finished flows, hand outbound frames to the guest, then block in
//! `mio::Poll` until a host socket is ready or the backend nudges the waker.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration as StdDuration;

use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token, Waker};
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress, IpEndpoint, IpListenEndpoint,
    IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};

use super::device::ProxyDevice;
use super::dhcp;
use super::dns::Resolver;
use super::forward::{Forward, ForwardListener, Proto};
use super::ndp;
use super::tcp::TcpFlow;
use super::udp::UdpFlow;
use super::{
    DNS_IP, DNS_IP6, FIRST_DYNAMIC_TOKEN, GATEWAY_IP, GATEWAY_IP6, GATEWAY_MAC, GUEST_IP, MTU,
    PREFIX6, SUBNET_PREFIX6, TCP_BUFFER, UDP_IDLE_TIMEOUT, UDP_META_SLOTS, UDP_PAYLOAD_BUFFER,
    build_interface, endpoint_to_socket_addr,
};

/// Host loopback, where gateway-destined (guest→host) connections are sent.
const HOST_LOOPBACK: IpAddress = IpAddress::v4(127, 0, 0, 1);
/// IPv6 host loopback (`::1`), for v6 gateway-destined connections.
const HOST_LOOPBACK6: IpAddress = IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1);
/// Longest the stack sleeps between wakeups, so it stays responsive to the stop
/// flag and to UDP idle reclamation even with no socket activity.
const MAX_POLL_WAIT: StdDuration = StdDuration::from_millis(100);
/// Bound on the inner drive loop so a busy flow can't starve the wait/stop check.
const MAX_DRIVE_ROUNDS: usize = 8;
/// Ephemeral local ports for stack-originated connections start here.
const EPHEMERAL_BASE: u16 = 49152;
/// Standard DNS port, where the gateway DNS responder listens.
const DNS_PORT: u16 = 53;

/// All state owned by the user-mode stack thread.
pub(super) struct Stack {
    poll: Poll,
    events: Events,
    device: ProxyDevice,
    iface: Interface,
    sockets: SocketSet<'static>,

    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound: Arc<(Mutex<VecDeque<Vec<u8>>>, Condvar)>,
    stop: Arc<AtomicBool>,

    /// Next mio token to hand out for a dynamically registered source.
    next_token: usize,
    /// Next ephemeral local port for a stack-originated connection.
    next_ephemeral: u16,

    /// Established/connecting outbound + inbound-forward TCP flows.
    tcp_flows: HashMap<SocketHandle, TcpFlow>,
    /// mio token → TCP flow handle, so a WRITABLE event can drive connect
    /// completion for the right flow (the cross-platform way to observe it).
    tcp_flow_tokens: HashMap<Token, SocketHandle>,
    /// Destinations with a smoltcp socket currently in `Listen` awaiting a SYN.
    tcp_listening: HashMap<(IpAddress, u16), SocketHandle>,
    /// Outbound UDP flows, keyed by guest destination `(ip, port)`.
    udp_flows: HashMap<(IpAddress, u16), (SocketHandle, UdpFlow)>,
    /// Local ports the stack uses for inbound UDP forwards toward the guest, so
    /// the guest's replies aren't mistaken for new outbound flows.
    forward_udp_local_ports: HashSet<u16>,
    /// Sockets to drop after the next poll flushes their final segment (RST/FIN).
    pending_removal: Vec<SocketHandle>,

    /// Bound, mio-registered inbound forward listeners.
    forwards: Vec<ForwardListener>,

    /// Off-thread DNS resolver for guest queries to the DNS alias.
    dns: Resolver,
    /// The smoltcp UDP socket bound to `DNS_IP:53` that receives guest queries.
    dns_socket: SocketHandle,
    /// The smoltcp UDP socket bound to `:67` that receives guest DHCP requests.
    dhcp_socket: SocketHandle,
}

impl Stack {
    /// Build the stack: the smoltcp interface over fresh queues, plus every
    /// inbound forward bound and registered with `poll`.
    pub(super) fn new(
        poll: Poll,
        waker: Arc<Waker>,
        forwards: Vec<Forward>,
        inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
        outbound: Arc<(Mutex<VecDeque<Vec<u8>>>, Condvar)>,
        stop: Arc<AtomicBool>,
    ) -> std::io::Result<Self> {
        let mut device = ProxyDevice::new();
        let iface = build_interface(&mut device);
        let mut sockets = SocketSet::new(Vec::new());

        // The gateway DNS responder: a smoltcp UDP socket on DNS_IP:53. set_any_ip
        // + DNS_IP in the interface's addresses route the guest's queries here.
        let dns = Resolver::new(waker);
        let mut dns_sock = make_udp_socket();
        dns_sock
            .bind(IpListenEndpoint {
                addr: Some(DNS_IP),
                port: DNS_PORT,
            })
            .map_err(|_| std::io::Error::other("failed to bind DNS responder socket"))?;
        let dns_socket = sockets.add(dns_sock);

        // The DHCP responder: a smoltcp UDP socket on :67 (any local address) so
        // it catches the guest's broadcast DISCOVER/REQUEST. Replies go back
        // broadcast (the client has no IP yet).
        let mut dhcp_sock = make_udp_socket();
        dhcp_sock
            .bind(IpListenEndpoint {
                addr: None,
                port: dhcp::SERVER_PORT,
            })
            .map_err(|_| std::io::Error::other("failed to bind DHCP responder socket"))?;
        let dhcp_socket = sockets.add(dhcp_sock);

        let mut next_token = FIRST_DYNAMIC_TOKEN;
        let mut bound = Vec::with_capacity(forwards.len());
        for f in forwards {
            let addr = SocketAddr::new(f.host_ip, f.host_port);
            let token = Token(next_token);
            next_token += 1;
            match f.proto {
                Proto::Tcp => {
                    let mut listener = TcpListener::bind(addr)?;
                    poll.registry()
                        .register(&mut listener, token, Interest::READABLE)?;
                    bound.push(ForwardListener::Tcp {
                        listener,
                        guest_port: f.guest_port,
                        token,
                    });
                }
                Proto::Udp => {
                    let mut sock = UdpSocket::bind(addr)?;
                    poll.registry()
                        .register(&mut sock, token, Interest::READABLE)?;
                    bound.push(ForwardListener::Udp {
                        sock,
                        guest_port: f.guest_port,
                        token,
                        outside: None,
                        guest_socket: None,
                    });
                }
            }
        }

        Ok(Self {
            poll,
            events: Events::with_capacity(256),
            device,
            iface,
            sockets,
            inbound,
            outbound,
            stop,
            next_token,
            next_ephemeral: EPHEMERAL_BASE,
            tcp_flows: HashMap::new(),
            tcp_flow_tokens: HashMap::new(),
            tcp_listening: HashMap::new(),
            udp_flows: HashMap::new(),
            forward_udp_local_ports: HashSet::new(),
            pending_removal: Vec::new(),
            forwards: bound,
            dns,
            dns_socket,
            dhcp_socket,
        })
    }

    /// Run until the stop flag is set (on backend drop).
    pub(super) fn run(mut self) {
        while !self.stop.load(Ordering::Acquire) {
            self.ingest_inbound();

            let mut rounds = 0;
            loop {
                let now = Instant::now();
                self.iface.poll(now, &mut self.device, &mut self.sockets);
                self.promote_listeners();
                self.accept_forwards();
                let mut worked = self.service_dns();
                worked |= self.service_dhcp();
                worked |= self.pump_all();
                // Flush any FIN/RST/ACK that pumping (close/abort) generated
                // before we reap the now-closed sockets.
                self.iface
                    .poll(Instant::now(), &mut self.device, &mut self.sockets);
                self.reap_closed();
                rounds += 1;
                if !worked || rounds >= MAX_DRIVE_ROUNDS {
                    break;
                }
            }

            self.reclaim_idle_udp();
            self.drain_to_guest();

            let now = Instant::now();
            let wait = mio_wait(self.iface.poll_delay(now, &self.sockets));
            let _ = self.poll.poll(&mut self.events, Some(wait));
            // Data readiness needs no routing — every source is serviced each
            // iteration. A WRITABLE event, though, is how a TCP flow's connect
            // completion is observed portably (Windows IOCP doesn't surface it
            // via peer_addr polling), so route those to the owning flow.
            let writable: Vec<Token> = self
                .events
                .iter()
                .filter(|e| e.is_writable())
                .map(mio::event::Event::token)
                .collect();
            for token in writable {
                if let Some(handle) = self.tcp_flow_tokens.get(&token).copied()
                    && let Some(flow) = self.tcp_flows.get_mut(&handle)
                {
                    flow.note_writable();
                }
            }
        }
    }

    // --- ingest + demux ----------------------------------------------------

    /// Move every queued guest frame into the smoltcp device, provisioning a
    /// listening/bound socket for any frame that opens a new flow.
    fn ingest_inbound(&mut self) {
        let frames: Vec<Vec<u8>> = {
            let mut q = self.inbound.lock().expect("user-net inbound poisoned");
            q.drain(..).collect()
        };
        for frame in frames {
            self.demux_and_push(frame);
        }
    }

    fn demux_and_push(&mut self, frame: Vec<u8>) {
        if let Some((proto, dst, dst_port, opens)) = inspect_frame(&frame) {
            match proto {
                IpProtocol::Tcp if opens => self.provision_tcp_listener(dst, dst_port),
                IpProtocol::Udp => self.provision_udp_flow(dst, dst_port),
                _ => {}
            }
        }
        // A guest Router Solicitation needs a Router Advertisement reply: smoltcp
        // has no RA server, so synthesize one (advertising the gateway + ULA
        // prefix) directly onto the guest-bound queue for SLAAC autoconfig.
        if let Some(rs) = ndp::parse_router_solicit(&frame) {
            let ra = ndp::build_router_advert(
                &rs,
                ipv6_of(GATEWAY_IP6),
                EthernetAddress(GATEWAY_MAC),
                ipv6_of(PREFIX6),
                SUBNET_PREFIX6,
                MTU as u32,
            );
            self.device.tx.push_back(ra);
        }
        // ARP, ICMP, established-flow segments, etc. are all handled by smoltcp.
        self.device.push_rx(frame);
    }

    fn provision_tcp_listener(&mut self, dst: IpAddress, port: u16) {
        let key = (dst, port);
        if self.tcp_listening.contains_key(&key) {
            return;
        }
        let mut sock = make_tcp_socket();
        let endpoint = IpListenEndpoint {
            addr: Some(dst),
            port,
        };
        if sock.listen(endpoint).is_ok() {
            let handle = self.sockets.add(sock);
            self.tcp_listening.insert(key, handle);
        }
    }

    /// Ensure a smoltcp UDP socket exists for the destination `(dst, port)`.
    /// One socket per destination is enough — smoltcp tags every received
    /// datagram with its guest source endpoint, so the per-source host-socket
    /// fan-out happens later in [`relay_udp_flows`](Self::relay_udp_flows).
    fn provision_udp_flow(&mut self, dst: IpAddress, port: u16) {
        let addr = dst;
        let key = (addr, port);
        if self.udp_flows.contains_key(&key) {
            return;
        }
        // A datagram to the gateway on a port we use for an inbound UDP forward
        // is a guest *reply*, not a new outbound flow — leave it for smoltcp.
        if addr == GATEWAY_IP && self.forward_udp_local_ports.contains(&port) {
            return;
        }
        // DNS queries to either gateway DNS alias are answered locally by the
        // DNS responder socket, not masqueraded.
        if (addr == DNS_IP || addr == DNS_IP6) && port == DNS_PORT {
            return;
        }
        let target = Self::host_target(IpEndpoint { addr, port });
        let mut sock = make_udp_socket();
        let endpoint = IpListenEndpoint {
            addr: Some(addr),
            port,
        };
        if sock.bind(endpoint).is_err() {
            return;
        }
        let handle = self.sockets.add(sock);
        self.udp_flows.insert(key, (handle, UdpFlow::new(target)));
    }

    // --- promotion + accept ------------------------------------------------

    /// A listening socket that has left `Listen` has accepted the guest's SYN.
    /// Open the matching host connection and turn it into a bridged flow.
    fn promote_listeners(&mut self) {
        let promoted: Vec<((IpAddress, u16), SocketHandle)> = self
            .tcp_listening
            .iter()
            .filter(|(_, h)| self.sockets.get::<tcp::Socket<'_>>(**h).state() != tcp::State::Listen)
            .map(|(k, h)| (*k, *h))
            .collect();

        for (key, handle) in promoted {
            self.tcp_listening.remove(&key);
            let local = self.sockets.get::<tcp::Socket<'_>>(handle).local_endpoint();
            let connected = local
                .map(Self::host_target)
                .and_then(|t| self.connect_host(t));
            if let Some((stream, token)) = connected {
                self.tcp_flow_tokens.insert(token, handle);
                self.tcp_flows.insert(handle, TcpFlow::new(stream, token));
            } else {
                // No host side → reset the guest (e.g. invalid destination).
                self.sockets.get_mut::<tcp::Socket<'_>>(handle).abort();
                self.pending_removal.push(handle);
            }
        }
    }

    /// Service inbound forwards: accept TCP connections / receive UDP datagrams
    /// from outside and originate the matching guest-side flow.
    fn accept_forwards(&mut self) {
        // Move the listeners out so we can freely call `&mut self` helpers while
        // iterating; they are owned values, so this just sidesteps the borrow.
        let mut forwards = std::mem::take(&mut self.forwards);
        for fl in &mut forwards {
            match fl {
                ForwardListener::Tcp {
                    listener,
                    guest_port,
                    ..
                } => self.accept_tcp_forward(listener, *guest_port),
                ForwardListener::Udp {
                    sock,
                    guest_port,
                    outside,
                    guest_socket,
                    ..
                } => self.relay_udp_forward(sock, *guest_port, outside, guest_socket),
            }
        }
        self.forwards = forwards;
    }

    fn accept_tcp_forward(&mut self, listener: &TcpListener, guest_port: u16) {
        loop {
            match listener.accept() {
                Ok((mut stream, _peer)) => {
                    let Some(handle) = self.originate_guest_tcp(guest_port) else {
                        continue;
                    };
                    let token = self.alloc_token();
                    if self
                        .poll
                        .registry()
                        .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
                        .is_err()
                    {
                        self.sockets.get_mut::<tcp::Socket<'_>>(handle).abort();
                        self.pending_removal.push(handle);
                        continue;
                    }
                    self.tcp_flow_tokens.insert(token, handle);
                    self.tcp_flows
                        .insert(handle, TcpFlow::new_connected(stream, token));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn relay_udp_forward(
        &mut self,
        sock: &UdpSocket,
        guest_port: u16,
        outside: &mut Option<SocketAddr>,
        guest_socket: &mut Option<SocketHandle>,
    ) {
        let mut buf = vec![0u8; 65_535];
        // Outside → guest.
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    *outside = Some(peer);
                    if guest_socket.is_none()
                        && let Some((handle, local_port)) = self.originate_guest_udp()
                    {
                        *guest_socket = Some(handle);
                        self.forward_udp_local_ports.insert(local_port);
                    }
                    if let Some(handle) = guest_socket {
                        let s = self.sockets.get_mut::<udp::Socket<'_>>(*handle);
                        let _ = s.send_slice(&buf[..n], IpEndpoint::new(GUEST_IP, guest_port));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        // Guest → outside (replies).
        if let (Some(handle), Some(peer)) = (*guest_socket, *outside) {
            let s = self.sockets.get_mut::<udp::Socket<'_>>(handle);
            while s.can_recv() {
                match s.recv() {
                    Ok((payload, _meta)) => {
                        let _ = sock.send_to(payload, peer);
                    }
                    Err(_) => break,
                }
            }
        }
    }

    // --- pumping + reaping -------------------------------------------------

    fn pump_all(&mut self) -> bool {
        let mut worked = false;
        let sockets = &mut self.sockets;
        for (handle, flow) in &mut self.tcp_flows {
            let socket = sockets.get_mut::<tcp::Socket<'_>>(*handle);
            worked |= flow.pump(socket);
        }
        worked |= self.relay_udp_flows();
        worked
    }

    /// Service the gateway DNS responder: hand any queued guest queries to the
    /// off-thread resolver, and send back any responses it has finished. Returns
    /// `true` if anything moved (so the drive loop keeps draining).
    fn service_dns(&mut self) -> bool {
        let mut worked = false;
        // Outbound: parse each queued query and submit it for resolution. The
        // parse (untrusted) stays on this thread; only the blocking lookup is
        // offloaded.
        loop {
            let socket = self.sockets.get_mut::<udp::Socket<'_>>(self.dns_socket);
            let Ok((payload, meta)) = socket.recv() else {
                break;
            };
            if let Some(query) = super::dns::parse_query(payload) {
                self.dns.submit(query, meta.endpoint);
            }
            worked = true;
        }
        // Inbound: send finished responses back to the querying guest endpoint.
        for result in self.dns.drain() {
            let socket = self.sockets.get_mut::<udp::Socket<'_>>(self.dns_socket);
            if socket.can_send() {
                let _ = socket.send_slice(&result.response, result.client);
                worked = true;
            }
        }
        worked
    }

    /// Service the gateway DHCP responder: answer a guest `DISCOVER` with an
    /// `OFFER` and a `REQUEST` with an `ACK`, handing out the one static lease.
    /// Replies are sent broadcast (the client has no address yet). Returns `true`
    /// if anything moved.
    fn service_dhcp(&mut self) -> bool {
        let mut worked = false;
        loop {
            let socket = self.sockets.get_mut::<udp::Socket<'_>>(self.dhcp_socket);
            let Ok((payload, _meta)) = socket.recv() else {
                break;
            };
            let Some(req) = dhcp::parse(payload) else {
                worked = true; // consumed a datagram even if we won't answer it
                continue;
            };
            let reply = dhcp::build_reply(
                &req,
                ipv4_of(GUEST_IP),
                ipv4_of(GATEWAY_IP),
                ipv4_of(DNS_IP),
                MTU as u16,
            );
            // Reply broadcast to the client port: the guest has no configured
            // address to receive a unicast reply on yet.
            let dst = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::BROADCAST), dhcp::CLIENT_PORT);
            let socket = self.sockets.get_mut::<udp::Socket<'_>>(self.dhcp_socket);
            if socket.can_send() {
                let _ = socket.send_slice(&reply, dst);
            }
            worked = true;
        }
        worked
    }

    /// Bridge every UDP destination both ways. Outbound: drain guest datagrams
    /// from each smoltcp socket, lazily creating one host socket per distinct
    /// guest source endpoint (so replies demux back to the right source), and
    /// forward. Inbound: drain each host source's replies onto the smoltcp
    /// socket addressed back to that guest source.
    fn relay_udp_flows(&mut self) -> bool {
        let mut worked = false;
        // Collect destination keys up front so we can take `&mut self` for the
        // per-source host-socket creation while iterating.
        let keys: Vec<(IpAddress, u16)> = self.udp_flows.keys().copied().collect();
        for key in keys {
            // Outbound: read each queued guest datagram, ensure its source has a
            // host socket, then send. Gather first to release the socket borrow
            // before touching `self.poll`/tokens.
            while let Some((handle, _)) = self.udp_flows.get(&key) {
                let handle = *handle;
                let socket = self.sockets.get_mut::<udp::Socket<'_>>(handle);
                let Ok((payload, meta)) = socket.recv() else {
                    break;
                };
                let payload = payload.to_vec();
                let src = meta.endpoint;
                self.ensure_udp_source(&key, src);
                if let Some((_, flow)) = self.udp_flows.get_mut(&key) {
                    flow.send_to_host(&src, &payload);
                }
                worked = true;
            }

            // Inbound: drain host replies onto the smoltcp socket, addressed to
            // the originating guest source.
            let Some((handle, flow)) = self.udp_flows.get_mut(&key) else {
                continue;
            };
            let handle = *handle;
            let socket = self.sockets.get_mut::<udp::Socket<'_>>(handle);
            let did = flow.drain_host(|guest_src, payload| {
                if socket.can_send() {
                    let _ = socket.send_slice(payload, guest_src);
                }
            });
            worked |= did;
        }
        worked
    }

    /// Lazily create the host socket for one guest source of a UDP destination:
    /// an ephemeral host UDP socket connected to the destination's target and
    /// registered for readiness. No-op if the source already has one.
    fn ensure_udp_source(&mut self, key: &(IpAddress, u16), src: IpEndpoint) {
        let Some((_, flow)) = self.udp_flows.get(key) else {
            return;
        };
        if flow.has_source(&src) {
            return;
        }
        let target = flow.target();
        let bind = if target.is_ipv4() {
            unspecified_v4()
        } else {
            unspecified_v6()
        };
        let Ok(mut host) = UdpSocket::bind(bind) else {
            return;
        };
        if host.connect(target).is_err() {
            return;
        }
        let token = self.alloc_token();
        if self
            .poll
            .registry()
            .register(&mut host, token, Interest::READABLE)
            .is_err()
        {
            return;
        }
        if let Some((_, flow)) = self.udp_flows.get_mut(key) {
            flow.add_source(src, host);
        }
    }

    fn reap_closed(&mut self) {
        let dead: Vec<SocketHandle> = self
            .tcp_flows
            .iter()
            .filter(|(h, _)| self.sockets.get::<tcp::Socket<'_>>(**h).state() == tcp::State::Closed)
            .map(|(h, _)| *h)
            .collect();
        for handle in dead {
            if let Some(mut flow) = self.tcp_flows.remove(&handle) {
                self.tcp_flow_tokens.remove(&flow.token);
                let _ = self.poll.registry().deregister(&mut flow.stream);
                self.sockets.remove(handle);
            }
        }
        for handle in std::mem::take(&mut self.pending_removal) {
            self.sockets.remove(handle);
        }
    }

    /// Reclaim idle UDP state at two granularities: first drop host sources
    /// (per guest source endpoint) that have gone quiet, then reap whole
    /// destinations once they are source-less and idle.
    fn reclaim_idle_udp(&mut self) {
        let now = std::time::Instant::now();

        // Per-source: deregister host sockets for guest sources gone idle.
        let keys: Vec<(IpAddress, u16)> = self.udp_flows.keys().copied().collect();
        for key in keys {
            if let Some((_, flow)) = self.udp_flows.get_mut(&key) {
                for mut src in flow.reap_idle_sources(now, UDP_IDLE_TIMEOUT) {
                    let _ = self.poll.registry().deregister(&mut src.sock);
                }
            }
        }

        // Per-destination: reap source-less, idle flows and their smoltcp socket.
        let expired: Vec<(IpAddress, u16)> = self
            .udp_flows
            .iter()
            .filter(|(_, (_, flow))| flow.is_reapable(now, UDP_IDLE_TIMEOUT))
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            if let Some((handle, _)) = self.udp_flows.remove(&key) {
                self.sockets.remove(handle);
            }
        }
    }

    // --- outbound to guest -------------------------------------------------

    fn drain_to_guest(&mut self) {
        if self.device.tx.is_empty() {
            return;
        }
        let (lock, cvar) = &*self.outbound;
        let mut q = lock.lock().expect("user-net outbound poisoned");
        q.extend(self.device.tx.drain(..));
        drop(q);
        cvar.notify_all();
    }

    // --- helpers -----------------------------------------------------------

    fn alloc_token(&mut self) -> Token {
        let token = Token(self.next_token);
        self.next_token += 1;
        token
    }

    fn alloc_ephemeral(&mut self) -> u16 {
        let port = self.next_ephemeral;
        self.next_ephemeral = self.next_ephemeral.checked_add(1).unwrap_or(EPHEMERAL_BASE);
        if self.next_ephemeral == 0 {
            self.next_ephemeral = EPHEMERAL_BASE;
        }
        port
    }

    /// Map a guest destination to its host-side target: a gateway IP folds to
    /// host loopback (guest→host) for its family; everything else is the literal
    /// destination (masquerade), for either family.
    fn host_target(dst: IpEndpoint) -> SocketAddr {
        let addr = if dst.addr == GATEWAY_IP {
            HOST_LOOPBACK
        } else if dst.addr == GATEWAY_IP6 {
            HOST_LOOPBACK6
        } else {
            dst.addr
        };
        endpoint_to_socket_addr(IpEndpoint {
            addr,
            port: dst.port,
        })
    }

    fn connect_host(&mut self, target: SocketAddr) -> Option<(TcpStream, Token)> {
        let mut stream = TcpStream::connect(target).ok()?;
        let token = self.alloc_token();
        self.poll
            .registry()
            .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
            .ok()?;
        Some((stream, token))
    }

    /// Originate a guest-side TCP connection (for an inbound forward): a smoltcp
    /// socket connecting from the gateway to `10.0.2.15:<guest_port>`.
    fn originate_guest_tcp(&mut self, guest_port: u16) -> Option<SocketHandle> {
        let mut sock = make_tcp_socket();
        let remote = IpEndpoint::new(GUEST_IP, guest_port);
        let local = IpListenEndpoint {
            addr: Some(GATEWAY_IP),
            port: self.alloc_ephemeral(),
        };
        sock.connect(self.iface.context(), remote, local).ok()?;
        Some(self.sockets.add(sock))
    }

    /// Originate a guest-side UDP socket (for an inbound forward), bound to a
    /// gateway-local ephemeral port. Returns the handle and that local port.
    fn originate_guest_udp(&mut self) -> Option<(SocketHandle, u16)> {
        let local_port = self.alloc_ephemeral();
        let mut sock = make_udp_socket();
        let endpoint = IpListenEndpoint {
            addr: Some(GATEWAY_IP),
            port: local_port,
        };
        sock.bind(endpoint).ok()?;
        Some((self.sockets.add(sock), local_port))
    }
}

/// Largest IPv6 extension-header chain we'll walk before giving up. A bound
/// against a hostile guest chaining headers to spin the parser.
const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Inspect a guest frame for flow-opening intent without consuming it.
///
/// Returns `(protocol, dst_ip, dst_port, opens_new_flow)` for IPv4/IPv6 TCP/UDP.
/// `opens_new_flow` is true only for a pure TCP SYN (so a guest SYN-ACK on an
/// inbound forward isn't mistaken for a new outbound listen). Malformed or
/// non-TCP/UDP frames return `None` and are simply forwarded to smoltcp.
///
/// This runs on fully guest-controlled bytes (the fuzzed surface): it must never
/// panic and never mis-classify a malformed frame as flow-opening.
fn inspect_frame(frame: &[u8]) -> Option<(IpProtocol, IpAddress, u16, bool)> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    match eth.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ip = Ipv4Packet::new_checked(eth.payload()).ok()?;
            inspect_l4(
                ip.next_header(),
                ip.payload(),
                IpAddress::Ipv4(ip.dst_addr()),
            )
        }
        EthernetProtocol::Ipv6 => {
            let ip = Ipv6Packet::new_checked(eth.payload()).ok()?;
            let dst = IpAddress::Ipv6(ip.dst_addr());
            // Walk past any extension headers to the L4 header.
            let (proto, l4) = ipv6_l4(ip.next_header(), ip.payload())?;
            inspect_l4(proto, l4, dst)
        }
        _ => None,
    }
}

/// Classify the L4 header (TCP/UDP) of an IP payload into a flow-opening tuple.
fn inspect_l4(
    proto: IpProtocol,
    l4: &[u8],
    dst: IpAddress,
) -> Option<(IpProtocol, IpAddress, u16, bool)> {
    match proto {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(l4).ok()?;
            let opens = tcp.syn() && !tcp.ack();
            Some((IpProtocol::Tcp, dst, tcp.dst_port(), opens))
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(l4).ok()?;
            Some((IpProtocol::Udp, dst, udp.dst_port(), false))
        }
        _ => None,
    }
}

/// Walk an IPv6 extension-header chain starting at `first` over `payload`,
/// returning the final L4 protocol and the slice at the start of its header.
/// Returns `None` on a malformed chain, an unknown header, or if the chain is
/// longer than [`MAX_IPV6_EXT_HEADERS`]. Bounds-checked and panic-free.
fn ipv6_l4(first: IpProtocol, payload: &[u8]) -> Option<(IpProtocol, &[u8])> {
    let mut proto = first;
    let mut rest = payload;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match proto {
            IpProtocol::Tcp | IpProtocol::Udp => return Some((proto, rest)),
            // These extension headers share the layout: next_header(1),
            // hdr_ext_len(1, in 8-octet units excluding the first 8), then data.
            IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                let next = *rest.first()?;
                let ext_len = *rest.get(1)? as usize;
                let total = 8 + ext_len * 8;
                rest = rest.get(total..)?;
                proto = IpProtocol::from(next);
            }
            // The fragment header is a fixed 8 bytes; next_header is the first.
            IpProtocol::Ipv6Frag => {
                let next = *rest.first()?;
                rest = rest.get(8..)?;
                proto = IpProtocol::from(next);
            }
            // Anything else (ICMPv6, no-next-header, unknown) is not a flow we
            // proxy — let smoltcp handle it.
            _ => return None,
        }
    }
    None
}

/// Fuzz entry point for the untrusted guest-frame demux/provisioning *decision*
/// path: run [`inspect_frame`] over arbitrary bytes. It must never panic and
/// must never mis-classify a malformed frame as flow-opening. Hidden from docs;
/// used by `dillo/fuzz` and the in-crate corpus test.
#[doc(hidden)]
pub fn fuzz_inspect_frame(frame: &[u8]) {
    let _ = inspect_frame(frame);
}

fn make_tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
    )
}

fn make_udp_socket() -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; UDP_PAYLOAD_BUFFER],
        ),
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; UDP_PAYLOAD_BUFFER],
        ),
    )
}

fn unspecified_v4() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

/// Extract the IPv4 address from one of the v4 addressing constants. The stack's
/// gateway/guest/DNS aliases are always v4; this is a convenience for the v4-only
/// DHCP responder.
fn ipv4_of(addr: IpAddress) -> Ipv4Address {
    match addr {
        IpAddress::Ipv4(a) => a,
        IpAddress::Ipv6(_) => Ipv4Address::UNSPECIFIED,
    }
}

/// Extract the IPv6 address from one of the v6 addressing constants.
fn ipv6_of(addr: IpAddress) -> Ipv6Address {
    match addr {
        IpAddress::Ipv6(a) => a,
        IpAddress::Ipv4(_) => Ipv6Address::UNSPECIFIED,
    }
}

fn unspecified_v6() -> SocketAddr {
    SocketAddr::from(([0u16; 8], 0))
}

/// smoltcp's optional `poll_delay`, clamped to [`MAX_POLL_WAIT`] so the loop
/// always wakes often enough to honor the stop flag and reclaim idle flows.
fn mio_wait(delay: Option<smoltcp::time::Duration>) -> StdDuration {
    match delay {
        Some(d) => StdDuration::from_micros(d.total_micros()).min(MAX_POLL_WAIT),
        None => MAX_POLL_WAIT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed Ethernet/IPv4/TCP **SYN** frame (the flow-opening case):
    /// 14 + 20 + 20 bytes, dst 127.0.0.1:80, SYN set / ACK clear.
    const TCP_SYN: &[u8] = &[
        // Ethernet: dst, src, ethertype=IPv4
        0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc, 0x08, 0x00,
        // IPv4: ver/ihl, tos, total_len=40, id, flags/frag, ttl, proto=6, csum=0, src, dst
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x02,
        0x0f, 0x7f, 0x00, 0x00, 0x01,
        // TCP: sport=12345, dport=80, seq, ack, off=5/flags=SYN, win, csum, urg
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    /// A well-formed Ethernet/IPv6/TCP **SYN** frame: 14 + 40 + 20 bytes, dst
    /// `::1`, SYN set / ACK clear, no extension headers.
    const TCP_SYN_V6: &[u8] = &[
        // Ethernet: dst, src, ethertype=IPv6 (0x86dd)
        0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc, 0x86, 0xdd,
        // IPv6: ver/tc/flow (4 bytes), payload_len=20, next_header=6 (TCP), hop_limit=64
        0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40, // src addr fd00::15
        0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x15, // dst addr ::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // TCP: sport=12345, dport=80, seq, ack, off=5/flags=SYN, win, csum, urg
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn inspect_recognizes_a_syn() {
        let (proto, dst, port, opens) = inspect_frame(TCP_SYN).expect("valid SYN frame");
        assert_eq!(proto, IpProtocol::Tcp);
        assert_eq!(dst, IpAddress::v4(127, 0, 0, 1));
        assert_eq!(port, 80);
        assert!(opens, "a pure SYN must be flow-opening");
    }

    #[test]
    fn inspect_recognizes_a_v6_syn() {
        let (proto, dst, port, opens) = inspect_frame(TCP_SYN_V6).expect("valid v6 SYN frame");
        assert_eq!(proto, IpProtocol::Tcp);
        assert_eq!(dst, IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(port, 80);
        assert!(opens, "a pure v6 SYN must be flow-opening");
    }

    #[test]
    fn inspect_never_panics_on_truncation() {
        // Every prefix of a valid frame must be handled without panicking; short
        // frames simply fail `new_checked` and return `None`. Both families.
        for len in 0..=TCP_SYN.len() {
            fuzz_inspect_frame(&TCP_SYN[..len]);
        }
        for len in 0..=TCP_SYN_V6.len() {
            fuzz_inspect_frame(&TCP_SYN_V6[..len]);
        }
    }

    #[test]
    fn inspect_never_panics_on_v6_ext_headers() {
        // A v6 frame whose next_header claims an extension header but whose body
        // is truncated/garbage must not panic or loop. Mutate the next_header
        // byte (offset 14 + 6) through every value and truncate at every length.
        let nh_off = 14 + 6;
        for nh in 0u8..=255 {
            let mut frame = TCP_SYN_V6.to_vec();
            frame[nh_off] = nh;
            for len in (nh_off + 1)..frame.len() {
                fuzz_inspect_frame(&frame[..len]);
            }
        }
    }

    #[test]
    fn inspect_never_panics_on_garbage() {
        // All-zeros, all-ones, and a sweep of single-byte values at many lengths.
        for len in 0..128usize {
            fuzz_inspect_frame(&vec![0u8; len]);
            fuzz_inspect_frame(&vec![0xffu8; len]);
            let ramp: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31) ^ len) as u8).collect();
            fuzz_inspect_frame(&ramp);
        }
    }

    #[test]
    fn syn_ack_is_not_flow_opening() {
        // Set the ACK bit (offset into TCP flags byte) so it is a SYN-ACK; an
        // inbound-forward guest reply must not be mistaken for a new listen.
        let mut frame = TCP_SYN.to_vec();
        let tcp_flags_off = 14 + 20 + 13; // eth + ip + tcp flags byte
        frame[tcp_flags_off] = 0x12; // SYN | ACK
        let (_, _, _, opens) = inspect_frame(&frame).expect("valid SYN-ACK");
        assert!(!opens, "a SYN-ACK must not be flow-opening");
    }
}
