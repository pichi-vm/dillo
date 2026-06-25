// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Portions derived from Firecracker (https://github.com/firecracker-microvm/firecracker),
// licensed under Apache-2.0 OR BSD-3-Clause. The connection state machine and
// credit-based flow control are adapted from Firecracker's vsock device.

//! Connection state machine for virtio-vsock.
//!
//! Manages per-stream connection state, credit-based flow control, and a
//! pluggable backend trait for routing vsock data (echo, UDS, etc.).

use std::collections::{HashMap, VecDeque};

use crate::packet::{
    VSOCK_FLAGS_SHUTDOWN_RCV, VSOCK_FLAGS_SHUTDOWN_SEND, VSOCK_HOST_CID, VSOCK_OP_CREDIT_REQUEST,
    VSOCK_OP_CREDIT_UPDATE, VSOCK_OP_REQUEST, VSOCK_OP_RESPONSE, VSOCK_OP_RST, VSOCK_OP_RW,
    VSOCK_OP_SHUTDOWN, VsockPacket,
};

/// Connection lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnState {
    /// Connection established, data can flow in both directions.
    Established,
    /// Peer requested receive shutdown.
    ShutdownRcv,
    /// Peer requested send shutdown.
    ShutdownSend,
    /// Both directions shut down, awaiting RST.
    ShutdownBoth,
    /// Connection fully closed.
    Closed,
}

/// Pluggable backend for vsock data routing.
///
/// Implementations decide what happens when the guest initiates connections
/// and sends data. The default `EchoBackend` reflects data back; `UdsBackend`
/// bridges to Unix domain sockets on the host.
pub(crate) trait VsockBackend: Send + Sync {
    /// Called when guest initiates a connection to host port.
    /// Return true to accept, false to reject (RST sent).
    fn on_connection_request(&mut self, local_port: u32, peer_port: u32) -> bool;

    /// Called when data arrives from guest on an established connection.
    fn on_data_received(&mut self, local_port: u32, peer_port: u32, data: &[u8]);

    /// Called when connection is closed/reset.
    fn on_connection_closed(&mut self, local_port: u32, peer_port: u32);

    /// Poll for data available to send to guest. Returns data for a specific connection.
    /// Returns None if no data available from any connection.
    fn poll_data(&mut self) -> Option<(u32, u32, Vec<u8>)>;

    /// Check if any data is available without consuming it.
    fn has_data(&self) -> bool;
}

/// A single vsock stream connection.
pub(crate) struct Connection {
    /// Local (host-side) port number.
    pub(crate) local_port: u32,
    /// Remote (guest-side) port number.
    pub(crate) peer_port: u32,
    /// Guest CID for addressing reply packets.
    pub(crate) guest_cid: u64,
    /// Current connection lifecycle state.
    pub(crate) state: ConnState,

    // Our credit state (host side).
    /// Buffer space we advertise to the peer.
    pub(crate) buf_alloc: u32,
    /// Bytes we have consumed from the peer (advanced when we receive data).
    pub(crate) fwd_cnt: u32,
    /// Last fwd_cnt value we sent to the peer.
    pub(crate) last_fwd_cnt_to_peer: u32,

    // Peer's credit state.
    /// Peer's advertised buffer allocation.
    pub(crate) peer_buf_alloc: u32,
    /// Peer's last reported fwd_cnt.
    pub(crate) peer_fwd_cnt: u32,
    /// Bytes we have sent to the peer.
    pub(crate) rx_cnt: u32,

    /// Outgoing control/data packets to write to the rx queue.
    pub(crate) pending_tx: VecDeque<VsockPacket>,
}

impl Connection {
    /// Create a new connection in the Established state.
    pub(crate) fn new(local_port: u32, peer_port: u32, guest_cid: u64) -> Self {
        Self {
            local_port,
            peer_port,
            guest_cid,
            state: ConnState::Established,
            buf_alloc: 65536,
            fwd_cnt: 0,
            last_fwd_cnt_to_peer: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
            rx_cnt: 0,
            pending_tx: VecDeque::new(),
        }
    }

    /// Process an incoming packet from the guest (non-REQUEST ops).
    pub(crate) fn recv_pkt(&mut self, pkt: &VsockPacket, backend: &mut dyn VsockBackend) {
        match pkt.op {
            VSOCK_OP_RW => {
                // Update peer credit info.
                self.peer_buf_alloc = pkt.buf_alloc;
                self.peer_fwd_cnt = pkt.fwd_cnt;

                // Advance our fwd_cnt by the amount of data received.
                self.fwd_cnt = self.fwd_cnt.wrapping_add(pkt.data.len() as u32);

                // Route data through backend.
                backend.on_data_received(self.local_port, self.peer_port, &pkt.data);

                // Send proactive credit update if threshold reached.
                if self.needs_credit_update() {
                    self.enqueue_credit_update();
                }
            }
            VSOCK_OP_SHUTDOWN => {
                let flags = pkt.flags;
                let rcv = flags & VSOCK_FLAGS_SHUTDOWN_RCV != 0;
                let send = flags & VSOCK_FLAGS_SHUTDOWN_SEND != 0;

                self.state = match (rcv, send, self.state) {
                    (true, true, _)
                    | (true, _, ConnState::ShutdownSend)
                    | (_, true, ConnState::ShutdownRcv) => {
                        // Both directions shut down. Transition to ShutdownBoth
                        // so pending backend data can still be delivered. RST is
                        // sent later when produce_rx_pkt finds no more data.
                        ConnState::ShutdownBoth
                    }
                    (true, false, ConnState::Established) => ConnState::ShutdownRcv,
                    (false, true, ConnState::Established) => ConnState::ShutdownSend,
                    _ => ConnState::ShutdownBoth,
                };
            }
            VSOCK_OP_CREDIT_UPDATE => {
                self.peer_buf_alloc = pkt.buf_alloc;
                self.peer_fwd_cnt = pkt.fwd_cnt;
            }
            VSOCK_OP_CREDIT_REQUEST => {
                self.enqueue_credit_update();
            }
            _ => {
                log::warn!(
                    "vsock: unexpected op {} on connection {}:{}",
                    pkt.op,
                    self.local_port,
                    self.peer_port
                );
            }
        }
    }

    /// Produce the next outgoing control packet.
    pub(crate) fn produce_tx(&mut self) -> Option<VsockPacket> {
        self.pending_tx.pop_front()
    }

    /// Available credit at the peer (how many bytes we can send).
    pub(crate) fn peer_avail_credit(&self) -> u32 {
        self.peer_buf_alloc
            .wrapping_sub(self.rx_cnt.wrapping_sub(self.peer_fwd_cnt))
    }

    /// Whether we should send a proactive credit update (threshold: 4096 bytes).
    pub(crate) fn needs_credit_update(&self) -> bool {
        self.fwd_cnt.wrapping_sub(self.last_fwd_cnt_to_peer) >= 4096
    }

    fn enqueue_credit_update(&mut self) {
        let mut pkt = VsockPacket::new_reply(
            VSOCK_OP_CREDIT_UPDATE,
            VSOCK_HOST_CID,
            self.guest_cid,
            self.local_port,
            self.peer_port,
        );
        pkt.buf_alloc = self.buf_alloc;
        pkt.fwd_cnt = self.fwd_cnt;
        self.last_fwd_cnt_to_peer = self.fwd_cnt;
        self.pending_tx.push_back(pkt);
    }
}

/// Manages all active vsock connections, routing packets by port pair.
pub(crate) struct ConnectionManager {
    /// Guest CID used for addressing reply packets.
    pub(crate) guest_cid: u64,
    connections: HashMap<(u32, u32), Connection>,
    backend: Box<dyn VsockBackend>,
}

impl ConnectionManager {
    /// Create a new connection manager with the given guest CID and backend.
    // Only reached via `VirtioVsock::new_with_backend`, whose lone non-test
    // caller is unix-gated; on non-unix this is test-only.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn new(guest_cid: u64, backend: Box<dyn VsockBackend>) -> Self {
        Self {
            guest_cid,
            connections: HashMap::new(),
            backend,
        }
    }

    /// Process a packet from the guest (tx queue direction).
    pub(crate) fn process_tx_pkt(&mut self, pkt: VsockPacket) {
        match pkt.op {
            VSOCK_OP_REQUEST => {
                let local_port = pkt.dst_port;
                let peer_port = pkt.src_port;
                let key = (local_port, peer_port);

                // Ask backend if it accepts this connection.
                if self.backend.on_connection_request(local_port, peer_port) {
                    let mut conn = Connection::new(local_port, peer_port, self.guest_cid);
                    conn.peer_buf_alloc = pkt.buf_alloc;
                    conn.peer_fwd_cnt = pkt.fwd_cnt;

                    // Send RESPONSE to accept the connection.
                    let mut resp = VsockPacket::new_reply(
                        VSOCK_OP_RESPONSE,
                        VSOCK_HOST_CID,
                        self.guest_cid,
                        local_port,
                        peer_port,
                    );
                    resp.buf_alloc = conn.buf_alloc;
                    resp.fwd_cnt = conn.fwd_cnt;
                    conn.pending_tx.push_back(resp);

                    self.connections.insert(key, conn);
                } else {
                    // Backend rejected -- send RST.
                    let mut conn = Connection::new(local_port, peer_port, self.guest_cid);
                    conn.peer_buf_alloc = pkt.buf_alloc;
                    conn.peer_fwd_cnt = pkt.fwd_cnt;

                    let rst = VsockPacket::new_reply(
                        VSOCK_OP_RST,
                        VSOCK_HOST_CID,
                        self.guest_cid,
                        local_port,
                        peer_port,
                    );
                    conn.pending_tx.push_back(rst);
                    conn.state = ConnState::Closed;
                    self.connections.insert(key, conn);
                }
            }
            VSOCK_OP_RST => {
                let key = (pkt.dst_port, pkt.src_port);
                if self.connections.remove(&key).is_some() {
                    self.backend
                        .on_connection_closed(pkt.dst_port, pkt.src_port);
                }
            }
            VSOCK_OP_RW | VSOCK_OP_SHUTDOWN | VSOCK_OP_CREDIT_UPDATE | VSOCK_OP_CREDIT_REQUEST => {
                let key = (pkt.dst_port, pkt.src_port);
                if let Some(conn) = self.connections.get_mut(&key) {
                    conn.recv_pkt(&pkt, &mut *self.backend);
                }
                // Silently drop if no connection found.
            }
            _ => {
                log::warn!("vsock: dropping packet with unknown op {}", pkt.op);
            }
        }
    }

    /// Produce the next packet to send to the guest (rx queue direction).
    ///
    /// Polls the backend for data first (so echo/UDS responses arrive before
    /// control packets like RST), then drains pending control packets.
    pub(crate) fn produce_rx_pkt(&mut self) -> Option<VsockPacket> {
        // First: poll backend for data from external sources (echo buffer, UDS, etc.).
        // This must happen before draining control packets so that echo data
        // arrives before RST when the guest sends RW + SHUTDOWN in one batch.
        if let Some((local_port, peer_port, data)) = self.backend.poll_data() {
            let key = (local_port, peer_port);
            if let Some(conn) = self.connections.get_mut(&key)
                && !data.is_empty()
            {
                let credit = conn.peer_avail_credit() as usize;
                if credit > 0 {
                    let to_send = std::cmp::min(data.len(), credit);
                    conn.rx_cnt = conn.rx_cnt.wrapping_add(to_send as u32);

                    let mut pkt = VsockPacket::new_reply(
                        VSOCK_OP_RW,
                        VSOCK_HOST_CID,
                        conn.guest_cid,
                        local_port,
                        peer_port,
                    );
                    pkt.buf_alloc = conn.buf_alloc;
                    pkt.fwd_cnt = conn.fwd_cnt;
                    pkt.len = to_send as u32;
                    pkt.data = data[..to_send].to_vec();
                    return Some(pkt);
                }
            }
        }

        // Second: drain pending control packets from connections.
        // Also finalize ShutdownBoth connections (send RST now that data is drained).
        let mut closed_keys = Vec::new();
        let mut result = None;

        for (&key, conn) in &mut self.connections {
            // ShutdownBoth with no pending packets: backend data is drained,
            // send SHUTDOWN (clean close) to complete the teardown. Using
            // SHUTDOWN instead of RST avoids ECONNRESET which discards data.
            if conn.state == ConnState::ShutdownBoth && conn.pending_tx.is_empty() {
                let mut pkt = VsockPacket::new_reply(
                    VSOCK_OP_SHUTDOWN,
                    VSOCK_HOST_CID,
                    conn.guest_cid,
                    conn.local_port,
                    conn.peer_port,
                );
                pkt.flags = VSOCK_FLAGS_SHUTDOWN_RCV | VSOCK_FLAGS_SHUTDOWN_SEND;
                conn.pending_tx.push_back(pkt);
                self.backend
                    .on_connection_closed(conn.local_port, conn.peer_port);
                conn.state = ConnState::Closed;
            }

            if let Some(pkt) = conn.produce_tx() {
                result = Some(pkt);
                if conn.state == ConnState::Closed && conn.pending_tx.is_empty() {
                    closed_keys.push(key);
                }
                break;
            }
            if conn.state == ConnState::Closed && conn.pending_tx.is_empty() {
                closed_keys.push(key);
            }
        }

        for key in closed_keys {
            self.connections.remove(&key);
        }

        result
    }

    /// Check if there are pending packets to send to the guest.
    ///
    /// This is a lightweight check used by process_rx to avoid popping
    /// descriptors from the avail ring when there's nothing to write.
    pub(crate) fn has_pending_rx(&self) -> bool {
        if self.backend.has_data() {
            return true;
        }

        self.connections
            .values()
            .any(|c| !c.pending_tx.is_empty() || c.state == ConnState::ShutdownBoth)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Echo backend: reflects received data back on the same stream.
    ///
    /// Test-only backend used to exercise ConnectionManager without a real UDS backend.
    struct EchoBackend {
        buffers: HashMap<(u32, u32), VecDeque<u8>>,
    }

    impl EchoBackend {
        fn new() -> Self {
            Self {
                buffers: HashMap::new(),
            }
        }
    }

    impl VsockBackend for EchoBackend {
        fn on_connection_request(&mut self, local_port: u32, peer_port: u32) -> bool {
            self.buffers
                .insert((local_port, peer_port), VecDeque::new());
            true
        }

        fn on_data_received(&mut self, local_port: u32, peer_port: u32, data: &[u8]) {
            if let Some(buf) = self.buffers.get_mut(&(local_port, peer_port)) {
                buf.extend(data);
            }
        }

        fn on_connection_closed(&mut self, _local_port: u32, _peer_port: u32) {
            // Don't remove the buffer here — poll_data needs to drain any pending
            // echo data first. Empty buffers are cleaned up in poll_data.
        }

        fn poll_data(&mut self) -> Option<(u32, u32, Vec<u8>)> {
            for (&(local_port, peer_port), buf) in &mut self.buffers {
                if !buf.is_empty() {
                    let data: Vec<u8> = buf.drain(..).collect();
                    return Some((local_port, peer_port, data));
                }
            }
            None
        }

        fn has_data(&self) -> bool {
            self.buffers.values().any(|buf| !buf.is_empty())
        }
    }

    impl ConnectionManager {
        /// Create a new connection manager with the default echo backend (test helper).
        fn new_echo(guest_cid: u64) -> Self {
            Self::new(guest_cid, Box::new(EchoBackend::new()))
        }

        /// Number of active connections (test helper).
        fn connection_count(&self) -> usize {
            self.connections.len()
        }
    }

    fn make_request_pkt(guest_cid: u64, src_port: u32, dst_port: u32) -> VsockPacket {
        let mut pkt = VsockPacket::new_reply(
            VSOCK_OP_REQUEST,
            guest_cid,
            VSOCK_HOST_CID,
            src_port,
            dst_port,
        );
        pkt.buf_alloc = 65536;
        pkt.fwd_cnt = 0;
        pkt
    }

    // --- EchoBackend tests ---

    #[test]
    fn echo_backend_echoes_data_back() {
        let mut backend = EchoBackend::new();
        assert!(backend.on_connection_request(5678, 1234));
        backend.on_data_received(5678, 1234, b"hello");

        let result = backend.poll_data();
        assert!(result.is_some());
        let (lp, pp, data) = result.unwrap();
        assert_eq!(lp, 5678);
        assert_eq!(pp, 1234);
        assert_eq!(data, b"hello");

        // After draining, no more data.
        assert!(backend.poll_data().is_none());
    }

    // --- Connection tests ---

    #[test]
    fn connection_request_response() {
        let mut mgr = ConnectionManager::new_echo(3);
        let pkt = make_request_pkt(3, 1234, 5678);
        mgr.process_tx_pkt(pkt);

        // Should have one connection now.
        assert_eq!(mgr.connection_count(), 1);

        // Should produce a RESPONSE packet.
        let resp = mgr.produce_rx_pkt().unwrap();
        assert_eq!(resp.op, VSOCK_OP_RESPONSE);
        assert_eq!(resp.src_cid, VSOCK_HOST_CID);
        assert_eq!(resp.dst_cid, 3);
        assert_eq!(resp.src_port, 5678);
        assert_eq!(resp.dst_port, 1234);
    }

    #[test]
    fn connection_echo_data() {
        let mut mgr = ConnectionManager::new_echo(3);
        // Establish connection.
        mgr.process_tx_pkt(make_request_pkt(3, 1234, 5678));
        // Drain RESPONSE.
        let _ = mgr.produce_rx_pkt().unwrap();

        // Send data.
        let mut data_pkt = VsockPacket::new_reply(VSOCK_OP_RW, 3, VSOCK_HOST_CID, 1234, 5678);
        data_pkt.buf_alloc = 65536;
        data_pkt.fwd_cnt = 0;
        data_pkt.data = b"echo me".to_vec();
        data_pkt.len = data_pkt.data.len() as u32;
        mgr.process_tx_pkt(data_pkt);

        // Should produce an echo RW packet.
        let echo = mgr.produce_rx_pkt().unwrap();
        assert_eq!(echo.op, VSOCK_OP_RW);
        assert_eq!(echo.data, b"echo me");
        assert_eq!(echo.src_port, 5678);
        assert_eq!(echo.dst_port, 1234);
    }

    #[test]
    fn connection_echo_data_after_guest_shutdown_send() {
        let mut mgr = ConnectionManager::new_echo(3);
        // Establish connection.
        mgr.process_tx_pkt(make_request_pkt(3, 1234, 5678));
        // Drain RESPONSE.
        let _ = mgr.produce_rx_pkt().unwrap();

        // Send data.
        let mut data_pkt = VsockPacket::new_reply(VSOCK_OP_RW, 3, VSOCK_HOST_CID, 1234, 5678);
        data_pkt.buf_alloc = 65536;
        data_pkt.fwd_cnt = 0;
        data_pkt.data = b"echo me".to_vec();
        data_pkt.len = data_pkt.data.len() as u32;
        mgr.process_tx_pkt(data_pkt);

        // Guest shuts down SEND direction (half-close: guest done writing,
        // but host should still be able to send data back).
        let mut shutdown = VsockPacket::new_reply(VSOCK_OP_SHUTDOWN, 3, VSOCK_HOST_CID, 1234, 5678);
        shutdown.flags = VSOCK_FLAGS_SHUTDOWN_SEND;
        mgr.process_tx_pkt(shutdown);

        // Should still produce the echo RW packet despite ShutdownSend state.
        let echo = mgr.produce_rx_pkt().unwrap();
        assert_eq!(echo.op, VSOCK_OP_RW);
        assert_eq!(echo.data, b"echo me");
        assert_eq!(echo.src_port, 5678);
        assert_eq!(echo.dst_port, 1234);
    }

    #[test]
    fn credit_flow_peer_avail_credit() {
        let mut conn = Connection::new(5678, 1234, 3);
        conn.peer_buf_alloc = 1000;
        conn.peer_fwd_cnt = 0;
        conn.rx_cnt = 0;

        // Full credit available.
        assert_eq!(conn.peer_avail_credit(), 1000);

        // After sending 300 bytes.
        conn.rx_cnt = 300;
        assert_eq!(conn.peer_avail_credit(), 700);

        // After peer reports consuming 200 bytes.
        conn.peer_fwd_cnt = 200;
        // peer_buf_alloc - (rx_cnt - peer_fwd_cnt) = 1000 - (300 - 200) = 900
        assert_eq!(conn.peer_avail_credit(), 900);
    }

    #[test]
    fn credit_update_sent_when_threshold_reached() {
        let mut conn = Connection::new(5678, 1234, 3);
        conn.peer_buf_alloc = 65536;
        conn.peer_fwd_cnt = 0;

        // Receive 4096 bytes of data to cross the threshold.
        let mut pkt = VsockPacket::new_reply(VSOCK_OP_RW, 3, VSOCK_HOST_CID, 1234, 5678);
        pkt.buf_alloc = 65536;
        pkt.data = vec![0u8; 4096];
        pkt.len = 4096;

        let mut backend = EchoBackend::new();
        backend.on_connection_request(5678, 1234);
        conn.recv_pkt(&pkt, &mut backend);

        // Should have a CREDIT_UPDATE in pending_tx.
        assert!(
            conn.pending_tx
                .iter()
                .any(|p| p.op == VSOCK_OP_CREDIT_UPDATE)
        );
        // fwd_cnt should be 4096.
        assert_eq!(conn.fwd_cnt, 4096);
    }

    #[test]
    fn connection_shutdown_closes_connection() {
        let mut mgr = ConnectionManager::new_echo(3);
        mgr.process_tx_pkt(make_request_pkt(3, 1234, 5678));
        let _ = mgr.produce_rx_pkt(); // drain RESPONSE

        // Send SHUTDOWN with both flags.
        let mut shutdown = VsockPacket::new_reply(VSOCK_OP_SHUTDOWN, 3, VSOCK_HOST_CID, 1234, 5678);
        shutdown.flags = VSOCK_FLAGS_SHUTDOWN_RCV | VSOCK_FLAGS_SHUTDOWN_SEND;
        mgr.process_tx_pkt(shutdown);

        // Should produce SHUTDOWN (clean close, not RST which causes ECONNRESET).
        let close = mgr.produce_rx_pkt().unwrap();
        assert_eq!(close.op, VSOCK_OP_SHUTDOWN);

        // Connection should be removed after draining.
        assert!(mgr.produce_rx_pkt().is_none());
        assert_eq!(mgr.connection_count(), 0);
    }

    #[test]
    fn connection_manager_routes_by_port_key() {
        let mut mgr = ConnectionManager::new_echo(3);

        // Two connections on different port pairs.
        mgr.process_tx_pkt(make_request_pkt(3, 1000, 2000));
        mgr.process_tx_pkt(make_request_pkt(3, 3000, 4000));

        assert_eq!(mgr.connection_count(), 2);

        // Drain both RESPONSE packets.
        let _ = mgr.produce_rx_pkt().unwrap();
        let _ = mgr.produce_rx_pkt().unwrap();

        // Send data on first connection only.
        let mut data_pkt = VsockPacket::new_reply(VSOCK_OP_RW, 3, VSOCK_HOST_CID, 1000, 2000);
        data_pkt.buf_alloc = 65536;
        data_pkt.data = b"conn1".to_vec();
        data_pkt.len = 5;
        mgr.process_tx_pkt(data_pkt);

        let echo = mgr.produce_rx_pkt().unwrap();
        assert_eq!(echo.data, b"conn1");
        assert_eq!(echo.src_port, 2000);
        assert_eq!(echo.dst_port, 1000);
    }

    #[test]
    fn echo_data_delivered_before_close_on_shutdown_both() {
        let mut mgr = ConnectionManager::new_echo(3);
        mgr.process_tx_pkt(make_request_pkt(3, 1234, 5678));
        let _ = mgr.produce_rx_pkt(); // drain RESPONSE

        // Send data + SHUTDOWN(both) in the same TX batch (mimics guest behavior).
        let mut data_pkt = VsockPacket::new_reply(VSOCK_OP_RW, 3, VSOCK_HOST_CID, 1234, 5678);
        data_pkt.buf_alloc = 65536;
        data_pkt.fwd_cnt = 0;
        data_pkt.data = b"echo me".to_vec();
        data_pkt.len = data_pkt.data.len() as u32;
        mgr.process_tx_pkt(data_pkt);

        let mut shutdown = VsockPacket::new_reply(VSOCK_OP_SHUTDOWN, 3, VSOCK_HOST_CID, 1234, 5678);
        shutdown.flags = VSOCK_FLAGS_SHUTDOWN_RCV | VSOCK_FLAGS_SHUTDOWN_SEND;
        mgr.process_tx_pkt(shutdown);

        // Echo data arrives first (backend polled before control packets).
        let echo = mgr.produce_rx_pkt().unwrap();
        assert_eq!(echo.op, VSOCK_OP_RW);
        assert_eq!(echo.data, b"echo me");

        // Then the close signal is delivered.
        let close = mgr.produce_rx_pkt().unwrap();
        assert_eq!(close.op, VSOCK_OP_SHUTDOWN);

        // Connection cleaned up.
        assert!(mgr.produce_rx_pkt().is_none());
        assert_eq!(mgr.connection_count(), 0);
    }

    // --- Backend rejection tests ---

    #[test]
    fn connection_manager_sends_rst_when_backend_rejects() {
        /// A backend that rejects all connections.
        struct RejectBackend;
        impl VsockBackend for RejectBackend {
            fn on_connection_request(&mut self, _: u32, _: u32) -> bool {
                false
            }
            fn on_data_received(&mut self, _: u32, _: u32, _: &[u8]) {}
            fn on_connection_closed(&mut self, _: u32, _: u32) {}
            fn poll_data(&mut self) -> Option<(u32, u32, Vec<u8>)> {
                None
            }
            fn has_data(&self) -> bool {
                false
            }
        }

        let mut mgr = ConnectionManager::new(3, Box::new(RejectBackend));
        mgr.process_tx_pkt(make_request_pkt(3, 1234, 5678));

        // Should produce RST (not RESPONSE).
        let pkt = mgr.produce_rx_pkt().unwrap();
        assert_eq!(pkt.op, VSOCK_OP_RST);
        assert_eq!(pkt.src_port, 5678);
        assert_eq!(pkt.dst_port, 1234);

        // Connection should be cleaned up after RST drained.
        assert!(mgr.produce_rx_pkt().is_none());
        assert_eq!(mgr.connection_count(), 0);
    }
}
