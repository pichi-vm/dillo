// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! One proxied TCP flow: a smoltcp TCP socket (the guest-facing half) bridged
//! to a [`mio::net::TcpStream`] (the host-facing half).
//!
//! The guest's connection is *terminated* by smoltcp; this module shuttles the
//! byte stream between that socket and a real host connection, preserving
//! half-close semantics and backpressure in both directions.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::time::{Duration, Instant};

use mio::Token;
use mio::net::TcpStream;
use smoltcp::socket::tcp;

/// How long the host-side connect may take before the guest connection is reset.
/// Backstop for black-holed destinations: the OS never delivers a WRITABLE event
/// for a connect that silently drops, so this is the only signal available.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// State for one bridged TCP connection. The smoltcp socket lives in the
/// [`SocketSet`](smoltcp::iface::SocketSet); this owns the host side.
// The flags below are independent points in the connection lifecycle (connect
// completion, each half-close direction, reset) that can co-occur, not a single
// state machine — a packed enum would not model them faithfully.
#[allow(clippy::struct_excessive_bools)]
pub(super) struct TcpFlow {
    /// Host-side connection (created with a non-blocking connect).
    pub(super) stream: TcpStream,
    /// mio token this stream is registered under (for deregistration on close).
    pub(super) token: Token,
    /// The non-blocking connect has completed (peer address resolved).
    connected: bool,
    /// The guest connection has reached `Established` at least once. Until then
    /// `may_recv()` is false simply because the handshake isn't done — which
    /// must not be mistaken for the guest half-closing.
    established_seen: bool,
    /// We've shut down the host write half after the guest's FIN drained.
    host_write_closed: bool,
    /// The host peer closed (EOF or error); we've FIN'd the guest socket.
    host_read_closed: bool,
    /// A fatal host-side error means the guest connection must be reset (RST).
    pub(super) reset: bool,
    /// When the host connect was initiated, for the [`CONNECT_TIMEOUT`] backstop.
    started: Instant,
}

impl std::fmt::Debug for TcpFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpFlow")
            .field("token", &self.token)
            .field("connected", &self.connected)
            .field("host_write_closed", &self.host_write_closed)
            .field("host_read_closed", &self.host_read_closed)
            .field("reset", &self.reset)
            .finish_non_exhaustive()
    }
}

impl TcpFlow {
    /// For an *outbound* flow: the host connect is still in flight (resolved by
    /// [`pump`](Self::pump) before any bytes move).
    pub(super) fn new(stream: TcpStream, token: Token) -> Self {
        Self {
            stream,
            token,
            connected: false,
            established_seen: false,
            host_write_closed: false,
            host_read_closed: false,
            reset: false,
            started: Instant::now(),
        }
    }

    /// For an *inbound forward* flow: the host stream came from `accept`, so it
    /// is already connected.
    pub(super) fn new_connected(stream: TcpStream, token: Token) -> Self {
        Self {
            stream,
            token,
            connected: true,
            established_seen: false,
            host_write_closed: false,
            host_read_closed: false,
            reset: false,
            started: Instant::now(),
        }
    }

    /// Handle a mio WRITABLE readiness event for the host stream. For a
    /// connecting socket this is the only cross-platform way to observe connect
    /// completion: mio's IOCP backend on Windows does not surface it through
    /// `take_error`/`peer_addr` polling while the connect is in progress.
    ///
    /// Follows the mio-recommended protocol: check `take_error` for a connect
    /// error, then confirm with `peer_addr` (a spurious WRITABLE may fire before
    /// the connect is truly established on some platforms).
    pub(super) fn note_writable(&mut self) {
        if self.connected || self.reset {
            return;
        }
        match self.stream.take_error() {
            Ok(None) => {
                // No error on the socket. Confirm the connect completed with
                // peer_addr per the mio docs: a spurious WRITABLE can fire
                // before the connect is truly established on some platforms.
                match self.stream.peer_addr() {
                    Ok(_) => self.connected = true,
                    // NotConnected/WouldBlock: spurious event, still connecting.
                    Err(e)
                        if e.kind() == std::io::ErrorKind::NotConnected
                            || e.kind() == std::io::ErrorKind::WouldBlock => {}
                    // Any other peer_addr error: connect failed.
                    Err(_) => self.reset = true,
                }
            }
            Ok(Some(_)) | Err(_) => self.reset = true,
        }
    }

    /// Pump bytes between the guest-facing `socket` and the host `stream` once.
    /// Returns `true` if any bytes moved in either direction (so the caller
    /// knows to keep draining before it sleeps).
    pub(super) fn pump(&mut self, socket: &mut tcp::Socket<'_>) -> bool {
        if !self.ensure_connected() {
            // Either still connecting, or a connect error already set `reset`.
            if self.reset {
                socket.abort();
            }
            return false;
        }

        // `may_send()` is true only from `Established` onward, so it marks the
        // point after which a dropped `may_recv()` genuinely means a guest FIN.
        if socket.may_send() {
            self.established_seen = true;
        }

        let mut worked = false;
        worked |= self.guest_to_host(socket);
        if !self.reset {
            self.maybe_shutdown_host_write(socket);
            worked |= self.host_to_guest(socket);
        }
        if self.reset {
            // A host-side failure (refused/reset/broken): RST the guest. The next
            // `iface.poll` flushes the reset; the caller reaps the now-Closed
            // socket afterward. This is distinct from a clean host EOF, which is
            // propagated as a FIN by `host_to_guest`.
            socket.abort();
        }
        worked
    }

    /// Wait for the non-blocking connect to complete. Sets `reset` on timeout.
    /// Returns `true` once the host side is usable (after [`note_writable`] has
    /// observed a WRITABLE event and confirmed connect success).
    ///
    /// We do NOT poll `take_error`/`peer_addr` here: mio's IOCP backend on
    /// Windows doesn't surface connect completion through those calls while the
    /// connect is in progress — they reliably reflect the outcome only after a
    /// WRITABLE readiness event is delivered, which [`note_writable`] handles.
    /// The timeout here is the backstop for black-holed destinations (the OS
    /// never delivers a WRITABLE event for a connect that silently drops).
    ///
    /// [`note_writable`]: Self::note_writable
    fn ensure_connected(&mut self) -> bool {
        if self.connected {
            return true;
        }
        if self.started.elapsed() >= CONNECT_TIMEOUT {
            self.reset = true;
            return false;
        }
        false
    }

    /// Drain the guest socket's receive buffer into the host stream, consuming
    /// exactly what the host accepted (the rest stays buffered → backpressure).
    fn guest_to_host(&mut self, socket: &mut tcp::Socket<'_>) -> bool {
        if !socket.can_recv() || self.host_write_closed {
            return false;
        }
        let result = socket.recv(|buf| match self.stream.write(buf) {
            Ok(n) => (n, Ok(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, Ok(0)),
            Err(e) => (0, Err(e)),
        });
        if let Ok(Ok(n)) = result {
            n > 0
        } else {
            // recv error (socket not in a receivable state) or host write error.
            self.reset = true;
            false
        }
    }

    /// Once the guest has sent its FIN (no more data will arrive and the buffer
    /// is drained), propagate it as a host write-shutdown.
    fn maybe_shutdown_host_write(&mut self, socket: &mut tcp::Socket<'_>) {
        if self.host_write_closed
            || !self.established_seen
            || socket.may_recv()
            || socket.can_recv()
        {
            return;
        }
        let _ = self.stream.shutdown(Shutdown::Write);
        self.host_write_closed = true;
    }

    /// Read from the host stream directly into the guest socket's send buffer,
    /// so we never read more than smoltcp can hold. A clean host EOF becomes a
    /// guest FIN; a host *error* (refused/reset/broken — including a connect
    /// failure that some platforms only surface on the first read) becomes a
    /// guest RST via `reset`.
    fn host_to_guest(&mut self, socket: &mut tcp::Socket<'_>) -> bool {
        if !socket.can_send() || self.host_read_closed {
            return false;
        }
        let result = socket.send(|buf| match self.stream.read(buf) {
            Ok(0) => (0, ReadOutcome::Eof),
            Ok(n) => (n, ReadOutcome::Bytes(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, ReadOutcome::WouldBlock),
            Err(_) => (0, ReadOutcome::Errored),
        });
        match result {
            Ok(ReadOutcome::Bytes(n)) => n > 0,
            Ok(ReadOutcome::Eof) => {
                socket.close();
                self.host_read_closed = true;
                false
            }
            Ok(ReadOutcome::Errored) => {
                self.reset = true;
                false
            }
            Ok(ReadOutcome::WouldBlock) | Err(_) => false,
        }
    }
}

enum ReadOutcome {
    Bytes(usize),
    Errored,
    Eof,
    WouldBlock,
}
