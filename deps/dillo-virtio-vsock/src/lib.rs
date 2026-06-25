// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! virtio-vsock device implementing [`VirtioDevice`].
//!
//! Ported from the dillo PoC `dillo-virtio-vsock` crate. The connection state
//! machine (`csm`), the 44-byte packet codec (`packet`), and the host Unix-
//! socket bridge (`uds`) are transport-agnostic and carry over intact. The
//! PoC's vhost-user `run()`, seccomp filter, and `PR_SET_PDEATHSIG` plumbing
//! are dropped — the device now runs in-process, driven directly by the
//! Machine attachment exactly like `dillo-virtio-console`.
//!
//! Three queues per virtio-vsock spec §5.10:
//! - Queue 0: RX (host → guest).
//! - Queue 1: TX (guest → host).
//! - Queue 2: event (unused; drained/ignored).
//!
//! The device terminates vsock itself and bridges each guest-initiated
//! connection (to host CID 2, port N) to a host Unix socket at `<uds>/N.sock`.
//! There is no kernel `/dev/vhost-vsock` dependency.

mod csm;
mod packet;
#[cfg(unix)]
mod uds;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dillo_mmio::Interrupt;
use dillo_virtio::queue::{Queue, QueueMemory, VIRTQ_DESC_F_WRITE};
use dillo_virtio::{
    ActivateError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle, VirtioDeviceHost,
    VirtioMemory, VirtioRunToken,
};

use crate::csm::{ConnectionManager, VsockBackend};
use crate::packet::{VSOCK_HEADER_LEN, VsockPacket};

/// VIRTIO_F_VERSION_1 from the virtio 1.x spec.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Virtio device-type id for a socket device (virtio 1.x §5.10).
pub const VIRTIO_ID_VSOCK: u32 = 19;

/// Per-queue max size (power of two). 128 is the standard virtio-vsock size.
const QUEUE_MAX: u16 = 128;
const QUEUE_SIZES: [u16; 3] = [QUEUE_MAX, QUEUE_MAX, QUEUE_MAX];

/// How often the RX worker re-polls for host → guest data when idle.
const RX_POLL: Duration = Duration::from_millis(10);

/// virtio-vsock: in-process, thread-mode device.
pub struct VirtioVsock {
    guest_cid: u64,
    conn_mgr: Arc<Mutex<ConnectionManager>>,
    activated: bool,
}

impl std::fmt::Debug for VirtioVsock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioVsock")
            .field("guest_cid", &self.guest_cid)
            .field("activated", &self.activated)
            .finish_non_exhaustive()
    }
}

impl VirtioVsock {
    /// Create a vsock device that bridges guest connections to host Unix
    /// sockets under `uds_path` (guest port N → `<uds_path>/N.sock`).
    #[cfg(unix)]
    pub fn new(guest_cid: u64, uds_path: std::path::PathBuf) -> Self {
        Self::new_with_backend(guest_cid, Box::new(uds::UdsBackend::new(uds_path)))
    }

    /// Create a vsock device with a caller-supplied backend (used by tests).
    // The only non-test caller is the unix-gated `new`; on non-unix this is
    // reachable solely from `#[cfg(test)]` code.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn new_with_backend(guest_cid: u64, backend: Box<dyn VsockBackend>) -> Self {
        Self {
            guest_cid,
            conn_mgr: Arc::new(Mutex::new(ConnectionManager::new(guest_cid, backend))),
            activated: false,
        }
    }
}

impl VirtioDevice for VirtioVsock {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_VSOCK
    }

    fn num_queues(&self) -> usize {
        3
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // vsock config space: guest_cid as u64 LE at offset 0, zeros beyond.
        let cid = self.guest_cid.to_le_bytes();
        for (i, byte) in data.iter_mut().enumerate() {
            let off = offset + i as u64;
            *byte = if off < cid.len() as u64 {
                cid[off as usize]
            } else {
                0
            };
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // guest_cid is read-only.
    }

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        if self.activated {
            return Err(ActivateError::InvalidConfig(
                "VirtioVsock::activate called twice".into(),
            ));
        }
        let queue_memory = activation.queue_memory();
        let buffer_memory = activation.buffer_memory();
        let mut queues = activation.take_queues();
        let mut queue_evts = activation.take_queue_evts();
        let host = activation.host()?;
        if queues.len() != 3 || queue_evts.len() != 3 {
            return Err(ActivateError::InvalidConfig(format!(
                "expected 3 queues + 3 evts, got {} / {}",
                queues.len(),
                queue_evts.len()
            )));
        }

        let rx_interrupt = activation.queue_interrupt(0);
        let tx_interrupt = activation.queue_interrupt(1);

        // Discard the event queue (index 2): we never generate vsock events.
        let _ = queues.remove(2);
        let _ = queue_evts.remove(2);

        // Queue 1 is TX (guest → host). Kick-driven worker.
        let tx_queue = queues.remove(1);
        let tx_evt = queue_evts.remove(1);
        let tx_wake = tx_evt.try_clone()?;
        let tx_handle = Arc::new(Mutex::new(Some(spawn_tx_worker(
            Arc::clone(&host),
            Arc::clone(&self.conn_mgr),
            Arc::clone(&queue_memory),
            Arc::clone(&buffer_memory),
            tx_queue,
            tx_evt,
            tx_interrupt,
        )?)));

        // Queue 0 is RX (host → guest). Poll-driven worker.
        let rx_queue = queues.remove(0);
        let rx_handle = Arc::new(Mutex::new(Some(spawn_rx_worker(
            host,
            Arc::clone(&self.conn_mgr),
            queue_memory,
            buffer_memory,
            rx_queue,
            rx_interrupt,
        )?)));

        let shutdown_tx_handle = Arc::clone(&tx_handle);
        let shutdown_rx_handle = Arc::clone(&rx_handle);

        self.activated = true;
        log::info!(
            "virtio-vsock: activated (guest_cid={}, TX/RX workers spawned)",
            self.guest_cid
        );
        Ok(VirtioDeviceHandle::new(
            move || {
                if let Some(handle) = shutdown_tx_handle
                    .lock()
                    .expect("virtio-vsock TX handle poisoned")
                    .as_mut()
                {
                    handle.shutdown();
                }
                if let Some(handle) = shutdown_rx_handle
                    .lock()
                    .expect("virtio-vsock RX handle poisoned")
                    .as_mut()
                {
                    handle.shutdown();
                }
                // Wake the kick-blocked TX worker so it observes shutdown.
                let _ = tx_wake.write(1);
            },
            move || {
                if let Some(handle) = tx_handle
                    .lock()
                    .expect("virtio-vsock TX handle poisoned")
                    .take()
                {
                    handle.join()?;
                }
                if let Some(handle) = rx_handle
                    .lock()
                    .expect("virtio-vsock RX handle poisoned")
                    .take()
                {
                    handle.join()?;
                }
                Ok(())
            },
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_tx_worker(
    host: Arc<dyn VirtioDeviceHost>,
    conn_mgr: Arc<Mutex<ConnectionManager>>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        tx_worker(
            &conn_mgr,
            &queue_memory,
            &buffer_memory,
            queue,
            &kick,
            interrupt.as_ref(),
            &token,
        );
        Ok(())
    }))
}

fn spawn_rx_worker(
    host: Arc<dyn VirtioDeviceHost>,
    conn_mgr: Arc<Mutex<ConnectionManager>>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        rx_worker(
            &conn_mgr,
            &queue_memory,
            &buffer_memory,
            queue,
            interrupt.as_ref(),
            &token,
        );
        Ok(())
    }))
}

/// TX worker: blocks on the queue kick, drains guest → host packets into the
/// connection manager, and returns the consumed descriptors to the guest.
fn tx_worker(
    conn_mgr: &Arc<Mutex<ConnectionManager>>,
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: &Kick,
    interrupt: Option<&Interrupt>,
    token: &VirtioRunToken,
) {
    let queue = Mutex::new(queue);
    loop {
        if let Err(e) = kick.read() {
            log::error!("virtio-vsock TX: kick read error: {e}");
            return;
        }
        if token.is_shutdown_requested() {
            return;
        }
        let mut q = queue.lock().expect("virtio-vsock TX queue mutex");
        let mut signaled = false;
        while let Some(head) = q.pop(queue_memory) {
            let head_index = head.index;
            if let Some(pkt) = read_tx_packet(queue_memory, buffer_memory, head) {
                conn_mgr
                    .lock()
                    .expect("virtio-vsock conn_mgr mutex")
                    .process_tx_pkt(pkt);
            }
            // TX descriptors are device-readable; nothing is written back.
            q.add_used(queue_memory, head_index, 0);
            signaled = true;
        }
        drop(q);
        if signaled && let Some(intr) = interrupt {
            intr.signal();
        }
    }
}

/// RX worker: polls the connection manager for host → guest packets and writes
/// them into guest-provided receive buffers. Poll-driven (no kick) because RX
/// data originates host-side; a produced packet that can't be delivered yet
/// (no guest buffer) is held and retried so it is never dropped.
fn rx_worker(
    conn_mgr: &Arc<Mutex<ConnectionManager>>,
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: Queue,
    interrupt: Option<&Interrupt>,
    token: &VirtioRunToken,
) {
    let queue = Mutex::new(queue);
    let mut pending: Option<VsockPacket> = None;
    loop {
        if token.is_shutdown_requested() {
            return;
        }
        if pending.is_none() {
            let mut mgr = conn_mgr.lock().expect("virtio-vsock conn_mgr mutex");
            // Cheap pre-check before the (timeout-bearing) backend poll inside
            // produce_rx_pkt, so an idle device doesn't poll every tick.
            if mgr.has_pending_rx() {
                pending = mgr.produce_rx_pkt();
            }
        }
        let Some(pkt) = pending.take() else {
            std::thread::sleep(RX_POLL);
            continue;
        };
        let mut q = queue.lock().expect("virtio-vsock RX queue mutex");
        if let Some(_written) = write_rx_packet(queue_memory, buffer_memory, &mut q, &pkt) {
            drop(q);
            if let Some(intr) = interrupt {
                intr.signal();
            }
        } else {
            // No guest RX buffer available; hold the packet and retry.
            drop(q);
            pending = Some(pkt);
            std::thread::sleep(RX_POLL);
        }
    }
}

/// Read one guest TX descriptor chain into a [`VsockPacket`]. Accumulates every
/// device-readable buffer in the chain, then splits header (44 bytes) + payload.
fn read_tx_packet(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    head: dillo_virtio::queue::DescriptorChain,
) -> Option<VsockPacket> {
    let mut bytes = Vec::new();
    let mut current = Some(head);
    while let Some(desc) = current {
        // Device-readable = guest-to-host data.
        if desc.flags & VIRTQ_DESC_F_WRITE == 0 {
            let mut buf = vec![0u8; desc.len as usize];
            if let Ok(n) = buffer_memory.read(desc.addr, &mut buf) {
                bytes.extend_from_slice(&buf[..n]);
            }
        }
        current = desc.next_desc(queue_memory);
    }
    if bytes.len() < VSOCK_HEADER_LEN {
        log::warn!(
            "virtio-vsock TX: chain shorter than header ({} bytes)",
            bytes.len()
        );
        return None;
    }
    let hdr: [u8; VSOCK_HEADER_LEN] = bytes[..VSOCK_HEADER_LEN].try_into().expect("len checked");
    let mut pkt = VsockPacket::parse_header(&hdr);
    let want = pkt.len as usize;
    let avail = bytes.len() - VSOCK_HEADER_LEN;
    let take = want.min(avail);
    pkt.data = bytes[VSOCK_HEADER_LEN..VSOCK_HEADER_LEN + take].to_vec();
    Some(pkt)
}

/// Write one [`VsockPacket`] (header + payload) into the next guest RX
/// descriptor chain. Returns the byte count written, or `None` if no RX buffer
/// is currently available (caller retains the packet to retry).
fn write_rx_packet(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &mut Queue,
    pkt: &VsockPacket,
) -> Option<u32> {
    let head = queue.pop(queue_memory)?;
    let head_index = head.index;

    let mut out = pkt.header_bytes().to_vec();
    out.extend_from_slice(&pkt.data);
    let mut remaining = out.as_slice();
    let mut written: u32 = 0;

    let mut current = Some(head);
    while let Some(desc) = current {
        if remaining.is_empty() {
            break;
        }
        // Device-writable = host-to-guest data.
        if desc.flags & VIRTQ_DESC_F_WRITE != 0 {
            let n = remaining.len().min(desc.len as usize);
            if n != 0 {
                match buffer_memory.write(desc.addr, &remaining[..n]) {
                    Ok(bytes) => {
                        written = written.saturating_add(bytes as u32);
                        remaining = &remaining[bytes..];
                    }
                    Err(e) => {
                        log::warn!("virtio-vsock RX: guest write at {:#x}: {e:?}", desc.addr.0);
                        break;
                    }
                }
            }
        }
        current = desc.next_desc(queue_memory);
    }

    queue.add_used(queue_memory, head_index, written);
    Some(written)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::packet::{VSOCK_HOST_CID, VSOCK_OP_REQUEST};

    /// Minimal echo backend mirroring the csm test backend, used to drive a
    /// packet through the device-level read/produce path.
    struct EchoBackend {
        buffers: std::collections::HashMap<(u32, u32), VecDeque<u8>>,
    }

    impl VsockBackend for EchoBackend {
        fn on_connection_request(&mut self, local_port: u32, peer_port: u32) -> bool {
            self.buffers
                .insert((local_port, peer_port), VecDeque::new());
            true
        }
        fn on_data_received(&mut self, local_port: u32, peer_port: u32, data: &[u8]) {
            if let Some(b) = self.buffers.get_mut(&(local_port, peer_port)) {
                b.extend(data);
            }
        }
        fn on_connection_closed(&mut self, _: u32, _: u32) {}
        fn poll_data(&mut self) -> Option<(u32, u32, Vec<u8>)> {
            for (&(lp, pp), b) in &mut self.buffers {
                if !b.is_empty() {
                    return Some((lp, pp, b.drain(..).collect()));
                }
            }
            None
        }
        fn has_data(&self) -> bool {
            self.buffers.values().any(|b| !b.is_empty())
        }
    }

    #[test]
    fn config_exposes_guest_cid() {
        let dev = VirtioVsock::new_with_backend(
            42,
            Box::new(EchoBackend {
                buffers: std::collections::HashMap::new(),
            }),
        );
        assert_eq!(dev.device_type(), VIRTIO_ID_VSOCK);
        assert_eq!(dev.num_queues(), 3);
        let mut cfg = [0u8; 8];
        dev.read_config(0, &mut cfg);
        assert_eq!(u64::from_le_bytes(cfg), 42);
    }

    #[test]
    fn request_produces_response_through_conn_mgr() {
        // Drive a REQUEST packet straight through the shared connection manager
        // (the same path the TX worker feeds) and confirm a RESPONSE comes back
        // out of the RX-producing side.
        let dev = VirtioVsock::new_with_backend(
            3,
            Box::new(EchoBackend {
                buffers: std::collections::HashMap::new(),
            }),
        );
        let mut req = VsockPacket::new_reply(VSOCK_OP_REQUEST, 3, VSOCK_HOST_CID, 1234, 5678);
        req.buf_alloc = 65536;
        {
            let mut mgr = dev.conn_mgr.lock().unwrap();
            mgr.process_tx_pkt(req);
            let resp = mgr.produce_rx_pkt().expect("response produced");
            assert_eq!(resp.dst_cid, 3);
            assert_eq!(resp.src_cid, VSOCK_HOST_CID);
        }
    }

    // Round-trip of the marshalling helpers (read_tx_packet / write_rx_packet)
    // is covered end-to-end by the `boots_with_vsock` integration test, which
    // exercises real guest descriptors over the live transport.
}
