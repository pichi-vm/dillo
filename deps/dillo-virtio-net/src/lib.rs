// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! In-process virtio-net device implementing [`VirtioDevice`].
//!
//! The device is transport- and host-agnostic, driven directly by the Machine
//! attachment exactly like [`dillo_virtio_console`] and `dillo-virtio-vsock`.
//! The transport (virtio-pci or virtio-mmio) wraps this device, handles
//! config-space + queue setup, and calls [`VirtioNet::activate`] once the guest
//! writes `DRIVER_OK`. We then spawn:
//!
//! - a **TX worker** that blocks on the TX queue kick, strips the 12-byte
//!   `virtio_net_hdr` off each guest frame, and hands the raw Ethernet frame to
//!   the [`NetBackend`];
//! - an **RX worker** that blocks on the backend for inbound frames, prepends a
//!   zeroed `virtio_net_hdr`, and writes the frame into guest RX buffers.
//!
//! Two virtqueues per virtio-net spec §5.1: queue 0 = RX (host → guest),
//! queue 1 = TX (guest → host). No control queue (`VIRTIO_NET_F_CTRL_VQ`
//! unset), no multiqueue (`VIRTIO_NET_F_MQ` unset), no checksum/GSO offloads —
//! a minimal, always-correct device. We negotiate only `VIRTIO_F_VERSION_1`,
//! `VIRTIO_NET_F_MAC` (config-space MAC), and `VIRTIO_NET_F_STATUS` (link
//! status), so the guest reads the host-assigned MAC and sees a link-up NIC.
//!
//! The L2 transport itself lives behind [`NetBackend`]: the cross-platform,
//! no-privilege [`UserNetBackend`] (the default), plus the Linux
//! [`BridgeBackend`] and [`MacvtapBackend`]. [`NullBackend`] remains a portable
//! sink used by tests.

mod backend;
mod user;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod bridge;
#[cfg(target_os = "linux")]
mod linux_fd;
#[cfg(target_os = "linux")]
mod macvtap;

use std::sync::{Arc, Mutex};

use dillo_mmio::Interrupt;
use dillo_virtio::queue::{Queue, QueueMemory, VIRTQ_DESC_F_WRITE};
use dillo_virtio::{
    ActivateError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle, VirtioDeviceHost,
    VirtioMemory, VirtioRunToken,
};

pub use backend::{MAX_FRAME_LEN, NetBackend, NullBackend, RECV_POLL};
pub use user::{Forward, Proto, UserNetBackend};
#[doc(hidden)]
pub use user::{
    fuzz_inspect_frame, fuzz_parse_dhcp, fuzz_parse_dns_query, fuzz_parse_router_solicit,
};

#[cfg(target_os = "linux")]
pub use bridge::BridgeBackend;
#[cfg(target_os = "macos")]
pub use bridge::VmnetBackend;
#[cfg(target_os = "linux")]
pub use macvtap::MacvtapBackend;

/// VIRTIO_F_VERSION_1 from the virtio 1.x spec.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Virtio device-type id for a network device (virtio 1.x §5.1).
pub const VIRTIO_ID_NET: u32 = 1;

/// `VIRTIO_NET_F_MAC`: the device advertises a MAC in config space (bit 5).
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// `VIRTIO_NET_F_STATUS`: config space carries a link-status field (bit 16).
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;

/// `VIRTIO_NET_S_LINK_UP` bit in the config-space status field.
const VIRTIO_NET_S_LINK_UP: u16 = 1;

/// Length of `struct virtio_net_hdr_v1` prepended to every frame on the rings.
/// With `VIRTIO_F_VERSION_1` the header is always 12 bytes and the trailing
/// `num_buffers` field is always present.
const NET_HDR_LEN: usize = 12;
/// Byte offset of the `num_buffers` field within `virtio_net_hdr_v1`.
const NET_HDR_NUM_BUFFERS_OFF: usize = 10;

/// Per-queue max size (power of two). 256 is the standard virtio-net size.
const QUEUE_MAX: u16 = 256;
const QUEUE_SIZES: [u16; 2] = [QUEUE_MAX, QUEUE_MAX];

/// virtio-net: in-process, thread-mode device over a [`NetBackend`].
pub struct VirtioNet {
    mac: [u8; 6],
    backend: Arc<dyn NetBackend>,
    activated: bool,
}

impl std::fmt::Debug for VirtioNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioNet")
            .field("mac", &format_mac(self.mac))
            .field("backend", &self.backend)
            .field("activated", &self.activated)
            .finish()
    }
}

impl VirtioNet {
    /// Create a virtio-net device with the given MAC and host backend.
    pub fn new(mac: [u8; 6], backend: Arc<dyn NetBackend>) -> Self {
        Self {
            mac,
            backend,
            activated: false,
        }
    }

    /// Create a virtio-net device backed by the portable [`NullBackend`] sink
    /// (a link-up NIC with no peer). Available on every host.
    pub fn null(mac: [u8; 6]) -> Self {
        Self::new(mac, Arc::new(NullBackend::new()))
    }

    /// The MAC this device advertises to the guest.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

impl VirtioDevice for VirtioNet {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_NET
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // virtio_net_config: mac[6] then status:u16 (LINK_UP). Everything past
        // that (max_virtqueue_pairs, mtu, …) is unadvertised and reads zero.
        let mut cfg = [0u8; 8];
        cfg[..6].copy_from_slice(&self.mac);
        let status = if self.backend.link_up() {
            VIRTIO_NET_S_LINK_UP
        } else {
            0
        };
        cfg[6..8].copy_from_slice(&status.to_le_bytes());
        for (i, byte) in data.iter_mut().enumerate() {
            let off = offset as usize + i;
            *byte = cfg.get(off).copied().unwrap_or(0);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // MAC and status are read-only.
    }

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        if self.activated {
            return Err(ActivateError::InvalidConfig(
                "VirtioNet::activate called twice".into(),
            ));
        }
        let queue_memory = activation.queue_memory();
        let buffer_memory = activation.buffer_memory();
        let mut queues = activation.take_queues();
        let mut queue_evts = activation.take_queue_evts();
        let host = activation.host()?;
        if queues.len() != 2 || queue_evts.len() != 2 {
            return Err(ActivateError::InvalidConfig(format!(
                "expected 2 queues + 2 evts, got {} / {}",
                queues.len(),
                queue_evts.len()
            )));
        }

        let rx_interrupt = activation.queue_interrupt(0);
        let tx_interrupt = activation.queue_interrupt(1);

        // Queue 1 is TX (guest → host). Kick-driven worker.
        let tx_queue = queues.remove(1);
        let tx_evt = queue_evts.remove(1);
        let tx_wake = tx_evt.try_clone()?;
        let tx_handle = Arc::new(Mutex::new(Some(spawn_tx_worker(
            Arc::clone(&host),
            Arc::clone(&self.backend),
            Arc::clone(&queue_memory),
            Arc::clone(&buffer_memory),
            tx_queue,
            tx_evt,
            tx_interrupt,
        )?)));

        // Queue 0 is RX (host → guest). Backend-driven worker.
        let rx_queue = queues.remove(0);
        let rx_handle = Arc::new(Mutex::new(Some(spawn_rx_worker(
            host,
            Arc::clone(&self.backend),
            queue_memory,
            buffer_memory,
            rx_queue,
            rx_interrupt,
        )?)));

        let shutdown_tx_handle = Arc::clone(&tx_handle);
        let shutdown_rx_handle = Arc::clone(&rx_handle);

        self.activated = true;
        log::info!(
            "virtio-net: activated (mac={}, TX/RX workers spawned)",
            format_mac(self.mac)
        );
        Ok(VirtioDeviceHandle::new(
            move || {
                if let Some(handle) = shutdown_tx_handle
                    .lock()
                    .expect("virtio-net TX handle poisoned")
                    .as_mut()
                {
                    handle.shutdown();
                }
                if let Some(handle) = shutdown_rx_handle
                    .lock()
                    .expect("virtio-net RX handle poisoned")
                    .as_mut()
                {
                    handle.shutdown();
                }
                // Wake the kick-blocked TX worker so it observes shutdown. The
                // RX worker polls the backend with a bounded timeout, so it
                // observes shutdown on its own.
                let _ = tx_wake.write(1);
            },
            move || {
                if let Some(handle) = tx_handle
                    .lock()
                    .expect("virtio-net TX handle poisoned")
                    .take()
                {
                    handle.join()?;
                }
                if let Some(handle) = rx_handle
                    .lock()
                    .expect("virtio-net RX handle poisoned")
                    .take()
                {
                    handle.join()?;
                }
                Ok(())
            },
        ))
    }
}

/// Render a MAC as `aa:bb:cc:dd:ee:ff` for logs.
fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[allow(clippy::too_many_arguments)]
fn spawn_tx_worker(
    host: Arc<dyn VirtioDeviceHost>,
    backend: Arc<dyn NetBackend>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        tx_worker(
            &backend,
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
    backend: Arc<dyn NetBackend>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        rx_worker(
            &backend,
            &queue_memory,
            &buffer_memory,
            queue,
            interrupt.as_ref(),
            &token,
        );
        Ok(())
    }))
}

/// TX worker: blocks on the queue kick, drains guest → host frames, hands each
/// (minus its virtio-net header) to the backend, and returns the consumed
/// descriptors to the guest.
fn tx_worker(
    backend: &Arc<dyn NetBackend>,
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
            log::error!("virtio-net TX: kick read error: {e}");
            return;
        }
        if token.is_shutdown_requested() {
            return;
        }
        drain_tx(backend, queue_memory, buffer_memory, &queue, interrupt);
    }
}

/// Drain every available TX descriptor chain once.
fn drain_tx(
    backend: &Arc<dyn NetBackend>,
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &Mutex<Queue>,
    interrupt: Option<&Interrupt>,
) {
    let mut q = queue.lock().expect("virtio-net TX queue mutex");
    let mut signaled = false;
    while let Some(head) = q.pop(queue_memory) {
        let head_index = head.index;
        if let Some(frame) = read_tx_frame(queue_memory, buffer_memory, head)
            && let Err(e) = backend.send(&frame)
        {
            log::warn!("virtio-net TX: backend send ({} bytes): {e}", frame.len());
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

/// Read one guest TX descriptor chain into a raw Ethernet frame, stripping the
/// leading 12-byte `virtio_net_hdr`. Returns `None` if the chain carries no
/// payload past the header.
fn read_tx_frame(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    head: dillo_virtio::queue::DescriptorChain,
) -> Option<Vec<u8>> {
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
    if bytes.len() <= NET_HDR_LEN {
        // Header-only (or short) chain: no Ethernet payload to transmit.
        return None;
    }
    Some(bytes[NET_HDR_LEN..].to_vec())
}

/// RX worker: blocks on the backend for inbound frames and writes each into a
/// guest RX descriptor chain (prefixed with a zeroed virtio-net header). A frame
/// that arrives with no guest buffer available is held and retried so it is
/// never dropped.
fn rx_worker(
    backend: &Arc<dyn NetBackend>,
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: Queue,
    interrupt: Option<&Interrupt>,
    token: &VirtioRunToken,
) {
    let queue = Mutex::new(queue);
    let mut scratch = vec![0u8; MAX_FRAME_LEN];
    let mut pending: Option<Vec<u8>> = None;
    loop {
        if token.is_shutdown_requested() {
            return;
        }
        let frame = match pending.take() {
            Some(frame) => frame,
            None => match backend.recv(&mut scratch) {
                Ok(Some(n)) => scratch[..n].to_vec(),
                // Timeout: loop to re-check shutdown, then poll again.
                Ok(None) => continue,
                Err(e) => {
                    log::warn!("virtio-net RX: backend recv: {e}");
                    continue;
                }
            },
        };
        let mut q = queue.lock().expect("virtio-net RX queue mutex");
        if write_rx_frame(queue_memory, buffer_memory, &mut q, &frame) {
            drop(q);
            if let Some(intr) = interrupt {
                intr.signal();
            }
        } else {
            // No guest RX buffer available; hold the frame and retry.
            drop(q);
            pending = Some(frame);
            std::thread::sleep(RECV_POLL);
        }
    }
}

/// Write one inbound Ethernet frame (prefixed with a zeroed `virtio_net_hdr`,
/// `num_buffers = 1`) into the next guest RX descriptor chain. Returns `false`
/// if no RX buffer is currently available (caller retains the frame to retry).
fn write_rx_frame(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &mut Queue,
    frame: &[u8],
) -> bool {
    let Some(head) = queue.pop(queue_memory) else {
        return false;
    };
    let head_index = head.index;

    let mut out = vec![0u8; NET_HDR_LEN];
    // num_buffers = 1: this frame occupies exactly one descriptor chain (no
    // VIRTIO_NET_F_MRG_RXBUF), as required by virtio 1.x even when the feature
    // is not negotiated.
    out[NET_HDR_NUM_BUFFERS_OFF..NET_HDR_NUM_BUFFERS_OFF + 2].copy_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(frame);

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
                        log::warn!("virtio-net RX: guest write at {:#x}: {e:?}", desc.addr.0);
                        break;
                    }
                }
            }
        }
        current = desc.next_desc(queue_memory);
    }

    queue.add_used(queue_memory, head_index, written);
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex as StdMutex;

    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use dillo_virtio::queue::VIRTQ_DESC_F_WRITE;
    use dillo_virtio::{SharedQueueMemory, SharedVirtioMemory};
    use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;

    /// Test backend: records transmitted frames and replays a queued inbound
    /// frame on the next `recv`.
    #[derive(Debug, Default)]
    struct MockBackend {
        sent: StdMutex<Vec<Vec<u8>>>,
        inbound: StdMutex<VecDeque<Vec<u8>>>,
    }

    impl NetBackend for MockBackend {
        fn send(&self, frame: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().push(frame.to_vec());
            Ok(())
        }

        fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
            match self.inbound.lock().unwrap().pop_front() {
                Some(frame) => {
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    Ok(Some(n))
                }
                None => Ok(None),
            }
        }
    }

    #[test]
    fn config_advertises_mac_and_link() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let dev = VirtioNet::null(mac);
        assert_eq!(dev.device_type(), VIRTIO_ID_NET);
        assert_eq!(dev.num_queues(), 2);
        let mut cfg = [0u8; 8];
        dev.read_config(0, &mut cfg);
        assert_eq!(&cfg[..6], &mac);
        assert_eq!(u16::from_le_bytes([cfg[6], cfg[7]]), VIRTIO_NET_S_LINK_UP);
    }

    #[test]
    fn features_are_minimal_modern() {
        let dev = VirtioNet::null([0; 6]);
        let f = dev.features();
        assert_ne!(f & VIRTIO_F_VERSION_1, 0, "must be modern virtio");
        assert_ne!(f & VIRTIO_NET_F_MAC, 0, "must advertise MAC");
        assert_ne!(f & VIRTIO_NET_F_STATUS, 0, "must advertise status");
        // No control queue, no MQ, no offloads.
        assert_eq!(f & (1 << 17), 0, "must not offer CTRL_VQ");
    }

    /// A queue + buffer memory harness backed by one shared-memory capability
    /// over `mem`.
    fn shared(mem: &GuestMemoryMmap, base: u64, size: u64) -> Arc<MappedSharedMemory> {
        Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange { base, size },
                access: SharedAccess::ReadWrite,
            },
        ))
    }

    fn ready_queue(desc: u64, avail: u64, used: u64) -> Queue {
        let mut q = Queue::new(16);
        q.size = 16;
        q.ready = true;
        q.desc_table = GuestAddress(desc);
        q.avail_ring = GuestAddress(avail);
        q.used_ring = GuestAddress(used);
        q
    }

    /// TX: a guest frame (virtio_net_hdr + Ethernet) is handed to the backend
    /// with the 12-byte header stripped.
    #[test]
    fn tx_strips_header_and_forwards_frame() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut q = ready_queue(0x100, 0x1000, 0x2000);

        // One readable descriptor at 0x5000 carrying hdr(12) + "hello-frame".
        let payload = b"hello-frame";
        let mut frame = vec![0u8; NET_HDR_LEN];
        frame.extend_from_slice(payload);
        mem.write(&frame, GuestAddress(0x5000)).unwrap();

        mem.write_obj::<u64>(0x5000, q.desc_table).unwrap();
        mem.write_obj::<u32>(frame.len() as u32, q.desc_table.unchecked_add(8))
            .unwrap();
        mem.write_obj::<u16>(0, q.desc_table.unchecked_add(12))
            .unwrap(); // readable
        mem.write_obj::<u16>(0, q.desc_table.unchecked_add(14))
            .unwrap();
        mem.write_obj::<u16>(0, q.avail_ring.unchecked_add(4))
            .unwrap();
        mem.write_obj::<u16>(1, q.avail_ring.unchecked_add(2))
            .unwrap();

        let qmem: Arc<dyn QueueMemory> =
            Arc::new(SharedQueueMemory::new(vec![shared(&mem, 0, 0x4000)]));
        let bmem: Arc<dyn VirtioMemory> =
            Arc::new(SharedVirtioMemory::new(vec![shared(&mem, 0x5000, 0x1000)]));

        let out = read_tx_frame(&qmem, &bmem, q.pop(&qmem).expect("pop")).expect("frame");
        assert_eq!(
            out, payload,
            "TX must deliver the Ethernet payload sans header"
        );

        // And the backend records exactly that payload when drained.
        let backend = MockBackend::default();
        backend.send(&out).unwrap();
        assert_eq!(backend.sent.lock().unwrap()[0], payload);
    }

    /// A round-trip through the mock backend: TX records, RX replays.
    #[test]
    fn mock_backend_round_trips() {
        let backend = MockBackend::default();
        backend.send(b"frame-a").unwrap();
        assert_eq!(backend.sent.lock().unwrap()[0], b"frame-a");
        backend
            .inbound
            .lock()
            .unwrap()
            .push_back(b"frame-b".to_vec());
        let mut buf = vec![0u8; MAX_FRAME_LEN];
        let n = backend.recv(&mut buf).unwrap().expect("inbound");
        assert_eq!(&buf[..n], b"frame-b");
        assert_eq!(backend.recv(&mut buf).unwrap(), None);
    }

    /// RX: an inbound Ethernet frame lands in a guest RX buffer with a 12-byte
    /// virtio_net_hdr prepended and num_buffers = 1.
    #[test]
    fn rx_prepends_header_into_guest_buffer() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut q = ready_queue(0x100, 0x1000, 0x2000);

        // One writable descriptor at 0x5000, 2048 bytes.
        mem.write_obj::<u64>(0x5000, q.desc_table).unwrap();
        mem.write_obj::<u32>(2048, q.desc_table.unchecked_add(8))
            .unwrap();
        mem.write_obj::<u16>(VIRTQ_DESC_F_WRITE, q.desc_table.unchecked_add(12))
            .unwrap();
        mem.write_obj::<u16>(0, q.desc_table.unchecked_add(14))
            .unwrap();
        mem.write_obj::<u16>(0, q.avail_ring.unchecked_add(4))
            .unwrap();
        mem.write_obj::<u16>(1, q.avail_ring.unchecked_add(2))
            .unwrap();

        let qmem: Arc<dyn QueueMemory> =
            Arc::new(SharedQueueMemory::new(vec![shared(&mem, 0, 0x4000)]));
        let bmem: Arc<dyn VirtioMemory> =
            Arc::new(SharedVirtioMemory::new(vec![shared(&mem, 0x5000, 0x1000)]));

        let payload = b"inbound-eth-frame";
        assert!(write_rx_frame(&qmem, &bmem, &mut q, payload));

        // Header is zeroed except num_buffers = 1, then the frame follows.
        let mut hdr = [0u8; NET_HDR_LEN];
        Bytes::read(&mem, &mut hdr, GuestAddress(0x5000)).unwrap();
        assert_eq!(
            u16::from_le_bytes([
                hdr[NET_HDR_NUM_BUFFERS_OFF],
                hdr[NET_HDR_NUM_BUFFERS_OFF + 1]
            ]),
            1
        );
        let mut got = vec![0u8; payload.len()];
        Bytes::read(&mem, &mut got, GuestAddress(0x5000 + NET_HDR_LEN as u64)).unwrap();
        assert_eq!(&got, payload);

        // used_idx advanced and the used length covers header + frame.
        let used_idx: u16 = mem.read_obj(GuestAddress(0x2002)).unwrap();
        assert_eq!(used_idx, 1);
        let used_len: u32 = mem.read_obj(GuestAddress(0x2000 + 8)).unwrap();
        assert_eq!(used_len as usize, NET_HDR_LEN + payload.len());
    }

    /// RX with no available guest buffer reports "not delivered" so the caller
    /// retains the frame.
    #[test]
    fn rx_without_buffer_is_held() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut q = ready_queue(0x100, 0x1000, 0x2000);
        // avail_idx == next_avail (0) → empty ring.
        mem.write_obj::<u16>(0, q.avail_ring.unchecked_add(2))
            .unwrap();
        let qmem: Arc<dyn QueueMemory> =
            Arc::new(SharedQueueMemory::new(vec![shared(&mem, 0, 0x4000)]));
        let bmem: Arc<dyn VirtioMemory> =
            Arc::new(SharedVirtioMemory::new(vec![shared(&mem, 0x5000, 0x1000)]));
        assert!(!write_rx_frame(&qmem, &bmem, &mut q, b"x"));
    }
}
