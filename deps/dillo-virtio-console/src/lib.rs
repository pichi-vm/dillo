// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! virtio-console device implementing [`VirtioDevice`].
//!
//! The device is driven directly by the Machine attachment. The
//! transport (virtio-pci, in crate `virtio-pci`) wraps this device,
//! handles config-space + BAR MMIO, and calls [`activate`] once the
//! guest writes DRIVER_OK. We then spawn a TX worker that drains the
//! TX queue and writes the bytes to stdout, plus an RX worker that
//! forwards host stdin into guest-provided receive buffers.
//!
//! Two queues per virtio-console spec §5.3:
//! - Queue 0: RX (host → guest input from stdin).
//! - Queue 1: TX (guest → host output → stdout).
//!
//! No multiport / control queue support (we don't negotiate
//! VIRTIO_CONSOLE_F_MULTIPORT). Single-console only — that's what
//! `console=hvc0` needs.
//!
use std::collections::VecDeque;
use std::io::{self, BufWriter, Write};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dillo_mmio::Interrupt;
use dillo_virtio::queue::{Queue, QueueMemory, VIRTQ_DESC_F_WRITE};
use dillo_virtio::{
    ActivateError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle, VirtioDeviceHost,
    VirtioMemory, VirtioRunToken,
};

/// VIRTIO_F_VERSION_1 from the virtio 1.x spec.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Virtio device-type id for a console (virtio 1.x §5.3).
pub const VIRTIO_ID_CONSOLE: u32 = 3;

/// Queue sizes (per spec a power of two; 64 is the typical hvc0 size).
const QUEUE_MAX: u16 = 64;
const QUEUE_SIZES: [u16; 2] = [QUEUE_MAX, QUEUE_MAX];

enum OutputMessage {
    Data(Vec<u8>),
    Flush(mpsc::Sender<()>),
}

fn output_tx() -> &'static Mutex<mpsc::Sender<OutputMessage>> {
    static OUTPUT_TX: OnceLock<Mutex<mpsc::Sender<OutputMessage>>> = OnceLock::new();
    OUTPUT_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("virtio-console-stdout".into())
            .spawn(move || output_worker(rx))
            .expect("spawn virtio-console stdout worker");
        Mutex::new(tx)
    })
}

fn output_worker(rx: mpsc::Receiver<OutputMessage>) {
    let stdout = io::stdout();
    let mut stdout = BufWriter::with_capacity(128 * 1024, stdout.lock());
    pump_output(&rx, &mut stdout);
}

/// Drain `rx` into `out`, flushing after every burst. hvc0 is a console:
/// its output must reach the host promptly, not languish in the BufWriter
/// until an explicit flush — which, mid-boot, never comes (boot output is
/// well under the 128 KiB buffer, so without this a `console=hvc0` guest
/// appears to emit nothing at all). Each `recv` wakeup drains everything
/// already queued into one write batch, then flushes once. Returns when
/// the channel closes.
fn pump_output(rx: &mpsc::Receiver<OutputMessage>, out: &mut impl Write) {
    while let Ok(msg) = rx.recv() {
        handle_output_message(msg, out);
        while let Ok(msg) = rx.try_recv() {
            handle_output_message(msg, out);
        }
        let _ = out.flush();
    }
}

fn handle_output_message(msg: OutputMessage, out: &mut impl Write) {
    match msg {
        OutputMessage::Data(output) => {
            let _ = out.write_all(&output);
        }
        OutputMessage::Flush(done) => {
            let _ = out.flush();
            let _ = done.send(());
        }
    }
}

fn enqueue_output(output: Vec<u8>) {
    if output.is_empty() {
        return;
    }
    if let Ok(tx) = output_tx().lock() {
        let _ = tx.send(OutputMessage::Data(output));
    }
}

pub fn flush_output() {
    let (done_tx, done_rx) = mpsc::channel();
    if let Ok(tx) = output_tx().lock() {
        let _ = tx.send(OutputMessage::Flush(done_tx));
    }
    let _ = done_rx.recv();
}

/// virtio-console: thread-mode device.
pub struct VirtioConsole {
    activated: bool,
}

impl std::fmt::Debug for VirtioConsole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioConsole")
            .field("activated", &self.activated)
            .finish()
    }
}

impl Default for VirtioConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioConsole {
    pub fn new() -> Self {
        Self { activated: false }
    }
}

impl VirtioDevice for VirtioConsole {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_CONSOLE
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        // Only VIRTIO_F_VERSION_1. No multiport, no size, no emerg-write.
        // Linux's hvc_virtio binds hvc0 with this minimal feature set.
        VIRTIO_F_VERSION_1
    }

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let queue_memory = activation.queue_memory();
        let buffer_memory = activation.buffer_memory();
        let mut queues = activation.take_queues();
        let mut queue_evts = activation.take_queue_evts();
        let host = activation.host()?;
        if self.activated {
            return Err(ActivateError::InvalidConfig(
                "VirtioConsole::activate called twice".into(),
            ));
        }
        if queues.len() != 2 || queue_evts.len() != 2 {
            return Err(ActivateError::InvalidConfig(format!(
                "expected 2 queues + 2 evts, got {} / {}",
                queues.len(),
                queue_evts.len()
            )));
        }

        let tx_call_interrupt = activation.queue_interrupt(1);
        let rx_call_interrupt = activation.queue_interrupt(0);

        // Queue 1 is TX. Pop it out and spawn a worker.
        let tx_queue = queues.remove(1);
        let tx_evt = queue_evts.remove(1);
        let tx_wake = tx_evt.try_clone()?;
        let tx_handle = Arc::new(Mutex::new(Some(spawn_tx_worker(
            Arc::clone(&host),
            Arc::clone(&queue_memory),
            Arc::clone(&buffer_memory),
            tx_queue,
            tx_evt,
            tx_call_interrupt,
        )?)));

        // Queue 0 is RX. Feed host stdin into guest-provided writable buffers.
        let rx_queue = queues.remove(0);
        let rx_evt = queue_evts.remove(0);
        let rx_wake = rx_evt.try_clone()?;
        let rx_handle = Arc::new(Mutex::new(Some(spawn_rx_worker(
            host,
            queue_memory,
            buffer_memory,
            rx_queue,
            rx_evt,
            rx_call_interrupt,
        )?)));
        let shutdown_tx_handle = Arc::clone(&tx_handle);
        let shutdown_rx_handle = Arc::clone(&rx_handle);

        self.activated = true;
        log::info!("virtio-console: activated (TX/RX workers spawned)");
        Ok(VirtioDeviceHandle::new(
            move || {
                if let Some(handle) = shutdown_tx_handle
                    .lock()
                    .expect("virtio-console TX handle poisoned")
                    .as_mut()
                {
                    handle.shutdown();
                }
                if let Some(handle) = shutdown_rx_handle
                    .lock()
                    .expect("virtio-console RX handle poisoned")
                    .as_mut()
                {
                    handle.shutdown();
                }
                let _ = tx_wake.write(1);
                let _ = rx_wake.write(1);
            },
            move || {
                if let Some(handle) = tx_handle
                    .lock()
                    .expect("virtio-console TX handle poisoned")
                    .take()
                {
                    handle.join()?;
                }
                if let Some(handle) = rx_handle
                    .lock()
                    .expect("virtio-console RX handle poisoned")
                    .take()
                {
                    handle.join()?;
                }
                Ok(())
            },
        ))
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        // No fields advertised (no multiport, no max_nr_ports). Spec
        // says the device-config region size is 12 bytes, all zero
        // when no relevant features are negotiated.
        for b in data.iter_mut() {
            *b = 0;
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // No writable fields.
    }
}

fn spawn_tx_worker(
    host: Arc<dyn VirtioDeviceHost>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        tx_worker(
            queue_memory,
            buffer_memory,
            queue,
            kick,
            call_interrupt,
            token,
        );
        Ok(())
    }))
}

fn spawn_rx_worker(
    host: Arc<dyn VirtioDeviceHost>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        rx_worker(
            queue_memory,
            buffer_memory,
            queue,
            kick,
            call_interrupt,
            token,
        );
        Ok(())
    }))
}

fn tx_worker(
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
    token: VirtioRunToken,
) {
    let queue = Arc::new(Mutex::new(queue));
    loop {
        if let Err(e) = kick.read() {
            log::error!("virtio-console TX: kick read error: {e}");
            return;
        }
        if token.is_shutdown_requested() {
            return;
        }
        drain_tx(
            &queue_memory,
            &buffer_memory,
            &queue,
            call_interrupt.as_ref(),
        );
    }
}

fn rx_worker(
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
    token: VirtioRunToken,
) {
    let queue = Arc::new(Mutex::new(queue));
    let mut pending = VecDeque::new();
    loop {
        if token.is_shutdown_requested() {
            return;
        }
        if pending.is_empty() {
            thread::sleep(Duration::from_millis(50));
            continue;
        }

        while !pending.is_empty() {
            if token.is_shutdown_requested() {
                return;
            }
            if drain_rx(
                &queue_memory,
                &buffer_memory,
                &queue,
                &mut pending,
                call_interrupt.as_ref(),
            ) {
                continue;
            }
            if let Err(e) = kick.read() {
                log::error!("virtio-console RX: kick read error: {e}");
                return;
            }
        }
    }
}

fn drain_rx(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &Arc<Mutex<Queue>>,
    pending: &mut VecDeque<u8>,
    call_interrupt: Option<&Interrupt>,
) -> bool {
    let mut q = queue.lock().expect("virtio-console RX queue mutex");
    let mut signaled = false;
    let mut made_progress = false;
    while !pending.is_empty() {
        let Some(head) = q.pop(queue_memory) else {
            break;
        };
        let head_index = head.index;
        let mut written: u32 = 0;
        let mut current = Some(head);
        while let Some(desc) = current {
            if desc.flags & VIRTQ_DESC_F_WRITE != 0 {
                let n = pending.len().min(desc.len as usize);
                if n != 0 {
                    let chunk: Vec<u8> = pending.drain(..n).collect();
                    match buffer_memory.write(desc.addr, &chunk) {
                        Ok(bytes) => {
                            written = written.saturating_add(bytes as u32);
                            made_progress = true;
                            if bytes < chunk.len() {
                                for byte in chunk[bytes..].iter().rev() {
                                    pending.push_front(*byte);
                                }
                                break;
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "virtio-console RX: guest write at {:#x}+{}: {e:?}",
                                desc.addr.0,
                                desc.len
                            );
                            for byte in chunk.iter().rev() {
                                pending.push_front(*byte);
                            }
                            break;
                        }
                    }
                }
            }
            if pending.is_empty() {
                break;
            }
            current = desc.next_desc(queue_memory);
        }
        q.add_used(queue_memory, head_index, written);
        signaled = true;
    }
    if signaled && let Some(intr) = call_interrupt {
        intr.signal();
    }
    made_progress
}

fn drain_tx(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &Arc<Mutex<Queue>>,
    call_interrupt: Option<&Interrupt>,
) {
    let mut q = queue.lock().expect("virtio-console TX queue mutex");
    let mut signaled = false;
    let mut output = Vec::new();
    while let Some(head) = q.pop(queue_memory) {
        let head_index = head.index;
        let mut written: u32 = 0;
        // Walk the chain manually — DescriptorChain isn't an Iterator,
        // it carries a `next_desc(mem)` accessor.
        let mut current = Some(head);
        while let Some(desc) = current {
            // Device-readable = guest-to-host data (TX path).
            if desc.flags & VIRTQ_DESC_F_WRITE == 0 {
                let mut buf = vec![0u8; desc.len as usize];
                match buffer_memory.read(desc.addr, &mut buf) {
                    Ok(n) => {
                        output.extend_from_slice(&buf[..n]);
                        written += n as u32;
                    }
                    Err(e) => {
                        log::warn!(
                            "virtio-console TX: guest read at {:#x}+{}: {e:?}",
                            desc.addr.0,
                            desc.len
                        );
                    }
                }
            }
            current = desc.next_desc(queue_memory);
        }
        q.add_used(queue_memory, head_index, written);
        signaled = true;
    }
    if signaled {
        enqueue_output(output);
        if let Some(intr) = call_interrupt {
            // Tell the guest one or more descriptors completed.
            intr.signal();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use dillo_virtio::queue::VIRTQ_DESC_F_WRITE;
    use dillo_virtio::{SharedQueueMemory, SharedVirtioMemory};
    use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

    /// A `Write` that records bytes and counts `flush` calls.
    #[derive(Default)]
    struct RecordingWriter {
        data: Vec<u8>,
        flushes: usize,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// Console output must be flushed after each burst — otherwise a
    /// `console=hvc0` guest's boot messages sit in the BufWriter and never
    /// reach the host. Regression test for that bug.
    #[test]
    fn output_is_flushed_after_each_burst() {
        let (tx, rx) = mpsc::channel();
        tx.send(OutputMessage::Data(b"hello".to_vec())).unwrap();
        tx.send(OutputMessage::Data(b" world".to_vec())).unwrap();
        drop(tx); // close the channel so pump_output returns

        let mut writer = RecordingWriter::default();
        pump_output(&rx, &mut writer);

        assert_eq!(writer.data, b"hello world");
        assert!(writer.flushes >= 1, "console output was never flushed");
    }

    #[test]
    fn rx_drains_pending_input_into_guest_buffer() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut queue = Queue::new(16);
        queue.size = 16;
        queue.ready = true;
        queue.desc_table = GuestAddress(0x100);
        queue.avail_ring = GuestAddress(0x1000);
        queue.used_ring = GuestAddress(0x2000);

        mem.write_obj::<u64>(0x5000, queue.desc_table).unwrap();
        mem.write_obj::<u32>(8, queue.desc_table.unchecked_add(8))
            .unwrap();
        mem.write_obj::<u16>(VIRTQ_DESC_F_WRITE, queue.desc_table.unchecked_add(12))
            .unwrap();
        mem.write_obj::<u16>(0, queue.desc_table.unchecked_add(14))
            .unwrap();
        mem.write_obj::<u16>(0, queue.avail_ring.unchecked_add(4))
            .unwrap();
        mem.write_obj::<u16>(1, queue.avail_ring.unchecked_add(2))
            .unwrap();

        let queue_shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x100,
                    size: 0x3000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let buffer_shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x5000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let queue_memory: Arc<dyn QueueMemory> =
            Arc::new(SharedQueueMemory::new(vec![queue_shared]));
        let buffer_memory: Arc<dyn VirtioMemory> =
            Arc::new(SharedVirtioMemory::new(vec![buffer_shared]));
        let queue = Arc::new(Mutex::new(queue));
        let mut pending: VecDeque<u8> = b"abc".iter().copied().collect();
        assert!(drain_rx(
            &queue_memory,
            &buffer_memory,
            &queue,
            &mut pending,
            None
        ));
        assert!(pending.is_empty());

        let mut out = [0u8; 3];
        Bytes::read(&mem, &mut out, GuestAddress(0x5000)).unwrap();
        assert_eq!(&out, b"abc");
        let used_idx: u16 = mem.read_obj(GuestAddress(0x2002)).unwrap();
        assert_eq!(used_idx, 1);
    }

    #[test]
    fn rx_drains_queue_metadata_through_shared_memory() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x100,
                    size: 0x3000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let buffer_shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x5000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let queue_memory: Arc<dyn QueueMemory> = Arc::new(SharedQueueMemory::new(vec![shared]));
        let buffer_memory: Arc<dyn VirtioMemory> =
            Arc::new(SharedVirtioMemory::new(vec![buffer_shared]));
        let mut queue = Queue::new(16);
        queue.size = 16;
        queue.ready = true;
        queue.desc_table = GuestAddress(0x100);
        queue.avail_ring = GuestAddress(0x1000);
        queue.used_ring = GuestAddress(0x2000);

        mem.write_obj::<u64>(0x5000, queue.desc_table).unwrap();
        mem.write_obj::<u32>(8, queue.desc_table.unchecked_add(8))
            .unwrap();
        mem.write_obj::<u16>(VIRTQ_DESC_F_WRITE, queue.desc_table.unchecked_add(12))
            .unwrap();
        mem.write_obj::<u16>(0, queue.desc_table.unchecked_add(14))
            .unwrap();
        mem.write_obj::<u16>(0, queue.avail_ring.unchecked_add(4))
            .unwrap();
        mem.write_obj::<u16>(1, queue.avail_ring.unchecked_add(2))
            .unwrap();

        let queue = Arc::new(Mutex::new(queue));
        let mut pending: VecDeque<u8> = b"abc".iter().copied().collect();
        assert!(drain_rx(
            &queue_memory,
            &buffer_memory,
            &queue,
            &mut pending,
            None
        ));

        let mut out = [0u8; 3];
        Bytes::read(&mem, &mut out, GuestAddress(0x5000)).unwrap();
        assert_eq!(&out, b"abc");
        assert_eq!(queue_memory.read_u16(GuestAddress(0x2002)), Some(1));
    }

    #[test]
    fn rx_rejects_payload_outside_shared_memory() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue_shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x100,
                    size: 0x3000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let buffer_shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0x6000,
                    size: 0x1000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let queue_memory: Arc<dyn QueueMemory> =
            Arc::new(SharedQueueMemory::new(vec![queue_shared]));
        let buffer_memory: Arc<dyn VirtioMemory> =
            Arc::new(SharedVirtioMemory::new(vec![buffer_shared]));
        let mut queue = Queue::new(16);
        queue.size = 16;
        queue.ready = true;
        queue.desc_table = GuestAddress(0x100);
        queue.avail_ring = GuestAddress(0x1000);
        queue.used_ring = GuestAddress(0x2000);

        mem.write_obj::<u64>(0x5000, queue.desc_table).unwrap();
        mem.write_obj::<u32>(8, queue.desc_table.unchecked_add(8))
            .unwrap();
        mem.write_obj::<u16>(VIRTQ_DESC_F_WRITE, queue.desc_table.unchecked_add(12))
            .unwrap();
        mem.write_obj::<u16>(0, queue.desc_table.unchecked_add(14))
            .unwrap();
        mem.write_obj::<u16>(0, queue.avail_ring.unchecked_add(4))
            .unwrap();
        mem.write_obj::<u16>(1, queue.avail_ring.unchecked_add(2))
            .unwrap();

        let queue = Arc::new(Mutex::new(queue));
        let mut pending: VecDeque<u8> = b"abc".iter().copied().collect();
        assert!(!drain_rx(
            &queue_memory,
            &buffer_memory,
            &queue,
            &mut pending,
            None
        ));
        assert_eq!(pending.iter().copied().collect::<Vec<_>>(), b"abc");
        assert_eq!(queue_memory.read_u16(GuestAddress(0x2002)), Some(1));
    }
}
