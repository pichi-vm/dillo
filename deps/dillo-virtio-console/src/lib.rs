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
//! With no named ports configured that is the whole device: no multiport, no
//! control queue, exactly the minimal feature set Linux's `hvc_virtio` binds
//! `hvc0` with.
//!
//! Given named ports ([`VirtioConsole::with_ports`]) the device additionally
//! negotiates `VIRTIO_CONSOLE_F_MULTIPORT` and grows the spec's queue map:
//!
//! | queues | purpose |
//! |--------|---------|
//! | 0 / 1 | port 0 RX / TX — the unnamed stdio console, unchanged |
//! | 2 / 3 | control receiveq / transmitq |
//! | 2i+2 / 2i+3 | named port id *i* (i ≥ 1) RX / TX |
//!
//! Each named port's host backend is an inherited `pipe:N` end (see
//! [`pipe`]); an omitted direction is closed and gets no worker at all. The
//! control plane ([`control`]) announces every port — including port 0, which
//! under MULTIPORT exists only because the control plane creates it.
//!
//! See `DESIGN-named-ports.md` and `PLAN-named-ports.md` in this crate.
mod control;
pub mod pipe;

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

/// VIRTIO_CONSOLE_F_MULTIPORT: the device has a control plane and may expose
/// more than one port (virtio 1.x §5.3.3).
const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;

/// Queue sizes (per spec a power of two; 64 is the typical hvc0 size).
const QUEUE_MAX: u16 = 64;
const QUEUE_SIZES: [u16; 2] = [QUEUE_MAX, QUEUE_MAX];

/// Queue index of the control receiveq (device → guest) under MULTIPORT.
const CONTROL_RX_QUEUE: usize = 2;
/// Queue index of the control transmitq (guest → device) under MULTIPORT.
const CONTROL_TX_QUEUE: usize = 3;

/// Queue indices `(rx, tx)` for port `id`: 0/1 for port 0, then 2i+2 / 2i+3
/// for named port `i` (the control pair occupies 2/3, i.e. port id 0's slot in
/// that formula).
fn port_queues(id: u32) -> (usize, usize) {
    if id == 0 {
        (0, 1)
    } else {
        let base = 2 * id as usize + 2;
        (base, base + 1)
    }
}

/// How often a named-port worker re-polls its pipe when idle. Short enough
/// that a one-shot host→guest hand-off is not perceptibly delayed, long enough
/// not to spin a core per port.
const PIPE_POLL: Duration = Duration::from_millis(5);

/// Read chunk for a named port's host → guest direction.
const PIPE_CHUNK: usize = 16 * 1024;

/// Cap on host→guest bytes held until the guest opens the port / drains RX.
const RX_PENDING_LIMIT: usize = 1024 * 1024;

/// Cap on guest→host bytes waiting on a pipe the host is not reading —
/// backpressure instead of unbounded growth.
const TX_BACKLOG_LIMIT: usize = 1024 * 1024;

/// A named MULTIPORT port with its adopted host pipe ends. An omitted
/// direction is closed: no backend, and no worker is spawned for it. The
/// layout requires at least one direction, so a port always carries data one
/// way or the other.
#[derive(Debug)]
pub struct NamedPort {
    name: String,
    rx: Option<pipe::PipeEnd>,
    tx: Option<pipe::PipeEnd>,
}

impl NamedPort {
    /// `rx` carries host → guest, `tx` carries guest → host (device sense).
    pub fn new(name: String, rx: Option<pipe::PipeEnd>, tx: Option<pipe::PipeEnd>) -> Self {
        Self { name, rx, tx }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Liveness of one named port's host side. A port is reported closed to the
/// guest once every direction it was configured with has hit EOF / EPIPE —
/// for a uni-directional port, that is its single direction.
#[derive(Debug)]
struct PortLiveness {
    id: u32,
    open_directions: std::sync::atomic::AtomicUsize,
    control: Arc<control::ControlPlane>,
}

impl PortLiveness {
    /// Has a guest process opened this port? Until it has, Linux discards
    /// anything the device puts on the port's receiveq.
    fn guest_has_opened(&self) -> bool {
        self.control.guest_has_opened(self.id)
    }

    /// One direction's host end went away. Non-fatal: the VM, the other
    /// direction's worker, the other ports, and port 0 all keep running.
    fn direction_closed(&self, direction: pipe::Direction) {
        use std::sync::atomic::Ordering;
        log::info!(
            "virtio-console: port {} {direction} host end closed",
            self.id
        );
        if self.open_directions.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.control.port_disconnected(self.id);
        }
    }
}

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
    /// Named MULTIPORT ports (port 0 is implicit and not in here). Empty ⇒
    /// today's two-queue single-port console.
    ports: Vec<NamedPort>,
    /// `queue_max_sizes` hands out a slice, so the sizes live here.
    queue_sizes: Vec<u16>,
}

impl std::fmt::Debug for VirtioConsole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioConsole")
            .field("activated", &self.activated)
            .field("ports", &self.ports)
            .field("queues", &self.queue_sizes.len())
            .finish()
    }
}

impl Default for VirtioConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioConsole {
    /// A single-port console: port 0 on stdout, no MULTIPORT.
    pub fn new() -> Self {
        Self::with_ports(Vec::new())
    }

    /// A console with `ports` named MULTIPORT ports **in addition to** the
    /// unnamed port 0. A non-empty list turns MULTIPORT on; an empty one is
    /// exactly [`VirtioConsole::new`].
    pub fn with_ports(ports: Vec<NamedPort>) -> Self {
        let queues = 2 + if ports.is_empty() {
            0
        } else {
            // control pair + rx/tx per named port.
            2 + 2 * ports.len()
        };
        Self {
            activated: false,
            ports,
            queue_sizes: vec![QUEUE_MAX; queues],
        }
    }

    /// `true` once the device will negotiate `VIRTIO_CONSOLE_F_MULTIPORT`.
    fn multiport(&self) -> bool {
        !self.ports.is_empty()
    }

    /// Total ports the guest may see: port 0 plus every named port.
    fn max_nr_ports(&self) -> u32 {
        1 + self.ports.len() as u32
    }
}

impl VirtioDevice for VirtioConsole {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_CONSOLE
    }

    fn num_queues(&self) -> usize {
        self.queue_sizes.len()
    }

    fn queue_max_sizes(&self) -> &[u16] {
        if self.multiport() {
            &self.queue_sizes
        } else {
            &QUEUE_SIZES
        }
    }

    fn features(&self) -> u64 {
        // Without named ports: only VIRTIO_F_VERSION_1 — no multiport, no
        // size, no emerg-write. Linux's hvc_virtio binds hvc0 with exactly
        // this minimal feature set, so that path is untouched.
        if self.multiport() {
            VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT
        } else {
            VIRTIO_F_VERSION_1
        }
    }

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let queue_memory = activation.queue_memory();
        let buffer_memory = activation.buffer_memory();
        let queues = activation.take_queues();
        let queue_evts = activation.take_queue_evts();
        let host = activation.host()?;
        if self.activated {
            return Err(ActivateError::InvalidConfig(
                "VirtioConsole::activate called twice".into(),
            ));
        }
        let expected = self.num_queues();
        if queues.len() != expected || queue_evts.len() != expected {
            return Err(ActivateError::InvalidConfig(format!(
                "expected {expected} queues + {expected} evts, got {} / {}",
                queues.len(),
                queue_evts.len()
            )));
        }

        // Taking queues/evts out by index: `Vec::remove` would renumber
        // everything after it, and the MULTIPORT map is index-addressed.
        let mut queues: Vec<Option<Queue>> = queues.into_iter().map(Some).collect();
        let mut queue_evts: Vec<Option<Kick>> = queue_evts.into_iter().map(Some).collect();

        // Workers, plus the kick each one may be blocked on at shutdown.
        let mut workers: Vec<VirtioDeviceHandle> = Vec::new();
        let mut wakes: Vec<Kick> = Vec::new();

        // --- port 0: the unnamed console, identical with or without MULTIPORT
        let tx_queue = take(&mut queues[1], "port 0 TX queue")?;
        let tx_evt = take(&mut queue_evts[1], "port 0 TX kick")?;
        wakes.push(tx_evt.try_clone()?);
        workers.push(spawn_tx_worker(
            Arc::clone(&host),
            Arc::clone(&queue_memory),
            Arc::clone(&buffer_memory),
            tx_queue,
            tx_evt,
            activation.queue_interrupt(1),
        )?);

        let rx_queue = take(&mut queues[0], "port 0 RX queue")?;
        let rx_evt = take(&mut queue_evts[0], "port 0 RX kick")?;
        wakes.push(rx_evt.try_clone()?);
        workers.push(spawn_rx_worker(
            Arc::clone(&host),
            Arc::clone(&queue_memory),
            Arc::clone(&buffer_memory),
            rx_queue,
            rx_evt,
            activation.queue_interrupt(0),
        )?);

        // --- named ports: control plane first, then one worker per open
        //     open direction; a closed direction gets no worker at all.
        if self.multiport() {
            let mut kinds = vec![control::PortKind::Console];
            kinds.extend(
                self.ports
                    .iter()
                    .map(|p| control::PortKind::Named(p.name.clone())),
            );
            let control_plane = Arc::new(control::ControlPlane::new(kinds));

            let control_rx_queue = take(&mut queues[CONTROL_RX_QUEUE], "control RX queue")?;
            let control_tx_queue = take(&mut queues[CONTROL_TX_QUEUE], "control TX queue")?;
            // The control worker polls both halves, so it never parks on a
            // kick; the kicks are drained to keep the counters from growing.
            let _ = take(&mut queue_evts[CONTROL_RX_QUEUE], "control RX kick")?;
            let _ = take(&mut queue_evts[CONTROL_TX_QUEUE], "control TX kick")?;
            workers.push(spawn_control_worker(
                Arc::clone(&host),
                Arc::clone(&control_plane),
                Arc::clone(&queue_memory),
                Arc::clone(&buffer_memory),
                control_rx_queue,
                control_tx_queue,
                activation.queue_interrupt(CONTROL_RX_QUEUE),
                activation.queue_interrupt(CONTROL_TX_QUEUE),
            )?);

            // Take only PipeEnds. Emptying `ports` would collapse MULTIPORT
            // identity after activate: features(), queue_max_sizes(), and
            // read_config's max_nr_ports all key off the port list.
            for (index, port) in self.ports.iter_mut().enumerate() {
                let id = index as u32 + 1;
                let (rx_index, tx_index) = port_queues(id);
                let rx = port.rx.take();
                let tx = port.tx.take();
                let open = usize::from(rx.is_some()) + usize::from(tx.is_some());
                let liveness = Arc::new(PortLiveness {
                    id,
                    open_directions: std::sync::atomic::AtomicUsize::new(open),
                    control: Arc::clone(&control_plane),
                });

                let rx_queue = take(&mut queues[rx_index], "named port RX queue")?;
                let _ = take(&mut queue_evts[rx_index], "named port RX kick")?;
                if let Some(end) = rx {
                    workers.push(spawn_port_rx_worker(
                        Arc::clone(&host),
                        end,
                        Arc::clone(&liveness),
                        Arc::clone(&queue_memory),
                        Arc::clone(&buffer_memory),
                        rx_queue,
                        activation.queue_interrupt(rx_index),
                    )?);
                }

                let tx_queue = take(&mut queues[tx_index], "named port TX queue")?;
                let _ = take(&mut queue_evts[tx_index], "named port TX kick")?;
                if let Some(end) = tx {
                    workers.push(spawn_port_tx_worker(
                        Arc::clone(&host),
                        end,
                        Arc::clone(&liveness),
                        Arc::clone(&queue_memory),
                        Arc::clone(&buffer_memory),
                        tx_queue,
                        activation.queue_interrupt(tx_index),
                    )?);
                }

                log::debug!(
                    "virtio-console: port {id} {:?} ({} open direction(s))",
                    port.name,
                    open
                );
            }
        }

        let workers = Arc::new(Mutex::new(workers));
        let shutdown_workers = Arc::clone(&workers);

        self.activated = true;
        log::info!(
            "virtio-console: activated ({} worker(s), multiport={})",
            workers
                .lock()
                .expect("virtio-console worker list poisoned")
                .len(),
            self.multiport()
        );
        Ok(VirtioDeviceHandle::new(
            move || {
                for handle in shutdown_workers
                    .lock()
                    .expect("virtio-console worker list poisoned")
                    .iter_mut()
                {
                    handle.shutdown();
                }
                // Release any worker parked in a blocking `Kick::read`.
                for wake in &wakes {
                    let _ = wake.write(1);
                }
            },
            move || {
                let drained: Vec<_> = std::mem::take(
                    &mut *workers.lock().expect("virtio-console worker list poisoned"),
                );
                let mut first_error = None;
                for handle in drained {
                    // Join every worker even if one fails: a half-joined
                    // device would leave threads touching guest memory.
                    if let Err(e) = handle.join()
                        && first_error.is_none()
                    {
                        first_error = Some(e);
                    }
                }
                match first_error {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            },
        ))
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // `struct virtio_console_config { le16 cols; le16 rows;
        //  le32 max_nr_ports; le32 emerg_wr; }`. Without MULTIPORT nothing is
        // advertised and the whole 12-byte region reads as zero; with it, the
        // guest sizes its port table from `max_nr_ports` at offset 4.
        let mut config = [0u8; 12];
        if self.multiport() {
            config[4..8].copy_from_slice(&self.max_nr_ports().to_le_bytes());
        }
        for (i, byte) in data.iter_mut().enumerate() {
            let off = offset as usize + i;
            *byte = config.get(off).copied().unwrap_or(0);
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

/// Take one indexed activation input, naming it if it is somehow already gone.
fn take<T>(slot: &mut Option<T>, what: &str) -> Result<T, ActivateError> {
    slot.take()
        .ok_or_else(|| ActivateError::InvalidConfig(format!("virtio-console: {what} taken twice")))
}

/// Spawn the MULTIPORT control worker: it drives the guest-facing port
/// announcements and consumes the guest's replies.
#[allow(clippy::too_many_arguments)]
fn spawn_control_worker(
    host: Arc<dyn VirtioDeviceHost>,
    plane: Arc<control::ControlPlane>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    rx_queue: Queue,
    tx_queue: Queue,
    rx_call_interrupt: Option<Interrupt>,
    tx_call_interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        control_worker(
            &plane,
            &queue_memory,
            &buffer_memory,
            rx_queue,
            tx_queue,
            rx_call_interrupt.as_ref(),
            tx_call_interrupt.as_ref(),
            &token,
        );
        Ok(())
    }))
}

/// Spawn the host → guest worker for one named port: read its pipe, hand the
/// bytes to the guest through that port's receiveq.
fn spawn_port_rx_worker(
    host: Arc<dyn VirtioDeviceHost>,
    end: pipe::PipeEnd,
    liveness: Arc<PortLiveness>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    call_interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        port_rx_worker(
            &end,
            &liveness,
            &queue_memory,
            &buffer_memory,
            queue,
            call_interrupt.as_ref(),
            &token,
        );
        Ok(())
    }))
}

/// Spawn the guest → host worker for one named port: drain its transmitq and
/// write the bytes to its pipe.
fn spawn_port_tx_worker(
    host: Arc<dyn VirtioDeviceHost>,
    end: pipe::PipeEnd,
    liveness: Arc<PortLiveness>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    call_interrupt: Option<Interrupt>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        port_tx_worker(
            &end,
            &liveness,
            &queue_memory,
            &buffer_memory,
            queue,
            call_interrupt.as_ref(),
            &token,
        );
        Ok(())
    }))
}

/// Drive the control plane until shutdown.
///
/// Poll-driven rather than kick-driven: the worker has two queues to watch and
/// must also deliver messages the data workers produce (a host-side
/// disconnect), none of which a single blocking `Kick::read` would wake it for.
/// Polling also means it can never be parked when the device is torn down.
#[allow(clippy::too_many_arguments)]
fn control_worker(
    plane: &control::ControlPlane,
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    rx_queue: Queue,
    tx_queue: Queue,
    rx_call_interrupt: Option<&Interrupt>,
    tx_call_interrupt: Option<&Interrupt>,
    token: &VirtioRunToken,
) {
    let rx_queue = Arc::new(Mutex::new(rx_queue));
    let tx_queue = Arc::new(Mutex::new(tx_queue));
    while !token.is_shutdown_requested() {
        let mut progress = false;

        // Guest → device: DEVICE_READY, PORT_READY, PORT_OPEN.
        for buf in drain_tx_buffers(queue_memory, buffer_memory, &tx_queue, tx_call_interrupt) {
            progress = true;
            match control::ControlMessage::decode(&buf) {
                Some(msg) => plane.handle(&msg),
                None => log::warn!(
                    "virtio-console: control message of {} byte(s) is too short",
                    buf.len()
                ),
            }
        }

        // Device → guest: whatever the state machine (or a disconnecting port)
        // has queued, one message per descriptor chain.
        while let Some(msg) = plane.pop_outbound() {
            if push_to_queue(
                queue_memory,
                buffer_memory,
                &rx_queue,
                &msg.encode(),
                rx_call_interrupt,
            ) {
                progress = true;
            } else {
                // No guest buffer right now; keep the message and retry.
                plane.requeue(msg);
                break;
            }
        }

        if !progress {
            thread::sleep(PIPE_POLL);
        }
    }
}

/// Host → guest for one named port.
fn port_rx_worker(
    end: &pipe::PipeEnd,
    liveness: &PortLiveness,
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: Queue,
    call_interrupt: Option<&Interrupt>,
    token: &VirtioRunToken,
) {
    let queue = Arc::new(Mutex::new(queue));
    let mut pending: VecDeque<u8> = VecDeque::new();
    let mut host_open = true;
    let mut buf = vec![0u8; PIPE_CHUNK];
    while !token.is_shutdown_requested() {
        let mut progress = false;

        // Read while the host end is alive and the guest is keeping up.
        if host_open && pending.len() < RX_PENDING_LIMIT {
            match end.read(&mut buf) {
                Ok(pipe::Transfer::Moved(n)) => {
                    pending.extend(&buf[..n]);
                    progress = true;
                }
                Ok(pipe::Transfer::WouldBlock) => {}
                Ok(pipe::Transfer::Closed) => host_open = false,
                Err(e) => {
                    log::warn!("virtio-console: port {} rx read failed: {e}", liveness.id);
                    host_open = false;
                }
            }
        }

        // Hold the bytes until a guest process has opened the port: Linux's
        // virtio_console drops inbound buffers for a port nobody has opened,
        // so handing them over early would lose them silently.
        if !pending.is_empty()
            && liveness.guest_has_opened()
            && drain_rx(
                queue_memory,
                buffer_memory,
                &queue,
                &mut pending,
                call_interrupt,
            )
        {
            progress = true;
        }

        // Nothing left to read and nothing left to hand over: this direction
        // is finished. The close is only reported now, once the last bytes
        // have reached the guest — a port that closes with data still queued
        // would look to the guest like the data never arrived. Returning here
        // (rather than idling) keeps the join at shutdown cheap and leaves
        // every other port untouched.
        if !host_open && pending.is_empty() {
            liveness.direction_closed(end.direction());
            return;
        }
        if !progress {
            thread::sleep(PIPE_POLL);
        }
    }
}

/// Guest → host for one named port.
fn port_tx_worker(
    end: &pipe::PipeEnd,
    liveness: &PortLiveness,
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: Queue,
    call_interrupt: Option<&Interrupt>,
    token: &VirtioRunToken,
) {
    let queue = Arc::new(Mutex::new(queue));
    let mut backlog: VecDeque<u8> = VecDeque::new();
    let mut host_open = true;
    while !token.is_shutdown_requested() {
        let mut progress = false;

        // Only pull more from the guest while the backlog is bounded —
        // otherwise a host that never reads its pipe would grow it forever.
        if backlog.len() < TX_BACKLOG_LIMIT {
            for buf in drain_tx_buffers(queue_memory, buffer_memory, &queue, call_interrupt) {
                progress = true;
                if host_open {
                    backlog.extend(&buf);
                }
                // With the host end gone the bytes are dropped, but the
                // descriptors are still returned above so the guest's writes
                // complete instead of hanging.
            }
        }

        while host_open && !backlog.is_empty() {
            let chunk: Vec<u8> = backlog.iter().take(PIPE_CHUNK).copied().collect();
            match end.write(&chunk) {
                Ok(pipe::Transfer::Moved(n)) => {
                    backlog.drain(..n);
                    progress = true;
                }
                Ok(pipe::Transfer::WouldBlock) => break,
                Ok(pipe::Transfer::Closed) => {
                    host_open = false;
                    backlog.clear();
                    liveness.direction_closed(end.direction());
                }
                Err(e) => {
                    log::warn!("virtio-console: port {} tx write failed: {e}", liveness.id);
                    host_open = false;
                    backlog.clear();
                    liveness.direction_closed(end.direction());
                }
            }
        }

        if !progress {
            thread::sleep(PIPE_POLL);
        }
    }
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
    let buffers = drain_tx_buffers(queue_memory, buffer_memory, queue, call_interrupt);
    if !buffers.is_empty() {
        enqueue_output(buffers.concat());
    }
}

/// Pop every available guest → host chain, returning **one buffer per chain**
/// so a framed protocol (the control queue) keeps its message boundaries, and
/// completing each chain on the used ring.
fn drain_tx_buffers(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &Arc<Mutex<Queue>>,
    call_interrupt: Option<&Interrupt>,
) -> Vec<Vec<u8>> {
    let mut q = queue.lock().expect("virtio-console TX queue mutex");
    let mut out = Vec::new();
    while let Some(head) = q.pop(queue_memory) {
        let head_index = head.index;
        let mut written: u32 = 0;
        let mut message = Vec::new();
        // Walk the chain manually — DescriptorChain isn't an Iterator,
        // it carries a `next_desc(mem)` accessor.
        let mut current = Some(head);
        while let Some(desc) = current {
            // Device-readable = guest-to-host data (TX path).
            if desc.flags & VIRTQ_DESC_F_WRITE == 0 {
                let mut buf = vec![0u8; desc.len as usize];
                match buffer_memory.read(desc.addr, &mut buf) {
                    Ok(n) => {
                        message.extend_from_slice(&buf[..n]);
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
        out.push(message);
    }
    if !out.is_empty()
        && let Some(intr) = call_interrupt
    {
        // Tell the guest one or more descriptors completed.
        intr.signal();
    }
    out
}

/// Write `payload` into one guest-provided writable chain on `queue`.
///
/// Returns `false` (having consumed nothing) when the guest has posted no
/// buffer, so the caller can hold the message and retry. A chain too small for
/// the payload is completed with what fits and a warning — truncating one
/// control message beats stalling the plane behind it forever.
fn push_to_queue(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &Arc<Mutex<Queue>>,
    payload: &[u8],
    call_interrupt: Option<&Interrupt>,
) -> bool {
    let mut q = queue.lock().expect("virtio-console queue mutex");
    let Some(head) = q.pop(queue_memory) else {
        return false;
    };
    let head_index = head.index;
    let mut written: u32 = 0;
    let mut remaining = payload;
    let mut current = Some(head);
    while let Some(desc) = current {
        if remaining.is_empty() {
            break;
        }
        if desc.flags & VIRTQ_DESC_F_WRITE != 0 {
            let n = remaining.len().min(desc.len as usize);
            match buffer_memory.write(desc.addr, &remaining[..n]) {
                Ok(bytes) => {
                    written = written.saturating_add(bytes as u32);
                    remaining = &remaining[bytes..];
                }
                Err(e) => {
                    log::warn!(
                        "virtio-console: guest write at {:#x}+{}: {e:?}",
                        desc.addr.0,
                        desc.len
                    );
                    break;
                }
            }
        }
        current = desc.next_desc(queue_memory);
    }
    if !remaining.is_empty() {
        log::warn!(
            "virtio-console: guest buffer too small for a {}-byte message ({} byte(s) dropped)",
            payload.len(),
            remaining.len()
        );
    }
    q.add_used(queue_memory, head_index, written);
    if let Some(intr) = call_interrupt {
        intr.signal();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use dillo_virtio::queue::VIRTQ_DESC_F_WRITE;
    use dillo_virtio::{SharedQueueMemory, SharedVirtioMemory};

    use crate::control::ControlMessage;
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

    // --- MULTIPORT shape ---

    fn named(names: &[&str]) -> VirtioConsole {
        VirtioConsole::with_ports(
            names
                .iter()
                .map(|n| NamedPort::new((*n).to_string(), None, None))
                .collect(),
        )
    }

    #[test]
    fn single_port_console_is_unchanged() {
        let console = VirtioConsole::new();
        assert_eq!(console.num_queues(), 2);
        assert_eq!(console.queue_max_sizes(), &[QUEUE_MAX, QUEUE_MAX]);
        assert_eq!(
            console.features(),
            VIRTIO_F_VERSION_1,
            "a console with no named ports must not negotiate MULTIPORT"
        );
        let mut config = [0xAA; 12];
        console.read_config(0, &mut config);
        assert_eq!(
            config, [0; 12],
            "no fields are advertised without MULTIPORT"
        );
    }

    #[test]
    fn named_ports_negotiate_multiport() {
        let console = named(&["build"]);
        assert_eq!(
            console.features(),
            VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT
        );
    }

    #[test]
    fn queue_count_follows_the_port_count() {
        // port 0 pair + control pair + one pair per named port.
        assert_eq!(named(&["a"]).num_queues(), 6);
        assert_eq!(named(&["a", "b"]).num_queues(), 8);
        let console = named(&["a", "b", "c"]);
        assert_eq!(console.num_queues(), 10);
        assert_eq!(console.queue_max_sizes().len(), 10);
        assert!(console.queue_max_sizes().iter().all(|s| *s == QUEUE_MAX));
    }

    #[test]
    fn queue_map_matches_the_spec_layout() {
        // 0/1 port 0, 2/3 control, 2i+2 / 2i+3 for named port i.
        assert_eq!(port_queues(0), (0, 1));
        assert_eq!((CONTROL_RX_QUEUE, CONTROL_TX_QUEUE), (2, 3));
        assert_eq!(port_queues(1), (4, 5));
        assert_eq!(port_queues(2), (6, 7));
        assert_eq!(port_queues(3), (8, 9));
        // Every port's queues stay inside the device's queue count, and no
        // two ports (or the control pair) collide.
        let console = named(&["a", "b", "c"]);
        let mut seen = vec![CONTROL_RX_QUEUE, CONTROL_TX_QUEUE];
        for id in 0..console.max_nr_ports() {
            let (rx, tx) = port_queues(id);
            assert!(tx < console.num_queues(), "port {id} queues out of range");
            assert!(
                !seen.contains(&rx) && !seen.contains(&tx),
                "port {id} collides"
            );
            seen.push(rx);
            seen.push(tx);
        }
    }

    #[test]
    fn config_space_advertises_max_nr_ports() {
        let console = named(&["build", "log"]);
        // 2 named ports + the unnamed port 0.
        assert_eq!(console.max_nr_ports(), 3);
        let mut config = [0u8; 12];
        console.read_config(0, &mut config);
        assert_eq!(&config[0..4], &[0; 4], "cols/rows stay zero");
        assert_eq!(u32::from_le_bytes(config[4..8].try_into().unwrap()), 3);

        // A partial read at the max_nr_ports offset sees the same bytes, and
        // reads past the 12-byte region read as zero.
        let mut tail = [0xAAu8; 4];
        console.read_config(4, &mut tail);
        assert_eq!(u32::from_le_bytes(tail), 3);
        let mut past = [0xAAu8; 4];
        console.read_config(12, &mut past);
        assert_eq!(past, [0; 4]);
    }

    #[test]
    fn multiport_identity_survives_activate_pipe_take() {
        // activate() takes only PipeEnds. Emptying `ports` would collapse
        // MULTIPORT under a live guest: features(), queue_max_sizes(), and
        // read_config's max_nr_ports all key off the port list.
        let mut console = named(&["build", "log"]);
        let features_before = console.features();
        let queue_len_before = console.queue_max_sizes().len();
        let mut config_before = [0u8; 12];
        console.read_config(0, &mut config_before);

        // Same mutation activate performs on the port list.
        for port in &mut console.ports {
            let _ = port.rx.take();
            let _ = port.tx.take();
        }

        assert_eq!(console.features(), features_before);
        assert_eq!(console.queue_max_sizes().len(), queue_len_before);
        let mut config_after = [0u8; 12];
        console.read_config(0, &mut config_after);
        assert_eq!(
            config_after, config_before,
            "config space must still advertise the same max_nr_ports"
        );
        assert_eq!(
            u32::from_le_bytes(config_after[4..8].try_into().unwrap()),
            3
        );
        assert!(
            console.multiport(),
            "named ports must still negotiate MULTIPORT after ends are taken"
        );
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

    // --- named-port queue plumbing ---

    /// A guest-side virtqueue with `count` single-descriptor chains posted,
    /// each `len` bytes at `0x5000 + i * len`. `writable` picks the direction:
    /// device-writable (RX / control receiveq) or device-readable (TX).
    struct TestQueue {
        mem: GuestMemoryMmap,
        queue_memory: Arc<dyn QueueMemory>,
        buffer_memory: Arc<dyn VirtioMemory>,
        queue: Arc<Mutex<Queue>>,
        buffer_base: u64,
        len: u32,
    }

    impl TestQueue {
        fn new(count: u16, len: u32, writable: bool) -> Self {
            const BUFFER_BASE: u64 = 0x5000;
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
            let mut queue = Queue::new(16);
            queue.size = 16;
            queue.ready = true;
            queue.desc_table = GuestAddress(0x100);
            queue.avail_ring = GuestAddress(0x1000);
            queue.used_ring = GuestAddress(0x2000);

            let flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
            for i in 0..count {
                let desc = queue.desc_table.unchecked_add(u64::from(i) * 16);
                mem.write_obj::<u64>(BUFFER_BASE + u64::from(i) * u64::from(len), desc)
                    .unwrap();
                mem.write_obj::<u32>(len, desc.unchecked_add(8)).unwrap();
                mem.write_obj::<u16>(flags, desc.unchecked_add(12)).unwrap();
                mem.write_obj::<u16>(0, desc.unchecked_add(14)).unwrap();
                mem.write_obj::<u16>(i, queue.avail_ring.unchecked_add(4 + u64::from(i) * 2))
                    .unwrap();
            }
            mem.write_obj::<u16>(count, queue.avail_ring.unchecked_add(2))
                .unwrap();

            let shared = |base, size| {
                Arc::new(MappedSharedMemory::new(
                    mem.clone(),
                    SharedMemoryRequirement {
                        range: AddressRange { base, size },
                        access: SharedAccess::ReadWrite,
                    },
                ))
            };
            Self {
                queue_memory: Arc::new(SharedQueueMemory::new(vec![shared(0x100, 0x3000)])),
                buffer_memory: Arc::new(SharedVirtioMemory::new(vec![shared(BUFFER_BASE, 0x2000)])),
                queue: Arc::new(Mutex::new(queue)),
                mem,
                buffer_base: BUFFER_BASE,
                len,
            }
        }

        /// Fill chain `i`'s buffer with guest → host bytes.
        fn put(&self, i: u64, bytes: &[u8]) {
            self.mem
                .write_slice(
                    bytes,
                    GuestAddress(self.buffer_base + i * u64::from(self.len)),
                )
                .unwrap();
        }

        /// Read back what the device wrote into chain `i`'s buffer.
        fn get(&self, i: u64, len: usize) -> Vec<u8> {
            let mut out = vec![0u8; len];
            Bytes::read(
                &self.mem,
                &mut out,
                GuestAddress(self.buffer_base + i * u64::from(self.len)),
            )
            .unwrap();
            out
        }

        fn used_idx(&self) -> u16 {
            self.queue_memory
                .read_u16(GuestAddress(0x2002))
                .expect("used idx")
        }
    }

    #[test]
    fn tx_buffers_keep_one_message_per_chain() {
        // The control queue is framed: two guest writes must not be glued
        // into one buffer the way raw console output legitimately is.
        let tq = TestQueue::new(2, 16, false);
        tq.put(
            0,
            &ControlMessage::new(0, control::event::DEVICE_READY, 1).encode(),
        );
        tq.put(
            1,
            &ControlMessage::new(1, control::event::PORT_READY, 1).encode(),
        );

        let buffers = drain_tx_buffers(&tq.queue_memory, &tq.buffer_memory, &tq.queue, None);
        assert_eq!(buffers.len(), 2, "chains must stay separate messages");
        assert_eq!(
            ControlMessage::decode(&buffers[0]).unwrap().event,
            control::event::DEVICE_READY
        );
        assert_eq!(
            ControlMessage::decode(&buffers[1]).unwrap().event,
            control::event::PORT_READY
        );
        assert_eq!(tq.used_idx(), 2, "both chains completed");
    }

    #[test]
    fn push_to_queue_writes_one_message_per_chain() {
        let tq = TestQueue::new(2, 16, true);
        let first = ControlMessage::port_name(1, "build").encode();
        assert!(push_to_queue(
            &tq.queue_memory,
            &tq.buffer_memory,
            &tq.queue,
            &first,
            None
        ));
        assert_eq!(tq.get(0, first.len()), first);
        assert_eq!(tq.used_idx(), 1);

        let second = ControlMessage::new(1, control::event::PORT_OPEN, 1).encode();
        assert!(push_to_queue(
            &tq.queue_memory,
            &tq.buffer_memory,
            &tq.queue,
            &second,
            None
        ));
        assert_eq!(tq.get(1, second.len()), second);
        assert_eq!(tq.used_idx(), 2);

        // Third message, no buffer left: the caller keeps it and retries.
        assert!(
            !push_to_queue(
                &tq.queue_memory,
                &tq.buffer_memory,
                &tq.queue,
                &second,
                None
            ),
            "an empty avail ring must not consume the message"
        );
        assert_eq!(tq.used_idx(), 2, "nothing was completed");
    }

    /// A control plane whose messages have nowhere to go must hold them, not
    /// drop them — the guest posts its receiveq buffers after DEVICE_READY.
    #[test]
    fn control_messages_survive_an_empty_receiveq() {
        let tq = TestQueue::new(0, 16, true);
        let plane = control::ControlPlane::new(vec![
            control::PortKind::Console,
            control::PortKind::Named("build".into()),
        ]);
        plane.handle(&ControlMessage::new(0, control::event::DEVICE_READY, 1));

        let msg = plane.pop_outbound().expect("PORT_ADD queued");
        assert!(!push_to_queue(
            &tq.queue_memory,
            &tq.buffer_memory,
            &tq.queue,
            &msg.encode(),
            None
        ));
        plane.requeue(msg.clone());
        assert_eq!(plane.pop_outbound(), Some(msg));
    }

    // --- named-port workers ---

    #[cfg(unix)]
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    // Only the Unix worker tests drive a worker to completion; the rest of
    // the named-port tests are host-agnostic.
    #[cfg(unix)]
    fn token(stop: &Arc<AtomicBool>) -> VirtioRunToken {
        let stop = Arc::clone(stop);
        VirtioRunToken::from_fn(move || stop.load(Ordering::Acquire))
    }

    fn liveness(id: u32, open: usize, plane: &Arc<control::ControlPlane>) -> Arc<PortLiveness> {
        Arc::new(PortLiveness {
            id,
            open_directions: std::sync::atomic::AtomicUsize::new(open),
            control: Arc::clone(plane),
        })
    }

    fn plane_with_one_named_port() -> Arc<control::ControlPlane> {
        Arc::new(control::ControlPlane::new(vec![
            control::PortKind::Console,
            control::PortKind::Named("build".into()),
        ]))
    }

    /// Host → guest: bytes written to the pipe land in the guest's buffer, and
    /// closing the host end finishes the worker and closes the port.
    #[cfg(unix)]
    #[test]
    fn port_rx_worker_moves_bytes_then_closes_on_eof() {
        use std::os::fd::IntoRawFd;

        let _fds = pipe::fd_table_lock();

        let (read_end, write_end) = nix::unistd::pipe().expect("pipe");
        nix::unistd::write(&write_end, b"hello").expect("host write");
        let end = pipe::PipeEnd::adopt("build", pipe::Direction::Rx, read_end.into_raw_fd() as u64)
            .expect("adopt");

        let tq = TestQueue::new(1, 16, true);
        let plane = plane_with_one_named_port();
        // The device holds host -> guest bytes until a guest process opens the
        // port, so tell the plane the guest did.
        plane.handle(&ControlMessage::new(1, control::event::PORT_OPEN, 1));
        let live = liveness(1, 1, &plane);
        let stop = Arc::new(AtomicBool::new(false));

        // Close the host end so the worker drains, reports the close, and
        // returns on its own rather than waiting for shutdown.
        drop(write_end);
        port_rx_worker(
            &end,
            &live,
            &tq.queue_memory,
            &tq.buffer_memory,
            tq.queue.lock().expect("queue").clone(),
            None,
            &token(&stop),
        );

        assert_eq!(tq.get(0, 5), b"hello");
        assert_eq!(
            plane.pop_outbound(),
            Some(ControlMessage::new(1, control::event::PORT_OPEN, 0)),
            "the guest must be told the host side closed"
        );
    }

    /// Guest → host: the guest's queued bytes reach the pipe.
    #[cfg(unix)]
    #[test]
    fn port_tx_worker_writes_guest_bytes_to_the_pipe() {
        use std::os::fd::IntoRawFd;

        let _fds = pipe::fd_table_lock();

        let (read_end, write_end) = nix::unistd::pipe().expect("pipe");
        let end =
            pipe::PipeEnd::adopt("build", pipe::Direction::Tx, write_end.into_raw_fd() as u64)
                .expect("adopt");

        let tq = TestQueue::new(1, 16, false);
        tq.put(0, b"from guest\0\0\0\0\0\0");

        let plane = plane_with_one_named_port();
        let live = liveness(1, 1, &plane);
        let stop = Arc::new(AtomicBool::new(false));
        let queue = tq.queue.lock().expect("queue").clone();

        let stopper = Arc::clone(&stop);
        let reader = thread::spawn(move || {
            let mut buf = [0u8; 16];
            let n = nix::unistd::read(&read_end, &mut buf).expect("host read");
            stopper.store(true, Ordering::Release);
            buf[..n].to_vec()
        });

        port_tx_worker(
            &end,
            &live,
            &tq.queue_memory,
            &tq.buffer_memory,
            queue,
            None,
            &token(&stop),
        );

        assert_eq!(reader.join().expect("reader"), b"from guest\0\0\0\0\0\0");
    }

    /// A uni-directional port is reported closed as soon as its one direction
    /// goes away — there is no second direction to wait for.
    #[test]
    fn uni_directional_port_closes_with_its_only_direction() {
        let plane = plane_with_one_named_port();
        let live = liveness(1, 1, &plane);
        assert_eq!(live.open_directions.load(Ordering::Acquire), 1);

        live.direction_closed(pipe::Direction::Rx);
        assert_eq!(
            plane.pop_outbound(),
            Some(ControlMessage::new(1, control::event::PORT_OPEN, 0))
        );
    }

    /// A bi-directional port stays open to the guest until *both* its
    /// directions have gone away.
    #[test]
    fn port_closes_only_after_every_direction_is_gone() {
        let plane = plane_with_one_named_port();
        let live = liveness(1, 2, &plane);

        live.direction_closed(pipe::Direction::Rx);
        assert!(
            plane.pop_outbound().is_none(),
            "one closed direction must not close the port"
        );

        live.direction_closed(pipe::Direction::Tx);
        assert_eq!(
            plane.pop_outbound(),
            Some(ControlMessage::new(1, control::event::PORT_OPEN, 0))
        );
    }
}
