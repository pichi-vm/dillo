// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! In-process virtio-blk device implementing [`VirtioDevice`].
//!
//! Ported from the dillo PoC's out-of-process vhost-user backend
//! (`dillo-virtio-blk`, `VhostUserBackendMut`) to the new in-process device
//! model. The data source is abstracted behind the [`BlockBacking`] trait —
//! [`RawImageBacking`] (this crate) is the single-file raw-image path; the
//! `dillo-virtio-gpt` crate provides a synthesized-GPT backing over multiple
//! files. Both present as a standard virtio-blk device to the guest.
//!
//! The transport (virtio-pci or virtio-mmio) wraps this device, handles
//! config-space + queue setup, and calls [`VirtioBlk::activate`] once the guest
//! writes `DRIVER_OK`. We then spawn a single request worker that blocks on the
//! queue [`Kick`] and services `VIRTIO_BLK_T_IN`/`OUT`/`FLUSH`/`GET_ID`.
//!
//! Single request queue (no `VIRTIO_BLK_F_MQ`). Seccomp / process-isolation
//! from the PoC is intentionally not ported: the worker runs as a thread inside
//! the VMM process, so a per-process syscall filter is not applicable.

use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};

use dillo_mmio::Interrupt;
use dillo_virtio::queue::{Queue, QueueMemory, VIRTQ_DESC_F_WRITE};
use dillo_virtio::{
    ActivateError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle, VirtioDeviceHost,
    VirtioMemory, VirtioRunToken,
};
use vm_memory::GuestAddress;

/// Cross-platform positional read (`pread`/`seek_read`).
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}

/// Cross-platform positional write (`pwrite`/`seek_write`).
fn write_at(file: &File, buf: &[u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_write(file, buf, offset)
    }
}

/// VIRTIO_F_VERSION_1 from the virtio 1.x spec.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Virtio device-type id for a block device (virtio 1.x §5.2).
pub const VIRTIO_ID_BLOCK: u32 = 2;

/// Sector size in bytes.
const SECTOR_SIZE: u64 = 512;

/// Request queue max size (negotiated down by the guest).
const QUEUE_MAX: u16 = 256;
const QUEUE_SIZES: [u16; 1] = [QUEUE_MAX];

// --- Block feature bits (virtio 1.1 §5.2.3) --------------------------------

/// `seg_max` field in config space is valid (bit 2).
const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
/// Device is read-only (bit 5).
const VIRTIO_BLK_F_RO: u64 = 1 << 5;
/// `blk_size` field in config space is valid (bit 6).
const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
/// Flush command supported (bit 9).
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
/// `topology` + `opt_io_size` fields in config space are valid (bit 10).
const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;

// --- Request types ---------------------------------------------------------

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;

// --- Status bytes ----------------------------------------------------------

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// ---------------------------------------------------------------------------
// BlockBacking trait (ported verbatim from the PoC Phase 45 BACKING-01)
// ---------------------------------------------------------------------------

/// Sync, RO-by-construction abstraction over the data source behind a virtio-blk
/// device.
///
/// - `&self` only (no `&mut self`): the trait object is shared via `Arc`.
/// - NO `write_at` method — RO-by-construction. The raw-image write path flows
///   through a separate `writable_fd` side-channel that RO backings never get,
///   so a confused-deputy write cannot reach disk.
/// - `flush()` defaults to `Ok(())` so RO impls satisfy virtio §5.2.6.2
///   (`T_FLUSH` on a `VIRTIO_BLK_F_RO` device returns `S_OK` with no work).
pub trait BlockBacking: Send + Sync {
    /// Total length in BYTES (not sectors). Capacity = `len_bytes / SECTOR_SIZE`.
    fn len_bytes(&self) -> u64;

    /// `pread(2)`-style read. Returns `Ok(n)` where `n <= buf.len()`. Short
    /// reads are permitted; the caller advances by `n`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Flush in-flight writes. Default `Ok(())` for RO backings.
    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// 20-byte serial returned to the guest by `VIRTIO_BLK_T_GET_ID`. Stable
    /// across process lifetime.
    fn get_id(&self) -> [u8; 20];

    /// True if the backing rejects writes structurally (RO-by-construction).
    fn is_read_only(&self) -> bool;

    /// Logical block size in bytes (the smallest unit the device will accept).
    /// Default `512`. Surfaced via `VIRTIO_BLK_F_BLK_SIZE` at config offset 20.
    /// Implementations MUST return a power of two `<= physical_block_size`.
    fn logical_block_size(&self) -> u32 {
        512
    }

    /// Physical block size in bytes. Default `512`. When it differs from
    /// `logical_block_size`, `VIRTIO_BLK_F_TOPOLOGY` is negotiated and
    /// `physical_block_exp = log2(physical / logical)` is exposed at offset 24.
    /// Implementations MUST return a power-of-two multiple of
    /// `logical_block_size`.
    fn physical_block_size(&self) -> u32 {
        512
    }

    /// Optional max segments per request. `None` (default) means
    /// `VIRTIO_BLK_F_SEG_MAX` is NOT advertised; `Some(n)` advertises it and
    /// exposes `seg_max = n` at config offset 12.
    fn max_segments(&self) -> Option<u32> {
        None
    }
}

// ---------------------------------------------------------------------------
// RawImageBacking — single-file raw image (ported verbatim)
// ---------------------------------------------------------------------------

/// [`BlockBacking`] backed by a single raw-image file. Writes (when the device
/// is not read-only) flow through the separate `writable_fd` held by
/// [`VirtioBlk`], not through this trait.
#[derive(Debug)]
pub struct RawImageBacking {
    backing_fd: File,
    len_bytes: u64,
}

impl RawImageBacking {
    /// Create a `RawImageBacking` from an open `File`, pre-computing `len_bytes`
    /// from its metadata.
    pub fn new(file: File) -> Self {
        let len_bytes = file.metadata().map_or(0, |m| m.len());
        let backing_fd = file;
        Self {
            backing_fd,
            len_bytes,
        }
    }
}

impl BlockBacking for RawImageBacking {
    fn len_bytes(&self) -> u64 {
        self.len_bytes
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        read_at(&self.backing_fd, buf, offset)
    }

    fn flush(&self) -> std::io::Result<()> {
        // Raw-image is writable; fdatasync is meaningful.
        self.backing_fd.sync_data()
    }

    fn get_id(&self) -> [u8; 20] {
        // Preserve PoC behavior: raw image has no inherent identity; the guest's
        // blkid falls back to UUID/by-path probing.
        [0u8; 20]
    }

    fn is_read_only(&self) -> bool {
        // The raw-image backing supports writes; the read-only CLI flag is
        // honored by VirtioBlk's `read_only` gate + the absence of `writable_fd`.
        false
    }
}

// ---------------------------------------------------------------------------
// VirtioBlk — the VirtioDevice
// ---------------------------------------------------------------------------

/// In-process virtio-blk device.
pub struct VirtioBlk {
    backing: Arc<dyn BlockBacking>,
    /// Writable fd for the raw-image path; `None` for RO backings. A guest
    /// write is rejected if EITHER `read_only` is true OR this is `None`.
    writable_fd: Option<Arc<File>>,
    /// Capacity in 512-byte sectors.
    capacity: u64,
    read_only: bool,
    logical_block_size: u32,
    physical_block_size: u32,
    max_segments: Option<u32>,
    activated: bool,
}

impl std::fmt::Debug for VirtioBlk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioBlk")
            .field("capacity", &self.capacity)
            .field("read_only", &self.read_only)
            .field("logical_block_size", &self.logical_block_size)
            .field("physical_block_size", &self.physical_block_size)
            .field("max_segments", &self.max_segments)
            .field("activated", &self.activated)
            .finish_non_exhaustive()
    }
}

impl VirtioBlk {
    /// Build a `VirtioBlk` from a [`BlockBacking`] trait object plus an optional
    /// writable fd (raw-image only) and the read-only flag. Topology values are
    /// captured at construction so the hot config-space path avoids vtable
    /// dispatch.
    pub fn new(
        backing: Arc<dyn BlockBacking>,
        writable_fd: Option<Arc<File>>,
        read_only: bool,
    ) -> Self {
        let capacity = backing.len_bytes() / SECTOR_SIZE;
        let logical_block_size = backing.logical_block_size();
        let physical_block_size = backing.physical_block_size();
        let max_segments = backing.max_segments();
        Self {
            backing,
            writable_fd,
            capacity,
            read_only,
            logical_block_size,
            physical_block_size,
            max_segments,
            activated: false,
        }
    }

    /// Open a raw-image file and build a `VirtioBlk` over it. When `read_only`
    /// is false the disk is opened read-write and a duplicated fd is retained
    /// for the write path.
    pub fn open_raw(path: &Path, read_only: bool) -> std::io::Result<Self> {
        let file = if read_only {
            File::open(path)?
        } else {
            File::options().read(true).write(true).open(path)?
        };
        // For the writable path, dup the fd so the backing and the write
        // side-channel can both hold one (both inherit the open-mode flags).
        let writable_fd: Option<Arc<File>> = if read_only {
            None
        } else {
            Some(Arc::new(file.try_clone()?))
        };
        let backing: Arc<dyn BlockBacking> = Arc::new(RawImageBacking::new(file));
        Ok(Self::new(backing, writable_fd, read_only))
    }

    /// Materialize the first 32 bytes of `virtio_blk_config` (virtio 1.1
    /// §5.2.4), then copy the requested `offset..offset+len` range out. Bytes
    /// outside populated fields stay zero (also spec-correct for fields gated by
    /// un-negotiated features).
    fn read_config_bytes(&self, offset: u64, data: &mut [u8]) {
        let mut config = [0u8; 32];

        // capacity @ 0..8 (le64) — always populated (in 512-byte sectors).
        config[0..8].copy_from_slice(&self.capacity.to_le_bytes());

        // seg_max @ 12..16 (le32) — populated iff F_SEG_MAX negotiated.
        if let Some(seg_max) = self.max_segments {
            config[12..16].copy_from_slice(&seg_max.to_le_bytes());
        }

        // blk_size @ 20..24 (le32) — always populated (F_BLK_SIZE always set).
        config[20..24].copy_from_slice(&self.logical_block_size.to_le_bytes());

        // topology @ 24..28 + opt_io_size @ 28..32 — populated iff F_TOPOLOGY.
        if self.physical_block_size != self.logical_block_size {
            let ratio = self.physical_block_size / self.logical_block_size;
            // physical_block_exp @ 24 (u8) = log2(physical / logical).
            config[24] = ratio.trailing_zeros() as u8;
            // min_io_size @ 26..28 (le16) — 1 logical block.
            config[26..28].copy_from_slice(&1u16.to_le_bytes());
            // opt_io_size @ 28..32 (le32) — physical/logical in logical blocks.
            config[28..32].copy_from_slice(&ratio.to_le_bytes());
        }

        for (i, byte) in data.iter_mut().enumerate() {
            let config_offset = offset as usize + i;
            *byte = config.get(config_offset).copied().unwrap_or(0);
        }
    }
}

impl VirtioDevice for VirtioBlk {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_BLOCK
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        // Always advertise BLK_SIZE so guests see the explicit logical block
        // size. TOPOLOGY iff physical != logical. SEG_MAX iff max_segments set.
        let mut features = VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH | VIRTIO_BLK_F_BLK_SIZE;
        if self.read_only {
            features |= VIRTIO_BLK_F_RO;
        }
        if self.physical_block_size != self.logical_block_size {
            features |= VIRTIO_BLK_F_TOPOLOGY;
        }
        if self.max_segments.is_some() {
            features |= VIRTIO_BLK_F_SEG_MAX;
        }
        features
    }

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        if self.activated {
            return Err(ActivateError::InvalidConfig(
                "VirtioBlk::activate called twice".into(),
            ));
        }
        let queue_memory = activation.queue_memory();
        let buffer_memory = activation.buffer_memory();
        let mut queues = activation.take_queues();
        let mut queue_evts = activation.take_queue_evts();
        let host = activation.host()?;
        if queues.len() != 1 || queue_evts.len() != 1 {
            return Err(ActivateError::InvalidConfig(format!(
                "virtio-blk expects 1 queue + 1 evt, got {} / {}",
                queues.len(),
                queue_evts.len()
            )));
        }

        let call_interrupt = activation.queue_interrupt(0);
        let queue = queues.remove(0);
        let evt = queue_evts.remove(0);
        let wake = evt.try_clone()?;

        let backing = Arc::clone(&self.backing);
        let writable_fd = self.writable_fd.clone();
        let read_only = self.read_only;

        let handle = Arc::new(Mutex::new(Some(spawn_request_worker(
            host,
            queue_memory,
            buffer_memory,
            queue,
            evt,
            call_interrupt,
            backing,
            writable_fd,
            read_only,
        )?)));
        let shutdown_handle = Arc::clone(&handle);

        self.activated = true;
        log::info!(
            "virtio-blk: activated (capacity={} sectors, read_only={})",
            self.capacity,
            self.read_only
        );
        Ok(VirtioDeviceHandle::new(
            move || {
                if let Some(handle) = shutdown_handle
                    .lock()
                    .expect("virtio-blk handle poisoned")
                    .as_mut()
                {
                    handle.shutdown();
                }
                let _ = wake.write(1);
            },
            move || {
                if let Some(handle) = handle.lock().expect("virtio-blk handle poisoned").take() {
                    handle.join()?;
                }
                Ok(())
            },
        ))
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_bytes(offset, data);
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // virtio_blk_config is read-only from the guest.
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_request_worker(
    host: Arc<dyn VirtioDeviceHost>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
    backing: Arc<dyn BlockBacking>,
    writable_fd: Option<Arc<File>>,
    read_only: bool,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        request_worker(
            queue_memory,
            buffer_memory,
            queue,
            kick,
            call_interrupt,
            backing,
            writable_fd,
            read_only,
            token,
        );
        Ok(())
    }))
}

#[allow(clippy::too_many_arguments)]
fn request_worker(
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
    backing: Arc<dyn BlockBacking>,
    writable_fd: Option<Arc<File>>,
    read_only: bool,
    token: VirtioRunToken,
) {
    let queue = Arc::new(Mutex::new(queue));
    loop {
        if let Err(e) = kick.read() {
            log::error!("virtio-blk: kick read error: {e}");
            return;
        }
        if token.is_shutdown_requested() {
            return;
        }
        drain_requests(
            &queue_memory,
            &buffer_memory,
            &queue,
            call_interrupt.as_ref(),
            backing.as_ref(),
            writable_fd.as_deref(),
            read_only,
        );
    }
}

/// One descriptor in a request chain: (guest address, byte length).
type Desc = (GuestAddress, u32);

fn drain_requests(
    queue_memory: &Arc<dyn QueueMemory>,
    buffer_memory: &Arc<dyn VirtioMemory>,
    queue: &Arc<Mutex<Queue>>,
    call_interrupt: Option<&Interrupt>,
    backing: &dyn BlockBacking,
    writable_fd: Option<&File>,
    read_only: bool,
) {
    let mut q = queue.lock().expect("virtio-blk queue mutex");
    let mut signaled = false;
    while let Some(head) = q.pop(queue_memory) {
        let head_index = head.index;

        // Split the chain into device-readable and device-writable descriptors.
        let mut readable: Vec<Desc> = Vec::new();
        let mut writable: Vec<Desc> = Vec::new();
        let mut current = Some(head);
        while let Some(desc) = current {
            if desc.flags & VIRTQ_DESC_F_WRITE != 0 {
                writable.push((desc.addr, desc.len));
            } else {
                readable.push((desc.addr, desc.len));
            }
            current = desc.next_desc(queue_memory);
        }

        if readable.is_empty() || writable.is_empty() {
            log::warn!("virtio-blk: malformed descriptor chain (no readable or writable)");
            q.add_used(queue_memory, head_index, 0);
            signaled = true;
            continue;
        }

        let (status, used_len) = process_request(
            buffer_memory,
            &readable,
            &writable,
            backing,
            writable_fd,
            read_only,
        );

        // Status byte goes to the last writable descriptor.
        let (status_addr, status_len) = writable[writable.len() - 1];
        if status_len >= 1 {
            let _ = buffer_memory.write(status_addr, &[status]);
        }
        q.add_used(queue_memory, head_index, used_len + 1);
        signaled = true;
    }
    if signaled && let Some(intr) = call_interrupt {
        intr.signal();
    }
}

fn process_request(
    buffer_memory: &Arc<dyn VirtioMemory>,
    readable: &[Desc],
    writable: &[Desc],
    backing: &dyn BlockBacking,
    writable_fd: Option<&File>,
    read_only: bool,
) -> (u8, u32) {
    // Request header is the first readable descriptor (16 bytes).
    let (hdr_addr, hdr_len) = readable[0];
    if (hdr_len as usize) < 16 {
        return (VIRTIO_BLK_S_IOERR, 0);
    }
    let mut hdr = [0u8; 16];
    if buffer_memory.read(hdr_addr, &mut hdr).is_err() {
        return (VIRTIO_BLK_S_IOERR, 0);
    }
    let request_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let sector = u64::from_le_bytes([
        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
    ]);

    match request_type {
        VIRTIO_BLK_T_IN => {
            // Read: data goes into the writable descriptors before the status.
            let data = &writable[..writable.len() - 1];
            handle_read(buffer_memory, data, sector, backing)
        }
        VIRTIO_BLK_T_OUT => {
            // Write: data is in the readable descriptors after the header.
            handle_write(
                buffer_memory,
                &readable[1..],
                sector,
                writable_fd,
                read_only,
            )
        }
        VIRTIO_BLK_T_FLUSH => match backing.flush() {
            Ok(()) => (VIRTIO_BLK_S_OK, 0),
            Err(_) => (VIRTIO_BLK_S_IOERR, 0),
        },
        VIRTIO_BLK_T_GET_ID => handle_get_id(buffer_memory, writable, backing),
        _ => (VIRTIO_BLK_S_UNSUPP, 0),
    }
}

fn handle_read(
    buffer_memory: &Arc<dyn VirtioMemory>,
    data: &[Desc],
    sector: u64,
    backing: &dyn BlockBacking,
) -> (u8, u32) {
    let mut offset = sector * SECTOR_SIZE;
    let mut total_written = 0u32;
    for &(addr, len) in data {
        let mut buf = vec![0u8; len as usize];
        let Ok(bytes_read) = backing.read_at(offset, &mut buf) else {
            return (VIRTIO_BLK_S_IOERR, 0);
        };
        if buffer_memory.write(addr, &buf[..bytes_read]).is_err() {
            return (VIRTIO_BLK_S_IOERR, 0);
        }
        offset += bytes_read as u64;
        total_written += bytes_read as u32;
    }
    (VIRTIO_BLK_S_OK, total_written)
}

fn handle_write(
    buffer_memory: &Arc<dyn VirtioMemory>,
    data: &[Desc],
    sector: u64,
    writable_fd: Option<&File>,
    read_only: bool,
) -> (u8, u32) {
    // Defense-in-depth: reject if read-only OR no writable fd (RO backing).
    if read_only {
        return (VIRTIO_BLK_S_IOERR, 0);
    }
    let Some(fd) = writable_fd else {
        return (VIRTIO_BLK_S_IOERR, 0);
    };
    let mut offset = sector * SECTOR_SIZE;
    for &(addr, len) in data {
        let mut buf = vec![0u8; len as usize];
        if buffer_memory.read(addr, &mut buf).is_err() {
            return (VIRTIO_BLK_S_IOERR, 0);
        }
        let Ok(written) = write_at(fd, &buf, offset) else {
            return (VIRTIO_BLK_S_IOERR, 0);
        };
        offset += written as u64;
    }
    (VIRTIO_BLK_S_OK, 0)
}

fn handle_get_id(
    buffer_memory: &Arc<dyn VirtioMemory>,
    writable: &[Desc],
    backing: &dyn BlockBacking,
) -> (u8, u32) {
    // The id buffer is the first writable descriptor; the last is the status
    // byte. Need at least one data descriptor distinct from status.
    if writable.len() < 2 {
        return (VIRTIO_BLK_S_IOERR, 0);
    }
    let (addr, len) = writable[0];
    if (len as usize) < 20 {
        return (VIRTIO_BLK_S_IOERR, 0);
    }
    let id = backing.get_id();
    if buffer_memory.write(addr, &id).is_err() {
        return (VIRTIO_BLK_S_IOERR, 0);
    }
    (VIRTIO_BLK_S_OK, 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use dillo_virtio::queue::VIRTQ_DESC_F_NEXT;
    use dillo_virtio::{SharedQueueMemory, SharedVirtioMemory};
    use vm_memory::{Address, Bytes, GuestMemoryMmap};

    /// In-RAM backing that serves bytes from a fixed buffer, for dispatch tests.
    struct RamBacking {
        data: Vec<u8>,
        read_only: bool,
    }

    impl RamBacking {
        fn new(data: Vec<u8>, read_only: bool) -> Self {
            Self { data, read_only }
        }
    }

    impl BlockBacking for RamBacking {
        fn len_bytes(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = offset as usize;
            if off >= self.data.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        }
        fn get_id(&self) -> [u8; 20] {
            *b"ram-backing-test-id\0"
        }
        fn is_read_only(&self) -> bool {
            self.read_only
        }
    }

    // --- Pure config / feature tests (ported from the PoC) -----------------

    fn blk_from(
        len_bytes: u64,
        logical: u32,
        physical: u32,
        max_segments: Option<u32>,
        read_only: bool,
    ) -> VirtioBlk {
        struct M {
            len_bytes: u64,
            logical: u32,
            physical: u32,
            max_segments: Option<u32>,
            read_only: bool,
        }
        impl BlockBacking for M {
            fn len_bytes(&self) -> u64 {
                self.len_bytes
            }
            fn read_at(&self, _o: u64, _b: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
            fn get_id(&self) -> [u8; 20] {
                [0u8; 20]
            }
            fn is_read_only(&self) -> bool {
                self.read_only
            }
            fn logical_block_size(&self) -> u32 {
                self.logical
            }
            fn physical_block_size(&self) -> u32 {
                self.physical
            }
            fn max_segments(&self) -> Option<u32> {
                self.max_segments
            }
        }
        VirtioBlk::new(
            Arc::new(M {
                len_bytes,
                logical,
                physical,
                max_segments,
                read_only,
            }),
            None,
            read_only,
        )
    }

    #[test]
    fn features_default_backing_minimal() {
        let blk = blk_from(1024 * 1024, 512, 512, None, false);
        let expected = VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH | VIRTIO_BLK_F_BLK_SIZE;
        assert_eq!(blk.features(), expected);
    }

    #[test]
    fn features_ro_sets_ro_bit() {
        let blk = blk_from(1024 * 1024, 512, 512, None, true);
        assert_ne!(blk.features() & VIRTIO_BLK_F_RO, 0);
    }

    #[test]
    fn features_vgpt_style_sets_topology_and_seg_max() {
        let blk = blk_from(1024 * 1024, 512, 4096, Some(254), true);
        let expected = VIRTIO_F_VERSION_1
            | VIRTIO_BLK_F_FLUSH
            | VIRTIO_BLK_F_BLK_SIZE
            | VIRTIO_BLK_F_RO
            | VIRTIO_BLK_F_TOPOLOGY
            | VIRTIO_BLK_F_SEG_MAX;
        assert_eq!(blk.features(), expected);
    }

    #[test]
    fn read_config_vgpt_layout() {
        let blk = blk_from(1024 * 1024, 512, 4096, Some(254), true);
        let capacity = 1024u64 * 1024 / SECTOR_SIZE;
        let mut buf = [0u8; 32];
        blk.read_config_bytes(0, &mut buf);
        assert_eq!(&buf[0..8], &capacity.to_le_bytes());
        assert_eq!(&buf[12..16], &254u32.to_le_bytes());
        assert_eq!(&buf[20..24], &512u32.to_le_bytes());
        assert_eq!(buf[24], 3); // log2(4096/512)
        assert_eq!(&buf[26..28], &1u16.to_le_bytes());
        assert_eq!(&buf[28..32], &8u32.to_le_bytes());
    }

    #[test]
    fn read_config_default_writes_capacity_and_blk_size_only() {
        let blk = blk_from(1024 * 1024, 512, 512, None, false);
        let capacity = 1024u64 * 1024 / SECTOR_SIZE;
        let mut buf = [0u8; 32];
        blk.read_config_bytes(0, &mut buf);
        assert_eq!(&buf[0..8], &capacity.to_le_bytes());
        assert_eq!(&buf[8..20], &[0u8; 12]);
        assert_eq!(&buf[20..24], &512u32.to_le_bytes());
        assert_eq!(&buf[24..32], &[0u8; 8]);
    }

    // --- Queue dispatch test (T_IN read) -----------------------------------

    /// Drive a single read request through `drain_requests` against a RAM
    /// backing, asserting the data lands in the guest data buffer and the status
    /// byte is S_OK. Memory layout mirrors the console crate's queue tests.
    #[test]
    fn read_request_fills_buffer_and_sets_status_ok() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        // Descriptor table at 0x100; 3 descriptors (header, data, status).
        let desc = GuestAddress(0x100);
        let avail = GuestAddress(0x1000);
        let used = GuestAddress(0x2000);
        let header_buf = GuestAddress(0x5000);
        let data_buf = GuestAddress(0x6000);
        let status_buf = GuestAddress(0x7000);

        // Request header: type=IN(0), reserved=0, sector=1.
        let mut hdr = [0u8; 16];
        hdr[8..16].copy_from_slice(&1u64.to_le_bytes());
        mem.write_slice(&hdr, header_buf).unwrap();

        // desc[0]: header, readable, NEXT->1
        write_desc(&mem, desc, 0, header_buf.0, 16, VIRTQ_DESC_F_NEXT, 1);
        // desc[1]: data, writable, NEXT->2
        write_desc(
            &mem,
            desc,
            1,
            data_buf.0,
            512,
            VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            2,
        );
        // desc[2]: status, writable, end
        write_desc(&mem, desc, 2, status_buf.0, 1, VIRTQ_DESC_F_WRITE, 0);

        // avail ring: ring[0]=0 (head desc index), idx=1
        mem.write_obj::<u16>(0, avail.unchecked_add(4)).unwrap();
        mem.write_obj::<u16>(1, avail.unchecked_add(2)).unwrap();

        let shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0,
                    size: 0x10000,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        let queue_memory: Arc<dyn QueueMemory> =
            Arc::new(SharedQueueMemory::new(vec![shared.clone()]));
        let buffer_memory: Arc<dyn VirtioMemory> = Arc::new(SharedVirtioMemory::new(vec![shared]));

        let mut q = Queue::new(16);
        q.size = 16;
        q.ready = true;
        q.desc_table = desc;
        q.avail_ring = avail;
        q.used_ring = used;
        let q = Arc::new(Mutex::new(q));

        // Backing: sector 1 (offset 512) holds 0xAB repeated.
        let mut data = vec![0u8; 4096];
        for b in &mut data[512..1024] {
            *b = 0xAB;
        }
        let backing = RamBacking::new(data, false);

        drain_requests(
            &queue_memory,
            &buffer_memory,
            &q,
            None,
            &backing,
            None,
            false,
        );

        // Guest data buffer filled with backing bytes.
        let mut out = [0u8; 512];
        mem.read_slice(&mut out, data_buf).unwrap();
        assert!(out.iter().all(|&b| b == 0xAB), "data buffer not filled");

        // Status byte = S_OK.
        let status: u8 = mem.read_obj(status_buf).unwrap();
        assert_eq!(status, VIRTIO_BLK_S_OK);

        // used ring: idx=1, used[0].len = 512 (data) + 1 (status).
        let used_idx: u16 = mem.read_obj(used.unchecked_add(2)).unwrap();
        assert_eq!(used_idx, 1);
        let used_len: u32 = mem.read_obj(used.unchecked_add(8)).unwrap();
        assert_eq!(used_len, 513);
    }

    fn write_desc(
        mem: &GuestMemoryMmap,
        table: GuestAddress,
        idx: u64,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let base = table.unchecked_add(idx * 16);
        mem.write_obj::<u64>(addr, base).unwrap();
        mem.write_obj::<u32>(len, base.unchecked_add(8)).unwrap();
        mem.write_obj::<u16>(flags, base.unchecked_add(12)).unwrap();
        mem.write_obj::<u16>(next, base.unchecked_add(14)).unwrap();
    }
}
