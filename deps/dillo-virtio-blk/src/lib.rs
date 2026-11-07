// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Format-aware virtio-blk device implementing [`VirtioDevice`].
//!
//! A [`BlockBacking`] session supplies reads and optional mutation authority for
//! raw, qcow2, or synthesized GPT storage. The transport (PCI or MMIO) supplies
//! negotiated features and activates one request worker through the host boundary.
//! Requests support read, write, flush, get-id and discard as
//! advertised by the backing. Process isolation and confinement are host-backend
//! responsibilities; see the repository's design rules and qualification gates.

use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};

use dillo_mmio::Interrupt;
use dillo_virtio::queue::{Queue, QueueMemory, VIRTQ_DESC_F_WRITE};
use dillo_virtio::{
    ActivateError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle, VirtioDeviceHost,
    VirtioMemory, VirtioRunToken,
};
use vm_memory::{Address, GuestAddress};

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
const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;
const MAX_RANGES: usize = 32;
const MAX_RANGE_SECTORS: u32 = 65536;
const MAX_TRANSFER: usize = 16 * 1024 * 1024;

// --- Request types ---------------------------------------------------------

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;
const VIRTIO_BLK_T_DISCARD: u32 = 11;

// --- Status bytes ----------------------------------------------------------

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// ---------------------------------------------------------------------------
// BlockBacking storage contracts
// ---------------------------------------------------------------------------

pub use dillo_storage::{BlockBacking, WritableBlockBacking};

// ---------------------------------------------------------------------------
// RawImageBacking — single-file raw image
// ---------------------------------------------------------------------------

/// A raw-image session; read and mutation capabilities share the same file.
#[derive(Debug)]
pub struct RawImageBacking {
    backing_fd: File,
    len_bytes: u64,
    read_only: bool,
}

impl RawImageBacking {
    /// Create a `RawImageBacking` from an open `File`, pre-computing `len_bytes`
    /// from its metadata.
    pub fn new(file: File, read_only: bool) -> std::io::Result<Self> {
        let len_bytes = file.metadata()?.len();
        let backing_fd = file;
        Ok(Self {
            backing_fd,
            len_bytes,
            read_only,
        })
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
        // Read-only sessions must not require a writable handle for FLUSH.
        if self.read_only {
            Ok(())
        } else {
            self.backing_fd.sync_data()
        }
    }

    fn get_id(&self) -> [u8; 20] {
        // Preserve PoC behavior: raw image has no inherent identity; the guest's
        // blkid falls back to UUID/by-path probing.
        [0u8; 20]
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }
    fn writer(&self) -> Option<&dyn WritableBlockBacking> {
        if self.read_only { None } else { Some(self) }
    }
}

impl WritableBlockBacking for RawImageBacking {
    fn write_at(&self, mut offset: u64, mut data: &[u8]) -> std::io::Result<()> {
        if self.read_only {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > self.len_bytes)
        {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        while !data.is_empty() {
            match write_at(&self.backing_fd, data, offset) {
                Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    offset += n as u64;
                    data = &data[n..];
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VirtioBlk — the VirtioDevice
// ---------------------------------------------------------------------------

/// In-process virtio-blk device.
pub struct VirtioBlk {
    backing: Arc<dyn BlockBacking>,
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
    /// Build a device from one image session and a read-only policy. Topology values are
    /// captured at construction so the hot config-space path avoids vtable
    /// dispatch.
    pub fn new(backing: Arc<dyn BlockBacking>, read_only: bool) -> Self {
        let read_only = read_only || backing.is_read_only();
        let capacity = backing.len_bytes() / SECTOR_SIZE;
        let logical_block_size = backing.logical_block_size();
        let physical_block_size = backing.physical_block_size();
        let max_segments = backing.max_segments();
        Self {
            backing,
            capacity,
            read_only,
            logical_block_size,
            physical_block_size,
            max_segments,
            activated: false,
        }
    }

    /// Open a raw-image file and build a `VirtioBlk` over it. When `read_only`
    /// is false the disk is opened read-write.
    pub fn open_raw(path: &Path, read_only: bool) -> std::io::Result<Self> {
        let file = if read_only {
            File::open(path)?
        } else {
            File::options().read(true).write(true).open(path)?
        };
        let backing: Arc<dyn BlockBacking> = Arc::new(RawImageBacking::new(file, read_only)?);
        Ok(Self::new(backing, read_only))
    }

    fn discard_enabled(&self) -> bool {
        !self.read_only
            && self
                .backing
                .writer()
                .is_some_and(WritableBlockBacking::supports_discard)
    }

    /// Materialize the first 48 bytes of `virtio_blk_config` (virtio 1.1
    /// §5.2.4), then copy the requested `offset..offset+len` range out. Bytes
    /// outside populated fields stay zero (also spec-correct for fields gated by
    /// un-negotiated features).
    fn read_config_bytes(&self, offset: u64, data: &mut [u8]) {
        let mut config = [0u8; 48];
        if self.discard_enabled() {
            config[36..40].copy_from_slice(&MAX_RANGE_SECTORS.to_le_bytes());
            config[40..44].copy_from_slice(&(MAX_RANGES as u32).to_le_bytes());
            config[44..48].copy_from_slice(&128u32.to_le_bytes());
        }

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
        if self.discard_enabled() {
            features |= VIRTIO_BLK_F_DISCARD;
        }
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
        let read_only = self.read_only;
        let negotiated = activation.negotiated_features();

        let handle = Arc::new(Mutex::new(Some(spawn_request_worker(
            host,
            queue_memory,
            buffer_memory,
            queue,
            evt,
            call_interrupt,
            backing,
            read_only,
            negotiated,
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
    read_only: bool,
    negotiated: u64,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        request_worker(
            queue_memory,
            buffer_memory,
            queue,
            kick,
            call_interrupt,
            backing,
            read_only,
            negotiated,
            token,
        )
        .map_err(|e| dillo_virtio::DeviceJoinError::Worker(e.to_string()))
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
    read_only: bool,
    negotiated: u64,
    token: VirtioRunToken,
) -> std::io::Result<()> {
    let queue = Arc::new(Mutex::new(queue));
    loop {
        if let Err(e) = kick.read() {
            log::error!("virtio-blk: kick read error: {e}");
            return Err(e);
        }
        if token.is_shutdown_requested() {
            return backing.flush();
        }
        drain_requests(
            &queue_memory,
            &buffer_memory,
            &queue,
            call_interrupt.as_ref(),
            backing.as_ref(),
            read_only,
            negotiated,
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
    read_only: bool,
    negotiated: u64,
) {
    let mut q = queue.lock().expect("virtio-blk queue mutex");
    let mut signaled = false;
    while let Some(head) = q.pop(queue_memory) {
        let head_index = head.index;

        // Split the chain into device-readable and device-writable descriptors.
        let mut readable: Vec<Desc> = Vec::new();
        let mut writable: Vec<Desc> = Vec::new();
        let mut current = Some(head);
        let mut count = 0usize;
        let mut malformed = false;
        while let Some(desc) = current {
            count += 1;
            if count > q.size as usize {
                malformed = true;
                break;
            }
            if desc.flags & VIRTQ_DESC_F_WRITE == 0 && !writable.is_empty() {
                malformed = true;
                break;
            }
            if desc.flags & VIRTQ_DESC_F_WRITE != 0 {
                writable.push((desc.addr, desc.len));
            } else {
                readable.push((desc.addr, desc.len));
            }
            let has_next = desc.flags & dillo_virtio::queue::VIRTQ_DESC_F_NEXT != 0;
            if desc.flags & !3 != 0 {
                malformed = true;
                break;
            }
            current = desc.next_desc(queue_memory);
            if has_next && current.is_none() {
                malformed = true;
                break;
            }
        }

        if malformed || readable.is_empty() || writable.is_empty() {
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
            read_only,
            negotiated,
        );

        let (status_addr, status_len) = writable[writable.len() - 1];
        let status_written = status_len
            .checked_sub(1)
            .and_then(|n| status_addr.checked_add(u64::from(n)))
            .is_some_and(|addr| buffer_memory.write(addr, &[status]).is_ok());
        q.add_used(
            queue_memory,
            head_index,
            used_len + u32::from(status_written),
        );
        signaled = true;
    }
    if signaled && let Some(intr) = call_interrupt {
        intr.signal();
    }
}

/// Read/write a bounded scatter/gather stream, allowing fields to cross descriptors.
fn transfer(
    memory: &Arc<dyn VirtioMemory>,
    descs: &[Desc],
    mut skip: usize,
    bytes: &mut [u8],
    write: bool,
) -> std::io::Result<()> {
    let mut done = 0;
    for &(address, length) in descs {
        let length = length as usize;
        if skip >= length {
            skip -= length;
            continue;
        }
        let n = (length - skip).min(bytes.len() - done);
        let address = address
            .checked_add(skip as u64)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        let result = if write {
            memory.write(address, &bytes[done..done + n])
        } else {
            memory.read(address, &mut bytes[done..done + n])
        };
        result.map_err(|_| std::io::Error::other("Guest memory access failed"))?;
        done += n;
        skip = 0;
        if done == bytes.len() {
            return Ok(());
        }
    }
    if done == bytes.len() {
        Ok(())
    } else {
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
}
fn stream_len(descs: &[Desc]) -> Option<usize> {
    descs
        .iter()
        .try_fold(0usize, |sum, &(_, n)| sum.checked_add(n as usize))
}
fn process_request(
    memory: &Arc<dyn VirtioMemory>,
    readable: &[Desc],
    writable: &[Desc],
    backing: &dyn BlockBacking,
    read_only: bool,
    negotiated: u64,
) -> (u8, u32) {
    let failure = (VIRTIO_BLK_S_IOERR, 0);
    let Some(read_len) = stream_len(readable).filter(|n| *n >= 16 && *n <= MAX_TRANSFER + 16)
    else {
        return failure;
    };
    let Some(write_len) = stream_len(writable).filter(|n| *n >= 1 && *n <= MAX_TRANSFER + 1) else {
        return failure;
    };
    let mut header = [0; 16];
    if transfer(memory, readable, 0, &mut header, false).is_err() {
        return failure;
    }
    let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
    let sector = u64::from_le_bytes(header[8..].try_into().unwrap());
    let valid_range = |sector: u64, length: u64| {
        sector.checked_mul(512).filter(|start| {
            start
                .checked_add(length)
                .is_some_and(|end| end <= backing.len_bytes())
        })
    };
    let mutation = matches!(kind, VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_DISCARD);
    if mutation && (read_only || backing.is_read_only() || backing.writer().is_none()) {
        return failure;
    }
    let result: std::io::Result<u32> = (|| match kind {
        VIRTIO_BLK_T_IN => {
            let length = write_len - 1;
            if read_len != 16 || length % 512 != 0 {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            let start =
                valid_range(sector, length as u64).ok_or(std::io::ErrorKind::InvalidInput)?;
            let mut data = vec![0; length];
            let mut done = 0;
            while done < length {
                match backing.read_at(start + done as u64, &mut data[done..]) {
                    Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                    Ok(n) if n <= length - done => done += n,
                    Ok(_) => return Err(std::io::ErrorKind::InvalidData.into()),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            transfer(memory, writable, 0, &mut data, true)?;
            Ok(length as u32)
        }
        VIRTIO_BLK_T_OUT => {
            let length = read_len - 16;
            if write_len != 1 || length % 512 != 0 {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            let start =
                valid_range(sector, length as u64).ok_or(std::io::ErrorKind::InvalidInput)?;
            let mut data = vec![0; length];
            transfer(memory, readable, 16, &mut data, false)?;
            backing.writer().unwrap().write_at(start, &data)?;
            Ok(0)
        }
        VIRTIO_BLK_T_DISCARD => {
            if negotiated & VIRTIO_BLK_F_DISCARD == 0 {
                return Err(std::io::ErrorKind::Unsupported.into());
            }
            let length = read_len - 16;
            if write_len != 1 || length == 0 || length % 16 != 0 || length / 16 > MAX_RANGES {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            let mut data = vec![0; length];
            transfer(memory, readable, 16, &mut data, false)?;
            let mut ranges = Vec::new();
            for record in data.as_chunks::<16>().0 {
                let sector = u64::from_le_bytes(record[..8].try_into().unwrap());
                let sectors = u32::from_le_bytes(record[8..12].try_into().unwrap());
                let flags = u32::from_le_bytes(record[12..].try_into().unwrap());
                if flags != 0 {
                    return Err(std::io::ErrorKind::Unsupported.into());
                }
                if sectors > MAX_RANGE_SECTORS {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
                let length = u64::from(sectors) * 512;
                let start = valid_range(sector, length).ok_or(std::io::ErrorKind::InvalidInput)?;
                ranges.push((start, length));
            }
            let writer = backing.writer().unwrap();
            for (start, length) in ranges {
                writer.discard(start, length)?;
            }
            Ok(0)
        }
        VIRTIO_BLK_T_FLUSH => {
            backing.flush()?;
            Ok(0)
        }
        VIRTIO_BLK_T_GET_ID => {
            if read_len != 16 || write_len < 21 {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            transfer(memory, writable, 0, &mut backing.get_id(), true)?;
            Ok(20)
        }
        _ => Err(std::io::ErrorKind::Unsupported.into()),
    })();
    match result {
        Ok(n) => {
            if mutation && negotiated & VIRTIO_BLK_F_FLUSH == 0 && backing.flush().is_err() {
                return failure;
            }
            (VIRTIO_BLK_S_OK, n)
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => (VIRTIO_BLK_S_UNSUPP, 0),
        Err(_) => failure,
    }
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
            false,
            VIRTIO_BLK_F_FLUSH,
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

#[cfg(test)]
mod qcow2_tests {
    use super::*;
    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use dillo_virtio::SharedVirtioMemory;
    use vm_memory::{Bytes, GuestMemoryMmap};

    fn memory() -> (GuestMemoryMmap, Arc<dyn VirtioMemory>) {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap();
        let shared = Arc::new(MappedSharedMemory::new(
            mem.clone(),
            SharedMemoryRequirement {
                range: AddressRange {
                    base: 0,
                    size: 65536,
                },
                access: SharedAccess::ReadWrite,
            },
        ));
        (mem, Arc::new(SharedVirtioMemory::new(vec![shared])))
    }
    fn submit(
        mem: &GuestMemoryMmap,
        access: &Arc<dyn VirtioMemory>,
        backing: &dyn BlockBacking,
        kind: u32,
        ranges: &[(u64, u32, u32)],
        negotiated: u64,
        ro: bool,
    ) -> u8 {
        let mut request = vec![0; 16];
        request[..4].copy_from_slice(&kind.to_le_bytes());
        for &(sector, length, flags) in ranges {
            request.extend_from_slice(&sector.to_le_bytes());
            request.extend_from_slice(&length.to_le_bytes());
            request.extend_from_slice(&flags.to_le_bytes());
        }
        mem.write_slice(&request, GuestAddress(1024)).unwrap();
        // Split in the middle of the header and the first range's sector field.
        let readable = [
            (GuestAddress(1024), 7),
            (GuestAddress(1031), 12),
            (GuestAddress(1043), (request.len() - 19) as u32),
        ];
        process_request(
            access,
            &readable,
            &[(GuestAddress(4096), 1)],
            backing,
            ro,
            negotiated,
        )
        .0
    }
    #[test]
    fn discard_negotiation_flags_and_all_ranges_are_validated_before_mutation() {
        struct Backing(std::sync::atomic::AtomicUsize);
        impl BlockBacking for Backing {
            fn len_bytes(&self) -> u64 {
                1024 * 1024
            }
            fn read_at(&self, _: u64, _: &mut [u8]) -> std::io::Result<usize> {
                unreachable!()
            }
            fn get_id(&self) -> [u8; 20] {
                [0; 20]
            }
            fn is_read_only(&self) -> bool {
                false
            }
            fn writer(&self) -> Option<&dyn WritableBlockBacking> {
                Some(self)
            }
        }
        impl WritableBlockBacking for Backing {
            fn write_at(&self, _: u64, _: &[u8]) -> std::io::Result<()> {
                unreachable!()
            }
            fn supports_discard(&self) -> bool {
                true
            }
            fn discard(&self, _: u64, _: u64) -> std::io::Result<()> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
        }
        let backing = Backing(std::sync::atomic::AtomicUsize::new(0));
        let (mem, access) = memory();
        for (ranges, mask, ro, expected) in [
            (vec![(0, 128, 0)], 0, false, VIRTIO_BLK_S_UNSUPP),
            (
                vec![(0, 128, 1)],
                VIRTIO_BLK_F_DISCARD,
                false,
                VIRTIO_BLK_S_UNSUPP,
            ),
            (
                vec![(0, 128, 0), (u64::MAX, 1, 0)],
                VIRTIO_BLK_F_DISCARD,
                false,
                VIRTIO_BLK_S_IOERR,
            ),
            (
                vec![(0, 128, 0)],
                VIRTIO_BLK_F_DISCARD,
                true,
                VIRTIO_BLK_S_IOERR,
            ),
        ] {
            assert_eq!(
                submit(
                    &mem,
                    &access,
                    &backing,
                    VIRTIO_BLK_T_DISCARD,
                    &ranges,
                    mask,
                    ro
                ),
                expected
            );
            assert_eq!(backing.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
        assert_eq!(
            submit(
                &mem,
                &access,
                &backing,
                VIRTIO_BLK_T_DISCARD,
                &[(0, 128, 0)],
                VIRTIO_BLK_F_DISCARD,
                false
            ),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(backing.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn writes_without_negotiated_flush_require_durable_completion() {
        struct Backing(Mutex<Vec<u8>>);
        impl BlockBacking for Backing {
            fn len_bytes(&self) -> u64 {
                512
            }
            fn read_at(&self, _: u64, _: &mut [u8]) -> std::io::Result<usize> {
                unreachable!()
            }
            fn get_id(&self) -> [u8; 20] {
                [0; 20]
            }
            fn is_read_only(&self) -> bool {
                false
            }
            fn writer(&self) -> Option<&dyn WritableBlockBacking> {
                Some(self)
            }
            fn flush(&self) -> std::io::Result<()> {
                Err(std::io::Error::other("injected sync failure"))
            }
        }
        impl WritableBlockBacking for Backing {
            fn write_at(&self, _: u64, data: &[u8]) -> std::io::Result<()> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(())
            }
        }
        let backing = Backing(Mutex::new(Vec::new()));
        let (mem, access) = memory();
        let mut data = vec![0x5a; 528];
        data[..16].fill(0);
        data[..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        mem.write_slice(&data, GuestAddress(1024)).unwrap();
        let readable = [(GuestAddress(1024), 528)];
        let writable = [(GuestAddress(4096), 1)];
        // No negotiated FLUSH means the sync error must fail this write.
        assert_eq!(
            process_request(&access, &readable, &writable, &backing, false, 0).0,
            VIRTIO_BLK_S_IOERR
        );
        assert_eq!(backing.0.lock().unwrap().len(), 512);
        assert_eq!(
            process_request(
                &access,
                &readable,
                &writable,
                &backing,
                false,
                VIRTIO_BLK_F_FLUSH
            )
            .0,
            VIRTIO_BLK_S_OK
        );
        // An overflow must be rejected before a third mutation.
        mem.write_slice(&u64::MAX.to_le_bytes(), GuestAddress(1032))
            .unwrap();
        assert_eq!(
            process_request(
                &access,
                &readable,
                &writable,
                &backing,
                false,
                VIRTIO_BLK_F_FLUSH
            )
            .0,
            VIRTIO_BLK_S_IOERR
        );
        assert_eq!(backing.0.lock().unwrap().len(), 1024);
    }

    #[test]
    #[cfg(unix)]
    #[ignore = "requires qemu-img and a hole-punch-capable filesystem"]
    fn guest_discard_reclaims_qcow2() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.qcow2");
        assert!(
            std::process::Command::new("qemu-img")
                .args(["create", "-f", "qcow2", "-o", "cluster_size=65536"])
                .arg(&path)
                .arg("1G")
                .status()
                .unwrap()
                .success()
        );
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let storage =
            imago::file::File::from_open_file(file, imago::StorageOpenOptions::new().write(true))
                .unwrap();
        let backing = dillo_storage::Qcow2Backing::open(storage, false).unwrap();
        backing
            .writer()
            .unwrap()
            .write_at(0, &vec![0x5a; 1024 * 1024])
            .unwrap();
        backing.flush().unwrap();
        let before = std::fs::metadata(&path).unwrap().blocks();
        let (mem, access) = memory();
        let features = VIRTIO_BLK_F_FLUSH | VIRTIO_BLK_F_DISCARD;
        assert_eq!(
            submit(
                &mem,
                &access,
                &backing,
                VIRTIO_BLK_T_DISCARD,
                &[(0, 2048, 0)],
                features,
                false
            ),
            VIRTIO_BLK_S_OK
        );
        backing.flush().unwrap();
        assert!(std::fs::metadata(&path).unwrap().blocks() < before / 2);
        let mut data = vec![1; 1024 * 1024];
        backing.read_at(0, &mut data).unwrap();
        assert!(data.iter().all(|b| *b == 0));
        let device = VirtioBlk::new(Arc::new(backing), false);
        assert_eq!(
            device.features() & VIRTIO_BLK_F_DISCARD,
            VIRTIO_BLK_F_DISCARD
        );
        let mut config = [0; 60];
        device.read_config(0, &mut config);
        assert_eq!(
            u32::from_le_bytes(config[36..40].try_into().unwrap()),
            MAX_RANGE_SECTORS
        );
        assert!(config[48..].iter().all(|byte| *byte == 0));
        drop(device);
        assert!(
            std::process::Command::new("qemu-img")
                .args(["check", "-f", "qcow2"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
    }
}
