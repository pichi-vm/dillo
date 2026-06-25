// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! In-process virtio-fs device implementing [`VirtioDevice`].
//!
//! virtio-fs (virtio 1.2 §5.11) shares a host directory into the guest by
//! speaking the Linux FUSE protocol over virtqueues. The guest mounts it with
//! `mount -t virtiofs <tag> <dir>` where `<tag>` matches this device's config
//! tag. This device is **read-only**: it serves files out of an [`FsBackend`]
//! ([`Passthrough`] over a host directory) and rejects every mutating FUSE
//! opcode with `EROFS`, mirroring the RO-by-construction stance of the
//! `dillo-virtio-blk` synthesized backings.
//!
//! Layout: one hiprio queue (queue 0) plus one request queue (queue 1). The
//! FUSE dispatch is uniform, so a worker is spawned per queue and both drive
//! the same [`fuse::dispatch`] against shared, mutex-guarded server state.
//! DAX / shared-memory windows are not implemented; all I/O flows as FUSE
//! messages through the queues.

mod backend;
mod fuse;

use std::sync::{Arc, Mutex};

use dillo_mmio::Interrupt;
use dillo_virtio::queue::{Queue, QueueMemory, VIRTQ_DESC_F_WRITE};
use dillo_virtio::{
    ActivateError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle, VirtioDeviceHost,
    VirtioMemory, VirtioRunToken,
};
use vm_memory::GuestAddress;

use crate::fuse::FsState;

pub use crate::backend::{Attr, DirEntry, FsBackend, MapFs, Passthrough, SetAttr};

/// VIRTIO_F_VERSION_1 from the virtio 1.x spec.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Virtio device-type id for a filesystem device (virtio 1.2 §5.11).
pub const VIRTIO_ID_FS: u32 = 26;

/// virtio-fs config tag length (`virtio_fs_config.tag`).
const TAG_LEN: usize = 36;

/// One hiprio queue + one request queue.
const NUM_QUEUES: usize = 2;
const QUEUE_MAX: u16 = 128;
const QUEUE_SIZES: [u16; NUM_QUEUES] = [QUEUE_MAX; NUM_QUEUES];

/// Cap the gathered request bytes per descriptor chain. Read-only requests are
/// tiny (header + name + fixed args); this only needs to bound a hostile chain.
const MAX_REQUEST: usize = (1 << 20) + 4096;

/// In-process virtio-fs device serving one [`FsBackend`] under a mount tag.
pub struct VirtioFs {
    /// Mount tag, NUL-padded to [`TAG_LEN`] for config space.
    tag: [u8; TAG_LEN],
    backend: Arc<dyn FsBackend>,
    state: Arc<Mutex<FsState>>,
    activated: bool,
}

impl std::fmt::Debug for VirtioFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag_end = self.tag.iter().position(|&b| b == 0).unwrap_or(TAG_LEN);
        f.debug_struct("VirtioFs")
            .field("tag", &String::from_utf8_lossy(&self.tag[..tag_end]))
            .field("activated", &self.activated)
            .finish_non_exhaustive()
    }
}

/// Error building a [`VirtioFs`].
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("virtio-fs tag must be 1..={TAG_LEN} bytes (got {0})")]
    TagLength(usize),
}

impl VirtioFs {
    /// Build a virtio-fs device from a mount `tag` and an [`FsBackend`]. When
    /// `readonly` is true every mutating FUSE opcode is rejected with `EROFS`
    /// before the backend is consulted.
    pub fn new(tag: &str, backend: Arc<dyn FsBackend>, readonly: bool) -> Result<Self, FsError> {
        let bytes = tag.as_bytes();
        if bytes.is_empty() || bytes.len() > TAG_LEN {
            return Err(FsError::TagLength(bytes.len()));
        }
        let mut tag_buf = [0u8; TAG_LEN];
        tag_buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            tag: tag_buf,
            backend,
            state: Arc::new(Mutex::new(FsState::new(readonly))),
            activated: false,
        })
    }

    /// Convenience: build a passthrough of a host directory under `tag`. When
    /// `readonly` is true the guest may read but not modify the share.
    /// Cross-platform; the Linux guest's FUSE attributes are read from Unix
    /// metadata on Unix hosts and synthesized elsewhere.
    pub fn passthrough(
        tag: &str,
        source: impl Into<std::path::PathBuf>,
        readonly: bool,
    ) -> std::io::Result<Self> {
        let backing = Passthrough::new(source)?;
        Self::new(tag, Arc::new(backing), readonly)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

impl VirtioDevice for VirtioFs {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_FS
    }

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // virtio_fs_config { char tag[36]; __le32 num_request_queues; }.
        let mut config = [0u8; TAG_LEN + 4];
        config[..TAG_LEN].copy_from_slice(&self.tag);
        // One request queue (queue 0 is hiprio, not counted here).
        config[TAG_LEN..].copy_from_slice(&1u32.to_le_bytes());
        for (i, byte) in data.iter_mut().enumerate() {
            let off = offset as usize + i;
            *byte = config.get(off).copied().unwrap_or(0);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // virtio_fs_config is read-only from the guest.
    }

    fn activate(
        &mut self,
        mut activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        if self.activated {
            return Err(ActivateError::InvalidConfig(
                "VirtioFs::activate called twice".into(),
            ));
        }
        let queue_memory = activation.queue_memory();
        let buffer_memory = activation.buffer_memory();
        let mut queues = activation.take_queues();
        let mut queue_evts = activation.take_queue_evts();
        let host = activation.host()?;
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            return Err(ActivateError::InvalidConfig(format!(
                "virtio-fs expects {NUM_QUEUES} queues + {NUM_QUEUES} evts, got {} / {}",
                queues.len(),
                queue_evts.len()
            )));
        }

        // Spawn one worker per queue (hiprio + request). FUSE dispatch is
        // uniform, so each worker runs the same drain over shared state.
        let mut workers: Vec<Arc<Mutex<Option<VirtioDeviceHandle>>>> =
            Vec::with_capacity(NUM_QUEUES);
        let mut wakes: Vec<Kick> = Vec::with_capacity(NUM_QUEUES);
        for index in 0..NUM_QUEUES {
            let queue = queues.remove(0);
            let evt = queue_evts.remove(0);
            wakes.push(evt.try_clone()?);
            let call_interrupt = activation.queue_interrupt(index);
            let handle = spawn_queue_worker(
                Arc::clone(&host),
                Arc::clone(&queue_memory),
                Arc::clone(&buffer_memory),
                queue,
                evt,
                call_interrupt,
                Arc::clone(&self.state),
                Arc::clone(&self.backend),
            )?;
            workers.push(Arc::new(Mutex::new(Some(handle))));
        }

        let shutdown_workers = workers.clone();
        let join_workers = workers;
        self.activated = true;
        log::info!(
            "virtio-fs: activated (tag={:?}, {NUM_QUEUES} queues)",
            String::from_utf8_lossy(
                &self.tag[..self.tag.iter().position(|&b| b == 0).unwrap_or(TAG_LEN)]
            )
        );
        Ok(VirtioDeviceHandle::new(
            move || {
                for worker in &shutdown_workers {
                    if let Some(handle) = worker.lock().expect("virtio-fs handle poisoned").as_mut()
                    {
                        handle.shutdown();
                    }
                }
                for wake in &wakes {
                    let _ = wake.write(1);
                }
            },
            move || {
                for worker in &join_workers {
                    if let Some(handle) = worker.lock().expect("virtio-fs handle poisoned").take() {
                        handle.join()?;
                    }
                }
                Ok(())
            },
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_queue_worker(
    host: Arc<dyn VirtioDeviceHost>,
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
    state: Arc<Mutex<FsState>>,
    backend: Arc<dyn FsBackend>,
) -> Result<VirtioDeviceHandle, ActivateError> {
    host.spawn(Box::new(move |token| {
        queue_worker(
            queue_memory,
            buffer_memory,
            queue,
            kick,
            call_interrupt,
            state,
            backend,
            token,
        );
        Ok(())
    }))
}

#[allow(clippy::too_many_arguments)]
fn queue_worker(
    queue_memory: Arc<dyn QueueMemory>,
    buffer_memory: Arc<dyn VirtioMemory>,
    queue: Queue,
    kick: Kick,
    call_interrupt: Option<Interrupt>,
    state: Arc<Mutex<FsState>>,
    backend: Arc<dyn FsBackend>,
    token: VirtioRunToken,
) {
    let queue = Arc::new(Mutex::new(queue));
    loop {
        if let Err(e) = kick.read() {
            log::error!("virtio-fs: kick read error: {e}");
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
            &state,
            backend.as_ref(),
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
    state: &Arc<Mutex<FsState>>,
    backend: &dyn FsBackend,
) {
    let mut q = queue.lock().expect("virtio-fs queue mutex");
    let mut signaled = false;
    while let Some(head) = q.pop(queue_memory) {
        let head_index = head.index;

        // Split the chain: device-readable = request, device-writable = reply.
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

        // Gather the request bytes.
        let mut input = Vec::new();
        for &(addr, len) in &readable {
            if input.len() >= MAX_REQUEST {
                break;
            }
            let take = (len as usize).min(MAX_REQUEST - input.len());
            let mut buf = vec![0u8; take];
            match buffer_memory.read(addr, &mut buf) {
                Ok(n) => input.extend_from_slice(&buf[..n]),
                Err(e) => {
                    log::warn!("virtio-fs: request read at {:#x}+{len}: {e:?}", addr.0);
                    break;
                }
            }
        }

        let reply = {
            let mut st = state.lock().expect("virtio-fs state mutex");
            fuse::dispatch(&mut st, backend, &input)
        };

        let written = match reply {
            Some(reply) => scatter_write(buffer_memory, &writable, &reply),
            None => 0, // replyless op (FORGET / INTERRUPT): return desc, len 0.
        };
        q.add_used(queue_memory, head_index, written);
        signaled = true;
    }
    if signaled && let Some(intr) = call_interrupt {
        intr.signal();
    }
}

/// Write `reply` across the device-writable descriptors in order. Returns the
/// number of bytes placed into guest memory.
fn scatter_write(buffer_memory: &Arc<dyn VirtioMemory>, writable: &[Desc], reply: &[u8]) -> u32 {
    let mut offset = 0usize;
    let mut written = 0u32;
    for &(addr, len) in writable {
        if offset >= reply.len() {
            break;
        }
        let n = (len as usize).min(reply.len() - offset);
        match buffer_memory.write(addr, &reply[offset..offset + n]) {
            Ok(w) => {
                written += w as u32;
                offset += w;
                if w < n {
                    break;
                }
            }
            Err(e) => {
                log::warn!("virtio-fs: reply write at {:#x}+{len}: {e:?}", addr.0);
                break;
            }
        }
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_mmio::{AddressRange, MappedSharedMemory, SharedAccess, SharedMemoryRequirement};
    use dillo_virtio::queue::VIRTQ_DESC_F_NEXT;
    use dillo_virtio::{SharedQueueMemory, SharedVirtioMemory};
    use vm_memory::{Address, Bytes, GuestMemoryMmap};

    #[test]
    fn config_carries_tag_and_one_request_queue() {
        let fs = VirtioFs::new("myshare", Arc::new(MapFs::new()), true).unwrap();
        let mut buf = [0u8; TAG_LEN + 4];
        fs.read_config(0, &mut buf);
        assert_eq!(&buf[..7], b"myshare");
        assert_eq!(buf[7], 0); // NUL padded
        assert_eq!(&buf[TAG_LEN..], &1u32.to_le_bytes());
    }

    #[test]
    fn tag_length_validated() {
        assert!(VirtioFs::new("", Arc::new(MapFs::new()), true).is_err());
        let long = "x".repeat(TAG_LEN + 1);
        assert!(VirtioFs::new(&long, Arc::new(MapFs::new()), true).is_err());
        assert!(VirtioFs::new(&"x".repeat(TAG_LEN), Arc::new(MapFs::new()), true).is_ok());
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

    /// Drive a single FUSE_INIT request through `drain_requests` against a real
    /// queue in guest memory, and assert the reply lands in the writable
    /// descriptor with a sane header (exercises scatter/gather + add_used).
    #[test]
    fn init_request_through_queue_writes_reply() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        let desc = GuestAddress(0x100);
        let avail = GuestAddress(0x1000);
        let used = GuestAddress(0x2000);
        let req_buf = GuestAddress(0x5000);
        let reply_buf = GuestAddress(0x6000);

        // Build a FUSE_INIT request (header + fuse_init_in) in guest memory.
        let mut req = Vec::new();
        let init_in_len = 16u32;
        let total = 40 + init_in_len;
        req.extend_from_slice(&total.to_le_bytes()); // len
        req.extend_from_slice(&26u32.to_le_bytes()); // opcode = FUSE_INIT
        req.extend_from_slice(&1u64.to_le_bytes()); // unique
        req.extend_from_slice(&0u64.to_le_bytes()); // nodeid
        req.extend_from_slice(&[0u8; 16]); // uid/gid/pid/extlen
        req.extend_from_slice(&7u32.to_le_bytes()); // major
        req.extend_from_slice(&31u32.to_le_bytes()); // minor
        req.extend_from_slice(&0u32.to_le_bytes()); // max_readahead
        req.extend_from_slice(&0u32.to_le_bytes()); // flags
        mem.write_slice(&req, req_buf).unwrap();

        // desc[0]: request, readable, NEXT->1.
        write_desc(
            &mem,
            desc,
            0,
            req_buf.0,
            req.len() as u32,
            VIRTQ_DESC_F_NEXT,
            1,
        );
        // desc[1]: reply buffer, writable.
        write_desc(&mem, desc, 1, reply_buf.0, 256, VIRTQ_DESC_F_WRITE, 0);

        // avail ring: ring[0]=0, idx=1.
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
        let state = Arc::new(Mutex::new(FsState::new(false)));
        let backend: Arc<dyn FsBackend> = Arc::new(MapFs::new());

        drain_requests(
            &queue_memory,
            &buffer_memory,
            &q,
            None,
            &state,
            backend.as_ref(),
        );

        // Reply: out_header (len, error=0, unique=1) + fuse_init_out.
        let reply_len: u32 = mem.read_obj(reply_buf).unwrap();
        let reply_err: i32 = mem.read_obj(reply_buf.unchecked_add(4)).unwrap();
        let reply_unique: u64 = mem.read_obj(reply_buf.unchecked_add(8)).unwrap();
        assert_eq!(reply_err, 0);
        assert_eq!(reply_unique, 1);
        let major: u32 = mem.read_obj(reply_buf.unchecked_add(16)).unwrap();
        assert_eq!(major, 7);

        // used ring: idx=1, used[0].len == reply_len.
        let used_idx: u16 = mem.read_obj(used.unchecked_add(2)).unwrap();
        assert_eq!(used_idx, 1);
        let used_len: u32 = mem.read_obj(used.unchecked_add(8)).unwrap();
        assert_eq!(used_len, reply_len);
    }
}
