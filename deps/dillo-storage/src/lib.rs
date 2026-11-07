// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use imago::{
    DenyImplicitOpenGate, FormatAccess, FormatDriverBuilder, Storage, StorageExt, qcow2::Qcow2,
};
use std::{io, sync::Mutex};

/// Operations available only through a writable image session.
pub trait WritableBlockBacking: Send + Sync {
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()>;
    fn supports_discard(&self) -> bool {
        false
    }
    fn discard(&self, _offset: u64, _length: u64) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Read access; mutation must be obtained from the same session.
pub trait BlockBacking: Send + Sync {
    /// Mutation authority tied to this same backing session.
    fn writer(&self) -> Option<&dyn WritableBlockBacking> {
        None
    }

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

/// A serialized imago session. Paths and implicit dependencies are never opened here.
pub struct Qcow2Backing<S: Storage + 'static> {
    image: Mutex<FormatAccess<S>>,
    capacity: u64,
    read_only: bool,
}
impl<S: Storage + 'static> std::fmt::Debug for Qcow2Backing<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qcow2Backing")
            .field("capacity", &self.capacity)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}
impl<S: Storage + 'static> Qcow2Backing<S> {
    /// Open an authorized storage object. The initial writable profile is ordinary
    /// standalone v3, 64 KiB clusters, 16-bit refcounts, without snapshot/bitmap/crypto
    /// state. Refuse other profiles before giving the engine mutation authority.
    pub fn open(storage: S, read_only: bool) -> io::Result<Self> {
        if storage.size()? < 104 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Truncated qcow2 header",
            ));
        }
        let mut h = [0; 104];
        storage.read(&mut h[..], 0)?;
        let u32at = |o| u32::from_be_bytes(h[o..o + 4].try_into().unwrap());
        let u64at = |o| u64::from_be_bytes(h[o..o + 8].try_into().unwrap());
        if u32at(0) != 0x5146_49fb
            || u32at(4) != 3
            || u32at(20) != 16
            || u32at(32) != 0
            || u32at(60) != 0
            || u64at(8) != 0
            || u64at(72) != 0
            || u64at(80) != 0
            || u64at(88) != 0
            || u32at(96) != 4
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Supported qcow2 profile: clean standalone v3, 64 KiB clusters, 16-bit refcounts; no backing, snapshots, encryption or extensions requiring feature bits",
            ));
        }
        let capacity = u64at(24);
        if capacity == 0 || capacity % 512 != 0 || u32at(36) > 4_194_304 || u32at(56) > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid qcow2 capacity or table limits",
            ));
        }
        if !read_only
            && (!storage.discard_align().is_power_of_two() || storage.discard_align() > 65536)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Host discard alignment exceeds qcow2 cluster size",
            ));
        }
        let image = Qcow2::<S>::builder(storage)
            .write(!read_only)
            .reclaim(!read_only)
            .open(DenyImplicitOpenGate::default())?;
        Ok(Self {
            image: Mutex::new(FormatAccess::new(image)),
            capacity,
            read_only,
        })
    }
    fn image(&self) -> io::Result<std::sync::MutexGuard<'_, FormatAccess<S>>> {
        self.image
            .lock()
            .map_err(|_| io::Error::other("qcow2 session poisoned"))
    }
    fn bounds(&self, offset: u64, length: u64) -> io::Result<()> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.capacity)
        {
            Err(io::ErrorKind::InvalidInput.into())
        } else {
            Ok(())
        }
    }
}
impl<S: Storage + 'static> BlockBacking for Qcow2Backing<S> {
    fn len_bytes(&self) -> u64 {
        self.capacity
    }
    fn read_at(&self, offset: u64, data: &mut [u8]) -> io::Result<usize> {
        self.bounds(offset, data.len() as u64)?;
        self.image()?.read(&mut *data, offset)?;
        Ok(data.len())
    }
    fn flush(&self) -> io::Result<()> {
        if !self.read_only {
            let image = self.image()?;
            image.flush()?;
            image.sync()?;
        }
        Ok(())
    }
    fn get_id(&self) -> [u8; 20] {
        [0; 20]
    }
    fn is_read_only(&self) -> bool {
        self.read_only
    }
    fn writer(&self) -> Option<&dyn WritableBlockBacking> {
        if self.read_only { None } else { Some(self) }
    }
}
impl<S: Storage + 'static> WritableBlockBacking for Qcow2Backing<S> {
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if self.read_only {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.bounds(offset, data.len() as u64)?;
        self.image()?.write(data, offset)
    }
    fn supports_discard(&self) -> bool {
        !self.read_only
    }
    fn discard(&self, offset: u64, length: u64) -> io::Result<()> {
        if self.read_only {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.bounds(offset, length)?;
        self.image()?.discard_to_zero(offset, length)
    }
}
