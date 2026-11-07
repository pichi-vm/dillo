// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Operations available only through a writable image session.
pub trait WritableBlockBacking: Send + Sync {
    fn write_at(&self, offset: u64, data: &[u8]) -> std::io::Result<()>;
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
