// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Internal write primitives shared by the overlay applier.

use crate::error::MalformedKind;
use crate::header::{FDT_HEADER_SIZE, FDT_MAGIC, FDT_SUPPORTED_VERSION};

/// Append-only writer over a caller-supplied byte slice.
pub(crate) struct WriteCursor<'a> {
    dst: &'a mut [u8],
    pos: usize,
}

impl<'a> WriteCursor<'a> {
    pub(crate) fn new(dst: &'a mut [u8]) -> Self {
        Self { dst, pos: 0 }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), MalformedKind> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(MalformedKind::SizeOverflow)?;
        self.dst
            .get_mut(self.pos..end)
            .ok_or(MalformedKind::SizeOverflow)?
            .copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub(crate) fn write_u32_be(&mut self, v: u32) -> Result<(), MalformedKind> {
        self.write(&v.to_be_bytes())
    }

    /// Reserve `len` bytes and call `f` on the slot. Lets the overlay
    /// merger apply phandle rewrites in place at emission time.
    pub(crate) fn write_with<F, E>(&mut self, len: usize, f: F) -> Result<(), E>
    where
        F: FnOnce(&mut [u8]) -> Result<(), E>,
        E: From<MalformedKind>,
    {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(MalformedKind::SizeOverflow)?;
        let slot = self
            .dst
            .get_mut(self.pos..end)
            .ok_or(MalformedKind::SizeOverflow)?;
        f(slot)?;
        self.pos = end;
        Ok(())
    }
}

pub(crate) fn u32_or(n: usize) -> Result<u32, MalformedKind> {
    u32::try_from(n).map_err(|_| MalformedKind::SizeOverflow)
}

pub(crate) fn build_header(
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    size_dt_struct: u32,
    size_dt_strings: u32,
) -> [u8; FDT_HEADER_SIZE] {
    let mut h = [0u8; FDT_HEADER_SIZE];
    // Slice indexing on a stack-local fixed array: bounds known statically.
    #[allow(clippy::indexing_slicing)]
    {
        h[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&totalsize.to_be_bytes());
        h[8..12].copy_from_slice(&off_dt_struct.to_be_bytes());
        h[12..16].copy_from_slice(&off_dt_strings.to_be_bytes());
        h[16..20].copy_from_slice(&off_mem_rsvmap.to_be_bytes());
        h[20..24].copy_from_slice(&FDT_SUPPORTED_VERSION.to_be_bytes());
        h[24..28].copy_from_slice(&16u32.to_be_bytes()); // last_comp_version
        // h[28..32] boot_cpuid_phys = 0
        h[32..36].copy_from_slice(&size_dt_strings.to_be_bytes());
        h[36..40].copy_from_slice(&size_dt_struct.to_be_bytes());
    }
    h
}
