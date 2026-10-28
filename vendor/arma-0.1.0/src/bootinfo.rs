// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `TatuBootInfo` wire format — must byte-match `tatu/src/bootinfo.rs`.
//!
//! Arma writes this 44-byte header into the first bytes of the
//! `.tatu.bootinfo` PE section when it materializes the tatu ELF as
//! PE sections. Tatu reads it at runtime via the `BOOTINFO_PAGE`
//! static.

use zerocopy::{Immutable, IntoBytes, KnownLayout};

/// Magic value identifying a `TatuBootInfo` header. Tatu rejects any
/// other prefix.
pub(crate) const MAGIC: [u8; 8] = *b"TATUBOOT";

/// Size of the header on the wire. `const_assert`-pinned below.
pub(crate) const HEADER_SIZE: usize = 76;

/// Total in-memory size of the `.tatu.bootinfo` section. Pinned at
/// 4 KiB to match PMI's small-section granularity (the PE section's
/// `SizeOfRawData` is a multiple of 4 KiB per
/// `pmi/spec/granularity.md`).
pub(crate) const SECTION_SIZE: usize = 4096;

/// Fixed 44-byte header. Packed so the wire layout has no implicit
/// padding. All fields little-endian.
#[repr(C, packed)]
#[derive(Copy, Clone, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct TatuBootInfo {
    pub(crate) magic: [u8; 8],
    pub(crate) base_dtb_gpa: u64,
    pub(crate) host_dtbo_gpa: u64,
    pub(crate) kernel_gpa: u64,
    /// GPA of the kernel's entry point. For x86 this is `kernel_gpa +
    /// (e_entry - link_base)` — the entry need not be the image base. For
    /// aarch64 it is the image base (the Image entry is offset 0). Placed among
    /// the `u64`s (before the `u32`s) so the layout stays naturally aligned with
    /// no padding — byte-identical to tatu's non-packed mirror.
    pub(crate) kernel_entry_gpa: u64,
    /// GPA of the x86 KASLR relocation table (see [`crate::kernel::Relocs`]), or
    /// `0` when absent (aarch64, or an x86 kernel without relocs). The table is
    /// three back-to-back `u32` arrays — `relocs64`, then `relocs32neg`, then
    /// `relocs32` — whose lengths are the `*_count` fields. tatu adds the random
    /// KASLR delta to each site before jumping to the kernel.
    pub(crate) relocs_gpa: u64,
    pub(crate) base_dtb_size: u32,
    pub(crate) host_dtbo_size: u32,
    pub(crate) kernel_size: u32,
    /// Kernel runtime RAM footprint (`.linux` VirtualSize: file image + BSS).
    /// tatu bounds the KASLR virtual base so the whole image stays within the
    /// kernel's `KERNEL_IMAGE_SIZE` high-map window.
    pub(crate) kernel_alloc_size: u32,
    /// Number of 8-byte relocation sites (`*p += delta`).
    pub(crate) relocs64_count: u32,
    /// Number of inverse 4-byte (per-CPU PC-relative) sites (`*p -= delta`).
    pub(crate) relocs32neg_count: u32,
    /// Number of 4-byte relocation sites (`*p += delta`).
    pub(crate) relocs32_count: u32,
}

const _: () = {
    assert!(core::mem::size_of::<TatuBootInfo>() == HEADER_SIZE);
};

/// The relocation-table locator passed to [`TatuBootInfo::new`]. Grouped to keep
/// the constructor's argument list manageable. All zero when there are no relocs.
#[derive(Copy, Clone, Default)]
pub(crate) struct RelocsHeader {
    pub(crate) gpa: u64,
    pub(crate) relocs64_count: u32,
    pub(crate) relocs32neg_count: u32,
    pub(crate) relocs32_count: u32,
}

impl TatuBootInfo {
    /// Build a header from the per-region GPAs and sizes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        base_dtb_gpa: u64,
        base_dtb_size: u32,
        host_dtbo_gpa: u64,
        host_dtbo_size: u32,
        kernel_gpa: u64,
        kernel_size: u32,
        kernel_entry_gpa: u64,
        kernel_alloc_size: u32,
        relocs: RelocsHeader,
    ) -> Self {
        Self {
            magic: MAGIC,
            base_dtb_gpa,
            host_dtbo_gpa,
            kernel_gpa,
            kernel_entry_gpa,
            relocs_gpa: relocs.gpa,
            base_dtb_size,
            host_dtbo_size,
            kernel_size,
            kernel_alloc_size,
            relocs64_count: relocs.relocs64_count,
            relocs32neg_count: relocs.relocs32neg_count,
            relocs32_count: relocs.relocs32_count,
        }
    }

    /// Render the header as a 4 KiB `.tatu.bootinfo` section payload:
    /// 44 bytes of header followed by 4052 bytes of zero padding.
    pub(crate) fn to_section_bytes(self) -> Vec<u8> {
        let mut v = vec![0u8; SECTION_SIZE];
        v[..HEADER_SIZE].copy_from_slice(self.as_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_relocs() -> RelocsHeader {
        RelocsHeader {
            gpa: 0xCAFE_0000_0000_1000,
            relocs64_count: 0x0101,
            relocs32neg_count: 0x0202,
            relocs32_count: 0x0303,
        }
    }

    #[test]
    fn header_is_76_bytes() {
        assert_eq!(core::mem::size_of::<TatuBootInfo>(), HEADER_SIZE);
        assert_eq!(HEADER_SIZE, 76);
    }

    #[test]
    fn section_bytes_have_correct_size_and_magic() {
        let bi = TatuBootInfo::new(
            0x1000,
            0x100,
            0x2000,
            0x200,
            0x3000,
            0x400,
            0x3200,
            0x800,
            sample_relocs(),
        );
        let bytes = bi.to_section_bytes();
        assert_eq!(bytes.len(), SECTION_SIZE);
        assert_eq!(&bytes[..8], &MAGIC);
        // Trailing pad is zero.
        assert!(bytes[HEADER_SIZE..].iter().all(|&b| b == 0));
    }

    #[test]
    fn field_layout_matches_tatu() {
        let bi = TatuBootInfo::new(
            0x1122_3344_5566_7788,
            0x9999,
            0xAABB_CCDD_EEFF_0011,
            0x2222,
            0x3333_4444_5555_6666,
            0x7777,
            0x3333_4444_5555_7000,
            0xABCD_1234,
            RelocsHeader {
                gpa: 0x0A0B_0C0D_0E0F_1011,
                relocs64_count: 0x4444_5555,
                relocs32neg_count: 0x6666_7777,
                relocs32_count: 0x8888_9999,
            },
        );
        let bytes = bi.as_bytes();
        let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        // u64 group: magic, then five u64s.
        assert_eq!(&bytes[0..8], &MAGIC);
        assert_eq!(u64_at(8), 0x1122_3344_5566_7788); // base_dtb_gpa
        assert_eq!(u64_at(16), 0xAABB_CCDD_EEFF_0011); // host_dtbo_gpa
        assert_eq!(u64_at(24), 0x3333_4444_5555_6666); // kernel_gpa
        assert_eq!(u64_at(32), 0x3333_4444_5555_7000); // kernel_entry_gpa
        assert_eq!(u64_at(40), 0x0A0B_0C0D_0E0F_1011); // relocs_gpa
        // u32 group at 48.
        assert_eq!(u32_at(48), 0x9999); // base_dtb_size
        assert_eq!(u32_at(52), 0x2222); // host_dtbo_size
        assert_eq!(u32_at(56), 0x7777); // kernel_size
        assert_eq!(u32_at(60), 0xABCD_1234); // kernel_alloc_size
        assert_eq!(u32_at(64), 0x4444_5555); // relocs64_count
        assert_eq!(u32_at(68), 0x6666_7777); // relocs32neg_count
        assert_eq!(u32_at(72), 0x8888_9999); // relocs32_count
    }
}
