// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap input wire format — the channel from arma to tatu.
//!
//! A single `.tatu.bootinfo` PE section holds a `TatuBootInfo`
//! struct: magic + GPA/size pairs for the three image-adjacent
//! regions tatu needs at boot time (measured base DTB, host-filled
//! DTBO, kernel image). The struct is the entire section — 4 KiB,
//! page-aligned — so PMI's small-section granularity is satisfied
//! by the type's own layout, not by the linker script.
//!
//! Arma writes the bytes at PMI build time. Tatu's per-arch reset
//! vector loads `&BOOTINFO` into the first-argument register and
//! calls `rust_main(&TatuBootInfo)`; the optimizer cannot fold
//! through that asm boundary, so no `UnsafeCell` is needed.
//!
//! `base_dtb_bytes`, `host_dtbo_bytes`, and `kernel_bytes` each
//! construct a raw slice from a (gpa, size) pair in the header.
//! They are the three `unsafe` sites in this module, with a single
//! shared `// SAFETY:` block on the helper they all call.

/// Magic value identifying a populated `TatuBootInfo` (i.e. one
/// arma actually filled in, vs the all-zero placeholder).
pub(crate) const MAGIC: [u8; 8] = *b"TATUBOOT";

/// Wire format. Fields are naturally aligned (8-byte u64s come
/// before 4-byte u32s), so plain `#[repr(C)]` would already give
/// the 44-byte payload layout with no internal padding. We use
/// `align(4096)` + an explicit `_reserved` tail to make the type
/// itself exactly one page, encoding PMI small-section granularity
/// (`pmi/spec/granularity.md`) in the type instead of the linker
/// script.
#[repr(C, align(4096))]
pub(crate) struct TatuBootInfo {
    pub magic: [u8; 8],
    pub base_dtb_gpa: u64,
    pub host_dtbo_gpa: u64,
    pub kernel_gpa: u64,
    /// GPA of the kernel's entry point (x86: `kernel_gpa + entry_offset`;
    /// aarch64: the image base). tatu jumps here. Among the `u64`s so the
    /// layout has no padding and matches arma's packed mirror byte-for-byte.
    pub kernel_entry_gpa: u64,
    /// GPA of the x86 KASLR relocation table, or `0` when absent (aarch64, or an
    /// x86 kernel without relocs). The table is three back-to-back `u32` arrays —
    /// `relocs64`, `relocs32neg`, `relocs32` — sized by the `*_count` fields.
    pub relocs_gpa: u64,
    pub base_dtb_size: u32,
    pub host_dtbo_size: u32,
    pub kernel_size: u32,
    /// Kernel runtime RAM footprint (`.linux` VirtualSize: file image + BSS).
    /// Bounds the KASLR virtual base so the image stays within `KERNEL_IMAGE_SIZE`.
    pub kernel_alloc_size: u32,
    pub relocs64_count: u32,
    pub relocs32neg_count: u32,
    pub relocs32_count: u32,
    _reserved: [u8; 4096 - 76],
}

impl TatuBootInfo {
    /// All-zero initializer used as the placeholder for the
    /// `.tatu.bootinfo` static. Arma overwrites this before tatu
    /// runs; a stale image (unfilled) fails the magic check at
    /// boot.
    pub(crate) const ZERO: Self = Self {
        magic: [0; 8],
        base_dtb_gpa: 0,
        host_dtbo_gpa: 0,
        kernel_gpa: 0,
        kernel_entry_gpa: 0,
        relocs_gpa: 0,
        base_dtb_size: 0,
        host_dtbo_size: 0,
        kernel_size: 0,
        kernel_alloc_size: 0,
        relocs64_count: 0,
        relocs32neg_count: 0,
        relocs32_count: 0,
        _reserved: [0; 4096 - 76],
    };
}

const _: () = {
    assert!(core::mem::size_of::<TatuBootInfo>() == 4096);
    assert!(core::mem::align_of::<TatuBootInfo>() == 4096);
};

// ---------------------------------------------------------------------------
// Region accessors. Each turns a (gpa, size) pair from the header
// into a typed `&'static [u8]`. Three call sites; one shared
// `// SAFETY:` helper.
// ---------------------------------------------------------------------------

/// Borrow the measured base-DTB region.
pub(crate) fn base_dtb_bytes(info: &TatuBootInfo) -> &'static [u8] {
    region(info.base_dtb_gpa, info.base_dtb_size)
}

/// Borrow the host-supplied DTBO region.
pub(crate) fn host_dtbo_bytes(info: &TatuBootInfo) -> &'static [u8] {
    region(info.host_dtbo_gpa, info.host_dtbo_size)
}

/// Borrow the loaded kernel image. aarch64 jumps to the raw Image base; x86
/// jumps to `kernel_entry_gpa` directly and never needs the slice.
#[cfg(any(test, target_arch = "aarch64"))]
pub(crate) fn kernel_bytes(info: &TatuBootInfo) -> &'static [u8] {
    region(info.kernel_gpa, info.kernel_size)
}

/// Borrow the loaded kernel image mutably, for x86 KASLR relocation. The image
/// is a PE section the VMM loaded into guest RAM; tatu patches it in place before
/// jumping. The byte count is the FILE size (`kernel_size`) — relocation sites
/// only ever fall in initialized data, never in the BSS tail beyond it.
#[cfg(any(test, target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub(crate) fn kernel_bytes_mut(info: &TatuBootInfo) -> &'static mut [u8] {
    // SAFETY: same single-vCPU, no-DMA, VMM-loaded-region argument as `region`
    // (see below). tatu is the sole accessor of the kernel image until it jumps,
    // so a unique `&mut` for the relocation pass is sound.
    unsafe {
        core::slice::from_raw_parts_mut(info.kernel_gpa as *mut u8, info.kernel_size as usize)
    }
}

/// Borrow the KASLR relocation table as one `u32` slice (`relocs64`, then
/// `relocs32neg`, then `relocs32`, back to back). `relocs_gpa` is 2 MiB-aligned,
/// so the `u32` reinterpret is well-aligned. Empty when there are no relocs.
#[cfg(any(test, target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub(crate) fn relocs_words(info: &TatuBootInfo) -> &'static [u32] {
    let count = info.relocs64_count as usize
        + info.relocs32neg_count as usize
        + info.relocs32_count as usize;
    if count == 0 {
        return &[];
    }
    // SAFETY: arma placed a `.linux.relocs` PE section of exactly `count` u32s at
    // `relocs_gpa` (2 MiB-aligned), loaded by the VMM before entry. Read-only,
    // single vCPU, no concurrent writer; lives for the whole boot.
    unsafe { core::slice::from_raw_parts(info.relocs_gpa as *const u32, count) }
}

#[allow(unsafe_code)]
fn region(gpa: u64, size: u32) -> &'static [u8] {
    // SAFETY: arma wrote the (gpa, size) pair to point at a PE
    // section loaded by the VMM per PMI's `load` / `dt:dtbo`
    // action before vCPU entry; pmi/spec/dt.md §2 makes the
    // VMM responsible for `/memory@*` covering each region. Tatu
    // runs on a single boot vCPU with no IRQs or DMA — no
    // concurrent writer. The slice lives for the whole boot.
    unsafe { core::slice::from_raw_parts(gpa as *const u8, size as usize) }
}
