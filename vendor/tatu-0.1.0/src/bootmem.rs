// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! x86_64 boot CPU tables, baked into the tatu binary at build time.
//!
//! The boot vCPU enters long mode, so dillo must load `cr3` and `gdtr`
//! *before* tatu's first instruction. Those structures therefore can't
//! be built at runtime — they ship as two fixed sections:
//!
//! - `.tatu.pgt`: 4-level identity map of the first 4 GiB using 2 MiB
//!   pages (PML4 + PDPT + 4× PD = 6 pages = 24 KiB).
//! - `.tatu.gdt`: one page holding a 3-entry GDT (null, 64-bit code at
//!   selector `0x08`, 64-bit data at `0x10`).
//!
//! Both are throwaway — Linux reloads `CR3`/`LGDT` in `head_64.S`.
//!
//! The page-table entries are self-referential: each inter-table pointer
//! embeds the table's own GPA. A `const fn` cannot read a static's
//! link-time address (`&STATIC` is a relocation, not a const value), so
//! the base is [`crate::sections::PGT_BASE`] — itself derived at const-eval
//! time as the prefix sum of the sections that precede `.tatu.pgt`, which
//! is exactly where the linker packs it. arma never reads this constant:
//! it discovers the section's GPA from tatu's ELF section table and
//! cross-checks it.

// `link_section` overrides trip the unsafe-code lint; this whole module
// is the documented x86 placement contract (linker/x86_64.ld), not a
// soundness hazard — same pattern as the reserved input sections.
#![allow(unsafe_code)]

use crate::Paged;
use crate::sections::PGT_BASE;
use crate::workspace::PageCell;

/// PML4 + PDPT + 4× PD. `pub` so [`crate::sections`] can fold it into the
/// conventional-RAM prefix sum that derives the stack size and `PGT_BASE`.
pub(crate) const PGT_SIZE: usize = 6 * 4096;
/// One page. `pub` for the same reason as [`PGT_SIZE`].
pub(crate) const GDT_SIZE: usize = 4096;

/// Page-table entry flags.
const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_WRITABLE: u64 = 1 << 1;
const PAGE_SIZE_2MB: u64 = 1 << 7;

/// Number of 1 GiB regions the identity map covers (4 → first 4 GiB).
const NUM_GB: usize = 4;

const fn write_u64(out: &mut [u8; PGT_SIZE], off: usize, val: u64) {
    let b = val.to_le_bytes();
    let mut k = 0;
    while k < 8 {
        out[off + k] = b[k];
        k += 1;
    }
}

/// Build the identity-mapped page tables at const-eval time.
///
/// Layout (relative to [`PGT_BASE`]):
///   page 0      (PML4): one entry → PDPT
///   page 1      (PDPT): four entries → PD0..PD3
///   pages 2..6  (PD):   512 entries each, 2 MiB pages over 4×1 GiB
// Const-evaluated: the array is materialized into a `static` (see the caller),
// never built on a runtime stack frame, so the large size is not a stack hazard.
#[allow(clippy::large_stack_arrays)]
const fn identity_map_4gib() -> [u8; PGT_SIZE] {
    let mut out = [0u8; PGT_SIZE];

    let pdpt_off: usize = 4096;
    let pd_base_off: usize = pdpt_off + 4096;

    // PML4 entry 0 → PDPT.
    write_u64(
        &mut out,
        0,
        (PGT_BASE + pdpt_off as u64) | PAGE_PRESENT | PAGE_WRITABLE,
    );

    // PDPT: one entry per GiB → PD0..PD3.
    let mut i = 0;
    while i < NUM_GB {
        let pd_gpa = PGT_BASE + pd_base_off as u64 + (i as u64) * 4096;
        write_u64(
            &mut out,
            pdpt_off + i * 8,
            pd_gpa | PAGE_PRESENT | PAGE_WRITABLE,
        );
        i += 1;
    }

    // PDs: 512 2 MiB entries each, identity-mapping 4×1 GiB.
    let mut i = 0;
    while i < NUM_GB {
        let pd_off = pd_base_off + i * 4096;
        let mut j = 0u64;
        while j < 512 {
            let phys = (i as u64) * (1 << 30) + j * (1 << 21);
            write_u64(
                &mut out,
                pd_off + (j as usize) * 8,
                phys | PAGE_PRESENT | PAGE_WRITABLE | PAGE_SIZE_2MB,
            );
            j += 1;
        }
        i += 1;
    }

    out
}

/// Build the 3-entry GDT page at const-eval time. The descriptor byte
/// patterns are known-good Linux long-mode entries: code (selector
/// `0x08`) and data (selector `0x10`), base 0, limit 4 GiB.
const fn gdt_page() -> [u8; GDT_SIZE] {
    let mut page = [0u8; GDT_SIZE];
    // Entry 1 @ offset 8: 64-bit code — 0xFF 0xFF 00 00 00 0x9B 0xAF 00.
    page[8] = 0xFF;
    page[9] = 0xFF;
    page[13] = 0x9B;
    page[14] = 0xAF;
    // Entry 2 @ offset 16: 64-bit data — 0xFF 0xFF 00 00 00 0x93 0xCF 00.
    page[16] = 0xFF;
    page[17] = 0xFF;
    page[21] = 0x93;
    page[22] = 0xCF;
    page
}

/// `.tatu.pgt` — the identity-map page tables. `PageCell` because the
/// CPU's page walker may set Accessed/Dirty bits while tatu runs under
/// these tables (a write tatu's Rust code never performs). Fixed at
/// [`PGT_BASE`] by the linker. Referenced only by the CPU via `cr3`;
/// `#[used]` keeps it in the binary.
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.pgt")]
static PGTABLE: PageCell<Paged<[u8; PGT_SIZE]>> = PageCell::new(Paged(identity_map_4gib()));

/// `.tatu.gdt` — the boot GDT. Referenced only by the CPU via `gdtr`.
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.gdt")]
static GDT: PageCell<Paged<[u8; GDT_SIZE]>> = PageCell::new(Paged(gdt_page()));
