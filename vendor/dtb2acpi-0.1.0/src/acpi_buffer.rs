// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! 16-byte-aligned ACPI table region.
//!
//! ACPI 6.5 §5.2.5.1 requires the RSDP to be 16-byte aligned. The
//! emitted layout places the RSDP at offset 0 of the output buffer,
//! so the buffer itself must be 16-byte aligned. [`AcpiBuffer`]
//! enforces that at the type level via `#[repr(align(16))]` — no
//! runtime check, no caller-side discipline.
//!
//! `N` is the buffer size in bytes. Callers either pick a
//! compile-time-known reservation size (typical for guest firmware
//! with a fixed ACPI region) or over-allocate to a `MAX` that covers
//! every realistic layout.

use devtree::TreeView;

use crate::OemIdentity;
use crate::count::{self, CpuCache, Domains};
use crate::emit::sdt::SdtHeader;
use crate::emit::{fadt, madt, mcfg, rsdp, slit, spcr, srat, xsdt};
use crate::error::EmitError;

/// `N`-byte buffer for emitted ACPI tables — a `#[repr(transparent)]`
/// newtype over `[u8; N]`, so the value IS exactly its bytes: no
/// metadata, no padding, `size_of` == `N`.
///
/// Construct with [`Default::default`] or the `const` [`Self::new`];
/// fill with [`Self::populate`], which returns the live image length.
/// After a successful `populate` the buffer's first byte is the RSDP,
/// and `base_gpa` (the value the caller passed) is what they publish to
/// the OS — the two coincide when the buffer's host/guest address equals
/// `base_gpa`. Because it is a newtype, `&buffer as *const _ ==
/// buffer.as_ref().as_ptr()` (the bytes are at struct offset 0).
///
/// **Alignment is the caller's responsibility.** ACPI 6.5 §5.2.5.1
/// requires the RSDP (buffer offset 0) to be 16-byte aligned; a
/// transparent `[u8; N]` has alignment 1, so the buffer must be placed
/// where its base is 16-aligned. PMI consumers get this for free — the
/// ACPI region is a page-aligned section (e.g. tatu wraps it in a 4 KiB
/// `Paged` slot).
///
/// **Stack size**: `Default::default()` materializes `[0; N]` directly
/// on the caller's stack before any move. For a tight boot stack, place
/// the buffer in a `static` slot via [`Self::new`] (a `const fn`).
#[repr(transparent)]
#[derive(Debug)]
pub struct AcpiBuffer<const N: usize>([u8; N]);

impl<const N: usize> Default for AcpiBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AcpiBuffer<N> {
    /// Zero-initialized buffer with no live image. `const` so it can
    /// back a `static` slot:
    ///
    /// ```ignore
    /// static ACPI: AcpiBuffer<8192> = AcpiBuffer::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self([0; N])
    }

    /// Walk `tree`, validate, and write the full ACPI layout into
    /// this buffer. Every cross-table pointer the emitters bake in
    /// is `base_gpa + offset` — `base_gpa` is the guest physical
    /// address at which `self.as_ref().as_ptr()` will appear to the
    /// guest OS. Stamps every emitted SDT header and the RSDP with
    /// `oem`. Every byte from offset 0 up to the layout size is
    /// overwritten; the tail beyond the layout is left untouched.
    ///
    /// On success returns the number of bytes the layout occupies —
    /// the buffer prefix `self.as_ref()[..n]` is the live ACPI image;
    /// the rest is untouched. Callers handing the image off to
    /// firmware / a VMM can use this to copy only the live prefix.
    ///
    /// `base_gpa` is the caller's responsibility: pass the address
    /// at which the live image will be visible to the guest OS. For
    /// guest-side execution under identity-mapped paging that is the
    /// buffer's own host address; for a VMM building tables externally
    /// it is the chosen guest physical address.
    ///
    /// Re-callable: each successful invocation fully overwrites the
    /// prefix up to the new layout size, so the buffer may be reused
    /// for a different DTB / OEM / `base_gpa`. On error the buffer
    /// contents are unspecified up to the attempted layout size;
    /// callers should treat a failed populate as leaving the buffer
    /// uninitialized.
    ///
    /// # Errors
    /// - [`EmitError::BufferTooSmall`] if `N` is smaller than the
    ///   bytes required by the validated DTB layout. The payload
    ///   reports the `needed` and `got` byte counts so callers can
    ///   resize.
    /// - [`EmitError::Dtb`] if the DTB is malformed or incomplete.
    ///   Internal layout-accounting bugs surface here too, as
    ///   `EmitError::Dtb(DtbError::Internal)` — defensive, unreachable
    ///   on a count-validated tree.
    pub fn populate<T: TreeView>(
        &mut self,
        tree: &T,
        oem: &OemIdentity,
        base_gpa: u64,
    ) -> Result<usize, EmitError> {
        // Stack-resident cpu cache (~2.3 KB at the 256-cpu cap, which
        // matches MADT's u8 processor_id). Populated during count's
        // `/cpus` walk so MADT/SRAT emit iterate without re-walking;
        // oversize trees surface as `DtbError::TooManyCpus`.
        let mut cpu_cache = CpuCache::new();
        let mut domains = Domains::new();
        let (off, fadt_plan, lapic_base) = count::run(tree, &mut cpu_cache, &mut domains)?;
        if self.0.len() < off.total {
            return Err(EmitError::BufferTooSmall {
                needed: off.total,
                got: self.0.len(),
            });
        }
        let buf = &mut self.0;

        // Emit in layout order so each emitter's slot is established
        // before any downstream emitter computes its cross-table GPA.
        rsdp::emit(off.rsdp.carve_in(buf)?, off.xsdt.gpa(base_gpa)?, oem)?;
        SdtHeader::write_dsdt_into(off.dsdt.carve_in(buf)?, oem, fadt_plan.sleep_value, tree)?;
        fadt::emit(
            off.fadt.carve_in(buf)?,
            off.dsdt.gpa(base_gpa)?,
            &fadt_plan,
            oem,
        )?;
        madt::emit(off.madt.carve_in(buf)?, oem, tree, lapic_base, &cpu_cache)?;
        if let Some(s) = off.mcfg {
            mcfg::emit(s.carve_in(buf)?, oem, tree)?;
        }
        if let Some(s) = off.spcr {
            spcr::emit(s.carve_in(buf)?, oem, tree)?;
        }
        if let Some(s) = off.srat {
            srat::emit(s.carve_in(buf)?, oem, tree, &cpu_cache)?;
        }
        if let Some(s) = off.slit {
            slit::emit(s.carve_in(buf)?, oem, tree, &domains)?;
        }
        xsdt::emit(off.xsdt.carve_in(buf)?, oem, base_gpa, &off)?;
        Ok(off.total)
    }
}

impl<const N: usize> AsRef<[u8]> for AcpiBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
