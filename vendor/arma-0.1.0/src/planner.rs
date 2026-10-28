// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guest-physical address planning.
//!
//! arma owns the guest-physical map for everything it controls; dillo
//! derives `/memory` from the loaded regions at launch. The Planner is the
//! single authority: given the immovable carve-outs (tatu's sections and
//! the architecture-fixed/-specific devices, flattened into `reserved`) and
//! the device configuration, it assigns a GPA to every region arma decides —
//! the generic device MMIO (serial, virtio-mmio, ECAM), the PCIe 64-bit BAR
//! window, the kernel, and the initrd — and returns them as a [`Layout`].
//!
//! Placement order (greedy first-fit, each result added to the carve-out
//! set):
//! 1. **PCI window** — fixed at `2^(A-1)` (BAR space, far above RAM).
//! 2. **kernel** — lowest `align`-aligned slot ≥ `min_gpa`, so it lands just
//!    above tatu and never approaches any ceiling.
//! 3. **initrd** — lowest page-aligned slot (above *or* below the kernel).
//! 4. **device band** — one contiguous block (ECAM + serial + virtio)
//!    placed high, just below the PCI window, then carved into the
//!    individual device ranges. Kept far from RAM so changing the device
//!    set never disturbs kernel/initrd placement.
//!
//! No architecture is named here: the arch shows up only in how the caller
//! builds `reserved` and in the device-presence flags of [`ArgsSpec`].

use core::ops::Range;

use thiserror::Error;

/// PMI large-section granularity (2 MiB). Per the PMI section-shape contract
/// (`pmi/spec/granularity.md`), a LARGE section is 2 MiB-aligned and occupies
/// whole 2 MiB units so a conformant VMM can map it with huge pages. The
/// planner rounds every region's carve-out out to this boundary so no two
/// distinct regions (RAM payload vs device MMIO) share a 2 MiB unit — i.e.
/// the emitted PMI is well-formed for *any* VMM, not tuned to one.
const GRAN: u64 = 2 * 1024 * 1024;
/// ns16550a MMIO window (one page).
const SERIAL_SIZE: u64 = 0x1000;
/// One virtio-mmio transport window.
const VIRTIO_SIZE: u64 = 0x200;
/// ECAM: one bus = 1 MiB of config space.
const ECAM_PER_BUS: u64 = 0x10_0000;
/// ECAM buses (`bus-range = <0 0x0f>`). Must match `base_dtb::ECAM_BUSES`.
pub(crate) const ECAM_BUSES: u64 = 16;
/// ECAM window size (16 buses × 1 MiB).
pub(crate) const ECAM_SIZE: u64 = ECAM_BUSES * ECAM_PER_BUS;

/// Device configuration — straight from the CLI / kconfig inference. Says
/// *what* generic devices exist and how big, never *where*.
pub(crate) struct ArgsSpec {
    pub(crate) serial: bool,
    pub(crate) mmio_slots: u32,
    pub(crate) pci_slots: u32,
    pub(crate) window_bits: u32,
    pub(crate) addr_space_bits: u32,
}

/// Kernel load requirements, derived by inspecting the kernel image.
pub(crate) struct KernelSpec {
    /// `.linux` RAM footprint (VirtualSize).
    pub(crate) size: u64,
    /// Load alignment — bzImage `kernel_alignment` / arm64 `Image` (≥ 2 MiB).
    pub(crate) align: u64,
    /// Kernel's intrinsic minimum load GPA (x86 `pref_address`; 0 elsewhere).
    pub(crate) min_gpa: u64,
}

/// Everything placement needs, as plain fields.
pub(crate) struct Planner<'a> {
    pub(crate) args: ArgsSpec,
    /// Immovable carve-outs the Planner must avoid: tatu's sections plus the
    /// architecture-fixed (LAPIC/IOAPIC) and architecture-specific (GIC,
    /// syscon) devices. The Planner does not distinguish them.
    pub(crate) reserved: &'a [Range<u64>],
    pub(crate) kernel: KernelSpec,
    pub(crate) initrd_size: Option<u64>,
    /// x86 KASLR relocation table size (bytes); `None`/0 ⇒ not placed. Loaded
    /// into guest RAM for tatu to consume at boot, then no longer needed.
    pub(crate) relocs_size: Option<u64>,
}

/// Everything the Planner decided. tatu's fixed sections are read from the
/// `TatuImage`; `/memory` is dillo's at launch.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    pub(crate) serial: Option<Range<u64>>,
    pub(crate) virtio: Vec<Range<u64>>,
    pub(crate) ecam: Option<Range<u64>>,
    pub(crate) pci_window: Option<Range<u64>>,
    pub(crate) linux: Range<u64>,
    pub(crate) initrd: Option<Range<u64>>,
    pub(crate) relocs: Option<Range<u64>>,
}

#[derive(Debug, Error)]
pub(crate) enum PlanError {
    #[error("{region} ({size:#x} bytes) does not fit in the guest-physical map")]
    DoesNotFit { region: &'static str, size: u64 },
    #[error(
        "pci window_bits {window_bits} + 2 exceeds addr_space_bits {addr_space_bits} \
         (window must be ≤ 2^(A-2))"
    )]
    WindowTooLarge {
        window_bits: u32,
        addr_space_bits: u32,
    },
    #[error("address computation overflowed")]
    Overflow,
}

impl Planner<'_> {
    pub(crate) fn plan(&self) -> Result<Layout, PlanError> {
        // Every carve-out is rounded out to the PMI large-section granularity
        // (`GRAN`) so distinct regions never share a 2 MiB unit — the PMI a
        // VMM consumes stays well-formed regardless of how it maps memory.
        let mut occupied: Vec<Range<u64>> = self.reserved.iter().map(round_out).collect();

        // 1. PCI 64-bit BAR window — fixed at 2^(A-1), size 2^B ≤ 2^(A-2).
        let pci_window = if self.args.pci_slots > 0 {
            let a = self.args.addr_space_bits;
            let b = self.args.window_bits;
            if b + 2 > a {
                return Err(PlanError::WindowTooLarge {
                    window_bits: b,
                    addr_space_bits: a,
                });
            }
            let base = 1u64 << (a - 1);
            let size = 1u64 << b;
            let w = base..base + size;
            occupied.push(round_out(&w));
            Some(w)
        } else {
            None
        };

        // 2. kernel — lowest aligned slot ≥ min_gpa (align ≥ the PMI large
        //    granularity).
        let align = self.kernel.align.max(GRAN);
        let linux = first_fit(
            self.kernel.min_gpa,
            self.kernel.size,
            align,
            &occupied,
            "kernel",
        )?;
        occupied.push(round_out(&linux));

        // 3. initrd — lowest GRAN-aligned slot (may land above or below the
        //    kernel, e.g. in the gap a high min_gpa leaves beneath it).
        let initrd = match self.initrd_size {
            Some(sz) if sz > 0 => {
                let r = first_fit(0, sz, GRAN, &occupied, "initrd")?;
                occupied.push(round_out(&r));
                Some(r)
            }
            _ => None,
        };

        // 3b. relocs table (x86 KASLR) — lowest GRAN-aligned slot, like initrd.
        let relocs = match self.relocs_size {
            Some(sz) if sz > 0 => {
                let r = first_fit(0, sz, GRAN, &occupied, "relocs")?;
                occupied.push(round_out(&r));
                Some(r)
            }
            _ => None,
        };

        // 4. device band — one contiguous GRAN-aligned block placed in HIGH
        //    MMIO, immediately below the PCI window base (2^(A-1)). Clustering
        //    device MMIO high keeps low RAM contiguous for the guest, and
        //    matches the BAR window's placement (low-fitting the band would
        //    instead wedge it into RAM right above the kernel). The window, if
        //    present, sits at 2^(A-1); the band abuts it from below.
        let (band_size, _band_align) = self.band_geometry();
        let (serial, virtio, ecam) = if band_size > 0 {
            let high_floor = 1u64 << (self.args.addr_space_bits - 1);
            let band_start = high_floor
                .checked_sub(band_size)
                .ok_or(PlanError::Overflow)?; // band_size & high_floor are GRAN-aligned
            let band = band_start..high_floor;
            if occupied
                .iter()
                .any(|r| r.start < band.end && band.start < r.end)
            {
                return Err(PlanError::DoesNotFit {
                    region: "device band",
                    size: band_size,
                });
            }
            self.carve_band(band.start)
        } else {
            (None, Vec::new(), None)
        };

        Ok(Layout {
            serial,
            virtio,
            ecam,
            pci_window,
            linux,
            initrd,
            relocs,
        })
    }

    /// `(size, alignment)` of the contiguous generic-device band — ECAM (if
    /// PCIe) + serial (if present) + the virtio transports. The band is one
    /// GRAN-aligned, GRAN-rounded block so it occupies whole 2 MiB units and
    /// never shares one with a RAM payload (the device registers pack tightly
    /// *inside* the band — sub-page MMIO is fine, it's all one device hole).
    fn band_geometry(&self) -> (u64, u64) {
        let mut size = 0u64;
        if self.args.pci_slots > 0 {
            size += ECAM_SIZE;
        }
        if self.args.serial {
            size += SERIAL_SIZE;
        }
        size += u64::from(self.args.mmio_slots) * VIRTIO_SIZE;
        if size == 0 {
            return (0, GRAN);
        }
        (round_up(size, GRAN), GRAN)
    }

    /// Subdivide the band at `base`: ECAM first (largest alignment, lands on
    /// the band's 1 MiB boundary), then serial, then the virtio transports
    /// (0x200 stride). Mirrors [`Self::band_geometry`].
    fn carve_band(&self, base: u64) -> (Option<Range<u64>>, Vec<Range<u64>>, Option<Range<u64>>) {
        let mut cur = base;
        let ecam = (self.args.pci_slots > 0).then(|| {
            let r = cur..cur + ECAM_SIZE;
            cur += ECAM_SIZE;
            r
        });
        let serial = self.args.serial.then(|| {
            let r = cur..cur + SERIAL_SIZE;
            cur += SERIAL_SIZE;
            r
        });
        let virtio = (0..self.args.mmio_slots)
            .map(|_| {
                let r = cur..cur + VIRTIO_SIZE;
                cur += VIRTIO_SIZE;
                r
            })
            .collect();
        (serial, virtio, ecam)
    }
}

/// Lowest `align`-aligned slot of `size` bytes at or above `start` that
/// overlaps no `occupied` range. Hops past the first overlap and retries;
/// `start`/hops increase monotonically so it terminates.
fn first_fit(
    start: u64,
    size: u64,
    align: u64,
    occupied: &[Range<u64>],
    region: &'static str,
) -> Result<Range<u64>, PlanError> {
    let mut sorted: Vec<&Range<u64>> = occupied.iter().filter(|r| r.end > r.start).collect();
    sorted.sort_by_key(|r| r.start);

    let mut g = align_up(start, align).ok_or(PlanError::Overflow)?;
    loop {
        let end = g.checked_add(size).ok_or(PlanError::Overflow)?;
        match sorted.iter().find(|r| r.start < end && g < r.end) {
            Some(c) => g = align_up(c.end, align).ok_or(PlanError::Overflow)?,
            None => return Ok(g..end),
        }
        // A conflicting carve-out at the very top of the space can't be
        // hopped: align_up already errored on overflow above, so any further
        // failure means there is genuinely no slot.
        if g == u64::MAX {
            return Err(PlanError::DoesNotFit { region, size });
        }
    }
}

fn align_up(v: u64, a: u64) -> Option<u64> {
    debug_assert!(a.is_power_of_two());
    let mask = a - 1;
    v.checked_add(mask).map(|x| x & !mask)
}

/// Round a region outward to whole `GRAN` units: `[align_down(start),
/// align_up(end))`. Guest physical addresses are far below `u64::MAX`, so the
/// `+GRAN` never overflows here.
fn round_out(r: &Range<u64>) -> Range<u64> {
    let start = r.start & !(GRAN - 1);
    let end = (r.end + (GRAN - 1)) & !(GRAN - 1);
    start..end
}

/// Round `v` up to a multiple of `a` (saturating; used for band sizing).
fn round_up(v: u64, a: u64) -> u64 {
    debug_assert!(a.is_power_of_two());
    (v + (a - 1)) & !(a - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tatu's low slab as a single reserved carve-out, like x86.
    // A one-entry free-list holding the single [0, 2 MiB) range — not a range
    // collected into a Vec of elements.
    #[allow(clippy::single_range_in_vec_init)]
    fn tatu_low() -> Vec<Range<u64>> {
        vec![0..0x20_0000]
    }

    fn args(serial: bool, mmio: u32, pci: u32) -> ArgsSpec {
        ArgsSpec {
            serial,
            mmio_slots: mmio,
            pci_slots: pci,
            window_bits: 37,
            addr_space_bits: 39,
        }
    }

    #[test]
    fn kernel_lands_just_above_tatu() {
        let reserved = tatu_low();
        let lay = Planner {
            args: args(false, 0, 0),
            reserved: &reserved,
            kernel: KernelSpec {
                size: 8 * 1024 * 1024,
                align: 2 * 1024 * 1024,
                min_gpa: 0,
            },
            initrd_size: None,
            relocs_size: None,
        }
        .plan()
        .unwrap();
        assert_eq!(lay.linux.start, 0x20_0000);
        assert_eq!(lay.linux.end, 0x20_0000 + 8 * 1024 * 1024);
        assert!(lay.pci_window.is_none());
    }

    #[test]
    fn kernel_floored_to_min_gpa() {
        let reserved = tatu_low();
        let pref = 16 * 1024 * 1024;
        let lay = Planner {
            args: args(false, 0, 0),
            reserved: &reserved,
            kernel: KernelSpec {
                size: 4 * 1024 * 1024,
                align: 2 * 1024 * 1024,
                min_gpa: pref,
            },
            initrd_size: None,
            relocs_size: None,
        }
        .plan()
        .unwrap();
        assert_eq!(lay.linux.start, pref);
    }

    #[test]
    fn initrd_fits_below_kernel_when_min_gpa_leaves_a_gap() {
        let reserved = tatu_low();
        let pref = 16 * 1024 * 1024;
        let lay = Planner {
            args: args(false, 0, 0),
            reserved: &reserved,
            kernel: KernelSpec {
                size: 4 * 1024 * 1024,
                align: 2 * 1024 * 1024,
                min_gpa: pref,
            },
            initrd_size: Some(1024 * 1024), // fits in [2M, 16M)
            relocs_size: None,
        }
        .plan()
        .unwrap();
        let initrd = lay.initrd.unwrap();
        assert!(initrd.start >= 0x20_0000 && initrd.end <= pref);
    }

    #[test]
    fn pci_window_at_midpoint_default() {
        let reserved = tatu_low();
        let lay = Planner {
            args: args(true, 2, 1), // X=39 B=37
            reserved: &reserved,
            kernel: KernelSpec {
                size: 4 * 1024 * 1024,
                align: 2 * 1024 * 1024,
                min_gpa: 0,
            },
            initrd_size: None,
            relocs_size: None,
        }
        .plan()
        .unwrap();
        let w = lay.pci_window.unwrap();
        assert_eq!(w.start, 1u64 << 38); // 2^(A-1) = 256 GiB
        assert_eq!(w.end - w.start, 1u64 << 37); // 2^B = 128 GiB
    }

    #[test]
    fn device_band_is_contiguous_and_carved() {
        let reserved = tatu_low();
        let lay = Planner {
            args: args(true, 3, 1),
            reserved: &reserved,
            kernel: KernelSpec {
                size: 4 * 1024 * 1024,
                align: 2 * 1024 * 1024,
                min_gpa: 0,
            },
            initrd_size: None,
            relocs_size: None,
        }
        .plan()
        .unwrap();
        let ecam = lay.ecam.unwrap();
        let serial = lay.serial.unwrap();
        assert_eq!(ecam.end - ecam.start, ECAM_SIZE);
        assert_eq!(ecam.start % GRAN, 0);
        // serial immediately follows ECAM; virtio transports follow serial,
        // each 0x200, contiguous.
        assert_eq!(serial.start, ecam.end);
        assert_eq!(lay.virtio.len(), 3);
        assert_eq!(lay.virtio[0].start, serial.end);
        for w in lay.virtio.windows(2) {
            assert_eq!(w[1].start, w[0].end);
            assert_eq!(w[0].end - w[0].start, VIRTIO_SIZE);
        }
        // band avoids the kernel and tatu.
        assert!(ecam.start >= lay.linux.end || ecam.end <= lay.linux.start);
        assert!(ecam.start >= 0x20_0000);
    }

    #[test]
    fn rejects_window_too_large() {
        let reserved = tatu_low();
        let r = Planner {
            args: ArgsSpec {
                serial: false,
                mmio_slots: 0,
                pci_slots: 1,
                window_bits: 35,
                addr_space_bits: 36, // 35 + 2 > 36
            },
            reserved: &reserved,
            kernel: KernelSpec {
                size: 4 * 1024 * 1024,
                align: 2 * 1024 * 1024,
                min_gpa: 0,
            },
            initrd_size: None,
            relocs_size: None,
        }
        .plan();
        assert!(matches!(r, Err(PlanError::WindowTooLarge { .. })));
    }
}
