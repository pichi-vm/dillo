// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Single-pass DTB walk: counts entries, validates bindings, computes
//! per-table sizes, and lays out the output buffer.
//!
//! [`run`] is the only fallible DTB-side phase — emit modules assume
//! the data they're handed is already validated. Products:
//!
//! - [`Offsets`] — slot offsets/lengths for every table.
//! - [`Fadt`] — FADT register descriptors.
//! - `lapic_base: u32` — the validated LAPIC base for MADT.
//! - [`Domains`] — distinct NUMA domain IDs in first-occurrence order
//!   (empty when the tree has no NUMA tagging). Consumed by SLIT emit
//!   for O(1) `(pd → matrix index)` resolution.
//!
//! Binding policy:
//!
//! - `/cpus` + `intc*` are required. Missing or malformed = error.
//! - `syscon-poweroff` is required. Missing = error.
//! - `syscon-reboot`, `pci-host-ecam-generic`, and NUMA bindings are
//!   optional. Absent = corresponding table omitted; partial = error.
//!
//! Per-vCPU MADT/SRAT entries are **not** stored — `count::run` only
//! counts and pre-computes their total byte cost. Emit re-walks `cpus`
//! to produce the actual entries. This keeps the count phase small
//! regardless of vCPU count (limit is the caller's output buffer).

use devtree::{NodeView, PropertyView, TreeView};

use crate::dtb::{DtbNode, cells_as_u32s};
use crate::emit::fadt::Fadt as FadtTable;
use crate::emit::madt::{MadtHeader, lapic_entry_size_for_apic, nmi_entry_size_for_uid};
use crate::emit::mcfg::McfgHeader;
use crate::emit::motherboard_resource;
use crate::emit::pci_host;
use crate::emit::rsdp::Rsdp;
use crate::emit::sdt::{GenericAddress, S5_AML_LEN, SdtHeader};
use crate::emit::serial_device;
use crate::emit::slit::SlitHeader;
use crate::emit::spcr::{self, Spcr};
use crate::emit::srat::{SratHeader, cpu_affinity_size_for_apic};
use crate::emit::xsdt;
use crate::error::{DtbError, NumaIncomplete, Site};

/// IOAPIC stride convention: each IOAPIC owns 24 consecutive GSIs
/// starting at its base. 24 is the standard Intel IOAPIC pin count
/// and is what every commodity virtual IOAPIC presents. DT cannot
/// express GSI numbering (each `interrupt-controller`'s `interrupts`
/// cells are local to that controller — no flat global IRQ space),
/// so this stride plus sequential IOAPIC IDs are policy choices
/// made entirely on the ACPI side. If a future caller needs to
/// describe an IOAPIC with a different pin count, this is the only
/// thing that has to change.
pub(crate) const IOAPIC_GSI_STRIDE: u32 = 24;

/// Raw DT `status` property value per DT spec §2.3.4 — the operational
/// state of a device. Used by both cpu nodes (DT spec §3.8.1, where
/// the values have CPU-specific definitions) and memory nodes
/// (DT spec §3.4, where `status` is permitted via "All other standard
/// properties (Section 2.3) are allowed"). Per-consumer mapping to
/// ACPI flag bits lives in the emit modules.
///
/// `"fail-<sss>"` (vendor-specific failure suffix per §2.3.4) folds
/// into [`Self::Fail`] — the suffix is informational; the operational
/// implication is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DtStatus {
    /// `"okay"` or property absent (DT spec default).
    Okay,
    /// `"disabled"` — quiescent. For cpus, brought online via an
    /// explicit `enable-method` (§3.8.1) — on x86 the enable method
    /// is INIT/SIPI, implicit, and we do not validate that property
    /// is present. For memory, this typically pairs with the
    /// `hotpluggable` property to express a hot-add slot.
    Disabled,
    /// `"reserved"` — operational, but should not be used; typically
    /// controlled by another software component such as platform
    /// firmware. ACPI MADT/SRAT have no encoding for "exists, is
    /// operational, but don't touch" — see the per-consumer flag
    /// derivation for how we map this to ACPI's nearest equivalent.
    Reserved,
    /// `"fail"` or `"fail-<sss>"` — not operational, or does not
    /// exist (§3.8.1 explicitly enumerates both meanings). Maps to
    /// ACPI's "OSPM ignores this entry" encoding.
    Fail,
}

impl DtStatus {
    /// Parse a DT `status` property value. `None` for any string the
    /// DT spec does not define (callers attribute that to a site-tagged
    /// [`DtbError::MalformedProperty`]).
    pub(crate) fn from_dt_str(s: &str) -> Option<Self> {
        match s {
            "okay" => Some(Self::Okay),
            "disabled" => Some(Self::Disabled),
            "reserved" => Some(Self::Reserved),
            s if s == "fail" || s.starts_with("fail-") => Some(Self::Fail),
            _ => None,
        }
    }
}

/// FADT register descriptors produced by the same pass as [`Offsets`]
/// (it shares the syscon-poweroff / syscon-reboot tree walks).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fadt {
    pub sleep_control_reg: GenericAddress,
    pub sleep_status_reg: GenericAddress,
    pub reset_reg: Option<GenericAddress>,
    pub reset_value: u8,
    /// Byte the guest must write to `sleep_control_reg` to trigger
    /// shutdown — taken verbatim from syscon-poweroff's `value`
    /// property. Threaded to [`crate::emit::sdt::SdtHeader::write_dsdt_into`]
    /// so the `\_S5_` AML object's SLP_TYP makes Linux emit this exact
    /// byte. Default 0 when the syscon-poweroff `value` property is absent.
    pub sleep_value: u8,
}

/// Internal scratch: raw counts produced by the DTB walk, immediately
/// consumed to derive [`Offsets`]. Not exposed.
struct Counts {
    vcpu_entries_bytes: usize,
    cpu_entries_bytes: usize,
    ioapic_count: u32,
    ecam_count: u32,
    /// Total bytes of DSDT body AML contributed by `Device(PCI<n>)`
    /// declarations — one per `pci-host-ecam-generic` root child.
    /// Computed by [`pci_host::dsdt_total_bytes`] so count and emit
    /// agree on the slot size without duplicating the size math.
    pci_dsdt_bytes: usize,
    /// Total bytes of DSDT body AML contributed by `PNP0C02` motherboard
    /// resource devices that reserve ECAM windows.
    motherboard_dsdt_bytes: usize,
    /// Total bytes of DSDT body AML contributed by `Device(SER0)`,
    /// or zero when the DTB has no serial node.
    serial_dsdt_bytes: usize,
    /// Total bytes of DSDT body AML contributed by `Device(VMnn)` virtio-mmio
    /// transports — one per `virtio,mmio` root child, zero when none.
    virtio_mmio_dsdt_bytes: usize,
    /// Whether the tree declares a `ns16550a` serial node — drives
    /// whether the SPCR table is emitted.
    has_serial: bool,
    has_numa: bool,
    memory_region_count: u32,
    has_distances: bool,
}

/// Distinct NUMA proximity domains in first-occurrence order: cpus
/// first (in `cpus.children()` order), then memory-only domains (in
/// `root.children()` order). Built once by [`run`] and consumed by
/// SLIT emit to resolve `(pd → matrix index)` in O(1) per cell.
///
/// Capacity is fixed at 256 because the SLIT header's
/// number-of-localities is a single byte, matching the binding
/// already enforced by `count_numa` via `u8::try_from(n_domains_u32)`.
/// No allocation: this is a 1 KB stack-resident array, suitable for
/// the boot-path context.
// Intentionally not `Copy`: `Domains` is ~1 KB on the stack; matches
// the policy stated on `CpuCache` below. Pass by `&Domains` /
// `&mut Domains` only.
#[derive(Debug, Clone)]
pub(crate) struct Domains {
    ids: [u32; 256],
    n: u8,
}

/// Hard cap on supported cpus. Tied to MADT's u8 `processor_id`
/// field (Type 0 §5.2.12.2, Type 4 §5.2.12.7) — UIDs above 255 cannot
/// be encoded, and `cpu@N` walk order produces sequential UIDs.
/// `count::run` rejects oversize trees as [`DtbError::TooManyCpus`];
/// the [`CpuCache`] is sized to match so emit can index it directly.
pub(crate) const CPU_CACHE_CAP: usize = 256;

/// Per-cpu data captured during `count::walk_cpus` so MADT and SRAT
/// emit can skip the `cpus.children()` re-walk and the per-cpu
/// property lookups.
///
/// Struct-of-arrays layout: 4-byte `apic_id`, 4-byte `numa_tag` (with
/// `u32::MAX` sentinel meaning "untagged"), and a 1-byte status code.
/// Roughly 2.3 KB at 256 cpus; not `Copy` so it isn't memcpy'd around
/// — populate it once in place and pass by reference. Oversize trees
/// surface as [`DtbError::TooManyCpus`] from [`Self::push`].
#[derive(Debug)]
pub(crate) struct CpuCache {
    apic_ids: [u32; CPU_CACHE_CAP],
    /// Per-cpu `numa-node-id`; `u32::MAX` means the property was absent
    /// on that cpu. (Real DTs would not use `u32::MAX` as a domain id;
    /// the SLIT cap is 256.)
    numa_tags: [u32; CPU_CACHE_CAP],
    /// Per-cpu [`DtStatus`] encoded via [`status_to_u8`].
    statuses: [u8; CPU_CACHE_CAP],
    /// Total cpu count observed. Bounded by [`CPU_CACHE_CAP`] —
    /// `push` rejects beyond that.
    n: u32,
}

const NUMA_TAG_NONE: u32 = u32::MAX;

#[inline]
const fn status_to_u8(s: DtStatus) -> u8 {
    match s {
        DtStatus::Okay => 0,
        DtStatus::Disabled => 1,
        DtStatus::Reserved => 2,
        DtStatus::Fail => 3,
    }
}

#[inline]
const fn status_from_u8(b: u8) -> DtStatus {
    // Only `status_to_u8` writes these bytes (0..=3). The wildcard
    // arm is unreachable on any byte this crate produced; it exists
    // because `match` over `u8` cannot be syntactically exhaustive.
    match b {
        0 => DtStatus::Okay,
        1 => DtStatus::Disabled,
        2 => DtStatus::Reserved,
        // 3 (or any other byte): treat as Fail. status_to_u8 only
        // ever produces 0..=3.
        _ => DtStatus::Fail,
    }
}

impl CpuCache {
    pub(crate) fn new() -> Self {
        Self {
            apic_ids: [0; CPU_CACHE_CAP],
            numa_tags: [NUMA_TAG_NONE; CPU_CACHE_CAP],
            statuses: [0; CPU_CACHE_CAP],
            n: 0,
        }
    }

    fn push(
        &mut self,
        apic_id: u32,
        numa_tag: Option<u32>,
        status: DtStatus,
    ) -> Result<(), DtbError> {
        let idx = usize::try_from(self.n).map_err(|_| DtbError::Internal)?;
        if idx >= CPU_CACHE_CAP {
            return Err(DtbError::TooManyCpus {
                limit: CPU_CACHE_CAP,
            });
        }
        *self.apic_ids.get_mut(idx).ok_or(DtbError::Internal)? = apic_id;
        *self.numa_tags.get_mut(idx).ok_or(DtbError::Internal)? = numa_tag.unwrap_or(NUMA_TAG_NONE);
        *self.statuses.get_mut(idx).ok_or(DtbError::Internal)? = status_to_u8(status);
        self.n = self.n.checked_add(1).ok_or(DtbError::Internal)?;
        Ok(())
    }

    /// Iterate `(processor_id, apic_id, numa_tag, status)` in walk
    /// order. Bounded by [`CPU_CACHE_CAP`] — `push` rejects beyond
    /// that, so every observed cpu is present.
    pub(crate) fn entries(&self) -> impl Iterator<Item = (u32, u32, Option<u32>, DtStatus)> + '_ {
        let n_in_cache: usize = usize::try_from(self.n).unwrap_or(0);
        // `push` enforces n_in_cache <= CPU_CACHE_CAP and i < u32::MAX
        // (CPU_CACHE_CAP = 256), so the zipped iter is exactly
        // n_in_cache long and the u32 cast is infallible — no silent
        // drops if a future invariant slips.
        self.apic_ids
            .iter()
            .zip(self.numa_tags.iter())
            .zip(self.statuses.iter())
            .take(n_in_cache)
            .enumerate()
            .map(|(i, ((apic, numa_raw), status_b))| {
                let numa = if *numa_raw == NUMA_TAG_NONE {
                    None
                } else {
                    Some(*numa_raw)
                };
                // i < CPU_CACHE_CAP = 256, infallible.
                let pid = u32::try_from(i).unwrap_or(0);
                (pid, *apic, numa, status_from_u8(*status_b))
            })
    }
}

impl Domains {
    pub(crate) const fn new() -> Self {
        Self {
            ids: [0; 256],
            n: 0,
        }
    }

    /// Number of distinct domains recorded so far.
    pub(crate) const fn len(&self) -> u8 {
        self.n
    }

    fn ids(&self) -> &[u32] {
        let n = usize::from(self.n);
        // n: u8 ≤ 255; array length 256. Slice is always in bounds.
        self.ids.get(..n).unwrap_or(&[])
    }

    /// Append `pd` if not already present. Returns
    /// [`DtbError::ValueOutOfRange`] (site `DistanceMap`) if the
    /// 256-domain cap would be exceeded — matches the cap
    /// `count_numa` enforces when narrowing to the SLIT header's u8.
    pub(crate) fn insert(&mut self, pd: u32) -> Result<(), DtbError> {
        if self.ids().contains(&pd) {
            return Ok(());
        }
        // Reserve the slot via checked_add BEFORE writing, so an overflow
        // (the 256th distinct domain) returns the error with no observable
        // mutation to `self.ids`.
        let new_n = self.n.checked_add(1).ok_or(DtbError::ValueOutOfRange {
            site: Site::DistanceMap,
            property: "numa-node-id",
        })?;
        let next = usize::from(self.n);
        let cell = self.ids.get_mut(next).ok_or(DtbError::Internal)?;
        *cell = pd;
        self.n = new_n;
        Ok(())
    }

    /// 0-based index of `pd` in the set, or `None` if not present.
    /// Linear scan over at most `self.n` entries (u8-bounded).
    pub(crate) fn index_of(&self, pd: u32) -> Option<u8> {
        self.ids()
            .iter()
            .position(|&x| x == pd)
            .and_then(|i| u8::try_from(i).ok())
    }
}

// ─── Offsets: slot layout in the output buffer ──────────────────────────

/// One table's position and size in the output buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    pub offset: usize,
    pub len: usize,
}

impl Slot {
    /// GPA at which this slot will live.
    ///
    /// # Errors
    /// [`DtbError::Internal`] if `base_gpa + offset` overflows
    /// `u64`. Unreachable on any realistic `base_gpa`; serves as
    /// the last line of defense against a layout bug.
    #[inline]
    pub(crate) fn gpa(self, base_gpa: u64) -> Result<u64, DtbError> {
        let off = u64::try_from(self.offset).map_err(|_| DtbError::Internal)?;
        base_gpa.checked_add(off).ok_or(DtbError::Internal)
    }

    /// Advance `cur` by `n` bytes and return the carved-out slot.
    /// Used by [`Offsets::new`] to lay tables out sequentially.
    #[inline]
    fn carve(cur: &mut usize, n: usize) -> Result<Self, DtbError> {
        let offset = *cur;
        *cur = cur.checked_add(n).ok_or(DtbError::Internal)?;
        Ok(Self { offset, len: n })
    }

    /// Borrow this slot's bytes out of `buf`. Unreachable on error
    /// because `populate` already validated `buf.len() >= off.total`
    /// and [`Offsets::new`] guarantees every slot fits within `total`
    /// — but the strict `indexing_slicing` lint requires the `.get_mut`
    /// form regardless. A failure here is a layout-accounting bug, not
    /// a DTB or buffer fault — surface it as such via
    /// [`DtbError::Internal`].
    #[inline]
    pub(crate) fn carve_in(self, buf: &mut [u8]) -> Result<&mut [u8], DtbError> {
        let end = self
            .offset
            .checked_add(self.len)
            .ok_or(DtbError::Internal)?;
        buf.get_mut(self.offset..end).ok_or(DtbError::Internal)
    }
}

/// Concrete byte layout for every table. RSDP first so the buffer's
/// first byte (and `base_gpa`) is the RSDP's location:
///
/// ```text
/// ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
/// │ RSDP │ DSDT │ FADT │ MADT │ MCFG?│ SPCR?│ SRAT?│ SLIT?│ XSDT │
/// └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘
/// ```
#[derive(Debug, Clone, Copy)]
pub(crate) struct Offsets {
    pub rsdp: Slot,
    pub dsdt: Slot,
    pub fadt: Slot,
    pub madt: Slot,
    pub mcfg: Option<Slot>,
    pub spcr: Option<Slot>,
    pub srat: Option<Slot>,
    pub slit: Option<Slot>,
    pub xsdt: Slot,
    /// Total bytes the layout occupies.
    pub total: usize,
}

impl Offsets {
    /// Lay out every table sequentially, computing per-slot offsets
    /// and the total byte cost. Consumes the raw `Counts` produced by
    /// the DTB walk; `n_domains` comes from the populated [`Domains`]
    /// set so SLIT can be sized.
    fn new(c: &Counts, n_domains: u8) -> Result<Self, DtbError> {
        let mut cur: usize = 0;

        let rsdp = Slot::carve(&mut cur, Rsdp::SIZE)?;
        // DSDT body carries `\_S5_` (so Linux installs `acpi_power_off`
        // as `pm_power_off`) plus one `Device(PCI<n>)` block per
        // `pci-host-ecam-generic` root child (so `acpi_pci_root_add`
        // registers each PCI root bus), plus `Device(SER0)` when the
        // DTB declares an ns16550a UART. SPCR points firmware console
        // redirection at the UART, but Linux still needs an enumerable
        // ACPI device before it creates a normal ttyS port.
        let dsdt_size = SdtHeader::SIZE
            .checked_add(S5_AML_LEN)
            .and_then(|n| n.checked_add(c.motherboard_dsdt_bytes))
            .and_then(|n| n.checked_add(c.pci_dsdt_bytes))
            .and_then(|n| n.checked_add(c.serial_dsdt_bytes))
            .and_then(|n| n.checked_add(c.virtio_mmio_dsdt_bytes))
            .ok_or(DtbError::Internal)?;
        let dsdt = Slot::carve(&mut cur, dsdt_size)?;
        let fadt = Slot::carve(&mut cur, FadtTable::SIZE)?;
        let madt = Slot::carve(
            &mut cur,
            MadtHeader::total_size(c.ioapic_count, c.vcpu_entries_bytes)?,
        )?;

        let mcfg = if c.ecam_count > 0 {
            Some(Slot::carve(
                &mut cur,
                McfgHeader::total_size(c.ecam_count)?,
            )?)
        } else {
            None
        };

        let spcr = if c.has_serial {
            Some(Slot::carve(&mut cur, Spcr::SIZE)?)
        } else {
            None
        };

        let (srat, slit) = if c.has_numa {
            let srat_slot = Slot::carve(
                &mut cur,
                SratHeader::total_size(c.memory_region_count, c.cpu_entries_bytes)?,
            )?;
            let slit_slot = if c.has_distances {
                Some(Slot::carve(&mut cur, SlitHeader::total_size(n_domains)?)?)
            } else {
                None
            };
            (Some(srat_slot), slit_slot)
        } else {
            (None, None)
        };

        // XSDT entries: FADT + MADT always; MCFG/SPCR/SRAT/SLIT when
        // present. The field list mirrors [`Self::xsdt_targets`] — keep
        // them in sync.
        let optional_count = [mcfg, spcr, srat, slit]
            .iter()
            .filter(|s| s.is_some())
            .count();
        let n_entries = 2usize
            .checked_add(optional_count)
            .ok_or(DtbError::Internal)?;
        let xsdt = Slot::carve(&mut cur, xsdt::total_size(n_entries)?)?;

        Ok(Self {
            rsdp,
            dsdt,
            fadt,
            madt,
            mcfg,
            spcr,
            srat,
            slit,
            xsdt,
            total: cur,
        })
    }

    /// Slots referenced by XSDT, in emission order: FADT + MADT always,
    /// then any of MCFG / SPCR / SRAT / SLIT that are present. RSDP,
    /// DSDT, and XSDT itself are excluded (RSDP points at XSDT; DSDT is
    /// referenced by FADT; XSDT cannot reference itself).
    pub(crate) fn xsdt_targets(&self) -> impl Iterator<Item = Slot> + '_ {
        [
            Some(self.fadt),
            Some(self.madt),
            self.mcfg,
            self.spcr,
            self.srat,
            self.slit,
        ]
        .into_iter()
        .flatten()
    }
}

// ─── count::run — the single-pass DTB walker ────────────────────────────

/// Walk the tree once per subtree, validating bindings and counting
/// entries. Returns the layout plus the values emit needs that aren't
/// otherwise derivable from `Offsets`:
///
/// - `lapic_base` — MADT's local-APIC-address header field.
/// - `domains` — populated in place with first-occurrence-ordered NUMA
///   proximity domains.
pub(crate) fn run<T: TreeView>(
    tree: &T,
    cpu_cache: &mut CpuCache,
    domains: &mut Domains,
) -> Result<(Offsets, Fadt, u32), DtbError> {
    let root = DtbNode::root_of(tree.root());

    // Required subtrees first. cpu walk populates the cpu side of
    // `domains`; memory walk extends it with memory-only domains.
    let cpu_walk = root.walk_cpus(domains, cpu_cache)?;
    let (lapic_base, ioapic_count) = root.count_intc()?;
    let fadt = root.extract_fadt()?;

    // Optional subtrees.
    let ecam_count = root.count_mcfg()?;
    let motherboard_dsdt_bytes = motherboard_resource::dsdt_total_bytes(tree)?;
    let pci_dsdt_bytes = pci_host::dsdt_total_bytes(tree)?;
    let serial_dsdt_bytes = serial_device::dsdt_total_bytes(tree)?;
    let virtio_mmio_dsdt_bytes = crate::emit::virtio_mmio::dsdt_total_bytes(tree)?;
    let has_serial = spcr::present(tree)?;
    let (has_numa, memory_region_count, has_distances) = root.count_numa(&cpu_walk, domains)?;

    let counts = Counts {
        vcpu_entries_bytes: cpu_walk.vcpu_entries_bytes,
        cpu_entries_bytes: cpu_walk.cpu_entries_bytes,
        ioapic_count,
        ecam_count,
        motherboard_dsdt_bytes,
        pci_dsdt_bytes,
        serial_dsdt_bytes,
        virtio_mmio_dsdt_bytes,
        has_serial,
        has_numa,
        memory_region_count,
        has_distances,
    };
    let offsets = Offsets::new(&counts, domains.len())?;
    Ok((offsets, fadt, lapic_base))
}

/// Aggregate of everything the single `/cpus` walk produces.
struct CpuWalk {
    vcpu_entries_bytes: usize,
    cpu_entries_bytes: usize,
    cpu_tagged_count: u32,
    cpu_untagged_count: u32,
}

// ─── small helpers shared with emit ─────────────────────────────────────

/// `true` iff `name` is `prefix` optionally followed by `@<unit>`.
#[inline]
pub(crate) fn base_name_is(name: &str, prefix: &str) -> bool {
    let stem = match name.find('@') {
        Some(i) => name.get(..i).unwrap_or(name),
        None => name,
    };
    stem == prefix
}

// ─── private to count.rs ─────────────────────────────────────────────────

// ─── DtbNode methods used by count (and shared with emit) ───────────────

impl<N: NodeView + Copy> DtbNode<N> {
    /// Decode this node's standard `status` property into [`DtStatus`].
    /// Absent property → [`DtStatus::Okay`] (DT spec §2.3.4 default).
    /// Malformed values surface as
    /// [`DtbError::MalformedProperty`] attributed to `site` — the caller
    /// passes [`Site::Cpu`] for cpu nodes, [`Site::Memory`] for memory.
    pub(crate) fn decode_status(&self, site: Site) -> Result<DtStatus, DtbError> {
        let Some(prop) = self.node.property("status") else {
            return Ok(DtStatus::Okay);
        };
        let malformed = || DtbError::MalformedProperty {
            site,
            property: "status",
        };
        let s = prop.as_str().ok_or_else(malformed)?;
        DtStatus::from_dt_str(s).ok_or_else(malformed)
    }

    /// Decode the standard DT `hotpluggable` property on a `/memory@…`
    /// node (DT spec §3.4, Table 3.3). Value type is `<empty>` (presence
    /// is the entire signal): present → may be hot-removed/added later.
    /// Maps to the ACPI SRAT Memory Affinity `HotPluggable` flag bit.
    pub(crate) fn decode_memory_hotpluggable(&self) -> bool {
        self.node.property("hotpluggable").is_some()
    }

    /// Pull `(apic_id, numa-node-id, status)` out of a `cpu@N` node in
    /// a single struct-block scan. Beats three back-to-back
    /// `property()` lookups (one per name) by paying the per-property
    /// prologue exactly once per property, not once per lookup.
    /// Called from `walk_cpus` over every `cpu@N` — at 256 cpus the
    /// savings are the dominant gain on the count side.
    #[inline]
    pub(crate) fn decode_cpu_subset(&self) -> Result<(u32, Option<u32>, DtStatus), DtbError> {
        let [reg_prop, numa_prop, status_prop] =
            self.node
                .property_subset([b"reg".as_slice(), b"numa-node-id", b"status"]);

        // reg → APIC ID (first cell of the first (base, _size) pair).
        let reg_prop = reg_prop.ok_or(DtbError::MissingProperty {
            site: Site::Cpu,
            property: "reg",
        })?;
        let mut reg_iter = crate::dtb::RegIter::new(
            reg_prop,
            self.parent_addr_cells,
            self.parent_size_cells,
            Site::Cpu,
        )?;
        // Present-but-empty reg → Malformed (not Missing — that's the
        // absent-property case caught above).
        let apic_id_u64 = reg_iter
            .next()
            .ok_or(DtbError::MalformedProperty {
                site: Site::Cpu,
                property: "reg",
            })?
            .0;
        let apic_id = u32::try_from(apic_id_u64).map_err(|_| DtbError::ValueOutOfRange {
            site: Site::Cpu,
            property: "reg",
        })?;

        // numa-node-id → Option<u32>. Site matches what
        // `property_u32_opt` would report: the iterator's inherited
        // parent site (`Cpus`), not the cpu node's own site. This
        // preserves the error attribution the integration tests
        // expect when a cpu under `/cpus` carries a malformed
        // numa-node-id.
        //
        // Reject `u32::MAX`: it collides with `NUMA_TAG_NONE`, the
        // in-cache sentinel for "property absent". Without this guard,
        // count accepts a tagged cpu and sizes SRAT for it, but emit's
        // CpuCache fast path decodes the sentinel back to None and
        // raises `PartialNuma::CpuUntagged` mid-write.
        let numa = match numa_prop {
            None => None,
            Some(p) => {
                let v = p.as_u32().ok_or(DtbError::MalformedProperty {
                    site: self.site,
                    property: "numa-node-id",
                })?;
                if v == NUMA_TAG_NONE {
                    return Err(DtbError::ValueOutOfRange {
                        site: self.site,
                        property: "numa-node-id",
                    });
                }
                Some(v)
            }
        };

        // status → DtStatus (default Okay if absent, per DT spec §2.3.4).
        let status = match status_prop {
            None => DtStatus::Okay,
            Some(p) => {
                let s = p.as_str().ok_or(DtbError::MalformedProperty {
                    site: Site::Cpu,
                    property: "status",
                })?;
                DtStatus::from_dt_str(s).ok_or(DtbError::MalformedProperty {
                    site: Site::Cpu,
                    property: "status",
                })?
            }
        };

        Ok((apic_id, numa, status))
    }

    /// Decode and validate a PCI host bridge's `bus-range` property:
    /// two big-endian u32 cells, both within u8, `start ≤ end`. Shared
    /// between [`count_mcfg`] and [`crate::emit::mcfg::emit`] so the
    /// count→emit re-walk parses bytes identically by construction.
    pub(crate) fn decode_pci_bus_range(&self) -> Result<(u8, u8), DtbError> {
        let bus_prop = self
            .node
            .property("bus-range")
            .ok_or(DtbError::MissingProperty {
                site: Site::PciHost,
                property: "bus-range",
            })?;
        let mut cells = cells_as_u32s(bus_prop.as_ref());
        let start = cells.next().ok_or(DtbError::MalformedProperty {
            site: Site::PciHost,
            property: "bus-range",
        })?;
        let end = cells.next().ok_or(DtbError::MalformedProperty {
            site: Site::PciHost,
            property: "bus-range",
        })?;
        let bus_start = u8::try_from(start).map_err(|_| DtbError::ValueOutOfRange {
            site: Site::PciHost,
            property: "bus-range",
        })?;
        let bus_end = u8::try_from(end).map_err(|_| DtbError::ValueOutOfRange {
            site: Site::PciHost,
            property: "bus-range",
        })?;
        if bus_start > bus_end {
            return Err(DtbError::MalformedProperty {
                site: Site::PciHost,
                property: "bus-range",
            });
        }
        Ok((bus_start, bus_end))
    }

    /// Find the LAPIC node (`compatible = "intel,ce4100-lapic"`) among
    /// this (root) node's children. Used by both count and emit. Its
    /// `reg[0]` base is the MADT local-APIC address.
    pub(crate) fn find_lapic(&self) -> Result<Self, DtbError> {
        for child in self.children()? {
            if child.has_compatible("intel,ce4100-lapic")? {
                return Ok(child);
            }
        }
        Err(DtbError::MissingNode { site: Site::Intc })
    }

    /// Iterate this (root) node's `intel,ce4100-ioapic` children, in
    /// `root.children()` order. Each node's `reg[0]` base is one MADT
    /// IOAPIC entry. Used by both count (to size) and emit (to write).
    pub(crate) fn ioapic_nodes(&self) -> Result<impl Iterator<Item = Self> + '_, DtbError> {
        Ok(self
            .children()?
            .filter(|c| c.has_compatible("intel,ce4100-ioapic").unwrap_or(false)))
    }

    /// Walk `/cpus`, validating each cpu node's bindings and computing
    /// the byte cost of its MADT and SRAT entries. Establishes the
    /// **processor UID assignment policy**: UID is the cpu's 0-based
    /// index in `cpus.children()` walk order (i.e. `n_vcpus` so far at the
    /// time the cpu is visited). UID 0 is therefore the conventional
    /// BSP — enforced by the [`DtbError::BootCpuNotEnabled`] check
    /// below — and `madt::emit` / `srat::emit` re-walk in the same
    /// order to produce matching UIDs. ACPI does not constrain
    /// UID-to-APIC-ID relationships, so sequential walk-order indexing
    /// is unambiguous and matches what every VMM (qemu, kvm, hyper-v,
    /// vmware) does in practice.
    fn walk_cpus(
        &self,
        domains: &mut Domains,
        cpu_cache: &mut CpuCache,
    ) -> Result<CpuWalk, DtbError> {
        let cpus = self
            .child("cpus", Site::Cpus)?
            .ok_or(DtbError::MissingNode { site: Site::Cpus })?;

        let mut w = CpuWalk {
            vcpu_entries_bytes: 0,
            cpu_entries_bytes: 0,
            cpu_tagged_count: 0,
            cpu_untagged_count: 0,
        };
        let mut n_vcpus: u32 = 0;
        for child in cpus.children()? {
            if !base_name_is(child.name(), "cpu") {
                continue;
            }
            let processor_id = n_vcpus;
            // Single struct-block scan pulling all three properties
            // count needs out of this cpu node at once — beats three
            // independent `property()` lookups by paying the per-prop
            // prologue (token read + strings-block NUL search) just
            // once per property instead of once per lookup.
            let (apic_id, tag, status) = child.decode_cpu_subset()?;

            // The hypervisor designates a vCPU as BSP at VM creation
            // (universally vCPU 0 in qemu/kvm/hyper-v/vmware), then sets
            // its IA32_APIC_BASE_MSR.BSP bit. The first cpu in walk
            // order therefore becomes the BSP-as-itself when it reads
            // ACPI; its MADT Enabled bit must be 1 or the entry is
            // self-contradictory.
            if processor_id == 0 && !matches!(status, DtStatus::Okay) {
                return Err(DtbError::BootCpuNotEnabled);
            }

            let per_vcpu = lapic_entry_size_for_apic(apic_id, processor_id)
                .checked_add(nmi_entry_size_for_uid(processor_id))
                .ok_or(DtbError::Internal)?;
            w.vcpu_entries_bytes = w
                .vcpu_entries_bytes
                .checked_add(per_vcpu)
                .ok_or(DtbError::Internal)?;
            w.cpu_entries_bytes = w
                .cpu_entries_bytes
                .checked_add(cpu_affinity_size_for_apic(apic_id))
                .ok_or(DtbError::Internal)?;

            if let Some(pd) = tag {
                w.cpu_tagged_count = w
                    .cpu_tagged_count
                    .checked_add(1)
                    .ok_or(DtbError::Internal)?;
                domains.insert(pd)?;
            } else {
                w.cpu_untagged_count = w
                    .cpu_untagged_count
                    .checked_add(1)
                    .ok_or(DtbError::Internal)?;
            }

            cpu_cache.push(apic_id, tag, status)?;

            n_vcpus = n_vcpus.checked_add(1).ok_or(DtbError::Internal)?;
        }
        if n_vcpus == 0 {
            return Err(DtbError::MissingNode { site: Site::Cpu });
        }
        Ok(w)
    }

    /// Decode an interrupt-controller node's `reg[0]` base, validating
    /// it fits the MADT u32 address field. Shared by the LAPIC and
    /// every IOAPIC.
    fn intc_base(&self) -> Result<u32, DtbError> {
        let base_u64 = self
            .reg(Site::Intc)?
            .next()
            .ok_or(DtbError::MalformedProperty {
                site: Site::Intc,
                property: "reg",
            })?
            .0;
        u32::try_from(base_u64).map_err(|_| DtbError::ValueOutOfRange {
            site: Site::Intc,
            property: "reg",
        })
    }

    /// Locate the LAPIC + IOAPIC nodes and return `(lapic_base,
    /// ioapic_count)`. The LAPIC (`intel,ce4100-lapic`) supplies the
    /// MADT local-APIC address; each `intel,ce4100-ioapic` node is one
    /// IOAPIC entry. All bases are validated to fit the MADT u32 field.
    fn count_intc(&self) -> Result<(u32, u32), DtbError> {
        let lapic_base = self.find_lapic()?.intc_base()?;

        let mut ioapic_count: u32 = 0;
        for ioapic in self.ioapic_nodes()? {
            let _ = ioapic.intc_base()?;
            ioapic_count = ioapic_count.checked_add(1).ok_or(DtbError::Internal)?;
        }
        Ok((lapic_base, ioapic_count))
    }

    /// Count PCI-host ECAM bridges under this (root) node, validating
    /// each one's `reg` and `bus-range` so emit can re-walk without
    /// re-validating.
    fn count_mcfg(&self) -> Result<u32, DtbError> {
        let mut ecam_count: u32 = 0;
        for child in self.children()? {
            if !child.has_compatible("pci-host-ecam-generic")? {
                continue;
            }
            // Validate: reg present + decodable.
            let _ = child
                .reg(Site::PciHost)?
                .next()
                .ok_or(DtbError::MissingProperty {
                    site: Site::PciHost,
                    property: "reg",
                })?;
            // Validate: bus-range present, two cells, both fit in u8, start <= end.
            let _ = child.decode_pci_bus_range()?;
            ecam_count = ecam_count.checked_add(1).ok_or(DtbError::Internal)?;
        }
        Ok(ecam_count)
    }

    /// Build the [`Fadt`] register plan from syscon-poweroff (required)
    /// and syscon-reboot (optional). Both are looked up in a single
    /// `root.children()` walk — calling `find_compatible` twice would
    /// pay the per-child `skip_subtree` cost twice over the same
    /// children, which adds up across `count`'s already-multiple
    /// root walks.
    fn extract_fadt(&self) -> Result<Fadt, DtbError> {
        let mut poweroff: Option<Self> = None;
        let mut reboot: Option<Self> = None;
        for child in self.children()? {
            // Independent checks: a node compatible with both
            // syscon-poweroff and syscon-reboot must be claimed for
            // both, matching the pre-fused-loop behavior. Realistic
            // DTs don't do this, but the cost of `else if` was a
            // silent behavior change vs. two separate find_compatible
            // calls.
            if poweroff.is_none() && child.has_compatible("syscon-poweroff")? {
                poweroff = Some(child);
            }
            if reboot.is_none() && child.has_compatible("syscon-reboot")? {
                reboot = Some(child);
            }
            if poweroff.is_some() && reboot.is_some() {
                break;
            }
        }

        let poweroff = poweroff.ok_or(DtbError::MissingNode {
            site: Site::SysconPoweroff,
        })?;
        let (sleep_addr, sleep_value) =
            poweroff.resolve_syscon(Site::SysconPoweroff, /* value_required */ false)?;
        let sleep_control_reg = GenericAddress::system_memory_byte(sleep_addr);
        let sleep_status_reg = sleep_control_reg;

        let (reset_reg, reset_value) = match reboot {
            None => (None, 0),
            Some(reboot) => {
                let (a, v) = reboot.resolve_syscon(Site::SysconReboot, true)?;
                (Some(GenericAddress::system_memory_byte(a)), v)
            }
        };

        Ok(Fadt {
            sleep_control_reg,
            sleep_status_reg,
            reset_reg,
            reset_value,
            sleep_value,
        })
    }

    /// Resolve this standalone syscon node (`syscon-poweroff` /
    /// `syscon-reboot`): read its own `reg[0]` base and its `value`,
    /// returning `(address, value)`. The deprecated `regmap` phandle +
    /// `offset` indirection is gone — each node carries its register
    /// directly (device-model §4, x86 poweroff/reset).
    fn resolve_syscon(&self, site: Site, value_required: bool) -> Result<(u64, u8), DtbError> {
        let addr = self
            .reg(site)?
            .next()
            .ok_or(DtbError::MalformedProperty {
                site,
                property: "reg",
            })?
            .0;
        // For syscon-poweroff (value_required=false) the DT binding
        // documents `value` as optional with a default of 0 (the value
        // written to the sleep register to power off). For syscon-reboot
        // we require it explicitly: 0 is almost never the right reset
        // payload and silently substituting it would manifest as a hang.
        let value_u32 = match self.node.property("value") {
            Some(p) => p.as_u32().ok_or(DtbError::MalformedProperty {
                site,
                property: "value",
            })?,
            None if value_required => {
                return Err(DtbError::MissingProperty {
                    site,
                    property: "value",
                });
            }
            None => 0,
        };
        let value = u8::try_from(value_u32).map_err(|_| DtbError::ValueOutOfRange {
            site,
            property: "value",
        })?;
        Ok((addr, value))
    }

    /// Returns `(has_numa, memory_region_count, has_distances)`. Extends
    /// `domains` with any memory-only proximity domains discovered (those
    /// already covered by a cpu are already present).
    fn count_numa(
        &self,
        cpu_walk: &CpuWalk,
        domains: &mut Domains,
    ) -> Result<(bool, u32, bool), DtbError> {
        let mut memory_region_count: u32 = 0;
        let mut memory_tagged_count: u32 = 0;
        let mut memory_total_count: u32 = 0;

        for child in self.children()? {
            if !base_name_is(child.name(), "memory") {
                continue;
            }
            memory_total_count = memory_total_count
                .checked_add(1)
                .ok_or(DtbError::Internal)?;
            // Validate `status` at count time so `srat::emit` can trust
            // the decode. Same pattern as the cpu side: fail-fast on
            // malformed values before any bytes are written. The result
            // is discarded here; `srat::emit` re-decodes when actually
            // computing the SRAT flag bits.
            let _ = child.decode_status(Site::Memory)?;
            let tag = child.property_u32_opt("numa-node-id")?;
            if let Some(pd) = tag {
                // Reject `u32::MAX`: symmetric with the cpu-side
                // [`DtbNode::decode_cpu_subset`] guard. `Domains` must
                // not carry the cpu-cache sentinel.
                if pd == NUMA_TAG_NONE {
                    return Err(DtbError::ValueOutOfRange {
                        site: Site::Memory,
                        property: "numa-node-id",
                    });
                }
                memory_tagged_count = memory_tagged_count
                    .checked_add(1)
                    .ok_or(DtbError::Internal)?;
                // First-occurrence: `Domains::insert` is a no-op if `pd`
                // was already seen on a cpu or an earlier memory node.
                domains.insert(pd)?;
            }
            for _ in child.reg(Site::Memory)? {
                memory_region_count = memory_region_count
                    .checked_add(1)
                    .ok_or(DtbError::Internal)?;
            }
        }

        let cpu_tagged = cpu_walk.cpu_tagged_count > 0;
        let memory_tagged = memory_tagged_count > 0;

        if !cpu_tagged && !memory_tagged {
            return Ok((false, 0, false));
        }

        if cpu_walk.cpu_untagged_count > 0 {
            return Err(DtbError::PartialNuma {
                reason: NumaIncomplete::CpuUntagged,
            });
        }
        if memory_tagged_count != memory_total_count {
            return Err(DtbError::PartialNuma {
                reason: NumaIncomplete::MemoryUntagged,
            });
        }

        // SLIT presence: only if >1 domain AND /distance-map has a
        // distance-matrix property. Semantic validation (symmetry,
        // value range) happens at slit::emit time.
        let has_distances = if domains.len() > 1 {
            match self.child("distance-map", Site::DistanceMap)? {
                Some(node) => {
                    node.node
                        .property("distance-matrix")
                        .ok_or(DtbError::MissingProperty {
                            site: Site::DistanceMap,
                            property: "distance-matrix",
                        })?;
                    true
                }
                None => false,
            }
        } else {
            false
        };

        Ok((true, memory_region_count, has_distances))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_gpa() {
        let s = Slot {
            offset: 0x100,
            len: 36,
        };
        assert_eq!(s.gpa(0x1000_0000).unwrap(), 0x1000_0100);
    }

    #[test]
    fn slot_gpa_overflow() {
        let s = Slot {
            offset: 0x100,
            len: 36,
        };
        assert!(s.gpa(u64::MAX).is_err());
    }
}
