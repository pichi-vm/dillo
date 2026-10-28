// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Error types for `dtb2acpi`.
//!
//! Two trust boundaries → two error types, both surfaced through
//! [`crate::AcpiBuffer::populate`]:
//!
//! - [`DtbError`] — the DTB itself is wrong, missing, or inconsistent.
//!   Wrapped inside [`EmitError::Dtb`] when returned.
//! - [`EmitError`] — the caller-supplied buffer is too short, or a
//!   per-table emitter's defense-in-depth re-walk of the tree surfaced
//!   a [`DtbError`].
//!
//! `EmitError::Dtb` exists for defense-in-depth: per-table emitters
//! re-walk the borrowed tree, and a tree that [`crate::count::run`]
//! accepted cannot in practice produce a re-walk failure — but the
//! type system can't prove that, so the variant has to exist.
//!
//! The principle that shapes [`DtbError`]: **partial binding = error,
//! absent binding = OK (if optional)**. If a binding's trigger is
//! present in the DTB, every required piece of that binding must
//! validate; missing required pieces surface as a `DtbError`.

use core::fmt;

/// What went wrong on the DTB side.
///
/// Variants carrying [`Site`] identify *where* in the binding the
/// problem occurred, without requiring runtime string allocation
/// (this crate is `no_alloc`).
///
/// Both the enum and every struct-form variant are `#[non_exhaustive]`.
/// The enum-level attribute reserves the right to add new variants;
/// the variant-level attributes reserve the right to add new diagnostic
/// fields (e.g. node path, expected vs found) without a major bump.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtbError {
    /// A required node is absent.
    #[non_exhaustive]
    MissingNode {
        /// What was being looked for.
        site: Site,
    },
    /// A required property is absent.
    #[non_exhaustive]
    MissingProperty {
        /// Where the missing property was expected.
        site: Site,
        /// Property name.
        property: &'static str,
    },
    /// A property exists but its value is malformed for its binding
    /// (e.g. `reg` shorter than `addr_cells + size_cells`).
    #[non_exhaustive]
    MalformedProperty {
        /// Where the malformed property was found.
        site: Site,
        /// Property name.
        property: &'static str,
    },
    /// `#address-cells` outside the range supported on x86_64 (1 or 2).
    /// Values > 2 cannot fit in a u64 physical address.
    #[non_exhaustive]
    UnsupportedAddressCells {
        /// Where the unsupported value was declared.
        site: Site,
        /// The value found.
        found: u32,
    },
    /// `#size-cells` outside the range supported on x86_64 (0, 1, or 2).
    #[non_exhaustive]
    UnsupportedSizeCells {
        /// Where the unsupported value was declared.
        site: Site,
        /// The value found.
        found: u32,
    },
    /// A DTB-supplied value exceeds the range its ACPI counterpart
    /// can represent (e.g. APIC ID > 255, LAPIC/IOAPIC base > 4 GiB,
    /// PCI bus number > 255, SLIT distance > 255).
    ///
    /// Surfaces *at count time* — silent truncation to the
    /// representable subset would produce wrong-but-syntactically-valid
    /// ACPI output that the OS cannot detect.
    #[non_exhaustive]
    ValueOutOfRange {
        /// Where the out-of-range value was declared.
        site: Site,
        /// Property whose value is out of range.
        property: &'static str,
    },
    /// NUMA topology is partially expressed — at least one
    /// `numa-node-id` exists, but coverage is incomplete (e.g.,
    /// some CPUs tagged, others not).
    #[non_exhaustive]
    PartialNuma {
        /// What kind of partiality was detected.
        reason: NumaIncomplete,
    },
    /// The first cpu in `/cpus` walk order — `cpu@0`, processor UID
    /// 0, the conventional bootstrap processor in every VMM —
    /// has a non-`"okay"` `status` (DT spec §2.3.4). The hypervisor
    /// designates a vCPU as the BSP at VM creation and sets its
    /// `IA32_APIC_BASE_MSR.BSP` bit; if MADT marks that cpu
    /// `Enabled=0` the BSP-as-itself reads a self-contradictory
    /// entry at boot. Other cpus may be `disabled` (hot-onlineable
    /// APs) or `fail` (defective) freely.
    BootCpuNotEnabled,
    /// More cpus than this crate supports. The hard cap is the size
    /// of MADT's u8 `processor_id` field (Type 0 §5.2.12.2, Type 4
    /// §5.2.12.7): processor UIDs above 255 cannot be encoded, and
    /// `cpu@N` walk order produces sequential UIDs.
    #[non_exhaustive]
    TooManyCpus {
        /// The hard cap on supported cpu count.
        limit: usize,
    },
    /// The DTB declares a property the binding consumer doesn't know
    /// how to translate. Strict-reject — silently dropping would couple
    /// dtb2acpi to OS-runtime defaults, and `#12` forbids both silent
    /// drops and "value matches default → ignore" heuristics. The
    /// per-site Display lists what *is* allowed at that site.
    #[non_exhaustive]
    UnsupportedProperty {
        /// Where the unknown property was found.
        site: Site,
    },
    /// The DTB declares a node the consumer doesn't know how to handle
    /// — e.g. a child of `isa@*` whose `compatible` isn't `ns16550a`.
    /// Strict-reject for the same reason as [`Self::UnsupportedProperty`].
    #[non_exhaustive]
    UnsupportedNode {
        /// Where the unknown node was found.
        site: Site,
    },
    /// Defensive: an internal size accounting or byte/word narrowing
    /// could not be represented. Reachable only via `Slot::gpa`
    /// overflow (which requires a `base_gpa` near `u64::MAX`) or via
    /// `usize`/u8 narrowing on a value that earlier count-side
    /// validation already constrained — i.e. unreachable on every
    /// realistic input. Surfacing this means a layout-accounting bug.
    Internal,
}

impl fmt::Display for DtbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingNode { site } => write!(f, "missing required node at {site}"),
            Self::MissingProperty { site, property } => {
                write!(f, "missing required property `{property}` at {site}")
            }
            Self::MalformedProperty { site, property } => {
                write!(f, "malformed property `{property}` at {site}")
            }
            Self::UnsupportedAddressCells { site, found } => write!(
                f,
                "#address-cells = {found} at {site} is not supported (expected 1 or 2)"
            ),
            Self::UnsupportedSizeCells { site, found } => write!(
                f,
                "#size-cells = {found} at {site} is not supported (expected 0, 1, or 2)"
            ),
            Self::ValueOutOfRange { site, property } => write!(
                f,
                "value of property `{property}` at {site} exceeds the range its ACPI counterpart can represent"
            ),
            Self::PartialNuma { reason } => write!(f, "partial NUMA topology: {reason}"),
            Self::BootCpuNotEnabled => f.write_str(
                "first cpu (UID 0, the conventional BSP) has non-`okay` `status` — \
                 hypervisor's BSP designation would conflict with MADT",
            ),
            Self::TooManyCpus { limit } => {
                write!(
                    f,
                    "more than {limit} cpus in /cpus — exceeds MADT processor_id u8"
                )
            }
            Self::UnsupportedProperty { site } => write!(
                f,
                "unsupported property at {site}; dtb2acpi cannot translate it to ACPI \
                 (allowed: {})",
                site.allowed_properties()
            ),
            Self::UnsupportedNode { site } => write!(
                f,
                "unsupported node at {site}; dtb2acpi cannot translate it to ACPI"
            ),
            Self::Internal => f.write_str("internal size accounting overflowed"),
        }
    }
}

impl core::error::Error for DtbError {}

/// What went wrong during [`crate::AcpiBuffer::populate`].
///
/// Two sources: the caller-supplied buffer is too small
/// ([`Self::BufferTooSmall`]); or any DTB-side fault, whether caught
/// during the count phase or during a per-table emitter's
/// defense-in-depth re-walk of the tree, wrapped as [`Self::Dtb`].
///
/// [`crate::AcpiBuffer`] alignment is enforced at compile time by
/// `#[repr(align(16))]`, so there is no runtime alignment failure mode.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    /// Caller-supplied buffer is shorter than the bytes required by
    /// the validated DTB layout.
    ///
    // The enum's `#[non_exhaustive]` covers adding new variants; this
    // variant-level `#[non_exhaustive]` covers adding new fields here
    // (e.g. the layout breakdown that produced `needed`) without a
    // major bump.
    #[non_exhaustive]
    BufferTooSmall {
        /// Bytes required to hold the full layout.
        needed: usize,
        /// Bytes the caller actually supplied.
        got: usize,
    },
    /// A DTB-side fault. Surfaced from the count phase, or from a
    /// per-table emitter's defense-in-depth re-walk of the borrowed
    /// tree (the latter is unreachable in practice). Internal
    /// layout-accounting bugs (e.g. a `Slot::carve_in` overshoot)
    /// surface here too, as [`Self::Dtb`] wrapping [`DtbError::Internal`].
    #[non_exhaustive]
    Dtb {
        /// The underlying DTB-side error.
        source: DtbError,
    },
}

impl From<DtbError> for EmitError {
    fn from(e: DtbError) -> Self {
        Self::Dtb { source: e }
    }
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, got } => {
                write!(f, "output buffer too small: need {needed} bytes, got {got}")
            }
            Self::Dtb { source } => write!(f, "DTB error during populate: {source}"),
        }
    }
}

impl core::error::Error for EmitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Dtb { source } => Some(source),
            _ => None,
        }
    }
}

/// Categorical locations where a DTB-side error can occur. Finite
/// and allocation-free; route on error site by matching with a `_`
/// fallback arm (the enum is `#[non_exhaustive]` so additional sites
/// can be added in future versions without a breaking change).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// The root node of the DTB.
    Root,
    /// The `/cpus` node.
    Cpus,
    /// A `/cpus/cpu@N` node.
    Cpu,
    /// A top-level `intc*` interrupt controller node.
    Intc,
    /// A child of root with `compatible = "pci-host-ecam-generic"`.
    PciHost,
    /// A `/memory@…` node.
    Memory,
    /// A standalone `syscon-poweroff` node (carrying its own `reg`).
    SysconPoweroff,
    /// A standalone `syscon-reboot` node (carrying its own `reg`).
    SysconReboot,
    /// The `/distance-map` node.
    DistanceMap,
    /// A top-level `serial@*` node with `compatible = "ns16550a"`.
    Serial,
    /// A child of root with `compatible = "virtio,mmio"`.
    VirtioMmio,
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Root => "/",
            Self::Cpus => "/cpus",
            Self::Cpu => "/cpus/cpu@*",
            Self::Intc => "/intc*",
            Self::PciHost => "compatible=\"pci-host-ecam-generic\"",
            Self::Memory => "/memory@*",
            Self::SysconPoweroff => "compatible=\"syscon-poweroff\"",
            Self::SysconReboot => "compatible=\"syscon-reboot\"",
            Self::DistanceMap => "/distance-map",
            Self::Serial => "compatible=\"ns16550a\"",
            Self::VirtioMmio => "compatible=\"virtio,mmio\"",
        })
    }
}

impl Site {
    /// The set of DTB properties this consumer recognizes at the site.
    /// Embedded in `UnsupportedProperty`'s error message so operators
    /// know what to remove from their DTB (or what dtb2acpi needs to
    /// learn). Empty string for sites where the coverage rule isn't
    /// enforced yet (`#12` will broaden this).
    pub(crate) fn allowed_properties(&self) -> &'static str {
        match self {
            Self::Serial => {
                "compatible, reg, interrupts, interrupt-parent, reg-shift, \
                 reg-io-width, clock-frequency, current-speed"
            }
            _ => "(coverage rule not yet enforced at this site — see issue #12)",
        }
    }
}

/// Sub-reasons for [`DtbError::PartialNuma`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaIncomplete {
    /// One or more CPUs lack `numa-node-id`.
    CpuUntagged,
    /// One or more `/memory@…` nodes lack `numa-node-id`.
    MemoryUntagged,
}

impl fmt::Display for NumaIncomplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CpuUntagged => "at least one cpu lacks `numa-node-id`",
            Self::MemoryUntagged => "at least one /memory@… node lacks `numa-node-id`",
        })
    }
}

#[cfg(test)]
mod tests {
    // In-crate display coverage: every `DtbError` struct-form variant
    // is `#[non_exhaustive]`, which blocks struct-literal construction
    // from integration tests. Exercising Display here keeps the
    // round-trip pinned without forcing every variant to round through
    // a synthetic fixture DTB.
    extern crate alloc;
    use alloc::format;

    use super::*;

    #[test]
    fn display_renders_every_dtb_error_variant() {
        let variants: &[DtbError] = &[
            DtbError::MissingNode { site: Site::Cpu },
            DtbError::MissingProperty {
                site: Site::PciHost,
                property: "reg",
            },
            DtbError::MalformedProperty {
                site: Site::DistanceMap,
                property: "distance-matrix",
            },
            DtbError::UnsupportedAddressCells {
                site: Site::Cpus,
                found: 3,
            },
            DtbError::UnsupportedSizeCells {
                site: Site::Cpus,
                found: 3,
            },
            DtbError::ValueOutOfRange {
                site: Site::Intc,
                property: "reg",
            },
            DtbError::PartialNuma {
                reason: NumaIncomplete::CpuUntagged,
            },
            DtbError::PartialNuma {
                reason: NumaIncomplete::MemoryUntagged,
            },
            DtbError::BootCpuNotEnabled,
            DtbError::Internal,
        ];
        for v in variants {
            let rendered = format!("{v}");
            assert!(!rendered.is_empty(), "Display for {v:?} is empty");
        }
    }

    #[test]
    fn display_renders_every_site() {
        for s in [
            Site::Root,
            Site::Cpus,
            Site::Cpu,
            Site::Intc,
            Site::PciHost,
            Site::Memory,
            Site::SysconPoweroff,
            Site::SysconReboot,
            Site::DistanceMap,
        ] {
            assert!(!format!("{s}").is_empty());
        }
    }

    #[test]
    fn display_renders_emit_error_dtb_wrapper() {
        // BufferTooSmall is exercised via the public API (see
        // tests/errors.rs); the Dtb-wrapping arm is pure formatter
        // coverage (it also carries internal layout-accounting bugs
        // as `EmitError::Dtb { source: DtbError::Internal }`).
        let wrapped = EmitError::Dtb {
            source: DtbError::Internal,
        };
        assert!(!format!("{wrapped}").is_empty());
    }
}
