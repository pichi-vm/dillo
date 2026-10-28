// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `dtb2acpi` — convert a flattened devicetree into an x86_64
//! HW-Reduced ACPI table layout.
//!
//! `no_std`, `no_alloc`, `forbid(unsafe_code)`. The crate's job is
//! purely DT→ACPI translation: it does not parse DTBs (that's
//! [`devtree`]) and does not interact with hardware (it produces
//! bytes).
//!
//! # Execution context
//!
//! `dtb2acpi` is designed to run inside the guest (firmware or
//! early boot), where the output buffer's first byte sits at the
//! guest physical address the OS will eventually use to find the
//! RSDP. Cross-table pointers baked into the emitted tables are
//! `base_gpa + offset`, where `base_gpa` is passed by the caller
//! to [`AcpiBuffer::populate`]. Under identity-mapped paging the
//! buffer's own host address is its GPA; external callers (e.g. a
//! VMM building tables for a guest at a GPA chosen independently
//! of host addressing) pass that GPA directly.
//!
//! # Architecture
//!
//! [`AcpiBuffer::populate`] orchestrates a single-pass pipeline:
//!
//! ```text
//! DTB ──count──▶ sizes + offsets ──emit──▶ bytes
//!         ^                            ^
//!  DtbError surfaces here:      EmitError surfaces here:
//!  one tree walk validates      BufferTooSmall (buffer < offsets.total)
//!  bindings, counts entries,    and Dtb(_) for the per-table emitters'
//!  computes byte totals.        defense-in-depth re-walks (unreachable
//!                               in practice on a count-validated tree).
//! ```
//!
//! Two trust boundaries → two error types. [`DtbError`] is "the DTB
//! is wrong" — every fault attributable to the source tree. [`EmitError`]
//! adds the caller-side failure mode ("the buffer is too short") and
//! wraps `DtbError` for the unreachable-in-practice re-walk surface.
//! [`AcpiBuffer`] is a transparent `[u8; N]`; the RSDP's 16-byte
//! alignment (ACPI 6.5 §5.2.5.1) is the caller's placement
//! responsibility — PMI consumers get it from page-aligned sections.
//!
//! Per-vCPU `(apic_id, numa_tag, status)` triples are captured during
//! count's `/cpus` walk into a stack-resident `CpuCache` (~2.3 KB at
//! 256 cpus) so MADT/SRAT emit can iterate without re-walking. The
//! cap is `CPU_CACHE_CAP = 256`, matching MADT's u8 `processor_id`
//! field; oversize trees surface as [`DtbError::TooManyCpus`].
//!
//! # Public surface
//!
//! ```
//! use devtree::Tree;
//! use dtb2acpi::{AcpiBuffer, EmitError, OemIdentity};
//!
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! /// Reserved size of the guest's ACPI region.
//! const ACPI_BYTES: usize = 8192;
//!
//! // Real DTB pulled from the test corpus so the example actually
//! // runs as a doctest rather than just type-checking.
//! let dtb_bytes: &[u8] = include_bytes!("../tests/data/basic.dtb");
//!
//! let tree: Tree<'_> = Tree::parse(dtb_bytes)?;
//! let oem = OemIdentity {
//!     oem_id:           *b"MYCORP",
//!     oem_table_id:     *b"MY_TABLE",
//!     oem_revision:     1,
//!     creator_id:       *b"MINE",
//!     creator_revision: 1,
//! };
//!
//! let mut buf = Box::new(AcpiBuffer::<ACPI_BYTES>::default());
//! // Guest-side, identity-mapped: the buffer's own address is the GPA.
//! let base_gpa = AsRef::<[u8]>::as_ref(&*buf).as_ptr() as u64;
//! // populate returns the live image length; `base_gpa` is the RSDP's
//! // location — publish it to the OS and hand off the prefix [..n].
//! let n = buf.populate(&tree, &oem, base_gpa)?;
//! let live: &[u8] = &AsRef::<[u8]>::as_ref(&*buf)[..n];
//! assert_eq!(&live[..8], b"RSD PTR ");
//! assert!(live.len() <= ACPI_BYTES);
//! # let _: Option<EmitError> = None;
//! # Ok(())
//! # }
//! ```
//!
//! # Out of scope (v1)
//!
//! The following ACPI tables and DT bindings are deliberately not
//! handled. Each is a candidate for a future task as concrete consumers
//! emerge.
//!
//! | Table / binding                          | Why deferred                                                                  |
//! | ---------------------------------------- | ----------------------------------------------------------------------------- |
//! | MADT Interrupt Source Override (type 2)  | No legacy 8259 PIC under HW-Reduced ACPI; identity GSI routing applies        |
//! | HPET                                     | TSC and LAPIC timer cover most needs                                          |
//! | `/reserved-memory`                       | e820 handles reserved regions for x86 boot                                    |
//! | Memory map → e820                        | Separate concern (boot setup, not `dtb2acpi`)                                 |
//! | IORT, GTDT                               | Not x86-relevant                                                              |
//! | NFIT                                     | No NVDIMM support in v1                                                       |
//! | DSDT AML beyond power / PCI / serial     | Only the platform devices Linux needs to boot are emitted; richer device AML is deferred |
//!
//! # DT binding scope
//!
//! This crate consumes DT properties that describe **hardware facts**
//! and deliberately rejects properties that encode **OS conventions**.
//! ACPI is OS-independent; if the DT inputs we consume drift into
//! OS-specific territory, the ACPI we emit would too.
//!
//! Bindings are tiered:
//!
//! 1. **DT spec proper** ([devicetree.org](https://www.devicetree.org/specifications/))
//!    — node shape, `reg`, `compatible`, `status`, `device_type`,
//!    `#address-cells`/`#size-cells`, the generic interrupt model.
//!    OS-agnostic by construction. **In scope.**
//!
//! 2. **Unprefixed cross-OS bindings** ([Linux kernel
//!    Documentation/devicetree/bindings/](https://www.kernel.org/doc/Documentation/devicetree/bindings/))
//!    — properties without a vendor/OS prefix, originated in the
//!    Linux bindings tree but adopted as the de facto DT vocabulary
//!    across consumers (U-Boot, BSD DT consumers, etc.). They describe
//!    hardware facts: register addresses, NUMA domains, bus topology.
//!    Examples this crate reads: `syscon-poweroff`, `syscon-reboot`
//!    (each with its own `reg`/`value`), `numa-node-id`,
//!    `distance-map`, `pci-host-ecam-generic`, `bus-range`, `ns16550a`
//!    (with `reg-shift`/`reg-io-width`). **In scope.**
//!
//! 3. **OS-prefixed properties** (`linux,*`, `freebsd,*`, etc.) —
//!    the vendor prefix is the spec's way of saying "this is that
//!    OS's convention, not a hardware fact." `linux,pci-domain` is a
//!    notable example: MCFG segment numbering is a Linux choice, not
//!    a DT-spec construct. This crate hardcodes single-segment output
//!    rather than read it. **Out of scope.**
//!
//! When a caller's need can only be expressed in tier-3 territory,
//! the right fix is to standardize an OS-agnostic alternative (in DT
//! spec or in the unprefixed bindings tree) — not to take the
//! prefixed property.
//!
//! # Strictness rule
//!
//! Three categories, three behaviors:
//!
//! 1. **Inputs that affect functionality MUST be strict.** Any DT
//!    property whose value changes the ACPI output (a `reg` cell, an
//!    `interrupts` cell, a `bus-range` endpoint, a `compatible` string
//!    that selects translation) is validated end-to-end: shape, type,
//!    range, and semantics. Wrong values surface as a specific
//!    [`DtbError`] variant tagged with the [`Site`] the value came
//!    from — never silently coerced to a guess.
//!
//! 2. **Inputs that don't affect functionality MAY be ignored.** If
//!    `dtb2acpi` reads a property only for completeness (e.g. an
//!    `interrupt-parent` phandle when ACPI has a single GSI space and
//!    the parent identity makes no difference to emit) the value is
//!    accepted as long as its shape parses. Resolving and validating
//!    something the emit path doesn't consume would be ceremony with
//!    no behavioral payoff.
//!
//! 3. **Unknown properties MUST be rejected.** Silently dropping an
//!    unrecognized property would couple `dtb2acpi`'s behavior to
//!    whether some OS driver's default happens to match the dropped
//!    value — an action-at-a-distance failure mode. Per-binding emit
//!    modules carry an explicit "allowed properties" set and surface
//!    [`DtbError::UnsupportedProperty`] (with the [`Site`]'s allowed
//!    list in the message) when the DT has anything outside it. The
//!    same rule applies to unknown child nodes under a binding's own
//!    namespace ([`DtbError::UnsupportedNode`]).
//!
//! The third clause is the load-bearing one for forward compatibility:
//! when arma starts emitting a property `dtb2acpi` doesn't yet handle,
//! the failure is loud and pointed at the missing translation rather
//! than silent and pointed at a confused guest kernel.
//!
//! As of today the strictness rule is enforced fully on the `serial@*`
//! (`ns16550a`) node. Other bindings (intc, PCI host bridge, syscon,
//! cpu, memory) are still permissive on unknown properties — see `#12`
//! for the broader audit that brings them up to the same standard.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division,
    clippy::modulo_arithmetic,
    clippy::dbg_macro
)]
// Test code is permitted to use `unwrap`, `expect`, indexing, etc. —
// the strict lints are about library-side correctness, not test
// readability.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation
    )
)]

mod acpi_buffer;
mod count;
mod dtb;
mod emit;
mod error;
mod oem;

pub use acpi_buffer::AcpiBuffer;
pub use error::{DtbError, EmitError, NumaIncomplete, Site};
pub use oem::OemIdentity;
