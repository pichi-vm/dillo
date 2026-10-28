// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Property-based trust-boundary tests.
//!
//! The DTB→ACPI pipeline takes untrusted bytes. These properties
//! assert two invariants:
//!
//! 1. The pipeline never panics — every malformed input surfaces as
//!    `Result::Err`, never an abort, never UB.
//! 2. Every successful populate produces a structurally-valid ACPI
//!    image: all SDT checksums verify, the XSDT lists in-bounds
//!    entries, and the FADT → DSDT pointer chain is intact. A bug
//!    that produced a non-panicking but corrupt image (wrong checksum,
//!    dangling cross-table pointer) would be caught here.
//!
//! Strategies:
//! 1. Arbitrary bytes → `Tree::parse` → (if Ok) `extract::run`
//!    → (if Ok) `emit::write`. Most inputs fail at parse; the
//!    value is in proving that no input reaches a panic.
//! 2. Bit-flip mutations across every shipped fixture, exercising
//!    the deeper extract/emit paths (NUMA, SLIT, multi-IOAPIC,
//!    high APIC IDs, multi-ECAM, oversize topologies) that random
//!    bytes rarely reach.

mod common;

use devtree::Tree;
use dtb2acpi::{AcpiBuffer, OemIdentity};
use proptest::prelude::*;

/// Fixture pool for mutation. Pulling from many shapes exercises
/// distinct extract/emit paths under bit-flip noise. The `too_many_*`
/// fixtures intentionally exceed `FUZZ_BUF`, so the unmutated case
/// returns `BufferTooSmall` — mutations may shrink the topology
/// enough for an `Ok` to arrive, which the structural post-condition
/// will then validate.
const FIXTURES: &[&[u8]] = &[
    include_bytes!("data/basic.dtb"),
    include_bytes!("data/numa.dtb"),
    include_bytes!("data/cpu_high_apic_id.dtb"),
    include_bytes!("data/two_ioapics.dtb"),
    include_bytes!("data/pci_two_ecams.dtb"),
    include_bytes!("data/numa_high_apic_id.dtb"),
    include_bytes!("data/too_many_ecam_regions.dtb"),
    include_bytes!("data/too_many_ioapics.dtb"),
    include_bytes!("data/too_many_memory_regions.dtb"),
    include_bytes!("data/too_many_numa_domains.dtb"),
];

const FUZZ_OEM: OemIdentity = OemIdentity {
    oem_id: *b"FUZZ00",
    oem_table_id: *b"FUZZTBL0",
    oem_revision: 0,
    creator_id: *b"FUZZ",
    creator_revision: 0,
};

/// Reservation big enough to cover any plan produced from a ≤4096-byte
/// fuzz input. The crate has no static capacity caps; oversize layouts
/// surface as `BufferTooSmall` rather than panic, which is exactly
/// what the property tests below check.
const FUZZ_BUF: usize = 65_536;

/// Drive the full pipeline on `bytes`. Any panic fails the property.
/// On `Ok`, the populated prefix must round-trip through the
/// independent verifier — catching non-panicking corruption.
fn drive(bytes: &[u8]) {
    let Ok(tree): Result<Tree<'_>, _> = Tree::parse(bytes) else {
        return;
    };
    let mut buf = Box::new(AcpiBuffer::<FUZZ_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    // BufferTooSmall + Dtb errors are valid Err outcomes (no panic
    // required); on Ok the buffer's `n_bytes` prefix must verify.
    if let Ok(n_bytes) = buf.populate(&tree, &FUZZ_OEM, gpa) {
        let prefix = &AsRef::<[u8]>::as_ref(&*buf)[..n_bytes];
        common::try_decode(prefix).expect("populate ok ⇒ image verifies");
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2048,
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    })]

    /// Arbitrary bytes must never panic the pipeline.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        drive(&bytes);
    }

    /// Mutating bytes of any shipped fixture must never panic.
    /// Exercises extract/emit paths beyond the parser across every
    /// distinct topology the test corpus covers.
    #[test]
    fn mutated_fixtures_never_panic(
        fixture_idx in 0usize..FIXTURES.len(),
        ops in prop::collection::vec(
            (0usize..u16::MAX as usize, any::<u8>()),
            0..32,
        ),
    ) {
        let fixture = FIXTURES[fixture_idx];
        let mut bytes = fixture.to_vec();
        for (idx_seed, val) in ops {
            let idx = idx_seed % bytes.len();
            bytes[idx] = val;
        }
        drive(&bytes);
    }
}
