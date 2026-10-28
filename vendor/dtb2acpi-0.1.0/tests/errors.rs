// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Negative tests: every DtbError variant the v1 surface can produce
//! is exercised by a synthetic fixture DTB.

use core::error::Error as _;

use devtree::Tree;
use dtb2acpi::{AcpiBuffer, DtbError, EmitError, NumaIncomplete, OemIdentity, Site};

mod common;

const TEST_BUF: usize = 8192;

/// Parse `dtb`, run `populate`, and return the DTB-side error.
/// `populate` fails fast on DTB issues before any write happens.
fn extract_err(dtb: &[u8]) -> DtbError {
    let tree: Tree<'_> = Tree::parse(dtb).expect("DTB parses");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    match buf
        .populate(&tree, &common::TEST_OEM, gpa)
        .expect_err("expected error")
    {
        EmitError::Dtb { source, .. } => source,
        other => panic!("expected Dtb error, got {other:?}"),
    }
}

#[test]
fn real_world_falconfalls_rejected_cleanly() {
    // `falconfalls.dts` is the only mainline x86 DTS (Linux
    // arch/x86/platform/ce4100/). It uses the `intel,ce4100-lapic` /
    // `intel,ce4100-ioapic` bindings this crate now consumes, but nests
    // them under `/soc@0/` rather than at the root where `find_lapic`
    // looks — so the LAPIC isn't found. This test pins the rejection
    // behavior: no panic, structured Err, identifies the binding gap.
    let err = extract_err(include_bytes!("data/falconfalls.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingNode {
            site: Site::Intc,
            ..
        }
    ));
}

#[test]
fn no_cpus_node_errors() {
    let err = extract_err(include_bytes!("data/no_cpus.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingNode {
            site: Site::Cpus,
            ..
        }
    ));
}

#[test]
fn empty_cpus_node_errors() {
    // /cpus exists but has no cpu@N children — hits the post-loop
    // `n_vcpus == 0` check inside `walk_cpus`, firing
    // `MissingNode { site: Cpu }`. Distinct from `no_cpus.dtb`,
    // which omits /cpus entirely (Site::Cpus).
    let err = extract_err(include_bytes!("data/cpus_empty.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingNode {
            site: Site::Cpu,
            ..
        }
    ));
}

#[test]
fn no_intc_errors() {
    let err = extract_err(include_bytes!("data/no_intc.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingNode {
            site: Site::Intc,
            ..
        }
    ));
}

#[test]
fn no_poweroff_errors() {
    let err = extract_err(include_bytes!("data/no_poweroff.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingNode {
            site: Site::SysconPoweroff,
            ..
        }
    ));
}

#[test]
fn cpu_missing_reg_errors() {
    let err = extract_err(include_bytes!("data/cpu_no_reg.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingProperty {
            site: Site::Cpu,
            property: "reg",
            ..
        }
    ));
}

#[test]
fn partial_numa_errors() {
    let err = extract_err(include_bytes!("data/partial_numa.dtb"));
    assert!(matches!(
        err,
        DtbError::PartialNuma {
            reason: NumaIncomplete::CpuUntagged,
            ..
        }
    ));
}

#[test]
fn pci_missing_bus_range_errors() {
    let err = extract_err(include_bytes!("data/pci_no_bus_range.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingProperty {
            site: Site::PciHost,
            property: "bus-range",
            ..
        }
    ));
}

#[test]
fn numa_memory_untagged_errors() {
    let err = extract_err(include_bytes!("data/numa_memory_untagged.dtb"));
    assert!(matches!(
        err,
        DtbError::PartialNuma {
            reason: NumaIncomplete::MemoryUntagged,
            ..
        }
    ));
}

#[test]
fn numa_distance_map_missing_matrix_errors() {
    let err = extract_err(include_bytes!("data/numa_distance_map_no_matrix.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingProperty {
            site: Site::DistanceMap,
            property: "distance-matrix",
            ..
        }
    ));
}

#[test]
fn lapic_base_above_4gib_errors() {
    let err = extract_err(include_bytes!("data/lapic_too_high.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::Intc,
            property: "reg",
            ..
        }
    ));
}

#[test]
fn bus_range_above_255_errors() {
    let err = extract_err(include_bytes!("data/bus_range_too_big.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::PciHost,
            property: "bus-range",
            ..
        }
    ));
}

#[test]
fn bus_range_start_above_255_errors() {
    // `bus-range = <0x1ff 0x200>;` — start > 255. The existing
    // bus_range_too_big fixture exercises the `end` narrowing arm
    // (start is in range); this one exercises the parallel `start`
    // arm, which is the structurally-identical but distinct check.
    let err = extract_err(include_bytes!("data/bus_range_start_too_big.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::PciHost,
            property: "bus-range",
            ..
        }
    ));
}

#[test]
fn buffer_too_small_errors() {
    let dtb: &[u8] = include_bytes!("data/basic.dtb");
    let tree: Tree<'_> = Tree::parse(dtb).unwrap();
    // AcpiBuffer<128> is provably smaller than any realistic plan.
    let mut tiny = Box::new(AcpiBuffer::<128>::default());
    let gpa = common::buf_gpa(&tiny);
    let err = tiny.populate(&tree, &common::TEST_OEM, gpa).unwrap_err();
    match err {
        EmitError::BufferTooSmall { needed, got, .. } => {
            assert!(needed > 128, "needed > buffer size");
            assert_eq!(got, 128, "got must report buffer's N");
        }
        _ => panic!("expected BufferTooSmall, got {err:?}"),
    }
}

#[test]
fn intc_empty_reg_is_malformed() {
    // intc.reg = <>; — RegIter yields no pairs, surfaces as
    // MalformedProperty { site: Intc, property: "reg" }.
    let err = extract_err(include_bytes!("data/intc_no_reg.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::Intc,
            property: "reg",
            ..
        }
    ));
}

#[test]
fn bus_range_one_cell_is_malformed() {
    let err = extract_err(include_bytes!("data/bus_range_one_cell.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::PciHost,
            property: "bus-range",
            ..
        }
    ));
}

#[test]
fn unsupported_address_cells_errors() {
    let err = extract_err(include_bytes!("data/unsupported_address_cells.dtb"));
    match err {
        DtbError::UnsupportedAddressCells { found, site, .. } => {
            assert_eq!(found, 3);
            // Fixture puts #address-cells=3 on root; the first reg
            // decode under root is intc.reg, which surfaces the cap.
            assert_eq!(site, Site::Intc);
        }
        other => panic!("expected UnsupportedAddressCells, got {other:?}"),
    }
}

#[test]
fn unsupported_size_cells_errors() {
    let err = extract_err(include_bytes!("data/unsupported_size_cells.dtb"));
    match err {
        DtbError::UnsupportedSizeCells { found, site, .. } => {
            assert_eq!(found, 3);
            assert_eq!(site, Site::Intc);
        }
        other => panic!("expected UnsupportedSizeCells, got {other:?}"),
    }
}

#[test]
fn syscon_reboot_value_overflow_errors() {
    let err = extract_err(include_bytes!("data/syscon_reboot_value_overflow.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::SysconReboot,
            property: "value",
            ..
        }
    ));
}

#[test]
fn memory_no_reg_errors() {
    // /memory has numa-node-id but no reg; extract_numa walks memory
    // to size SRAT entries, which calls reg(Site::Memory).
    let err = extract_err(include_bytes!("data/memory_no_reg.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingProperty {
            site: Site::Memory,
            property: "reg",
            ..
        }
    ));
}

// ─── Malformed-property cases (DtbNode::own_cells, property_u32,
//     property_u32_opt — the `as_u32` arms that previously had no
//     direct fixture coverage) ─────────────────────────────────────────

#[test]
fn malformed_address_cells_errors() {
    // `#address-cells = <1 2>;` — 8 bytes instead of the required
    // single u32 cell. Fires from `DtbNode::own_cells` the first
    // time a child's reg has to be decoded; root's first reg-bearing
    // child here is intc.
    let err = extract_err(include_bytes!("data/cells_malformed.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::Root,
            property: "#address-cells",
            ..
        }
    ));
}

#[test]
fn malformed_syscon_value_errors() {
    // `value = "x";` — 2-byte string property where a u32 cell is
    // expected. Fires from `resolve_syscon` reading the poweroff
    // node's own `value` (the deprecated `regmap` phandle path is gone;
    // see device-model §4).
    let err = extract_err(include_bytes!("data/syscon_value_malformed.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::SysconPoweroff,
            property: "value",
            ..
        }
    ));
}

#[test]
fn boot_cpu_disabled_errors() {
    // cpu@0 (the conventional BSP) is `status = "disabled"`; cpu@1 is
    // healthy. The hypervisor still designates cpu@0 as BSP, so MADT
    // marking it Enabled=0 is self-contradictory. count must reject.
    let err = extract_err(include_bytes!("data/cpu_status_bsp_disabled.dtb"));
    assert!(matches!(err, DtbError::BootCpuNotEnabled));
}

#[test]
fn all_cpus_disabled_also_errors_via_bsp_check() {
    // Every cpu has non-`okay` status. cpu@0 in particular is
    // "disabled", so the BootCpuNotEnabled check fires first
    // (a stricter superset of the "all disabled" condition).
    let err = extract_err(include_bytes!("data/cpu_status_all_disabled.dtb"));
    assert!(matches!(err, DtbError::BootCpuNotEnabled));
}

#[test]
fn malformed_cpu_status_errors() {
    // `status = "bogus"` — not one of the spec-defined values.
    let err = extract_err(include_bytes!("data/cpu_status_malformed.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::Cpu,
            property: "status",
            ..
        }
    ));
}

#[test]
fn malformed_memory_status_errors() {
    // Memory-side mirror of `malformed_cpu_status_errors`. Same
    // decode path (decode_status), different Site for attribution.
    let err = extract_err(include_bytes!("data/memory_status_malformed.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::Memory,
            property: "status",
            ..
        }
    ));
}

#[test]
fn malformed_optional_u32_errors() {
    // `numa-node-id = <0 0>;` — 8 bytes where a single u32 cell is
    // expected. Fires from `DtbNode::property_u32_opt` inside
    // `walk_cpus`. Site is `Cpus` (the children-iter's parent site).
    let err = extract_err(include_bytes!("data/numa_node_id_malformed.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::Cpus,
            property: "numa-node-id",
            ..
        }
    ));
}

#[test]
fn cpu_numa_node_id_u32_max_errors() {
    // `numa-node-id = <0xFFFFFFFF>` collides with `NUMA_TAG_NONE`, the
    // CpuCache sentinel for "property absent". Rejected at count time
    // so the count/emit invariant holds.
    let err = extract_err(include_bytes!("data/cpu_numa_node_id_u32_max.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::Cpus,
            property: "numa-node-id",
            ..
        }
    ));
}

#[test]
fn memory_numa_node_id_u32_max_errors() {
    // Symmetric memory-side guard against the `NUMA_TAG_NONE` sentinel.
    let err = extract_err(include_bytes!("data/memory_numa_node_id_u32_max.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::Memory,
            property: "numa-node-id",
            ..
        }
    ));
}

#[test]
fn too_many_cpus_errors() {
    // 257 vCPUs — one past CPU_CACHE_CAP and one past MADT's u8
    // processor_id limit. Surfaces as TooManyCpus from CpuCache::push.
    let err = extract_err(include_bytes!("data/too_many_cpus.dtb"));
    assert!(matches!(err, DtbError::TooManyCpus { limit: 256, .. }));
}

// ─── SLIT (distance-map) negative cases ────────────────────────────────

#[test]
fn slit_distance_below_10_errors() {
    // Off-diagonal value of 5 is below the ACPI minimum of 10
    // (0..9 reserved; 0 also collides with the "unwritten" sentinel).
    // Hits the `val_u8 < 10 → malformed` arm — distinct from the
    // diagonal `!= 10` rejection and the > 255 narrowing failure
    // already covered.
    let err = extract_err(include_bytes!("data/numa_slit_distance_too_small.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::DistanceMap,
            property: "distance-matrix",
            ..
        }
    ));
}

#[test]
fn slit_distance_above_255_errors() {
    let err = extract_err(include_bytes!("data/numa_slit_distance_too_big.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::DistanceMap,
            property: "distance-matrix",
            ..
        }
    ));
}

#[test]
fn slit_non_10_diagonal_is_malformed() {
    let err = extract_err(include_bytes!("data/numa_slit_bad_diagonal.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::DistanceMap,
            property: "distance-matrix",
            ..
        }
    ));
}

#[test]
fn slit_partial_triple_is_malformed() {
    let err = extract_err(include_bytes!("data/numa_slit_partial_triple.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::DistanceMap,
            property: "distance-matrix",
            ..
        }
    ));
}

#[test]
fn slit_unknown_domain_is_malformed() {
    let err = extract_err(include_bytes!("data/numa_slit_unknown_domain.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::DistanceMap,
            property: "distance-matrix",
            ..
        }
    ));
}

#[test]
fn slit_asymmetric_conflict_is_malformed() {
    let err = extract_err(include_bytes!("data/numa_slit_asymmetric_conflict.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::DistanceMap,
            property: "distance-matrix",
            ..
        }
    ));
}

// Static capacity caps were removed in favor of the dynamic-capacity
// model: oversize counts surface as `EmitError::BufferTooSmall` (see
// the boundary test below). The former `too_many_*` fixtures remain
// in tests/data/ as oversize topologies the fuzzer exercises.

// ─── MCFG branches ─────────────────────────────────────────────────────

#[test]
fn pci_inverted_bus_range_is_malformed() {
    let err = extract_err(include_bytes!("data/pci_inverted_bus_range.dtb"));
    assert!(matches!(
        err,
        DtbError::MalformedProperty {
            site: Site::PciHost,
            property: "bus-range",
            ..
        }
    ));
}

#[test]
fn pci_missing_reg_errors() {
    let err = extract_err(include_bytes!("data/pci_no_reg.dtb"));
    assert!(matches!(
        err,
        DtbError::MissingProperty {
            site: Site::PciHost,
            property: "reg",
            ..
        }
    ));
}

#[test]
fn cpu_reg_above_u32_errors() {
    let err = extract_err(include_bytes!("data/cpu_reg_too_big.dtb"));
    assert!(matches!(
        err,
        DtbError::ValueOutOfRange {
            site: Site::Cpu,
            property: "reg",
            ..
        }
    ));
}

// ─── Display / core::error::Error contract ─────────────────────────────

#[test]
fn write_error_display_renders_dtb_chain() {
    // Wrap a DtbError in EmitError::Dtb to exercise the Display path.
    let err: EmitError = extract_err(include_bytes!("data/no_cpus.dtb")).into();
    let rendered = format!("{err}");
    assert!(rendered.starts_with("DTB error"), "got {rendered:?}");
    assert!(rendered.contains("missing"), "got {rendered:?}");
    assert!(rendered.contains("/cpus"), "got {rendered:?}");
}

#[test]
fn write_error_display_renders_buffer_too_small() {
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut tiny = Box::new(AcpiBuffer::<128>::default());
    let gpa = common::buf_gpa(&tiny);
    let err = tiny.populate(&tree, &common::TEST_OEM, gpa).unwrap_err();
    let rendered = format!("{err}");
    assert!(rendered.contains("too small"), "got {rendered:?}");
    assert!(rendered.contains("128"), "got {rendered:?}");
}

#[test]
fn write_error_source_is_none_for_non_dtb_variants() {
    // Dtb-wrapping is covered below; this verifies the `_ => None`
    // arm in `EmitError::source` for the variants whose error has
    // no inner source.
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut tiny = Box::new(AcpiBuffer::<1>::default());
    let gpa = common::buf_gpa(&tiny);
    let buffer_too_small = tiny.populate(&tree, &common::TEST_OEM, gpa).unwrap_err();
    assert!(
        buffer_too_small.source().is_none(),
        "BufferTooSmall has no source"
    );
}

#[test]
fn write_error_source_chains_to_dtb_error() {
    let err: EmitError = extract_err(include_bytes!("data/no_cpus.dtb")).into();
    let src = err
        .source()
        .expect("EmitError::Dtb exposes its DtbError as source");
    let inner = src.downcast_ref::<DtbError>().expect("source is DtbError");
    assert!(matches!(
        *inner,
        DtbError::MissingNode {
            site: Site::Cpus,
            ..
        }
    ));
}

#[test]
fn buffer_zero_length_errors() {
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut empty = Box::new(AcpiBuffer::<0>::default());
    let gpa = common::buf_gpa(&empty);
    let err = empty.populate(&tree, &common::TEST_OEM, gpa).unwrap_err();
    match err {
        EmitError::BufferTooSmall { got, .. } => assert_eq!(got, 0),
        _ => panic!("expected BufferTooSmall, got {err:?}"),
    }
}

#[test]
fn buffer_too_small_needed_is_deterministic_and_got_reflects_n() {
    // Public API takes `AcpiBuffer<const N: usize>`, so we can't pick
    // N == needed at runtime to probe the exact boundary. We can still
    // verify: (a) `needed` is the same across two calls, (b) `got`
    // reflects each buffer's distinct N. A delta regression on either
    // field would surface here.
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();

    let mut probe_a = Box::new(AcpiBuffer::<32>::default());
    let gpa_a = common::buf_gpa(&probe_a);
    let needed_a = match probe_a
        .populate(&tree, &common::TEST_OEM, gpa_a)
        .unwrap_err()
    {
        EmitError::BufferTooSmall { needed, got, .. } => {
            assert_eq!(got, 32);
            needed
        }
        other => panic!("expected BufferTooSmall, got {other:?}"),
    };

    let mut probe_b = Box::new(AcpiBuffer::<64>::default());
    let gpa_b = common::buf_gpa(&probe_b);
    let needed_b = match probe_b
        .populate(&tree, &common::TEST_OEM, gpa_b)
        .unwrap_err()
    {
        EmitError::BufferTooSmall { needed, got, .. } => {
            assert_eq!(got, 64);
            needed
        }
        other => panic!("expected BufferTooSmall, got {other:?}"),
    };

    assert_eq!(
        needed_a, needed_b,
        "needed is deterministic for a given DTB"
    );
    assert!(needed_a > 64, "basic.dtb's layout exceeds 64 bytes");
}

/// Layout total for `basic.dtb`, pinned. Probed once via the
/// `buffer_too_small_*` tests' `BufferTooSmall.needed` field
/// (those tests independently re-verify it is deterministic). If
/// `basic.dtb` or the count arithmetic changes, the exact-fit and
/// one-byte-short tests below will fail with the new value in
/// their error message — bake that in here.
const BASIC_DTB_NEEDED: usize = 1016;

#[test]
fn buffer_at_exact_needed_succeeds() {
    // Closes the off-by-one boundary: `populate` must accept
    // N == needed. A regression that flipped `<` to `<=` on the
    // size check would BufferTooSmall here.
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut buf = Box::new(AcpiBuffer::<BASIC_DTB_NEEDED>::default());
    let gpa = common::buf_gpa(&buf);
    let n = buf
        .populate(&tree, &common::TEST_OEM, gpa)
        .expect("exact-fit must succeed");
    assert_eq!(
        n, BASIC_DTB_NEEDED,
        "populate must return the exact byte count it wrote"
    );
}

#[test]
fn buffer_one_byte_short_errors_with_exact_needed_and_got() {
    // The complementary boundary: N == needed - 1 must fail with
    // BufferTooSmall { needed: BASIC_DTB_NEEDED, got: BASIC_DTB_NEEDED - 1 }.
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut buf = Box::new(AcpiBuffer::<{ BASIC_DTB_NEEDED - 1 }>::default());
    let gpa = common::buf_gpa(&buf);
    match buf.populate(&tree, &common::TEST_OEM, gpa).unwrap_err() {
        EmitError::BufferTooSmall { needed, got, .. } => {
            assert_eq!(
                needed, BASIC_DTB_NEEDED,
                "needed must match BASIC_DTB_NEEDED (else update the const)"
            );
            assert_eq!(got, BASIC_DTB_NEEDED - 1, "got reflects N");
        }
        other => panic!("expected BufferTooSmall, got {other:?}"),
    }
}

#[test]
fn buffer_oversized_succeeds() {
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa)
        .expect("oversize must succeed");
    // Sanity: bytes were written (RSDP signature at offset 0).
    let bytes: &[u8] = (*buf).as_ref();
    assert_eq!(&bytes[..8], b"RSD PTR ");
}

#[test]
fn custom_oem_identity_appears_in_emitted_bytes() {
    // Custom OEM survives end-to-end into every SDT header and the RSDP.
    let custom = OemIdentity {
        oem_id: *b"MYVMM!",
        oem_table_id: *b"MYTABLE_",
        oem_revision: 0xABCD_1234,
        creator_id: *b"MINE",
        creator_revision: 0x9999,
    };
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &custom, gpa).unwrap();

    // RSDP lives at offset 0 (buffer start). oem_id is at bytes 9..15.
    assert_eq!(&AsRef::<[u8]>::as_ref(&*buf)[9..15], &custom.oem_id);

    // Each SDT header carries the full identity at known offsets.
    // Walk via the test decoder. `decoded.tables` contains XSDT plus
    // every entry the XSDT lists (FACP/APIC/MCFG, here); the DSDT is
    // reachable via FADT.X_DSDT and exposed as `decoded.dsdt`.
    let decoded = common::decode(&*buf);
    let bytes = AsRef::<[u8]>::as_ref(&*buf);
    let check_sdt_header_oem = |offset: usize, label: &str| {
        // SDT header: sig(4) len(4) rev(1) csum(1) oem_id(6)
        // oem_table_id(8) oem_revision(4) creator_id(4) creator_revision(4)
        assert_eq!(
            &bytes[offset + 10..offset + 16],
            &custom.oem_id,
            "{label} oem_id"
        );
        assert_eq!(
            &bytes[offset + 16..offset + 24],
            &custom.oem_table_id,
            "{label} oem_table_id"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[offset + 24..offset + 28].try_into().unwrap()),
            custom.oem_revision,
            "{label} oem_revision"
        );
        assert_eq!(
            &bytes[offset + 28..offset + 32],
            &custom.creator_id,
            "{label} creator_id"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[offset + 32..offset + 36].try_into().unwrap()),
            custom.creator_revision,
            "{label} creator_revision"
        );
    };
    for sig in [b"XSDT", b"FACP", b"APIC", b"MCFG"] {
        let header_off = decoded
            .tables
            .get(sig)
            .unwrap_or_else(|| panic!("expected {sig:?} in XSDT"))
            .offset_in_buf;
        check_sdt_header_oem(header_off, core::str::from_utf8(sig).unwrap());
    }
    check_sdt_header_oem(decoded.dsdt.header.offset_in_buf, "DSDT");
}

#[test]
fn display_renders_buffer_too_small_via_public_api() {
    // DtbError struct-form variants are `#[non_exhaustive]`, so this
    // file (an external crate) cannot enumerate them via struct-literal
    // construction; that coverage lives in src/error.rs's #[cfg(test)]
    // mod. Here we verify the only EmitError variant the public API
    // produces directly — BufferTooSmall — renders non-empty Display
    // and Debug strings.
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut tiny = Box::new(AcpiBuffer::<1>::default());
    let gpa = common::buf_gpa(&tiny);
    let err = tiny.populate(&tree, &common::TEST_OEM, gpa).unwrap_err();
    assert!(!format!("{err}").is_empty());
    assert!(!format!("{err:?}").is_empty());
}
