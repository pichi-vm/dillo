// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! NUMA-aware DTB → SRAT + SLIT integration tests.

mod common;

use devtree::Tree;
use dtb2acpi::AcpiBuffer;

const NUMA_DTB: &[u8] = include_bytes!("data/numa.dtb");
const TEST_BUF: usize = 8192;

fn build_layout() -> Box<AcpiBuffer<TEST_BUF>> {
    let tree: Tree<'_> = Tree::parse(NUMA_DTB).expect("DTB parse");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa)
        .expect("write_into");
    buf
}

#[test]
fn numa_emits_srat() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    assert!(
        d.tables.contains_key(b"SRAT"),
        "SRAT should be present for NUMA-tagged DTB"
    );
    // 4 vCPUs (type 0) + 2 memory regions (type 1).
    let n_cpu = d.srat_entries.iter().filter(|(t, _)| *t == 0).count();
    let n_mem = d.srat_entries.iter().filter(|(t, _)| *t == 1).count();
    assert_eq!(n_cpu, 4, "expected 4 SRAT CPU affinity entries");
    assert_eq!(n_mem, 2, "expected 2 SRAT memory affinity entries");
}

#[test]
fn numa_emits_slit() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    let matrix = d
        .slit_matrix
        .as_ref()
        .expect("SLIT should be present with >1 domain + distance-map");
    // 2 domains → 2x2 matrix.
    assert_eq!(matrix.len(), 4, "2x2 distance matrix");
    // Diagonals: 10 (local). Off-diagonals: 21 (per fixture).
    assert_eq!(matrix[0], 10, "[0][0]");
    assert_eq!(matrix[1], 21, "[0][1]");
    assert_eq!(matrix[2], 21, "[1][0]");
    assert_eq!(matrix[3], 10, "[1][1]");
}

#[test]
fn xsdt_includes_srat_and_slit() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    // FACP + APIC + SRAT + SLIT (no MCFG in numa.dts).
    assert_eq!(d.xsdt.entries.len(), 4);
}

#[test]
fn numa_slit_single_direction_mirrors() {
    // DTB lists only <0 1 21>; the extractor auto-mirrors so the
    // emitted SLIT is symmetric (matrix[0][1] == matrix[1][0] == 21).
    const DTB: &[u8] = include_bytes!("data/numa_slit_one_direction.dtb");
    let tree: Tree<'_> = Tree::parse(DTB).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);
    let matrix = d.slit_matrix.as_ref().expect("SLIT present");
    assert_eq!(matrix.len(), 4, "2x2 distance matrix");
    assert_eq!(matrix[0], 10, "[0][0] diagonal");
    assert_eq!(matrix[1], 21, "[0][1] explicit");
    assert_eq!(matrix[2], 21, "[1][0] auto-mirrored");
    assert_eq!(matrix[3], 10, "[1][1] diagonal");
}

#[test]
fn numa_no_distance_map_emits_srat_without_slit() {
    // 2 NUMA domains but /distance-map omitted: per ACPI spec Linux
    // uses default distances when SLIT is absent. We omit SLIT.
    const DTB: &[u8] = include_bytes!("data/numa_no_distance_map.dtb");
    let tree: Tree<'_> = Tree::parse(DTB).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);
    assert!(d.tables.contains_key(b"SRAT"), "SRAT present");
    assert!(
        !d.tables.contains_key(b"SLIT"),
        "SLIT absent when /distance-map omitted"
    );
    assert!(d.slit_matrix.is_none());
}

#[test]
fn numa_single_domain_emits_srat_without_slit() {
    // All cpus + memory in one NUMA domain. SRAT is emitted (NUMA
    // tagging is present) but SLIT is skipped because `n_domains > 1`
    // is false — distinct from `numa_no_distance_map_emits_srat_*`,
    // which has 2 domains but omits /distance-map. This is the
    // false-branch of the `n_domains > 1` guard in `count_numa`.
    const DTB: &[u8] = include_bytes!("data/numa_single_domain.dtb");
    let tree: Tree<'_> = Tree::parse(DTB).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);
    assert!(
        d.tables.contains_key(b"SRAT"),
        "SRAT present (NUMA tagging)"
    );
    assert!(
        !d.tables.contains_key(b"SLIT"),
        "SLIT absent with a single NUMA domain"
    );
    assert!(d.slit_matrix.is_none());
}

#[test]
fn numa_slit_diagonal_only_fills_defaults() {
    // Distance-matrix lists only `<0 0 10>, <1 1 10>` — the
    // off-diagonal cells stay at the sentinel (0) after the triple
    // loop, and `slit::emit`'s final-fill pass replaces them with
    // the ACPI default of 20. This is the only fixture exercising
    // that fallback; every other NUMA fixture provides explicit
    // off-diagonal triples.
    const DTB: &[u8] = include_bytes!("data/numa_slit_diagonal_only.dtb");
    let tree: Tree<'_> = Tree::parse(DTB).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);
    let matrix = d.slit_matrix.as_ref().expect("SLIT present");
    assert_eq!(matrix.len(), 4, "2x2 distance matrix");
    assert_eq!(matrix[0], 10, "[0][0] from explicit triple");
    assert_eq!(matrix[1], 20, "[0][1] defaulted to 20");
    assert_eq!(matrix[2], 20, "[1][0] defaulted to 20");
    assert_eq!(matrix[3], 10, "[1][1] from explicit triple");
}

#[test]
fn numa_memory_only_domain_emits_3x3_slit() {
    // Fixture exercises (a) the memory-only NUMA path in
    // slit::index_of_domain — domain 2 is tagged on memory but no cpu;
    // (b) the duplicate-memory-pd no-op insert in count_numa
    // (two /memory@... nodes both tagged pd=2). Without this fixture
    // the dedup branch and the post-cpu memory walk in Domains were
    // dead from a test perspective.
    const DTB: &[u8] = include_bytes!("data/numa_memory_only_domain.dtb");
    let tree: Tree<'_> = Tree::parse(DTB).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);

    // 4 memory regions × Type 1 + 2 cpus × Type 0 in SRAT.
    let n_cpu = d.srat_entries.iter().filter(|(t, _)| *t == 0).count();
    let n_mem = d.srat_entries.iter().filter(|(t, _)| *t == 1).count();
    assert_eq!(n_cpu, 2, "expected 2 SRAT CPU affinity entries");
    assert_eq!(n_mem, 4, "expected 4 SRAT memory affinity entries");

    // Three distinct NUMA domains: 0, 1 (cpu+mem), 2 (memory-only).
    // SLIT therefore is 3x3, not 2x2 — which would be the symptom
    // if domain 2 were dropped (memory-only path skipped) or if the
    // duplicate pd=2 memory node grew the count to 4.
    let matrix = d.slit_matrix.as_ref().expect("SLIT present");
    assert_eq!(matrix.len(), 9, "3x3 distance matrix");

    // Row-major index order: cpus first (0, 1), then memory-only (2).
    // Matrix encodes our fixture's distance-matrix exactly.
    assert_eq!(matrix[0], 10, "[0][0] diagonal");
    assert_eq!(matrix[1], 21, "[0][1]");
    assert_eq!(matrix[2], 31, "[0][2] cpu→memory-only");
    assert_eq!(matrix[3], 21, "[1][0]");
    assert_eq!(matrix[4], 10, "[1][1] diagonal");
    assert_eq!(matrix[5], 32, "[1][2] cpu→memory-only");
    assert_eq!(matrix[6], 31, "[2][0] memory-only→cpu");
    assert_eq!(matrix[7], 32, "[2][1] memory-only→cpu");
    assert_eq!(matrix[8], 10, "[2][2] diagonal");
}
