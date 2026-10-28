// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-cpu `status` (DT spec §2.3.4) → ACPI MADT/SRAT flag mapping.
//!
//! - `okay` (or absent) → MADT Enabled=1; SRAT Enabled=1
//! - `disabled` → MADT OnlineCapable=1 (Enabled=0); SRAT Enabled=1
//!   (affinity is a static topology property, kept across hot-plug)
//! - `fail` / `fail-*` / `reserved` → MADT both flags=0; SRAT Enabled=0

mod common;

use devtree::Tree;
use dtb2acpi::AcpiBuffer;

const DISABLED_DTB: &[u8] = include_bytes!("data/cpu_status_disabled.dtb");
const FAIL_DTB: &[u8] = include_bytes!("data/cpu_status_fail.dtb");
const TEST_BUF: usize = 8192;

fn build(dtb: &[u8]) -> Box<AcpiBuffer<TEST_BUF>> {
    let tree: Tree<'_> = Tree::parse(dtb).expect("DTB parse");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa)
        .expect("populate");
    buf
}

/// Read the flags u32 from a Type 0 LAPIC MADT entry. Layout per
/// ACPI 6.5 §5.2.12.2: type, length, processor_id, apic_id, flags.
fn lapic_flags(entry: &(u8, u8, Vec<u8>)) -> u32 {
    let bytes = &entry.2;
    assert_eq!(entry.0, 0, "expected Type 0 LAPIC entry");
    assert_eq!(entry.1, 8, "Type 0 length is 8");
    u32::from_le_bytes(bytes[4..8].try_into().unwrap())
}

/// Read the flags u32 from a Type 0 SRAT ProcessorLocalApicAffinity
/// entry's BODY (the `common::decode` slice strips the type/length
/// prefix). Body layout: proximity_domain_lo, apic_id, flags(u32 LE).
fn srat_cpu_flags(body: &[u8]) -> u32 {
    u32::from_le_bytes(body[2..6].try_into().unwrap())
}

#[test]
fn explicit_okay_and_disabled_produce_distinct_madt_flags() {
    let buf = build(DISABLED_DTB);
    let d = common::decode(&*buf);
    let lapics: Vec<_> = d.madt_entries.iter().filter(|(t, _, _)| *t == 0).collect();
    assert_eq!(lapics.len(), 2, "two LAPIC entries — one per cpu node");

    // cpu@0 has explicit `status = "okay"` (DT spec equivalent of
    // absent); must map to ENABLED only.
    assert_eq!(lapic_flags(lapics[0]), 0b01, "cpu@0 ENABLED");

    // cpu@1 has `status = "disabled"`; must map to OnlineCapable only.
    assert_eq!(lapic_flags(lapics[1]), 0b10, "cpu@1 ONLINE_CAPABLE");
}

#[test]
fn disabled_cpu_keeps_srat_enabled() {
    // Hot-onlineable cpus retain their NUMA affinity so the OS knows
    // where to place memory references after onlining. SRAT only has
    // an Enabled bit (no OnlineCapable concept).
    let buf = build(DISABLED_DTB);
    let d = common::decode(&*buf);
    let srat_cpu: Vec<_> = d.srat_entries.iter().filter(|(t, _)| *t == 0).collect();
    assert_eq!(srat_cpu.len(), 2);
    for (i, (_t, body)) in srat_cpu.iter().enumerate() {
        assert_eq!(
            srat_cpu_flags(body) & 0x1,
            0x1,
            "cpu@{i} SRAT entry must stay Enabled (affinity is static)"
        );
    }
}

#[test]
fn fail_cpu_zeroes_madt_and_srat_flags() {
    let buf = build(FAIL_DTB);
    let d = common::decode(&*buf);
    let lapics: Vec<_> = d.madt_entries.iter().filter(|(t, _, _)| *t == 0).collect();
    assert_eq!(lapics.len(), 2);
    assert_eq!(lapic_flags(lapics[0]), 0b01, "cpu@0 still ENABLED");
    // cpu@1 status="fail" → both bits clear, OSPM ignores per
    // ACPI 6.5 §5.2.12.2.
    assert_eq!(
        lapic_flags(lapics[1]),
        0,
        "cpu@1 NotPresent: both bits clear"
    );

    let srat_cpu: Vec<_> = d.srat_entries.iter().filter(|(t, _)| *t == 0).collect();
    assert_eq!(srat_cpu.len(), 2);
    assert_eq!(
        srat_cpu_flags(&srat_cpu[0].1) & 0x1,
        0x1,
        "cpu@0 SRAT Enabled"
    );
    assert_eq!(
        srat_cpu_flags(&srat_cpu[1].1) & 0x1,
        0,
        "cpu@1 SRAT NotPresent: Enabled bit cleared"
    );
}
