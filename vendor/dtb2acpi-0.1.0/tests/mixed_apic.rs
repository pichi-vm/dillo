// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Mixed-mode MADT/SRAT entry tests: vCPUs with APIC ID ≤254 use
//! Type 0/4 (xAPIC); APIC ID ≥255 forces Type 9 (Processor Local
//! x2APIC) and the matching Type 2 SRAT affinity. NMI selection
//! between Type 4 and Type 10 is driven by the processor UID
//! (assigned sequentially from 0; UID >254 needs >254 vCPUs).
//! `many_cpus.dtb` is generator-built (256 vCPUs) so this fixture
//! still ships in-tree without being hand-written — see
//! `tests/data/generate_many_cpus.sh`.

mod common;

use devtree::Tree;
use dtb2acpi::AcpiBuffer;

const HIGH_APIC_DTB: &[u8] = include_bytes!("data/cpu_high_apic_id.dtb");
const NUMA_HIGH_APIC_DTB: &[u8] = include_bytes!("data/numa_high_apic_id.dtb");
const MANY_CPUS_DTB: &[u8] = include_bytes!("data/many_cpus.dtb");
const TEST_BUF: usize = 8192;

fn build_layout(dtb: &[u8]) -> Box<AcpiBuffer<TEST_BUF>> {
    let tree: Tree<'_> = Tree::parse(dtb).expect("DTB parse");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa)
        .expect("write_into");
    buf
}

#[test]
fn madt_mixes_type_0_and_type_9_per_vcpu() {
    let buf = build_layout(HIGH_APIC_DTB);
    let d = common::decode(&*buf);
    let mut n_lapic = 0;
    let mut n_x2apic = 0;
    let mut n_ioapic = 0;
    let mut n_nmi = 0;
    let mut n_x2nmi = 0;
    let mut x2apic_ids = Vec::new();
    let mut x2apic_uids = Vec::new();
    for (typ, len, bytes) in &d.madt_entries {
        match typ {
            0 => {
                assert_eq!(*len, 8, "Type 0 length is 8");
                n_lapic += 1;
            }
            1 => {
                assert_eq!(*len, 12, "Type 1 length is 12");
                n_ioapic += 1;
            }
            4 => {
                assert_eq!(*len, 6, "Type 4 length is 6");
                n_nmi += 1;
            }
            9 => {
                assert_eq!(*len, 16, "Type 9 length is 16");
                n_x2apic += 1;
                let id = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let uid = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                x2apic_ids.push(id);
                x2apic_uids.push(uid);
            }
            10 => {
                n_x2nmi += 1;
            }
            _ => {}
        }
    }
    assert_eq!(n_lapic, 1, "1 Type 0 entry (apic_id 0)");
    assert_eq!(n_x2apic, 1, "1 Type 9 entry (apic_id 4096)");
    assert_eq!(n_ioapic, 1);
    assert_eq!(n_nmi, 2, "2 Type 4 NMI entries (both UIDs ≤254)");
    assert_eq!(n_x2nmi, 0, "no Type 10 entries (UIDs are 0 and 1)");
    assert_eq!(x2apic_ids, vec![0x1000], "x2APIC ID from cpu@1000.reg[0]");
    assert_eq!(
        x2apic_uids,
        vec![1],
        "x2APIC UID is sequential (second cpu)"
    );
}

#[test]
fn srat_emits_type_2_for_high_apic_id() {
    // numa_high_apic_id.dts combines APIC ID 4096 with NUMA tagging,
    // forcing one SRAT Type 0 (cpu@0, apic 0, domain 0) and one SRAT
    // Type 2 (cpu@1000, apic 0x1000, domain 1). Without this fixture
    // the Type 2 packing was never exercised by any test.
    let buf = build_layout(NUMA_HIGH_APIC_DTB);
    let d = common::decode(&*buf);

    let type_0: Vec<&(u8, Vec<u8>)> = d.srat_entries.iter().filter(|(t, _)| *t == 0).collect();
    let type_2: Vec<&(u8, Vec<u8>)> = d.srat_entries.iter().filter(|(t, _)| *t == 2).collect();
    let type_1: Vec<&(u8, Vec<u8>)> = d.srat_entries.iter().filter(|(t, _)| *t == 1).collect();

    assert_eq!(type_0.len(), 1, "1 SRAT Type 0 for apic_id 0");
    assert_eq!(type_2.len(), 1, "1 SRAT Type 2 for apic_id 0x1000");
    assert_eq!(type_1.len(), 2, "2 SRAT memory affinity entries");

    // Type 2 body layout after the (entry_type, length) prefix
    // (which `decode` strips): reserved_1[2] @ 0..2, proximity_domain
    // @ 2..6, x2apic_id @ 6..10. Total entry length is 24 bytes
    // (decoded body slice length is 22).
    let body = &type_2[0].1;
    assert_eq!(body.len(), 24 - 2, "X2ApicAffinity body is 22 bytes");
    let pd = u32::from_le_bytes(body[2..6].try_into().unwrap());
    let x2id = u32::from_le_bytes(body[6..10].try_into().unwrap());
    assert_eq!(pd, 1, "proximity_domain matches numa-node-id on cpu@1000");
    assert_eq!(x2id, 0x1000, "x2apic_id matches cpu@1000.reg[0]");
}

#[test]
fn madt_emits_type_10_nmi_when_uid_exceeds_xapic_max() {
    // 256 vCPUs → UID 255 forces the x2APIC NMI path (Type 10). The
    // first 255 vCPUs (UID 0..=254, APIC ID 0..=254) get Type 0 + 4;
    // the last (UID 255) gets Type 9 + 10. Without this fixture the
    // Type 10 NMI encoder was only reached by the direct unit test
    // in src/emit/madt.rs.
    let buf = build_layout(MANY_CPUS_DTB);
    let d = common::decode(&*buf);
    let mut n_lapic = 0;
    let mut n_x2apic = 0;
    let mut n_nmi = 0;
    let mut n_x2nmi = 0;
    let mut x2apic_uids = Vec::new();
    let mut x2nmi_uids = Vec::new();
    for (typ, _len, bytes) in &d.madt_entries {
        match typ {
            0 => n_lapic += 1,
            4 => n_nmi += 1,
            9 => {
                n_x2apic += 1;
                let uid = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                x2apic_uids.push(uid);
            }
            10 => {
                n_x2nmi += 1;
                // Type 10 layout: type, length, flags(u16 LE),
                // uid(u32 LE), lint, reserved[3] — 12 bytes total.
                let uid = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let lint = bytes[8];
                x2nmi_uids.push(uid);
                assert_eq!(lint, 1, "Type 10 NMI must wire LINT1");
            }
            _ => {}
        }
    }
    assert_eq!(n_lapic, 255, "255 Type 0 entries (UID 0..=254)");
    assert_eq!(n_x2apic, 1, "1 Type 9 entry (UID 255)");
    assert_eq!(n_nmi, 255, "255 Type 4 NMI entries (UID 0..=254)");
    assert_eq!(n_x2nmi, 1, "1 Type 10 NMI entry (UID 255)");
    assert_eq!(x2apic_uids, vec![255], "x2APIC UID is the 256th cpu");
    assert_eq!(x2nmi_uids, vec![255], "Type 10 NMI UID matches");
}
