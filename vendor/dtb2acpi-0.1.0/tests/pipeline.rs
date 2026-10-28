// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end pipeline tests.
//!
//! Parses a fixture DTB, runs `AcpiBuffer::populate`, then validates
//! the resulting bytes by walking the cross-table chain (RSDP → XSDT
//! → tables; FADT → DSDT) via a hand-written verifier (see
//! `common/mod.rs`) that is independent of the emit code path.

mod common;

use devtree::Tree;
use dtb2acpi::AcpiBuffer;

const BASIC_DTB: &[u8] = include_bytes!("data/basic.dtb");

/// Reservation big enough to cover every fixture in `tests/data/`.
/// Real callers size this to their actual ACPI region.
const TEST_BUF: usize = 8192;

fn build_layout() -> Box<AcpiBuffer<TEST_BUF>> {
    let tree: Tree<'_> = Tree::parse(BASIC_DTB).expect("DTB parse");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa)
        .expect("write_into");
    buf
}

#[test]
fn rsdp_checksums_zero() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    assert_eq!(&d.rsdp.signature, b"RSD PTR ");
    assert_eq!(d.rsdp.revision, 2);
    assert_eq!(d.rsdp.length, 36);
}

#[test]
fn sdt_checksums_all_zero() {
    let buf = build_layout();
    // decode() verifies every SDT checksum during walk.
    let _ = common::decode(&*buf);
}

#[test]
fn fadt_hw_reduced_and_points_at_dsdt() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    assert!(d.hw_reduced(), "HW_REDUCED_ACPI must be set");
    assert_eq!(
        d.fadt.fadt_minor_version, 5,
        "FADT minor version 5 (ACPI 6.5)"
    );
    // The DSDT pointed at by FADT.X_DSDT must be valid (decode follows it).
    assert_eq!(&d.dsdt.header.signature, b"DSDT");
    assert!(d.fadt.x_dsdt >= AsRef::<[u8]>::as_ref(&*buf).as_ptr() as u64);
}

#[test]
fn fadt_iapc_boot_arch_reflects_no_legacy_hardware() {
    // Per the HW-Reduced + no-legacy-hardware contract: VGA absent
    // (bit 2) and CMOS RTC absent (bit 5) are set; the LEGACY_DEVICES,
    // 8042, MSI_NOT_SUPPORTED, and PCIE_ASPM_CONTROLS bits are clear.
    // See `IAPC_BOOT_ARCH_NO_LEGACY` in src/emit/fadt.rs for the
    // bit-by-bit rationale.
    let buf = build_layout();
    let d = common::decode(&*buf);
    let v = d.fadt.iapc_boot_arch;
    assert_eq!(v & (1 << 0), 0, "LEGACY_DEVICES clear");
    assert_eq!(v & (1 << 1), 0, "8042 controller clear");
    assert_eq!(v & (1 << 2), 1 << 2, "VGA_NOT_PRESENT set");
    assert_eq!(
        v & (1 << 3),
        0,
        "MSI_NOT_SUPPORTED clear (virtio-pci uses MSI-X)"
    );
    assert_eq!(
        v & (1 << 4),
        0,
        "PCIE_ASPM_CONTROLS clear (OS decides per device)"
    );
    assert_eq!(v & (1 << 5), 1 << 5, "CMOS_RTC_NOT_PRESENT set");
    assert_eq!(v & !((1 << 2) | (1 << 5)), 0, "reserved bits zero");
}

#[test]
fn xsdt_lists_expected_tables() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    // basic.dts has /cpus + LAPIC + IOAPIC + syscon-poweroff +
    // syscon-reboot + pci-host-ecam-generic + ns16550a serial, no NUMA.
    // So we expect: FACP, APIC, MCFG, SPCR, plus XSDT/DSDT/RSDP
    // (separately addressable).
    assert!(d.tables.contains_key(b"FACP"), "FADT missing");
    assert!(d.tables.contains_key(b"APIC"), "MADT missing");
    assert!(d.tables.contains_key(b"MCFG"), "MCFG missing");
    assert!(d.tables.contains_key(b"SPCR"), "SPCR missing");
    assert!(!d.tables.contains_key(b"SRAT"), "SRAT should be absent");
    assert!(!d.tables.contains_key(b"SLIT"), "SLIT should be absent");
    // XSDT entries should be FADT + MADT + MCFG + SPCR.
    assert_eq!(d.xsdt.entries.len(), 4, "XSDT should list 4 tables");
}

#[test]
fn madt_has_expected_entries() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    // basic.dts: 2 vCPUs, 1 IOAPIC, 0 ISO, plus 2 LAPIC NMI entries.
    let mut n_lapic = 0;
    let mut n_ioapic = 0;
    let mut n_nmi = 0;
    let mut n_iso = 0;
    for (typ, _len, _bytes) in &d.madt_entries {
        match typ {
            0 => n_lapic += 1,
            1 => n_ioapic += 1,
            2 => n_iso += 1,
            4 => n_nmi += 1,
            _ => {}
        }
    }
    assert_eq!(n_lapic, 2, "expected 2 LAPIC entries");
    assert_eq!(n_ioapic, 1, "expected 1 IOAPIC entry");
    assert_eq!(n_iso, 0, "expected 0 ISO entries (no interrupt-map)");
    assert_eq!(n_nmi, 2, "expected 2 LAPIC NMI entries (one per vCPU)");
}

#[test]
fn mcfg_lists_pci_ecam() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    assert_eq!(d.mcfg_allocations.len(), 1, "1 ECAM allocation");
    let (base, seg, bs, be) = d.mcfg_allocations[0];
    assert_eq!(base, 0x3000_0000, "ECAM base");
    assert_eq!(seg, 0, "segment group 0");
    assert_eq!(bs, 0x00, "bus_start");
    assert_eq!(be, 0xFF, "bus_end");
}

#[test]
fn dsdt_carries_s5_aml_derived_from_syscon_value() {
    // basic.dts declares syscon-poweroff value = 0x34 (the conformant
    // device-model §4 value). Per SdtHeader::write_dsdt_into,
    // SLP_TYP = (value >> 2) & 0x7 = 5. The DSDT body starts with the
    // \_S5_ AML (13 bytes), one Device(MBR0) PNP0C02 reservation for
    // ECAM (84 bytes), one Device(PCI0) block (78 bytes for the basic
    // fixture, which has no `ranges` property → zero MMIO windows), and
    // one Device(SER0) block for the MMIO ns16550a.
    let buf = build_layout();
    let d = common::decode(&*buf);
    let bytes = AsRef::<[u8]>::as_ref(&*buf);
    assert_eq!(
        d.dsdt.header.length,
        36 + 13 + 84 + 78 + 201,
        "DSDT = header(36) + _S5_(13) + Device(MBR0)(84) + Device(PCI0)(78) + Device(SER0)(201)"
    );
    let body_off = d.dsdt.header.offset_in_buf + 36;
    let s5 = &bytes[body_off..body_off + 13];
    assert_eq!(
        s5,
        &[
            0x08, 0x5C, 0x5F, 0x53, 0x35, 0x5F, 0x12, 0x06, 0x03, 0x0A, 0x05, 0x00, 0x00
        ],
        "DSDT body must start with Name(\\_S5_, Package(3){{5,0,0}})"
    );
    // The next byte begins the Device(MBR0) block: ExtOpPrefix 0x5B,
    // DeviceOp 0x82.
    assert_eq!(
        &bytes[body_off + 13..body_off + 15],
        &[0x5B, 0x82],
        "Device(MBR0) follows _S5_"
    );
}

#[test]
fn dsdt_reserves_ecam_as_motherboard_resource() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    let bytes = AsRef::<[u8]>::as_ref(&*buf);
    let dsdt = &bytes[d.dsdt.header.offset_in_buf..][..d.dsdt.header.length as usize];

    let mbr = dsdt
        .windows(4)
        .position(|w| w == b"MBR0")
        .expect("Device(MBR0) present");
    assert!(
        dsdt[mbr..]
            .windows(5)
            .any(|w| w == [0x0c, 0x41, 0xd0, 0x0c, 0x02]),
        "_HID PNP0C02 present"
    );
    let mem = dsdt[mbr..]
        .windows(46)
        .position(|w| w[0] == 0x8A && w[1] == 0x2B && w[3] == 0x00)
        .expect("ECAM QWordMemory descriptor present")
        + mbr;
    let desc = &dsdt[mem..mem + 46];
    assert_eq!(
        u64::from_le_bytes(desc[14..22].try_into().unwrap()),
        0x3000_0000,
        "ECAM reservation base"
    );
    assert_eq!(
        u64::from_le_bytes(desc[38..46].try_into().unwrap()),
        0x1000_0000,
        "ECAM reservation size"
    );
}

#[test]
fn dsdt_carries_mmio_serial_device() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    let bytes = AsRef::<[u8]>::as_ref(&*buf);
    let dsdt = &bytes[d.dsdt.header.offset_in_buf..][..d.dsdt.header.length as usize];

    let ser = dsdt
        .windows(4)
        .position(|w| w == b"SER0")
        .expect("Device(SER0) present");
    assert!(
        dsdt[ser..].windows(9).any(|w| w == b"RSCV0003\0"),
        "_HID RSCV0003 present"
    );
    let mem = dsdt[ser..]
        .windows(46)
        .position(|w| w[0] == 0x8A && w[1] == 0x2B && w[3] == 0x00)
        .expect("serial QWordMemory descriptor present")
        + ser;
    let desc = &dsdt[mem..mem + 46];
    assert_eq!(
        u64::from_le_bytes(desc[14..22].try_into().unwrap()),
        0x900_0000
    );
    assert!(
        dsdt.windows(9).any(|w| w[0] == 0x89
            && w[1] == 0x06
            && w[3] == 0x03
            && u32::from_le_bytes(w[5..9].try_into().unwrap()) == 4),
        "ExtendedInterrupt GSI 4, edge + active-high (sense=1) present"
    );
    assert!(
        dsdt.windows("clock-frequency".len())
            .any(|w| w == b"clock-frequency")
            && dsdt.windows("reg-shift".len()).any(|w| w == b"reg-shift")
            && dsdt
                .windows("reg-io-width".len())
                .any(|w| w == b"reg-io-width"),
        "_DSD serial port properties present"
    );
}

#[test]
fn fadt_sleep_control_from_syscon_poweroff() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    // basic.dts: poweroff@9010000 carries its own reg = 0x9010000.
    assert_eq!(d.fadt.sleep_control_addr, 0x901_0000);
    assert_eq!(d.fadt.sleep_status_addr, 0x901_0000);
}

#[test]
fn fadt_reset_from_syscon_reboot() {
    let buf = build_layout();
    let d = common::decode(&*buf);
    // basic.dts: reboot@9020000 carries its own reg = 0x9020000, value 0x1.
    assert_eq!(d.fadt.reset_addr, 0x902_0000);
    assert_eq!(d.fadt.reset_value, 0x01);
    // RESET_REG_SUP (bit 10) must be set whenever reset_reg is populated —
    // ACPI 6.5 §5.2.9.3 gates OS inspection of reset_reg on this flag.
    assert!(
        d.fadt.flags & (1 << 10) != 0,
        "RESET_REG_SUP must be set when syscon-reboot is present"
    );
}

#[test]
fn madt_lists_two_ioapics_with_sequential_ids() {
    // Covers the IOAPIC re-walk in madt::emit: count counts the
    // intel,ce4100-ioapic nodes; emit assigns id = 0..N and
    // gsi_base = N*24 sequentially by walking those nodes in order.
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/two_ioapics.dtb")).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);

    let ioapics: Vec<&(u8, u8, Vec<u8>)> = d
        .madt_entries
        .iter()
        .filter(|(typ, _, _)| *typ == 1)
        .collect();
    assert_eq!(ioapics.len(), 2, "expected 2 IOAPIC entries");
    for (i, (_typ, len, bytes)) in ioapics.iter().enumerate() {
        assert_eq!(*len, 12, "IOAPIC entry length");
        assert_eq!(bytes[2], i as u8, "io_apic_id sequential 0..N");
        assert_eq!(bytes[3], 0, "reserved byte");
        let base = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let gsi = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let expected_base = 0xfec0_0000u32 + (i as u32) * 0x1000;
        let expected_gsi = (i as u32) * 24;
        assert_eq!(base, expected_base, "IOAPIC[{i}] base");
        assert_eq!(gsi, expected_gsi, "IOAPIC[{i}] gsi_base");
    }
}

#[test]
fn dsdt_above_4gib_zeros_legacy_field() {
    // When base_gpa places the DSDT above 4 GiB, FADT's legacy 32-bit
    // `dsdt` field must be zero; only x_dsdt carries the real address.
    // Documented in the crate-root rustdoc; previously untested
    // because all tests use heap-allocated Box<AcpiBuffer> which lives
    // below 4 GiB.
    let tree: Tree<'_> = Tree::parse(BASIC_DTB).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let high_gpa: u64 = 0x1_0000_0000; // 4 GiB exactly
    buf.populate(&tree, &common::TEST_OEM, high_gpa).unwrap();

    // Walk the full chain at the synthetic GPA — re-verifies every
    // SDT checksum and follows XSDT/FADT/DSDT pointers as the OS
    // would, catching any checksum or pointer breakage that's
    // specific to a non-buffer base GPA.
    let d = common::decode_at_base(&*buf, high_gpa);
    assert_eq!(d.fadt.dsdt_legacy, 0, "legacy FADT.dsdt zero above 4 GiB");
    assert!(d.fadt.x_dsdt >= high_gpa, "x_dsdt carries the high GPA");
    assert!(d.fadt.x_dsdt > u64::from(u32::MAX), "x_dsdt is above 4 GiB");
    assert_eq!(
        &d.dsdt.header.signature, b"DSDT",
        "DSDT reachable via x_dsdt"
    );
}

#[test]
fn populate_is_recallable_across_different_dtbs() {
    // First populate writes the NUMA layout (includes SRAT/SLIT).
    // Second populate with the basic DTB shrinks the layout (no SRAT,
    // no SLIT). The second populated() prefix must reflect only the
    // new layout — no stale SRAT/SLIT entries leaking through XSDT.
    let numa_dtb: &[u8] = include_bytes!("data/numa.dtb");
    let basic_tree: Tree<'_> = Tree::parse(BASIC_DTB).unwrap();
    let numa_tree: Tree<'_> = Tree::parse(numa_dtb).unwrap();

    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&numa_tree, &common::TEST_OEM, gpa).unwrap();
    let numa_decoded = common::decode(&*buf);
    assert!(
        numa_decoded.tables.contains_key(b"SRAT"),
        "numa fixture has SRAT"
    );
    assert!(
        numa_decoded.tables.contains_key(b"SLIT"),
        "numa fixture has SLIT"
    );

    buf.populate(&basic_tree, &common::TEST_OEM, gpa).unwrap();
    let basic_decoded = common::decode(&*buf);
    assert!(
        !basic_decoded.tables.contains_key(b"SRAT"),
        "second populate must not leave stale SRAT reachable via XSDT"
    );
    assert!(
        !basic_decoded.tables.contains_key(b"SLIT"),
        "second populate must not leave stale SLIT reachable via XSDT"
    );
    // The basic layout has its own distinct table set (MCFG + SPCR, no
    // NUMA tables); the numa fixture has SRAT/SLIT and no PCI/serial.
    // The recall must reflect only the new layout.
    assert!(
        basic_decoded.tables.contains_key(b"MCFG") && basic_decoded.tables.contains_key(b"SPCR"),
        "recall reflects the basic layout's MCFG + SPCR"
    );
    assert!(
        !numa_decoded.tables.contains_key(b"SPCR"),
        "numa fixture has no SPCR"
    );
}

#[test]
fn populate_returns_live_image_length() {
    // populate's Ok(n) is the live ACPI image length: the live image is
    // the buffer prefix [..n] (starting at the RSDP), the rest is the
    // untouched tail. This is the whole contract now that the buffer is
    // a pure `[u8; N]` with no embedded length.
    let tree: Tree<'_> = Tree::parse(BASIC_DTB).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    let n = buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let live = &AsRef::<[u8]>::as_ref(&*buf)[..n];
    assert_eq!(&live[..8], b"RSD PTR ", "live prefix starts at the RSDP");
    assert!(n <= TEST_BUF, "live image fits the buffer");
}

#[test]
fn populate_recovers_after_prior_error() {
    // The rustdoc contracts that a failed populate leaves the buffer
    // reusable. Pin that: error first (no_cpus), then a normal populate
    // on the same buffer must succeed and decode cleanly.
    let no_cpus_tree: Tree<'_> = Tree::parse(include_bytes!("data/no_cpus.dtb")).unwrap();
    let good_tree: Tree<'_> = Tree::parse(BASIC_DTB).unwrap();

    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    let _ = buf
        .populate(&no_cpus_tree, &common::TEST_OEM, gpa)
        .expect_err("no_cpus must error");

    buf.populate(&good_tree, &common::TEST_OEM, gpa)
        .expect("populate after prior error must succeed");
    let d = common::decode(&*buf);
    assert_eq!(&d.rsdp.signature, b"RSD PTR ");
}

#[test]
fn buffer_bytes_field_lives_at_struct_offset_zero() {
    // The documented contract: `&buf as *const _` is the address of the
    // RSDP. AcpiBuffer is a `#[repr(transparent)]` newtype over
    // `[u8; N]`, so the bytes are at struct offset 0 — callers pass
    // `&buf as u64` as base_gpa and the RSDP lands there. Pin it.
    let buf = AcpiBuffer::<256>::default();
    let struct_addr = &raw const buf as usize;
    let bytes_addr = buf.as_ref().as_ptr() as usize;
    assert_eq!(
        struct_addr, bytes_addr,
        "AcpiBuffer's bytes must live at struct offset 0 \
         (callers pass `&buf as u64` as base_gpa)"
    );
}

#[test]
fn const_new_constructs_into_static_slot() {
    // The doc on AcpiBuffer recommends `static` placement via the
    // const constructor; the type system has to accept the pattern.
    static ACPI: AcpiBuffer<256> = AcpiBuffer::new();
    assert_eq!(AsRef::<[u8]>::as_ref(&ACPI).len(), 256);
}

#[test]
fn pci_crs_includes_64bit_qword_window() {
    // pci_64bit_window.dts declares a single 64-bit MMIO window (space
    // code 0x03). The Device(PCI0) _CRS must carry a QWordMemory
    // descriptor (large-resource tag 0x8A) with the 64-bit base/length
    // — proving the 64-bit window is no longer silently dropped.
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/pci_64bit_window.dtb")).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);
    let bytes = AsRef::<[u8]>::as_ref(&*buf);
    let dsdt_off = d.dsdt.header.offset_in_buf;
    let dsdt = &bytes[dsdt_off..dsdt_off + d.dsdt.header.length as usize];

    let pci = dsdt
        .windows(4)
        .position(|w| w == b"PCI0")
        .expect("Device(PCI0) present");

    // Find the QWordMemory descriptor (tag 0x8A) in the PCI0 _CRS.
    let q = dsdt[pci..]
        .windows(46)
        .position(|w| w[0] == 0x8A && w[1] == 0x2B && w[3] == 0x00)
        .expect("QWordMemory descriptor present in PCI0 _CRS")
        + pci;
    let desc = &dsdt[q..q + 46];
    let min = u64::from_le_bytes(desc[14..22].try_into().unwrap());
    let max = u64::from_le_bytes(desc[22..30].try_into().unwrap());
    let len = u64::from_le_bytes(desc[38..46].try_into().unwrap());
    assert_eq!(min, 0x0000_0008_0000_0000, "64-bit window base = 32 GiB");
    assert_eq!(len, 0x0000_0020_0000_0000, "64-bit window size = 128 GiB");
    assert_eq!(max, min + len - 1, "max = base + size - 1");
}

#[test]
fn spcr_describes_mmio_16550() {
    // basic.dts declares serial@9000000 (ns16550a, reg-io-width=4,
    // interrupts = <4 1>). The SPCR must describe a full 16550 over
    // SYSTEM_MEMORY at 0x9000000, 32-bit access, GSI 4.
    let buf = build_layout();
    let d = common::decode(&*buf);
    let h = d.tables.get(b"SPCR").expect("SPCR present");
    let bytes = AsRef::<[u8]>::as_ref(&*buf);
    let off = h.offset_in_buf;
    // SPCR rev 2 length is 80 bytes.
    assert_eq!(h.length, 80, "SPCR length");
    // interface_type at offset 36 — 0 = full 16550.
    assert_eq!(bytes[off + 36], 0x00, "interface_type = full 16550");
    // base_address GAS at offset 40: space_id, bit_width, bit_offset,
    // access_size, then u64 address.
    assert_eq!(bytes[off + 40], 0x00, "GAS space_id = SYSTEM_MEMORY");
    assert_eq!(bytes[off + 41], 32, "GAS register_bit_width = 32");
    assert_eq!(
        bytes[off + 43],
        3,
        "GAS access_size = dword (reg-io-width 4)"
    );
    let addr = u64::from_le_bytes(bytes[off + 44..off + 52].try_into().unwrap());
    assert_eq!(addr, 0x900_0000, "base address from serial reg");
    // interrupt_type at offset 52 — bit 3 (IO-APIC).
    assert_eq!(bytes[off + 52], 0x08, "interrupt_type = IO-APIC");
    // gsi (u32) at offset 54.
    let gsi = u32::from_le_bytes(bytes[off + 54..off + 58].try_into().unwrap());
    assert_eq!(gsi, 4, "gsi = IO-APIC pin from interrupts<4 1>");
    // baud_rate at offset 58 — 7 = 115200, translated from DT current-speed.
    assert_eq!(bytes[off + 58], 7, "SPCR baud_rate = 115200");
}

#[test]
fn mcfg_lists_two_ecams() {
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/pci_two_ecams.dtb")).unwrap();
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa).unwrap();
    let d = common::decode(&*buf);
    assert_eq!(d.mcfg_allocations.len(), 2, "2 ECAM allocations");
    assert_eq!(d.mcfg_allocations[0].0, 0x3000_0000, "first ECAM base");
    assert_eq!(d.mcfg_allocations[1].0, 0x4000_0000, "second ECAM base");
    assert_eq!(d.mcfg_allocations[0].2, 0x00, "first bus_start");
    assert_eq!(d.mcfg_allocations[0].3, 0x7f, "first bus_end");
    assert_eq!(d.mcfg_allocations[1].2, 0x80, "second bus_start");
    assert_eq!(d.mcfg_allocations[1].3, 0xff, "second bus_end");
}
