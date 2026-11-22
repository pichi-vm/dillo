// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::fdt_writer::FdtBuilder;
use dillo_devtree::devtree::{NodeView, Tree, TreeView};
use dillo_devtree::platform::PropExt;
use serde_json::json;

#[derive(Debug, Clone, Copy)]
enum BaseChannel {
    Bundled,
    Detached,
    Optional,
}

const ARCHES: [HostArchitecture; 2] = [HostArchitecture::X86_64, HostArchitecture::Aarch64];
const CHANNELS: [BaseChannel; 3] = [
    BaseChannel::Bundled,
    BaseChannel::Detached,
    BaseChannel::Optional,
];

fn base(arch: HostArchitecture, fixed_cpus: bool, fixed_memory: bool) -> Vec<u8> {
    let mut fdt = FdtBuilder::new();
    fdt.begin_node("");
    fdt.property_u32("#address-cells", 2);
    fdt.property_u32("#size-cells", 2);
    match arch {
        HostArchitecture::X86_64 => {
            for (name, compatible, address, phandle) in [
                (
                    "interrupt-controller@fee00000",
                    "intel,ce4100-lapic",
                    0xfee0_0000,
                    1,
                ),
                (
                    "interrupt-controller@fec00000",
                    "intel,ce4100-ioapic",
                    0xfec0_0000,
                    2,
                ),
            ] {
                fdt.begin_node(name);
                fdt.property_string("compatible", compatible);
                fdt.property_reg_2cells("reg", address, 0x1000);
                fdt.property_u32("#interrupt-cells", 2);
                fdt.property("interrupt-controller", &[]);
                fdt.property_u32("phandle", phandle);
                fdt.end_node();
            }
            fdt.begin_node("poweroff@9010000");
            fdt.property_string("compatible", "syscon-poweroff");
            fdt.property_reg_2cells("reg", 0x0901_0000, 4);
            fdt.property_u32("value", 0x34);
            fdt.end_node();
        }
        HostArchitecture::Aarch64 => {
            fdt.begin_node("interrupt-controller@8000000");
            fdt.property_string("compatible", "arm,gic-v3");
            let regs: Vec<u8> = [0u32, 0x0800_0000, 0, 0x10000, 0, 0x0810_0000, 0, 0x200_0000]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect();
            fdt.property("reg", &regs);
            fdt.property_u32("#interrupt-cells", 3);
            fdt.property("interrupt-controller", &[]);
            fdt.property_u32("phandle", 1);
            fdt.end_node();
            fdt.begin_node("msi-controller@a100000");
            fdt.property_string("compatible", "arm,gic-v2m-frame");
            fdt.property("msi-controller", &[]);
            fdt.property_reg_2cells("reg", 0x0a10_0000, 0x10000);
            fdt.property_u32("arm,msi-base-spi", 64);
            fdt.property_u32("arm,msi-num-spis", 32);
            fdt.property_u32("phandle", 3);
            fdt.end_node();
            fdt.begin_node("timer");
            fdt.property_string("compatible", "arm,armv8-timer");
            let irqs: Vec<u8> = [
                1u32, 13, 0xff08, 1, 14, 0xff08, 1, 11, 0xff08, 1, 10, 0xff08,
            ]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect();
            fdt.property("interrupts", &irqs);
            fdt.property_u32("interrupt-parent", 1);
            fdt.end_node();
            fdt.begin_node("psci");
            fdt.property_string("compatible", "arm,psci-0.2");
            fdt.property_string("method", "hvc");
            fdt.end_node();
        }
    }
    if fixed_cpus {
        fdt.begin_node("cpus");
        fdt.property_u32("#address-cells", 1);
        fdt.property_u32("#size-cells", 0);
        fdt.begin_node("cpu@0");
        fdt.property_string("device_type", "cpu");
        fdt.property_u32("reg", 0);
        fdt.end_node();
        fdt.end_node();
    }
    if fixed_memory {
        fdt.begin_node("memory@0");
        fdt.property_string("device_type", "memory");
        fdt.property_reg_2cells("reg", 0, 4 << 20);
        fdt.end_node();
    }
    fdt.end_node();
    fdt.finish()
}

// A small native PMI fixture, with no kernel download or hypervisor required.
// The dummy load backs one 2 MiB page; the base and overlay occupy the next.
// Keep a .dtbo reservation even without its fill to prove the action is required.
fn image(
    arch: HostArchitecture,
    channel: BaseChannel,
    base: &[u8],
    overlay: Option<u32>,
) -> Vec<u8> {
    let mut actions = vec![json!({"type": "load", "section": ".code", "gpa": 0})];
    actions.push(match channel {
        BaseChannel::Bundled => json!({"type": "load", "section": ".base", "gpa": 0x20_0000}),
        _ => json!({"type": "fill", "section": ".dtb", "gpa": 0x20_0000, "kind": "dt:dtb"}),
    });
    if overlay.is_some() {
        actions
            .push(json!({"type": "fill", "section": ".dtbo", "gpa": 0x20_1000, "kind": "dt:dtbo"}));
    }
    let (machine, profile) = match arch {
        HostArchitecture::X86_64 => (0x8664u16, "x86-64-v1"),
        HostArchitecture::Aarch64 => (0xaa64, "armv8.0-a"),
    };
    let mut manifest = json!({"version": 1, "actions": actions, "cpu:profile": profile});
    if !matches!(channel, BaseChannel::Detached) {
        manifest["dt:dtb"] = json!(".base");
    }
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&manifest, &mut cbor).unwrap();

    let mut bytes = vec![0; 0x20_1000];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&5u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[0xb8..0xbc].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    bytes[0xbc..0xc0].copy_from_slice(&0x1000u32.to_le_bytes()); // FileAlignment
    for (i, (name, size, offset, raw_size, flags)) in [
        (".pmi.vm", 0x1000, 0x1000, cbor.len() as u32, 0x0200_0040u32),
        (".base", 0x1000, 0x2000, base.len() as u32, 0x40),
        (".code", 0x20_0000, 0x20_0000, 0x1000, 0x40),
        (".dtb", 0x1000, 0, 0, 0x80),
        (".dtbo", overlay.unwrap_or(0x1000), 0, 0, 0x80),
    ]
    .into_iter()
    .enumerate()
    {
        let header = 0x188 + i * 40;
        bytes[header..header + name.len()].copy_from_slice(name.as_bytes());
        for (field, value) in [(8, size), (16, raw_size), (20, offset), (36, flags)] {
            bytes[header + field..header + field + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    bytes[0x1000..0x1000 + cbor.len()].copy_from_slice(&cbor);
    bytes[0x2000..0x2000 + base.len()].copy_from_slice(base);
    bytes
}

fn edit_manifest(bytes: &mut [u8], edit: impl FnOnce(&mut serde_json::Value)) {
    let mut manifest = ciborium::from_reader(&bytes[0x1000..0x2000]).unwrap();
    edit(&mut manifest);
    let mut encoded = Vec::new();
    ciborium::into_writer(&manifest, &mut encoded).unwrap();
    bytes[0x1000..0x2000].fill(0);
    bytes[0x1000..0x1000 + encoded.len()].copy_from_slice(&encoded);
    bytes[0x190..0x194].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    bytes[0x198..0x19c].copy_from_slice(&0x1000u32.to_le_bytes());
}

fn launch(
    arch: HostArchitecture,
    channel: BaseChannel,
    base: &[u8],
    overlay: Option<u32>,
    vcpus: u32,
) -> Result<(tempfile::TempDir, LaunchPlan), LaunchError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.pmi");
    std::fs::write(&path, image(arch, channel, base, overlay)).unwrap();
    let dtb_path = dir.path().join("base.dtb");
    std::fs::write(&dtb_path, base).unwrap();
    LaunchPlan::read(
        &path,
        arch,
        None,
        || Ok(48),
        4,
        vcpus,
        matches!(channel, BaseChannel::Detached).then_some(dtb_path.as_path()),
        None,
    )
    .map(|plan| (dir, plan))
}

#[test]
fn replay_uses_direct_slices_from_the_held_pmi() {
    let arch = HostArchitecture::X86_64;
    let (dir, plan) = launch(
        arch,
        BaseChannel::Bundled,
        &base(arch, false, false),
        Some(4096),
        1,
    )
    .unwrap();
    let check_section = |bytes: &[u8]| {
        let expected = &bytes[0x20_0000..0x20_1000];
        let mut data_writes = 0;
        plan.guest_writes[0]
            .apply(bytes, |gpa, data| {
                if gpa < 0x1000 {
                    assert_eq!(gpa, 0);
                    assert!(std::ptr::eq(data, expected));
                    data_writes += 1;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(data_writes, 1);
    };

    check_section(plan.pmi.bytes());
    let file = plan.pmi.release();

    // Renaming the stable image must keep replay tied to the opened file.
    let path = dir.path().join("image.pmi");
    std::fs::rename(&path, dir.path().join("original.pmi")).unwrap();
    std::fs::write(&path, b"replacement pathname").unwrap();
    let replay = file.map().unwrap();
    assert_eq!(&replay[..2], b"MZ");
    check_section(&replay);
}

#[test]
fn optional_base_fill_uses_the_selected_source() {
    let arch = HostArchitecture::X86_64;
    let bundled = base(arch, false, false);
    let dir = tempfile::tempdir().unwrap();
    let image_path = dir.path().join("image.pmi");
    let mut bytes = image(arch, BaseChannel::Optional, &bundled, Some(4096));
    edit_manifest(&mut bytes, |manifest| {
        manifest["actions"].as_array_mut().unwrap().push(json!({
            "type": "fill", "section": ".dtb", "gpa": 0x20_2000, "kind": "dt:dtb"
        }));
    });
    std::fs::write(&image_path, bytes).unwrap();
    let fallback = LaunchPlan::read(&image_path, arch, None, || Ok(48), 4, 1, None, None).unwrap();
    let fallback_bytes = &fallback.pmi.bytes()[0x2000..0x2000 + bundled.len()];
    fallback.guest_writes[1]
        .apply(fallback.pmi.bytes(), |gpa, data| {
            assert_eq!(gpa, 0x20_0000);
            assert!(std::ptr::eq(data, fallback_bytes));
            Ok(())
        })
        .unwrap();

    let override_path = dir.path().join("override.dtb");
    let mut external = bundled;
    external.push(0);
    std::fs::write(&override_path, &external).unwrap();
    let overridden = LaunchPlan::read(
        &image_path,
        arch,
        None,
        || Ok(48),
        4,
        1,
        Some(&override_path),
        None,
    )
    .unwrap();
    let surveyed = overridden.platform.dtb();
    assert_eq!(surveyed, external);
    for (index, expected_gpa) in [(1, 0x20_0000), (3, 0x20_2000)] {
        overridden.guest_writes[index]
            .apply(overridden.pmi.bytes(), |gpa, data| {
                assert_eq!(gpa, expected_gpa);
                assert!(std::ptr::eq(data, surveyed));
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn bundled_base_fill_checks_the_mapped_section_size() {
    let arch = HostArchitecture::X86_64;
    let mut base = base(arch, false, false);
    base.resize(0x1100, 0xee);
    let mut bytes = image(arch, BaseChannel::Optional, &base, Some(4096));
    let base_virtual_size = 0x188 + 40 + 8;
    bytes[base_virtual_size..base_virtual_size + 4].copy_from_slice(&0x1100u32.to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.pmi");
    std::fs::write(&path, bytes).unwrap();
    let result = LaunchPlan::read(&path, arch, None, || Ok(48), 4, 1, None, None);
    assert!(matches!(
        result,
        Err(LaunchError::BaseDtbTooLarge {
            actual: 0x1100,
            cap: 0x1000,
        })
    ));
}

#[test]
fn coff_section_name_obeys_the_length_cap() {
    use dillo_launch::pmi_parse::{Error, caps::MAX_SECTION_NAME_LEN, parse};

    let arch = HostArchitecture::X86_64;
    let mut bytes = image(
        arch,
        BaseChannel::Bundled,
        &base(arch, false, false),
        Some(4096),
    );
    let table = bytes.len();
    bytes[0x8c..0x90].copy_from_slice(&(table as u32).to_le_bytes());
    // The unused .dtb section refers to the first COFF string at offset 4.
    let section = 0x188 + 3 * 40;
    bytes[section..section + 8].copy_from_slice(b"/4\0\0\0\0\0\0");
    let opts = ParseOptions {
        host_arch: pmi_arch(arch),
        memory_mib: 4,
    };
    for len in [MAX_SECTION_NAME_LEN, MAX_SECTION_NAME_LEN + 1] {
        bytes.truncate(table);
        bytes.extend_from_slice(&((4 + len + 1) as u32).to_le_bytes());
        bytes.resize(table + 4 + len, b'x');
        bytes.push(0);
        let result = parse(&bytes, &opts);
        if len == MAX_SECTION_NAME_LEN {
            result.expect("section name at cap");
        } else {
            assert!(matches!(
                result,
                Err(Error::SectionNameTooLong { len: actual, cap })
                    if actual == len && cap == MAX_SECTION_NAME_LEN
            ));
        }
    }
}

#[test]
fn oversized_manifest_is_refused_before_decode() {
    use dillo_launch::pmi_parse::{Error, caps::MAX_MANIFEST_SIZE, parse};

    let arch = HostArchitecture::X86_64;
    let mut bytes = image(arch, BaseChannel::Bundled, &base(arch, false, false), None);
    let size = (MAX_MANIFEST_SIZE + 1) as u32;
    for range in [0x190..0x194, 0x198..0x19c] {
        bytes[range].copy_from_slice(&size.to_le_bytes());
    }
    bytes[0x1000] = 0xff;
    let opts = ParseOptions {
        host_arch: pmi_arch(arch),
        memory_mib: 4,
    };
    assert!(matches!(
        parse(&bytes, &opts),
        Err(Error::ManifestTooLarge { actual, cap, .. })
            if actual == size as usize && cap == MAX_MANIFEST_SIZE
    ));
}

#[test]
fn section_loads_clear_zero_pages_and_padded_tails() {
    let arch = HostArchitecture::X86_64;
    let mut bytes = image(
        arch,
        BaseChannel::Bundled,
        &base(arch, false, false),
        Some(4096),
    );
    let mut manifest: serde_json::Value = ciborium::from_reader(&bytes[0x1000..0x2000]).unwrap();
    manifest["actions"].as_array_mut().unwrap().push(json!({
        "type": "load", "section": ".dtb", "gpa": 0x20_2000
    }));
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&manifest, &mut cbor).unwrap();
    bytes[0x1000..0x1000 + cbor.len()].copy_from_slice(&cbor);
    bytes[0x198..0x19c].copy_from_slice(&(cbor.len() as u32).to_le_bytes());
    let code_virtual_size = 0x188 + 2 * 40 + 8;
    bytes[code_virtual_size..code_virtual_size + 4].copy_from_slice(&0x1f_ffffu32.to_le_bytes());
    let zero_file_offset = 0x188 + 3 * 40 + 20;
    bytes[zero_file_offset..zero_file_offset + 4].copy_from_slice(&0x40_0000u32.to_le_bytes());
    bytes[0x20_0000..0x20_1000].fill(0x66);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.pmi");
    std::fs::write(&path, bytes).unwrap();
    let plan = LaunchPlan::read(&path, arch, None, || Ok(48), 4, 1, None, None).unwrap();
    let mut ram = vec![0xcc; 0x20_4000];
    for write in &plan.guest_writes {
        write
            .apply(plan.pmi.bytes(), |gpa, data| {
                let gpa = gpa as usize;
                ram[gpa..gpa + data.len()].copy_from_slice(data);
                Ok(())
            })
            .unwrap();
    }
    let error = plan.guest_writes[0]
        .apply(&[], |_, _| {
            panic!("source bounds must be checked before writing")
        })
        .unwrap_err();
    assert!(error.to_string().contains("out of PMI bounds"));
    assert!(ram[..0x1000].iter().all(|&byte| byte == 0x66));
    assert!(ram[0x1000..0x20_0000].iter().all(|&byte| byte == 0));
    assert!(ram[0x20_2000..0x20_3000].iter().all(|&byte| byte == 0));
    assert_eq!(ram[0x20_3000], 0xcc);
}

#[test]
fn repeated_actions_write_in_manifest_order() {
    let recipe = [
        (".code", 0x40_0000, None, 0x1f_ffff),
        (".dtbo", 0x80_1000, Some("dt:dtbo"), 0x1000),
        (".base", 0x20_1000, None, 0x1000),
        (".dtb", 0x80_2000, Some("dt:dtb"), 0x1000),
        (".dtb", 0x80_3000, None, 0x1000),
        (".code", 0, None, 0x1f_ffff),
        (".base", 0x20_3000, None, 0x1000),
        (".dtbo", 0x80_5000, Some("dt:dtbo"), 0x1000),
        (".dtb", 0x80_6000, Some("dt:dtb"), 0x1000),
        (".dtb", 0x80_7000, None, 0x1000),
    ];
    for arch in ARCHES {
        let mut base = base(arch, false, false);
        let fdt_size = base.len();
        base.resize(0x1000, 0xee);
        let mut bytes = image(arch, BaseChannel::Optional, &base, Some(4096));
        edit_manifest(&mut bytes, |manifest| {
            manifest["actions"] = json!(recipe.map(|(section, gpa, fill, _)| match fill {
                Some(kind) => json!({"type": "fill", "section": section, "gpa": gpa, "kind": kind}),
                None => json!({"type": "load", "section": section, "gpa": gpa}),
            }));
        });
        // Give the PE a compact layout with addresses distinct from the actions.
        bytes[0xb0..0xb8].copy_from_slice(&0x1000_0000u64.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x20_5000u32.to_le_bytes()); // SizeOfImage
        bytes[0xd4..0xd8].copy_from_slice(&0x1000u32.to_le_bytes()); // SizeOfHeaders
        for (i, rva) in [0x1000u32, 0x2000, 0x3000, 0x20_3000, 0x20_4000]
            .into_iter()
            .enumerate()
        {
            let field = 0x188 + i * 40 + 12;
            bytes[field..field + 4].copy_from_slice(&rva.to_le_bytes());
        }
        let code_virtual_size = 0x188 + 2 * 40 + 8;
        bytes[code_virtual_size..code_virtual_size + 4]
            .copy_from_slice(&0x1f_ffffu32.to_le_bytes());
        bytes[0x20_0000..0x20_1000].fill(0x66);
        bytes.resize(0x20_2000, 0xee); // Poison bytes after .code's raw data.

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.pmi");
        std::fs::write(&path, bytes).unwrap();
        let plan = LaunchPlan::read(&path, arch, None, || Ok(48), 8, 1, None, None).unwrap();
        assert_eq!(plan.platform.dtb(), &base[..fdt_size]);
        let ranges: Vec<_> = plan
            .memory
            .ranges()
            .iter()
            .map(|r| (r.gpa, r.size))
            .collect();
        assert_eq!(ranges, [(0, 0x60_0000), (0x80_0000, 0x20_0000)]);
        let parsed = dillo_launch::pmi_parse::parse(
            plan.pmi.bytes(),
            &ParseOptions {
                host_arch: pmi_arch(arch),
                memory_mib: 8,
            },
        )
        .unwrap();
        assert_eq!(parsed.actions.len(), recipe.len());
        assert_eq!(plan.guest_writes.len(), recipe.len());
        let mut ram = vec![0xcc; 0x80_9000];
        for ((section, gpa, _, size), (action, write)) in recipe
            .into_iter()
            .zip(parsed.actions.iter().zip(&plan.guest_writes))
        {
            assert_eq!(
                (&*action.section, action.gpa, action.source.virtual_size),
                (section, gpa, size)
            );
            let mut first = None;
            write
                .apply(plan.pmi.bytes(), |addr, data| {
                    first.get_or_insert(addr);
                    let start = addr as usize;
                    ram[start..start + data.len()].copy_from_slice(data);
                    Ok(())
                })
                .unwrap();
            assert_eq!(first, Some(gpa));
        }
        for start in [0x20_1000, 0x20_3000, 0x80_2000, 0x80_6000] {
            assert_eq!(&ram[start..start + 0x1000], base);
        }
        for start in [0, 0x40_0000] {
            assert!(ram[start..start + 0x1000].iter().all(|&b| b == 0x66));
            let padding = &ram[start + 0x1000..start + 0x20_0000];
            assert!(padding.iter().all(|&b| b == 0));
        }
        for start in [0x80_3000, 0x80_7000] {
            assert!(ram[start..start + 0x1000].iter().all(|&b| b == 0));
        }
        let overlay = &ram[0x80_1000..0x80_2000];
        assert_eq!(overlay, &ram[0x80_5000..0x80_6000]);
        let [first, second] = [1, 7].map(|index| &plan.guest_writes[index].data);
        let (WriteSrc::Shared(first), WriteSrc::Shared(second)) = (first, second) else {
            panic!("overlays must share their synthesized payload")
        };
        assert!(Arc::ptr_eq(first, second));
        let tree: Tree<'_> = Tree::parse(overlay).unwrap();
        tree.find_path("/fragment@1/__overlay__/memory@800000")
            .expect("overlay describes the high RAM island");
        for neighbor in [
            0x20_0000, 0x20_2000, 0x20_4000, 0x60_0000, 0x80_0fff, 0x80_4000, 0x80_8000,
        ] {
            assert_eq!(ram[neighbor], 0xcc, "{arch:?} {neighbor:#x}");
        }
    }
}

#[test]
fn repeated_actions_use_guest_capacity_not_platform_minimum() {
    let high = 1u64 << 40;
    for arch in ARCHES {
        let mut base = base(arch, false, false);
        base.resize(0x1000, 0);
        let image = image(arch, BaseChannel::Bundled, &base, Some(0x1000));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("high.pmi");
        let launch = |bits| LaunchPlan::read(&path, arch, None, || Ok(bits), 6, 1, None, None);
        for (index, section) in [(0, ".code"), (2, ".dtbo")] {
            let mut bytes = image.clone();
            repeat_action(&mut bytes, index, high);
            std::fs::write(&path, bytes).unwrap();
            let plan = launch(48).unwrap();
            assert!(plan.memory.ranges().iter().any(|r| r.gpa == high));
            assert!(matches!(
                launch(40),
                Err(LaunchError::DtbCrossValidate(SurveyError::LoadAddressOverflow {
                    section: name, start, ..
                })) if name == section && start == high
            ));
        }
        assert!(matches!(launch(24), Err(LaunchError::AddressSpace { .. })));
    }
}

fn repeat_action(bytes: &mut [u8], index: usize, gpa: u64) {
    edit_manifest(bytes, |manifest| {
        let actions = manifest["actions"].as_array_mut().unwrap();
        let mut action = actions[index].clone();
        action["gpa"] = json!(gpa);
        actions.insert(index, action);
    });
}

#[test]
fn repeated_actions_validate_each_destination() {
    use dillo_launch::pmi_parse::{Error, parse};

    let arch = HostArchitecture::X86_64;
    let mut base = base(arch, false, false);
    base.resize(0x1000, 0);
    let image = image(arch, BaseChannel::Bundled, &base, Some(0x2000));
    let opts = ParseOptions {
        host_arch: pmi_arch(arch),
        memory_mib: 6,
    };
    let invalid = |index, gpa| {
        let mut bytes = image.clone();
        repeat_action(&mut bytes, index, gpa);
        parse(&bytes, &opts).unwrap_err()
    };
    for (index, gpa, section, granularity) in [
        (0, 0x40_1000, ".code", "2 MiB"),
        (2, 0x40_0001, ".dtbo", "4 KiB"),
    ] {
        let error = invalid(index, gpa);
        assert!(
            matches!(&error, Error::AlignmentViolation { name, rule, .. }
                if name == section && rule.contains(granularity)),
            "{error}"
        );
    }
    for gpa in [u64::MAX - 0x1fff, u64::MAX - 0x2fff] {
        let error = invalid(2, gpa);
        assert!(
            matches!(&error, Error::VirtualAddressOverflow { name } if name == ".dtbo"),
            "{error}"
        );
    }
    for (gpa, section) in [(0x20_0000, ".base"), (0x20_2000, ".dtbo")] {
        let error = invalid(2, gpa);
        assert!(
            matches!(&error, Error::SectionsOverlap { a, b } if a == section && b == ".dtbo"),
            "{error}"
        );
    }
}

#[test]
fn invalid_image_does_not_require_a_hypervisor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.pmi");
    std::fs::write(&path, b"not a PMI").unwrap();
    let error = LaunchPlan::read(
        &path,
        HostArchitecture::X86_64,
        None,
        || panic!("invalid input must be rejected before probing the backend"),
        4,
        1,
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(error, LaunchError::PmiParse(_)));
}

#[test]
fn load_validation_checks_raw_size_and_backing_end() {
    use dillo_launch::pmi_parse::{Error, parse};
    let arch = HostArchitecture::X86_64;
    let mut bytes = image(
        arch,
        BaseChannel::Bundled,
        &base(arch, false, false),
        Some(4096),
    );
    let opts = ParseOptions {
        host_arch: pmi_arch(arch),
        memory_mib: 4,
    };
    let code_virtual_size = 0x188 + 2 * 40 + 8;
    bytes[code_virtual_size..code_virtual_size + 4].copy_from_slice(&0xfffu32.to_le_bytes());
    assert!(
        matches!(parse(&bytes, &opts), Err(Error::InvalidLoadSize(section)) if section == ".code")
    );

    bytes[code_virtual_size..code_virtual_size + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    let mut manifest: serde_json::Value = ciborium::from_reader(&bytes[0x1000..0x2000]).unwrap();
    manifest["actions"][0]["gpa"] = json!(u64::MAX - 0x1fff);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&manifest, &mut cbor).unwrap();
    bytes[0x1000..0x1000 + cbor.len()].copy_from_slice(&cbor);
    bytes[0x198..0x19c].copy_from_slice(&(cbor.len() as u32).to_le_bytes());
    assert!(
        matches!(parse(&bytes, &opts), Err(Error::VirtualAddressOverflow { name }) if name == ".code")
    );
}

#[test]
fn zero_load_requires_positive_size_and_aligned_pointer() {
    use dillo_launch::pmi_parse::{Error, parse};
    let arch = HostArchitecture::X86_64;
    let mut bytes = image(
        arch,
        BaseChannel::Bundled,
        &base(arch, false, false),
        Some(4096),
    );
    let opts = ParseOptions {
        host_arch: pmi_arch(arch),
        memory_mib: 4,
    };
    let code_header = 0x188 + 2 * 40;
    bytes[code_header + 16..code_header + 20].fill(0);
    bytes[code_header + 8..code_header + 12].fill(0);
    assert!(
        matches!(parse(&bytes, &opts), Err(Error::InvalidLoadSize(section)) if section == ".code")
    );
    for size in [0x10_0000u32, 0x20_0000] {
        bytes[code_header + 8..code_header + 12].copy_from_slice(&size.to_le_bytes());
        bytes[code_header + 20..code_header + 24].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            matches!(parse(&bytes, &opts), Err(Error::AlignmentViolation { name, .. }) if name == ".code")
        );
        bytes[code_header + 20..code_header + 24].fill(0);
        parse(&bytes, &opts).expect("aligned Zero load");
    }
}

// Use a non-arma section name and a 4 KiB capacity. Action GPAs remain the
// authority even though the PE section's VirtualAddress is deliberately zero.
fn with_bootconfig(mut bytes: Vec<u8>, gpas: &[u64], capacity: u32, raw_size: u32) -> Vec<u8> {
    let mut manifest: serde_json::Value = ciborium::from_reader(&bytes[0x1000..0x2000]).unwrap();
    for gpa in gpas {
        manifest["actions"].as_array_mut().unwrap().push(json!({
            "type": "fill", "section": ".config", "gpa": gpa, "kind": "lbc:bootconfig"
        }));
    }
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&manifest, &mut cbor).unwrap();
    bytes[0x1000..0x2000].fill(0);
    bytes[0x1000..0x1000 + cbor.len()].copy_from_slice(&cbor);
    bytes[0x188 + 16..0x188 + 20].copy_from_slice(&(cbor.len() as u32).to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&6u16.to_le_bytes());
    let header = 0x188 + 5 * 40;
    bytes[header..header + 7].copy_from_slice(b".config");
    for (field, value) in [
        (8, capacity),
        (16, raw_size),
        (20, if raw_size == 0 { 0 } else { 0x2000 }),
        (36, 0x80),
    ] {
        bytes[header + field..header + field + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn bootconfig_launch_uses_declared_reservation_and_snapshots_input() {
    const GPA: u64 = 0x40_0000;
    const CAPACITY: usize = 0x20_0004;
    const ALIGNED_SIZE: usize = 0x20_1000;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.pmi");
    let input = dir.path().join("input.bconf");
    for arch in ARCHES {
        let base = base(arch, false, false);
        let bytes = with_bootconfig(
            image(arch, BaseChannel::Bundled, &base, Some(4096)),
            &[GPA],
            CAPACITY as u32,
            0,
        );
        std::fs::write(&path, &bytes).unwrap();
        for text in [None, Some(b"".as_slice()), Some(b"carapace.tip = abc;")] {
            let file = text.map(|text| {
                std::fs::write(&input, text).unwrap();
                input.as_path()
            });
            let plan = LaunchPlan::read(&path, arch, None, || Ok(48), 8, 1, None, file).unwrap();
            let write = plan.guest_writes.last().unwrap();
            assert_eq!(write.section, ".config");
            assert_eq!(write.gpa, GPA);
            let WriteSrc::Owned(data) = &write.data else {
                panic!("bootconfig must be retained for reboot")
            };
            assert!(data.capacity() < 4096);
            let text = text.unwrap_or_default();
            if text.is_empty() {
                assert!(data.is_empty());
            } else {
                assert_eq!(data.len(), ((text.len() + 4) & !3) + 20);
                assert!(data.starts_with(text));
                assert!(data.ends_with(b"#BOOTCONFIG\n"));
            }
            let apply = |ram: &mut [u8]| {
                write
                    .apply(plan.pmi.bytes(), |gpa, bytes| {
                        let start = (gpa - GPA) as usize + 1;
                        ram[start..start + bytes.len()].copy_from_slice(bytes);
                        Ok(())
                    })
                    .unwrap();
            };
            let mut ram = vec![0xcc; ALIGNED_SIZE + 2];
            apply(&mut ram);
            let reservation = &ram[1..=CAPACITY];
            let payload_start = CAPACITY - data.len();
            assert!(reservation[..payload_start].iter().all(|&b| b == 0));
            assert_eq!(&reservation[payload_start..], data);
            assert!(ram[1 + CAPACITY..=ALIGNED_SIZE].iter().all(|&b| b == 0));
            assert_eq!((ram[0], ram[ALIGNED_SIZE + 1]), (0xcc, 0xcc));
            std::fs::write(&input, b"changed after preflight").unwrap();
            std::fs::remove_file(&input).unwrap();
            let mut replay = vec![0xcc; ALIGNED_SIZE + 2];
            apply(&mut replay);
            assert_eq!(replay, ram);
            assert_eq!(plan.platform.dtb(), base);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        std::fs::write(&path, image(arch, BaseChannel::Bundled, &base, Some(4096))).unwrap();
        std::fs::write(&input, b"").unwrap();
        let err =
            LaunchPlan::read(&path, arch, None, || Ok(48), 4, 1, None, Some(&input)).unwrap_err();
        assert!(matches!(
            err,
            LaunchError::Bootconfig(bootconfig::Error::Undeclared)
        ));
    }
}

#[test]
fn all_fill_kinds_require_nonempty_zero_sections() {
    use dillo_launch::pmi_parse::{Error, parse};

    let arch = HostArchitecture::X86_64;
    let image = with_bootconfig(
        image(
            arch,
            BaseChannel::Optional,
            &base(arch, false, false),
            Some(4096),
        ),
        &[0x20_2000],
        4096,
        0,
    );
    let opts = ParseOptions {
        host_arch: pmi_arch(arch),
        memory_mib: 4,
    };
    for (index, section) in [(3, ".dtb"), (4, ".dtbo"), (5, ".config")] {
        let mut bytes = image.clone();
        let header = 0x188 + index * 40;
        bytes[header + 36..header + 40].copy_from_slice(&0x0200_0080u32.to_le_bytes());
        parse(&bytes, &opts).expect("discardable Zero reservation");
        for (size, raw_size) in [(4096u32, 4096u32), (4096, 4), (0, 0), (0, 4)] {
            bytes[header + 8..header + 12].copy_from_slice(&size.to_le_bytes());
            bytes[header + 16..header + 20].copy_from_slice(&raw_size.to_le_bytes());
            bytes[header + 20..header + 24].copy_from_slice(&0x2000u32.to_le_bytes());
            let result = parse(&bytes, &opts);
            assert!(
                matches!(&result, Err(Error::InvalidFillShape(name)) if name == section),
                "{section} ({size}, {raw_size}): {result:?}"
            );
        }
    }
}

#[test]
fn bootconfig_invalid_reservations_fail_preflight() {
    use dillo_launch::pmi_parse::Error;
    for arch in ARCHES {
        let base = image(
            arch,
            BaseChannel::Bundled,
            &base(arch, false, false),
            Some(4096),
        );
        let opts = ParseOptions {
            host_arch: pmi_arch(arch),
            memory_mib: 4,
        };
        let bytes = with_bootconfig(base.clone(), &[0x20_2000, 0x20_3000], 4096, 0);
        assert!(matches!(
            dillo_launch::pmi_parse::parse(&bytes, &opts),
            Err(Error::BootconfigFill("duplicate fill"))
        ));
        let bytes = with_bootconfig(base.clone(), &[0x20_2001], 4096, 0);
        assert!(matches!(
            dillo_launch::pmi_parse::parse(&bytes, &opts),
            Err(Error::AlignmentViolation { .. })
        ));
        let bytes = with_bootconfig(base.clone(), &[0x20_1000], 4096, 0);
        assert!(matches!(
            dillo_launch::pmi_parse::parse(&bytes, &opts),
            Err(Error::SectionsOverlap { .. })
        ));
        let bytes = with_bootconfig(base, &[0x40_0000], 4 * 1024 * 1024, 0);
        assert!(
            dillo_launch::pmi_parse::parse(&bytes, &opts).is_err(),
            "reservation exceeds guest memory budget"
        );
    }
}

#[test]
fn delegated_cpus_and_memory_require_overlay_fill() {
    for arch in ARCHES {
        for channel in CHANNELS {
            let err = launch(arch, channel, &base(arch, false, false), None, 2).unwrap_err();
            assert!(
                matches!(err, LaunchError::DelegatedAllocationRequiresDtbo),
                "{arch:?} {channel:?}: {err}"
            );
            assert_eq!(err.exit_code(), 11);
        }
    }
}

#[test]
fn delegated_allocation_is_delivered_in_reserved_overlay() {
    for arch in ARCHES {
        for channel in CHANNELS {
            for size in [0x1000, 0x1_0000] {
                let (_dir, plan) =
                    launch(arch, channel, &base(arch, false, false), Some(size), 2).unwrap();
                let write = plan
                    .guest_writes
                    .iter()
                    .find(|write| write.section == ".dtbo")
                    .unwrap();
                assert_eq!(write.gpa, 0x20_1000);
                let WriteSrc::Shared(data) = &write.data else {
                    panic!("overlay must be synthesized")
                };
                assert!(data.len() <= size as usize);
                let tree: Tree<'_> = Tree::parse(data).unwrap();
                let cpus = tree.find_path("/fragment@0/__overlay__/cpus").unwrap();
                assert_eq!(cpus.children().count(), 2);
                let memory = tree.find_path("/fragment@1/__overlay__").unwrap();
                let delivered: Vec<_> = memory
                    .children()
                    .map(|node| node.property("reg").unwrap().reg_pair(0).unwrap())
                    .collect();
                let planned: Vec<_> = plan
                    .memory
                    .ranges()
                    .iter()
                    .map(|region| (region.gpa, region.size))
                    .collect();
                assert_eq!(delivered, planned);
                assert_eq!(planned.iter().map(|(_, size)| size).sum::<u64>(), 4 << 20);
            }
        }
    }
}

#[test]
fn fixed_resource_declarations_are_still_refused() {
    for arch in ARCHES {
        // Missing CPUs with fixed memory, and missing memory with fixed CPUs:
        // these unsupported fixed layouts must never become implicit CLI allocations.
        for (cpus, memory) in [(false, true), (true, false), (true, true)] {
            for overlay in [None, Some(0x1000)] {
                let err = launch(
                    arch,
                    BaseChannel::Bundled,
                    &base(arch, cpus, memory),
                    overlay,
                    2,
                )
                .unwrap_err();
                if cpus {
                    assert!(
                        matches!(err, LaunchError::Coverage(SurveyError::BaseHasCpus)),
                        "{err}"
                    );
                } else {
                    assert!(
                        matches!(err, LaunchError::Coverage(SurveyError::Uncovered(_))),
                        "{err}"
                    );
                }
            }
        }
    }
}

#[test]
fn overlay_reservation_bounds_are_enforced() {
    for size in [0xfff, 0x1_0001] {
        let err = launch(
            HostArchitecture::X86_64,
            BaseChannel::Bundled,
            &base(HostArchitecture::X86_64, false, false),
            Some(size),
            2,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                LaunchError::PmiParse(dillo_launch::pmi_parse::Error::DtboSizeOutOfRange { .. })
            ),
            "{err}"
        );
    }
    let err = launch(
        HostArchitecture::X86_64,
        BaseChannel::Bundled,
        &base(HostArchitecture::X86_64, false, false),
        Some(0x1000),
        128,
    )
    .unwrap_err();
    assert!(matches!(err, LaunchError::DtboSynth(_)), "{err}");
    assert_eq!(err.exit_code(), 11);
}

#[test]
fn repeated_overlay_checks_the_later_reservation() {
    let arch = HostArchitecture::X86_64;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.pmi");
    let mut bytes = image(
        arch,
        BaseChannel::Bundled,
        &base(arch, false, false),
        Some(0x1_0000),
    );
    std::fs::write(&path, &bytes).unwrap();
    let read = || LaunchPlan::read(&path, arch, None, || Ok(48), 4, 128, None, None);
    read().expect("the first overlay reservation fits");

    edit_manifest(&mut bytes, |manifest| {
        manifest["actions"].as_array_mut().unwrap().push(json!({
            "type": "fill", "section": ".dtb", "gpa": 0x21_1000, "kind": "dt:dtbo"
        }));
    });
    std::fs::write(&path, bytes).unwrap();
    let err = read().unwrap_err();
    assert!(matches!(err, LaunchError::DtboSynth(_)), "{err}");
    assert!(err.to_string().contains("section size (4096 bytes)"));
}

#[test]
fn machine_constructor_refuses_unadmitted_ram() {
    use crate::machine_select::machine::Vm;
    use dillo_machine::{Host, LaunchConfig, Machine, RamRange};

    let arch = match <Vm as Host>::ARCH {
        HostArchitecture::X86_64 => Arch::X86_64,
        HostArchitecture::Aarch64 => Arch::Aarch64,
    };
    let platform = PlatformMachine::survey(base(<Vm as Host>::ARCH, false, false), arch)
        .expect("survey fixture platform");
    let (gpa, size) = platform
        .placement_regions()
        .next()
        .expect("declared region");
    let error = Vm::from_launch_config(LaunchConfig {
        platform: &platform,
        vcpus: 1,
        ram: vec![RamRange { gpa, size }],
    })
    .expect_err("overlap must fail before native setup");
    assert!(
        error.to_string().contains("overlaps a declared region"),
        "{error}"
    );

    let available = Vm::guest_address_bits().expect("native guest address capacity");
    let error = Vm::from_launch_config(LaunchConfig {
        platform: &platform,
        vcpus: 1,
        ram: vec![RamRange {
            gpa: 1 << available,
            size: 2 << 20,
        }],
    })
    .expect_err("over-width RAM must fail before allocation");
    assert!(error.to_string().contains("address"), "{error}");
}
