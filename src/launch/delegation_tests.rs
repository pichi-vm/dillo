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
    let (machine, profile, vcpu) = match arch {
        HostArchitecture::X86_64 => (0x8664u16, "x86-64-v1", json!({})),
        HostArchitecture::Aarch64 => (0xaa64, "armv8.0-a", json!({"pstate": 5})),
    };
    let mut manifest =
        json!({"version": 1, "actions": actions, "vm:vcpu": vcpu, "cpu:profile": profile});
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
        4,
        vcpus,
        matches!(channel, BaseChannel::Detached).then_some(dtb_path.as_path()),
        None,
    )
    .map(|plan| (dir, plan))
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.pmi");
    let input = dir.path().join("input.bconf");
    for arch in ARCHES {
        let base = base(arch, false, false);
        let bytes = with_bootconfig(
            image(arch, BaseChannel::Bundled, &base, Some(4096)),
            &[0x20_2000],
            4096,
            0,
        );
        std::fs::write(&path, &bytes).unwrap();
        for text in [None, Some(b"".as_slice()), Some(b"carapace.tip = abc;")] {
            let file = text.map(|text| {
                std::fs::write(&input, text).unwrap();
                input.as_path()
            });
            let plan = LaunchPlan::read(&path, arch, None, 4, 1, None, file).unwrap();
            let write = plan.guest_writes.last().unwrap();
            assert_eq!(write.section, ".config");
            assert_eq!(write.gpa, 0x20_2000);
            let WriteSrc::Owned(data) = &write.data else {
                panic!("bootconfig must be retained for reboot")
            };
            assert_eq!(data.len(), 4096);
            if text.is_none_or(<[u8]>::is_empty) {
                assert!(data.iter().all(|b| *b == 0));
            } else {
                assert!(
                    data.windows(text.unwrap().len())
                        .any(|window| Some(window) == text)
                );
                assert!(data.ends_with(b"#BOOTCONFIG\n"));
            }
            let snapshot = data.clone();
            std::fs::write(&input, b"changed after preflight").unwrap();
            std::fs::remove_file(&input).unwrap();
            assert_eq!(
                data, &snapshot,
                "reboot uses owned launch bytes, not the file"
            );
            assert_eq!(plan.merged_dtb, base);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        std::fs::write(&path, image(arch, BaseChannel::Bundled, &base, Some(4096))).unwrap();
        std::fs::write(&input, b"").unwrap();
        let err = LaunchPlan::read(&path, arch, None, 4, 1, None, Some(&input)).unwrap_err();
        assert!(matches!(
            err,
            LaunchError::Bootconfig(bootconfig::Error::Undeclared)
        ));
    }
}

#[test]
fn bootconfig_invalid_reservations_fail_preflight() {
    use dillo::pmi_parse::Error;
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
        for (gpas, capacity, raw_size) in [
            (vec![0x20_2000, 0x20_2000], 4096, 0),
            (vec![0x20_2000], 4096, 4),
            (vec![0x20_2000], 0, 0),
        ] {
            let bytes = with_bootconfig(base.clone(), &gpas, capacity, raw_size);
            assert!(matches!(
                dillo::pmi_parse::parse(&bytes, &opts),
                Err(Error::BootconfigFill(_))
            ));
        }
        let bytes = with_bootconfig(base.clone(), &[0x20_2001], 4096, 0);
        assert!(matches!(
            dillo::pmi_parse::parse(&bytes, &opts),
            Err(Error::AlignmentViolation { .. })
        ));
        let bytes = with_bootconfig(base.clone(), &[0x20_1000], 4096, 0);
        assert!(matches!(
            dillo::pmi_parse::parse(&bytes, &opts),
            Err(Error::SectionsOverlap { .. })
        ));
        let bytes = with_bootconfig(base, &[0x40_0000], 4 * 1024 * 1024, 0);
        assert!(
            dillo::pmi_parse::parse(&bytes, &opts).is_err(),
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
                let WriteSrc::Owned(data) = &write.data else {
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
                    .memory_nodes
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
                LaunchError::PmiParse(dillo::pmi_parse::Error::DtboSizeOutOfRange { .. })
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
