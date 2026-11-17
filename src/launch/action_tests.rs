// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::delegation_tests::{BaseChannel, base, image};
use super::*;
use dillo::pmi_parse::{self, Error as ParseError};
use dillo_machine::{Cpu, CpuProfile, CpuState, LaunchConfig, Machine, Memory, RamRange, VcpuStop};
use serde_json::json;

/// A current-schema PE with independent source sections and authored actions.
struct ActionImage {
    bytes: Vec<u8>,
    manifest: serde_json::Value,
    directory: tempfile::TempDir,
    arch: HostArchitecture,
}

impl ActionImage {
    fn new(arch: HostArchitecture) -> Self {
        let mut bytes = image(
            arch,
            BaseChannel::Bundled,
            &base(arch, false, false),
            Some(4096),
        );
        let manifest = ciborium::from_reader(&bytes[0x1000..0x2000]).unwrap();
        bytes[0xbc..0xc0].copy_from_slice(&512u32.to_le_bytes()); // PE FileAlignment
        let base_raw_size = u32::from_le_bytes(bytes[0x1c0..0x1c4].try_into().unwrap());
        bytes[0x1c0..0x1c4].copy_from_slice(&base_raw_size.next_multiple_of(512).to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&8u16.to_le_bytes());
        for (index, (name, size, offset, raw_size)) in [
            (".data", 512u32, 0x4000u32, 512u32),
            (".zero", 0x1001, u32::MAX, 0),
            (".padded", 0x1001, 0x5000, 512),
        ]
        .into_iter()
        .enumerate()
        {
            let header = 0x188 + (5 + index) * 40;
            bytes[header..header + name.len()].copy_from_slice(name.as_bytes());
            for (field, value) in [
                (8, size),
                (12, 0xffff_0000),
                (16, raw_size),
                (20, offset),
                (36, 0x40),
            ] {
                bytes[header + field..header + field + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes[0x4000..0x4200].fill(0x11);
        bytes[0x4000..0x4003].copy_from_slice(&[1, 2, 3]);
        bytes[0x4200..0x4203].fill(0xee); // Poison past SizeOfRawData must never be loaded.
        bytes[0x5000..0x5200].fill(0x44);
        bytes[0x5000..0x5003].copy_from_slice(&[4, 5, 6]);
        bytes[0x5200..0x5203].fill(0xee);
        Self {
            bytes,
            manifest,
            directory: tempfile::tempdir().unwrap(),
            arch,
        }
    }

    fn load(&mut self, section: &str, gpa: u64) {
        self.manifest["actions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"load", "section":section, "gpa":gpa}));
    }

    fn fill(&mut self, section: &str, gpa: u64, kind: &str) {
        self.manifest["actions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"fill", "section":section, "gpa":gpa, "kind":kind}));
    }

    fn bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::into_writer(&self.manifest, &mut encoded).unwrap();
        assert!(encoded.len() < 4096);
        let mut bytes = self.bytes.clone();
        bytes[0x1000..0x2000].fill(0);
        bytes[0x1000..0x1000 + encoded.len()].copy_from_slice(&encoded);
        bytes[0x198..0x19c]
            .copy_from_slice(&((encoded.len() as u32).next_multiple_of(512)).to_le_bytes());
        bytes
    }

    fn parse(&self) -> Result<pmi_parse::ParsedPmi, ParseError> {
        pmi_parse::parse(
            &self.bytes(),
            &ParseOptions {
                host_arch: pmi_arch(self.arch),
                memory_mib: 4,
            },
        )
    }

    fn plan(&self, bits: u32) -> Result<LaunchPlan, LaunchError> {
        let path = self.directory.path().join("image.pmi");
        std::fs::write(&path, self.bytes()).unwrap();
        LaunchPlan::read(&path, self.arch, None, || Ok(bits), 4, 1, None, None)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Operation {
    Write(u64, Vec<u8>),
    Zero(u64, u64),
}

/// The receiver owns real, deliberately dirty backing and records actual calls.
struct RecordingMachine {
    bytes: Vec<u8>,
    operations: Vec<Operation>,
    fail_at: Option<usize>,
}

impl RecordingMachine {
    fn dirty(byte: u8) -> Self {
        Self {
            bytes: vec![byte; 4 << 20],
            operations: Vec::new(),
            fail_at: None,
        }
    }

    fn admit(&self) -> std::io::Result<()> {
        if self.fail_at == Some(self.operations.len()) {
            return Err(std::io::Error::other("injected memory operation failure"));
        }
        Ok(())
    }
}

struct UnusedCpu;
struct UnusedCpuInput;
struct UnusedMemory;

impl Cpu for UnusedCpu {
    type Error = std::io::Error;
    fn run(&self) -> Result<VcpuStop, Self::Error> {
        panic!("recipe tests never execute CPUs")
    }
    fn stop(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
impl CpuState for UnusedCpuInput {
    type Error = std::io::Error;
    fn new(_: u32, _: CpuProfile) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}
impl Memory for UnusedMemory {
    type Error = std::io::Error;
    fn from_ranges(_: &[RamRange]) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}
impl Machine for RecordingMachine {
    type Error = std::io::Error;
    type Cpu = UnusedCpu;
    type CpuState = UnusedCpuInput;
    type Memory = UnusedMemory;
    fn guest_address_bits() -> Result<u32, Self::Error> {
        Ok(48)
    }
    fn from_launch_config(_: LaunchConfig) -> Result<Self, Self::Error> {
        Ok(Self::dirty(0xa5))
    }
    fn write_guest(&mut self, gpa: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.admit()?;
        self.bytes[gpa as usize..gpa as usize + bytes.len()].copy_from_slice(bytes);
        self.operations.push(Operation::Write(gpa, bytes.to_vec()));
        Ok(())
    }
    fn zero_guest(&mut self, gpa: u64, len: u64) -> Result<(), Self::Error> {
        self.admit()?;
        self.bytes[gpa as usize..gpa as usize + len as usize].fill(0);
        self.operations.push(Operation::Zero(gpa, len));
        Ok(())
    }
}

#[test]
fn repeated_sources_keep_order_full_contents_and_neighbor_bytes_on_fresh_machines() {
    for arch in [HostArchitecture::X86_64, HostArchitecture::Aarch64] {
        let mut image = ActionImage::new(arch);
        for (section, gpa) in [
            (".data", 0x30_4000),
            (".zero", 0x30_0000),
            (".padded", 0x30_2000),
            (".data", 0x30_8000),
            (".zero", 0x30_a000),
            (".padded", 0x30_c000),
        ] {
            image.load(section, gpa);
        }
        let plan = image.plan(48).unwrap();
        assert_eq!(
            plan.parsed
                .actions
                .iter()
                .skip(3)
                .map(pmi_parse::Action::gpa)
                .collect::<Vec<_>>(),
            [
                0x30_4000, 0x30_0000, 0x30_2000, 0x30_8000, 0x30_a000, 0x30_c000
            ]
        );
        assert!(
            plan.memory
                .memslots
                .iter()
                .any(|r| r.gpa <= 0x30_0000 && r.gpa + r.size >= 0x30_e000)
        );
        let mut data = vec![0x11; 512];
        data[..3].copy_from_slice(&[1, 2, 3]);
        let mut padded = vec![0x44; 512];
        padded[..3].copy_from_slice(&[4, 5, 6]);
        for dirty in [0xa5, 0x5a] {
            let mut machine = RecordingMachine::dirty(dirty);
            plan.recipe.apply(&mut machine, plan.pmi.bytes()).unwrap();
            let emitted: Vec<_> = machine
                .operations
                .into_iter()
                .filter(|op| match op {
                    Operation::Write(gpa, _) | Operation::Zero(gpa, _) => *gpa >= 0x30_0000,
                })
                .collect();
            assert_eq!(
                emitted,
                [
                    Operation::Write(0x30_4000, data.clone()),
                    Operation::Zero(0x30_4200, 3584),
                    Operation::Zero(0x30_0000, 8192),
                    Operation::Write(0x30_2000, padded.clone()),
                    Operation::Zero(0x30_2200, 7680),
                    Operation::Write(0x30_8000, data.clone()),
                    Operation::Zero(0x30_8200, 3584),
                    Operation::Zero(0x30_a000, 8192),
                    Operation::Write(0x30_c000, padded.clone()),
                    Operation::Zero(0x30_c200, 7680)
                ]
            );
            for (gpa, size, data) in [
                (0x30_4000, 4096, data.as_slice()),
                (0x30_0000, 8192, &[][..]),
                (0x30_2000, 8192, padded.as_slice()),
                (0x30_8000, 4096, data.as_slice()),
                (0x30_a000, 8192, &[][..]),
                (0x30_c000, 8192, padded.as_slice()),
            ] {
                assert_eq!(&machine.bytes[gpa..gpa + data.len()], data);
                assert!(
                    machine.bytes[gpa + data.len()..gpa + size]
                        .iter()
                        .all(|b| *b == 0)
                );
            }
            for gpa in [0x2f_ffff, 0x30_5000, 0x30_7fff, 0x30_9000, 0x30_e000] {
                assert_eq!(machine.bytes[gpa], dirty);
            }
        }
    }
}

#[test]
fn repeated_fills_use_each_destination_and_zero_the_complete_reservation() {
    let mut image = ActionImage::new(HostArchitecture::X86_64);
    for (section, gpa, kind) in [
        (".dtb", 0x30_0000, "dt:dtb"),
        (".dtb", 0x30_2000, "dt:dtb"),
        (".dtbo", 0x30_4000, "dt:dtbo"),
        (".dtbo", 0x30_6000, "dt:dtbo"),
    ] {
        image.fill(section, gpa, kind);
    }
    let plan = image.plan(48).unwrap();
    let mut machine = RecordingMachine::dirty(0xcc);
    plan.recipe.apply(&mut machine, plan.pmi.bytes()).unwrap();
    for (source, destinations) in [
        (0x20_0000, [0x30_0000, 0x30_2000]),
        (0x20_1000, [0x30_4000, 0x30_6000]),
    ] {
        let size =
            u32::from_be_bytes(machine.bytes[source + 4..source + 8].try_into().unwrap()) as usize;
        for gpa in destinations {
            assert_eq!(
                &machine.bytes[gpa..gpa + 4096],
                &machine.bytes[source..source + 4096]
            );
            assert!(
                machine.bytes[gpa + size..gpa + 4096]
                    .iter()
                    .all(|b| *b == 0)
            );
            assert_eq!(machine.bytes[gpa + 4096], 0xcc);
        }
    }
    let emitted: Vec<_> = machine
        .operations
        .iter()
        .filter(|op| match op {
            Operation::Write(gpa, _) | Operation::Zero(gpa, _) => *gpa >= 0x30_0000,
        })
        .collect();
    assert_eq!(emitted.len(), 8);
    for (pair, gpa) in emitted
        .as_chunks::<2>()
        .0
        .iter()
        .zip([0x30_0000, 0x30_2000, 0x30_4000, 0x30_6000])
    {
        let Operation::Write(actual, data) = pair[0] else {
            panic!("fill starts with content")
        };
        assert_eq!(*actual, gpa);
        assert_eq!(
            *pair[1],
            Operation::Zero(gpa + data.len() as u64, 4096 - data.len() as u64)
        );
    }
}

#[test]
fn per_action_overlaps_alignment_and_checked_range_boundaries_are_rejected() {
    for (first, second) in [(0x30_0000, 0x30_0000), (0x30_0000, 0x30_1000)] {
        let mut image = ActionImage::new(HostArchitecture::X86_64);
        image.load(".zero", first);
        image.load(".data", second);
        assert!(matches!(
            image.parse(),
            Err(ParseError::SectionsOverlap { .. })
        ));
    }
    for gpa in [u64::MAX - 4095, u64::MAX - 0x1f_ffff] {
        let mut image = ActionImage::new(HostArchitecture::X86_64);
        image.load(".data", gpa);
        assert!(matches!(
            image.parse(),
            Err(ParseError::VirtualAddressOverflow { .. })
        ));
    }
    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.load(".data", 0x30_0001);
    assert!(matches!(
        image.parse(),
        Err(ParseError::AlignmentViolation { .. })
    ));
    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.manifest["actions"][0]["gpa"] = json!(1u64 << 48);
    assert!(matches!(
        image.plan(48),
        Err(LaunchError::DtbCrossValidate(
            SurveyError::LoadAddressOverflow { .. }
        ))
    ));
    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.fill(".data", 0x30_0000, "dt:dtb");
    assert!(matches!(
        image.parse(),
        Err(ParseError::InvalidSectionShape { .. })
    ));
}

#[test]
fn action_address_width_and_large_section_alignment_are_checked() {
    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.manifest["actions"][0]["gpa"] = json!(1u64 << 48);
    assert!(matches!(
        image.plan(48),
        Err(LaunchError::DtbCrossValidate(
            SurveyError::LoadAddressOverflow { .. }
        ))
    ));
    let plan = image.plan(49).unwrap();
    assert!(plan.memory.memslots.iter().any(|r| r.gpa == 1 << 48));

    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.load(".padded", 0x40_1000);
    let size_field = 0x188 + 7 * 40 + 8;
    image.bytes[size_field..size_field + 4].copy_from_slice(&0x1f_ffffu32.to_le_bytes());
    let options = ParseOptions {
        host_arch: HostArch::X86_64,
        memory_mib: 8,
    };
    assert!(pmi_parse::parse(&image.bytes(), &options).is_ok());
    image.bytes[size_field..size_field + 4].copy_from_slice(&0x20_0000u32.to_le_bytes());
    assert!(matches!(
        pmi_parse::parse(&image.bytes(), &options),
        Err(ParseError::AlignmentViolation { .. })
    ));
}

#[test]
fn malformed_fill_shapes_and_raw_data_larger_than_virtual_size_are_rejected() {
    for kind in ["dt:dtb", "dt:dtbo", "lbc:bootconfig"] {
        let mut image = ActionImage::new(HostArchitecture::X86_64);
        image.fill(".data", 0x30_0000, kind);
        assert!(matches!(
            image.parse(),
            Err(ParseError::InvalidSectionShape { .. })
        ));
    }
    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.load(".data", 0x30_0000);
    let field = 0x188 + 5 * 40 + 8;
    image.bytes[field..field + 4].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        image.parse(),
        Err(ParseError::InvalidSectionShape { .. })
    ));
}

#[test]
fn failed_write_or_zero_ends_recipe_before_subsequent_operations() {
    let image = ActionImage::new(HostArchitecture::X86_64);
    let plan = image.plan(48).unwrap();
    for fail_at in [0, 1] {
        let mut machine = RecordingMachine::dirty(0xa5);
        machine.fail_at = Some(fail_at);
        assert!(
            plan.recipe
                .apply(&mut machine, plan.pmi.bytes())
                .unwrap_err()
                .to_string()
                .contains("injected memory operation failure")
        );
        assert_eq!(machine.operations.len(), fail_at);
        assert_eq!(
            machine.bytes[0x1000], 0xa5,
            "failed zero must not be treated as success"
        );
        assert_eq!(machine.bytes[0x20_0000], 0xa5, "later action must not run");
    }
}
