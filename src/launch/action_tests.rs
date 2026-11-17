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
            plan.recipe.apply(&mut machine).unwrap();
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
    plan.recipe.apply(&mut machine).unwrap();
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
fn every_fill_kind_requires_a_nonempty_zero_section() {
    for arch in [HostArchitecture::X86_64, HostArchitecture::Aarch64] {
        for (kind, expected) in [
            ("dt:dtb", FillKind::DtDtb),
            ("dt:dtbo", FillKind::DtDtbo),
            ("lbc:bootconfig", FillKind::LbcBootconfig),
        ] {
            for section in [".data", ".padded", ".zero"] {
                let mut image = ActionImage::new(arch);
                if section == ".zero" {
                    // Make the raw-empty .zero section have no capacity either.
                    let size = 0x188 + 6 * 40 + 8;
                    image.bytes[size..size + 4].copy_from_slice(&0u32.to_le_bytes());
                }
                image.fill(section, 0x30_0000, kind);
                assert!(
                    matches!(
                        image.parse(),
                        Err(ParseError::InvalidSectionShape {
                            section: rejected,
                            reason: "fill requires a nonempty Zero section",
                        }) if rejected == section
                    ),
                    "{arch:?} {kind} must reject {section}"
                );
            }

            let mut image = ActionImage::new(arch);
            // A 4 KiB Zero reservation also meets the overlay minimum and native
            // bootconfig framing alignment. Replace an existing fill of this
            // kind so duplicate-kind rules cannot obscure shape acceptance.
            let size = 0x188 + 6 * 40 + 8;
            image.bytes[size..size + 4].copy_from_slice(&4096u32.to_le_bytes());
            image.manifest["actions"]
                .as_array_mut()
                .unwrap()
                .retain(|action| action["kind"] != kind);
            image.fill(".zero", 0x30_0000, kind);
            let parsed = image.parse().unwrap_or_else(|error| {
                panic!("{arch:?} {kind} must accept nonempty Zero: {error}")
            });
            let action = parsed.actions.last().unwrap();
            assert_eq!(action.section(), ".zero");
            assert_eq!(action.kind(), ActionKind::Fill(expected));
        }
    }
}

#[test]
fn raw_data_larger_than_virtual_size_is_rejected() {
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
                .apply(&mut machine)
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

#[test]
fn captured_bytes_survive_original_changes_before_validation() {
    for arch in [HostArchitecture::X86_64, HostArchitecture::Aarch64] {
        let mut image = ActionImage::new(arch);
        image.load(".data", 0x30_0000);
        let path = image.directory.path().join("image.pmi");
        std::fs::write(&path, image.bytes()).unwrap();
        let captured = Pmi::<SelectedInput>::open(&path).unwrap();
        std::fs::write(&path, b"the original is no longer a PMI").unwrap();
        let plan = captured
            .validate(arch, None, || Ok(48), 4, 1, None, None)
            .unwrap();
        let mut machine = RecordingMachine::dirty(0xa5);
        plan.recipe.apply(&mut machine).unwrap();
        assert_eq!(&machine.bytes[0x30_0000..0x30_0003], &[1, 2, 3]);
    }
}

#[test]
fn source_truncation_between_validation_and_loading_cannot_replace_recipe_input() {
    for arch in [HostArchitecture::X86_64, HostArchitecture::Aarch64] {
        let mut image = ActionImage::new(arch);
        image.load(".data", 0x30_0000);
        let path = image.directory.path().join("image.pmi");
        std::fs::write(&path, image.bytes()).unwrap();
        let plan = LaunchPlan::read(
            &path,
            arch,
            None,
            || {
                // This callback runs after parsing and DT survey, before the
                // resolved recipe is applied to any guest memory.
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
                Ok(48)
            },
            4,
            1,
            None,
            None,
        )
        .unwrap();
        let mut machine = RecordingMachine::dirty(0xa5);
        plan.recipe.apply(&mut machine).unwrap();
        assert_eq!(&machine.bytes[0x30_0000..0x30_0003], &[1, 2, 3]);
    }
}

#[test]
fn retained_recipe_survives_same_inode_writes_and_guest_memory_mutation() {
    use std::io::{Seek, Write};

    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.load(".data", 0x30_0000);
    image.load(".padded", 0x30_2000);
    let plan = image.plan(48).unwrap();
    let path = image.directory.path().join("image.pmi");
    let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let mut initial = RecordingMachine::dirty(0xa5);
    plan.recipe.apply(&mut initial).unwrap();
    let expected = std::mem::take(&mut initial.operations);

    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let start_ref = &start;
        let writer = scope.spawn(move || {
            start_ref.wait();
            for _ in 0..64 {
                writer.set_len(0).unwrap();
                writer.rewind().unwrap();
                writer.write_all(&[0xff; 8192]).unwrap();
                std::thread::yield_now();
            }
        });
        start.wait();
        // Guest/debugger mutations affect only receiver-owned RAM. Replaying
        // into the old receiver or fresh dirty memory must use retained bytes.
        initial.bytes.fill(0x77);
        plan.recipe.apply(&mut initial).unwrap();
        assert_eq!(initial.operations, expected);
        for _ in 0..4 {
            let mut replacement = RecordingMachine::dirty(0x55);
            plan.recipe.apply(&mut replacement).unwrap();
            assert_eq!(replacement.operations, expected);
        }
        writer.join().unwrap();
    });
}

#[test]
fn pathname_replacement_does_not_change_retained_recipe() {
    let mut image = ActionImage::new(HostArchitecture::X86_64);
    image.load(".data", 0x30_0000);
    let plan = image.plan(48).unwrap();
    let path = image.directory.path().join("image.pmi");
    let retired = image.directory.path().join("retired.pmi");
    std::fs::rename(&path, &retired).unwrap();
    let mut replacement = image.bytes();
    replacement[0x4000..0x4200].fill(0x99);
    std::fs::write(&path, replacement).unwrap();
    std::fs::write(retired, b"old inode changed too").unwrap();
    let mut machine = RecordingMachine::dirty(0xa5);
    plan.recipe.apply(&mut machine).unwrap();
    assert_eq!(&machine.bytes[0x30_0000..0x30_0003], &[1, 2, 3]);
}

#[test]
fn external_dt_and_bootconfig_keep_their_captured_identity_for_replay() {
    for arch in [HostArchitecture::X86_64, HostArchitecture::Aarch64] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image.pmi");
        let dtb_path = directory.path().join("base.dtb");
        let config_path = directory.path().join("input.bconf");
        let dtb = base(arch, false, false);
        let bytes = super::delegation_tests::with_bootconfig(
            image(arch, BaseChannel::Detached, &dtb, Some(4096)),
            &[0x20_2000],
            4096,
            0,
        );
        std::fs::write(&path, bytes).unwrap();
        std::fs::write(&dtb_path, &dtb).unwrap();
        std::fs::write(&config_path, b"launch.identity = retained;").unwrap();
        let plan = LaunchPlan::read(
            &path,
            arch,
            None,
            || Ok(48),
            4,
            1,
            Some(&dtb_path),
            Some(&config_path),
        )
        .unwrap();
        let mut initial = RecordingMachine::dirty(0xa5);
        plan.recipe.apply(&mut initial).unwrap();
        std::fs::write(&dtb_path, b"invalid replacement DT").unwrap();
        std::fs::remove_file(&config_path).unwrap();
        std::fs::write(&config_path, b"launch.identity = changed;").unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(plan.merged_dtb, dtb);
        let mut replacement = RecordingMachine::dirty(0x55);
        plan.recipe.apply(&mut replacement).unwrap();
        assert_eq!(replacement.operations, initial.operations);
        assert_eq!(&replacement.bytes[0x20_0000..0x20_0000 + dtb.len()], dtb);
        assert!(
            replacement.bytes[0x20_2000..0x20_3000]
                .windows(b"launch.identity = retained;".len())
                .any(|bytes| bytes == b"launch.identity = retained;")
        );
    }
}

#[test]
fn empty_captured_input_is_refused_by_the_parser() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("empty.pmi");
    std::fs::write(&path, []).unwrap();
    assert!(matches!(
        LaunchPlan::read(
            &path,
            HostArchitecture::X86_64,
            None,
            || Ok(48),
            4,
            1,
            None,
            None
        ),
        Err(LaunchError::PmiParse(_))
    ));
}

#[test]
fn failed_retained_source_view_prevents_all_guest_writes() {
    #[derive(Debug)]
    struct RefusedView {
        source: SelectedInput,
        viewed: std::cell::Cell<bool>,
    }
    impl LaunchInput for RefusedView {
        type View<'a> = <SelectedInput as LaunchInput>::View<'a>;

        fn capture(source: std::fs::File) -> std::io::Result<Self> {
            Ok(Self {
                source: SelectedInput::capture(source)?,
                viewed: std::cell::Cell::new(false),
            })
        }

        fn view(&self) -> std::io::Result<Self::View<'_>> {
            if self.viewed.replace(true) {
                return Err(std::io::Error::other("injected retained-view refusal"));
            }
            self.source.view()
        }
    }
    let image = ActionImage::new(HostArchitecture::X86_64);
    let path = image.directory.path().join("image.pmi");
    std::fs::write(&path, image.bytes()).unwrap();
    let plan = Pmi::<RefusedView>::open(&path)
        .unwrap()
        .validate(image.arch, None, || Ok(48), 4, 1, None, None)
        .unwrap();
    let mut machine = RecordingMachine::dirty(0xa5);
    let error = plan.recipe.apply(&mut machine).unwrap_err();
    assert!(error.to_string().contains("injected retained-view refusal"));
    assert!(machine.operations.is_empty());
    assert!(machine.bytes.iter().all(|byte| *byte == 0xa5));
}
