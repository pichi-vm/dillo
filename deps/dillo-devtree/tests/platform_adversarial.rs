// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Self-contained malformed-input and declaration checks for the DT survey.

use dillo_devtree::devtree::{OwnedNode, OwnedProperty, OwnedTree};
use dillo_devtree::platform::{Arch, Machine, SurveyError};

/// Owns a valid platform so each negative case can change one input fact.
struct SurveyFixture(OwnedTree);

impl SurveyFixture {
    fn new() -> Self {
        let mut root = OwnedNode::new("")
            .with_property(OwnedProperty::new("#address-cells").with_u32(2))
            .with_property(OwnedProperty::new("#size-cells").with_u32(2));
        for (name, compatible, base, phandle) in [
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
            root = root.with_child(
                OwnedNode::new(name)
                    .with_property(OwnedProperty::new("compatible").with_str(compatible))
                    .with_property(OwnedProperty::new("reg").with_u32s(&[0, base, 0, 0x1000]))
                    .with_property(OwnedProperty::new("#interrupt-cells").with_u32(2))
                    .with_property(OwnedProperty::new("interrupt-controller"))
                    .with_property(OwnedProperty::new("phandle").with_u32(phandle)),
            );
        }
        root = root
            .with_child(
                OwnedNode::new("poweroff@9010000")
                    .with_property(OwnedProperty::new("compatible").with_str("syscon-poweroff"))
                    .with_property(OwnedProperty::new("reg").with_u32s(&[0, 0x0901_0000, 0, 4]))
                    .with_property(OwnedProperty::new("value").with_u32(0x34)),
            )
            .with_child(
                OwnedNode::new("pcie@b0000000")
                    .with_property(
                        OwnedProperty::new("compatible").with_str("pci-host-ecam-generic"),
                    )
                    .with_property(OwnedProperty::new("device_type").with_str("pci"))
                    .with_property(OwnedProperty::new("reg").with_u32s(&[
                        0,
                        0xb000_0000,
                        0,
                        0x10_0000,
                    ]))
                    .with_property(OwnedProperty::new("#address-cells").with_u32(3))
                    .with_property(OwnedProperty::new("#size-cells").with_u32(2))
                    .with_property(OwnedProperty::new("bus-range").with_u32s(&[0, 0]))
                    .with_property(OwnedProperty::new("ranges").with_u32s(&[
                        0x0200_0000,
                        0,
                        0xc000_0000,
                        0,
                        0xc000_0000,
                        0,
                        0x1000_0000,
                    ])),
            );
        let fixture = Self(OwnedTree::new(root));
        fixture
            .survey()
            .expect("unmodified fixture must survey successfully");
        fixture
    }

    fn with_property(mut self, node: &str, property: OwnedProperty) -> Self {
        self.0
            .root_mut()
            .child_mut(node)
            .expect("fixture node")
            .set_property(property);
        self
    }

    fn with_child(mut self, child: OwnedNode) -> Self {
        self.0.root_mut().set_child(child);
        self
    }

    fn bytes(&self) -> Vec<u8> {
        self.0.encode().expect("encode owned fixture")
    }

    fn survey(&self) -> Result<Machine, SurveyError> {
        Machine::survey(&self.bytes(), Arch::X86_64)
    }
}

#[test]
fn empty_dtb_rejected() {
    let err = Machine::survey(&[], Arch::X86_64).expect_err("0 bytes must not parse");
    assert!(matches!(err, SurveyError::Parse(_)), "got {err:?}");
}

#[test]
fn truncated_dtb_rejected() {
    // FDT header is 40 bytes; anything shorter can't even be sized.
    let bytes = vec![0u8; 16];
    let err = Machine::survey(&bytes, Arch::X86_64).expect_err("16 bytes must not parse");
    assert!(matches!(err, SurveyError::Parse(_)), "got {err:?}");
}

#[test]
fn garbage_with_wrong_magic_rejected() {
    let mut bytes = vec![0u8; 256];
    // Set first 4 bytes to non-FDT magic.
    bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    let err = Machine::survey(&bytes, Arch::X86_64).expect_err("wrong magic must not parse");
    assert!(matches!(err, SurveyError::Parse(_)), "got {err:?}");
}

#[test]
fn generated_platform_surveys_declared_resources() {
    let platform = SurveyFixture::new().survey().unwrap();
    assert!(platform.has_pcie);
    assert_eq!(platform.pcie.ecam_base, 0xb000_0000);
    assert_eq!(platform.pcie.mmio_base, 0xc000_0000);
    let poweroff = platform.poweroff.expect("declared poweroff");
    assert_eq!(
        (poweroff.base, poweroff.size, poweroff.value),
        (0x0901_0000, 4, 0x34)
    );
    assert_eq!(platform.plan.regions().len(), 5);
}

#[test]
fn invalid_structure_token_rejected() {
    let mut bytes = SurveyFixture::new().bytes();
    let structure = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    bytes[structure..structure + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        Machine::survey(&bytes, Arch::X86_64),
        Err(SurveyError::Parse(_))
    ));
}

#[test]
fn non_allowlisted_intc_compatible_rejected() {
    let result = SurveyFixture::new()
        .with_property(
            "interrupt-controller@fee00000",
            OwnedProperty::new("compatible").with_str("made,up,intc"),
        )
        .survey();
    assert!(
        matches!(result, Err(SurveyError::MissingNode("/lapic"))),
        "{result:?}"
    );
}

#[test]
fn non_allowlisted_pcie_compatible_rejected() {
    let result = SurveyFixture::new()
        .with_property(
            "pcie@b0000000",
            OwnedProperty::new("compatible").with_str("not-pci-host-ecam-generic"),
        )
        .survey();
    assert!(
        matches!(
            result,
            Err(SurveyError::Unsupported {
                node: "/pcie",
                prop: "compatible",
                ..
            })
        ),
        "{result:?}"
    );
}

#[test]
fn non_allowlisted_syscon_compatible_rejected() {
    let result = SurveyFixture::new()
        .with_property(
            "poweroff@9010000",
            OwnedProperty::new("compatible").with_str("made,up,syscon"),
        )
        .survey();
    assert!(
        matches!(
            result,
            Err(SurveyError::Unsupported {
                node: "/poweroff",
                prop: "compatible",
                ..
            })
        ),
        "{result:?}"
    );
}

#[test]
fn pcie_ecam_mmio_overlap_rejected() {
    let result = SurveyFixture::new()
        .with_property(
            "pcie@b0000000",
            OwnedProperty::new("ranges").with_u32s(&[
                0x0200_0000,
                0,
                0xb005_0000,
                0,
                0xb005_0000,
                0,
                0x1_0000,
            ]),
        )
        .survey();
    assert!(
        matches!(result, Err(SurveyError::Overlap { .. })),
        "{result:?}"
    );
}

#[test]
fn truncated_register_tuple_rejected() {
    let result = SurveyFixture::new()
        .with_property(
            "poweroff@9010000",
            OwnedProperty::new("reg").with_u32s(&[0, 0x0901_0000, 0]),
        )
        .survey();
    assert!(
        matches!(
            result,
            Err(SurveyError::BadProperty {
                node: "/poweroff",
                prop: "reg",
                ..
            })
        ),
        "{result:?}"
    );
}

#[test]
fn base_with_cpus_node_rejected() {
    let result = SurveyFixture::new()
        .with_child(
            OwnedNode::new("cpus")
                .with_property(OwnedProperty::new("#address-cells").with_u32(1))
                .with_property(OwnedProperty::new("#size-cells").with_u32(0)),
        )
        .survey();
    assert!(
        matches!(result, Err(SurveyError::BaseHasCpus)),
        "{result:?}"
    );
}
