// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The x86 interrupt-controller model the devicetree contract declares, and
//! the KVM capabilities that decide whether it can be realized.
//!
//! The devicetree is dillo's machine contract (DESIGN-RULES DT-001): the LAPIC
//! and IOAPIC windows it declares are what the backend must construct, not a
//! description of whatever KVM happens to create by default. This module lifts
//! both controllers out of the tree and decides, against KVM's actual
//! interfaces, whether each declaration can be honored — so an unrealizable
//! declaration is refused at VM construction, before any vCPU runs, instead of
//! being silently replaced by KVM's defaults (DT-002).
//!
//! # What KVM can configure
//!
//! **LAPIC base — configurable.** The in-kernel LAPIC decodes at
//! `IA32_APIC_BASE[51:12]`, which userspace programs per vCPU through
//! `kvm_sregs::apic_base` (`KVM_SET_SREGS` → `kvm_apic_set_base`). KVM
//! re-points the vCPU's APIC MMIO decode at the new address, so a nonstandard
//! declared base is realized faithfully. Two kernel-side limits bound it:
//!
//!   * `apic->base_address` is masked with `MSR_IA32_APICBASE_BASE`
//!     (`0xfffff << 12`), so only bits 12–31 survive: a base at or above 4 GiB
//!     is accepted by the ioctl and then truncated. Such a base is refused here
//!     rather than silently realized somewhere else.
//!   * Relocating the LAPIC sets `APICV_INHIBIT_REASON_APIC_BASE_MODIFIED`,
//!     disabling hardware APIC virtualization for the VM. Interrupt delivery
//!     stays correct; it is slower. That is a performance consequence of the
//!     declaration, not a reason to refuse it.
//!
//! **IOAPIC base — not configurable.** `kvm_ioapic_init()` registers the
//! in-kernel IOAPIC on the MMIO bus at `IOAPIC_DEFAULT_BASE_ADDRESS` and KVM
//! exposes no interface to move it. `KVM_SET_IRQCHIP` copies a caller-supplied
//! `base_address` into the IOAPIC state but does not re-register the bus
//! device, so a relocated base leaves the controller unreachable at both
//! addresses: accesses at the registered range fail `ioapic_in_range()`, and
//! accesses at the declared base reach no in-kernel device at all. A
//! nonstandard IOAPIC base is therefore refused. (Realizing one would mean
//! moving the IOAPIC into userspace via `KVM_CAP_SPLIT_IRQCHIP`, which changes
//! how every wired line and MSI is routed; that is a separate change.)
//!
//! **Window sizes — bounded below, not above.** KVM decodes a fixed span at
//! each controller base: 4 KiB for the LAPIC (`LAPIC_MMIO_LENGTH`) and 256
//! bytes for the IOAPIC (`IOAPIC_MEM_LENGTH`). A declared window shorter than
//! that span is refused: KVM would answer addresses the contract never granted
//! to the controller (DT-003). A longer declared window is honored — the tail
//! simply decodes to nothing, which instantiates no undeclared hardware.

use dillo_devtree::devtree::{OwnedNode, OwnedTree};
use dillo_devtree::{NodeExt, PropExt};

use crate::hypervisor::Error;

/// Bytes the in-kernel LAPIC decodes at its base (`LAPIC_MMIO_LENGTH`).
pub(crate) const LAPIC_DECODED_LEN: u64 = 0x1000;

/// Bytes the in-kernel IOAPIC decodes at its base (`IOAPIC_MEM_LENGTH`).
pub(crate) const IOAPIC_DECODED_LEN: u64 = 0x100;

/// The only IOAPIC base KVM's in-kernel IOAPIC can occupy
/// (`IOAPIC_DEFAULT_BASE_ADDRESS`).
pub(crate) const IOAPIC_FIXED_BASE: u64 = 0xFEC0_0000;

/// Highest LAPIC base KVM can hold: `apic->base_address` keeps only bits 12–31
/// of `IA32_APIC_BASE`, so anything at or above this is truncated.
const LAPIC_BASE_LIMIT: u64 = 1 << 32;

/// The declared x86 interrupt-controller model, validated against what KVM can
/// realize. Constructing one is the proof that the declaration is realizable;
/// [`Vm::new_with_intc`](crate::hypervisor::Vm) then realizes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct X86Intc {
    lapic_base: u64,
    lapic_size: u64,
    ioapic_base: u64,
    ioapic_size: u64,
}

impl X86Intc {
    /// Validate a declared controller pair against KVM's capabilities.
    ///
    /// # Errors
    ///
    /// One of the `Unsupported*` variants of [`Error`] when KVM cannot decode
    /// the declared window at the declared address.
    pub(crate) fn new(
        lapic_base: u64,
        lapic_size: u64,
        ioapic_base: u64,
        ioapic_size: u64,
    ) -> Result<Self, Error> {
        // IA32_APIC_BASE carries the base in bits 12 and up; a misaligned
        // declaration has no representation at all.
        if !lapic_base.is_multiple_of(LAPIC_DECODED_LEN) {
            return Err(Error::UnsupportedLapicBase {
                base: lapic_base,
                reason: "IA32_APIC_BASE holds a 4 KiB-aligned base",
            });
        }
        if lapic_base >= LAPIC_BASE_LIMIT {
            return Err(Error::UnsupportedLapicBase {
                base: lapic_base,
                reason: "KVM keeps only bits 12-31 of IA32_APIC_BASE",
            });
        }
        if lapic_size < LAPIC_DECODED_LEN {
            return Err(Error::UnsupportedLapicSize {
                size: lapic_size,
                decoded: LAPIC_DECODED_LEN,
            });
        }
        if ioapic_base != IOAPIC_FIXED_BASE {
            return Err(Error::UnsupportedIoapicBase {
                base: ioapic_base,
                default: IOAPIC_FIXED_BASE,
            });
        }
        if ioapic_size < IOAPIC_DECODED_LEN {
            return Err(Error::UnsupportedIoapicSize {
                size: ioapic_size,
                decoded: IOAPIC_DECODED_LEN,
            });
        }
        Ok(Self {
            lapic_base,
            lapic_size,
            ioapic_base,
            ioapic_size,
        })
    }

    /// The declared LAPIC base, to be programmed into `IA32_APIC_BASE`.
    pub(crate) fn lapic_base(&self) -> u64 {
        self.lapic_base
    }

    /// The declared LAPIC window size.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lapic_size(&self) -> u64 {
        self.lapic_size
    }

    /// The declared IOAPIC base.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn ioapic_base(&self) -> u64 {
        self.ioapic_base
    }

    /// The declared IOAPIC window size.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn ioapic_size(&self) -> u64 {
        self.ioapic_size
    }

    /// Consume both `interrupt-controller@*` nodes from `tree` and validate the
    /// model they declare.
    ///
    /// The two x86 controllers share a node-name prefix, so they are
    /// disambiguated by `compatible` exactly as the platform survey does.
    ///
    /// # Errors
    ///
    /// [`Error::MissingSubstrate`] when either controller node is absent,
    /// [`Error::BadSubstrateProperty`] when a node is malformed or carries
    /// anything dillo has no authority to interpret, and the `Unsupported*`
    /// variants when the declaration cannot be realized.
    pub(crate) fn from_tree(tree: &mut OwnedTree) -> Result<Self, Error> {
        let (lapic_base, lapic_size) = claim(tree, "intel,ce4100-lapic", "/lapic")?;
        let (ioapic_base, ioapic_size) = claim(tree, "intel,ce4100-ioapic", "/ioapic")?;
        Self::new(lapic_base, lapic_size, ioapic_base, ioapic_size)
    }
}

/// Remove one `interrupt-controller@*` node matching `compat` and return its
/// declared `(base, size)`, refusing any property dillo does not consume.
fn claim(
    tree: &mut OwnedTree,
    compat: &'static str,
    path: &'static str,
) -> Result<(u64, u64), Error> {
    let root = tree.root_mut();
    let name = root
        .children()
        .find(|node| {
            node.name().starts_with("interrupt-controller@") && node.compatible_contains(compat)
        })
        .map(|node| node.name().to_string())
        .ok_or(Error::MissingSubstrate(path))?;
    let mut node = root
        .remove_child(&name)
        .ok_or(Error::MissingSubstrate(path))?;

    // `compatible` matched above; the rest must be present and are consumed
    // here so an unexpected property cannot pass unnoticed.
    let reg = require(&mut node, path, "reg")?;
    let (base, size) = (&reg).reg_pair(0).ok_or(Error::BadSubstrateProperty {
        node: path,
        prop: "reg",
        reason: "missing reg pair",
    })?;
    for prop in [
        "compatible",
        "#interrupt-cells",
        "interrupt-controller",
        "phandle",
    ] {
        require(&mut node, path, prop)?;
    }
    if node.properties().next().is_some() || node.children().next().is_some() {
        return Err(Error::BadSubstrateProperty {
            node: path,
            prop: "*",
            reason: "unconsumed property or child",
        });
    }
    Ok((base, size))
}

fn require(
    node: &mut OwnedNode,
    path: &'static str,
    prop: &'static str,
) -> Result<dillo_devtree::devtree::OwnedProperty, Error> {
    node.remove_property(prop)
        .ok_or(Error::BadSubstrateProperty {
            node: path,
            prop,
            reason: "missing",
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod tests {
    use dillo_devtree::devtree::{OwnedNode, OwnedProperty};

    use super::*;

    const LAPIC_STD: u64 = 0xFEE0_0000;

    fn reg2(base: u64, size: u64) -> [u32; 4] {
        [
            (base >> 32) as u32,
            base as u32,
            (size >> 32) as u32,
            size as u32,
        ]
    }

    fn intc_node(name: &str, compat: &str, base: u64, size: u64, phandle: u32) -> OwnedNode {
        OwnedNode::new(name)
            .with_property(OwnedProperty::new("compatible").with_str(compat))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(base, size)))
            .with_property(OwnedProperty::new("#interrupt-cells").with_u32(2))
            .with_property(OwnedProperty::new("interrupt-controller"))
            .with_property(OwnedProperty::new("phandle").with_u32(phandle))
    }

    /// A root declaring both controllers at the given windows.
    pub(crate) fn tree(
        lapic_base: u64,
        lapic_size: u64,
        ioapic_base: u64,
        ioapic_size: u64,
    ) -> OwnedTree {
        let root = OwnedNode::new("")
            .with_property(OwnedProperty::new("#address-cells").with_u32(2))
            .with_property(OwnedProperty::new("#size-cells").with_u32(2))
            .with_child(intc_node(
                &format!("interrupt-controller@{lapic_base:x}"),
                "intel,ce4100-lapic",
                lapic_base,
                lapic_size,
                1,
            ))
            .with_child(intc_node(
                &format!("interrupt-controller@{ioapic_base:x}"),
                "intel,ce4100-ioapic",
                ioapic_base,
                ioapic_size,
                2,
            ));
        OwnedTree::new(root)
    }

    #[test]
    fn standard_layout_is_accepted() {
        let intc = X86Intc::from_tree(&mut tree(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, 0x1000))
            .expect("standard layout realizable");
        assert_eq!(intc.lapic_base(), LAPIC_STD);
        assert_eq!(intc.lapic_size(), 0x1000);
        assert_eq!(intc.ioapic_base(), IOAPIC_FIXED_BASE);
        assert_eq!(intc.ioapic_size(), 0x1000);
    }

    #[test]
    fn nonstandard_lapic_base_is_carried_through() {
        for base in [0x1100_0000, 0x4000_0000, 0xDEAD_0000u64] {
            let intc = X86Intc::from_tree(&mut tree(base, 0x1000, IOAPIC_FIXED_BASE, 0x1000))
                .expect("relocatable LAPIC accepted");
            assert_eq!(intc.lapic_base(), base);
        }
    }

    #[test]
    fn lapic_window_larger_than_decode_is_accepted() {
        let intc = X86Intc::from_tree(&mut tree(0x1100_0000, 0x10_0000, IOAPIC_FIXED_BASE, 0x1000))
            .expect("oversized LAPIC window accepted");
        assert_eq!(intc.lapic_size(), 0x10_0000);
    }

    #[test]
    fn lapic_window_shorter_than_decode_is_refused() {
        let err = X86Intc::from_tree(&mut tree(LAPIC_STD, 0x800, IOAPIC_FIXED_BASE, 0x1000))
            .expect_err("short LAPIC window refused");
        assert!(
            matches!(err, Error::UnsupportedLapicSize { size, decoded }
                if size == 0x800 && decoded == LAPIC_DECODED_LEN),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn misaligned_lapic_base_is_refused() {
        let err = X86Intc::from_tree(&mut tree(0x1100_0800, 0x1000, IOAPIC_FIXED_BASE, 0x1000))
            .expect_err("misaligned LAPIC base refused");
        assert!(
            matches!(err, Error::UnsupportedLapicBase { base, .. } if base == 0x1100_0800),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn lapic_base_above_4gib_is_refused() {
        // KVM would accept the MSR write and then decode at the truncated
        // address — exactly the silent substitution DT-002 forbids.
        let err = X86Intc::from_tree(&mut tree(0x1_0000_0000, 0x1000, IOAPIC_FIXED_BASE, 0x1000))
            .expect_err("4 GiB+ LAPIC base refused");
        assert!(
            matches!(err, Error::UnsupportedLapicBase { base, .. } if base == 0x1_0000_0000),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nonstandard_ioapic_base_is_refused() {
        let err = X86Intc::from_tree(&mut tree(LAPIC_STD, 0x1000, 0x1200_0000, 0x1000))
            .expect_err("relocated IOAPIC refused");
        assert!(
            matches!(err, Error::UnsupportedIoapicBase { base, default }
                if base == 0x1200_0000 && default == IOAPIC_FIXED_BASE),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ioapic_window_shorter_than_decode_is_refused() {
        let err = X86Intc::from_tree(&mut tree(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, 0x80))
            .expect_err("short IOAPIC window refused");
        assert!(
            matches!(err, Error::UnsupportedIoapicSize { size, decoded }
                if size == 0x80 && decoded == IOAPIC_DECODED_LEN),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ioapic_window_between_decode_and_page_is_accepted() {
        // KVM decodes 0x100; the conventional tree declares a whole page. Both
        // are realizable, so neither may be rewritten to the other.
        for size in [IOAPIC_DECODED_LEN, 0x200, 0x1000] {
            let intc = X86Intc::from_tree(&mut tree(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, size))
                .expect("IOAPIC window accepted");
            assert_eq!(intc.ioapic_size(), size);
        }
    }

    #[test]
    fn missing_controller_is_refused() {
        let root = OwnedNode::new("").with_child(intc_node(
            "interrupt-controller@fec00000",
            "intel,ce4100-ioapic",
            IOAPIC_FIXED_BASE,
            0x1000,
            2,
        ));
        let err = X86Intc::from_tree(&mut OwnedTree::new(root)).expect_err("missing LAPIC refused");
        assert!(
            matches!(err, Error::MissingSubstrate("/lapic")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unconsumed_property_is_refused() {
        let mut t = tree(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, 0x1000);
        t.root_mut()
            .child_mut("interrupt-controller@fee00000")
            .expect("LAPIC node")
            .set_property(OwnedProperty::new("dillo,unknown").with_u32(1));
        let err = X86Intc::from_tree(&mut t).expect_err("unknown property refused");
        assert!(
            matches!(err, Error::BadSubstrateProperty { node: "/lapic", .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn controllers_are_consumed_from_the_tree() {
        let mut t = tree(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, 0x1000);
        X86Intc::from_tree(&mut t).expect("standard layout realizable");
        assert_eq!(t.root().children().count(), 0);
    }
}
