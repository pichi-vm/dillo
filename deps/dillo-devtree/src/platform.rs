// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Coverage-framework survey of the base DTB (the `merged` model).
//!
//! `Machine::survey` proves **total coverage**: it materializes the base DTB
//! into an owned, drainable tree and runs a fixed **specific → general**
//! sequence of self-routing device constructors. Each `from_tree` finds its
//! own node(s), removes the properties it models, and removes the node once it
//! is empty. There is no router handing nodes out; all routing knowledge lives
//! in the device. When every constructor has run, the tree must be empty; a
//! non-empty residual is an uncovered node/property and fails the launch
//! ([`SurveyError::Uncovered`]). Every guest-visible region is declared *from* a
//! claimed property ([`ResourcePlan::declare_from`]), so no constant can reach
//! the resource plan.

use devtree::{OwnedNode, OwnedProperty, OwnedTree, Tree};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn cpu_enable_method(self) -> Option<&'static str> {
        match self {
            Arch::Aarch64 => Some("psci"),
            Arch::X86_64 => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pcie {
    pub ecam_base: u64,
    pub ecam_size: u64,
    pub bus_min: u8,
    pub bus_max: u8,
    pub mmio_base: u64,
    pub mmio_size: u64,
    pub msi: Option<MsiParentage>,
}

impl Pcie {
    /// Sentinel for a microVM with no PCIe bridge (`has_pcie == false`).
    pub const ZEROED: Pcie = Pcie {
        ecam_base: 0,
        ecam_size: 0,
        bus_min: 0,
        bus_max: 0,
        mmio_base: 0,
        mmio_size: 0,
        msi: None,
    };
}

/// A virtio-mmio transport slot: a fixed MMIO window and its wired IRQ.
#[derive(Debug, Clone)]
pub struct VirtioMmio {
    pub base: u64,
    pub size: u64,
    /// GIC SPI number from `interrupts = <0 spi flags>` (aarch64), or the
    /// IO-APIC pin (x86). The VMM injects this when the slot's device signals.
    pub irq: u32,
    pub interrupt: WiredInterrupt,
}

#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    pub base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Syscon {
    pub base: u64,
    pub offset: u64,
    pub value: u32,
    pub mask: u32,
}

/// The device-model serial: an `ns16550a` (16550) over MMIO.
#[derive(Debug, Clone)]
pub struct Uart {
    pub base: u64,
    pub size: u64,
    /// `reg-shift`: the register stride is `1 << reg_shift` bytes.
    pub reg_shift: u32,
    /// x86 IO-APIC pin or aarch64 GIC interrupt cell consumed from DTB.
    pub irq: u32,
    pub interrupt: WiredInterrupt,
}

#[derive(Debug, Clone, Copy)]
pub struct Psci {
    pub method: PsciMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciMethod {
    Hvc,
    Smc,
}

/// Failures surveying the base DTB into a [`Machine`].
#[derive(Debug, Error)]
pub enum SurveyError {
    #[error("base DTB parse failed: {0:?}")]
    Parse(devtree::Error),

    #[error(
        "base DTB declares a `/cpus` node; the base must declare nothing \
         CPU-related — the host overlay authors the entire `/cpus` subtree \
         (PMI merged.md §1)"
    )]
    BaseHasCpus,

    #[error("required node `{0}` not found")]
    MissingNode(&'static str),

    #[error("required property `{prop}` not found on `{node}`")]
    MissingProperty { node: String, prop: &'static str },

    #[error("property `{prop}` on `{node}` is malformed ({reason})")]
    BadProperty {
        node: &'static str,
        prop: &'static str,
        reason: &'static str,
    },

    #[error("property `{prop}` on `{node}` has unsupported value `{value}`")]
    Unsupported {
        node: &'static str,
        prop: &'static str,
        value: String,
    },

    #[error("node `{node}` has properties/children no device claimed: {props:?} {children:?}")]
    Leftover {
        node: String,
        props: Vec<String>,
        children: Vec<String>,
    },

    #[error("base DTB has uncovered nodes/properties after survey: {0}")]
    Uncovered(String),

    #[error("declared regions overlap: `{a}` and `{b}`")]
    Overlap { a: String, b: String },

    #[error("loaded section `{section}` at [{start:#x}..{end:#x}) overflows guest address space")]
    LoadAddressOverflow {
        section: String,
        start: u64,
        end: u64,
    },

    #[error(
        "loaded section `{section}` at [{start:#x}..{end:#x}) overlaps declared `{region}` region [{region_start:#x}..{region_end:#x})"
    )]
    LoadOverlapsRegion {
        section: String,
        start: u64,
        end: u64,
        region: String,
        region_start: u64,
        region_end: u64,
    },

    #[error("property `{prop}` on `{node}` references unknown phandle {phandle}")]
    UnknownPhandle {
        node: &'static str,
        prop: &'static str,
        phandle: u32,
    },

    #[error("property `{prop}` on `{node}` references {actual:?}, expected {expected:?}")]
    UnexpectedController {
        node: &'static str,
        prop: &'static str,
        actual: ControllerKind,
        expected: ControllerKind,
    },
}

/// What a declared region is, so the realize step can map RAM, install MMIO
/// handlers, and treat windows (ECAM, BAR) appropriately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Guest RAM (authored by the host into the overlay; not seen here).
    Ram,
    /// A device MMIO register block dillo emulates.
    Mmio,
    /// The interrupt-controller substrate (GIC dist/redist/MSI frame).
    SubstrateMmio,
    /// A PCIe ECAM config window.
    EcamWindow,
    /// A PCIe BAR (MMIO) window.
    BarWindow,
}

/// Proof that a [`DeclaredRegion`] came from a claimed DTB property — no region
/// can be created without a property in hand (see [`ResourcePlan::declare_from`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub node: String,
    pub prop: String,
}

impl core::fmt::Display for Origin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.node, self.prop)
    }
}

/// One guest-physical region, tagged by kind and traced to its origin property.
#[derive(Debug, Clone)]
pub struct DeclaredRegion {
    pub gpa: u64,
    pub size: u64,
    pub kind: RegionKind,
    pub origin: Origin,
}

/// The typed, origin-tracked list of DTB-declared address regions.
///
/// Every region is created through [`Self::declare_from`], which requires a
/// reference to the claimed [`OwnedProperty`]. That is the only constructor, so
/// a region cannot originate from a constant.
#[derive(Debug, Default, Clone)]
pub struct ResourcePlan {
    regions: Vec<DeclaredRegion>,
}

impl ResourcePlan {
    /// Declare a region parsed from a claimed property. The `prop` reference is
    /// the proof of provenance; its name is recorded in the region's [`Origin`].
    pub fn declare_from(
        &mut self,
        prop: &OwnedProperty,
        node: &str,
        gpa: u64,
        size: u64,
        kind: RegionKind,
    ) {
        self.regions.push(DeclaredRegion {
            gpa,
            size,
            kind,
            origin: Origin {
                node: node.to_string(),
                prop: prop.name().to_string(),
            },
        });
    }

    /// The declared regions.
    pub fn regions(&self) -> &[DeclaredRegion] {
        &self.regions
    }

    /// Reject any pair of declared regions that overlap in guest-physical space.
    pub fn check_disjoint(&self) -> Result<(), SurveyError> {
        for (i, a) in self.regions.iter().enumerate() {
            for b in &self.regions[i + 1..] {
                if overlaps(a.gpa, a.size, b.gpa, b.size) {
                    return Err(SurveyError::Overlap {
                        a: a.origin.to_string(),
                        b: b.origin.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Reject loaded sections that overlap any surveyed non-RAM region, or that
    /// fall outside the guest's physical address space. Per pmi spec bc7f581 the
    /// upper bound is the guest address width — `pa_bits` (the image's declared
    /// address-space width, [`Machine::min_addr_space_bits`]) — never a
    /// hardcoded 2^48.
    pub fn cross_validate_loads(
        &self,
        loaded: &[(String, u64, u64)],
        pa_bits: u32,
    ) -> Result<(), SurveyError> {
        for (section, gpa, size) in loaded {
            if *size == 0 {
                continue;
            }
            let end = gpa
                .checked_add(*size)
                .ok_or(SurveyError::LoadAddressOverflow {
                    section: section.clone(),
                    start: *gpa,
                    end: u64::MAX,
                })?;
            if u128::from(end) > (1u128 << pa_bits) {
                return Err(SurveyError::LoadAddressOverflow {
                    section: section.clone(),
                    start: *gpa,
                    end,
                });
            }
            for region in self
                .regions
                .iter()
                .filter(|region| region.kind != RegionKind::Ram)
            {
                if overlaps(*gpa, *size, region.gpa, region.size) {
                    return Err(SurveyError::LoadOverlapsRegion {
                        section: section.clone(),
                        start: *gpa,
                        end,
                        region: region.origin.to_string(),
                        region_start: region.gpa,
                        region_end: region.gpa.saturating_add(region.size),
                    });
                }
            }
        }
        Ok(())
    }
}

fn overlaps(a: u64, a_size: u64, b: u64, b_size: u64) -> bool {
    let a_end = a.saturating_add(a_size);
    let b_end = b.saturating_add(b_size);
    a_size != 0 && b_size != 0 && a < b_end && b < a_end
}

/// The aarch64 interrupt-controller configuration, lifted from the GICv3
/// (`interrupt-controller@…`) and its GICv2m MSI frame (`msi-controller@…`) —
/// the values the hypervisor binds the in-kernel GIC to (replacing the
/// hardcoded `hvf.rs` constants in Stage 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicConfig {
    pub dist_base: u64,
    pub dist_size: u64,
    pub redist_base: u64,
    pub redist_size: u64,
    pub msi_frame_base: u64,
    pub msi_frame_size: u64,
    pub spi_base: u32,
    pub spi_count: u32,
}

/// Interrupt controller kinds that guest-visible interrupt specifiers may
/// target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerKind {
    GicV3,
    Lapic,
    IoApic,
    GicV2mFrame,
}

/// DTB phandle metadata for an interrupt controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptControllerRef {
    pub node: String,
    pub phandle: u32,
    pub kind: ControllerKind,
    pub interrupt_cells: u32,
}

/// A wired interrupt source decoded through its declared `interrupt-parent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiredInterrupt {
    pub node: String,
    pub controller: InterruptControllerRef,
    pub cells: Vec<u32>,
    pub irq: u32,
}

/// DTB phandle metadata for an MSI controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiControllerRef {
    pub node: String,
    pub phandle: u32,
    pub kind: ControllerKind,
}

/// MSI parentage decoded from a device node's `msi-parent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiParentage {
    pub node: String,
    pub controller: MsiControllerRef,
}

#[derive(Debug, Default)]
struct Topology {
    interrupt_controllers: Vec<InterruptControllerRef>,
    msi_controllers: Vec<MsiControllerRef>,
}

impl Topology {
    fn register_interrupt_controller(&mut self, controller: InterruptControllerRef) {
        self.interrupt_controllers.push(controller);
    }

    fn register_msi_controller(&mut self, controller: MsiControllerRef) {
        self.msi_controllers.push(controller);
    }

    fn claim_wired_interrupt(
        &self,
        node: &mut OwnedNode,
        node_path: &'static str,
        expected: ControllerKind,
    ) -> Result<WiredInterrupt, SurveyError> {
        let parent = node.require_u32("interrupt-parent", node_path)?;
        let controller =
            self.resolve_interrupt_controller(parent, node_path, "interrupt-parent", expected)?;
        let interrupts = node.require("interrupts", node_path)?;
        let cells = interrupt_cells(&interrupts, node_path)?;
        if cells.len() != controller.interrupt_cells as usize {
            return Err(SurveyError::BadProperty {
                node: node_path,
                prop: "interrupts",
                reason: "cell count does not match interrupt-parent #interrupt-cells",
            });
        }
        let irq = interrupt_irq(&cells, controller.kind, node_path)?;
        Ok(WiredInterrupt {
            node: node_path.to_string(),
            controller,
            cells,
            irq,
        })
    }

    fn validate_interrupts(
        &self,
        node: &mut OwnedNode,
        node_path: &'static str,
        expected: ControllerKind,
    ) -> Result<(), SurveyError> {
        let parent = node.require_u32("interrupt-parent", node_path)?;
        let controller =
            self.resolve_interrupt_controller(parent, node_path, "interrupt-parent", expected)?;
        let interrupts = node.require("interrupts", node_path)?;
        let cells = interrupt_cells(&interrupts, node_path)?;
        let interrupt_cells = controller.interrupt_cells as usize;
        if interrupt_cells == 0 || cells.len() % interrupt_cells != 0 {
            return Err(SurveyError::BadProperty {
                node: node_path,
                prop: "interrupts",
                reason: "cell count does not match interrupt-parent #interrupt-cells",
            });
        }
        Ok(())
    }

    fn claim_msi_parent(
        &self,
        node: &mut OwnedNode,
        node_path: &'static str,
        expected: ControllerKind,
    ) -> Result<Option<MsiParentage>, SurveyError> {
        if self.msi_controllers.is_empty() && node.property("msi-parent").is_none() {
            return Ok(None);
        }
        let parent = node.require_u32("msi-parent", node_path)?;
        let controller = self.resolve_msi_controller(parent, node_path, "msi-parent", expected)?;
        Ok(Some(MsiParentage {
            node: node_path.to_string(),
            controller,
        }))
    }

    fn resolve_interrupt_controller(
        &self,
        phandle: u32,
        node: &'static str,
        prop: &'static str,
        expected: ControllerKind,
    ) -> Result<InterruptControllerRef, SurveyError> {
        let controller = self
            .interrupt_controllers
            .iter()
            .find(|controller| controller.phandle == phandle)
            .ok_or(SurveyError::UnknownPhandle {
                node,
                prop,
                phandle,
            })?;
        if controller.kind != expected {
            return Err(SurveyError::UnexpectedController {
                node,
                prop,
                actual: controller.kind,
                expected,
            });
        }
        Ok(controller.clone())
    }

    fn resolve_msi_controller(
        &self,
        phandle: u32,
        node: &'static str,
        prop: &'static str,
        expected: ControllerKind,
    ) -> Result<MsiControllerRef, SurveyError> {
        let controller = self
            .msi_controllers
            .iter()
            .find(|controller| controller.phandle == phandle)
            .ok_or(SurveyError::UnknownPhandle {
                node,
                prop,
                phandle,
            })?;
        if controller.kind != expected {
            return Err(SurveyError::UnexpectedController {
                node,
                prop,
                actual: controller.kind,
                expected,
            });
        }
        Ok(controller.clone())
    }
}

/// A fully surveyed machine: every base-DTB node was claimed, every region
/// traces to a property, and the regions are pairwise disjoint. Backend
/// substrate nodes are consumed for coverage and provenance here, but the
/// launch-facing state exposes only the portable device facts that `dillo`
/// composes: PCI windows, UART, virtio-mmio slots, syscon actions, and the
/// resource plan.
#[derive(Debug, Clone)]
pub struct Machine {
    pub arch: Arch,
    /// The PCIe host bridge. Valid only when [`has_pcie`](Self::has_pcie) is
    /// true; a `--pci-slots 0` microVM declares no bridge, in which case this
    /// is a zeroed sentinel ([`Pcie::ZEROED`]) the VMM must not install.
    pub pcie: Pcie,
    /// Whether the base declares a PCIe host bridge (false ⇒ virtio-mmio-only
    /// microVM; skip all PCI fabric).
    pub has_pcie: bool,
    pub plan: ResourcePlan,
    /// The `ns16550a` serial (MMIO), shared by both arches; `None` unless the
    /// base was built with `--serial`.
    pub uart: Option<Uart>,
    /// virtio-mmio transport slots declared by the base DTB. The survey claims
    /// all slots whether or not dillo currently plugs a device into each one.
    pub virtio_mmio: Vec<VirtioMmio>,
    pub poweroff: Option<Syscon>,
    pub reboot: Option<Syscon>,
}

impl Machine {
    /// Survey a base DTB into a `Machine`, proving total coverage.
    pub fn survey(dtb: &[u8], arch: Arch) -> Result<Machine, SurveyError> {
        let tree: Tree<'_> = Tree::parse(dtb).map_err(SurveyError::Parse)?;
        let mut t = OwnedTree::materialize(&tree);
        if t.root().child("cpus").is_some() {
            return Err(SurveyError::BaseHasCpus);
        }
        let mut plan = ResourcePlan::default();
        let mut topology = Topology::default();
        let mut poweroff = None;
        let mut reboot = None;

        // arch-specific substrate (specific → general within the arch).
        match arch {
            Arch::Aarch64 => {
                GicConfig::from_tree(&mut t, &mut plan, &mut topology)?;
                Timer::from_tree(&mut t, &mut plan, &topology)?;
                Psci::from_tree(&mut t, &mut plan)?;
            }
            Arch::X86_64 => {
                X86Intc::from_tree(&mut t, &mut plan, &mut topology)?;
                let (po, rb) = X86Syscon::from_tree(&mut t, &mut plan)?;
                poweroff = Some(po);
                reboot = rb;
            }
        }

        // Shared devices, then the general device last. The serial is the same
        // MMIO `ns16550a` on both arches (present only under `--serial`).
        let uart = Uart::from_tree(&mut t, &mut plan, arch, &topology)?;
        let virtio_mmio = VirtioMmioSlots::from_tree(&mut t, &mut plan, arch, &topology)?;
        let (pcie, has_pcie) = match Pcie::from_tree(&mut t, &mut plan, &topology)? {
            Some(p) => (p, true),
            None => (Pcie::ZEROED, false),
        };
        CoreVm::from_tree(&mut t, &mut plan)?;

        // (a) total coverage: nothing left.
        let root = t.root();
        if root.properties().next().is_some() || root.children().next().is_some() {
            return Err(SurveyError::Uncovered(residual_report(root)));
        }
        // (b) declared regions are disjoint.
        plan.check_disjoint()?;

        Ok(Machine {
            arch,
            pcie,
            has_pcie,
            plan,
            uart,
            virtio_mmio,
            poweroff,
            reboot,
        })
    }

    /// Declared non-RAM regions as `(base, size)` tuples for placement code.
    pub fn placement_regions(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.plan
            .regions()
            .iter()
            .filter(|region| region.kind != RegionKind::Ram)
            .map(|region| (region.gpa, region.size))
    }

    /// Address-space watermark used by HVF: with PCIe present, the BAR
    /// burned-buddy top; otherwise the highest declared region end.
    pub fn min_addr_space_bits(&self) -> u32 {
        let space_top = if self.has_pcie {
            self.pcie.mmio_base + 2 * self.pcie.mmio_size
        } else {
            self.placement_regions()
                .map(|(base, size)| base.saturating_add(size))
                .max()
                .unwrap_or(1 << 20)
        };
        space_top.max(2).next_power_of_two().ilog2()
    }
}

// ── self-routing device constructors ──────────────────────────────────

impl GicConfig {
    /// Claim the GICv3 (`interrupt-controller@…`, `arm,gic-v3`) and the GICv2m
    /// MSI frame (`msi-controller@…`, `arm,gic-v2m-frame`). Nodes are
    /// unit-addressed; matched by name-prefix, then verified by compatible.
    fn from_tree(
        t: &mut OwnedTree,
        plan: &mut ResourcePlan,
        topology: &mut Topology,
    ) -> Result<GicConfig, SurveyError> {
        let root = t.root_mut();

        let intc_name = child_name_prefixed(root, "interrupt-controller@")
            .ok_or(SurveyError::MissingNode("/interrupt-controller@*"))?;
        let intc_path = format!("/{intc_name}");
        let mut intc = root.remove_child(&intc_name).expect("just located");
        require_compatible(&mut intc, "/interrupt-controller", "arm,gic-v3")?;
        let reg = intc.require("reg", "/interrupt-controller")?;
        let (dist_base, dist_size) = reg.reg_pair(0).ok_or(SurveyError::BadProperty {
            node: "/interrupt-controller",
            prop: "reg",
            reason: "missing GICD pair",
        })?;
        let (redist_base, redist_size) = reg.reg_pair(1).ok_or(SurveyError::BadProperty {
            node: "/interrupt-controller",
            prop: "reg",
            reason: "missing GICR pair",
        })?;
        plan.declare_from(
            &reg,
            "/interrupt-controller",
            dist_base,
            dist_size,
            RegionKind::SubstrateMmio,
        );
        plan.declare_from(
            &reg,
            "/interrupt-controller",
            redist_base,
            redist_size,
            RegionKind::SubstrateMmio,
        );
        let interrupt_cells = intc.require_u32("#interrupt-cells", "/interrupt-controller")?;
        if interrupt_cells != 3 {
            return Err(SurveyError::BadProperty {
                node: "/interrupt-controller",
                prop: "#interrupt-cells",
                reason: "expected GICv3 3-cell interrupt specifier",
            });
        }
        intc.ack("interrupt-controller");
        let intc_phandle = intc.require_u32("phandle", "/interrupt-controller")?;
        topology.register_interrupt_controller(InterruptControllerRef {
            node: intc_path,
            phandle: intc_phandle,
            kind: ControllerKind::GicV3,
            interrupt_cells,
        });
        intc.ensure_drained()?;

        let v2m_name = child_name_prefixed(root, "msi-controller@")
            .ok_or(SurveyError::MissingNode("/msi-controller@*"))?;
        let v2m_path = format!("/{v2m_name}");
        let mut v2m = root.remove_child(&v2m_name).expect("just located");
        require_compatible(&mut v2m, "/msi-controller", "arm,gic-v2m-frame")?;
        let vreg = v2m.require("reg", "/msi-controller")?;
        let (msi_frame_base, msi_frame_size) =
            vreg.reg_pair(0).ok_or(SurveyError::BadProperty {
                node: "/msi-controller",
                prop: "reg",
                reason: "missing MSI frame pair",
            })?;
        plan.declare_from(
            &vreg,
            "/msi-controller",
            msi_frame_base,
            msi_frame_size,
            RegionKind::SubstrateMmio,
        );
        let spi_base = v2m.require_u32("arm,msi-base-spi", "/msi-controller")?;
        let spi_count = v2m.require_u32("arm,msi-num-spis", "/msi-controller")?;
        v2m.ack("msi-controller");
        let v2m_phandle = v2m.require_u32("phandle", "/msi-controller")?;
        topology.register_msi_controller(MsiControllerRef {
            node: v2m_path,
            phandle: v2m_phandle,
            kind: ControllerKind::GicV2mFrame,
        });
        v2m.ensure_drained()?;

        Ok(GicConfig {
            dist_base,
            dist_size,
            redist_base,
            redist_size,
            msi_frame_base,
            msi_frame_size,
            spi_base,
            spi_count,
        })
    }
}

/// The ARMv8 generic timer (`/timer`) — system-register driven, no MMIO.
struct Timer;

impl Timer {
    fn from_tree(
        t: &mut OwnedTree,
        _plan: &mut ResourcePlan,
        topology: &Topology,
    ) -> Result<(), SurveyError> {
        let mut timer = t
            .root_mut()
            .remove_child("timer")
            .ok_or(SurveyError::MissingNode("/timer"))?;
        require_compatible(&mut timer, "/timer", "arm,armv8-timer")?;
        topology.validate_interrupts(&mut timer, "/timer", ControllerKind::GicV3)?;
        timer.ack("always-on");
        timer.ensure_drained()
    }
}

impl Psci {
    /// Claim the root-level `/psci` node (`arm,psci.yaml`); there is no
    /// `/firmware` wrapper in the device model.
    fn from_tree(t: &mut OwnedTree, _plan: &mut ResourcePlan) -> Result<Psci, SurveyError> {
        let mut psci = t
            .root_mut()
            .remove_child("psci")
            .ok_or(SurveyError::MissingNode("/psci"))?;

        let compat = psci.require("compatible", "/psci")?;
        let has_psci = compat
            .as_strs()
            .is_some_and(|mut it| it.any(|s| s.starts_with("arm,psci-")));
        if !has_psci {
            return Err(SurveyError::Unsupported {
                node: "/psci",
                prop: "compatible",
                value: compat.as_str().unwrap_or("<list>").to_string(),
            });
        }
        let method = match psci.require("method", "/psci")?.as_str() {
            Some("hvc") => PsciMethod::Hvc,
            Some("smc") => PsciMethod::Smc,
            other => {
                return Err(SurveyError::Unsupported {
                    node: "/psci",
                    prop: "method",
                    value: other.unwrap_or("<non-string>").to_string(),
                });
            }
        };
        psci.ensure_drained()?;
        Ok(Psci { method })
    }
}

impl Uart {
    /// Claim `serial@*` (`ns16550a`, a 16550 over MMIO) — present only under
    /// `--serial`. Absent ⇒ `Ok(None)`. There is no `/apb-pclk` clock node in
    /// the device model.
    fn from_tree(
        t: &mut OwnedTree,
        plan: &mut ResourcePlan,
        arch: Arch,
        topology: &Topology,
    ) -> Result<Option<Uart>, SurveyError> {
        let root = t.root_mut();
        let Some(name) = child_name_prefixed(root, "serial@") else {
            return Ok(None); // no serial in this base
        };
        let mut serial = root.remove_child(&name).expect("just located");
        require_compatible(&mut serial, "/serial", "ns16550a")?;
        let reg = serial.require("reg", "/serial")?;
        let (base, size) = reg.reg_pair(0).ok_or(SurveyError::BadProperty {
            node: "/serial",
            prop: "reg",
            reason: "missing reg pair",
        })?;
        plan.declare_from(&reg, "/serial", base, size, RegionKind::Mmio);
        let reg_shift = serial.require_u32("reg-shift", "/serial")?;
        let interrupt =
            topology.claim_wired_interrupt(&mut serial, "/serial", interrupt_parent_kind(arch))?;
        let irq = interrupt.irq;
        serial.ack("reg-io-width");
        serial.ack("clock-frequency");
        serial.ack("current-speed");
        serial.ensure_drained()?;

        Ok(Some(Uart {
            base,
            size,
            reg_shift,
            irq,
            interrupt,
        }))
    }
}

/// Every `virtio_mmio@*` transport slot (`virtio,mmio`). Each is a fixed MMIO
/// window + a wired IRQ, declared on the board whether or not a backend is
/// plugged. The survey drains ALL of them so none is an uncovered residual.
struct VirtioMmioSlots;

impl VirtioMmioSlots {
    fn from_tree(
        t: &mut OwnedTree,
        plan: &mut ResourcePlan,
        arch: Arch,
        topology: &Topology,
    ) -> Result<Vec<VirtioMmio>, SurveyError> {
        let root = t.root_mut();
        let mut slots = Vec::new();
        while let Some(name) = child_name_prefixed(root, "virtio_mmio@") {
            let mut node = root.remove_child(&name).expect("just located");
            require_compatible(&mut node, "/virtio_mmio", "virtio,mmio")?;
            let reg = node.require("reg", "/virtio_mmio")?;
            let (base, size) = reg.reg_pair(0).ok_or(SurveyError::BadProperty {
                node: "/virtio_mmio",
                prop: "reg",
                reason: "missing reg pair",
            })?;
            plan.declare_from(&reg, "/virtio_mmio", base, size, RegionKind::Mmio);
            let interrupt = topology.claim_wired_interrupt(
                &mut node,
                "/virtio_mmio",
                interrupt_parent_kind(arch),
            )?;
            let irq = interrupt.irq;
            node.ensure_drained()?;
            slots.push(VirtioMmio {
                base,
                size,
                irq,
                interrupt,
            });
        }
        slots.sort_by_key(|slot| slot.base);
        Ok(slots)
    }
}

impl Pcie {
    /// Claim the `pcie@*` ECAM host bridge (`pci-host-ecam-generic`), matched by
    /// name-prefix then verified by compatible. A `--pci-slots 0` microVM
    /// declares no bridge ⇒ `Ok(None)`.
    fn from_tree(
        t: &mut OwnedTree,
        plan: &mut ResourcePlan,
        topology: &Topology,
    ) -> Result<Option<Pcie>, SurveyError> {
        let root = t.root_mut();
        let Some(name) = child_name_prefixed(root, "pcie@") else {
            return Ok(None); // no host bridge in this base
        };
        let mut pci = root.remove_child(&name).expect("just located");

        require_compatible(&mut pci, "/pcie", "pci-host-ecam-generic")?;
        let reg = pci.require("reg", "/pcie")?;
        let (ecam_base, ecam_size) = reg.reg_pair(0).ok_or(SurveyError::BadProperty {
            node: "/pcie",
            prop: "reg",
            reason: "missing ECAM pair",
        })?;
        plan.declare_from(&reg, "/pcie", ecam_base, ecam_size, RegionKind::EcamWindow);

        let ranges = pci.require("ranges", "/pcie")?;
        let (mmio_base, mmio_size) = pci_window(&ranges).ok_or(SurveyError::BadProperty {
            node: "/pcie",
            prop: "ranges",
            reason: "expected at least one 7-cell window",
        })?;
        plan.declare_from(
            &ranges,
            "/pcie",
            mmio_base,
            mmio_size,
            RegionKind::BarWindow,
        );

        let bus = pci.require("bus-range", "/pcie")?;
        let bus_cells: Vec<u32> = bus
            .as_u32s()
            .ok_or(SurveyError::BadProperty {
                node: "/pcie",
                prop: "bus-range",
                reason: "not u32 cells",
            })?
            .collect();
        if bus_cells.len() != 2 {
            return Err(SurveyError::BadProperty {
                node: "/pcie",
                prop: "bus-range",
                reason: "expected two cells",
            });
        }

        pci.ack("device_type");
        pci.ack("#address-cells");
        pci.ack("#size-cells");
        pci.ack("dma-coherent");
        pci.reject("dma-ranges", "/pcie")?;
        let msi = topology.claim_msi_parent(&mut pci, "/pcie", ControllerKind::GicV2mFrame)?;
        pci.ensure_drained()?;

        Ok(Some(Pcie {
            ecam_base,
            ecam_size,
            bus_min: bus_cells[0] as u8,
            bus_max: bus_cells[1] as u8,
            mmio_base,
            mmio_size,
            msi,
        }))
    }
}

/// The general device: runs last, claims root's own grammar and `/chosen`,
/// rejects a base `/cpus`, and sweeps any now-empty containers.
struct CoreVm;

impl CoreVm {
    fn from_tree(t: &mut OwnedTree, _plan: &mut ResourcePlan) -> Result<(), SurveyError> {
        let root = t.root_mut();
        if root.child("cpus").is_some() {
            return Err(SurveyError::BaseHasCpus);
        }
        root.ack("#address-cells");
        root.ack("#size-cells");
        root.ack("model");
        root.ack("compatible");

        if let Some(mut chosen) = root.remove_child("chosen") {
            chosen.ack("bootargs");
            chosen.ack("linux,initrd-start");
            chosen.ack("linux,initrd-end");
            chosen.ack("stdout-path");
            // No `kaslr-seed` ack: it is guest-generated entropy and MUST NOT
            // appear in the measured base DTB. tatu injects it at boot via a
            // trusted overlay (see arma deps/tatu `kaslr.rs`). A seed present
            // here is non-conformant and `ensure_drained` rejects it.
            chosen.ensure_drained()?;
        }
        if let Some(mut aliases) = root.remove_child("aliases") {
            aliases.ack("serial0");
            aliases.ensure_drained()?;
        }

        // Sweep now-empty containers a leaf device may have emptied.
        let empties: Vec<String> = root
            .children()
            .filter(|c| c.properties().next().is_none() && c.children().next().is_none())
            .map(|c| c.name().to_string())
            .collect();
        for name in empties {
            root.remove_child(&name);
        }
        Ok(())
    }
}

// ── x86-64 devices ─────────────────────────────────────────────────────

/// x86 LAPIC + IOAPIC — two SEPARATE `interrupt-controller@*` nodes
/// (`intel,ce4100-lapic` and `intel,ce4100-ioapic`), each with its own `reg`.
struct X86Intc;

impl X86Intc {
    fn from_tree(
        t: &mut OwnedTree,
        plan: &mut ResourcePlan,
        topology: &mut Topology,
    ) -> Result<(MmioRegion, MmioRegion), SurveyError> {
        let lapic = X86Intc::claim_one(
            t,
            "intel,ce4100-lapic",
            "/lapic",
            plan,
            topology,
            ControllerKind::Lapic,
        )?;
        let ioapic = X86Intc::claim_one(
            t,
            "intel,ce4100-ioapic",
            "/ioapic",
            plan,
            topology,
            ControllerKind::IoApic,
        )?;
        Ok((lapic, ioapic))
    }

    /// Claim one `interrupt-controller@*` node by compatible, declaring its
    /// `reg` window as substrate MMIO. Both x86 intc nodes share the
    /// `interrupt-controller@` prefix, so they are disambiguated by compatible.
    fn claim_one(
        t: &mut OwnedTree,
        compat: &'static str,
        path: &'static str,
        plan: &mut ResourcePlan,
        topology: &mut Topology,
        controller_kind: ControllerKind,
    ) -> Result<MmioRegion, SurveyError> {
        let root = t.root_mut();
        let name = root
            .children()
            .find(|c| {
                c.name().starts_with("interrupt-controller@")
                    && c.property("compatible")
                        .and_then(|p| p.as_str())
                        .is_some_and(|s| s == compat)
            })
            .map(|c| c.name().to_string())
            .ok_or(SurveyError::MissingNode(path))?;
        let mut node = root.remove_child(&name).expect("just located");
        node.ack("compatible"); // matched above
        let reg = node.require("reg", path)?;
        let (base, size) = reg.reg_pair(0).ok_or(SurveyError::BadProperty {
            node: path,
            prop: "reg",
            reason: "missing reg pair",
        })?;
        plan.declare_from(&reg, path, base, size, RegionKind::SubstrateMmio);
        let interrupt_cells = node.require_u32("#interrupt-cells", path)?;
        node.ack("interrupt-controller");
        let phandle = node.require_u32("phandle", path)?;
        topology.register_interrupt_controller(InterruptControllerRef {
            node: path.to_string(),
            phandle,
            kind: controller_kind,
            interrupt_cells,
        });
        node.ensure_drained()?;
        Ok(MmioRegion { base, size })
    }
}

/// x86 power: standalone `poweroff@*` (`syscon-poweroff`) and optional
/// `reboot@*` (`syscon-reboot`), each with its OWN `reg` + trigger `value` (no
/// `/syscon` container, no `regmap`/`offset`/`mask`).
struct X86Syscon;

impl X86Syscon {
    fn from_tree(
        t: &mut OwnedTree,
        plan: &mut ResourcePlan,
    ) -> Result<(Syscon, Option<Syscon>), SurveyError> {
        let root = t.root_mut();
        let poweroff = syscon_action(root, "poweroff@", "syscon-poweroff", "/poweroff", plan)?
            .ok_or(SurveyError::MissingNode("/poweroff@*"))?;
        let reboot = syscon_action(root, "reboot@", "syscon-reboot", "/reboot", plan)?;
        Ok((poweroff, reboot))
    }
}

/// Claim a standalone `syscon-{poweroff,reboot}` action node (matched by
/// name-prefix, verified by compatible), declaring its own `reg` as MMIO. The
/// trigger is a write of `value` at the node's reg (offset 0), masking the low
/// byte.
fn syscon_action(
    root: &mut OwnedNode,
    prefix: &str,
    compat: &'static str,
    path: &'static str,
    plan: &mut ResourcePlan,
) -> Result<Option<Syscon>, SurveyError> {
    let Some(name) = child_name_prefixed(root, prefix) else {
        return Ok(None);
    };
    let mut node = root.remove_child(&name).expect("just located");
    require_compatible(&mut node, path, compat)?;
    let reg = node.require("reg", path)?;
    let (base, size) = reg.reg_pair(0).ok_or(SurveyError::BadProperty {
        node: path,
        prop: "reg",
        reason: "missing reg pair",
    })?;
    plan.declare_from(&reg, path, base, size, RegionKind::Mmio);
    let value = node.require_u32("value", path)?;
    node.ensure_drained()?;
    Ok(Some(Syscon {
        base,
        offset: 0,
        value,
        mask: 0xFF,
    }))
}

// ── helpers ────────────────────────────────────────────────────────────

fn require_compatible(
    node: &mut OwnedNode,
    path: &'static str,
    expected: &'static str,
) -> Result<(), SurveyError> {
    let compat = node.require("compatible", path)?;
    match compat.as_str() {
        Some(s) if s == expected => Ok(()),
        Some(_) | None => Err(SurveyError::Unsupported {
            node: path,
            prop: "compatible",
            value: compat.as_str().unwrap_or("<non-string>").to_string(),
        }),
    }
}

fn interrupt_parent_kind(arch: Arch) -> ControllerKind {
    match arch {
        Arch::Aarch64 => ControllerKind::GicV3,
        Arch::X86_64 => ControllerKind::IoApic,
    }
}

fn interrupt_cells(prop: &OwnedProperty, node: &'static str) -> Result<Vec<u32>, SurveyError> {
    let cells = prop
        .as_u32s()
        .ok_or(SurveyError::BadProperty {
            node,
            prop: "interrupts",
            reason: "not u32 cells",
        })?
        .collect();
    Ok(cells)
}

fn interrupt_irq(
    cells: &[u32],
    controller: ControllerKind,
    node: &'static str,
) -> Result<u32, SurveyError> {
    let index = match controller {
        // GIC form: <type number flags>. The runtime wants the interrupt number,
        // not the type cell.
        ControllerKind::GicV3 => 1,
        // IO-APIC form: <pin sense>. The runtime wants the pin/GSI.
        ControllerKind::IoApic => 0,
        ControllerKind::Lapic | ControllerKind::GicV2mFrame => {
            return Err(SurveyError::BadProperty {
                node,
                prop: "interrupts",
                reason: "controller cannot decode wired device interrupts",
            });
        }
    };
    cells.get(index).copied().ok_or(SurveyError::BadProperty {
        node,
        prop: "interrupts",
        reason: "too few interrupt cells",
    })
}

fn child_name_prefixed(node: &OwnedNode, prefix: &str) -> Option<String> {
    node.children()
        .find(|c| c.name().starts_with(prefix))
        .map(|c| c.name().to_string())
}

/// First `ranges` window CPU base + size: `<phys.hi mid lo cpu.hi cpu.lo size.hi size.lo>`.
fn pci_window(prop: &OwnedProperty) -> Option<(u64, u64)> {
    let cells: Vec<u32> = prop.as_u32s()?.collect();
    let w = cells.get(0..7)?;
    let cpu_base = (u64::from(w[3]) << 32) | u64::from(w[4]);
    let size = (u64::from(w[5]) << 32) | u64::from(w[6]);
    Some((cpu_base, size))
}

fn residual_report(root: &OwnedNode) -> String {
    let mut parts: Vec<String> = Vec::new();
    let props: Vec<&str> = root.properties().map(OwnedProperty::name).collect();
    if !props.is_empty() {
        parts.push(format!("root props {props:?}"));
    }
    for c in root.children() {
        let cp: Vec<&str> = c.properties().map(OwnedProperty::name).collect();
        parts.push(format!("node /{} props {:?}", c.name(), cp));
    }
    parts.join("; ")
}

/// Draining/claiming helpers on the foreign owned types.
trait NodeExt {
    /// Remove a required property, or error if absent.
    fn require(
        &mut self,
        prop: &'static str,
        node: &'static str,
    ) -> Result<OwnedProperty, SurveyError>;
    /// Remove a required `u32` property, or error if absent/malformed.
    fn require_u32(&mut self, prop: &'static str, node: &'static str) -> Result<u32, SurveyError>;
    /// Remove a property that is acknowledged but carries no modeled value.
    fn ack(&mut self, prop: &'static str);
    /// Fail closed on a recognized property whose semantics are not modeled.
    fn reject(&self, prop: &'static str, node: &'static str) -> Result<(), SurveyError>;
    /// Error unless the node has no remaining properties or children.
    fn ensure_drained(&self) -> Result<(), SurveyError>;
}

impl NodeExt for OwnedNode {
    fn require(
        &mut self,
        prop: &'static str,
        node: &'static str,
    ) -> Result<OwnedProperty, SurveyError> {
        self.remove_property(prop)
            .ok_or(SurveyError::MissingProperty {
                node: node.to_string(),
                prop,
            })
    }

    fn require_u32(&mut self, prop: &'static str, node: &'static str) -> Result<u32, SurveyError> {
        self.require(prop, node)?
            .as_u32()
            .ok_or(SurveyError::BadProperty {
                node,
                prop,
                reason: "expected single u32",
            })
    }

    fn ack(&mut self, prop: &'static str) {
        let _ = self.remove_property(prop);
    }

    fn reject(&self, prop: &'static str, node: &'static str) -> Result<(), SurveyError> {
        if self.properties().any(|p| p.name() == prop) {
            Err(SurveyError::Unsupported {
                node,
                prop,
                value: "present".to_string(),
            })
        } else {
            Ok(())
        }
    }

    fn ensure_drained(&self) -> Result<(), SurveyError> {
        let props: Vec<String> = self.properties().map(|p| p.name().to_string()).collect();
        let children: Vec<String> = self.children().map(|c| c.name().to_string()).collect();
        if props.is_empty() && children.is_empty() {
            Ok(())
        } else {
            Err(SurveyError::Leftover {
                node: self.name().to_string(),
                props,
                children,
            })
        }
    }
}

trait PropExt {
    /// Read the `idx`-th `(base, size)` pair from a root-governed (2-cell/2-cell)
    /// `reg` property.
    fn reg_pair(&self, idx: usize) -> Option<(u64, u64)>;
}

impl PropExt for OwnedProperty {
    fn reg_pair(&self, idx: usize) -> Option<(u64, u64)> {
        let cells: Vec<u32> = self.as_u32s()?.collect();
        let i = idx * 4;
        let b = cells.get(i..i + 4)?;
        let base = (u64::from(b[0]) << 32) | u64::from(b[1]);
        let size = (u64::from(b[2]) << 32) | u64::from(b[3]);
        Some((base, size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GICD 0x0800_0000/0x1_0000, GICR 0x0810_0000/0x200_0000.
    const GICD_BASE: u64 = 0x0800_0000;
    const GICR_BASE: u64 = 0x0810_0000;
    const V2M_BASE: u64 = 0x0A10_0000;
    const SERIAL_BASE: u64 = 0x0A20_0000;
    const VIRTIO_BASE: u64 = 0x0A30_0000;
    const ECAM_BASE: u64 = 0x0C00_0000;
    const PCI_MMIO_BASE: u64 = 0x0C10_0000;

    fn reg2(base: u64, size: u64) -> Vec<u32> {
        vec![
            (base >> 32) as u32,
            base as u32,
            (size >> 32) as u32,
            size as u32,
        ]
    }

    /// An aarch64 base DTB matching arma's device-model emission (with serial
    /// and one virtio-mmio slot).
    fn base_root() -> OwnedNode {
        let mut intc_reg = reg2(GICD_BASE, 0x1_0000);
        intc_reg.extend(reg2(GICR_BASE, 0x200_0000));

        let intc = OwnedNode::new("interrupt-controller@8000000")
            .with_property(OwnedProperty::new("compatible").with_str("arm,gic-v3"))
            .with_property(OwnedProperty::new("#interrupt-cells").with_u32(3))
            .with_property(OwnedProperty::new("interrupt-controller"))
            .with_property(OwnedProperty::new("reg").with_u32s(&intc_reg))
            .with_property(OwnedProperty::new("phandle").with_u32(1));

        let v2m = OwnedNode::new("msi-controller@a100000")
            .with_property(OwnedProperty::new("compatible").with_str("arm,gic-v2m-frame"))
            .with_property(OwnedProperty::new("msi-controller"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(V2M_BASE, 0x1_0000)))
            .with_property(OwnedProperty::new("arm,msi-base-spi").with_u32(64))
            .with_property(OwnedProperty::new("arm,msi-num-spis").with_u32(32))
            .with_property(OwnedProperty::new("phandle").with_u32(3));

        let timer = OwnedNode::new("timer")
            .with_property(OwnedProperty::new("compatible").with_str("arm,armv8-timer"))
            .with_property(
                OwnedProperty::new("interrupts")
                    .with_u32s(&[1, 13, 0xff08, 1, 14, 0xff08, 1, 11, 0xff08, 1, 10, 0xff08]),
            )
            .with_property(OwnedProperty::new("interrupt-parent").with_u32(1))
            .with_property(OwnedProperty::new("always-on"));

        let psci = OwnedNode::new("psci")
            .with_property(
                OwnedProperty::new("compatible").with_strs(&["arm,psci-1.0", "arm,psci-0.2"]),
            )
            .with_property(OwnedProperty::new("method").with_str("hvc"));

        let serial = OwnedNode::new("serial@9000000")
            .with_property(OwnedProperty::new("compatible").with_str("ns16550a"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(SERIAL_BASE, 0x1000)))
            .with_property(OwnedProperty::new("reg-shift").with_u32(2))
            .with_property(OwnedProperty::new("reg-io-width").with_u32(4))
            .with_property(OwnedProperty::new("clock-frequency").with_u32(3_686_400))
            .with_property(OwnedProperty::new("current-speed").with_u32(115_200))
            .with_property(OwnedProperty::new("interrupt-parent").with_u32(1))
            .with_property(OwnedProperty::new("interrupts").with_u32s(&[0, 1, 4]));

        let virtio = OwnedNode::new("virtio_mmio@a000000")
            .with_property(OwnedProperty::new("compatible").with_str("virtio,mmio"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(VIRTIO_BASE, 0x200)))
            .with_property(OwnedProperty::new("interrupt-parent").with_u32(1))
            .with_property(OwnedProperty::new("interrupts").with_u32s(&[0, 16, 1]));

        let pci = OwnedNode::new("pcie@c000000")
            .with_property(OwnedProperty::new("compatible").with_str("pci-host-ecam-generic"))
            .with_property(OwnedProperty::new("device_type").with_str("pci"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(ECAM_BASE, 0x10_0000)))
            .with_property(OwnedProperty::new("bus-range").with_u32s(&[0, 0]))
            .with_property(OwnedProperty::new("#address-cells").with_u32(3))
            .with_property(OwnedProperty::new("#size-cells").with_u32(2))
            .with_property(OwnedProperty::new("ranges").with_u32s(&[
                0x0300_0000,
                0,
                PCI_MMIO_BASE as u32,
                0,
                PCI_MMIO_BASE as u32,
                0,
                0x03F0_0000,
            ]))
            .with_property(OwnedProperty::new("dma-coherent"))
            .with_property(OwnedProperty::new("msi-parent").with_u32(3));

        OwnedNode::new("")
            .with_property(OwnedProperty::new("#address-cells").with_u32(2))
            .with_property(OwnedProperty::new("#size-cells").with_u32(2))
            .with_property(OwnedProperty::new("model").with_str("Arma Virtual Platform"))
            .with_property(OwnedProperty::new("compatible").with_str("arma,v1"))
            .with_child(
                OwnedNode::new("chosen")
                    .with_property(
                        OwnedProperty::new("bootargs").with_str("earlycon console=ttyS0"),
                    )
                    .with_property(OwnedProperty::new("stdout-path").with_str("serial0:115200n8")),
            )
            .with_child(
                OwnedNode::new("aliases")
                    .with_property(OwnedProperty::new("serial0").with_str("/serial@9000000")),
            )
            .with_child(intc)
            .with_child(v2m)
            .with_child(timer)
            .with_child(psci)
            .with_child(serial)
            .with_child(virtio)
            .with_child(pci)
    }

    fn dtb(root: OwnedNode) -> Vec<u8> {
        OwnedTree::new(root).encode().expect("encode base")
    }

    #[test]
    fn base_drains_to_empty_and_binds_devices() {
        let m = Machine::survey(&dtb(base_root()), Arch::Aarch64).expect("survey ok");

        let uart = m.uart.as_ref().expect("uart present");
        assert_eq!(uart.base, SERIAL_BASE);
        assert_eq!(uart.size, 0x1000);
        assert_eq!(uart.reg_shift, 2);
        assert_eq!(uart.irq, 1);

        assert_eq!(m.virtio_mmio.len(), 1);
        assert_eq!(m.virtio_mmio[0].base, VIRTIO_BASE);
        assert_eq!(m.virtio_mmio[0].size, 0x200);
        assert_eq!(m.virtio_mmio[0].irq, 16);

        assert!(m.has_pcie);
        assert_eq!(m.pcie.ecam_base, ECAM_BASE);
        assert_eq!(m.pcie.mmio_base, PCI_MMIO_BASE);

        // Regions: GICD, GICR, MSI frame, serial, virtio-mmio, ECAM, PCI MMIO.
        assert_eq!(m.plan.regions().len(), 7);
        assert_eq!(
            m.placement_regions().collect::<Vec<_>>(),
            vec![
                (GICD_BASE, 0x1_0000),
                (GICR_BASE, 0x200_0000),
                (V2M_BASE, 0x1_0000),
                (SERIAL_BASE, 0x1000),
                (VIRTIO_BASE, 0x200),
                (ECAM_BASE, 0x10_0000),
                (PCI_MMIO_BASE, 0x03F0_0000),
            ]
        );
        assert_eq!(
            m.min_addr_space_bits(),
            (PCI_MMIO_BASE + 2 * 0x03F0_0000)
                .next_power_of_two()
                .ilog2()
        );
    }

    #[test]
    fn base_without_serial_has_no_uart_and_still_drains() {
        let mut root = base_root();
        root.remove_child("serial@9000000");
        let m = Machine::survey(&dtb(root), Arch::Aarch64).expect("survey ok");
        assert!(m.uart.is_none());
        // GICD, GICR, MSI frame, virtio-mmio, ECAM, PCI MMIO — no serial.
        assert_eq!(m.plan.regions().len(), 6);
    }

    #[test]
    fn firecracker_style_no_pci_drains_to_empty() {
        // A microVM with no PCIe bridge and several virtio-mmio slots.
        let mut root = base_root();
        root.remove_child("pcie@c000000");
        for (i, addr) in [0x0A40_0000u64, 0x0A41_0000, 0x0A42_0000]
            .iter()
            .enumerate()
        {
            root.set_child(
                OwnedNode::new(&format!("virtio_mmio@{addr:x}"))
                    .with_property(OwnedProperty::new("compatible").with_str("virtio,mmio"))
                    .with_property(OwnedProperty::new("reg").with_u32s(&reg2(*addr, 0x200)))
                    .with_property(OwnedProperty::new("interrupt-parent").with_u32(1))
                    .with_property(OwnedProperty::new("interrupts").with_u32s(&[
                        0,
                        17 + i as u32,
                        1,
                    ])),
            );
        }
        let m = Machine::survey(&dtb(root), Arch::Aarch64).expect("survey ok");
        assert!(!m.has_pcie);
        assert_eq!(m.pcie.ecam_base, 0); // ZEROED sentinel
        assert_eq!(m.virtio_mmio.len(), 4);
        assert_eq!(
            m.virtio_mmio
                .iter()
                .map(|slot| slot.irq)
                .collect::<Vec<_>>(),
            vec![16, 17, 18, 19]
        );
        assert_eq!(
            m.min_addr_space_bits(),
            (0x0A42_0000u64 + 0x200).next_power_of_two().ilog2()
        );
        // GICD, GICR, MSI frame, serial, four virtio-mmio (1 base + 3 added).
        assert_eq!(m.plan.regions().len(), 8);
    }

    #[test]
    fn aarch64_missing_interrupt_parent_is_rejected() {
        let mut root = base_root();
        root.child_mut("serial@9000000")
            .unwrap()
            .remove_property("interrupt-parent");

        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::MissingProperty {
                    ref node,
                    prop: "interrupt-parent"
                } if node == "/serial"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn aarch64_unknown_interrupt_parent_is_rejected() {
        let mut root = base_root();
        root.child_mut("serial@9000000")
            .unwrap()
            .property_mut("interrupt-parent")
            .unwrap()
            .set_u32(99);

        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::UnknownPhandle {
                    node: "/serial",
                    prop: "interrupt-parent",
                    phandle: 99
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn aarch64_interrupt_cells_must_match_parent() {
        let mut root = base_root();
        root.child_mut("virtio_mmio@a000000")
            .unwrap()
            .property_mut("interrupts")
            .unwrap()
            .set_u32s(&[0, 16]);

        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::BadProperty {
                    node: "/virtio_mmio",
                    prop: "interrupts",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn aarch64_missing_msi_parent_is_rejected() {
        let mut root = base_root();
        root.child_mut("pcie@c000000")
            .unwrap()
            .remove_property("msi-parent");

        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::MissingProperty {
                    ref node,
                    prop: "msi-parent"
                } if node == "/pcie"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn pci_dma_ranges_is_rejected_until_modeled() {
        let mut root = base_root();
        root.child_mut("pcie@c000000").unwrap().set_property(
            OwnedProperty::new("dma-ranges").with_u32s(&[
                0x0300_0000,
                0,
                PCI_MMIO_BASE as u32,
                0,
                PCI_MMIO_BASE as u32,
                0,
                0x03F0_0000,
            ]),
        );

        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::Unsupported {
                    node: "/pcie",
                    prop: "dma-ranges",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn extra_node_is_uncovered() {
        let mut root = base_root();
        root.set_child(
            OwnedNode::new("bogus@0").with_property(OwnedProperty::new("foo").with_u32(1)),
        );
        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(matches!(err, SurveyError::Uncovered(_)), "got {err:?}");
    }

    #[test]
    fn extra_property_is_left_over() {
        let mut root = base_root();
        root.child_mut("timer")
            .unwrap()
            .set_property(OwnedProperty::new("surprise").with_u32(1));
        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::Leftover { .. } | SurveyError::Uncovered(_)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn base_with_cpus_is_rejected() {
        let mut root = base_root();
        root.set_child(
            OwnedNode::new("cpus").with_property(OwnedProperty::new("#address-cells").with_u32(1)),
        );
        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(matches!(err, SurveyError::BaseHasCpus), "got {err:?}");
    }

    #[test]
    fn overlapping_regions_are_rejected() {
        let mut root = base_root();
        // Move the serial onto the ECAM window so two declared regions overlap.
        root.child_mut("serial@9000000")
            .unwrap()
            .property_mut("reg")
            .unwrap()
            .set_u32s(&reg2(ECAM_BASE, 0x1000));
        let err = Machine::survey(&dtb(root), Arch::Aarch64).unwrap_err();
        assert!(matches!(err, SurveyError::Overlap { .. }), "got {err:?}");
    }

    #[test]
    fn cross_validate_loads_rejects_declared_region_overlap() {
        let m = Machine::survey(&dtb(base_root()), Arch::Aarch64).expect("survey ok");

        let pa_bits = m.min_addr_space_bits();
        let err = m
            .plan
            .cross_validate_loads(&[("kernel".to_string(), SERIAL_BASE, 0x1000)], pa_bits)
            .unwrap_err();

        assert!(
            matches!(
                err,
                SurveyError::LoadOverlapsRegion {
                    ref section,
                    ref region,
                    region_start: SERIAL_BASE,
                    ..
                } if section == "kernel" && region == "/serial:reg"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn cross_validate_loads_accepts_zero_sized_sections() {
        let m = Machine::survey(&dtb(base_root()), Arch::Aarch64).expect("survey ok");

        let pa_bits = m.min_addr_space_bits();
        m.plan
            .cross_validate_loads(&[("zero".to_string(), SERIAL_BASE, 0)], pa_bits)
            .expect("zero-sized section ignored");
    }

    #[test]
    fn cross_validate_loads_rejects_address_above_guest_width() {
        let m = Machine::survey(&dtb(base_root()), Arch::Aarch64).expect("survey ok");

        // An address at 2^48 exceeds the test platform's declared address
        // width (min_addr_space_bits ≪ 48), so it is rejected by the derived
        // bound — not a hardcoded constant (pmi spec bc7f581).
        let pa_bits = m.min_addr_space_bits();
        assert!(pa_bits < 48);
        let err = m
            .plan
            .cross_validate_loads(&[("too-high".to_string(), 1u64 << 48, 1)], pa_bits)
            .unwrap_err();

        assert!(
            matches!(
                err,
                SurveyError::LoadAddressOverflow { ref section, .. } if section == "too-high"
            ),
            "got {err:?}"
        );
    }

    // x86-64 base layout (arma `src/base_dtb/x86_64.rs`).
    const LAPIC_BASE: u64 = 0xFEE0_0000;
    const IOAPIC_BASE: u64 = 0xFEC0_0000;
    const POWEROFF_BASE: u64 = 0x0901_0000;
    const REBOOT_BASE: u64 = 0x0902_0000;
    const X86_SERIAL_BASE: u64 = 0x0900_0000;
    const X86_ECAM_BASE: u64 = 0xB000_0000;
    const X86_PCI_MMIO_BASE: u64 = 0xC000_0000;

    /// An x86-64 base DTB matching arma's device-model emission (with serial).
    fn x86_base_root() -> OwnedNode {
        let lapic = OwnedNode::new("interrupt-controller@fee00000")
            .with_property(OwnedProperty::new("compatible").with_str("intel,ce4100-lapic"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(LAPIC_BASE, 0x1000)))
            .with_property(OwnedProperty::new("#interrupt-cells").with_u32(2))
            .with_property(OwnedProperty::new("interrupt-controller"))
            .with_property(OwnedProperty::new("phandle").with_u32(1));

        let ioapic = OwnedNode::new("interrupt-controller@fec00000")
            .with_property(OwnedProperty::new("compatible").with_str("intel,ce4100-ioapic"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(IOAPIC_BASE, 0x1000)))
            .with_property(OwnedProperty::new("#interrupt-cells").with_u32(2))
            .with_property(OwnedProperty::new("interrupt-controller"))
            .with_property(OwnedProperty::new("phandle").with_u32(2));

        let poweroff = OwnedNode::new("poweroff@9010000")
            .with_property(OwnedProperty::new("compatible").with_str("syscon-poweroff"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(POWEROFF_BASE, 0x4)))
            .with_property(OwnedProperty::new("value").with_u32(0x34));

        let reboot = OwnedNode::new("reboot@9020000")
            .with_property(OwnedProperty::new("compatible").with_str("syscon-reboot"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(REBOOT_BASE, 0x4)))
            .with_property(OwnedProperty::new("value").with_u32(0x1));

        let serial = OwnedNode::new("serial@9000000")
            .with_property(OwnedProperty::new("compatible").with_str("ns16550a"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(X86_SERIAL_BASE, 0x1000)))
            .with_property(OwnedProperty::new("reg-shift").with_u32(2))
            .with_property(OwnedProperty::new("reg-io-width").with_u32(4))
            .with_property(OwnedProperty::new("clock-frequency").with_u32(3_686_400))
            .with_property(OwnedProperty::new("current-speed").with_u32(115_200))
            .with_property(OwnedProperty::new("interrupt-parent").with_u32(2))
            .with_property(OwnedProperty::new("interrupts").with_u32s(&[4, 1]));

        let pci = OwnedNode::new("pcie@b0000000")
            .with_property(OwnedProperty::new("compatible").with_str("pci-host-ecam-generic"))
            .with_property(OwnedProperty::new("device_type").with_str("pci"))
            .with_property(OwnedProperty::new("reg").with_u32s(&reg2(X86_ECAM_BASE, 0x10_0000)))
            .with_property(OwnedProperty::new("bus-range").with_u32s(&[0, 0]))
            .with_property(OwnedProperty::new("#address-cells").with_u32(3))
            .with_property(OwnedProperty::new("#size-cells").with_u32(2))
            .with_property(OwnedProperty::new("ranges").with_u32s(&[
                0x0300_0000,
                0,
                X86_PCI_MMIO_BASE as u32,
                0,
                X86_PCI_MMIO_BASE as u32,
                0,
                0x1000_0000,
            ]));

        OwnedNode::new("")
            .with_property(OwnedProperty::new("#address-cells").with_u32(2))
            .with_property(OwnedProperty::new("#size-cells").with_u32(2))
            .with_property(OwnedProperty::new("model").with_str("Arma Virtual Platform"))
            .with_property(OwnedProperty::new("compatible").with_str("arma,v1"))
            .with_child(
                OwnedNode::new("chosen")
                    .with_property(
                        OwnedProperty::new("bootargs").with_str("earlycon console=ttyS0"),
                    )
                    .with_property(OwnedProperty::new("stdout-path").with_str("serial0:115200n8")),
            )
            .with_child(
                OwnedNode::new("aliases")
                    .with_property(OwnedProperty::new("serial0").with_str("/serial@9000000")),
            )
            .with_child(lapic)
            .with_child(ioapic)
            .with_child(poweroff)
            .with_child(reboot)
            .with_child(serial)
            .with_child(pci)
    }

    #[test]
    fn x86_base_drains_and_binds() {
        let m = Machine::survey(&dtb(x86_base_root()), Arch::X86_64).expect("survey ok");

        let po = m.poweroff.expect("poweroff");
        assert_eq!((po.base, po.value, po.mask), (POWEROFF_BASE, 0x34, 0xFF));
        let rb = m.reboot.expect("reboot");
        assert_eq!((rb.base, rb.value), (REBOOT_BASE, 0x1));
        // Serial is the shared MMIO ns16550a; on x86 the IRQ is the IO-APIC pin.
        let s = m.uart.expect("serial");
        assert_eq!((s.base, s.irq), (X86_SERIAL_BASE, 4));
        assert!(m.has_pcie);
        assert_eq!(m.pcie.ecam_base, X86_ECAM_BASE);
        assert_eq!(m.pcie.mmio_base, X86_PCI_MMIO_BASE);
        // LAPIC, IOAPIC, poweroff, reboot, serial, ECAM, PCI MMIO.
        assert_eq!(m.plan.regions().len(), 7);
    }

    #[test]
    fn x86_base_without_serial_has_no_uart_and_still_drains() {
        let mut root = x86_base_root();
        root.remove_child("serial@9000000");
        let m = Machine::survey(&dtb(root), Arch::X86_64).expect("survey ok");
        assert!(m.uart.is_none());
    }

    #[test]
    fn x86_virtio_mmio_interrupt_uses_ioapic_pin_cell() {
        let mut root = x86_base_root();
        root.set_child(
            OwnedNode::new("virtio_mmio@9100000")
                .with_property(OwnedProperty::new("compatible").with_str("virtio,mmio"))
                .with_property(OwnedProperty::new("reg").with_u32s(&reg2(0x0910_0000, 0x200)))
                .with_property(OwnedProperty::new("interrupt-parent").with_u32(2))
                .with_property(OwnedProperty::new("interrupts").with_u32s(&[16, 1])),
        );

        let m = Machine::survey(&dtb(root), Arch::X86_64).expect("survey ok");
        assert_eq!(m.virtio_mmio.len(), 1);
        assert_eq!(m.virtio_mmio[0].irq, 16);
    }

    #[test]
    fn x86_interrupt_parent_must_be_ioapic() {
        let mut root = x86_base_root();
        root.child_mut("serial@9000000")
            .unwrap()
            .property_mut("interrupt-parent")
            .unwrap()
            .set_u32(1);

        let err = Machine::survey(&dtb(root), Arch::X86_64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::UnexpectedController {
                    node: "/serial",
                    prop: "interrupt-parent",
                    actual: ControllerKind::Lapic,
                    expected: ControllerKind::IoApic
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn x86_interrupt_cells_must_match_ioapic_parent() {
        let mut root = x86_base_root();
        root.child_mut("serial@9000000")
            .unwrap()
            .property_mut("interrupts")
            .unwrap()
            .set_u32s(&[4, 1, 0]);

        let err = Machine::survey(&dtb(root), Arch::X86_64).unwrap_err();
        assert!(
            matches!(
                err,
                SurveyError::BadProperty {
                    node: "/serial",
                    prop: "interrupts",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn x86_extra_node_is_uncovered() {
        let mut root = x86_base_root();
        root.set_child(
            OwnedNode::new("bogus@0").with_property(OwnedProperty::new("foo").with_u32(1)),
        );
        let err = Machine::survey(&dtb(root), Arch::X86_64).unwrap_err();
        assert!(matches!(err, SurveyError::Uncovered(_)), "got {err:?}");
    }
}
