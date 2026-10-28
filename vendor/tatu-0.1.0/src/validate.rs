// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Devicetree validation.
//!
//! The host-supplied DTBO is adversarial: [`validate_host_dtbo`]
//! enforces the merged-extension allowlist (per `pmi/spec/dt.md`
//! §2) before merging.
//!
//! The merged tree (base + host DTBO) is then validated by
//! [`validate_merged`], but only on surfaces the host can actually
//! contribute to per §2's allowlist:
//!
//! - `/cpus/cpu@N` count, bounded by [`MAX_CPUS`] for DoS protection.
//! - `/memory@*` `reg` regions, bounded by [`MAX_MEMORY_REGIONS`].
//! - The §4.4 check 2 memory-vs-device overlap test, which requires
//!   walking `/intc`, `/syscon`, and `/pci` for their `reg` regions.
//!
//! Base-DTB-only content (root attrs, `/firmware`, `/poweroff`,
//! `/reboot`, `/timer`, `/chosen`, `/reserved-memory`, plus the
//! property whitelists on `/intc`, `/syscon`, `/pci`) is arma's
//! responsibility. arma is trusted; we don't re-validate it.
//!
//! All buffers are bounded by `ArrayVec`; the validation pass has
//! no heap and no dynamic allocation.

use arrayvec::ArrayVec;
use devtree::{Error as DtError, Fragment, NodeView, OverlayView, PropertyView, Target, TreeView};

// §4.5 compile-time maxima.
pub(crate) const MAX_CPUS: usize = 2048;
pub(crate) const MAX_MEMORY_REGIONS: usize = 32;
// ArrayVec cap for platform-device `reg` pairs collected for the §4.4
// memory-vs-device overlap check. Covers GIC (dist+redist) + v2m + serial +
// PCIe ECAM plus a generous virtio-mmio slot count; the bound is mechanical
// (the type needs a const size), not load-bearing — all base-only.
pub(crate) const MAX_DEVICE_RANGES: usize = 64;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum ValidationError {
    // Host-DTBO allowlist (pmi/spec/dt.md, "Overlay contents").
    HostOverlayUnsupportedTarget,
    HostOverlayProhibitedPath,
    HostOverlayCpuPhandleProhibited,
    HostOverlayConflictingProperty,
    HostOverlayMemoryOverflow,

    // Semantic (pmi/spec/dt.md, "Address validation").
    MemoryOverlapsDevice,
    NonCanonicalGpa,
    ZeroSize,
    AddressOverflow,

    /// A `cpu@N` `cpu-release-addr` is not a safe write/release target: out of
    /// range, over device MMIO, or outside declared guest RAM.
    CpuReleaseAddrUnsafe,

    // §4.5 — maxima.
    TooManyCpus,
    TooManyMemoryRegions,
    TooManyDeviceRanges,

    // Property shape / parse.
    BadPropertyShape,
    Devtree(DtError),
}

impl From<DtError> for ValidationError {
    fn from(e: DtError) -> Self {
        ValidationError::Devtree(e)
    }
}

// ---------------------------------------------------------------------------
// Host-DTBO allowlist (pmi/spec/dt.md §2).
// ---------------------------------------------------------------------------

/// Enforce the merged-extension allowlist on the host-supplied DTBO
/// against the measured base DTB. The four allowed categories:
///
/// 1. `/cpus`: the overlay authors the entire subtree — it creates the
///    `/cpus` node itself (carrying only `#address-cells`/`#size-cells`)
///    and may add `cpu@N` nodes (the base declares no `/cpus`). The
///    cpu-node properties are host-authored; only `phandle` /
///    `linux,phandle` are prohibited. The count is DoS-bounded by
///    [`MAX_CPUS`] in [`validate_merged`], not template-matched.
/// 2. Nodes and properties under `/memory@*`.
/// 3. Nodes and properties under `/distance-map`.
/// 4. The `numa-node-id` property added to any base-declared node
///    (and it MUST NOT appear with any other host-contributed
///    property on the same node).
///
/// Fragments using a label-style target are rejected: the merged
/// model expects hosts to address the base via explicit paths.
pub(crate) fn validate_host_dtbo<'a, O, T>(overlay: &O, base: &T) -> Result<(), ValidationError>
where
    O: OverlayView<'a>,
    T: TreeView,
{
    for frag in overlay.fragments() {
        let Target::Path(path) = frag.target() else {
            return Err(ValidationError::HostOverlayUnsupportedTarget);
        };
        classify_fragment(path, frag, base)?;
    }
    Ok(())
}

fn classify_fragment<T>(path: &str, frag: Fragment<'_>, base: &T) -> Result<(), ValidationError>
where
    T: TreeView,
{
    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let overlay_node = frag.node();

    match path {
        "/" => {
            // Only allowed root-level additions: /memory@* and
            // /distance-map. Any property on '/' itself is rejected.
            if overlay_node.properties().next().is_some() {
                return Err(ValidationError::HostOverlayProhibitedPath);
            }
            for child in overlay_node.children() {
                let seg = top_segment(child.name());
                match seg {
                    "memory" => check_memory_node(&child)?,
                    "distance-map" => { /* contents unchecked beyond structural */ }
                    "cpus" => {
                        // The base declares no /cpus, so the host creates it
                        // via a root fragment; route through the cpus check
                        // (which permits the container's cell properties).
                        check_cpus_additions(&child)?;
                    }
                    _ => return Err(ValidationError::HostOverlayProhibitedPath),
                }
            }
        }
        "/cpus" => check_cpus_additions(&overlay_node)?,
        "/distance-map" => { /* allowed per allowlist 3 */ }
        p if memory_path(p) => check_memory_node(&overlay_node)?,
        _ => {
            // Allowed only if the overlay adds nothing but
            // numa-node-id on a base-declared node (rule 4).
            if base.find_path(path).is_none() {
                return Err(ValidationError::HostOverlayProhibitedPath);
            }
            let mut saw_numa = false;
            for p in overlay_node.properties() {
                if p.name() != "numa-node-id" {
                    return Err(ValidationError::HostOverlayConflictingProperty);
                }
                saw_numa = true;
            }
            if overlay_node.children().next().is_some() {
                return Err(ValidationError::HostOverlayProhibitedPath);
            }
            if !saw_numa {
                return Err(ValidationError::HostOverlayProhibitedPath);
            }
        }
    }
    Ok(())
}

/// True for any `/memory@<unit>` path. Avoids matching nested paths.
fn memory_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/memory") else {
        return false;
    };
    rest.starts_with('@') && !rest.contains('/')
}

fn check_cpus_additions<N>(overlay_cpus: &N) -> Result<(), ValidationError>
where
    N: NodeView,
{
    // The host authors the /cpus container, so it carries exactly the two
    // cell properties; any other property on /cpus itself is non-conformant.
    // Bad cell *values* are a boot-time DoS, not consumer-validated (§2).
    for p in overlay_cpus.properties() {
        if !matches!(p.name(), "#address-cells" | "#size-cells") {
            return Err(ValidationError::HostOverlayConflictingProperty);
        }
    }
    for child in overlay_cpus.children() {
        if top_segment(child.name()) != "cpu" {
            return Err(ValidationError::HostOverlayProhibitedPath);
        }
        // dt.md §2 cat 1: the host authors the cpu instances; their
        // `device_type` / `reg` / `status` / `enable-method` / `compatible`
        // are all allowed and DoS-bounded by count (in `validate_merged`),
        // not template-matched. Only `phandle` / `linux,phandle` are
        // prohibited — no host-contributed surface references cpus by
        // phandle, so we close that capability per the trust boundary.
        for p in child.properties() {
            if matches!(p.name(), "phandle" | "linux,phandle") {
                return Err(ValidationError::HostOverlayCpuPhandleProhibited);
            }
        }
    }
    Ok(())
}

fn check_memory_node<N: NodeView>(node: &N) -> Result<(), ValidationError> {
    let Some(reg) = NodeView::property(node, "reg") else {
        return Ok(());
    };
    let bytes = reg.as_ref();
    if !bytes.len().is_multiple_of(16) {
        return Err(ValidationError::HostOverlayMemoryOverflow);
    }
    let (chunks, _) = bytes.as_chunks::<16>();
    for chunk in chunks {
        let r = parse_one_region(chunk);
        if r.end().is_none() {
            return Err(ValidationError::HostOverlayMemoryOverflow);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Merged-tree validation: only host-touchable surfaces + the
// memory-vs-device overlap check 2.
// ---------------------------------------------------------------------------

pub(crate) fn validate_merged<T: TreeView>(tree: &T, pa_bits: u32) -> Result<(), ValidationError> {
    let mut memory: ArrayVec<Region, MAX_MEMORY_REGIONS> = ArrayVec::new();
    let mut devices: ArrayVec<Region, MAX_DEVICE_RANGES> = ArrayVec::new();
    let mut cpu_count: usize = 0;

    for child in tree.root().children() {
        match top_segment(child.name()) {
            "cpus" => count_cpus(&child, &mut cpu_count)?,
            "memory" => extract_regs(
                &child,
                &mut memory,
                pa_bits,
                ValidationError::TooManyMemoryRegions,
            )?,
            // Any other top-level node carrying a `reg` is a platform device
            // (E1, §4.4). Matching by structure (has `reg`), not by node name,
            // is robust to the device-model's names (interrupt-controller@,
            // msi-controller@, serial@, virtio_mmio@, pcie@, …) and collects
            // every device MMIO region rather than a hand-listed subset.
            _ => {
                if NodeView::property(&child, "reg").is_some() {
                    extract_regs(
                        &child,
                        &mut devices,
                        pa_bits,
                        ValidationError::TooManyDeviceRanges,
                    )?;
                }
            }
        }
    }

    semantic_overlap_checks(&memory, &devices)?;
    validate_cpu_release_addrs(tree, &memory, &devices, pa_bits)?;
    Ok(())
}

/// Validate every `cpu@N` `cpu-release-addr` in the merged tree.
///
/// A host-chosen release address is where the kernel writes a secondary vCPU's
/// entry point and the secondary spins, so per pmi/spec/dt.md ("Address
/// validation", safe write/release targets) the guest must confirm it is a sane
/// RAM target before the kernel acts on it: in range, clear of device MMIO, and
/// inside declared guest RAM. CPU identity and features are never taken from the
/// overlay, so nothing else about `cpu@N` needs checking here.
fn validate_cpu_release_addrs<T: TreeView>(
    tree: &T,
    memory: &[Region],
    devices: &[Region],
    pa_bits: u32,
) -> Result<(), ValidationError> {
    for child in tree.root().children() {
        if top_segment(child.name()) != "cpus" {
            continue;
        }
        for cpu in child.children() {
            let Some(prop) = NodeView::property(&cpu, "cpu-release-addr") else {
                continue;
            };
            let addr = parse_release_addr(prop.as_ref())?;
            let target = Region { gpa: addr, size: 8 };
            // In range (and no end-overflow).
            validate_region(target, pa_bits)?;
            // Clear of device MMIO.
            if devices.iter().any(|d| regions_overlap(target, *d)) {
                return Err(ValidationError::CpuReleaseAddrUnsafe);
            }
            // Inside a declared guest-RAM region.
            if !memory.iter().any(|m| region_contains(*m, target)) {
                return Err(ValidationError::CpuReleaseAddrUnsafe);
            }
        }
    }
    Ok(())
}

/// Parse a `cpu-release-addr` property (1 or 2 big-endian cells) to an address.
fn parse_release_addr(bytes: &[u8]) -> Result<u64, ValidationError> {
    match bytes.len() {
        8 => Ok(u64::from_be_bytes(bytes.try_into().unwrap())),
        4 => Ok(u64::from(u32::from_be_bytes(bytes.try_into().unwrap()))),
        _ => Err(ValidationError::BadPropertyShape),
    }
}

/// Count `/cpus/cpu@N` children for the [`MAX_CPUS`] DoS bound.
/// Host can add cpu@N nodes per §4.2, so this bound is load-bearing.
fn count_cpus<N: NodeView>(node: &N, count: &mut usize) -> Result<(), ValidationError> {
    for _ in node.children() {
        *count = count.checked_add(1).ok_or(ValidationError::TooManyCpus)?;
        if *count > MAX_CPUS {
            return Err(ValidationError::TooManyCpus);
        }
    }
    Ok(())
}

/// Parse a node's `reg` property into validated `(gpa, size)` regions,
/// pushing each into `regions`. `overflow_err` is returned when the
/// ArrayVec is full.
fn extract_regs<N: NodeView, const CAP: usize>(
    node: &N,
    regions: &mut ArrayVec<Region, CAP>,
    pa_bits: u32,
    overflow_err: ValidationError,
) -> Result<(), ValidationError> {
    let Some(reg) = NodeView::property(node, "reg") else {
        return Ok(());
    };
    let bytes = reg.as_ref();
    if !bytes.len().is_multiple_of(16) {
        return Err(ValidationError::BadPropertyShape);
    }
    let (chunks, _) = bytes.as_chunks::<16>();
    for chunk in chunks {
        let r = parse_one_region(chunk);
        validate_region(r, pa_bits)?;
        regions.try_push(r).map_err(|_| overflow_err)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic checks (§4.4).
// ---------------------------------------------------------------------------

fn semantic_overlap_checks(memory: &[Region], devices: &[Region]) -> Result<(), ValidationError> {
    // §4.4 check 2: /memory@* does not overlap any device region.
    for m in memory {
        for d in devices {
            if regions_overlap(*m, *d) {
                return Err(ValidationError::MemoryOverlapsDevice);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Region {
    pub gpa: u64,
    pub size: u64,
}

impl Region {
    fn end(self) -> Option<u64> {
        self.gpa.checked_add(self.size)
    }
}

/// Validate a region's invariants: nonzero size, no end-overflow, and that the
/// region fits within the guest's physical address space. Per dt.md §2 the
/// overflow + bound checks are required on host-contributed addresses; the
/// bound is the guest PA/IPA width (`pa_bits`), not a hardcoded constant (pmi
/// spec bc7f581).
fn validate_region(r: Region, pa_bits: u32) -> Result<(), ValidationError> {
    if r.size == 0 {
        return Err(ValidationError::ZeroSize);
    }
    let end = r.end().ok_or(ValidationError::AddressOverflow)?;
    if end > (1u64 << pa_bits) {
        return Err(ValidationError::NonCanonicalGpa);
    }
    Ok(())
}

fn regions_overlap(a: Region, b: Region) -> bool {
    let Some(a_end) = a.end() else {
        return true;
    };
    let Some(b_end) = b.end() else {
        return true;
    };
    a.gpa < b_end && b.gpa < a_end
}

/// True when `inner` lies wholly within `outer`.
fn region_contains(outer: Region, inner: Region) -> bool {
    let (Some(outer_end), Some(inner_end)) = (outer.end(), inner.end()) else {
        return false;
    };
    outer.gpa <= inner.gpa && inner_end <= outer_end
}

/// Parse one 16-byte `reg` chunk: a (u64 address, u64 size) pair
/// in big-endian byte order. Assumes the parent's `#address-cells`
/// and `#size-cells` are both 2 — the qemu/virt convention that
/// arma+dillo produce. Callers gate on `len() % 16 == 0` before
/// chunking, so this function is total.
fn parse_one_region(chunk: &[u8]) -> Region {
    debug_assert_eq!(chunk.len(), 16);
    // Fixed-size chunking at the callers guarantees exactly 16 bytes,
    // so both `try_into` calls are infallible. `unwrap_or_default` keeps
    // the function total without pulling in `unwrap`.
    let gpa = u64::from_be_bytes(chunk[..8].try_into().unwrap_or_default());
    let size = u64::from_be_bytes(chunk[8..16].try_into().unwrap_or_default());
    Region { gpa, size }
}

/// Strip the `@unit-address` suffix from a node name to get the
/// canonical node type segment (e.g. `memory@40000000` → `memory`).
fn top_segment(name: &str) -> &str {
    match name.split_once('@') {
        Some((seg, _)) => seg,
        None => name,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use devtree::{Overlay, Tree};

    // Representative guest PA/IPA width for tests (aarch64 PARange=5 / x86
    // typical). The production bound comes from `arch::guest_pa_bits()`.
    const TEST_PA_BITS: u32 = 48;

    #[test]
    fn region_validation_rejects_zero_size() {
        assert_eq!(
            validate_region(
                Region {
                    gpa: 0x1000,
                    size: 0
                },
                TEST_PA_BITS
            ),
            Err(ValidationError::ZeroSize)
        );
    }

    #[test]
    fn region_validation_rejects_overflow() {
        assert_eq!(
            validate_region(
                Region {
                    gpa: u64::MAX - 0xFFF,
                    size: 0x1000
                },
                TEST_PA_BITS
            ),
            Err(ValidationError::AddressOverflow)
        );
    }

    #[test]
    fn region_validation_rejects_above_pa_width() {
        // A region ending past 2^pa_bits is rejected by the derived bound.
        assert_eq!(
            validate_region(
                Region {
                    gpa: 1u64 << TEST_PA_BITS,
                    size: 0x1000
                },
                TEST_PA_BITS
            ),
            Err(ValidationError::NonCanonicalGpa)
        );
        // A narrower width rejects an address a wider one would accept.
        assert_eq!(
            validate_region(
                Region {
                    gpa: 1u64 << 39,
                    size: 0x1000
                },
                36
            ),
            Err(ValidationError::NonCanonicalGpa)
        );
    }

    #[test]
    fn overlap_detection() {
        let a = Region {
            gpa: 0x1000,
            size: 0x2000,
        };
        let b = Region {
            gpa: 0x2000,
            size: 0x1000,
        };
        let c = Region {
            gpa: 0x4000,
            size: 0x1000,
        };
        assert!(regions_overlap(a, b));
        assert!(!regions_overlap(a, c));
        assert!(!regions_overlap(b, c));
    }

    #[test]
    fn parse_one_region_basic() {
        let chunk: &[u8] = &[
            0, 0, 0, 0, 0x40, 0, 0, 0, // gpa 0x40000000
            0, 0, 0, 0, 0x10, 0, 0, 0, // size 0x10000000
        ];
        assert_eq!(
            parse_one_region(chunk),
            Region {
                gpa: 0x40000000,
                size: 0x10000000
            }
        );
    }

    // ----- DTB-driven tests using devtree on real fixtures --------------

    #[test]
    fn merged_dtb_basic_fixture_passes() {
        let blob = include_bytes!("../deps/dtb2acpi/tests/data/basic.dtb");
        let tree: devtree::Tree<'_> = devtree::Tree::parse(blob).unwrap();
        validate_merged(&tree, TEST_PA_BITS).expect("basic fixture should pass");
    }

    // ----- cpu-release-addr safe write/release target (dt.md) -----------
    //
    // A merged tree with RAM at [0x4000_0000, 0x5000_0000), a device at
    // [0x0800_0000, 0x0801_0000), and one spin-table cpu whose release
    // address is `release_cells`.
    fn merged_with_release(release_cells: &str) -> String {
        format!(
            "/dts-v1/;\n/ {{ #address-cells = <2>; #size-cells = <2>;\n\
             memory@40000000 {{ device_type = \"memory\"; \
             reg = <0x0 0x40000000 0x0 0x10000000>; }};\n\
             intc@8000000 {{ reg = <0x0 0x8000000 0x0 0x10000>; }};\n\
             cpus {{ #address-cells = <1>; #size-cells = <0>;\n\
             cpu@0 {{ device_type = \"cpu\"; reg = <0>; enable-method = \"spin-table\";\n\
             cpu-release-addr = {release_cells}; }}; }}; }};"
        )
    }

    #[test]
    fn release_addr_in_ram_accepted() {
        let Some(bb) = dtc_compile(&merged_with_release("<0x0 0x40001000>")) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let tree: Tree<'_> = Tree::parse(&bb).unwrap();
        validate_merged(&tree, TEST_PA_BITS).expect("release addr in RAM must pass");
    }

    #[test]
    fn release_addr_over_device_rejected() {
        let Some(bb) = dtc_compile(&merged_with_release("<0x0 0x8000000>")) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let tree: Tree<'_> = Tree::parse(&bb).unwrap();
        assert_eq!(
            validate_merged(&tree, TEST_PA_BITS),
            Err(ValidationError::CpuReleaseAddrUnsafe)
        );
    }

    #[test]
    fn release_addr_outside_ram_rejected() {
        let Some(bb) = dtc_compile(&merged_with_release("<0x0 0x90000000>")) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let tree: Tree<'_> = Tree::parse(&bb).unwrap();
        assert_eq!(
            validate_merged(&tree, TEST_PA_BITS),
            Err(ValidationError::CpuReleaseAddrUnsafe)
        );
    }

    #[test]
    fn release_addr_out_of_range_rejected() {
        // 0x1_0000_0000_0000 == 2^48; end overflows the test PA width.
        let Some(bb) = dtc_compile(&merged_with_release("<0x10000 0x0>")) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let tree: Tree<'_> = Tree::parse(&bb).unwrap();
        assert_eq!(
            validate_merged(&tree, TEST_PA_BITS),
            Err(ValidationError::NonCanonicalGpa)
        );
    }

    // ----- Host-DTBO allowlist tests (dt.md §2) ---------------------
    //
    // The host authors the entire /cpus subtree via a root fragment (the
    // base declares no /cpus). These compile DTS with `dtc` at run time
    // and skip gracefully when it is absent, mirroring dillo's adversarial
    // suite — no committed binary fixtures.

    fn dtc_compile(dts: &str) -> Option<Vec<u8>> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("dtc")
            .args(["-I", "dts", "-O", "dtb"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(dts.as_bytes()).ok()?;
        let out = child.wait_with_output().ok()?;
        out.status.success().then_some(out.stdout)
    }

    const MINIMAL_BASE: &str = r"/dts-v1/;
/ { #address-cells = <2>; #size-cells = <2>; };";

    /// Build a root-targeting overlay whose `__overlay__` holds `body`.
    fn root_overlay(body: &str) -> String {
        format!(
            "/dts-v1/;\n/ {{ fragment@0 {{ target-path = \"/\";\n\
             __overlay__ {{ {body} }}; }}; }};"
        )
    }

    /// T2: a host-authored /cpus subtree (container cell props + a full
    /// cpu@N) delivered via a root fragment is accepted.
    #[test]
    fn host_authored_cpus_subtree_accepted() {
        let overlay_dts = root_overlay(
            r#"cpus { #address-cells = <1>; #size-cells = <0>;
                 cpu@0 { device_type = "cpu"; reg = <0>; status = "okay";
                         enable-method = "psci"; compatible = "arm,neoverse-v2"; }; };"#,
        );
        let (Some(ob), Some(bb)) = (dtc_compile(&overlay_dts), dtc_compile(MINIMAL_BASE)) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let overlay: Overlay<'_> = Overlay::parse(&ob).unwrap();
        let base: Tree<'_> = Tree::parse(&bb).unwrap();
        validate_host_dtbo(&overlay, &base).expect("host-authored /cpus must be accepted");
    }

    /// T4: a `phandle` on a host cpu node is rejected.
    #[test]
    fn cpu_phandle_rejected() {
        let overlay_dts = root_overlay(
            r#"cpus { #address-cells = <1>; #size-cells = <0>;
                 cpu@0 { device_type = "cpu"; reg = <0>; phandle = <1>; }; };"#,
        );
        let (Some(ob), Some(bb)) = (dtc_compile(&overlay_dts), dtc_compile(MINIMAL_BASE)) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let overlay: Overlay<'_> = Overlay::parse(&ob).unwrap();
        let base: Tree<'_> = Tree::parse(&bb).unwrap();
        assert_eq!(
            validate_host_dtbo(&overlay, &base),
            Err(ValidationError::HostOverlayCpuPhandleProhibited)
        );
    }

    /// T1: a non-cell property on the /cpus node itself is rejected.
    #[test]
    fn non_cell_property_on_cpus_rejected() {
        let overlay_dts =
            root_overlay(r"cpus { #address-cells = <1>; #size-cells = <0>; bogus = <1>; };");
        let (Some(ob), Some(bb)) = (dtc_compile(&overlay_dts), dtc_compile(MINIMAL_BASE)) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let overlay: Overlay<'_> = Overlay::parse(&ob).unwrap();
        let base: Tree<'_> = Tree::parse(&bb).unwrap();
        assert_eq!(
            validate_host_dtbo(&overlay, &base),
            Err(ValidationError::HostOverlayConflictingProperty)
        );
    }

    /// T4: a fragment targeting an off-allowlist path absent from the base
    /// is rejected.
    #[test]
    fn off_allowlist_path_rejected() {
        let overlay_dts = "/dts-v1/;\n/ { fragment@0 { target-path = \"/soc\";\n\
             __overlay__ { foo = <1>; }; }; };";
        let (Some(ob), Some(bb)) = (dtc_compile(overlay_dts), dtc_compile(MINIMAL_BASE)) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let overlay: Overlay<'_> = Overlay::parse(&ob).unwrap();
        let base: Tree<'_> = Tree::parse(&bb).unwrap();
        assert_eq!(
            validate_host_dtbo(&overlay, &base),
            Err(ValidationError::HostOverlayProhibitedPath)
        );
    }

    /// T3: a merged tree whose /cpus exceeds MAX_CPUS is rejected.
    #[test]
    fn too_many_cpus_rejected() {
        use core::fmt::Write as _;
        let mut body = String::from("/dts-v1/;\n/ { cpus {\n");
        for n in 0..=MAX_CPUS {
            let _ = writeln!(body, "cpu@{n} {{ device_type = \"cpu\"; reg = <{n}>; }};");
        }
        body.push_str("}; };");
        let Some(bb) = dtc_compile(&body) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let tree: Tree<'_> = Tree::parse(&bb).unwrap();
        assert_eq!(
            validate_merged(&tree, TEST_PA_BITS),
            Err(ValidationError::TooManyCpus)
        );
    }
}
