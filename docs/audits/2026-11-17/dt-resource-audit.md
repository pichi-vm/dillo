# Devicetree claims, realization and reverse authority

Baseline: Dillo code/design `c808d800e0e020df275548bb64c3061ce8e3379a`, PMI
`d6c2543129c3dad900d39a14ac9c4909bd39c0ac`. The locked devtree implementation is
`07526cfdba0ce0eefdcf641c582a44ce335cd4fe`. This is source review with historical
probe/test evidence explicitly distinguished from new execution. No new native
experiment was run.

## Entry, consumption and realization

`src/main.rs:1653` selects bundled/detached/optional DT input, surveys the base,
requires an overlay channel for its supported delegated CPU/RAM model, checks
load placement against declared resources and native address width, then builds
launch writes. Fixed CPU declarations are explicitly rejected; fixed memory
declarations remain unhandled and are rejected. Unsupported fixed models are
not silently overridden. `src/main.rs:2717` creates the selected Machine and
attaches RAM, UART, syscon and configured device compositions before CPUs run.

`deps/dillo-devtree/src/platform.rs:559` uses destructive OwnedTree consumption
and residual checks. Required properties use removal, so the same stored entry
cannot be consumed twice. Handlers verify residual properties/children before
returning. The devtree dependency preserves properties and children in Vecs
(`src/owned.rs:443`); materialization is not a name-keyed overwrite. These are
useful foundations, not complete DT-007 conformance:

- `CoreVm` sweeps every empty root child, without distinguishing a handled
  container from unknown input. #143 covers that acceptance defect.
- Root/PCI cell declarations are acknowledged without validating the values;
  `reg_pair` assumes fixed widths and `pci_window` reads the first seven cells.
  #144 covers cell/tuple validation; #14 covers lost child-to-parent translation.
- `GicConfig`, timer and PSCI results are discarded by the survey. The returned
  platform stores intervals and some device facts, not every handled model.
- Each backend parses a fresh tree for substrate creation. It does not consume
  delegated typed claims from the survey or return a complete realization
  account to a finalizer. #165 tracks that missing connection; duplicate parsing
  alone is not proof that a resource was instantiated twice.
- `ResourcePlan::declare_from` records a property name plus caller-provided
  address/size. Its label does not prove that the original property means those
  values or that native realization matches them.

Original duplicate DT entries and the FDT reservation block require explicit
qualification. OwnedTree retains reservations (`owned.rs:577`), but the survey
checks only the root's properties and children. This is not evidence that all
reservation entries are invalid or that a reserved range authorizes VMM use.
The remaining semantic/refusal evidence belongs in #151/#165. No new acceptance
or native-access probe for reservations/duplicates was run.

## Resource inventory

| Declared or exposed resource | Forward and reverse source trace | Scoped result |
| --- | --- | --- |
| Guest RAM and load extents | preflight cross-validation, `placement::plan_around_regions`, Machine-family Memory attachment | Declared holes constrain normal placement; action destinations/zeros and stable source have #133/#134/#157 gaps. Generic attachment authority is #10. |
| Delegated CPUs/RAM and overlays | `src/main.rs:1324,1653`, `src/launch/delegation_tests.rs` | Supported delegated path is explicit; fixed models are refused. Guest-side validation remains Arma #48/#49, not established by host checks. |
| x86 KVM LAPIC/IOAPIC | survey -> `intc_x86.rs` -> `hypervisor.rs:245` and per-vCPU LAPIC-base setup | Existing capability/refusal path honors supported LAPIC placement and refuses unsupported IOAPIC placement/short spans. Native scope is limited to prior tests; do not reopen the fixed #2 behavior. |
| x86 KVM implicit PICs | `hypervisor.rs:245` creates full irqchip; `irq.rs:80` installs PIC routes | Extra undeclared legacy resources remain #3. |
| x86 KVM scratch TSS/exclusion | `hypervisor.rs:253` calls set_tss_address | #4 remains: remove restricted-guest compatibility and qualify effective Intel configuration. The call does not imply a scratch mapping on AMD/unrestricted Intel. |
| WHP IOAPIC/LAPIC | `lib.rs:242` retains IOAPIC reg; native VM enables local APIC without retaining DT LAPIC | IOAPIC source path exists; LAPIC declaration loss is new #164. Effective nondefault native decode remains unverified. |
| Arm KVM GICD/GICR | survey records sizes; `lib.rs:489` retains bases only; `hypervisor.rs:694` configures VGIC | #9 covers missing extent fidelity; native extent/refusal behavior requires qualification. |
| Arm KVM GICv2m | survey records frame/base/count; native substrate drops frame/base and uses direct SPI routing | #8: transport interception is not realization of a declared frame. No new Arm execution. |
| HVF GICD/GICR/MSI frame | `lib.rs:283` retains bases/MSI IDs, discards extents; `hypervisor.rs:103` configures native GIC | Base/ID propagation exists. Extent fidelity and supported bounds are unverified under #151; no assumed API equivalence. |
| Arm timer | survey `Timer::from_tree` validates only shape/parent and retains no model; backend native timer path | #149 covers empty tuple acceptance and lost semantics. Native nondefault routing not qualified. |
| Arm PSCI | survey accepts hvc/smc then discards method; HVF HVC branch handles PSCI, SMC branch warns | #137 source mismatch remains. KVM conduit support/refusal must be independently qualified. |
| UART | survey `Uart::from_tree` -> `attach_uart` -> shared Ns16550; optional absence skips it | Base/extent/reg-shift/interrupt request propagate in normal path. Every accepted interrupt flag/width and native effect is not qualified; #151/#10. |
| x86 syscon poweroff/reset | `parse_syscon` validates >=4 bytes/no overflow; `attach_syscon` preserves base/size and trigger | Existing extent fix #7 remains. General value/trigger semantics and native failure cases remain qualification in #151. |
| PCI root/ECAM | survey -> `attach_devices` only constructs root when a PCI endpoint exists | #135: declared empty root omitted. No root is invented when PCI is absent in normal placement. |
| PCI buses and windows | `Pcie::from_tree` narrows bus bounds unchecked; `pci_window` drops child address/type/later windows | #136 bus validation; #14 translation. Do not infer that a nonzero first bus must fail merely from internal zero-based offsets. |
| PCI endpoint BARs/MSI-X | configured factories -> PciRoot -> transport header/config and separately registered windows | #13 BAR/routing coherence; #163 native KVM message state/errors. Closed #11/#12 bounds and sibling-vector fixes remain preserved. |
| Virtio-MMIO slots | survey all slots -> empty transport or populated composed transport in `src/main.rs:2467` | Required empty-slot headers are implemented (#122 closed). Device protocol remains independent of transport. Generic route admission remains #10. |
| Virtio-console/ports | executable configuration supplies one device through selected transport; overlay generates CPUs/RAM only | No console/port DT nodes are added. Port discovery is through virtio; linked console behavior has separate #147/#148 gaps. |

The inventory includes CPU-visible hardware effects of backend initialization,
not only devices registered in the userspace bus. Features expressly permitted
by PMI's ordinary-vm CPU profile are not automatically undeclared DT hardware.
Confidential private mappings/measurement are deferred under #152.

## Placement and admission

`dillo-config::allocate` at `deps/dillo-config/src/lib.rs:1020` resolves each
explicit bus, reserves pinned slots first, then assigns the lowest free slot.
It rejects missing/unavailable buses, exhaustion and conflicts. Relevant tests
are assertion-bearing and the earlier component run applies to identical code.
No transport fallback appears in this path.

Normal placement is not the only admission path. Public generic Attach
implementations in all three backends accept component windows and interrupt
requirements without looking up their authority in the surveyed contract.
Bus overlap assertions are neither declaration authority nor effect-aware
admission failures. Same-backend capability types do not establish instance
identity. #10/#140/#165 therefore remain even when the executable chooses valid
resources for its own ordinary path.

## Native evidence and interface consequences

Existing positive native boots and the earlier focused KVM tests are retained
with their original revisions and limitations; code, tests and lockfile are
unchanged from the preceding audit. They do not qualify every modified DT,
failure path or backend. #151 owns the explicit remaining native matrix.

The major interface specification needs four distinct things: consumed source
entries; semantic declarations retaining relevant facts; instance-bound
admission/realization records; and successful finalization permitting execution.
No one of those is a substitute for the others. These are consequences of
adopted requirements, not a new requirement to funnel every constructor through
Machine or a claim that counting receipts proves native behavior.
