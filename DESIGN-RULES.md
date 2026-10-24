# Dillo Design Rules

**Status:** Draft for review. These rules describe the intended architecture, not a claim that the current implementation fully conforms.

## 1. Devicetree is the VM hardware-model contract

Unlike VMMs that use devicetree only to describe a separately constructed virtual machine to the guest, Dillo uses devicetree as the authoritative hardware-model contract from which the VMM constructs the machine.

### DT-001 — Construct the machine from the contract

Guest-visible hardware and its resource relationships must follow the devicetree contract. Backend defaults must not independently define the machine.

The direction is:

```text
Devicetree contract
    → configured devices, transports, and resources
    → realization using host primitives
    → VM execution
```

Passing the tree to the guest is an additional use of the same contract, not a substitute for constructing the declared model.

### DT-002 — Realize declarations faithfully

Required declarations must be faithfully realized or explicitly refused. Do not silently substitute default addresses, sizes, topology, controllers, or semantics.

Honor nonstandard declared values wherever the backend permits. Conventional layouts are not the authority.

### DT-003 — Introduce no undeclared hardware resources

Every instantiated guest-visible device, mapping, interrupt relationship, and guest-address-space exclusion must have authority in the contract. Audit implicit side effects of backend APIs as well as explicitly constructed devices.

A reserved range alone neither identifies its purpose nor authorizes arbitrary VMM use.

### DT-004 — Preserve contract ownership

Host-generated allocations and overlays must remain within the governing PMI contract. A backend limitation does not authorize silently changing the hardware model.

Where the contract permits child-resource derivation, preserve its bounds and relationships. Address containment alone is not permission to instantiate arbitrary child hardware.

### DT-005 — Parsing is not conformance

Successful parsing, complete claim coverage, and provenance labels do not prove faithful realization. Conformance requires tracing both declarations to realized hardware and realized hardware back to its authority.

## 2. Host and guest scope

### PLATFORM-001 — Support the three host operating systems

Dillo targets Linux, macOS, and Windows hosts. Host-specific mechanisms belong behind the host-backend boundary, not in shared device and transport behavior.

This target does not imply that every architecture or confidential-computing mode is available on every host OS. Document actual capabilities and tested combinations separately.

### GUEST-001 — Support Linux guests

Dillo targets Linux guests only. Compatibility with other guest operating systems is not a design requirement.

### PLATFORM-002 — Target modern virtualization

Dillo is a purpose-specific VMM, not a general-purpose compatibility platform. Target modern virtualization, including Intel TDX, AMD SEV-SNP, and Arm CCA where available, with as few distinct code paths as practical.

Do not preserve legacy execution paths solely for general-purpose compatibility. In particular, ordinary Intel KVM execution must not depend on the restricted-guest scratch-TSS workaround.

## 3. Host backend and machine model

**Host backend** means the implementation that realizes the machine model using a host hypervisor API and supporting OS primitives.

**Host primitives** are the services supplied by that backend, such as memory mapping, interrupt delivery, notifications—for example, eventfd on Linux—process creation, and sandboxing.

**Machine model** means the total surface exposed to the guest, as defined by the devicetree.

Devices and transports implement the devicetree-defined machine model using primitives supplied by the selected host backend. These terms describe architectural roles and do not prescribe renaming existing Rust types.

### MODEL-001 — One host backend obtains

Only one host backend obtains in an execution context. Shared composition need not support mixing unrelated host-backend implementation families or selecting a different host backend per component.

### MODEL-002 — Associate types at actual host-backend differences

`Machine` must provide associated concrete types for host-specific primitives. Those types form the implementation family used to realize the shared machine model.

Do not make a component host-specific merely because its underlying services differ across hosts. Associated types exist to maximize reuse, not to duplicate machine-model behavior.

The current `Machine` trait selects `Error`, `Cpu`, `CpuState`, and `Memory`. Which additional primitives require associated types remains an interface-design question.

## 4. Device composition and reuse

### COMPOSE-001 — Share devices and transports

Devices and transports are host-backend-agnostic code configured according to the devicetree and activated using primitives supplied by the selected host backend.

Transports belong to the machine model. They are not host-specific replacements selected independently by each host implementation.

### COMPOSE-002 — Preserve responsibility boundaries

Preserve the separation between machine realization, attachment, transport behavior, and device behavior, including nested PCI and virtio composition.

Host-backend differences belong in the primitives those components use—for example, memory access, interrupt delivery, notification, and execution mechanisms—not in duplicated implementations of the protocols themselves.

### COMPOSE-003 — Separate requirements from supplied authority

A component declaring a resource requirement does not authorize itself to obtain that resource. The owner admitting it into the machine must establish that the realization follows the contract.

A dispatcher need not interpret DT to perform its job. The precise validation API and representation of authorization evidence remain design decisions; these rules do not require DT evidence inside `MmioBus`.

## 5. Process model and confinement

### PROCESS-001 — Use out-of-process execution where supported

Components must execute out-of-process wherever the host backend supports the required separation. In-process execution is a host-backend fallback, not an alternative selected for convenience.

### PROCESS-002 — Implement the process model at the host-backend boundary

`Machine` and its associated host-specific types provide the mechanisms needed to realize the process model, including process establishment, communication, resource transfer, notification, and lifecycle control.

Shared devices and transports must not select OS-specific process mechanisms or assume that other components share their address space.

### PROCESS-003 — Preserve interfaces across execution topology

The common traits and types must accommodate both in-process implementations and out-of-process proxies while preserving logical composition and service semantics.

Local Rust objects need not themselves cross a process boundary. A host-backend implementation may supply a local proxy backed by IPC. Conversely, `Send`, `Sync`, an `Arc`, or a boxed closure does not by itself establish cross-process portability.

### PROCESS-004 — Constrain component authority

Process separation must be accompanied by restrictions on the resources and operations available to the component. A separate process with unrestricted access is not the intended isolation model.

On Linux, device processes must use strict seccomp filters. Filtering belongs inside the Linux `Machine` implementation or its associated host-specific types, not in shared devices or transports.

Common interfaces express required services and semantics; they do not expose Linux-specific sandbox configuration. Other host backends realize confinement through their own mechanisms.

## 6. Trait and type responsibilities

These assignments describe intended responsibilities. They are not assertions that every current implementation enforces them.

| Types or boundary | Responsibility |
| --- | --- |
| DT interpretation: `dillo_devtree::platform::Machine`, `ResourcePlan`, `Topology` | Interpret the hardware contract and preserve resource identities, origins, and relationships. The survey type named `Machine` is distinct from the host-backend trait. |
| Launch composition: `LaunchPlan` and launcher | Sequence interpretation, planning, configuration, attachment, and execution without independently inventing hardware. |
| Host-backend boundary: `dillo_machine::Machine`, `LaunchConfig` | Realize the hardware model through the selected host backend and supply host-specific implementation types. |
| `Host` | Supply host services and host-derived facts through the host-backend boundary. |
| `Memory`, `RamRange`, `CpuState`, `BootVcpuState`, `Cpu` | Represent or realize launch-derived memory and CPU state and expose execution/lifecycle operations. |
| `Attach<T>` implementations | Integrate a component into its owner and realize its permitted resources and services. |
| `MmioDevice` | Define host-backend-agnostic MMIO behavior and resource requirements. |
| `MmioAttachment`, `InterruptLine`, `MessageInterruptDomain`, `SharedMemory` | Supply realized services through common contracts with host-specific implementations. |
| `MmioBus` | Dispatch installed MMIO routes and maintain routing consistency, rather than define the hardware model. |
| `PciRoot`, `PciBus`, `PciDevice`, `PciDeviceHost` | Compose shared PCI behavior and child services within the governing resource contract. |
| Virtio transports, `VirtioDevice`, `VirtioActivate` | Implement shared transport/device behavior and activation using host-backend-provided services. |
| KVM, HVF, WHP implementations | Implement host-specific primitives, backend operations, and execution/confinement mechanisms without changing the declared hardware model. |

The concrete type names are a map to current code, not a requirement to freeze those APIs. Changes must preserve the responsibilities.

## 7. Architecture-conformance reviews

### REVIEW-001 — Evaluate rules with scoped evidence

Human and automated conformance passes must identify:

- Rule ID and source revision.
- Component, host backend, architecture, and configuration examined.
- Relevant source and construction/service paths.
- Tests or probes actually executed and their results.
- Verdict: `conforms`, `violates`, `unverified`, or `not-applicable`.
- Limitations and unresolved contract questions.

A conformance claim applies only to its stated scope. Source inspection, an isolated API probe, a complete VM boot, and confidential-computing validation are different evidence levels.

### REVIEW-002 — Check boundaries and lifecycle

Review declaration-to-realization paths, reverse authority traces, associated-type use, host-backend dependencies in shared code, process-boundary assumptions, resource confinement, and reset/teardown behavior.

Use focused tests and actual host-backend execution where appropriate. Automated source review and pattern checks can identify candidates; they do not prove total architectural conformance.

### REVIEW-003 — Keep requirements separate from implementation gaps

Existing violations belong in tracked findings, not implicit exceptions to the rules. An open issue does not waive a requirement.

Keep unresolved design choices explicit. Do not let a conformance pass silently invent a new interface, binding, or cross-project contract.

## 8. Ecosystem boundaries

Dillo owns VM execution and the device model. Pichi owns image management and user-facing orchestration. PMI owns the image-format specification.

Changes to shared contracts must be coordinated with the projects that own them. Architectural tradeoffs and changes to these design rules require explicit review and agreement.
