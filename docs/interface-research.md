# Interface research

Research scope: native CPU ownership/completion, process proxies and device
barriers underlying [INTERFACES.md](../INTERFACES.md). References were checked
on 2026-11-17. Peer source revisions are pinned; platform documentation is
linked directly. These are implementation precedents and API constraints,
not evidence that Dillo already conforms or that a cross-platform mechanism
has passed qualification. No peer code is copied.

## Current implementation constraints

At Dillo `c808d800e0e020df275548bb64c3061ce8e3379a`,
[Machine](https://github.com/pichi-vm/dillo/blob/c808d800e0e020df275548bb64c3061ce8e3379a/deps/dillo-machine/src/lib.rs#L115)
associates CPU, CPU input and memory types. Its
[CPU contract](https://github.com/pichi-vm/dillo/blob/c808d800e0e020df275548bb64c3061ce8e3379a/deps/dillo-machine/src/lib.rs#L104)
combines `run` and `stop` under `Send + Sync`. General
[attachment services](https://github.com/pichi-vm/dillo/blob/c808d800e0e020df275548bb64c3061ce8e3379a/deps/dillo-mmio/src/lib.rs#L646)
live in MMIO and spawn closures on threads. Existing
[virtio activation](https://github.com/pichi-vm/dillo/blob/c808d800e0e020df275548bb64c3061ce8e3379a/deps/dillo-virtio/src/device.rs#L301)
already separates devices from transports. Preserve that useful protocol seam
while replacing the process/lifecycle boundary. The detailed source chains
and gaps are in the [audit](audits/2026-11-17/README.md).

## Native CPU boundary

KVM documents that several exits, including MMIO and port I/O, complete only
on reentry. It permits completing them with further guest execution suppressed.
`immediate_exit` is checked at entry, so a shared flag by itself is not a
complete wake/entry protocol. This supports owner-private instruction
settlement and an explicit stopped acknowledgement.
[KVM API, kvm_run](https://docs.kernel.org/virt/kvm/api.html#the-kvm-run-structure)

Apple creates an HVF vCPU for the calling thread. That supports an owner-local
runner without a general `Send + Sync` requirement.
[Apple hv_vcpu_create](https://developer.apple.com/documentation/hypervisor/hv_vcpu_create(_:_:_:))

WHP permits another thread to cancel a running virtual processor. The
documentation does not establish a sticky cancel-before-entry guarantee.
Consequently the proposed control contract requires a qualified entry-race
handshake, not merely calling cancellation and assuming success means stopped.
[WHvCancelRunVirtualProcessor](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcancelrunvirtualprocessor)

Firecracker's `VcpuHandle` sends events to an owner thread and receives
responses. Its send path publishes the event, sets immediate exit and signals
the thread. This is precedent for separate request/control and execution,
not for copying its exposed vCPU fd or state-save authority into Dillo's
ordinary interface. The source identifies Apache-2.0 licensing.
[Firecracker CPU control, cc88013](https://github.com/firecracker-microvm/firecracker/blob/cc88013eadcf432da1b37d47d445b7e8bcc3046e/src/vmm/src/vstate/vcpu.rs#L494)

Cloud Hypervisor's CPU manager publishes pause intent, signals CPUs and waits
for active owners to report paused. This supports shared supervision with
owner acknowledgements. It does not prove Dillo's device-aware barrier or
authorize post-launch state access. The source identifies Apache-2.0 and
BSD-3-Clause licensing.
[Cloud Hypervisor CPU manager, e90a727](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/e90a72710ed015b4ed29b111cb9f41fa03ebe2ab/vmm/src/cpu.rs#L2656)

## Process proxy and fast paths

crosvm's child dispatch owns a `BusDevice`; its parent proxy serializes bus
and configuration operations. Reads use replies while ordinary writes can
be sent without waiting. This is a concrete precedent for a parent bus proxy
and child device model. Dillo must additionally track applied writes, report
errors and fence lifecycle effects under its adopted requirements; copying
the shape alone would not establish those properties. The source identifies
a BSD-style license.
[crosvm proxy, f4ef01f](https://github.com/google/crosvm/blob/f4ef01fabd83f3c7ac8db34cace20d893a059347/devices/src/proxy.rs#L106)

WHP notification ports signal a host event for matching partition doorbells;
triggers deliver configured partition interrupts/events when a host event is
signaled. Thus Machine can retain registration authority while a worker holds
an event endpoint. API existence is not evidence of transfer rights, sandbox
coverage, teardown ordering or performance in Dillo; those need native tests.
[Notification ports](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatenotificationport),
[triggers](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatetrigger)

## Device stop boundary

The vhost-user suspended state prohibits guest-memory writes and guest
notifications while retaining frontend request/reply processing. Stopping
vrings normally drains inflight I/O, with separately negotiated alternatives.
This supports preserving completion/control services during a barrier.
Dillo additionally forbids software-device guest-memory reads after all-stop;
protocol negotiation alone therefore cannot establish its stronger barrier.
An external backend must demonstrate the required stop semantics. Vhost-user
remains the preferred external queue-backend interface, not the built-in
parent-to-worker register protocol.
[Vhost-user suspended state](https://www.qemu.org/docs/master/interop/vhost-user.html#suspended-device-state)

## Consequences and limits

The research supports the adopted owner/control split, shared lifecycle,
child transport/device placement and independently progressing completion
services. The two-phase stop protocol in INTERFACES.md is Dillo's synthesis
of those constraints and its stronger all-stop requirement; no claim is made
that another VMM implements that entire policy package.

The proposed traits preserve requirements without selecting new policy.
Native interruption races, pending-instruction completion, notification
registration/retirement, malicious-worker confinement, host-I/O draining and
ordinary debug operations remain explicitly unverified acceptance work.
Confidential launch/debug mechanisms are deferred, not inferred from these
ordinary-VM references. No performance claim follows from this research.
