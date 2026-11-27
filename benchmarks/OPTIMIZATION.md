# Device performance milestone

Plan dated 2026-11-27. Source inspected: `7604a035dc25d13e7fe274d42836a75c58a04494`.
Implementation is underway. Interim measurements and qualification status are
recorded in [the execution report](results/2026-11-27-optimization/REPORT.md).

## Outcome

Make out-of-process device I/O match or beat in-process execution, starting with
the workloads in the [baseline report](results/2026-11-27/REPORT.md). Optimize
the entire request path, especially native queue notifications. Keep devices
isolated, transports in the parent, and the existing vhost-user control plane.

The target is at least the control's throughput, with no increase in CPU per
operation or request latency. Evaluate each platform, transport and workload
separately. A gain under load does not compensate for a queue-depth-one loss.
Keep startup, idle CPU, threads and private memory visible, but do not reopen
the deferred image-loading/startup optimization project.

The milestone finishes with an integrated branch, native correctness and
performance evidence, and a report of remaining gaps. Only claim parity for
cases that demonstrate it. A remaining regression means the parity objective
is unfinished, even if the implementation is useful. Pause for reflection
after the milestone; do not automatically start another architectural change.

## Evidence and first priorities

PCI random-I/O throughput currently retains 41–87% of in-process performance
across the measured machines. The physical Linux Arm host has the largest
loss. CPU per GiB also rises. Sampler-disabled controls reproduce the loss;
there is no successful CPU profile yet that apportions it among functions.

Source inspection identifies removable work, not a measured attribution:

1. [PCI activation](../deps/dillo-pci-virtio/src/transport.rs) creates a
   mutex/condition-variable `Kick` for every queue. [Worker activation](../deps/dillo-worker/src/parent.rs)
   consequently spawns a thread to forward it to the worker's native endpoint.
   Linux virtio-MMIO already obtains and exports an `ioeventfd` instead.
2. Worker activation always creates a parent completion relay. On KVM that
   relay ultimately signals an existing [irqfd-backed interrupt](../deps/dillo-machine-kvm/src/msi.rs).
   The kernel primitive exists; the worker cannot use it directly today.
3. Linux worker notifications already use eventfds; Windows already uses
   auto-reset events transferred over ALPC. macOS uses nonblocking pipe
   signals. We do not need another control transport to remove the relays.
4. Guest memory is already mapped into the worker. Steady block payload access
   does not make a parent RPC. Block processing does allocate descriptor lists
   and payload buffers; network TX gathers and copies frames. Those costs also
   exist in the in-process control and must not be called isolation overhead.
5. Block and network TX already drain available descriptors and signal once
   per drain. “Add batching” alone is not a diagnosis. Further suppression,
   allocations and RX polling are secondary candidates to measure.

The first implementation should remove the PCI kick relay and enable native
kick registration. Then bind eligible completions directly to native routes.
This implements the intent already recorded in
[DESIGN.md, NOTIFY-001 through NOTIFY-003](../DESIGN.md#notifications-and-interrupt-delivery).

## Native paths

### Linux / KVM, x86-64 and AArch64

Use `KVM_IOEVENTFD` for eligible PCI and MMIO notify writes and `KVM_IRQFD` for
eligible completions. Reuse the existing registration and route owners. Extend
the current four-byte, value-matching notification request only enough to
describe PCI's notification width/address semantics. Retain software dispatch
for accesses the native registration does not match. KVM documents both
interfaces and explicit deassignment in its [API reference](https://docs.kernel.org/virt/kvm/api.html#kvm-ioeventfd).

Bind the worker's call eventfd to a validated MSI-X route while it is enabled
and unmasked. Remove that binding when it is no longer eligible, retaining
pending notifications for the parent transport. Start with PCI MSI-X: the
virtio queue ISR bit is required when MSI-X is disabled, so MSI-X queue delivery
need not execute the current ISR-setting closure on every completion.
Configuration interrupts and legacy/level paths retain their required state.
See [virtio 1.3, ISR and used-buffer notifications](https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html).

Do not merely export the existing domain's eventfd: its `enabled` method
currently logs changes, and software MSI-X state supplies masking/pending
behavior. Direct binding must supply that missing control first. Prefer one
stable queue eventfd with native assignment/deassignment and pending inspection
at control transitions, rather than a new per-completion relay or protocol.
QEMU's [PCI implementation](https://github.com/qemu/qemu/blob/master/hw/virtio/virtio-pci.c)
uses native route binding, mask/unmask handling and pending-event inspection;
study those semantics without importing its implementation.

On Arm, retain the declared GICv2m SPI allocation and existing irqchip routing;
do not add an ITS or change the tenant DTB to obtain acceleration. MMIO
completion acceleration is a separate obligation: its ISR/acknowledgement and
level semantics must remain correct. `IRQFD_RESAMPLE` can help implement level
delivery, but does not maintain a virtio ISR. Keep the necessary relay until a
complete state-preserving path is established. Do not count an edge-pulse
substitution as an optimization. [KVM IRQFD contract](https://docs.kernel.org/virt/kvm/api.html#kvm-irqfd)

### Windows / WHP, native MSVC

Use doorbell-type `WHvCreateNotificationPort` for matching guest notify writes.
Use `WHvCreateTrigger` with the x64 interrupt type for eligible completions;
its returned event activates a preconfigured interrupt. Transfer the event,
not partition authority, through the existing ALPC resource path. These are
documented WHP APIs, with x64 support from Windows 10 20H2. Verify availability
and behavior on the supported runner before wiring them into production.
[Notification ports](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatenotificationport)
and [interrupt triggers](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatetrigger)

Check mask/retarget/delete races in a small native probe first. A deleted
trigger leaves its event handle valid but inert; an update can race with a
signal and deliver either old or new parameters. Therefore handle replacement
or retargeting alone is not our quiescence barrier. Preserve pending work while
switching between native and software delivery using existing queue-control
semantics. [Trigger deletion](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvdeletetrigger)
and [updates](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvupdatetriggerparameters)

Ordinary virtual devices need neither SynIC hypercalls nor assigned VPCI
devices for this x64 path. Do not extrapolate it to Windows Arm: the ordinary
interrupt trigger type is x64-only. No Windows Arm parity claim is included.

### macOS / HVF

Have the vCPU's notify-exit handler signal the worker's existing pipe directly,
removing the condition-variable-to-pipe forwarding thread. Preserve the
receiver's local cancellation wake and the existing coalescing behavior.

Keep the necessary Machine-side completion injection via the native GIC APIs.
No documented event-to-interrupt binding equivalent to irqfd was identified
in this inspection; do not promise a nonexistent fast path. Measure whether
draining several ready calls per wake or a small `kqueue` dispatcher improves
CPU/latency and reduces idle relay threads. Keep the simpler existing relay if
multiplexing adds latency. The vCPU must never wait for device processing.
[HVF GIC APIs](https://developer.apple.com/documentation/hypervisor/gic-functions)

## Execution order and evidence at each step

1. **Establish attribution and native feasibility.** Extend the existing
   benchmark mode with opt-in, bounded counters for notify exits, kick/call
   signals, relay wakes, completions per drain and native registrations.
   Aggregate at phase end; do not log every request. Collect per-thread CPU
   and scheduler evidence with perf/ETW/Instruments where already permitted.
   Where profiling is unavailable, use counters and controlled path toggles.
   Prove WHP ports/triggers and KVM masked-route transitions early, before
   designing a shared API around assumptions. These probes become focused
   native regression cases, not a second transport framework.
2. **Remove kick forwarding.** Create an exportable queue notification at the
   attachment boundary, use it directly from software MMIO dispatch, and bind
   eligible writes through KVM/WHP. PCI and MMIO retain their own register
   semantics. On macOS use the existing pipe endpoints directly. Demonstrate
   removal of the extra forwarding thread and, for accelerated writes, parent
   notify exits. Repeat one-device PCI and MMIO QD1 measurements immediately.
3. **Remove eligible completion forwarding.** Introduce only the small owned
   binding needed by the transport and Machine. Implement KVM MSI-X first,
   including masks/pending/reconfiguration, then WHP interrupt triggers.
   Reuse `SET_VRING_CALL`/`SET_VRING_KICK` and standard queue lifecycle control;
   the [vhost-user protocol](https://www.qemu.org/docs/master/interop/vhost-user.html)
   already passes notification endpoints. Account for an endpoint cloned by
   an in-flight call: acknowledgement of `SET_VRING_CALL` is not proof that
   the old endpoint can no longer be signaled. Use a real drain/barrier before
   native retirement. Demonstrate zero parent completion wakes on eligible
   unmasked steady-state queues, then rerun QD1 and correctness on all lanes.
4. **Optimize remaining measured work.** Rank the residual cost after steps
   2–3. Reuse bounded block scratch/descriptor storage; remove redundant net
   frame copies; replace buffer-starvation timer polling with actual queue
   readiness where measurements implicate it. Consider admitted ring-view
   reuse only with invalidation on memory/queue reconfiguration and unchanged
   access checks. Apply common improvements equally to the in-process control.
   Further notification suppression must follow negotiated virtio semantics
   and recheck-before-sleep ordering. Add EVENT_IDX only as a complete feature,
   not an advertised bit or an assumption about the guest.
5. **Finish the native comparison and simplify.** Run the full matrix below,
   remove temporary instrumentation from normal builds, and delete superseded
   relay machinery where the new path makes it unnecessary. Retain one clear
   fallback for genuinely unsupported paths. Report each optimization's
   incremental effect, remaining relays and resulting code/unsafe footprint.

If host storage service becomes the measured bottleneck at higher queue depth,
evaluate existing safe wrappers for Linux io_uring and Windows overlapped I/O
with IOCP. Compare against ordinary positioned I/O first. These are conditional
experiments, not prerequisites or excuses to build another I/O framework.
Likewise, test locality/affinity as a controlled variable before adding policy.
Do not spend cores in permanent spin loops to obtain the throughput target.

## Correctness that the fast paths must preserve

The parent owns guest-visible transport state; Machine owns native bindings;
the worker receives a narrowly bound signal/wait endpoint. Validate exact
queue indices, access widths, addresses and values against the attached
windows. Reprogramming/reset must retire obsolete registrations before reuse.
Unsupported acceleration is distinct from a failed live registration: report
native failures and unwind ownership; do not silently lose notifications.

For each binding, exercise:

- masked completion, pending-bit read, unmask and function-mask transitions;
  queue/vector changes, NO_VECTOR and shared vectors;
- completion concurrent with mask, route change, acknowledgement, pause,
  memory-table replacement and reset, including a worker retaining an old
  endpoint after native deassignment;
- repeated/coalesced notifications, a full pipe or signaled event, and the
  race between the final ring check and sleeping;
- wrong-width/value/address writes taking the ordinary dispatch path; any
  supported BAR change invalidating its old binding;
- worker failure and partial registration cleanup, without delivery into a
  replacement device or machine; level deassert/reassert where applicable.

Ring state, not event counts, determines work. No additional payload copy,
unchecked host reference into guest-controlled memory, widened memory grant,
kernel patch, weakened confinement, or changed guest hardware declaration is
justified by a faster result. Keep native unsafe calls in the existing backend
owners and prefer existing bindings/RAII types. Do not add a dependency solely
to replace a small already-correct primitive wrapper.

## Comparison and acceptance

Preserve the original report and source. Use two comparisons:

- Same-revision worker versus benchmark-only in-process execution, with the
  same device implementation and all common optimizations enabled in both.
- Candidate versus the frozen benchmark revision, rerun on the same host and
  image. This catches a change that improves the ratio by slowing the control.

Keep the original 4 KiB random and 64 KiB sequential read/write QD1 cases over
PCI and MMIO for one device, four PCI devices, plus 64-byte and 64-KiB network echo. Diagnose
the existing long network tails before claiming an improvement from them.
Add a bounded snuffler QD8/QD32 block mode and concurrent-device case to measure
batching/scaling, alongside QD1. Do not relabel the existing serial four-disk
case as a saturation test or compare echo goodput to one-way network capacity.

Use the physical Linux x86 and Arm machines, macOS Arm, and Windows x86/MSVC;
retain hosted Linux as a secondary check. Pair modes in the same host
allocation, alternate AB/BA, warm up, and collect at least ten pairs of
five-second operations for the final primary cases. Freeze the run design
before comparison. If intervals remain wide, retain and report the first run
and extend the prespecified series to twenty pairs; do not rerun until green.
Use shorter targeted pairs between changes and reserve the full matrix for
integrated candidates. Run independent native lanes without waiting on PRs.

Report absolute rates, p50/p95/p99 latency, paired ratios and 95% paired
confidence intervals. The goal is worker/control >= 1 for useful work per
second and <= 1 for latency and total process-tree CPU per operation. Use a
5% noninferiority margin as an explicit *measurement decision band*: the
interval must exclude a worse loss before calling a result indistinguishable
at that resolution. A repeatable smaller regression remains an open item;
the band is not permission to quietly redefine the goal as “95% as fast.”
An inconclusive interval is not parity. Report cases separately, not one
geometric mean that conceals a platform or QD1 failure.

The Windows guest's refined-jiffies clock cannot establish microsecond
request latency. Validate an existing high-resolution clock on that host, or
report accurately named host notification/service timings separately. Keep
guest tail latency explicitly unqualified until there is a valid clock; do
not change guest CPU features or the kernel just to make the graph complete.
Retain the macOS memory-query limitation if it persists. Account for one
shared guest backing, total parent/worker CPU, native counter semantics and
observer cost as in the original report.

All device kinds must retain their existing correctness/lifecycle behavior.
Block and usernet provide the first performance claim; add focused existing
snuffler filesystem/vsock probes before extending that claim to those devices.
Console remains exercised during boots, not claimed throughput-qualified.
No result here establishes confidential-guest performance or external-server
interoperability. Track startup and private footprint without pretending that
process isolation itself has zero fixed cost.

## Reviewable result

Keep one working milestone branch. Use coherent, functional commits, targeting
under 100 changed lines when practical; do not split a native owner from its
required cleanup merely to satisfy that soft limit. Each optimization needs a
source-level reason, a focused correctness check, and a measured incremental
benefit. Remove complexity that fails to earn its cost. No PR boundary should
block integration or native CI; PR presentation follows a working result.

Deliver the optimized branch, retained measurements and failures, a compact
per-platform parity report, and the runtime/test/dependency/unsafe-code delta.
Name any remaining fallback and performance gap plainly. Then pause and review
the milestone with the user.
