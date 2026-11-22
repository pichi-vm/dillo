# CPU, device and debugger lifecycle source audit

Baseline and scope are those in README.md. This reviews the current ordinary-VM
shared path and KVM x86/Arm, HVF Arm and WHP x86 implementations. Native stop
boundary experiments, failure injection and debugger qualification have not
been run in this pass. SNP mechanisms remain explicitly deferred.

## Implemented path

`src/main.rs:2618` creates CPU wrappers, calls `prepare_vcpu_run`, starts a
thread for each CPU, and starts a polling supervisor-stop monitor. The first
returning CPU sets shared shutdown and requests that peers stop. The main thread
joins CPU threads and collects errors; guest reset/poweroff can replace the
stored outcome as joins are visited. Operator stop is checked again afterward.
This is a shared terminal-run coordinator, not the adopted resumable lifecycle
state machine.

KVM/WHP CPU objects are shareable wrappers around mutex-protected runners;
native creation/programming happens during attachment. KVM stop requesters are
shared across the VM; WHP has per-CPU cancel handles. HVF uses owner-thread
native creation and a CPU runtime that parks APs for guest PSCI startup, but
its terminal stop/shutdown behavior is shared VM state. Existing native kick
and signal-mask tests are useful terminal-interruption evidence; they do not
prove every resumable stop/reentry/instruction-settlement requirement.

`run_selected` creates one VM, memory and device composition. Guest reset calls
`reset_for_reboot` on that same VM and replays launch writes. It retains device
objects and transports, and does not retire their outstanding activity before
replay. #18 now requires fresh reconstruction instead of repairing this loop as
an in-place reset mechanism.

Device workers use shutdown/join closures. `VirtioDeviceHandle::drop` requests
shutdown, joins and logs errors; it does not promptly notify VM supervision
while the guest is running. Transports retain activation handles. User-network
stack threads, DNS workers, console stdio/lifetime work and native callbacks
also need lifecycle accounting outside virtqueue activation. #141 tracks
unexpected failure propagation; #17 covers helper ownership; resource-specific
backpressure/termination defects retain their existing issues.

## Rule dispositions

| Requirement family | Current source disposition | Qualification / issue |
| --- | --- | --- |
| Owner runner vs shareable control (CPU-001) | Logical BSP/AP workers exist; KVM/WHP creation is not on their eventual execution owner; native HVF owner affinity is respected. There is no complete separate resumable control contract. | #159; lazy native AP creation is allowed, not a defect. |
| Opaque ordinary CPU state (CPU-002) | Public ordinary interfaces do not expose general postlaunch register read/write. Native exit decoding/completion remains backend-private. Authorized debug service is absent. | Preserve the narrow normal interface; #160 adds separate authority. |
| Shared lifecycle and safe stopping (CPU-003) | Shared terminal coordination exists, but no machine/transition-identified resumable acknowledgements, run-permission protocol or CPU/device barrier. | #159. Exact native instruction settlement/reentry remains unverified under #151. |
| Fresh reconstruction (LIFECYCLE-001) | Reset reuses the VM, RAM, transports and devices. Stable input retention, endpoint handoff and old-generation retirement are missing. | #18, #140, #157. Stream disposition is not inferred from retained current objects. |
| Unexpected failure (LIFECYCLE-002) | CPU errors return failure; worker failures are not promptly supervised. No current automatic worker respawn was found. Some helper errors are treated as EOF/shutdown. | #141. No-respawn is a constraint to preserve, not an allegation of an existing retry loop. |
| Intent precedence (LIFECYCLE-003) | Join-order outcome selection and a later operator-stop override do not implement the adopted unified arbitration or generation isolation. | #159; #18 for retired-generation reset behavior. |
| Effect-aware errors (LIFECYCLE-004) | Results do not encode the adopted refused/pending/coherent-stopped/terminal distinction. Register and native route paths discard errors. Debug/reconstruction error semantics do not exist yet. | #159, #162, #163. Ordinary propagated errors often already terminate; not every Result is alleged unsafe. |
| Stop deadlines (LIFECYCLE-005) | There is no acknowledged resumable stop/deadline mechanism to qualify. Current blocking joins do not establish stopped/debug authority. | #159. Required deadline diagnostics and matching late replies remain missing/unverified. |
| Debug authority and all-stop (DEBUG-001/002) | No debug service/session, stop-scoped capabilities, device drain or settled-exit barrier is implemented. | #160, with bounded traversal #53/#54 and helper/resource issues. |
| Selected resume/step (DEBUG-003) | No selected-CPU resume/step or device-ready barrier; parked AP state only participates in ordinary boot/terminal shutdown. | #160; do not equate AP power-on with resume. |
| Detach/loss policy (DEBUG-004) | No session cleanup, reconnect hold, authority revocation or uncertain-command handling exists. | #160. The policy was adopted; this is an implementation gap, not a new decision. |
| Reboot debugger holds (DEBUG-005) | No boot-wait/session hold gate; reset is the retained-machine loop. | #160/#18. Replacement must hold after finalization when required. |

Absence of a capability is source evidence of missing implementation, not a
reproduced bug in a nonexistent native debugger. Where a requirement describes
the behavior of a future operation, its native behavior stays unverified while
the missing operation is tracked. An ordinary successful boot cannot close
these requirements.

## Cross-boundary review

The supervisor cannot obtain device quiescence by joining only CPUs. It must
also account for register writes admitted during native exit settlement,
devices activated by those writes, event channels, native signals, host I/O
and callbacks. Likewise, a device's pause acknowledgement cannot prove mapping
revocation or authorize freeing its backing. Retirement and paused correctness
are different requirements. The current APIs provide neither a complete cohort
barrier nor a retirement proof.

Service errors must preserve what is known about effects: a failed native route
update can leave the old route live, and a register write may have taken effect
before its reply is lost. The current bool/Option dispatch conversions and KVM
message-route helper returning unconditional success discard that information.
#162/#163 are concrete boundary defects, independently useful even before a
debugger is implemented.

Interface consequences are a non-shareable owner runner, narrow shareable CPU
and device controls, instance/transition identities, effect-aware completion,
separate finalization/run/stop/debug authority and explicit retirement. A shared
runtime owns policy; native backends implement mechanisms. The major contracts are specified in
[INTERFACES.md](../../../INTERFACES.md), with primary-source research and
explicit qualification limits.
