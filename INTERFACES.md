# Machine interfaces

This document specifies the major implementation contracts for
[DESIGN.md](DESIGN.md). The design's rule IDs remain normative. Names and Rust
signatures below are illustrative, not a compiled API or an implementation
claim. Native qualification requirements remain explicit. Confidential-target
mechanisms, including SNP, are deferred; an ordinary VM is not a substitute.

The [source audit](docs/audits/2026-11-17/README.md) records current gaps and
issue owners. [Primary-source research](docs/interface-research.md) grounds
the native execution and process boundaries. Neither document changes policy.

## Contract ownership

The executable selects a Machine family, retains authorized launch/session
inputs, supplies concrete factories, and dispatches normal or hidden-worker
entry points. It does not become a second implementation of lifecycle policy.

| Owner | Contracts and callers |
| --- | --- |
| `dillo-machine` | Family-associated CPU, memory, admission, notification, process, lifecycle and debug service contracts; consumed by shared layers and implemented by native backends. |
| `dillo-devtree` | Draining tree, declaration claims and provenance; consumed by launch and native substrate handlers. |
| `dillo-launch` | Stable validated input, ordered recipe, realization coordinator and finalized launch; consumed by executable/runtime. |
| `dillo-runtime` | Shared supervisor, transition arbitration, stop permits, reconstruction and debug session policy; consumes Machine contracts and launch recipes. |
| `dillo-ipc` | Bounded wire encoding, message identities and resource-role descriptions; consumes Machine contract vocabulary. |
| `dillo-worker` | Parent proxies and child dispatch/bootstrap; implements Machine participant controls and MMIO/PCI interfaces over native channels. |
| Native machine crates | Native execution, memory backing, registration, process creation, confinement and handle transfer. |
| MMIO/PCI/virtio and concrete devices | Reusable transport/protocol behavior; consume only their bound services. |
| Storage crates | Backing I/O and composition over supplied resources, independently of guest transport. |

This preserves LAYOUT-002. Machine contracts do not import launch, devtree,
IPC, worker or concrete device types. `dillo-launch` translates DT claims into
Machine resource descriptions and correlates receipts with those claims.
Native substrate handlers may consume delegated DT entries directly because
their crates already depend on devtree. Their consumed claims and realized
resource receipts still return to the same finalization ledger.

The runtime accepts participant controls implementing Machine contracts; it
does not import worker proxies. Worker accepts local MMIO/PCI interfaces;
the executable supplies transport/device factories inside the child. General
memory, interrupt and execution services move out of MMIO into Machine.
Type erasure is permitted after family selection and instance binding; a
trait-object wrapper must not discard that binding.

## Family, instance and admission

A family describes native service types without requiring a live VM. An
instance owns one realization and its execution authority. Family compatibility
alone never authorizes cross-instance attachment.

```rust,ignore
// Contract sketch: associated names denote the interfaces described below.
trait Machine: Sized {
    type Platform: PlatformServices;
    type CpuSetup: CpuSetup;
    type CpuControl: CpuControl;
    type MemoryExport: GuestMemoryAccess;
    type DeviceServices: BoundDeviceServices;
    type Debug: DebugAccess;

    fn admit(&mut self, request: ResourceRequest) -> Outcome<Admission>;
    fn allocate(&mut self, admission: &Admission,
                request: AllocationRequest) -> Outcome<Allocation>;
    fn bind_device(&mut self, admission: &Admission)
        -> Outcome<Self::DeviceServices>;
    fn export_memory(&mut self, device: &DeviceBinding)
        -> Outcome<Self::MemoryExport>;
    fn prepare_cpu(&mut self, admission: &Admission,
                   role: CpuRole) -> Outcome<Self::CpuSetup>;
    fn finalize(&mut self, evidence: RealizationEvidence)
        -> Outcome<LaunchSeal>;
}
```

`ResourceRequest` carries requirements, not allocation authority. Admission
checks the selected model's declarations, bounds, relationships, conflicts and
backend limitations. Every entry point, including independently constructed
devices, uses the same checks. Machine chooses allocation placement only
within delegated PMI authority; it cannot invent additional guest-visible RAM
or hardware. Requests for access to existing virtqueue buffers are not new
allocations. Unsupported requests fail explicitly.

Admissions, exports, CPU preparation receipts and registrations identify the
instance and resource. Their constructors belong to trusted admission/native
code, with validation at cross-crate and wire boundaries. Rust visibility is
an API discipline, not protection against a malicious host or compromised
worker. Bound OS endpoints and retained authorization records enforce worker
authority; a serialized instance ID by itself does not.

Use separate identities for instance, participant, launch, run, stop and debug
session. Check them when applying commands or accepting acknowledgements.
Monotonic counters fail on exhaustion rather than wrap. Reused addresses,
descriptor numbers or CPU indices do not identify a replacement instance.

## Stable launch and complete realization

`LaunchRecipe` belongs to launch. It retains stable validated bytes, selected
architecture/target/profile, ordered actions, delegated configuration and
authorized resource identities needed by reconstruction. It does not retain
live CPU/device state or mutable guest RAM as a source for another boot.

Acquire immutable contents before parsing: accept a source whose immutability
is established, or capture owned bytes and validate that capture. A pathname,
open file or read-only mapping of a mutable file is insufficient. Actions
reference the stable source by checked ranges; each retains its own destination
and operation, including Zero extents and Padded tails. This avoids per-action
staging copies. Acquisition may require one retained copy; it does not add
copies to routine device payload I/O.

The realization coordinator maintains both directions of the resource ledger:

1. Drain every DT node/property exactly once, including informational and
   structural entries, with explicit delegation to responsible handlers.
2. Associate hardware claims with admitted requirements and actual native or
   software resource receipts. Account for implicit effects of native APIs.
3. Check every required claim has its faithful realization and every realized
   resource has authority. Empty drain state alone is insufficient.
4. Account for ordered launch actions, fills, CPU preparation and worker
   readiness. Refuse unsupported profiles, shapes and resource relationships.
5. Perform target finalization and return a seal bound to this instance.

Launch passes Machine a contract-level realization summary, not an untrusted
boolean saying the DT is empty. The launch coordinator owns DT completeness;
Machine owns validation of its admissions, native receipts and target finish.
Together they produce a finalized launch. No component may mint execution
permission from CPU count alone. All CPU workers require the seal and current
runtime permission; APs additionally require guest-directed startup.

Only the BSP receives PMI's fixed target/architecture state. `CpuRole` is
`Bsp` or `Ap`; it is not a caller-supplied register image. Target preparation
performs the prescribed BSP setup. The guest supplies AP startup semantics
through the native backend. Logical readiness, native CPU existence and run
permission remain distinct, including for targets that create AP state later.

## CPU owner and control

```rust,ignore
trait CpuSetup: Send {
    type Runner: CpuRunner; // no Send or Sync bound
    fn bind_on_owner(self) -> Outcome<Self::Runner>;
}
trait CpuRunner {
    fn prepare(&mut self) -> Outcome<CpuPrepared>;
    fn progress(&mut self, permission: &ExecutionGate)
        -> Outcome<CpuProgress>;
    fn retire(&mut self) -> Outcome<CpuRetired>;
}
trait CpuControl: Send + Sync {
    fn request(&self, command: CpuCommand) -> Outcome<CommandId>;
}
```

The shared owner-worker loop binds setup, creates/operates/destroys the runner
on its native owner thread, and reports through an event channel. The
supervisor holds controls and wake endpoints, never the runner. Every logical
BSP and AP has an owner worker; parked APs still service lifecycle commands.
Preparation may create native state immediately or retain a guest-startable
AP, according to target semantics. Moving setup must not move an already
thread-affine runner.

Setup establishes the paired control/event endpoints through the selected
family. The runner's native wake endpoint becomes available after owner
binding; logical mailbox wakeup also works before native creation. Neither
endpoint exposes the native CPU object to its caller.

`CpuCommand` expresses prepare/run selection/stop/retire, with debug commands
on a separately authorized path. `CpuProgress` distinguishes runnable or
guest-parked state, interruption, pending exit completion, debugger cause,
guest reset, poweroff and failure. The ordinary contract exposes no register
getter/setter, state snapshot or restore method.

The runtime publishes permission/transition state before waking an owner.
Every native entry and internal reentry checks it. The backend must close
the check-to-entry race using its native mechanism. A one-shot cancellation
call is not itself proof of that handshake; WHP and HVF require native race
qualification. A parked AP also has a wake path independent of native entry.

Native instruction decoding and reply destinations remain owner-private.
An exit can yield a pending device operation, allowing independent control
and reply processing. A synchronous native callback may wait on the CPU
owner only if its completion/control services can progress independently;
it holds no shared bus or supervisor lock across that wait.

Stopping settles an admitted instruction before acknowledging the CPU. KVM
may require completion reentry with execution suppressed. No subsequent guest
instruction may execute merely to finish a stop. A CPU waiting on device I/O
remains an outstanding participant; a timeout cannot turn it into a stopped
CPU. Native completion errors retain their effects classification.

## Memory access and resource lifetime

Machine owns layout, allocations and backing lifetime. A `MemoryExport`
contains checked region metadata and retained backing access for one instance.
Workers receive the permitted OS mapping resources, never VM/vCPU handles
or allocation/replacement authority. Ordinary devices may share the whole
exported RAM. This deliberately provides no same-VM device-to-device memory
isolation or per-request exclusive ownership.

`GuestMemoryAccess` provides checked byte/descriptor access against actual
regions, including holes, with overflow and permission errors. Validity is
not inferred from a single maximum GPA. Guest contents remain concurrently
mutable; validated descriptor/control fields must not be replaced by unchecked
rereads. Access wrappers must preserve Rust memory safety without fabricating
exclusive references. Protocol publication ordering remains the device's
responsibility. This contract does not require an extra full payload copy.

Exports and native I/O leases keep backing alive while mappings, callbacks
or kernel references may use it. Quiescence is not revocation. Child exit
alone does not account for external native references. Retirement inventories
those references and prevents backing or endpoint reuse until old access can
no longer reach a replacement. An unsafe reclamation is not justified by a
terminal VM status. Private-memory exports and transitions require future
target-native mechanisms; no generic live memory-replacement RPC is specified.

## Worker construction and confinement

`PlatformServices`, associated with the selected family, supplies process
creation, channels, event endpoints, wait/exit observation, explicit resource
transfer and confinement. It can create an unbound worker before Machine
construction. `BoundDeviceServices` supplies only admitted memory access,
interrupt/notification requests and lifecycle endpoints after instance binding.

The same executable's hidden entry point constructs one device and its
independently selected per-device transport. Bootstrap carries validated data
and explicit native resources, not closures, pointers or parent Rust objects.
Worker-local thread helpers remain possible and belong to that worker's
lifecycle. Portable filesystem, network and storage adapters remain modules
in their respective crates; native authority comes from the bound services.

```rust,ignore
trait PlatformServices {
    type Child: WorkerProcess;
    type Channel: ResourceChannel;
    fn spawn(&self, spec: WorkerProcessSpec)
        -> Outcome<(Self::Child, Self::Channel)>;
}
trait WorkerProcess {
    fn observe(&mut self) -> Outcome<ProcessState>;
    fn terminate(&mut self) -> Outcome<RetirementId>;
    fn reap(&mut self) -> Outcome<ProcessExit>;
}
trait DeviceControl: Send + Sync {
    fn request(&self, command: DeviceCommand) -> Outcome<CommandId>;
}
```

These contracts live in Machine. `WorkerProcessSpec` describes the authorized
executable entry and inherited resource inventory, not a concrete device Rust
constructor. `ResourceChannel` transfers bounded frames and explicit native
resources; IPC defines their message encoding and worker defines dispatch.
`DeviceCommand` carries the lifecycle operations below; a separate event
stream returns progress, matching acknowledgements and failures. Submitting
a command is not acknowledging it. Worker proxies implement `DeviceControl`
so runtime does not depend on the worker crate.

The parent sends an exact built-in wire version, instance/device identity,
declared resource limits, transport/device selection, memory-region metadata
and handle roles. The receiver validates message bounds and resource types,
rights, counts and roles before construction. OS transfer and peer creation
establish authority; IDs correlate it. Built-ins use one executable version
and reject mismatches rather than guess compatibility.

Ready means construction, mappings, binding and confinement succeeded, not
merely that a process was spawned. No guest input is admitted beforehand.
All worker threads are confined: default-deny seccomp-BPF plus `no_new_privs`
and resource/privilege restrictions on Linux; default-deny Seatbelt and a
closed descriptor inventory on macOS; AppContainer/LPAC or restricted-token
resource confinement, explicit handles, jobs and mitigations on Windows.
Exact per-device policies need native qualification with actual adapters.
Failure refuses startup. No unrestricted or thread-only fallback, ptrace or
custom kernel mechanism is allowed.

VM/CPU/debug handles and unrelated inherited resources are excluded. Parent
process observation is independent of a worker's ability to send a reply.
Unexpected exit, panic or unrecoverable channel failure ends the VM without
respawn. Normal endpoint EOF and guest request errors have separate meanings.

## Register proxy and notification contracts

Parent MMIO/PCI proxies route only admitted regions. Child dispatch invokes
its local transport/device interfaces. Neither side transfers CPU registers.
Machine validates native route changes; the worker owns transport state.

| Operation | Completion contract |
| --- | --- |
| Read | Correlated exact-width bytes or classified error before native instruction completion. |
| Write | Ordered application or explicit failure; submission alone is not application. |
| Fence | All preceding register operations applied or failed; not a promise that queue payload I/O has finished. |
| BeginDrain | Close autonomous work admission while maintaining services needed by already admitted operations. |
| FinishStop | After CPU settlement, fence the final register sequence and all device/helper/notification effects. |
| Resume | Reopen retained device execution for the current stopped instance/transition. |
| Retire | Permanently close execution and account for process, registration and native-reference retirement. |

Use finite message/queue/resource bounds before allocating from worker or
guest-supplied lengths. Preserve required ordering across CPUs and channels.
Posted writes are allowed only when transport semantics permit; keep an
applied watermark and failure reporting until fenced. Configuration that
changes routing cannot complete before the corresponding validated native
update. A missing reply never authorizes replay of a possibly effective write.
Unmapped-address behavior prescribed by a bus remains distinct from failure
of a mapped device; IPC failure cannot become a successful zero-filled read.

Control/failure/completion processing must progress despite saturated data
queues. No shared lock spans a wait requiring that lock. Queue kicks are
wakeups, not per-request completions; queue state and publication ordering
govern rechecks and coalescing.

Eligible kicks and interrupts use Linux ioeventfd/irqfd and WHP notification
ports/triggers. Workers receive event endpoints; Machine retains registration,
validation, updates and teardown. HVF uses CPU-exit forwarding and a parent
interrupt relay. A forwarded kick does not wait for payload processing.
Routine payload data uses mapped guest backing, not register RPC copies.

Transport interrupt state gates actual completion: vector selection, masks,
pending bits, acknowledgement and route updates must form one ordered path.
A masked completion remains pending according to transport semantics. Changing
a table entry cannot leave queue completion tied to a stale captured vector.
Events already admitted natively and signals on independent channels enter
the lifecycle accounting; a control-channel reply cannot flush them by fiat.

## Shared lifecycle and failure effects

### Local device and backing interfaces

`VirtioDevice` remains transport-independent. Activation receives negotiated
features, validated queue configuration and bound memory/kick/completion
services. MMIO and PCI adapt their transport behavior to that same contract.
Activation returns a participant handle whose failures and helper activity
join worker supervision; it is not a request to spawn another OS process.
UART uses the same worker lifecycle through its MMIO interface without a
virtio dependency. Machine-side syscon/native substrate remain routed under
their declared authority.

Queue access distinguishes an empty queue from invalid or inaccessible
metadata. Conceptually, `pop` returns `Result<Option<Descriptor>, QueueError>`
and `publish_used` returns an explicit effect-aware result. Validate head/next
indices, checked arithmetic, actual mapped extents and finite traversal/work
budgets. Advance host publication state only consistently with successful
guest publication; never notify as if an ignored write succeeded. Guest
protocol errors and broken host services have distinct dispositions.

`BlockBacking` and optional write authority stay independent of Machine and
virtio. The executable supplies authorized backing resources; the worker
owns adapter execution and native-I/O retirement accounting. Raw and QCOW2
implementations belong in storage; GPT composes those backings. Filesystem,
network and vsock adapter interfaces similarly retain portable protocol/I/O
behavior while consuming confined endpoints. Console's resize wire format
belongs to console, with terminal/session policy outside the device. Helper
threads, callbacks and operations blocked in host I/O cannot disappear from
the participant registry merely because a virtqueue is inactive.

### Supervisor transitions

The supervisor owns state transitions and participant accounting. Native
backends supply mechanisms; worker proxies implement the same participant
control contracts as other devices. The participant registry includes helper
threads, callbacks and work outside virtqueue activation. It also includes
devices activated while a pending CPU instruction is being settled.

| State | Allowed progress |
| --- | --- |
| Preparing | Realize claims/actions, bind confined workers and prepare CPU owners; no guest execution. |
| Finalized/held | Launch is complete; execution waits for normal release or authorized debugger release. |
| Running | Release permitted CPUs, preserve guest AP startup and supervise devices. |
| Stopping | Settle admitted work under one transition; no new independent admission. |
| Stopped | Current all-stop permit may authorize debugging; devices cannot access guest queues/buffers or publish interrupts. |
| Retiring | No future execution; join/reap and account for retained native references. |
| Terminal | Report outcome; retain resources still reachable by outstanding native access. |

For an all-stop transition, publish stop permission, interrupt CPUs and begin
device draining concurrently. Keep reply/completion services alive until every
CPU's admitted instruction is settled. Then close the register source and
send each worker its final sequence fence. Collect matching device, helper,
relay and native-delivery acknowledgements. Only the complete barrier grants
a stop permit. No device guest-memory reads/writes or new software interrupt
publication follows acknowledgement. Native timers and already submitted
interrupts may remain pending; external effects are not rolled back.

Resume readies devices first, then releases selected CPU owners. A selected
AP remains guest-parked until the guest starts it. A subsequent stop establishes
a new complete barrier. Stop deadlines report outstanding participants and
dependencies while preserving the same transition. They do not grant inspect,
resume, retry or reclamation authority; explicit termination remains available.

Arbitrate uncommitted intents in design order: unexpected execution failure;
operator termination/guest poweroff; guest reset; debugger stop; resume/step.
Do not undo committed effects or suppress a later-discovered shutdown failure.

`Outcome<T>` expresses effects, not just success/error:

- Completed: operation's stated effect and receipt are established.
- Refused unchanged: previous state and authority remain valid.
- Pending: known progress with a defined safe completion path and identity;
  continue that operation without submitting it again.
- Coherent stopped error: report defined partial debug effects and retain the
  acknowledged stop, without implicit resume or mutation replay.
- Fatal/unknown effects: no coherent state or safe continuation; end the VM
  and retire resources. Do not label uncertainty as endless pending work.

Worker replies cannot prove hostile-process compliance. Frame/identity errors,
impossible transitions and unexpected loss are execution failures. Host
containment relies on confinement; all-stop is a correctness contract for
conformant participants, not RAM revocation.

## Reboot, retained resources and device reset

Runtime reconstruction uses the original stable recipe and fresh Machine
instance, backing, CPU owners, workers, transports and registrations. It
retires old access before replacement release or endpoint/backing reuse.
Endpoints are never retargeted from an old worker to the new machine.

The executable/session layer may retain authorized disk identity/locks and
inherited stream resources outside an execution generation. Handoff occurs
only after old use ends. Completed disk writes persist; uncertain writes are
not replayed. Device adapters define consumed-but-undelivered stream-data
disposition without promising rollback. Final shutdown closes retained
duplicates so they do not indefinitely suppress peer EOF.

A guest virtio device reset is a separate protocol operation inside a live
machine. It must stop and account for that activation's work before clearing
transport state or accepting a new activation. It is not VM reconstruction
and must not become recovery from an unexpected worker failure.

## Authorized debugging

Debug services are separate from normal runner and device services. Machine
grants operations only under host authorization and target policy. Runtime
checks instance, session and current all-stop permit for every command; CPU
operations execute on the relevant owner and memory operations through
Machine. An AP with no inspectable native state reports unavailable, not
invented register values. Debug support includes register/memory access,
breakpoints and selected-CPU resume/step; native support must be qualified.

Only one controller owns command authority. Explicit detach removes installed
session instrumentation and confirms cleanup before resuming devices and
ordinarily runnable CPUs. Cleanup failure does not implicitly resume.
Unexpected connection loss revokes command authority, rejects queued stale
commands and requests/retains all-stop. Preserve instrumentation on that same
target for authorized reattachment; do not replay uncertain mutations.

Reboot invalidates the old session and its instrumentation. A listener may
persist, but the fresh target needs new authorization. Hold it after
finalization and before its first instruction if a debugger was attached,
connection-loss hold was unresolved, or boot-wait is configured. Attachment
does not release that hold. Boot-wait remains configured across reboot and
clean detach even when detach releases the current target.

Ordinary-VM mechanisms do not establish confidential debugging. Future
debug-enabled confidential targets require native access consistent with
their launch policy; debug-denied state remains protected. No API in this
document weakens those requirements or supplies a placeholder mechanism.

## Qualification boundary

These contracts implement adopted policy without an additional architectural
choice. Exact Rust generics, wire encoding and per-device confinement rules
are implementation details subject to these contracts. Native race closure,
instruction settlement, real process confinement, cross-channel barriers,
retirement, debug operations and adverse host-I/O behavior remain qualification
work, not assumed guarantees. The audit links each gap to its issue and
acceptance criteria. This document defines no implementation ordering.
