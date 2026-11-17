# Memory, device execution and notification source audit

Baseline: Dillo c808d800; native lanes KVM x86/Arm, HVF Arm and WHP x86.
No new native run, concurrency stress or hostile-guest experiment was executed.
The earlier pinned runs remain limited evidence, not general certification.

## Memory access and lifetime

The three backends allocate ordinary RAM and expose typed views through
MappedSharedMemory. Devices receive read/write and queue-metadata interfaces,
not RAM allocation/replacement methods. Whole ordinary-RAM sharing is allowed.
The unresolved ownership defects are instance binding and backing retirement
(#140), not the breadth of that ordinary export. Generic fixed shared-memory
requirements are refused rather than silently allocating extra hardware;
authorized new-allocation requests still need the Machine admission contract.

MappedSharedRegion (deps/dillo-mmio/src/lib.rs:245) checks local access mode,
offset+length and GPA addition, then delegates to vm-memory. SharedVirtioMemory
and SharedQueueMemory request bounded regions for each access. Their public
operations copy to/from host-owned buffers and do not expose ordinary exclusive
references to guest-mutable bytes. This narrow positive does not prove raw
mapping lifetime or atomicity of scalar metadata. The lockfile's vm-memory
0.17.2 compatibility package delegates to 0.18.0; that dependency's volatile
memory API documents the distinction between volatile access and Rust references.
The CPU/device publication and scalar atomicity obligations still need explicit
qualification (#140). Fences alone do not prove atomic scalar accesses.

Each descriptor's fields are copied into a host DescriptorChain. A guest can
change fields during that copy or change a later descriptor; every obtained
value must therefore be independently bounded. The shared walker uses unchecked
address addition and does not verify head/next indices against queue size.
Queue::is_valid has only test callers and assumes one upper memory bound;
actual exports can have holes and nonzero starts (#53/#54).

QueueMemory uses Option for failed accesses. Queue::pop conflates access failure
and an empty queue; add_used ignores publication failures while advancing its
host index. This newly tracked error-contract gap is #167. Guest malformed
requests and unexpected service failure need distinct dispositions.

| Device path | Metadata and payload handling | Remaining scoped findings |
| --- | --- | --- |
| Block, lib.rs:471/593 | Local chain count bounded by queue size; unsupported flags and descriptor ordering rejected. Host metadata vectors, copied 16-byte header, checked stream lengths and backing sector math; MAX_TRANSFER is 16 MiB. | Shared index checks; bounded outer drain/control progress; exported-range validation before bounded allocation. #53/#54/#55/#167. Earlier blanket unbounded-block-chain and 4-GiB-allocation claims are corrected. |
| Filesystem, lib.rs:288 | Descriptor collection precedes capped request gather; parse uses the host input buffer; reply scatter uses bounded memory calls. | Unbounded collection, partial gather on failure (#66), parser panic/progress (#57/#58), 32-bit-only arithmetic (#64), and explicit count validation (#65), resource tables/host file authority (#56/#59/#41/#67). |
| Console, lib.rs:937/1013/1074 | Host copies for data/control and bounded RX writes; named-port pending input is bounded. | Unbounded TX chain/descriptor allocation and aggregate batch; global output queue, control replies and helper lifetime (#53/#55/#146/#148/#17). |
| Network, lib.rs:346/373/454 | Host frame gather for TX, bounded host RX scratch, guest writes through wrappers. | Unbounded TX chain/descriptor allocation before frame parsing; flow/DNS resources and helper shutdown (#53/#55/#60/#17). |
| Vsock, lib.rs:361/397 | Header parsed from gathered host bytes; RX scatters bounded portions of host packet. | Unbounded TX gather and chain; connection-map/lock-held host-I/O progress (#53/#55/#61). |

These are per-path dispositions, not an assertion that each protocol is fully
secure. The backing/device review records final issue-scope reconciliation.
No direct guest-buffer Rust slice is exposed through the reviewed memory seam;
that does not certify each native unsafe mapping or callback implementation.

## Execution and host resources

All real backend attachment hosts spawn threads using closures and shared Arc
objects. There is no isolated worker bootstrap, explicit handle-transfer
protocol, instance-binding handshake or worker confinement stage. The adopted
hidden subcommands and per-device transport processes are missing on every
host (#15/#150). Linux confinement is #16; Seatbelt and Windows token/object,
handle/job/mitigation policy is #62. No existing sandbox or early-fork guarantee
is inferred from Rust module boundaries.

Block storage calls, filesystem adapters, network-stack sockets and vsock
streams can remain portable implementation modules inside their workers. Their
mere use of std file/socket I/O is not a crate-placement violation. Machine
services must supply native authority, transfer, confinement and supervised
lifetime; those boundaries are missing (#17/#158). DNS creates blocking resolver
threads and retains JoinHandles without joining them; vmnet has asynchronous
callbacks and best-effort stop. Console has stdio/liveness/resize helpers beyond
queue activation. All require inclusion in worker pause and retirement.

Current register dispatch is in-process and synchronous. Native decoding and
instruction completion stay in the CPU backend, a property to retain. There
is no process proxy with sequencing, asynchronous-write accounting, independent
completion/control progress or cross-channel barriers to qualify. #150/#159/
#160 track those missing mechanisms; #162 records actual register error loss.
Current blocking joins under transport reset are not a resumable stop protocol.
Deadlock freedom of the future proxy is unverified, not established by current
absence of IPC.

## Notifications

Kick (deps/dillo-virtio/src/kick.rs) is a blocking saturating counter protected
by one mutex/condition variable. Its predicate loop and retained count preserve
a local pending wake; workers inspect queue indices and drain work rather than
treating count as a request count. Queue code includes acquire/release/full
fences and updates avail_event before rechecking. These are useful mechanisms,
not proof of every race, native eventfd saturation case or protocol error path.

KVM MMIO queue notification registration checks a declared register window,
offset, width and value and deassigns on Drop. PCI currently creates local
kicks without a native notification seam. WHP lacks notification-port/trigger
wiring; HVF needs the future process relay. #161 tracks the required native
paths, including retention of eligible acceleration and no extra IPC payload
copies. No process payload-copy path exists yet to measure.

MMIO transport retains interrupt status and acknowledgement state. PCI retains
MSI-X table/PBA fields, but actual device completion handles are obtained from
the native domain and bypass the table's pending helper. Only tests call
set_pending; unmask clears a bit without pending delivery. HVF/WHP suppress
masked signals without retaining transport PBA state. KVM has additional
enable/mask/programming-error defects. #166 tracks shared completion/pending
integration; #163 tracks KVM native state. The earlier assumption that shared
mask helpers already protect KVM delivery was corrected after tracing callers.

There is no stop acknowledgement that accounts for queued register writes,
native signals, callbacks and relays, nor a complete old-generation retirement
contract. #159/#160/#18/#140 cover these gaps. Submitted native interrupts may
remain pending during pause; absence of software publication after acknowledgement
and absence of stale replacement delivery require explicit native qualification
under #151/#161/#166. No new native interrupt-loss or bypass test is claimed.
