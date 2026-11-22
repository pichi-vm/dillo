# Linked console and network design review

The 46 console and 30 network clauses are unchanged between the earlier audit
and c808d800. Their cited Dillo source/test paths are byte-identical (see
prior-evidence-drift.json). Each clause was compared with the current root
design and its scoped prior evidence. The current interpretations are below; historical
registers linked from README retain earlier evidence and its limitations.
Source-level positives and old native tests retain their original limits.

## Console

The shared device implements ID 3, unnamed port zero, ordered named ports,
MULTIPORT queue numbering, max_nr_ports and configured feature offering.
src/main.rs:445 sizes PCI MSI-X capacity from queue count plus configuration;
that capacity is distinct from correct pending delivery (#166). Configuration
enforces one console, explicit bus, stdio rules, at most 31 named ports, unique
nonempty bounded names, no NUL, endpoint direction presence and unique inherited
numbers above stdio. There are no reserved consumer-specific names.

Offering SIZE/MULTIPORT when resize is configured and queue numbering after
MULTIPORT negotiation conform. The earlier negative verdicts for CONSOLE.09/.41
were overbroad. Activation nevertheless follows configured multiport rather
than negotiated features (#147). Control readiness/repeated PORT_READY replies
remain defective (#148). NUL name serialization and omitted-direction handling
are separate narrow positives; they do not excuse invalid control sequencing.

Named-pipe worker EOF/poll/cancellation behavior is present. Endpoint adoption
does not fully validate type/direction (#153); normal numeric checks and useful
diagnostics do not close that gap. All constructor-error/teardown paths and
non-Linux negative endpoint behavior remain unverified. The global stdout
pipeline is unbounded and not instance-owned (#146). Named TX checks backlog
before an unbounded drain, so a backlog threshold alone does not bound that
batch (#53/#55). Lifecycle and helper ownership remain #17/#141/#160.

Resize accepts four bytes, nonzero little-endian columns then rows, closes the
connection, retains latest size, bounds a partial client to a four-byte buffer
and one-second deadline, and uses private Unix peer/Windows user authority.
The source and earlier native positive tests support the successful negotiated
path; service-family placement and adverse native lifecycle qualification are
separate. No new guest-kernel-specific behavior is proposed.

Supplementary scope remains pinned: Pichi 9d9b88c0d598e3ad0b82125aa7e70bc6cf17178d
resize.rs:59 sends exactly four bytes and bounds connection/write/EOF waiting
to one second. Madrillo cb1eea5c947fd7764bb44297549a407316148039 main.rs:913 handles
its terminal resize and does not relay Dillo's resize protocol. Those pinned
sources were reread; no claim about unexamined later revisions or new integrated
execution is made.

## Network

VirtioNet and NetBackend retain the independent protocol/frame boundary.
Configuration keeps MAC and explicit bus placement separate from connectivity,
defaults to user networking, validates structured/shorthand forwarding and
loopback default bind, and explicitly rejects unavailable bridge/macvtap modes.
The launcher chooses the requested Linux bridge/macvtap or macOS vmnet path;
Windows bridge and non-Linux macvtap are refused. Effective privileged endpoint
authority remains unverified (#80/#151).

Shared user networking re-originates host sockets and implements TCP/UDP,
DHCP/DNS/IPv6 and forwarding. Prior localhost tests support specific closure,
half-close/backpressure and forwarding paths, not all external connectivity.
UDP has source/destination idle reaping; this does not bound the number of
active flows. Unbounded flow maps, DNS job/result queues and detached blocking
resolution remain #60/#17. Frames can be gathered into unbounded allocations
before parsing (#55). Native callback and process teardown need qualification.

The shared protocol portion of NET.18 conforms; the host-service/confinement
portion does not yet have the adopted family boundary. Portable socket and
adapter methods need not all move into a backend crate. Native authority,
endpoint transfer, confinement and supervision must conform, with adapter
modules/helpers inside their worker. NET.05/.07 and CONSOLE.02/.24/.35 are
interpreted on that basis, not as a ban on portable I/O.

Independent constructors are supported. Early isolated workers and process
proxies are missing (#15/#150), so the early-process and proxy equivalence
parts remain unverified rather than being inferred from in-process behavior.
Virtio device reset/reactivation (#19) is distinct from whole-VM fresh
reconstruction (#18); both must preserve the relevant endpoint/lifetime rules.

The linked review is complete as a scoped audit, not a compliance certificate.
Its unresolved native cases have issues; no new native run was performed.
