# Backing and device authority review

Source baseline is c808d800. This covers storage, GPT, filesystem and vsock
at source-review scope; native races, teardown and confinement remain
unverified with their issue owners. No new native or hostile-input experiment
was run.

Storage owns BlockBacking/WritableBlockBacking and Qcow2Backing. Mutation is
tied to the same backing session. Qcow2Backing checks a bounded supported
header/profile, checked access bounds and read-only authority, and opens its
engine with DenyImplicitOpenGate. Authorized storage is supplied by the caller;
the adapter does not silently open backing dependencies. Its serialized I/O
and external effects need the worker pause/retirement contract (#17/#18/#160).
This does not re-certify imago internals or native storage durability. Raw
backing still lives in virtio-blk and must move under the adopted role (#158).

GPT is a read-only BlockBacking, not an additional guest device. assemble
opens explicitly configured files; synthesis checks partition count, lengths,
alignment and checked disk-size arithmetic; VgptBacking dispatches across
metadata, gaps and file-backed regions. Normal construction supplies matching
vectors, while its public constructor asserts consistency. It currently
imports BlockBacking through virtio-blk and has the old virtio-gpt name (#158).
Portable positional reads may stay in this backing implementation. Worker
bootstrap must validate untrusted resource descriptions before constructing
such objects; the constructor assertions are not a wire-validation boundary.
Stable authorized endpoint identity and reboot handoff remain #18/#17.

Filesystem Passthrough retains a canonical root path, sanitizes lexical input,
then canonicalizes an existing ancestor and later reopens a pathname. This
does not establish retained identity or race-free containment (#41/#52).
Existing-special-file opens lack the intended type/authority guard (#56).
Current FUSE node/handle maps and directory snapshots are unbounded (#59);
current main stores paths, not the unmerged proposal's retained O_PATH objects.
Resource exhaustion must not trigger a weaker confinement fallback.

The inspected parser paths retain the short-WRITE slice panic and unchecked
SystemTime construction (#58), xattr growth nonprogress (#57), and dispatch of
partially gathered requests after a memory read error (#66). SETXATTR's reported
addition overflow concerns 32-bit hosts (#64); bounded request bytes plus a
u32 size do not produce that overflow on the four supported 64-bit lanes.
BATCH_FORGET breaks when an entry cannot be read (#65); remaining work is
explicit count/length consistency, not an unbounded loop for a short buffer.
Windows current-main rename is path-based; #67's specific handle-to-path helper
belongs to its cited proposal. Native identity/race qualification is still open.

Vsock's UDS implementation is Unix-only and opens a guest-selected numeric
port under a configured endpoint directory. Its connection manager retains
unbounded guest-selected entries, including rejected requests until receive
cleanup. Blocking connect/write and per-stream timed reads occur under the
manager lock (#61). Queue gathering/buffer budgets remain #53/#55; failure and
shutdown must join shared supervision rather than depend on eventual blocking
I/O completion (#141/#159/#160). A read timeout on each stream does not bound
a sweep over an unbounded connection map. The native endpoint authority must
be supplied and confined through the Machine family (#17/#16/#62), while the
portable connection state machine stays in the device module.

Existing issue evidence remains scoped to its named revision and execution
level. Issues #59/#64/#65/#67 were clarified; #41/#52/#56/#57/#58/#61/#66 retain
source-supported findings. #63's checked sector arithmetic is already present,
but its outstanding explicit IN/OUT boundary/overflow test matrix is retained
as verification work, not an unchanged unchecked-math defect. No issue was
closed based only on a source pattern or a general component-test count.
