# Shared MMIO interrupt status experiment

This Linux/Windows experiment measures the cost of the parent completion relay. It
is not a production implementation or a vhost-user specification proposal.
The comparison uses one binary, first with `DILLO_BENCH_SHARED_ISR` absent,
then set. Both worker and in-process modes receive the selected path. Guest
images, kernel, queue depth and measurement durations stay the same.

Each MMIO activation receives a fresh, zeroed, host-only 4-KiB mapping: a sealed
memfd on Linux or a committed pagefile section on Windows. The first aligned
word is accessed through AtomicU32 operations by both processes. The worker
sets the used-buffer bit before signaling the native call endpoint. The parent
transport reads that word and atomically clears acknowledged bits. Used-ring
publication still precedes notification. No guest register or kernel changes.

The experimental feature bit 63 and request 0xffff0001 are unassigned values
used only between this branch's paired processes. The request has an empty body
and one native resource; the child requires SET_OWNER, the negotiated feature,
and no active device. Existing vhost-user STATUS messages refer
to device status, not this interrupt latch; this experiment does not repurpose
those messages. A production design would need a negotiated, documented
interface with explicit ordering and lifecycle semantics.

On Linux the child checks the exact extent and seals; confinement permits the
read-only F_GET_SEALS query. Windows adopts the committed section granted by
the trusted parent through ALPC. Neither resource is included in guest RAM.
The separate call endpoint carries a device-specific KVM irqfd or WHP trigger;
it grants no VM capability. macOS retains its existing parent completion path.

The latch represents pending used-buffer notification, not a completion count.
All queues of the activation share bit 0. `used()` performs a sequentially
consistent OR before the call; `acknowledge()` atomically clears only the
requested low two bits. Reserved bits are never exposed. The current device
path publishes queue notifications only; this does not add configuration-change
notifications. ACK racing with publication may leave the latch clear or set
according to their atomic order. Queue contents remain authoritative; testing
must check progress and pending state, not one interrupt per completion.

The follow-up candidate signals only when setting a previously clear used
bit. It coalesces notifications until the guest acknowledges that bit. This
is also experimental: successful Linux boots alone do not establish the
interrupt and lifecycle contracts below.

Reset stops and joins the backend, retires its native binding, and discards the old
status mapping. Retained old handles remain valid but cannot signal the new
binding. Level-triggered declarations use IRQFD_RESAMPLE and a sleeping
resampler which reasserts while status remains pending. This adds a parent
wake after EOI; it removes the completion relay from the delivery path, not
all parent activity or CPU cost. Edge declarations retain edge delivery.
KVM resampler errors/panics now notify the existing failure observer while the
VM is running, and retirement attempts native deassignment before wake/join.
Windows preserves the existing edge-injecting IOAPIC model: route replacement
quiesces the worker, retires the old trigger, installs a new endpoint and
reasserts pending status. It does not implement level-triggered EOI handling.

The local x86 native fixture performs an actual guest LAPIC EOI, checks
reassertion before transport acknowledgement and no reassertion after it,
then checks an obsolete export against a replacement binding. An analogous
Arm fixture uses guest GIC system-register reads and EOI. It passes on the
native runner at `fefb91e` after explicitly selecting level-triggered delivery;
the earlier fixture incorrectly relied on the GIC reset value. The recorded
failure showed ICFGR=0xaaaaaaaa (edge-triggered), with IAR and EOI otherwise
working. Run 46052881345 measures the corrected version separately.

The transport fixture checks status publication, coalescing until ACK, reset,
failed activation, and isolation from retained callbacks after reactivation.
Its recording native binding verifies retirement calls; the native fixtures
above separately exercise kernel deassignment. These do not establish all
concurrent ACK/EOI/reset interleavings.

The following remain unqualified:

- Concurrent transport reset/restart and ACK/EOI paths beyond the fixtures above.
- Windows level-triggered/EOI realization; existing edge-mode results do not
  establish it. The native trigger/EOI probe does not implement an IOAPIC model.
- External-backend interoperability. The private bit/request values are not an
  assigned interface; the current experiment connects matching Dillo processes.

Current native evidence, including Windows status mapping, trigger retirement
and KVM failure supervision, is retained in the
[execution report](results/2026-11-27-optimization/REPORT.md). The Linux counts
below describe the initial experiment, not the current qualification total.

The MMIO transport tests pass, and 32 PCI-free Linux x86 comparison
boots complete block/network operations in both modes. Neither establishes
the outstanding contracts. Raw local assets, source patch, binary hashes and
measurements are retained under `target/performance/shared-isr-experiment`
and `target/performance/shared-isr-lifetime`
in the main performance worktree. The branch workflow compares both paths
on the same native runner; it is explicitly diagnostic.
