# Shared MMIO interrupt status experiment

This Linux-only branch measures the cost of the parent completion relay. It
is not a production implementation or a vhost-user specification proposal.
The comparison uses one binary, first with `DILLO_BENCH_SHARED_ISR` absent,
then set. Both worker and in-process modes receive the selected path. Guest
images, kernel, queue depth and measurement durations stay the same.

Each MMIO device receives a sealed, host-only 4-KiB memfd. The first aligned
word is accessed through AtomicU32 operations by both processes. The worker
sets the used-buffer bit before writing the native call eventfd. The parent
transport reads that word and atomically clears acknowledged bits. Used-ring
publication still precedes notification. No guest register or kernel changes.

The experimental feature bit 63 and request 0xffff0001 are unassigned values
used only between this branch's paired processes. The new request passes one
descriptor before queue activation. Existing vhost-user STATUS messages refer
to device status, not this interrupt latch; this experiment does not repurpose
those messages. A production design would need a negotiated, documented
interface with explicit ordering and lifecycle semantics.

The child maps the exact sealed extent after checking its size and seals.
Confinement permits the read-only F_GET_SEALS query; it gains no VM capability.
The page is not included in guest RAM. Only a device-specific KVM
eventfd is exported. The measurement therefore removes the completion relay
and preserves guest-visible ISR publication for ordinary active operation.

The follow-up candidate signals only when setting a previously clear used
bit. It coalesces notifications until the guest acknowledges that bit. This
is also experimental: successful Linux boots alone do not establish the
interrupt and lifecycle contracts below.

The activation-scoped follow-up gives each activation a fresh page and irqfd.
Reset stops the backend, explicitly deassigns its irqfd, and discards the old
status mapping. Retained old handles remain valid but cannot signal the new
binding. Level-triggered declarations use IRQFD_RESAMPLE and a sleeping
resampler which reasserts while status remains pending. This adds a parent
wake after EOI; it removes the completion relay from the delivery path, not
all parent activity or CPU cost. Edge declarations retain edge delivery.

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

The following remain unqualified and prevent merging this prototype:

- Concurrent transport reset/restart and ACK/EOI paths, beyond the fixtures
  above. Asynchronous resampler failure supervision also
  needs integration; the current helper reports its failure at retirement.
- Windows and macOS realization, arbitrary backend interoperability, and a
  full failure/reset/concurrent-acknowledgement qualification.

The MMIO transport tests pass, and 32 PCI-free Linux x86 comparison
boots complete block/network operations in both modes. Neither establishes
the outstanding contracts. Raw local assets, source patch, binary hashes and
measurements are retained under `target/performance/shared-isr-experiment`
and `target/performance/shared-isr-lifetime`
in the main performance worktree. The branch workflow compares both paths
on the same native runner; it is explicitly diagnostic.
