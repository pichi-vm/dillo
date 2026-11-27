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
The page is not included in guest RAM. Only the existing, device-specific KVM
eventfd is exported. The measurement therefore removes the completion relay
and preserves guest-visible ISR publication for ordinary active operation.

The follow-up candidate signals only when setting a previously clear used
bit. It coalesces notifications until the guest acknowledges that bit. This
is also experimental: successful Linux boots do not establish the missing
level-triggered contract below.

The following remain unqualified and prevent merging this prototype:

- Per-activation revocation of exported native events and old status mappings.
  The current binding belongs to the VM, so this is a single-activation probe.
- Native level-triggered reassertion and ACK/EOI races. It retains the existing
  KVM pulse implementation and does not establish level semantics for Arm.
- Windows and macOS realization, arbitrary backend interoperability, and a
  full failure/reset/concurrent-acknowledgement qualification.

The existing MMIO transport tests pass, and eight PCI-free Linux x86 smoke
boots complete block/network operations in both modes. Neither establishes
the outstanding contracts. Raw local assets, source patch, binary hashes and
measurements are retained under `target/performance/shared-isr-experiment`
in the main performance worktree. The branch workflow compares both paths
on the same native runner; it is explicitly diagnostic.
