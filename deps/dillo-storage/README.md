# Qcow2 integration

Dillo uses the MIT-licensed [pichi-vm/imago fork](https://github.com/pichi-vm/imago), pinned by commit in Cargo.toml. Upstream is [hreitz/imago](https://gitlab.com/hreitz/imago). Library changes remain separate from the dillo protocol adapter so they can be proposed upstream. No upstream merge request has been submitted.

This is the initial integration, not completion of the [full implementation plan](https://github.com/pichi-vm/dillo/blob/docs/qcow2-research/deps/dillo-virtio-blk/PLAN-qcow2.md). It is not production-qualified for power-loss recovery or hostile images. Keep the broader plan's qualification gates in force.

## Usage and supported profile

Create a compatible sparse disk with:

```
qemu-img create -f qcow2 -o compat=1.1,cluster_size=65536,lazy_refcounts=off data.qcow2 20G
```

Attach it to an existing dillo invocation using:

```
--blk path=data.qcow2,format=qcow2,bus=mmio
```

Select a bus available in the machine contract (`mmio` or `pci`). Add `readonly` for a read-only attachment. The equivalent JSON block object accepts `"format":"qcow2"`. The format defaults to raw; filename extensions never select the format. Existing GPT attachments retain their read-only contract.

The initial admitted profile is clean standalone qcow2 v3, 64 KiB clusters and 16-bit refcounts. Backing files, internal snapshots, encryption, lazy-refcount feature bits, extended L2, external data, nondefault compression feature bits and autoclear state are refused before handing mutation authority to imago. The fork's snapshot-retention test does not imply that dillo admits snapshot-bearing images yet.

Writable launch acquires an exclusive file lock and tests required host reclamation on a disposable sibling file. This needs permission to create a temporary file in the image directory. Unsupported hole punching fails launch. Read-only launch takes a shared lock. Locks coordinate cooperating processes; they do not prevent arbitrary external writes.

## Storage and virtio behavior

The format crate receives an already authorized storage object and denies implicit opens. A backing's writer comes from the same session as its reader; raw descriptors no longer bypass format translation. Dillo advertises DISCARD for the admitted writable qcow2 backend. Limits are 32 ranges and 65536 sectors per range. Both MMIO and PCI deliver negotiated feature bits. Descriptor fields may cross descriptor boundaries, and all ranges are checked before mutation.

Discard reclaims eligible complete clusters; partial edges remain allocated as required to preserve neighboring bytes. Guest filesystem free space is reclaimed only when the guest submits discard, such as through `fstrim`.

The fork durably removes mappings before punching, retains the last refcount until the punch completes, and serializes reuse with the allocator. Failures propagate and can leave recoverable leaks. Guest FLUSH invokes both format flush and storage sync. When FLUSH is offered but not negotiated, successful mutations are synced before completion. Worker shutdown flushes and reports errors through the worker handle.

## Validation and remaining gates

Executed on Linux: imago async and sync unit suites; explicit QEMU reclamation/snapshot/reuse tests on tmpfs and Btrfs; dillo component unit tests; a test driving split-descriptor discard requests through the actual virtio request handler, checking allocated blocks and `qemu-img check`; clippy and Linux compilation. The QEMU-dependent tests are explicitly selected with `--ignored` and fail if QEMU is missing:

```
cargo test -p dillo-virtio-blk --lib -- --ignored
```

Imago and the dillo binary also cross-check for Windows/MSVC and macOS/ARM64. Cross-compilation is not native runtime evidence.

Still required before production qualification: native APFS/NTFS runtime tests; Linux guest FITRIM/online-discard/reboot tests on both transports; broad storage-reordering/torn-write/disk-full recovery tests; dirty-state lifecycle and recovery policy; adversarial image/parser qualification; host-process/confinement conformance; and the remaining format/lifecycle milestones in the full plan. The new failure tests specifically cover reclamation ordering and cancellation, not all qcow2 allocation crash behavior.
