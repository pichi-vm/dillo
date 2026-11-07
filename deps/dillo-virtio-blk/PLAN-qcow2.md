# Dillo qcow2 implementation plan

Status: proposed implementation program, grounded in [the Rust implementation survey](RESEARCH-qcow2.md). Baseline: `d30e8cfbc6671f4b0e653400cfaca8d7ec948dd3`. This plan does not authorize deployment or claim that the feature exists.

Implement qcow2 as a format-aware backing for dillo's existing virtio-blk device. **Guest TRIM/discard, internal cluster reuse, and actual host extent reclamation are mandatory, including the first usable qcow2 release.** Target Linux/KVM, macOS/HVF and Windows/WHP with Linux guests. Use imago's native synchronous engine as the starting point, with a pinned, maintained patch series; the upstream engine alone does not meet the reclaim/durability requirements.

The program includes backed images, snapshot-safe COW, zeroing, format compatibility, lifecycle operations, recovery, resource limits and all host implementations. A standalone ordinary-v3 milestone is useful for development but does not replace this final scope. Advanced formats remain explicitly refused while their implementation is incomplete. Legacy encryption and unknown extensions have explicit dispositions below rather than silently becoming supported.

## Requirements and ownership

| ID | Required outcome | Owner and proof |
| --- | --- | --- |
| R1 | qcow2 virtual capacity and guest bytes are correct; raw behavior remains compatible | Dillo storage engine; QEMU differential tests and raw/GPT regression suite |
| R2 | Guest discard frees eligible qcow2 clusters and host allocation; subsequent writes reuse freed space | Engine plus host services; guest fstrim, allocation accounting and repeated churn |
| R3 | No mutation bypass for read-only images or synthesized GPT | Dillo capability types; byte-identical fixtures after every mutating opcode |
| R4 | Flush, allocation, deallocation and shutdown preserve acknowledged durable data across failures | Engine and worker lifecycle; crash/fault matrix, reopen and qemu-img check |
| R5 | All three host backends implement storage and reclamation with truthful capability reporting | KVM/HVF/WHP; native host integration tests |
| R6 | Backing chains, shared references, compressed/zero/subcluster mappings and advanced profiles are handled or explicitly gated per the matrix | Engine; feature-specific interoperability tests |
| R7 | Parsing and guest requests are bounded, checked and confined to authorized storage | Launcher, host service and virtio; adversarial/fuzz tests |
| R8 | Creation, conversion, checking, repair, resize and snapshot management have defined ecosystem ownership | Pichi manages images; dillo provides live I/O/quiescence; PMI contract unchanged unless separately designed |
| R9 | Performance, space accounting, failures and support limits are observable and documented | Dillo diagnostics and Pichi workflow; benchmark/report gates |

Dillo's [design rules](../../DESIGN-RULES.md) govern host primitives and process isolation. Shared protocol and format logic must not create host processes, choose OS syscalls, or acquire additional filesystem authority. Pichi owns image management; PMI owns the image contract. External qcow2 disks do not imply changing the embedded PMI boot image or making synthesized GPT writable. Current Pichi `src/cmd/run.rs::build_dillo_args` and `src/cmd/build.rs::build_dillo_args` construct `--gpt` carapace attachments; qcow2 is a new explicit disk attachment/workflow, not a reinterpretation of their COW/verity partitions. Preserve those paths and their tests. Pichi work must follow its AGENTS.md/BUILD.md contracts. Windows integration targets native MSVC/WHP, not MinGW.

## Storage architecture

Replace the raw-file write side channel in `src/lib.rs` of this crate. A backing factory returns a single image session with read access, optional mutation capability, immutable geometry, and advertised operation limits. Read and mutation views must share the same locked format state and image identity. Do not allow callers to pair an arbitrary read backing with an unrelated writable object.

Keep `BlockBacking` or an equivalent read trait for GPT compatibility. Introduce a separate `WritableBlockBacking` capability containing exact write, discard and write-zeroes operations. Geometry and capability results include virtual length, logical/physical sector size, discard alignment, maximum ranges/sectors, zero support and whether host reclamation is available. Use a sealed constructor or session-owned accessor to derive the optional writer. Effective read-only state is the union of CLI policy, backing policy and absence of mutation authority.

Reads/writes use exact-length semantics at this boundary. Internally loop over short positional I/O and EINTR; reject unexpected EOF/zero-progress rather than completing a partially transferred guest request as success. Use checked arithmetic before offset multiplication/addition, descriptor accumulation and allocation. Enforce capacity at the guest boundary and again in the engine. Do not infer capacity from the container's host file length. Reject non-512-byte-aligned virtual capacities rather than silently rounding away the tail. Read-only flush is a successful no-op; it must not require a writable host handle. Choose 512-byte logical sectors; qcow2 cluster size is allocation geometry, not a reason to advertise a 64 KiB logical or physical sector.

Create a focused `dillo-storage` crate for storage contracts, raw backing and the qcow2 adapter, with the existing GPT crate implementing the read interface. Keep `dillo-virtio-blk` focused on protocol behavior. Avoid circular dependencies with `dillo-machine`: common storage contracts live below host implementations, which supply concrete storage services. The initial API names are design names, not claims about existing interfaces.

Use imago `default-features=false, features=["sync"]`. An owning mutex or worker-owned mutable session provides safe discard access and serialization; the format library's unsafe discard entry points should not be called from virtio code. Implement its storage primitive boundary in an audited adapter where unavoidable unsafe code is narrowly allowed under the repository's lint policy. Do not expose path-based implicit opening to the engine. Use an explicitly opened object plus denial of implicit opens and attach only authorized backing/data objects.

### Host storage services

A `HostFile` contract supplies exact positional reads/writes, length, metadata sync, data sync, allocation accounting, alignment/capability queries, lock acquisition and host-range deallocation. Image opening and descriptor/handle transfer are owned by the launcher and selected host backend. Store capabilities with the open file session, not as global OS assumptions.

- Linux: `fallocate(PUNCH_HOLE | KEEP_SIZE)` on supported filesystems; no substitution of `ZERO_RANGE`, which need not free space.
- macOS: `fcntl(F_PUNCHHOLE)` with filesystem alignment handling. Implement the durability primitive needed by the selected power-loss contract, including evaluating `F_FULLFSYNC`; ordinary cache flush must not be labeled durable without evidence.
- Windows: mark writable sparse files with `FSCTL_SET_SPARSE`, deallocate using `FSCTL_SET_ZERO_DATA`, and flush with the proper file-handle primitive. Query allocation using native allocation-size/range APIs; do not use apparent length as a surrogate.

Use file-backed sparse regular files for this feature. Probe capability using host/filesystem information or a disposable sibling file, never by punching a live image range. Treat OS errors separately: unsupported operation, insufficient space/quota, I/O failure, permission failure and transient interruption are not interchangeable. For supported filesystems, reclaim failures propagate and diagnostics retain the host error.

Proposed policy: writable qcow2 defaults to `discard=unmap,reclaim=required`; fail launch when host reclamation is unavailable rather than silently promising it. Explicit `reclaim=best-effort` permits internal reuse with a reported degraded state. `discard=ignore` is an opt-out, never the default qcow2 experience. Successful reclaim means eligible live-file extents were released; host filesystem snapshots/reflinks may continue to retain underlying physical blocks. TRIM is not secure erase.

### Process and lifecycle integration

The current device source describes an in-process worker, while the design rules require out-of-process execution where available. Route the image session through the existing `VirtioDeviceHost`/host-worker boundary and extend that boundary as needed; do not add a second ad hoc worker architecture inside the storage crate. On hosts supporting process isolation, the backend owns worker creation, handle transfer and confinement. Linux filters must allow only required positional I/O, sync, deallocation and IPC operations over authorized handles. Backing chains and keys are resolved before confinement.

The worker owns image state until its requests and pending host deallocations are drained. Shutdown/reset: stop intake, finish accepted operations, flush format caches, sync all writable image components, finish reclamation, clear dirty state durably when safe, then release locks. Return errors through join/supervisor status; do not rely on Drop to report persistence failures. Device reset must preserve disk state while clearing negotiated transport state. Abnormal worker exit leaves the image marked for checking; a timeout cannot authorize abandoning in-flight writes and reopening the same image concurrently.

## Virtio changes

Update the existing feature/config/request implementation in `deps/dillo-virtio-blk/src/lib.rs`. Preserve one queue initially; correctness and bounded memory precede multiqueue optimization.

| Item | Required change |
| --- | --- |
| Feature negotiation | Offer DISCARD bit 13 and WRITE_ZEROES bit 14 only for eligible writable sessions. Add negotiated feature delivery to `VirtioActivate`, which currently has no such field; populate it in both MMIO and PCI transports. Clear it on reset. |
| Configuration | Extend the current 32-byte image through byte 59. Discard maximum sectors/segments/alignment are at offsets 36/40/44; zero maximum sectors/segments/unmap flag at 48/52/56. Keep reserved bytes zero, support partial reads, check transport device-config window length. |
| Request dispatch | Implement DISCARD type 11 and WRITE_ZEROES type 13. Parse each 16-byte little-endian range record (`sector`, `num_sectors`, `flags`) across descriptor boundaries. |
| Validation | Check negotiated capability, descriptor direction/order, header/status layout, payload multiple of 16, range count, per-range sector limits, arithmetic, capacity, flags and read-only state before mutation. Bound descriptor traversal and buffer allocation. |
| Completion | Return spec-correct OK/IOERR/UNSUPP. Unknown range flags and DISCARD's unmap bit get UNSUPP. Status-byte guest-memory failures and malformed chains must not crash or hang the worker. Used lengths count device-written bytes only. |
| Zero semantics | WRITE_ZEROES must read back zero regardless of UNMAP. With UNMAP clear, retain existing allocations; allocate where a backing value must be masked if necessary. With UNMAP set, deallocate only when zero-read semantics remain true. |
| Ordering | A completed FLUSH covers all prior successful writes, zeroes, metadata changes and pending deallocation relevant to durability. If FLUSH is offered but not negotiated (and CONFIG_WCE is absent), persist each write before reporting completion, including the data and metadata needed to preserve it. Apply the effective durability policy to zero/discard mutations too. No configurable write-cache mode is added until its semantics and negotiation are implemented. |

Use a bounded scatter/gather cursor instead of assuming headers or records occupy individual descriptors. Reject a request exceeding limits before changing the image, but do not promise transaction-wide rollback after a later host I/O failure: virtio allows indeterminate per-range results on IOERR. Start with at most 32 range records and 65536 sectors per range, further restricted by the backend (the separate 16 MiB transfer cap applies to data I/O, not the logical span of discard); tune only with benchmarks. Do not expose guest-requested allocation sizes directly to Vec allocation. Guest logical-sector validation is independent from inward rounding to reclaimable qcow2/host extents.

## Allocation and reclamation invariants

A discarded guest range is translated through qcow2 metadata; never pass guest byte offsets directly to host hole punching. Preserve every byte outside the requested range. Full-cluster discard is the first implementation; partial head/tail can remain allocated because discard is advisory. WRITE_ZEROES must zero those edges. Extended L2 later gives subcluster mapping semantics but does not imply that an independently referenced host cluster can always be physically released.

For a backed v3 image, use a zero mapping when discarding active data to avoid re-exposing parent contents as a product guarantee. Unallocated and explicit-zero mappings differ. For v2, which cannot express the v3 zero flag, preserve bytes outside the discard range and define advisory discarded bytes as unspecified; use ordinary zero writes for WRITE_ZEROES. Do not upgrade a v2 header silently.

Track physical ownership by refcount. Never punch snapshot-shared data, live L2/refcount/header/snapshot/bitmap/crypto metadata, or compressed sectors shared with another cluster. External-data images require separate mapping and target-file rules. Maintain a metadata-overlap validator and checked file/cluster ranges. Validate copied bits against supported sharing rules; never treat the copied bit alone as authority to overwrite.

Use a quarantined pending-free set with ownership generations. The durable sequence for a full data-cluster release is:

1. Serialize with reads/writes that can retain the mapping. Preserve shared L2 tables by COW and prepare the new zero/unallocated mapping.
2. Publish removal of the active reference and durably sync the required mapping metadata before any destructive host operation. Ensure references retained by snapshots/other owners remain valid.
3. Persist the decremented refcount in dependency order. Only when the actual count is zero can the physical range be a reclaim candidate. Keep it unavailable to the allocator until the host operation finishes or is canceled safely.
4. Punch the eligible host range, report/account the result, and release quarantine. Never allow a retry queue to punch a range that has since been allocated to a new generation.

For allocation, acquire/record ownership before publishing a pointer, initialize the entire newly exposed logical region including untouched bytes, sync data/new metadata before durable parent publication, and free old structures only after the replacement is durable. Cache eviction must follow the same dependencies as explicit flush. Serialize an image first; a later multiqueue implementation must preserve these invariants rather than relying on a global virtio queue lock.

No standard qcow2 transaction log guarantees multi-sector atomicity. Set dirty state durably before risky mutations and clear it only after a consistent durable checkpoint; mark/refuse corruption as appropriate. Define the supported crash model explicitly: successful barriers preserve prior durable bytes, incomplete writes may be partial within their target range, and interrupted metadata operations may leave detectable/recoverable leaks but must not silently alias or destroy unrelated live data. Torn writes, sync errors, storage reordering and interrupted hole punching all belong in the fault model. Dirty/corrupt files are refused for ordinary writable launch; offline checking/recovery is an explicit Pichi operation. A sidecar journal is not part of the default format contract.

## Complete format and operation coverage

This is the final compatibility program. Phase numbers below establish sequencing; until a row passes its gate, the opener must reject that profile clearly. Feature bits that are unknown and incompatible always cause refusal; compatible features may be ignored only when their spec semantics permit it. Preserve unknown header/extensions on rewrite. Unsupported autoclear state is cleared durably before mutation, after nonmutating validation; required bitmap preservation must instead cause refusal.

| Profile or operation | Planned behavior and required checks | Phase |
| --- | --- | --- |
| Standard qcow2 v2/v3, sparse/zero mappings | Read/write/flush/discard; QEMU-supported cluster sizes 512 B through 2 MiB, subject to format constraints; v2/v3 zero semantics distinguished | 2–4 |
| Refcount widths 1/2/4/8/16/32/64 bits | Parse/update safely, reject overflow; one-bit refcounts cannot represent shared snapshots; grow/relocate tables without losing ownership | 2, 6 |
| Raw/qcow2 backing chains | Explicit authority/format for every node, immutable parents, depth/cycle checks, correct partial-cluster copy-up and EOF zeros; refuse opening when a required parent is missing | 5 |
| Internal snapshots | Active-image COW for shared data and L2 tables; preserve all snapshots under write/discard. List/create/delete/revert disk snapshots through offline Pichi management | 6 |
| Compressed clusters | Deflate and zstd read; copy/decompress on write, release old physical references only when safe; offline compression output in Pichi | 6 |
| Extended L2 | Validate allocation/zero bitmaps and reserved combinations; subcluster reads/copy-up/zero/discard; reclaim shared host cluster only when ownership permits | 6 |
| External data file and raw-external flag | Explicit authorized second handle, separate flush/deallocation, raw-data visibility rules, forbidden feature-combination validation | 6 |
| Lazy refcounts and dirty/corrupt flags | Open clean compatible inputs using eager correct updates; do not introduce lazy operation by default. Refuse dirty/corrupt writable opening; offline check/repair before retry | 2, 6 |
| Persistent dirty bitmaps | Either maintain spec-valid recording across writes/discard/snapshots or invalidate through defined autoclear semantics. Preservation mode must refuse unsupported bitmap handling. Pichi owns incremental-backup lifecycle | 7 |
| LUKS qcow2 encryption | Engine adapter for spec-compatible encryption, bounded KDF work, secrets through supplied handles/services, correct zero/discard and multi-file durability; no keys in logs or config serialization | 7 |
| Legacy AES encryption | Explicit unsupported error plus offline conversion workflow; do not silently decrypt, mutate or claim support. No proprietary LUKS2/custom-hash extension compatibility promise | 7 |
| VM-state snapshot payloads | Preserve opaque existing payload/refcounts while operating on the disk. Dillo disk snapshot support does not mean restoring QEMU machine/RAM state | 6 |
| Create/convert/flatten/rebase/commit/compact | Pichi owns orchestration, dependencies and atomic output publication. Use explicit-format qemu-img initially; native tools only after equivalent gates | 5, 7 |
| Capacity resize | Offline grow/shrink through Pichi initially; reject shrink without explicit filesystem/partition-safe intent. Live grow requires worker quiescence, durable header update and capacity-change interrupt; no automatic live shrink | 7 |
| Multiqueue/direct I/O/cache tuning | Optional performance work after correctness gates; alignment, per-cluster ordering, bounded caches and quiescence must remain correct | 8 |

For encrypted or snapshot-shared data, discard does not guarantee every requested byte releases storage; tests distinguish ownership constraints from missing host support. Guest free space can only be inferred from discard, not from qcow2 zero detection. Zero-write detection is an optional optimization with its own tests, not a substitute for discard.

## Configuration and secure opening

Extend `BlkSpec`, `ResolvedDevice::Blk`, resolver tests and `src/main.rs::build_block_device` with explicit `format=raw|qcow2`. Default remains raw for existing configurations; no filename-extension detection or silent format fallback. Proposed basic use: `--blk path=data.qcow2,format=qcow2`. Existing raw/read-only/MMIO/PCI syntax remains valid. Format-neutral discard policy and required-reclamation policy are validated before launching devices.

Preflight opens read-only first, validates feature/profile and all requested authority, then acquires/revalidates writable handles under exclusive locks before mutation. Avoid a reopen race by preserving identity and verifying it across any access upgrade; never validate one file and write a replacement path. Acquire chain locks in deterministic identity order, with shared locks for immutable parents and exclusive locks for writable components, deduplicating hard-link aliases. Refuse writing a parent referenced by another live session. Locks protect cooperating programs; do not claim protection against arbitrary external raw writes.

Do not trust backing path names, URI schemes, symlinks or format hints embedded in an image as authority. Resolve only against caller-authorized objects, detect cycles by identity, cap chain depth (proposed 32), validate every ancestor and limit total metadata/decompression work. A backing file shorter than virtual capacity supplies zeros beyond its end where the format requires; truncated allocated metadata/payload is corruption, not a sparse hole.

Set explicit limits before allocation: cluster bits, virtual-size-to-table coverage, host offsets, table byte lengths, header extensions, snapshots/bitmaps, decompression output, and cache memory. Proposed starting limits: QEMU-compatible 32 MiB L1 and 8 MiB refcount table ceilings, 64 MiB total metadata cache per image, 32-node chain and 16 MiB maximum guest transfer. Reject images that exceed supported coverage; these are implementation resource limits, not claims about theoretical format maximums. Report actual configured limits and budget the aggregate across all disks. Never follow an image header into a device/network path unless explicitly supported and authorized by the host owner.

## Work packages and dependency order

| Phase | Concrete outputs | Exit gate |
| --- | --- | --- |
| 1 — Engine qualification | Pinned imago dependency/patch policy; host-storage and mutation-capability design; nonmutating preflight; faults and QEMU fixtures; compare applicable fork fixes | Durable allocation/free prototype passes controlled crash tests. If it fails, switch engine behind the interface before frontend integration; do not waive R4 |
| 2 — Storage and core format | New storage crate; raw/GPT adapters; serialized qcow2 session; exact I/O; dirty handling; allocation, table growth and durable pending-free implementation | Backend differential suite, no-op open/RO byte stability, fault tests and allocator churn pass |
| 3 — Native host services | Linux/macOS/Windows locks, exact I/O, sync, sparse operations, accounting and capability reporting; host-owned worker/IPC/confinement integration | Native host filesystem tests and worker failure tests on all three hosts; unsupported-FS policy verified |
| 4 — Virtio and launch | Extended config and feature negotiation, descriptor cursor, DISCARD and WRITE_ZEROES handlers, explicit CLI/JSON format and policies, graceful reset/shutdown | Both transports, invalid descriptors/ranges, real Linux guest discard and reboot tests. First usable ordinary-image release must pass R2 on every advertised host |
| 5 — Backing and Pichi integration | Authorized chain graph, parent locks/COW, separate image lifecycle orchestration, default sparse creation and import/export behavior | Nonzero-parent discard/zero tests, chain authorization tests, overlay copy-up and QEMU conversion comparison |
| 6 — Shared and advanced mappings | Snapshot data/L2 COW, internal snapshot retention, compressed and extended L2, external data, refcount-width coverage | Matrix-specific round trips and crash/discard/shared-reference tests pass; no silent unsupported profile opening |
| 7 — Management and remaining format contracts | Encryption, bitmap preservation/invalidation, offline lifecycle/check/repair, live-grow contract, published compatibility/error matrix | QEMU interoperability per operation, key/authority tests, recovery rehearsal and Pichi/dillo ownership review |
| 8 — Performance and release | Bounded cache tuning, allocation/reclaim counters, stress/latency reports, documentation, licensing/provenance, supported-host CI | All requirements and coverage rows accounted for; hardware runs completed; no outstanding corruption/reclamation regressions |

Do not combine these into one unreviewable change. The backend contract, imago patches, host adapters, virtio changes and Pichi workflows can be separate review units with explicit dependencies. Each upstream-derived patch records base revision, license, reason, focused regression and upstream issue/commit when available. No engine choice may be justified solely by stars, README feature lists, or a green test command that ran zero relevant tests.

## Validation matrix and release criteria

| Gate | Tests and evidence required |
| --- | --- |
| T1 Protocol | Feature offered vs negotiated, durable completion when FLUSH is offered but not negotiated, RO rejection, zero records, malformed flags, overflow, out-of-range sectors, descriptor splits at every field boundary, unknown opcodes, status writes, limits and both transports. Tests assert no disk mutation on validation failure. |
| T2 Byte correctness | QEMU-created v2/v3 fixtures, all admitted geometry/refcounts/features; random reference-model reads/writes/zero/discard; cross L1/L2/cluster boundaries; short I/O/EINTR/EOF; final qemu-img check and raw content comparison. |
| T3 Reclamation | Native Linux ext4/XFS (and Btrfs accounting), macOS APFS and Windows NTFS; create sparse → write incompressible data → sync → discard → sync → measure native allocated bytes → reopen. Keep neighboring live patterns. Unsupported-filesystem fixture must exercise refusal/degraded policy. |
| T4 Churn and sharing | At least 1000 bounded allocate/discard/rewrite cycles, reused clusters at different guest offsets, stale deferred-punch injection, refcount table growth/relocation, disk full/quota failure, snapshot and compressed shared sectors, repeated no-op discard. Report metadata growth separately; verify stable allocation after warm-up. |
| T5 Durability | Instrumented storage fails/crashes before/after each metadata write, barrier and punch; includes torn metadata writes and reordered unsynced writes. Model acknowledged flush epochs. Restart from persisted state, compare durable live bytes, check/refuse/repair per policy. Repeat representative real process-kill tests on persistent host filesystems. Killing a process on tmpfs is not a power-loss test. |
| T6 Guest | Existing snuffler/boot infrastructure plus an ext4-capable guest test workload: format disk, write/sync files with hashes, delete selected files, invoke FITRIM (or fstrim), check host allocation, reboot and verify surviving hashes. Exercise online discard too; cover MMIO/PCI and supported host/architecture combinations without building an unrelated guest kernel. |
| T7 Lifecycle and authority | Writable/RO alias opens, conflicting writers, parent immutability, path replacement and traversal, cycles/huge chains, malformed metadata overlap, guest reset, worker crash, shutdown flush error, process confinement, external-file identity, secret isolation. |
| T8 Advanced profiles | Snapshot create/write/discard/delete/revert; compressed rewrite; extended-L2 allocated/zero/backing bit combinations; external raw-data visibility; dirty-bitmaps write/zero/discard epochs; encryption zero-read/reopen and bounded KDF; resize preserves old bytes and signals capacity. |
| T9 Performance | Raw vs QEMU vs candidate backend on same filesystems/cache modes; sequential/random 4 KiB and 1 MiB I/O, first-write allocation, flush-heavy workload, fstrim latency, CPU and memory. Report p50/p95/p99 and host bytes per guest live byte. Flag unexplained >20% throughput or p99 regressions against the agreed pre-change baseline; investigate before release, without making an unmeasured throughput promise. |
| T10 Delivery | Cargo fmt/clippy/tests for affected workspace crates, supported target builds, actual VM lanes, license/dependency audit, pinned source provenance, fuzz corpus and user documentation. Missing native hardware is unverified, not a passing lane. |

QEMU tests must fail their prerequisite check if qemu-img/qemu-io are unavailable in the interoperability lane; do not silently skip and report green. Pin QEMU versions in CI and exercise both the minimum supported tool version and a current one. Use per-test disposable files; qemu-img mutation/check must never race an open writable dillo image. Fuzz header/metadata/chain parsing and virtio descriptor streams separately, with process-level memory/time limits. Test format engines through injected host I/O as well as through their own unit suites.

Add guest probe/report fields for discard limits, FITRIM result and retained-file hashes; host tests capture allocated bytes before/after and worker flush errors. Do not infer native host reclamation from FITRIM success alone. Export/log guest discarded bytes, qcow2 clusters released, host bytes requested for punch, host failures, reused clusters, pending-free count and cache memory without exposing secrets. The amount actually reclaimed is measured by host allocation accounting, not merely summed request lengths.

## Completion boundary

The research and plan are complete when the evidence inventory, chosen approach, all required behavior, ownership and validation gates have no unresolved planning gaps under three consecutive reviews. That is distinct from implementing the feature. Implementation completion requires R1–R9 and T1–T10, the scheduled format matrix, documented intentional refusals, and real host evidence. Earlier staged releases must name their supported profile and cannot be reported as completion of this full program.

## Primary protocol and host references

- [QEMU qcow2 format](https://www.qemu.org/docs/master/interop/qcow2.html) and [qemu-img operations](https://www.qemu.org/docs/master/tools/qemu-img.html).
- [Virtio 1.3 block device specification](https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html), especially feature/config/operation requirements.
- [Linux fallocate](https://man7.org/linux/man-pages/man2/fallocate.2.html).
- [Apple fcntl definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h), including F_PUNCHHOLE and F_FULLFSYNC.
- [Windows sparse-file operations](https://learn.microsoft.com/en-us/windows/win32/fileio/sparse-file-operations) and [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
