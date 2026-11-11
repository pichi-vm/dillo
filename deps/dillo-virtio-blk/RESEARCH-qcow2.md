# Rust qcow2 implementation research

Research date: 2026-11-07. Dillo baseline: `d30e8cfbc6671f4b0e653400cfaca8d7ec948dd3`.

Dillo should use an existing Rust format engine behind a host-supplied storage interface. **Imago with its native synchronous feature is the recommended starting point**, with explicit work to add durable host reclamation and complete the compatibility profile. It is not ready to satisfy this project's requirements unmodified. Guest TRIM, qcow2 allocation reuse, and host extent reclamation are three separate requirements. The full implementation program is in [PLAN-qcow2.md](PLAN-qcow2.md).

## Discovery and evidence

The survey covers public implementations discoverable through crates.io searches for `qcow`, `qcow2`, `imago`, and `virtdisk`; GitHub repository searches for `qcow language:Rust` and `qcow2 language:Rust`; targeted web searches; Rust VMM block backends; and dependencies and forks found in those sources. The `qcow2` registry search returned 77 packages, all screened from published package descriptions/manifests and source archives where available. The narrower `qcow` query additionally found calf and keramics. GitHub searches returned 10 and 28 repositories respectively before deduplication. Searches were repeated with known candidates excluded to find less prominent implementations.

[Source revisions](qcow2-research/sources.json) pin the inspected repositories/branches; [registry screening](qcow2-research/registry-screen.json) records all 77 package dispositions and versions. A registry version and a repository HEAD are separate evidence: notably, qcow2-rs publishes 0.1.6 while the inspected tree identifies itself as 0.2.0 and has new discard support. Mutable README descriptions and search snippets were not treated as proof of implementation. This is a dated public-source census, not a claim to enumerate private code or every unindexed fork. Forks sharing an engine are grouped, with materially different reclamation work identified separately.

The only upstream test executions in this research are the imago unit suite, an imago reclamation probe, qcow2-rs discard integration tests, and a QEMU reference probe. Other capability assessments are source inspection, not runtime certification or a complete security audit. Upstream licenses below are observed declarations used for selection; dependency/license review remains an implementation gate.

## General purpose engines and VMM implementations

| Implementation | Source findings | Suitability for dillo |
| --- | --- | --- |
| [Imago](https://gitlab.com/hreitz/imago), 0.2.6 tree | MIT; synchronous or async API, abstract storage, reads/writes, allocation, zero/discard, backing images, external data, compressed reads and resizing. `flush()` and `sync()` are separate. | Best integration fit; missing host reclamation in the tested qcow2 path. Extend engine ordering/reclamation and compatibility rather than merely wrapping its discard API. |
| [msb-imago](https://github.com/superradcompany/imago), registry 0.1.7 | MIT fork; qcow2 allocation/mapping code and async/sync-wrapper lineage. Published allocator frees references without a qcow2 host-punch hook. | Older alternative, no demonstrated advantage over current upstream for the required behavior. |
| [ltstriker imago](https://github.com/ltstriker/imago/tree/boxlite/punch-hole) | Inspect `boxlite/punch-hole` at `182f7cd95adbc525679ff3be8cebeaa0850e3a11`, not default `main`. `free_data_clusters` collects refcount transitions from one to zero and punches while holding the allocator lock. Errors remain best effort. | Useful patch reference for reclamation and reuse exclusion. Does not by itself prove durable unlink-before-punch ordering. Rebase conceptually onto current upstream; do not adopt old fork wholesale. |
| [mariobm imago](https://github.com/mariobm/imago) | MIT maintenance fork; cache-dependency and crash-consistency changes. Inspected flush path and allocation/cache modules. | Compare fixes against current upstream; commit ancestry and test coverage must establish which changes still apply. Fork description is not a durability guarantee. |
| [ublk qcow2-rs](https://github.com/ublk-org/qcow2-rs) | MIT/Apache-2.0; async I/O trait, allocation/refcounts, read/write, backing and compressed reads. Current `dev/discard.rs` unmaps full clusters and invokes host fallocate; skips compressed clusters and partial ends. | Credible alternative, but source-level ordering/shared-cluster issues below prevent recommending it unmodified. Runtime dependency is larger than dillo needs. |
| [rsd](https://gitlab.com/hreitz/rsd) | Storage daemon with internal Rust qcow2 engine; predecessor of qcow2-rs. Source has read/write, mapping/refcount caches and node/queue integration. Package declares MIT; repository also contains GPL license material, requiring per-file provenance checks for extraction. | Historical/design reference; extracting a daemon-internal engine offers less benefit than its library descendant. |
| [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor/tree/fbb64e0c53cdd654f3637b04b2a6a44da6569eb2/block/src/formats/qcow) | Crosvm-derived Rust engine with parser/metadata and synchronous/io_uring engines, discard/zero, backing support, dirty handling and targeted regression/fuzz tests. Writable internal-snapshot images are explicitly refused by current parser. | Strong correctness reference and extraction fallback. Unix file use and VMM-internal dependencies make direct cross-platform adoption expensive. Preserve per-file BSD/Apache notices when extracting permitted code. |
| [Crosvm](https://github.com/google/crosvm/tree/f0880b36b6e3f25ee814222e6bd1cead4151bc85/disk/src/qcow) | Read/write qcow2, backing support, zeroing, refcount allocation and hole punching; snapshot-bearing images rejected. Uses `base`, volatile buffers and disk-worker abstractions. | Mature lineage, but not a standalone general qcow2 library. Portability and integration work still required. |
| [StratoVirt](https://github.com/openeuler-mirror/stratovirt/tree/2846f668ea971dd4539852aeb5436af56ff84696/block_backend/src/qcow2) | Mulan PSL v2; separate header/cache/table/refcount/check/snapshot modules. Discard/write-zero paths and internal snapshot operations exist; allocator drains pending discards before reuse. | Broader management reference, tightly coupled to Linux AIO, QMP and machine-manager code. Review license policy before extraction. |
| [virtdisk](https://github.com/CaddyGlow/virtdisk), registry 0.3.1 | MIT; separate immutable/writable capabilities, parser budgets, authorized parents, Linux writable qcow2 profile, snapshot COW and sidecar redo recovery. Native writes restricted to standard v3/64 KiB/16-bit profile. | Valuable authority/recovery design reference. Linux-specific mutation and nonstandard recovery sidecar complicate three-host interoperability; not selected. |
| [rust-img-qcow2](https://github.com/antimatter-studios/rust-img-qcow2), formerly am-img-qcow2 | MIT; current 0.6.1 code has writes despite stale package description saying reader. Supports backing copy-up, compressed-cluster rewrite and snapshot-shared COW; rejects encrypted, external-data and extended-L2 profiles. No discard API found in inspected source. | Smaller alternative for read/write; substantial new reclaim and durability work, so not preferred over imago. |
| [fstool](https://github.com/KarpelesLab/fstool/tree/d01fbe06168451c66c5f509ff7e2b9067e644af7/src/block/qcow2) | MIT; independent read/write/create/zero-range implementation, backing and compression/crypto modules. Zero mappings are not evidence of host discard. | Image manipulation library, not a demonstrated VMM discard backend. Reuse would require the same reclamation and lifecycle work. |
| [Instar](https://github.com/shakenfist/instar/tree/e0b0fe13f48f4e95db8a687519b4c889eee1885a/src/crates) | Rust parsing/creation/check/management crates and a `no_std` write planner/executor. Source explicitly distinguishes ordering from durability and describes executor paths without fsync. | Useful format, limits and fault-model reference; planner is not a drop-in persistent VMM disk. Check individual crate licenses before reuse. |
| [ruvm](https://github.com/tamnd/ruvm/tree/d9f4ea18ec3d137f27715c8f19dac652e8a825ca/crates/block/src/qcow2) | GPL-2.0-or-later Rust port of QEMU format behavior, with snapshots, bitmaps, crypto, create/check/resize and discard paths. Explicitly lacks zstd in inspected module. | Broad behavioral comparison, not a proposed linked dependency for dillo's Apache distribution. No GPL code should be copied into the proposed engine. |
| [unixshells clone](https://github.com/unixshells/clone/blob/a9525154846e709bd46a7aeb64ceb1fb43547ee2/src/storage/qcow2.rs) | MIT VMM-local read/write allocation/backing/cache implementation. No discard path in inspected file; `flush` writes caches and calls ordinary file flush. | Not suitable as-is for reclamation or durable guest FLUSH. |
| [qcow2-lib](https://github.com/pcbastler/qcow2-lib) | Broad feature claims, including snapshots, extended L2, encryption and bitmaps. LICENSE prohibits use/copy/modification/distribution without written permission. | Excluded from code reuse. Public source visibility does not grant a usable license. |

### Imago evidence and required changes

At `ff96e18ce872bb3dec4f1f2d178fc41dc89d3bf6`, `FormatAccess` has safe mutable discard entry points suitable for a serialized owner. Its native `sync` feature avoids introducing an async runtime. `Storage` is a useful seam for dillo host services, though implementing its unsafe primitives requires a narrowly reviewed adapter; keep the shared virtio device free of unsafe calls.

The qcow2 allocator decrements references but does not issue a host discard. The probe below confirms that this matters. `Header::load` accepts external-data incompatible features but rejects other incompatible flags; zstd/extended L2 need work. Writable open clears autoclear bits before the later unsupported-incompatible-feature check: dillo needs a nonmutating preflight before handing over writable authority. Supporting a cached write and calling flush followed by sync does not establish power-loss-safe metadata publication; the engine must enforce durable dependencies during eviction and allocation as well.

### qcow2-rs evidence and required changes

The current discard implementation clears an L2 mapping in cache, releases its refcount, then punches the host extent. It does not visibly condition punching on the resulting refcount being zero or quarantine the range against reuse in that method. Cached metadata is explicitly left for later `flush_meta`. These are source-level hazards requiring fault/shared-reference tests before adoption, not a claim that every workload reproduces corruption. Clearing an overlay L2 entry to unallocated also reveals backing bytes rather than guaranteeing zero. Its public method clips out-of-range requests, so the virtio frontend must validate capacity itself. Windows host-allocation assertions in the discard suite are disabled. Passing the seven tests establishes their ordinary-image cases only.

## Other independent implementations and subsets

These were retained in the census even when they cannot supply dillo's writable backend.

| Project or published package | Classification and disposition |
| --- | --- |
| [vasi qcow2](https://github.com/vasi/qcow2-rs), 0.1.2 | MIT read-only reader. No write/discard engine. `qcow2-fuse` consumes this engine. |
| [panda-re qcow](https://github.com/panda-re/qcow-rs), 1.2.0 | MIT qcow1/qcow2 reader and snapshot inspection; `qcow-cli` is its frontend. |
| [calf](https://github.com/puffyCid/calf), 0.3.0 | MIT read-only forensic parser/reader. |
| [keramics](https://github.com/keramics/keramics/tree/a3623ffbfa02a39d1104c6e83e6d9277bf020d36/keramics-formats/src/qcow) | Apache-2.0 forensic block reader, format parsing and encryption handling; no writable device backend. |
| [qcow2-core and qcow2-forensic](https://github.com/SecurityRonin/qcow2-forensic) | Apache-2.0 reader plus anomaly auditor. Not the identically named proprietary qcow2-lib core crate. |
| [Exhume Body](https://github.com/forensicxlab/exhume_body/blob/b824d198479eb663b2f55764062a09c2defd2fbe/src/qcow2.rs) | Independent read-only qcow2 engine with backing, extended-L2 and external-data parsing. Current code has this support despite older documentation describing it as future work. |
| [VMkatz](https://github.com/nikaiw/VMkatz/blob/46e45a7d599c587b8bc60c1f98e21afc44a44c1f/src/disk/qcow2.rs) | Independent read-only virtual-disk parser inside a forensic application; not a write/discard engine. |
| [cloud-image-inspector](https://github.com/virtainer/cloud-image-inspector/blob/432b7f93948d43a8741847555b71481037d0a82e/src/qcow2.rs) | Apache-2.0 independent reader for offline inspection. |
| [NYU streaming-qcow2-writer](https://github.com/NYU-RTS/streaming-qcow2-writer) | MIT sequential conversion/backup writer; not random-access live-disk mutation or discard. |
| [Foxing fxcp-core](https://aenertia.codeberg.page/foxing/src/fxcp_core/qcow2.rs.html) | GPL-2.0-or-later read-only header and persistent-dirty-bitmap parser for replication; no guest data mutation engine. |
| [dump_qcow](https://github.com/wtfrank/dump_qcow) | Delta extraction utility with its own metadata reader; no live writable engine. |
| [bux-qcow2](https://github.com/qntx/bux/tree/85b994523957423f2ec98248f859d52d3e114df4/crates/bux-qcow2), 0.2.0 | Image-management subset: header/overlay/chain operations, with resize delegated to qemu-img. Bux uses libkrun for VM I/O. |
| [rimimg](https://github.com/mkidv/rim), 0.10.1 | MIT sparse reader/writer via RimIO, allocation and conversion; no discard method found in published qcow2 module. Header claims of full compliance do not prove feature parity. |
| [dsk-vm](https://github.com/danifunker/rusty-backup), 0.1.0 | MIT plain qcow2 reader plus export and in-place write code in published module; restrictive format profile and no discard path found. Introductory read-only comment is stale relative to methods. |
| [remanence](https://github.com/ferroteca/remanence-lib), 0.1.0-alpha.1 | GPL-3.0-only native read/write backing-chain driver; writable profile excludes snapshots and non-16-bit refcounts; not selected for linked reuse. |
| [ABT](https://github.com/nervosys/AgenticBlockTransfer) and [IBT](https://github.com/nervosys/IronBlockTransfer) | Related AGPL-3.0-only streaming readers in published 1.7.1 and 2.0.0 packages; no writable/discard engine. |
| [isomage](https://github.com/JackDanger/isomage), 2.1.0 | MIT container reader and image-tree reconstruction. |
| [exav-unpack](https://github.com/sylvinus/exav), 0.0.2 | MIT independent qcow2 reconstruction/decompression for scanning, not live writes. |
| [own-backup](https://github.com/coinman-dev/own-backup/tree/febd28fd10a5a6ede46bb180d5b71904df36a6b8/crates/backup/src/qcow2) | Independent reader, cluster writer, merge/consolidation and chain code. Noncommercial/commercial-license split, no guest-discard backend demonstrated; excluded from proposed reuse. |
| [partition-manager](https://github.com/inalto/partition-manager/blob/397dec1d79c734056917d22ecd423fdaf909b597/crates/pm-image/src/qcow2.rs) | MIT sparse image create/open backend, bounded ordinary v3 profile using shared sparse allocator; not a complete qcow2 discard engine. |

## VMMs and consumers without another independent engine

- **Libkrun:** inspected `src/devices/src/virtio/block/{device,worker}.rs` and Cargo manifest; uses imago 0.2.6 native sync, dispatches discard/zero requests. This does not cure imago's host-reclamation gap.
- **BoxLite:** lockfile contains registry imago 0.2.6; image helper uses qcow2-rs header/layout code. The ltstriker fork is a separate lead, not proof that the inspected BoxLite revision uses its punch-hole branch.
- **Alioth:** qcow2 structures and CLI qcow2-to-raw conversion exist; inspected virtio block path is not a qcow2 read/write engine. Conversion support must not be counted as native serving support.
- **Firecracker:** inspected native disk-format module defines raw and VMDK; no native qcow2 engine in the collected tree. External vhost-user storage is a different execution boundary.
- **Propolis:** inspected block modules implement file, memory and Crucible backends; no qcow2 engine found in its tree or block manifest.
- **OpenVMM:** inspected storage packages include raw/file, VHD/VHDX and VMDK plus layered storage; no qcow2 engine found in the collected tree.
- **Kata Dragonball:** inspected local block backends operate on files/AIO/io_uring, with vhost-user as a separate backend. Kata selecting QEMU/Cloud Hypervisor does not create a new Rust qcow2 implementation.
- **rust-vmm:** surveyed vm-device and vhost-device trees do not contain a qcow2 engine. They provide composition/protocol components; do not mistake them for an image-format library.
- **SmolVM:** uses imago for chain inspection/rebase and libkrun for execution. **rsemu:** uses fstool for image formats. **rublk and xhfs-core:** consume qcow2-rs; **Quickemu qe_mac_apid and vmrunner:** consume imago. **imgdelta, sdme, recqemu and herolib-virt:** invoke QEMU tools/NBD. [recqemu](https://github.com/LevitateOS/recqemu) explicitly delegates disk creation to qemu-img. Registry UI/orchestration packages are consumers, not additional engines. Coxswain and rgx/rgy expose header/inspection information, not VMM mutation.

## Executed checks

Environment: Linux, Rust `1.99.0-nightly (1a98b1e13 2026-08-07)`, QEMU 10.2.2. The temporary fixture filesystem was **tmpfs**: these probes establish logical behavior and host allocation accounting, not persistent-storage power-loss behavior. No dillo implementation was changed or booted for these probes.

| Check | Result | Scope |
| --- | --- | --- |
| Imago `cargo test --no-default-features --features sync --lib --quiet` | 56 passed, zero ignored | Existing upstream unit tests, not dillo integration. |
| qcow2-rs `cargo test discard --quiet` | 7 integration tests passed | Default 64 KiB/16-bit images on this Linux host, QEMU available. Other targets were filtered; an earlier `--lib discard` invocation ran zero tests and is not evidence. |
| QEMU 1 GiB image, write then discard 64 MiB | Allocation 200704 → 67375104 → 266240 bytes; check clean | Desired host reclaim behavior. Apparent length after discard remained 67436544 bytes. |
| Imago same geometry, write → flush → sync → discard → flush → sync | Allocation 200704 → 67375104 → 67375104 bytes; zero reads and check clean | Demonstrates missing physical reclaim despite valid logical discard. |

The [probe source](qcow2-research/imago-probe.rs) and saved logs accompany this document. To reproduce, create a throwaway Cargo binary with the pinned imago checkout as a path dependency, `default-features=false, features=["sync"]`, and use the probe as `src/main.rs`. Run it with a new disposable image path: **the probe invokes qemu-img create and must never receive an existing valuable image**. Run the upstream test commands from their pinned checkouts. Source trees used for inspection are outside the repository; [sources.json](qcow2-research/sources.json) supplies their immutable revisions.

## Selection conclusion

Use current upstream imago as the base for a maintained, pinned dependency patch series, native sync mode, and an injected host storage adapter. First establish durable allocation/deallocation, error propagation and all three host reclamation operations. Keep snapshot-bearing and advanced images refused until their scheduled implementation gates pass; do not describe that intermediate state as the full feature's completion. If imago cannot satisfy the fault-injection gate, stop integration and extract/adapt the permissively licensed Cloud Hypervisor/crosvm engine behind the same interface. Neither option makes a new handwritten qcow2 implementation the default.

The remaining implementation work is substantial, but the choices no longer hinge on unknown library names: the plan identifies required engine patches, format coverage, ownership, tests and release criteria.
