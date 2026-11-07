# Qcow2 research and plan gap analysis

This audit evaluates the requested research and implementation plan, not an implemented qcow2 feature. The acceptance condition is three consecutive gap-analysis passes without an unresolved planning/evidence gap. A discovered gap resets the count. Reviews are separate passes by the same agent; no independent reviewers or subagents are claimed.

## Requirements derived from the request

| Requirement | Authoritative evidence for completion |
| --- | --- |
| Research existing Rust engines broadly, including other VMMs | RESEARCH-qcow2.md inventories engines, forks, reader/writer subsets, VMM consumers and negative findings; sources.json pins collected source trees; registry-screen.json accounts for 77 registry results |
| Avoid mistaking a wrapper, reader, old release or marketing claim for a writable engine | Source paths, published versions, inspected HEADs and explicit dispositions in research tables |
| Evaluate licensing and integration suitability | Candidate table and selection conclusion; proprietary and copyleft alternatives separated from proposed permissive reuse |
| TRIM is mandatory and actually releases host storage | PLAN R2/R5, native services, allocation invariants and T3/T6; QEMU/imago contrasting probe logs |
| Give a complete implementation plan rather than only a minimal v3 subset | PLAN full format/operation matrix, phases 1–8 and completion boundary |
| Ground integration in current dillo | Baseline revision, backing/write bypass, 32-byte config, missing activation feature delivery, launch/config/GPT and host-worker seams |
| Preserve read-only authority and platform/process boundaries | PLAN storage capabilities, host services, process lifecycle and Pichi ownership sections |
| Cover data integrity, crashes and flush | PLAN R4, durable allocation/deallocation sequence, dirty policy and T4/T5 |
| Cover both transports and hostile requests/images | PLAN protocol, secure opening and T1/T2/T7 |
| Cover advanced ownership cases | PLAN backing/snapshots/compression/extended-L2/external-data/bitmap/encryption rows and T8 |
| Define implementation validation, performance and rollout | PLAN T1–T10, staged exit gates, benchmark threshold and native hardware requirements |
| Make findings reproducible without claiming unrun checks | Saved source revisions, actual logs, probe sources, environment and explicit tmpfs/native-host limitations |
| Complete three consecutive clean gap analyses | Review records below, against stable research/plan/evidence hashes |
| Keep session title and avoid unrelated code changes | Title remains qcow2 for dillo; repository status contains only these new research artifacts plus the pre-existing tests/pmi_adversarial.rs modification |

## Findings resolved before the clean sequence

1. The original shortlist omitted imago, its forks, several VMM implementations and less prominent published readers/writers. Expanded discovery across registry archives, source trees, forks and repeated external searches; added every discovered independent implementation and classified wrappers separately.
2. qcow2-rs default-branch discard is newer than the published registry release. Recorded versions separately and inspected actual methods/tests rather than relying on a README.
3. The ltstriker default branch did not contain its advertised host-punch changes. Located and inspected the `boxlite/punch-hole` branch and pinned it separately.
4. Logical imago discard did not reduce host allocation. Ran a probe, recorded the failure to reclaim, and made host reclamation an engine patch and release requirement.
5. The initial qcow2-rs test filter matched no library tests. Ran the integration test filter, inspected the seven matched tests and kept the zero-test invocation out of positive evidence.
6. tmpfs allocation probes do not establish durable crash behavior. Recorded the filesystem and added persistent-host fault/kill tests to the implementation gates.
7. VirtioActivate currently carries no negotiated-feature mask. Added the shared activation API and both transport changes to the plan.
8. A plain-v3-only proposal did not fulfill the expanded planning scope. Added the complete feature/operation matrix, cross-project ownership and explicit advanced milestones/refusals.
9. Pichi's current run/build path attaches carapace GPT partitions. Added that concrete integration boundary, native MSVC/WHP constraint, capacity alignment validation and read-only flush handling.
10. Registry descriptions were stale for rust-img-qcow2, dsk-vm and virtdisk; Exhume documentation was also older than its code. Classified the inspected source/release behavior rather than copying those descriptions.

## Clean review sequence

Reviews are recorded only after the checks and read-throughs complete. The hash manifest excludes this audit record so adding review results does not change the reviewed artifact set.

### Pass 1 — discovery, evidence and requirement coverage: clear

Read the research and complete plan against all requirement rows above. Reconciled the 77 registry dispositions, 43 repository/branch snapshots and supplementary primary pages; every package classified as an implementation or image-management subset has a research-table disposition. Checked source/release distinctions, fork branch identity, exclusions and consumer/negative findings. Revisited imago's refcount-release path and qcow2-rs's mapping/free/punch sequence against the qualified claims. Compared the recorded test totals and allocation numbers with saved logs and inspected the probe's flush/sync/read/check sequence. Verified all ten reviewed artifact hashes. No unresolved discovery, evidence or scope gap found. Consecutive clean count: **1**.

### Interrupted sequence — protocol gap found and resolved

The next protocol review found that the plan did not explicitly cover virtio's writethrough requirement when FLUSH is offered but not negotiated and CONFIG_WCE is absent. Added stable write completion and the corresponding negotiated-feature test to the protocol section and T1. This is required by virtio section 5.2.6.2. The prior clean count is reset to **0**; updated the plan hash before starting a new sequence.

### Final sequence, pass 1 — requirements and protocol: clear

Rechecked all requirement rows against the revised plan, retaining the source/inventory reconciliation from the interrupted sequence and confirming unchanged research/evidence hashes. Compared virtio configuration layout, opcodes, flag errors, zero semantics and stable-write rules with section 5.2.6.2. Checked both actual transport activation sites (`dillo-pci-virtio` and `dillo-mmio-virtio`), current backing/raw write authority, launcher and design-rule boundaries. The newly added unnegotiated-FLUSH case now has both behavior and a test gate. Reviewed the complete phase and feature matrices for retained scope. No unresolved gap. Consecutive clean count: **1**.

### Wording correction and sequence restart

The ownership review found ambiguous wording, “missing required parents fail open.” Changed it to “refuse opening when a required parent is missing,” consistent with the authority model. Because the reviewed plan changed, reset the clean count to **0** and updated its hash.

### Accepted sequence, pass 1 — evidence and full requirements: clear

Reviewed the corrected artifact set against all 14 requirement rows. Revalidated 77 unique registry dispositions and 43 source snapshots, implementation/subset coverage in the census, exact test counts and probe conclusions. Confirmed that the recommendation is conditional on engine qualification, advanced features remain in the full program, and the two review corrections have explicit implementation/test consequences. All ten artifact hashes match. No unresolved gap. Consecutive clean count: **1**.

### Accepted sequence, pass 2 — failure scenarios and integration: clear

Walked the plan through these scenarios: discard of one snapshot-shared reference; partial-cluster discard beside live bytes; backed zeroing; compressed-sector sharing; crash before/after durable unlink and refcount release; a delayed punch after attempted reuse; host unsupported/error/full conditions; writable-open identity replacement; missing/cyclic parents; reset and worker exit; and FLUSH offered without negotiation. Checked that each has an invariant or explicit refusal and a corresponding T1–T8 gate. Rechecked storage/host/transport/Pichi ownership and the full feature matrix against the requirement list. Discovery conclusions and evidence limitations still hold; no plan/evidence edits were needed. No unresolved gap. Consecutive clean count: **2**.

### Accepted sequence, pass 3 — completion and reproducibility: clear

Final review compared the research recommendation, mandatory reclamation requirement, eight implementation phases, R1–R9, T1–T10 and full compatibility matrix for inconsistent scope or unsupported completion claims. Confirmed the saved probe sources, pinned revisions, logs and reproduction instructions agree; tmpfs evidence remains explicitly separated from persistent-host durability and unrun native-host checks. Verified stable hashes for all ten reviewed artifacts, local documentation links and whitespace. Repository status shows only the new research/plan/audit/evidence artifacts and the pre-existing 21-line test diff; no production implementation is claimed. The title was not changed. No unresolved planning or evidence gap. Consecutive clean count: **3**.

## Outcome

The research and implementation plan satisfy the requested three consecutive clean gap-analysis passes against the final stable artifact set. Earlier interrupted sequences are retained above rather than counted. This is a planning review by one agent, not independent certification. Implementation remains future work subject to the plan's engine qualification, interoperability, crash, guest and native-host gates.

## PR packaging note

The PR adds the repository-required SPDX header to the saved imago probe and
updates that file's hash in the manifest. Its executable contents are unchanged.
The clean-pass records above describe the research-time artifact set; this later
license-only change does not claim an additional semantic review or test run.

Standalone research PR packaging also removes trailing blank lines from two
recorded test logs and updates their hashes. Test output content is unchanged.
