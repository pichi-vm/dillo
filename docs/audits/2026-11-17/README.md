# Design conformance and interface audit

This audit covers the merged design and adopted crate graph. Every main and
linked obligation has a scoped disposition, and every production unit has a
reverse authority/lifecycle review. This is completion of source-review
coverage, **not implementation conformance or native certification**. The
interface deliverable remains subject to review and merge.

## Baselines and scope

| Source | Pinned revision |
| --- | --- |
| Dillo code and normative design | `c808d800e0e020df275548bb64c3061ce8e3379a` |
| Current PMI | `d6c2543129c3dad900d39a14ac9c4909bd39c0ac` |
| Current Arma and in-tree Tatu | `08f2f176d594c78f398dd22d6d6e2e746e06b0f5` |
| Dillo's locked PMI | `5d6fe93b87d5af20d7387491f97aa89f31361ef9` |
| Dillo's locked Arma/Tatu | `f8b8fb829d9489b5a3104562730a973c86f4c995` |
| Locked devtree | `07526cfdba0ce0eefdcf641c582a44ce335cd4fe` |

Dillo, PMI and Arma main refs were rechecked at publication and still matched
the first three revisions. The findings concern those baselines, not future
branches. Prototype worktrees are preserved and are not implementation
authority. The supplementary console review pins Pichi and Madrillo separately.

Scope is steps 1–3: gap analysis, issue reconciliation and major interfaces.
There is no runtime implementation or fourth-step implementation sequence.
SNP-specific mechanisms are explicitly deferred; their requirements remain
tracked and unverified. Ordinary same-machine whole-RAM sharing is permitted;
exclusive per-device/per-request memory grants are not a requirement.

## Method and stopping criteria

1. Decompose all substantive design clauses, including linked console/network
   documents and crate responsibilities, into reviewable obligations.
2. Trace construction, execution, failure and retirement in both directions:
   every declaration to its realization and every resource to its authority.
   Include alternate admission paths and helpers outside queue activation.
3. Scope each finding to shared source or its applicable native lane: KVM
   x86-64, KVM AArch64, HVF AArch64 and WHP x86-64. Distinguish a missing
   implementation from behavior needing native qualification.
4. Record evidence and one verdict per examined scope: conforms, violates,
   unverified or not-applicable. A narrow positive is not a whole-rule pass.
   Every exclusion needs a reason; every unknown needs an issue owner.
5. Reconcile live issues, correct obsolete claims, retain fixed cases and
   file missing gaps with evidence and acceptance criteria.
6. Specify ownership, associated services, operations, authority, completion,
   failure effects and retirement under the adopted crate graph, grounded in
   source and primary research. Keep actual policy choices explicit.
7. Close coverage only when the forward register and reverse inventory have
   no unreviewed entries, every adverse disposition has an owner or explicit
   deferral, and source revisions and references are checked. Required
   documentation must also be reviewed and merged before the goal closes.

The denominator is 55 rules decomposed into 290 obligations, plus 76 linked
clauses. Multiple scopes can have different verdicts for one obligation.
These counts are neither bug counts nor a compliance percentage.

## Evidence index

| Artifact | What it establishes |
| --- | --- |
| [Main register](coverage.json) | All 290 obligations, scoped assessments, evidence, issue owners and interface-section mapping. |
| [Linked register](linked-coverage.json) | All 46 console and 30 network clauses under the current design. |
| [Reverse inventory](reverse-inventory.json) | All 154 baseline tracked paths classified; all 20 production units reviewed, including storage/GPT/filesystem/vsock. No unclassified paths. |
| [Crate graph](crate-graph.json) | Actual 21 workspace packages plus fuzz versus adopted 25 roles plus fuzz, with conditional production edges. |
| [Issue register](issue-register.json) | 72 referenced issues: 67 open finding/qualification owners and five retained closed cases; live bodies fingerprinted at review. |
| [Source drift](prior-evidence-drift.json) | Fifty cited source/test path checks against the preceding audit; runtime, tests and lockfiles unchanged. |

The source reports explain paths behind the register:

- [PMI producer/consumer and launch boundary](launch-boundary.md).
- [DT claims, native realization and reverse authority](dt-resource-audit.md).
- [CPU, device and debugger lifecycle](lifecycle-source-audit.md).
- [Memory, worker processes and notifications](memory-device-notification-audit.md).
- [Console and network contracts](linked-design-review.md).
- [Storage, filesystem and vsock authority](storage-filesystem-vsock-review.md).

Bare source locations in reports are relative to the named pinned repository;
the register supplies pinned links or local report references. Issue numbers
mean Dillo unless explicitly marked Arma. Read verdicts together with their
scope and limitations. The reports do not claim a line-by-line security proof.

## Findings and major interface consequences

| Boundary | Main gap owners | Required interface |
| --- | --- | --- |
| Current PMI, fixed BSP, exact actions and stable inputs | [#131](https://github.com/pichi-vm/dillo/issues/131), [#133](https://github.com/pichi-vm/dillo/issues/133), [#134](https://github.com/pichi-vm/dillo/issues/134), [#157](https://github.com/pichi-vm/dillo/issues/157), [Arma/Tatu #47](https://github.com/pichi-vm/arma/issues/47) | Stable recipe, target-specific BSP preparation, action-specific destinations and final launch seal. |
| DT completeness and actual resources | [#165](https://github.com/pichi-vm/dillo/issues/165), [#164](https://github.com/pichi-vm/dillo/issues/164), [#10](https://github.com/pichi-vm/dillo/issues/10), [#151](https://github.com/pichi-vm/dillo/issues/151) | Drained claims plus instance admission and faithful realization receipts; reverse native-resource account. |
| Service ownership and crate direction | [#158](https://github.com/pichi-vm/dillo/issues/158), [#17](https://github.com/pichi-vm/dillo/issues/17), [#140](https://github.com/pichi-vm/dillo/issues/140) | Machine-associated services, bound exports, retained native I/O lifetime; portable adapter modules. |
| Device processes and confinement | [#15](https://github.com/pichi-vm/dillo/issues/15), [#150](https://github.com/pichi-vm/dillo/issues/150), [#16](https://github.com/pichi-vm/dillo/issues/16), [#62](https://github.com/pichi-vm/dillo/issues/62) | Early unbound process creation, explicit bootstrap and confined readiness before guest input. |
| CPU/runtime/debug lifecycle | [#159](https://github.com/pichi-vm/dillo/issues/159), [#160](https://github.com/pichi-vm/dillo/issues/160), [#18](https://github.com/pichi-vm/dillo/issues/18), [#141](https://github.com/pichi-vm/dillo/issues/141) | Owner runner/control, shared arbitration, asynchronous settlement, all-stop permits and fresh reconstruction. |
| Proxy, queue and interrupt completion | [#161](https://github.com/pichi-vm/dillo/issues/161), [#162](https://github.com/pichi-vm/dillo/issues/162), [#163](https://github.com/pichi-vm/dillo/issues/163), [#166](https://github.com/pichi-vm/dillo/issues/166), [#167](https://github.com/pichi-vm/dillo/issues/167) | Ordered replies/fences, native event paths, effect-aware errors and actual transport pending/vector integration. |
| Confidential protection | [#152](https://github.com/pichi-vm/dillo/issues/152), [Arma #48](https://github.com/pichi-vm/arma/issues/48), [Arma #49](https://github.com/pichi-vm/arma/issues/49) | Preserve target authorization and independent guest/verifier validation; SNP mechanisms deferred. |

The full [interface specification](../../../INTERFACES.md) covers these
contracts. [Research](../../interface-research.md) distinguishes native API
guarantees and peer precedents from Dillo's synthesis and remaining tests.
No additional architectural policy choice is hidden in the signature sketches.

Thirty-four issue bodies were created or reconciled and verified; eleven
missing findings were filed as #157–#167. Existing device issues retain their
narrow scope. Corrections include bounded block chains/transfers, offered
console features, MSI-X completion bypassing table helpers, the 32-bit-only
SETXATTR overflow claim, and BATCH_FORGET's existing input-exhaustion bound.
Portable adapter I/O is not itself a violation. Missing isolated workers and
fresh-machine lifetime accounting remain violations.

## Execution evidence and limits

This pass performed source inspection and evidence reconciliation. It ran no
new native probe, hostile-input experiment or guest boot. Required native
qualification remains open rather than being counted as conformance.

The earlier audit's [evidence record](https://github.com/pichi-vm/dillo/issues/139#issuecomment-6926573202)
and [API probes](https://github.com/pichi-vm/dillo/issues/139#issuecomment-6926573888)
retain their original scope: component tests, focused probes and ordinary
native CI lanes against the older locked PMI/Arma. They also record silently
skipped parser assertions. Unchanged code makes those results relevant, not
broader than originally demonstrated. Historical registers and reverse paths
remain linked from [the tracking issue](https://github.com/pichi-vm/dillo/issues/139).

Outstanding qualification includes current-PMI native initialization and
refusal, DT duplicate/reservation semantics, CPU entry races and instruction
settlement, actual confined processes, cross-channel notification barriers,
native I/O retirement, host-filesystem races and debugger operations. Their
issue acceptance criteria define the needed tests; ordinary boot success
does not close them. Audit closure does not close implementation findings.
