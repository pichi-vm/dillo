# Typed lifecycle retrofit

Measured code candidate: `e3eb0d86213143ba535dce7084d7b83cb09a8931`.
Reworded code head: `5419a7b4c9ea134d7c1c9727a76a1be9e4733cc4`.
Final code head: `b589d79f6fdcf25d919e3f6289cb260ab2d960c3`.
Baseline: `25f811fe93ee7e17fc301a53a505acf3c6e435fc`.

The measured and reworded commits have the identical tree
`7cf6e2702d0fccaf8804ab0b3ea82714cf60729a`. Only the two new commit
messages changed; [the mapping](commit-message-rewrite.json) preserves the
qualification provenance. The final code head additionally contains the
binding correction described below; that source change is not attributed
to the earlier measurements. Subsequent report changes do not change code.

This is a working experiment on `milestone/device-typestate`, not a proposed
release of the common API. Block and multiport console implement the new
backend trait. The current frontend API is bridged by `Local`; the other
backends use an explicit `Legacy` bridge. Crate/binary extraction and external
QEMU interoperability are outside this milestone.

The prototype is functional on all four native platforms. The ownership
changes remove device-specific cleanup, but compatibility adapters increase
total code size. The measurements support keeping the design for review;
they do not establish universal performance parity. A small Linux x86 network
regression remains unresolved, and Windows storage measurements are too
variable to decide. This milestone stops here rather than starting another
optimization cycle.

## Ownership exercised

`Device<B, S>` owns the backend and phase-specific execution state. Its
configured owner can start workers, its running owner can request a drain,
and only a successfully quiesced owner can resume. Reset retires the workers
before returning an unconfigured owner; stopping can also go directly through
cancellation and join. A timed-out drain returns its quiescing owner. A failed
start or join retains a failed owner.
Dropping an execution owner cancels and joins its workers before dropping the
backend. All workers receive cancellation before any is joined.

The important implementation refinement is `Activation<'a>`. Its constructor
is private to configured-device startup, and it borrows the common worker
list. Each successful spawn immediately transfers its handle and shutdown
wake to that list. A backend cannot retain the startup capability in a worker
or return from a failed partial start with ownership scattered among local
variables. Console's manual aggregate shutdown/join callbacks disappear.

The ring controller is `Ring<L, E>`, with independent lifecycle and enablement
parameters. Only configured stopped rings can start. Only stopped rings can
change geometry or expose their restart cursor. Stopping or changing
enablement requires a borrowed drain proof for the matching execution domain.
The proof prevents device resume while it is borrowed. Cross-thread atomics
remain as worker signals; they are private implementation details rather
than a public collection of unrestricted lifecycle setters.

The final self-check found a hole at the legacy queue boundary: a caller could
produce multiple worker endpoints from one ring and bind a second activation,
overwriting the first activation's drain identity. The 50-line follow-up
`b589d79` rejects any second live binding before workers start. It checks under
the existing setup mutex; no request-loop operation changes. Regression cases
cover rebinding across devices, preserving the original drain authority, and
duplicate endpoints in one activation. The duplicate test fails with the guard
removed. This runtime admission check is needed while the old cloneable `Queue`
is accepted; a future API with a linear worker endpoint could remove that
legacy ambiguity rather than adding more lifecycle flags.

The vhost-user decoder necessarily handles runtime messages. Its small enums
hold typed owners and dispatch the legal transition; invalid wire sequences
remain ordinary errors. It still supports staggered startup, polling without
a kick handle, independent stop/restart, and disabled TX completion versus
disabled RX buffer retention. Console's control RX/TX queues still share one
worker. Quiescing also parks its resize and named-port work; it does not
reset port identity or discard pending input.

## API sketch from the implementation

```rust
pub trait Backend: Send + 'static {
    fn activate(&mut self, activation: Activation<'_>) -> Result<(), ActivateError>;
    // Identity, queue sizes, feature/config access, and the reset hook omitted.
}

// Each fallible transition returns its owner on error.
let configured = Device::new(backend).configure(features);
let running = configured_device.start(resources);
let draining = running_device.request_quiesce();
let quiesced = draining.finish(timeout);
// Borrow quiesced_device.drained() while changing a stopped ring.
let running = quiesced_device.resume();
```

The raw `VirtioActivate` remains at the existing frontend boundary. Device
implementations receive the more restricted `Activation`, which exposes
resources and owned spawning but not an escaping host executor.

## Costs and limits

The [source inventory](source-footprint.json) adds 844 net production Rust
lines and 250 test lines, separating test items with the existing syntax-tree
counter. Physical counts include comments, forwarding methods and compile-fail
documentation. Block and console together shrink by 136 physical lines.
The common lifecycle and ring code, plus the runtime adapter enums,
account for most of the growth. This is an ownership improvement, not yet a
code-size reduction. Removing the old frontend/legacy bridge is later work.

There are no dependency or unsafe-code additions. Neither the vhost-user
codec nor the Windows ALPC channel changes. The state transitions, worker
registry and ring-domain checks run on the control path. They add no request
payload copy, per-request allocation, notification RPC, or new hot-path
mutex. The marker parameters themselves carry no data. Control resources
still cost real storage: a common worker vector, retained wakes, a shared
barrier, and adapter state. Local frontend adaptation also caches metadata
and serializes control operations, without putting that mutex in workers.

This does not make arbitrary backend logic correct by construction. Worker
loops still cooperate at checkpoints after completing admitted requests and
releasing locks. Guest descriptor validation and I/O semantics remain runtime
work. The prototype preserves the existing checked queue engine and memory
interfaces; it does not prove that an arbitrary backend cannot retain a raw
memory capability. The `Legacy` bridge also retains the older backends'
partial-start cleanup contract until those implementations are migrated.

The drain wait is bounded; thread join is not. An uncooperative or indefinitely
blocked backend operation can still delay local retirement. The timeout
retains ownership rather than pretending the operation stopped. Existing
out-of-process deadline/termination policy remains with the process owner;
typestate does not replace that containment mechanism.

Borrowed startup proved more useful than merely putting an activation flag
behind a marker: it removed per-device rollback ownership. The price of the
consuming API is explicit owner-preserving error handling and adapter enums.
The current execution hook uses the existing host executor; this experiment
does not yet evaluate a shared event-loop implementation or a new async
runtime.

Before publishing a general library API, the dynamic `Slot` adapter should
be hidden behind the transport boundary rather than exposing its temporary
`Vacant` variant. The prototype also keeps metadata forwarding methods from
the old interface. Neither is a reason to add more states or wire messages;
they are concrete API simplification questions for the milestone review.

## Correctness evidence

[Local validation](local-validation.json.gz) records the exact code revision,
583 passing workspace/doc tests, six ignored tests, and strict all-target,
all-feature workspace Clippy. The count includes six compile-fail examples.
The separate worker-process executable also completes successfully.

[Final local validation](final-local-validation.json.gz) repeats the workspace
and strict Clippy checks after the binding correction: 584 passed, six ignored,
and no failures. It also retains the worker-process run and the deliberate
negative regression run without the guard.

The new cases exercise an admitted blocking operation delaying a drain,
retention after a drain timeout, worker retirement before backend drop,
partial console startup failure at each spawn boundary, local console
quiesce/resume/reset, and rejection of a drain from another device. The
existing process suite exercises real raw/qcow2 requests, pending writes,
reset/crash/deadline handling, independent ring relocation, disable/enable,
console input/resize, filesystem sessions, networking and vsock.

[Final native CI run 46158042943](https://github.com/pichi-vm/dillo/actions/runs/46158042943)
checked `b589d79`, including the binding correction. All four native platform
jobs passed:

| Platform | Result | Job |
| --- | --- | --- |
| Linux x86-64 / KVM | Passed | 141018923202 |
| Linux AArch64 / KVM | Passed | 141018923439 |
| macOS AArch64 / HVF | Passed | 141018923438 |
| Windows x86-64 MSVC / WHP | Passed | 141018923484 |

The platform jobs include their workspace and guest boot suites. The separate
macOS confinement, format/Clippy, dependency and license jobs also passed.
[Full job/step metadata](final-native-ci.json) retains skipped steps explicitly.
The [earlier run](https://github.com/pichi-vm/dillo/actions/runs/46154216697)
also passed all native and code checks on the measured `e3eb0d8` tree;
[its metadata](native-ci.json) is retained separately.

The earlier workflow's commit-message job failed on inherited experimental
history and the two new titles/bodies. The new messages are corrected in
the identical-tree rewrite above; local `gitlint` passes for all three new
commits through `b589d79`. All 104 commit-message failures in the final run
are [verified ancestors of the baseline](commitlint-history.json). That history
remains untouched. Consequently this report claims successful native/code
checks, not an entirely green workflow or a merge-ready PR.

## Measurement protocol

Use the same baseline/candidate runtime pair, producer, guest kernel and
probe within each host allocation. Compare local with local and worker with
worker. Measure block PCI, block MMIO without PCI, network PCI and network
MMIO without PCI. Use ten balanced pairs plus warm-up, two seconds per
operation, block depth eight, and the existing host sampler. Retain all
observations, both latency and CPU results, rather than selecting favorable
operations. The normal vhost-user completion path is selected; the private
shared-ISR experiment is disabled on both revisions.

Network is a control for changes in the common worker machinery. Console is
present in every measured boot and is exercised directly by lifecycle and
process fixtures. This experiment does not measure sustained multiport console
throughput, so it cannot establish performance equivalence for that workload.

Run 46153587269 was canceled during compilation, before any measurements,
when startup ownership was tightened. Its source was `3463654`; it is not
performance evidence for the final candidate. The earlier candidate's CI
run 46153584979 passed all native platform jobs. Its commit-message check also
failed; it is not reported as a fully green workflow.

## Measured results

[Run 46154219252](https://github.com/pichi-vm/dillo/actions/runs/46154219252)
completed 176 successful boots per platform, 704 total. Every measured and
warm-up boot is retained. The imported records verify guest success, data
verification, expected process counts, PCI absence in MMIO-only cases, matched
guest assets, and distinct baseline/candidate runtime hashes. Artifact digests
were checked during download; [CI/artifact metadata](benchmark-ci.json) records
their exact source and IDs.

Each table cell is local / worker throughput as a percentage of its own
baseline; 100 means unchanged and higher is better. Ranges span the paired
medians of four block operations or two network sizes, not confidence
intervals. A median of paired ratios need not equal a ratio of medians.

| Platform | Block PCI | Block MMIO, no PCI | Network PCI | Network MMIO, no PCI |
| --- | --- | --- | --- | --- |
| Linux x86-64 | 98.6–100.0 / 99.4–100.2 | 99.1–105.2 / 97.4–102.0 | 100.0–100.7 / 98.6–99.8 | 99.2–99.3 / 100.0–100.1 |
| Linux AArch64 | 98.6–99.7 / 99.4–100.5 | 97.0–100.1 / 99.6–101.0 | 97.0–101.9 / 95.6–97.4 | 100.3–100.7 / 97.4–99.8 |
| macOS AArch64 | 99.5–101.1 / 96.0–100.2 | 97.3–100.2 / 100.2–101.9 | 99.6–99.8 / 99.7–100.1 | 99.7–99.8 / 99.7–100.0 |
| Windows x86-64 | 95.9–104.6 / 86.6–98.7 | 100.4–104.6 / 95.1–103.4 | 99.1–99.5 / 99.3–100.0 | 98.9–100.4 / 100.9–102.5 |

The existing analyzer bootstraps a 95% interval for each paired median. These
are descriptive intervals assuming exchangeable pairs, without a correction
for testing many metrics. An interval containing 100% is not by itself proof
of equivalence, particularly when it is wide.

- Linux storage throughput intervals include the baseline. Some MMIO intervals
  are wide, so this excludes neither small costs nor small gains.
- Most macOS rates are close to the baseline. Local PCI random-read throughput
  is 99.5% (98.4–99.8%), while its CPU/GiB and p99 improve. Other small shifts
  and mixed tail-latency changes are retained without causal attribution.
- Linux x86 worker PCI 64-KiB echo throughput is 98.6% (97.4–99.3%); CPU/GiB is
  102.9% (101.4–104.2%), and p99 is 101.6% (101.1–102.7%). This remains an
  unresolved small regression rather than a declared noise pass.
- Windows worker PCI sequential-read throughput is 86.6% with a 43.9–162.6%
  interval. Storage parity is inconclusive. The p99 readings all land in the
  same roughly 4-ms bucket, which cannot establish latency equivalence.

One Windows candidate p95 series contains a zero reading. The analyzer omits
that ratio, leaving mismatched metric sets between revisions. The comparison
uses their common metrics and explicitly records the unmatched
`block-mmio-only` random-read p95 series in the Windows archive; the raw
reading is preserved. No boot or nonzero observation was discarded to improve
the result.

## Bounded calibration

[Run 46157827731](https://github.com/pichi-vm/dillo/actions/runs/46157827731)
ran 44 additional successful PCI-network boots with the final `b589d79` binary
under both labels. Runtime hashes match. Worker bulk throughput was 99.7%
(99.1–100.4%) and CPU/GiB 100.1% (99.4–100.5%).

However, GitHub assigned an AMD EPYC 7763 host to this calibration, whereas the
original comparison used an Intel Xeon 6975P-C. This is not a matched-host
calibration and cannot clear the Intel result. It is retained as evidence,
not applied as a universal noise band. The planned single calibration budget
is exhausted; there is no optimization or repeated-run search for a pass.
[Calibration records](linux-x86-noise.json.gz) and [CI metadata](noise-ci.json)
preserve the distinction.

The full four-platform baseline comparison measures the retrofit before the
final binding guard. The guard changes setup admission only, with no change to
the request-loop functions; its correctness is separately qualified on all
platforms. The final head has the focused calibration above, not a second full
baseline comparison. The results must not be described as exact-final-head
performance certification.

## Memory and startup

Process and thread counts do not increase in any measured case. Native
process-tree PSS increases by a paired median of 85–165 KiB on Linux x86 and
184–322.5 KiB on Linux Arm, depending on case/mode. Windows summed private bytes
vary by −38 to +40 KiB. These native metrics have different meanings; they are
not a cross-platform physical-footprint total. macOS private-memory data was
unavailable, and summed RSS is deliberately not substituted. No attribution to
individual allocations is claimed.

The exact source shows no added per-request allocation, payload copy, thread,
or process. The extra common owners, retained wakes and compatibility metadata
still occupy storage; zero-sized markers do not make those resources free.
Guest RAM size and backing remain unchanged.

Ready-time observations use the existing 50-ms sampler. Some macOS differences
are only one or two sampling ticks, so large relative ready-time percentages
are not treated as precise startup costs. Attachment traces, raw samples,
CPU/GiB and all latency results remain in the archives.

## Review boundary

Keep the borrowed startup capability and consuming device/ring transitions for
the next design discussion: they handle real rollback and reset obligations
and work through both existing execution paths. Before freezing a common
library API, simplify the compatibility adapters and decide how to replace the
legacy cloneable queue endpoint with a linear one. Broader device migration,
crate extraction, new executor design and more performance tuning are not
started in this milestone.

All operation-level comparisons, intervals, raw boot records and samples:

- [Linux x86-64](linux-x86-measurements.json.gz)
- [Linux AArch64](linux-arm-measurements.json.gz)
- [macOS AArch64](macos-arm-measurements.json.gz)
- [Windows MSVC](windows-msvc-measurements.json.gz)
- [Compact comparison index](measurement-summary.json)
