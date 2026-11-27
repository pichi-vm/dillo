# Device performance: interim execution evidence

This is an incremental diagnostic, not the final parity qualification. The
milestone remains active. Source: `8690c35` for the initial direct completion
candidate (`c442891` after a message-only history rewrite).

## Changes

- Native queue endpoints eliminate the extra kick forwarding thread on all
  supported platforms. KVM registers PCI word writes and MMIO dword writes
  using their exact address, width and value.
- KVM PCI queues export a stable eventfd to the worker and bind it with irqfd.
  The parent retains mask, pending-bit, retarget and reset ownership. The
  in-process control receives the same native completion endpoint.
- Native reconfiguration errors propagate through PCI/MMIO dispatch to CPU
  supervision, rather than being mistaken for an unmapped access.
- WHP doorbells now pass native notification and guest boot checks. WHP
  interrupt triggers also pass guest-observed delivery, retargeting and
  revocation checks. Queue pause drains the worker before replacing its
  signaling endpoint. Software pending events survive endpoint replacement;
  the signal-only native trigger event must not be polled as a waitable event.

## Physical Linux x86 diagnostic

Apollo, AMD EPYC 8324P; both modes restricted to CPUs 24–27. One PCI block
endpoint, unchanged guest/kernel/assets, 4 KiB random and 64 KiB sequential
QD1 operations. Each stage uses one warm-up pair followed by three alternating
pairs, two seconds per operation. Process-tree CPU sampling remains enabled.
Builds completed before timed runs. Source/binaries and raw observations are
retained under `target/performance/{frozen,direct-kicks,pci-ioeventfd,pci-irqfd}`.

The frozen control is source `7604a03` (message-only rewrite `cc0c1bb`), the
ioeventfd stage is `26fea7f` (`bd60488`), and the irqfd stage is `8690c35`.

| QD1 operation | Frozen worker MiB/s | irqfd worker MiB/s | irqfd in-process MiB/s | Paired worker/control throughput | Paired CPU/GiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random read, 4 KiB | 58.91 | 118.86 | 119.06 | 0.992 | 1.010 |
| Random write, 4 KiB | 53.70 | 97.24 | 99.10 | 0.992 | 1.014 |
| Sequential read, 64 KiB | 409.60 | 532.71 | 539.20 | 0.975 | 1.020 |
| Sequential write, 64 KiB | 281.02 | 463.99 | 494.03 | 0.992 | 1.008 |

Rates are medians; paired ratios are medians of matched ratios, not the ratio
of the two column medians. With only three pairs, these are directional
results. They do not establish the plan's confidence-interval criterion.
Random-read/write p99 histogram bounds both match the optimized control in
this run; sequential-read p99 remains worse. Total idle threads fall from
25 to 19 for the worker mode, and 20 to 16 for the control. The control also
benefits because the accompanying console uses the same optimized paths.

## Correctness and remaining work

Local checks pass for native KVM masking/retarget/deassignment with retained
exports; transport function/vector masks, shared-vector pending coalescing,
NO_VECTOR, reset and binding-error propagation; and real child activation
with a host refusing every kick/call relay spawn. Existing process reset,
quiescence, failure and native grant fixtures pass on Linux. Strict workspace
Clippy passes after the fixture corrections.

[Run 46017858751](https://github.com/pichi-vm/dillo/actions/runs/46017858751)
qualified the kick changes across all native platforms.
[Run 46030159145](https://github.com/pichi-vm/dillo/actions/runs/46030159145)
passed all nine native/check jobs at `cb9f4e7`, including integrated WHP
completions, endpoint replacement, memory fast paths and pipe coalescing. The first direct-call macOS fixture
released its reader before writing its cleanup wake; the fixture now retains
that reader. This was not a production notification failure.

## Longer run and cross-platform results

The ten-pair, five-second Apollo run is retained in
`target/performance/pci-irqfd-long/results`; selected absolute observations
and paired ratios are in [apollo-long.json.gz](apollo-long.json.gz). It prevents a
parity claim based on the shorter run: median paired random-read throughput
is 0.983 of control, but random-write throughput is 0.900, with p99 histogram
bounds 1.40 times control. Sequential-write throughput is 0.956. The write
variation remains under investigation; it has not been discarded as noise.

[Benchmark run 46024352541](https://github.com/pichi-vm/dillo/actions/runs/46024352541)
completed all four platforms at `88e09dc` (tree-identical to `fe48be6`). Each
case has three alternating pairs of two-second operations after a retained
warm-up pair. This includes native kicks and KVM PCI completions, but precedes
WHP native completion integration. Artifacts retain raw reports, logs and
environment/binary identity. [matrix-short.json.gz](matrix-short.json.gz) contains
selected absolute observations and paired ratios. These short runs guide
optimization; they do not establish the final confidence criterion.

- Hosted Linux x86 PCI block throughput retains 97–99% across the four
  operations; its 64-KiB network echo retains 77%.
- Physical Linux Arm PCI random reads reach 108% of control, while random
  writes retain 84%. MMIO random reads/writes retain 71%/64%, and cost more
  CPU per GiB. Their necessary parent completion relay remains.
- macOS PCI random reads/writes retain 88%/89%; MMIO retains 88%/78%.
  Direct kicks help, but completion injection still crosses the parent.
- Windows PCI random reads/writes retain 86%/85% before native completions.
  Those results are not measurements of the newer trigger implementation.

Ratios above are rounded medians of matched pairs. Windows guest latency
remains unqualified because its clock is refined-jiffies. Short network
echo results include the host echo service and are not link-capacity claims.

## Current attribution and qualification

Userspace-only Linux `perf` sampling works without changing host policy
(`cycles:u`, DWARF user call chains). The initial traces cover whole boots
and timed phases; they are diagnostic, not phase-isolated CPU accounting.
They identify repeated guest-memory iteration, region admission and heap
allocation in both modes. The implementation removes a per-claim allocation and uses a checked
single-mapping copy when possible, preserving admission, capability lifetime
and the existing cross-mapping fallback.

[Windows run 46027280352](https://github.com/pichi-vm/dillo/actions/runs/46027280352)
qualifies the native completion owner at `4cae185`, including a signal
immediately followed by trigger deletion and retained obsolete handles.
Its preceding owner test exposed an invalid wait on a signal-only handle;
that failure and correction are retained in the qualification record. The
subsequent full native run above passed on every supported platform.

## Shared-path improvements

Three-pair/two-second Apollo comparisons use separately frozen binaries and
identical guest assets, with CPUs 24–27 and no concurrent build. See
[memory-short.json.gz](memory-short.json.gz). The combined inline-region and
contiguous-copy changes raise worker random-read throughput from 117.65 to
125.60 MiB/s and lower process-tree CPU/GiB from 13.622 to 12.618. The optimized
control still leads at 128.50 MiB/s and 12.253 CPU-s/GiB. The sequential-read
worker result rises from 575.63 to 634.50 MiB/s. These are short attribution
runs, not final parity evidence.

The TCP proxy previously enabled Nagle on both its host and guest-facing
connections, irrespective of the original application's TCP_NODELAY choice.
Disabling that extra buffering raises 64-KiB echo worker throughput from
143.69 to 164.61 MiB/s in the matched short experiment. The median of each
run's worst request falls from 43.77 ms to 1.61 ms; p99 histogram bounds fall
from 0.623 ms to 0.508 ms. The control improves too. See
[network-short.json.gz](network-short.json.gz). These measurements include the
host echo service; they are not one-way link-capacity results. Host sockets
are configured before transfer, without extending worker syscall authority.

Snuffler now measures bounded concurrency at 1, 8 and 32 requests per device.
The four-device concurrent case synchronizes all devices within each measured
window; the older serial four-device case keeps its original meaning. The
native run at `cb9f4e7` qualifies these changes. QD1 remains the primary target;
load results cannot compensate for a QD1 regression.

The short Apollo QD8/QD32 experiments are retained in
[concurrency-short.json.gz](concurrency-short.json.gz). At QD32 one PCI block
device retains 98–101% of control throughput across the four operations;
four concurrent devices retain 93–99%. Process-tree CPU/GiB is within about
2% in those QD32 runs, but some latency tails are worse. These are three-pair
diagnostics, not evidence that concurrency eliminates isolation overhead.

[Windows run 46030327297](https://github.com/pichi-vm/dillo/actions/runs/46030327297)
measures the integrated native trigger at `227bc73`. PCI block throughput
retains 95–97% in the three-pair/two-second run; MMIO retains 76–83%, with
16–35% more CPU/GiB. See
[windows-trigger-short.json.gz](windows-trigger-short.json.gz). This is a
different hosted allocation from the earlier Windows run, so the cross-run
improvement alone is not a controlled attribution to triggers. Guest latency
remains unqualified.

## Candidates kept and rejected

The cross-VMM source comparison in [the plan](../../OPTIMIZATION.md#cross-vmm-check-of-the-remaining-constraints)
shows that software interrupt state does not require one receiver per queue.
`5f6c1eb` shares the existing call endpoint only when queues have the same
interrupt owner; native bindings and distinct owners remain separate. The
existing process fixture delivers completions for six queues through two
receivers across repeated activation. Local unit/process tests and strict
Clippy pass. The [Windows worker run](https://github.com/pichi-vm/dillo/actions/runs/46036770078)
also passed at this exact head, including the native notification checks;
the later [macOS worker run](https://github.com/pichi-vm/dillo/actions/runs/46038114850)
passed with both receiver sharing and the kqueue candidate below.

An actual guest comparison changes only the accompanying console from PCI
to MMIO, using the same PCI block workload and assets. Sharing the console's
two call endpoints removes one idle parent thread: worker mode falls from
21 to 20 total threads, and the control from 18 to 17. The three-pair rates
vary without a consistent CPU or latency improvement; this change earns its
cost by removing redundant receivers, not by establishing QD1 parity. See
[shared-calls-short.json.gz](shared-calls-short.json.gz). The temporary harness
diff and frozen binaries are retained under `target/performance/shared-calls`.

A descriptor-list reuse candidate removed two allocations per block request
but added retained per-worker vectors. Its matched three-pair run showed no
clear worker throughput or CPU benefit, so the implementation was removed.
[descriptor-reuse-short.json.gz](descriptor-reuse-short.json.gz) retains the
result; the candidate binary and source patch remain under
`target/performance/descriptor-reuse`.

A second candidate avoided locking permanently shared memory state while
retaining the dynamic-state check for capabilities that support conversion.
Its short run showed little consistent end-to-end benefit, so it too was
removed. [static-shared-short.json.gz](static-shared-short.json.gz) and
`target/performance/static-shared` retain the observations and source patch.

The macOS-only candidate `59f3e98` keeps the notification and cancellation
pipes registered in a receiver-owned kqueue. This changes neither the
transferred endpoint nor interrupt status, and retains readiness after a
partial drain. It adds one descriptor per receiver; native correctness and
latency results must justify that cost before keeping it. Linux fallback
tests and strict Clippy pass, but do not qualify the macOS implementation.
The macOS worker run at `59f3e98` passed the native pipe tests and real
confined-process fixture. Guest performance on Hermes remains unmeasured
for this candidate.

The ten-pair/five-second matrix is running at `6e73b7c` in
[run 46032087496](https://github.com/pichi-vm/dillo/actions/runs/46032087496).
Its results and residual gaps will be recorded before any parity claim.
