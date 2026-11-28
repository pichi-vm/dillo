# Device performance: interim execution evidence

This is an incremental diagnostic, not the final parity qualification. The
milestone remains active. Source: `8690c35` for the initial direct completion
candidate (`c442891` after a message-only history rewrite).

Acceptance clarification: matching the equally optimized control within
measured noise is success. Earlier entries requiring every small nonzero
point estimate to improve are superseded by this rule; their observations
remain unchanged. Calibration is specific to the platform, transport,
workload and metric. Wide uncertainty alone does not qualify a result.

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
  CPU per GiB. Their current parent completion relay remains; this is an
  implementation choice, not a virtio requirement.
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
confined-process fixture. The later three-pair Hermes run at `6d4b3cb` retains
substantial worker/control differences; it does not isolate kqueue from
polling because the earlier run used different durations.

The controlled [Hermes comparison](https://github.com/pichi-vm/dillo/actions/runs/46046071714)
builds both waits on one host with identical Arma, snuffler and kernel hashes.
Three-pair/two-second PCI-free measurements favor kqueue in all six measured
worker operations: throughput rises 1.0–13.4% and CPU/GiB falls 2.6–12.8%.
Block random-write p99 bounds fall from 34.8 to 31.7 microseconds; the 64-KiB
network bound falls from 344 to 328 microseconds. The in-process control also
benefits. This supports retaining the implementation and its extra descriptor
per receiver, but does not establish worker/control parity. Results are in
[macos-wait-short.json.gz](macos-wait-short.json.gz), with raw artifacts under
`target/performance/macos-wait-comparison-46046071714`.
The first comparison attempt (`46045085711`) failed before measurement because
the runner denied Bash's here-document temporary file. A checked-in Python
helper replaced that shell mechanism; the runner configuration was unchanged.

## Completed long matrix and PCI-free measurements

[Run 46032087496](https://github.com/pichi-vm/dillo/actions/runs/46032087496)
completed all four native platforms at `6e73b7c`: ten alternating measured
pairs per case, five seconds per operation, plus a retained warm-up pair.
This includes native kicks, KVM/WHP PCI completions, memory improvements and
TCP_NODELAY. It precedes shared software call receivers and the kqueue
candidate. [matrix-long.json.gz](matrix-long.json.gz) retains selected absolute
observations, paired ratios and 95% bootstrap intervals. The raw artifact
directories are under `target/performance/matrix-long-46032087496`.

The remaining MMIO gap is clear. For random reads/writes, paired worker/control
throughput is 0.775/0.663 on physical Linux Arm, 0.899/0.828 on macOS and
0.817/0.818 on Windows. Linux Arm uses 1.333/1.613 times the CPU per GiB;
Windows uses 1.221/1.242 times. These cases have an MMIO workload but a PCI
console. They do not qualify a guest with no PCI hardware.

PCI is closer, but does not establish the overall goal either. Windows block
throughput retains 94.5–96.0% across the four operations. Physical Linux Arm
sequential reads/writes retain 93.3/93.1%, with about 8% more CPU per GiB.
macOS PCI block retains 87.8–92.0%. Windows histogram tails remain unusable
for microsecond comparisons because the guest clock is refined-jiffies;
identical reported bounds are not evidence of equal latency.

The separate Apollo ten-pair/five-second run at `5f6c1eb` includes shared call
receivers. PCI random reads retain 99.1% of control throughput, while MMIO
random reads retain 88.0% and use 21.9% more CPU per GiB. Other cases and their
intervals are retained in [apollo-current-long.json.gz](apollo-current-long.json.gz).
Both modes used CPUs 24–27 and the same frozen guest assets. This physical
host result is distinct from the hosted Linux x86 matrix allocation.

The new `block-mmio-only` and `net-mmio-only` cases request zero PCI slots and
two MMIO slots from Arma, put both console and workload on MMIO, and reject a
guest report containing any PCI devices. Image-generation commands and hashes
are retained. PCI driver support in the shared kernel does not create PCI
hardware in these images.

The initial three-pair/two-second PCI-free diagnostics completed on Apollo,
[Linux Arm](https://github.com/pichi-vm/dillo/actions/runs/46042528649),
[macOS](https://github.com/pichi-vm/dillo/actions/runs/46041985577) and
[Windows](https://github.com/pichi-vm/dillo/actions/runs/46042528651). The native
runs use `6d4b3cb`; Apollo uses that harness with the frozen `5f6c1eb` binary.
[pci-free-short.json.gz](pci-free-short.json.gz) retains all selected results.
Random-read/write throughput retains 90.4/82.6% on Apollo, 75.1/70.1% on Linux
Arm, 90.5/77.8% on macOS and 92.2/84.1% on Windows. These short diagnostics confirm the gap exists
without PCI; they are not final qualification or controlled comparisons
against different-duration runs on different hosted allocations.

PCI and MMIO performance are independent, equal acceptance conditions,
including guests without a PCI bridge. The next experiment
tests publishing a host-only interrupt latch before native notification,
leaving register reads and acknowledgements in the parent transport. This is
isolated from the production branch: a prototype using an unassigned protocol
extension cannot establish interoperability, reset/revocation correctness or
native level reassertion. Its purpose is to measure the cost of the relay
before selecting a complete mechanism.

## Shared-status prototype on Linux x86

The isolated [prototype branch](https://github.com/pichi-vm/dillo/tree/experiment/mmio-shared-status)
has now completed an Apollo comparison: the same frozen binary with the
shared latch disabled/enabled, unchanged guest assets, CPUs 24–27, three
alternating pairs per case and two seconds per operation. Both console and
workload use MMIO; every retained guest report has an empty PCI list. See
[shared-isr-short.json.gz](shared-isr-short.json.gz) and the raw records under
`target/performance/shared-isr-experiment`.

Worker random-read throughput rises from 50.70 to 57.01 MiB/s, against an
enabled-path control at 57.62 MiB/s. CPU/GiB falls from 28.65 to 23.83 seconds
(control 23.49). Random-write throughput rises from 46.54 to 56.55 MiB/s.
Two parent relay threads disappear, one for the console and one for the
workload. The prototype adds a host-only 4-KiB status mapping per device.
This is evidence that the current MMIO relay cost is removable, not a
parity or correctness qualification.

Immediate native signaling also exposes a network tradeoff: 64-KiB worker
echo falls from 123.49 to 82.11 MiB/s. A follow-up candidate signals only when
setting a previously clear used-buffer bit, coalescing until guest ACK. Its
three-pair result reaches 143.72 MiB/s (control 145.00), with 14.31 CPU-s/GiB
(control 14.19); both modes improve. The hypothesis is excessive notifications,
not a measured interrupt-count attribution. Sequential block results vary
substantially and some p99 bounds remain worse. All observations are retained.

The first binary corresponds to `3605a64` source, with the recorded harness
change and frozen hash; the coalescing variant has its own retained patch and
binary. Both variants are excluded from the production optimization branch.
[Native Linux Arm run 46045365585](https://github.com/pichi-vm/dillo/actions/runs/46045365585)
completed both paths at `3605a64` on the same host, with the same three-pair,
two-second design. Worker random reads rise from 94.94 to 135.07 MiB/s and
random writes from 83.29 to 121.96 MiB/s. The corresponding shared-path control
medians are 117.49 and 118.09 MiB/s. Worker CPU/GiB falls from 16.81 to 11.26
seconds for reads and 19.75 to 12.82 for writes. The 64-KiB network case still
has a worse p99 bound; the coalescing follow-up below measures that separately.
[shared-isr-arm-short.json.gz](shared-isr-arm-short.json.gz) retains the paired
observations, and raw artifacts are in `target/performance/shared-isr-arm-46045365585`.
Neither the host-only latch nor successful guest I/O resolves per-activation
capability revocation or native level reassertion; the experiment retains the
existing KVM pulse behavior.

[The Arm coalescing run](https://github.com/pichi-vm/dillo/actions/runs/46046812309)
completed all 32 PCI-free boots at `690dbd6`. It compares relay and coalesced
shared status in the same binary, with three pairs of two-second operations
per case. Worker random reads increase from 89.41 to 145.43 MiB/s and random
writes from 80.07 to 123.46 MiB/s; the shared-path control medians are 117.37
and 123.81 MiB/s. Worker CPU/GiB falls from 17.91 to 10.14 seconds for reads
and from 20.64 to 12.50 for writes. The 64-KiB echo rate rises from 107.16 to
123.57 MiB/s, but its optimized control reaches 140.32 MiB/s: paired worker
throughput retains 92.2%, and CPU/GiB is 17.1% higher. Its p99 bound improves
to 589823 ns, versus 622591 ns for control. This mixed result does not
establish parity. [shared-isr-arm-coalesced-short.json.gz](shared-isr-arm-coalesced-short.json.gz)
retains all paired metrics; the raw artifact and its verified digest are
recorded with the data. The level-delivery and revocation limits above still
apply. Coalescing is not merged into the production branch.

The activation-scoped follow-up (`bdcc6fa`) creates a fresh native binding and
status page on each activation, and deassigns the old irqfd on retirement.
Level declarations use KVM resampling rather than the earlier pulse path.
The native x86 fixture passes real guest EOI, reassertion while pending,
acknowledgement and obsolete-export checks. Arm runs
[46050795668](https://github.com/pichi-vm/dillo/actions/runs/46050795668) and
[46051334834](https://github.com/pichi-vm/dillo/actions/runs/46051334834) fail
before benchmarking: initial delivery and guest IAR/EOI execute, but the
fixture observes no resample notification. Their logs remain under
`target/performance/shared-isr-lifetime`; the correction below reruns it.

Apollo completed 32 PCI-free boots with this runtime, using the same frozen
binary for both paths, three pairs of two-second operations and CPUs 24–27.
Random-read worker throughput rises from 50.65 to 57.18 MiB/s, against a
57.55 MiB/s shared-path control; CPU/GiB falls from 28.63 to 23.57 seconds,
versus 23.39 in process. Random writes rise from 46.78 to 57.39 MiB/s.
The 64-KiB echo rate rises from 123.86 to 142.97 MiB/s, against 147.49 in
process. Sequential reads still retain only 93.5% of control throughput and
use 9.0% more CPU/GiB. These short observations do not establish parity, and
the x86 image's edge interrupts do not exercise level-resampling cost.
[shared-isr-lifetime-short.json.gz](shared-isr-lifetime-short.json.gz)
records every paired metric and asset hash. The transport-level reset races,
asynchronous helper failure, and protocol interoperability remain unqualified.

The same frozen runtime also completed a separate 16-boot PCI comparison,
with the same short design and CPU affinity. Paired worker/control throughput
retains 98.5% for random reads, 96.6% for random writes, 97.4% for sequential
reads and 97.9% for sequential writes; CPU/GiB is 2.6–4.0% higher. The 64-KiB
echo case retains 98.9% throughput with 1.6% more CPU/GiB. The sequential-read
p99 paired ratio is 1.097. These independent PCI observations are included in
the same data file. They neither qualify final parity nor substitute for the
MMIO results; the two transports have separate controls and acceptance tests.

[Run 46052881345](https://github.com/pichi-vm/dillo/actions/runs/46052881345)
passes the native Arm lifecycle fixture and completes 32 PCI-free measurement
boots at `fefb91e`. The prior fixture had never programmed SPI 48's trigger
type: diagnostic run 46052592772 observed ICFGR=0xaaaaaaaa, indicating edges,
while confirming IAR activation and EOI deactivation. Explicitly selecting
level delivery fixes the fixture; it now observes reassertion before ACK,
no reassertion after ACK, and revocation of retained old exports.

The benchmark images still use Arma's declared edge-triggered MMIO SPIs,
preserved through the launcher; they do not measure level-resampling overhead.
Their worker random reads increase from 93.96 to 118.34 MiB/s, against a
115.85 MiB/s shared-path control, while CPU/GiB falls from 16.97 to 13.19
seconds. The 64-KiB echo median rises from 108.96 to 116.42 MiB/s, but the
paired worker/control throughput ratio is 0.937, CPU/GiB ratio 1.159, and p99
ratio 1.25. Random writes vary substantially between pairs: the median of
paired throughput ratios is 0.945 even though the separate worker median
exceeds the separate control median. Short runs remain diagnostic, and all
paired observations are retained in
[shared-isr-arm-lifetime-short.json.gz](shared-isr-arm-lifetime-short.json.gz).

The separate register-level fixture also verifies ACK/coalescing, activation
failure and reset isolation from retained callbacks. It uses a recording
native binding; native deassignment is tested separately above. Strict Linux
workspace Clippy passes with both VM tests and the in-process benchmark
enabled. Concurrent transport/native reset races and live resampler-failure
supervision remain open, as do the protocol and non-Linux implementation.

## Windows shared-status and native wired completion experiment

[Run 46057401790](https://github.com/pichi-vm/dillo/actions/runs/46057401790)
completed 32 PCI-free boots at `2fc9543`, comparing relay and shared-status
paths in the same binary with identical guest assets. Each path retains a
warm-up pair and three alternating measured pairs of two-second QD1 operations.
Both console and workload use MMIO; all guest PCI lists are empty. The modes
run sequentially, so these short observations still allow host/time variation.

| Operation | Relay worker MiB/s | Shared worker MiB/s | Shared control MiB/s | Paired shared/control throughput | Paired CPU/GiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random read, 4 KiB | 16.89 | 18.83 | 20.23 | 0.932 | 1.169 |
| Random write, 4 KiB | 16.42 | 18.77 | 19.96 | 0.940 | 1.036 |
| Sequential read, 64 KiB | 183.14 | 195.43 | 207.67 | 0.944 | 1.044 |
| Sequential write, 64 KiB | 183.68 | 197.11 | 209.05 | 0.937 | 1.118 |
| TCP echo, 64 B | 0.138 | 0.217 | 0.225 | 0.972 | 1.018 |
| TCP echo, 64 KiB | 44.97 | 67.53 | 69.40 | 0.964 | 1.058 |

Block worker idle threads fall from 30 to 28; control falls from 22 to 21.
Random-read worker CPU/GiB falls from 53.35 to 46.18 seconds, but the shared
control uses 40.96 seconds. The worker/control differences remain real work;
neither these medians nor the coarse guest latency histograms establish parity.
[shared-isr-windows-short.json.gz](shared-isr-windows-short.json.gz) retains
every paired metric, clock report, exact source, asset hashes and artifact
digest. Raw observations and native logs are under
`target/performance/windows-wired-completion-46057401790`.

The status page uses an owned pagefile section transferred through ALPC.
[Run 46056134419](https://github.com/pichi-vm/dillo/actions/runs/46056134419)
at `203a2ea` first qualified its real confined-worker mapping and atomic
status/ACK behavior. [Run 46057399368](https://github.com/pichi-vm/dillo/actions/runs/46057399368)
at `2fc9543` then passed the integrated worker fixtures and native WHP
mask/pending, retarget, retirement and obsolete-event checks; the benchmark
job repeats those native checks before building the measured assets.
IOAPIC route changes drain the worker before replacing its exported trigger.
This preserves the backend's existing edge injection model; it does not prove
level interrupt/EOI conformance. Concurrent integrated teardown/error paths
and the experimental unassigned protocol extension still need qualification.

The Windows latency limitation has a concrete fixture cause. Its pinned
[Firecracker 6.1.155 config](https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.config)
disables `CONFIG_HYPERV`. The matching
[Linux initialization](https://github.com/gregkh/linux/blob/v6.1.155/arch/x86/kernel/cpu/mshyperv.c)
registers the Hyper-V clock only with that option enabled and marks TSC
unstable without the invariant-TSC privilege. Retained guest logs show this
decision and only jiffies/refined-jiffies clocks. A prebuilt kernel with the
existing Hyper-V clock driver is being investigated; no forced TSC reliability
or kernel source modification is part of the measurement plan.

[Clock diagnostic run 46059813993](https://github.com/pichi-vm/dillo/actions/runs/46059813993)
completed all eight boots at `7a4cec0`. It uses Microsoft's unmodified prebuilt
WSL 6.18.58.1 kernel, extracted from the checksum-verified WSL 3.0.5 MSI without
installing it. The embedded configuration enables the existing Hyper-V clock
drivers. All guests selected `hyperv_clocksource_tsc_page` and the Hyper-V
clockevent; real virtio-disk p99 bounds were sub-millisecond. The host-observed
active intervals agree with the requested 500-ms windows at the precision of
console observation. This resolves the clock capability question without
asserting that raw TSC is reliable or changing a kernel or CPU declaration.

This is a clock diagnostic, not a parity result. That kernel supplies sixteen
nonempty RAM disks, and the old snuffler timed them as well as the intended
virtio disk. [windows-clock-diagnostic.json.gz](windows-clock-diagnostic.json.gz)
retains every boot's clock, selected-disk operation and observed interval, plus
the paired data and artifact digest. The complete logs remain under
`target/performance/windows-clock-diagnostic/46059813993`. The follow-up harness
explicitly selects its disposable virtio disks and checks the resulting device
set before longer PCI and PCI-free comparisons. This kernel lacks built-in
IP autoconfiguration; the explicit guest setup used by the subsequent network
measurements is described below.

## macOS direct completion-read experiment

[Run 46060898814](https://github.com/pichi-vm/dillo/actions/runs/46060898814)
completed 64 boots at `4cc749a`, including PCI and PCI-free block/network cases.
The same binary and guest assets compare the existing kqueue receiver with a
blocking pipe read that retains its own cancellation writer. Native receiver
and confined-worker lifecycle checks passed before measurement. Each mode
uses three alternating worker/control pairs of two seconds after a retained
warm-up; the existing mode runs before the candidate.

The candidate does not consistently improve the measured workloads. Most
worker throughput changes are within roughly 1%; MMIO random writes improve
3.2%, while the PCI 64-KiB network case falls 1.3%. Tail bounds do not improve
consistently either. The candidate still uses 21% more CPU/GiB for MMIO 64-KiB
echo than its same-revision control. These short observations do not justify
adding a notification factory and separate cancellation/lifetime path, so the
candidate remains outside the production optimization branch. The existing
kqueue implementation remains in place. All metrics, including the mixed
results, are retained in [macos-call-read-short.json.gz](macos-call-read-short.json.gz)
and `target/performance/macos-call-read-46060898814`.

## Sharing the immutable mapping collection

A phase-isolated Linux x86 profile identifies repeated region-handle work in
both modes during 64-KiB TCP echo. Dropping `SharedRegion` accounts for about
13–14% of sampled cycles, and constructing a mapped claim accounts for about
8%. Source inspection confirms that cloning `GuestMemoryMmap` allocates a new
vector of region references on every claim. The candidate `219fa22` retains
one `Arc<GuestMemoryMmap>` instead. This changes private ownership fields only;
range/permission/shared-state checks and access behavior remain in place. The
existing access fixture now drops the provider before using its claimed region.
Memory and virtqueue checks and strict Clippy pass.

The profile uses user call chains and the monotonic clock, filtering to the
interior of each measured phase and the Dillo process tree. Earlier attempts
without explicit user-only call chains were refused; those logs are retained.
The raw trace can contain guest-address samples, which are not attributed to
host functions. Profiled rates are not parity evidence. The selected symbols
and time windows are in [region-owner-profile.json.gz](region-owner-profile.json.gz).

An unprofiled comparison completed 32 PCI-free boots with identical guest
assets on CPUs 24–27: three two-second pairs per case and binary, baseline
`070fe3a` before candidate `219fa22`. Large network echo increases from 144.92
to 152.99 MiB/s; worker CPU/GiB falls from 14.14 to 13.35 seconds. The candidate
retains 99.4% of its control's throughput with 2.4% more CPU/GiB, but its p99
bound is 5.6% higher. Small-message echo is essentially unchanged.

Block observations are mixed: sequential reads gain 7.0% throughput, while
sequential writes lose 12.9% and use 18.0% more CPU/GiB. Random reads/writes
change by +1.2%/−1.4%. These short sequential runs do not distinguish temporal
variation from a regression. The candidate remains experimental pending
further measurement. All paired observations are in
[region-owner-short.json.gz](region-owner-short.json.gz); native Arm and macOS
results follow below. The raw comparison remains in the candidate worktree's
`target/performance/region-owner` directory.

A ten-pair/five-second follow-up now interleaves both binaries and both modes
on the same host, rather than measuring the complete baseline first. Its
predeclared 88-boot order and raw results are under
`target/performance/region-owner-interleaved` in the candidate worktree. This
specifically investigates the sequential-write regression. A follow-up CPU
trace of the stripped release candidate is also retained; its unresolved
Rust symbols cannot establish that a particular function's sampled cost fell.

The native [Linux Arm](https://github.com/pichi-vm/dillo/actions/runs/46063811981)
and [macOS](https://github.com/pichi-vm/dillo/actions/runs/46063813891) runs at
`219fa22` each completed 16 PCI-free boots, three pairs of two-second operations
after warm-up. On Arm, worker/control block throughput spans 92.4–103.2%, and
network spans 94.8–97.1%; CPU/GiB spans 97.6–108.7% across the six workloads.
On macOS, block retains 89.1–94.0% and network 97.5–98.0%, with CPU/GiB at
104.6–124.3%. Neither platform establishes parity. These runs compare execution
modes at the candidate revision, not the candidate against its predecessor;
they cannot attribute a change to the shared mapping owner alone. All paired
observations, binary hashes and clocks are retained in
[region-owner-native-short.json.gz](region-owner-native-short.json.gz).

## Windows block measurements with the Hyper-V clock

[Run 46062103549](https://github.com/pichi-vm/dillo/actions/runs/46062103549)
completed all 44 boots at `070fe3a`: ten alternating measured pairs for PCI and
PCI-free MMIO, five seconds per QD1 operation, plus each retained warm-up pair.
All guests selected `hyperv_clocksource_tsc_page`; the harness verified that
only the intended `vda` disk was timed. This uses the unmodified prebuilt WSL
kernel, so cross-kernel differences are not attributed to a Dillo optimization.

| Operation | PCI throughput ratio | PCI CPU/GiB ratio | PCI p99 ratio | MMIO throughput ratio | MMIO CPU/GiB ratio | MMIO p99 ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random read, 4 KiB | 0.962 | 1.014 | 1.024 | 0.931 | 1.043 | 1.059 |
| Random write, 4 KiB | 0.965 | 0.979 | 1.043 | 0.955 | 1.024 | 0.950 |
| Sequential read, 64 KiB | 1.309 | 0.844 | 0.829 | 1.414 | 0.747 | 0.806 |
| Sequential write, 64 KiB | 1.240 | 0.850 | 0.816 | 1.429 | 0.771 | 0.750 |

These are medians of paired worker/control ratios. The MMIO random-read
throughput interval is [0.925, 0.937], so its roughly 7% deficit remains clear.
PCI random-read CPU/GiB has a wide interval [0.956, 1.145], and further pairs
are needed there. Sequential worker throughput is higher in this run; that
does not compensate for random-I/O regressions or establish their cause.
The latency histogram still has finite bin width, even with a working clock.
Every paired observation and bootstrap interval is retained in
[windows-clock-block-long.json.gz](windows-clock-block-long.json.gz), with raw
artifacts under `target/performance/windows-block-long-46062103549`.

## Interleaved mapping-owner follow-up

All 88 boots completed: ten five-second measured pairs per variant and case,
with binary order rotated. Warm-ups remain in
the raw evidence. The frozen executables and guest assets match the preceding
short comparison. [region-owner-interleaved.json.gz](region-owner-interleaved.json.gz)
retains the predeclared order, provenance, paired results and confidence bounds.

For 64-KiB echo, candidate worker throughput improves 6.8% over the baseline
worker, with a paired 95% interval of +5.9–8.1%; CPU/GiB falls 7.2%
([−8.1%, −6.3%]). The control improves too: throughput rises 5.9% and CPU/GiB
falls 8.1%. Against that faster control, the candidate worker retains 99.0%
throughput, uses 102.9% CPU/GiB, and has a 105.6% p99 bound. These observations
do not establish parity or a latency improvement.

Block results remain inconclusive. The candidate worker's sequential-write
throughput changes by −4.9%, with an interval spanning −13.9% to +2.8%, while
the control becomes faster. Random-write and sequential-read worker intervals
also cross no change. The predeclared extension uses the same frozen
executables and retains all original observations.

All 44 extension boots completed, giving twenty block pairs per variant.
Worker random-read throughput increases 0.8% ([0.3%, 1.1%]), with CPU/GiB
falling 1.1% ([0.5%, 1.6%]). Sequential-write throughput remains uncertain:
95.1% of the prior worker, with a 95% interval [88.6%, 101.3%]; CPU/GiB is
106.9% ([98.8%, 115.8%]). The corresponding control throughput ratio is
99.6% ([96.2%, 106.5%]). The twenty-pair extension does not rule out a worker
regression, so the mapping-owner candidate remains separate. The network
benefit above does not excuse that uncertainty.
[region-owner-block-20.json.gz](region-owner-block-20.json.gz) retains the
extension plan, both sets of paired observations, combined intervals and
the comparison between revisions. No earlier observations were discarded.

Schedule inspection found an additional limitation in both local runs:
reversing revision order while choosing mode order from its position left
each revision with a fixed worker/control order. The bootstrap intervals do
not account for that possible ordering bias, including in the network result.
The common harness now rotates these factors independently and checks that
each revision/mode combination occupies every position over four pairs.

## Windows network measurements with the Hyper-V clock

[Run 46065767739](https://github.com/pichi-vm/dillo/actions/runs/46065767739)
completed 16 boots at `566ad5c`: three two-second measured pairs per transport,
plus warm-ups. Safe guest netlink setup brings up the named interface and
assigns its benchmark IPv4 address before timing; it is used only when the
kernel lacks IP autoconfiguration. All guests use the unmodified prebuilt WSL
kernel and `hyperv_clocksource_tsc_page`; only the intended network operation
is timed.

| Transport / message | Throughput ratio | CPU/GiB ratio | p99 ratio |
| --- | ---: | ---: | ---: |
| PCI / 64 B | 0.887 | 1.100 | 1.143 |
| PCI / 64 KiB | 0.938 | 1.063 | 1.588 |
| PCI-free MMIO / 64 B | 0.955 | 0.998 | 1.000 |
| PCI-free MMIO / 64 KiB | 0.959 | 1.035 | 1.478 |

These paired medians expose substantial network tail overhead that the former
coarse clock could not resolve. They are short diagnostic results, not parity
qualification. [windows-clock-network-short.json.gz](windows-clock-network-short.json.gz)
retains the clocks, source, asset hashes and paired observations. The longer
[ten-pair run](https://github.com/pichi-vm/dillo/actions/runs/46067542377) uses
the same source tree with corrected commit messages (`3525c2d`).

That ten-pair run completed all 44 boots. The longer paired medians are:

| Transport / message | Throughput ratio | CPU/GiB ratio | p99 ratio |
| --- | ---: | ---: | ---: |
| PCI / 64 B | 0.958 | 1.025 | 1.029 |
| PCI / 64 KiB | 0.953 | 1.043 | 1.263 |
| PCI-free MMIO / 64 B | 0.982 | 1.020 | 1.000 |
| PCI-free MMIO / 64 KiB | 0.963 | 1.032 | 1.298 |

The large-message p99 intervals are [1.232, 1.326] for PCI and
[1.272, 1.345] for MMIO: the tail deficit remains clear. Some throughput and
CPU bounds remain inconclusive at the 5% measurement band. These observations
use a different CI host from the short run and are not evidence of an intervening
optimization. [windows-clock-network-long.json.gz](windows-clock-network-long.json.gz)
retains all paired observations, intervals, clocks and exact asset provenance.

## macOS network stack profile

[Run 46066522027](https://github.com/pichi-vm/dillo/actions/runs/46066522027)
completed four PCI-free boots at `daa975a`, collecting ten successful
three-second process profiles during 64-KiB echo. This optimized symbolized
build is for attribution; stack counts include sleeping threads, and the
instrumented rates are not performance qualification.

The parent/child control receivers remain blocked during the captured steady
traffic. The data path includes pipe notification reads/writes, the stack's
socket I/O and per-frame `mio::Waker::wake` calls from `UserNetBackend::send`.
The latter wakes even when frames are already queued. A small candidate wakes
only when that queue becomes nonempty; the consumer drains under the same
lock, preserving a wake for later arrivals. Both execution modes receive the
change. It is undergoing same-host native comparisons before any performance
claim. [macos-network-stack-profile.json.gz](macos-network-stack-profile.json.gz)
records the exact source, artifact and individual stack-file hashes.

The first revision-comparison attempts are excluded from optimization evidence.
Mac run `46068691985` stopped before measurement when Bash could not create a
here-document temporary file; the helper now lives in `benchmarks/runtime.py`.
Arm run `46068695950` and Windows run `46068693741` completed, but their baseline
and candidate executable hashes were identical. Sharing Cargo's target directory
between worktrees reused the baseline executable for the candidate. Their raw
artifacts and logs are retained; the differing timings do not measure the code
change. Mac retry `46069476195` was cancelled after this flaw was identified.

The comparison fixture now gives the baseline a separate Cargo target directory
and refuses identical executables before timing. Source-level network checks
passed before the affected comparison builds; they are separate from the invalid
performance attribution.

The corrected [macOS](https://github.com/pichi-vm/dillo/actions/runs/46070400880),
[Arm](https://github.com/pichi-vm/dillo/actions/runs/46070402572) and
[Windows](https://github.com/pichi-vm/dillo/actions/runs/46070548856)
comparisons at `ecd59d6` all completed. Each ran 32 boots, with three
two-second measured pairs per transport and revision. The retained environment
records verify different Dillo executable hashes and identical guest assets
within each host. Native network checks passed before measurement.

On macOS, coalescing stack wakes improves large-echo worker throughput by
4.6% on PCI and 7.4% on MMIO; CPU/GiB falls 8.4% and 12.3%. The control also
improves, leaving worker CPU/GiB at 129.0% and 126.6% of control. Windows PCI
large-echo worker throughput rises 10.2%, with CPU/GiB falling 6.4%; its MMIO
throughput is nearly unchanged. Arm observations are mixed, including a
4.3% small-echo PCI throughput decrease. None establishes parity.

The baseline revision ran before the candidate, so these short observations
still include temporal host variation. A longer comparison will rotate both
revision and execution-mode order before deciding whether to keep the change.
[network-wake-native-short.json.gz](network-wake-native-short.json.gz) retains
all paired results, revision comparisons, executable and guest hashes, and
artifact provenance, including the unfavorable observations.

## Latency measurement precision

The existing histogram's upper bounds can exceed a sample by 6.25%, which is
too coarse to resolve a close comparison at the plan's 5% decision band. The
guest probe now uses 64 subdivisions instead of 16, bounding that excess at
1.5625%. Storage remains fixed, increasing from 8 to 32 KiB per histogram;
there is no allocation per observation or change to the report fields.
The percentile, boundary and merge check passes with the finer bins. Earlier
measurements retain their original precision; only results using the updated
probe can support the finer bounds.

## Bounded receive batches on physical x86

Candidate `9664cd2` retains a pending RX frame in its existing scratch buffer
and drains up to 64 immediately available user-network frames per interrupt.
It signals completed work before waiting for guest buffers or reaching the
host pause checkpoint; a single frame does not wait for a batch to fill.
Other backends retain their existing receive behavior. The focused fixture
checks a lone frame, a burst, the batch limit and a temporarily starved ring.
All 57 network unit tests and strict Clippy pass; four external-network cases
remain ignored as before. Both execution modes use the same implementation.

Apollo completed 40 boots against `0adf801`: four measured two-second pairs
per case/revision, plus warm-ups, on CPUs 24–27. The predeclared schedule
balances binary and execution-mode order independently. Executables are
frozen from separate build directories and share identical guest assets,
including the finer latency histogram. Both transports have separate images;
the MMIO image has no PCI bridge.

Large-echo worker throughput increases 37.8% over PCI and 13.2% over MMIO;
CPU/GiB falls 24.2% and 9.0%, and p99 bounds fall 24.5% and 16.4%. The control
also improves: its throughput rises 38.9% and 12.5%. Candidate worker/control
throughput is 99.1%/99.4%, CPU/GiB 101.5%/101.3%, and p99 103.9%/101.8%.
These short results support further native measurement, not a parity claim.

Small-echo worker throughput changes by −1.4% on PCI and −0.6% on MMIO;
the control changes by +12.7% and +0.9%. The MMIO candidate still uses 4.4%
more CPU/GiB than its control. Retain these mixed observations rather than
claiming the large-message improvement applies everywhere.
[network-rx-batch-local-short.json.gz](network-rx-batch-local-short.json.gz)
contains the plan, absolute and paired observations, environments and hashes
of all boot results; raw records remain under `target/performance/net-rx`.

## Balanced native wake comparison

The [macOS](https://github.com/pichi-vm/dillo/actions/runs/46072891282),
[Linux Arm](https://github.com/pichi-vm/dillo/actions/runs/46072894382) and
[Windows](https://github.com/pichi-vm/dillo/actions/runs/46072897621) runs each
completed 104 boots: twelve five-second pairs per transport and revision,
plus warm-ups. Revision and execution-mode order rotate independently, with
each combination occupying every position three times. Baseline `3525c2d`
and candidate `0adf801` have different executable hashes and identical guest
assets on each host. Wake coalescing is their only Dillo runtime difference;
the finer histogram runs in the common guest probe.

macOS large-message worker throughput improves 5.4% on PCI and 5.1% on MMIO,
while CPU/GiB falls 9.6% and 9.0%. Both improvements exclude no change in the
paired 95% intervals. The control improves too; worker CPU/GiB still exceeds
it by 27.2% and 26.4%. Small-message performance is essentially unchanged.

Linux Arm PCI large-message worker throughput regresses 5.2%, with a paired
95% interval of -7.9% to -2.0%; the control regresses 5.5%. Worker CPU/GiB
rises 4.3% and p99 rises 8.3%, also excluding no change. The MMIO observations
are mixed. Restore Linux's previous per-frame wake behavior rather than keep
a regression because another platform benefits. This is a measured policy
choice, not a demonstrated explanation of the scheduler or kernel mechanism.

Windows MMIO large-message throughput improves 1.8% for the worker
([0.7%, 2.3%]) and 1.0% for the control ([0.3%, 2.2%]). The earlier short-run
PCI improvement does not reproduce: its worker throughput ratio is 99.7%
([97.7%, 100.6%]). Worker/control large-message p99 remains 127.1% on PCI
and 126.7% on MMIO. Neither these results nor the macOS improvements establish
parity. Coalescing remains enabled on the non-Linux paths for further
integrated qualification.

[network-wake-native-balanced.json.gz](network-wake-native-balanced.json.gz)
retains all comparisons, absolute results, confidence bounds, predeclared
orders, environments, artifact digests and hashes of every boot record.

## Receive-header reuse comparison

Apollo completed another 40 boots, comparing `73201a6` with `9664cd2` using
four independently balanced two-second pairs per case and identical guest
assets. Both have RX scratch reuse and batching; the candidate also reserves
the virtio header in that scratch, removing the remaining per-frame header
allocation and copy. All 57 network unit tests and strict Clippy pass.

The short observations do not establish a performance benefit. PCI large
echo throughput rises 1.9% for the worker and 2.3% for the control, while
MMIO is nearly unchanged. PCI small echo falls 5.8% for the worker and 2.0%
for the control, with worker CPU/GiB rising 6.9%. Four pairs cannot establish
confidence bounds, and fewer source-level copies do not prove faster I/O.
The combined RX changes remain under native comparison before acceptance.
[network-rx-header-local-short.json.gz](network-rx-header-local-short.json.gz)
retains both favorable and unfavorable observations with their full schedule
and source/binary provenance.

## Native receive-path comparison

Runs [46076484267](https://github.com/pichi-vm/dillo/actions/runs/46076484267)
(macOS), [46076702385](https://github.com/pichi-vm/dillo/actions/runs/46076702385)
(Linux Arm), and [46076703994](https://github.com/pichi-vm/dillo/actions/runs/46076703994)
(Windows) compare `73201a6` with `0adf801`. The candidate combines scratch
reuse, bounded receive batching and header reuse. Each run completed 40 boots:
four independently balanced two-second pairs per case/revision, plus warm-ups.
All boots returned zero. Executable hashes differ; guest assets match. Windows
uses the unmodified prebuilt WSL kernel with its Hyper-V clock. These short
comparisons have no confidence intervals and do not qualify parity.

Large-message worker throughput improves 11.1%/11.3% on macOS PCI/MMIO, with
CPU/GiB falling 24.9%/22.2%. The control improves more in throughput, leaving
worker/control ratios at 93.5%/94.8%; CPU/GiB remains 115.8%/113.9% of control.
Retained process samples put large-message PCI user CPU at about 1.05 cores
in both modes, but system CPU at 0.58 for the worker tree versus 0.45 locally.
MMIO shows the same pattern (1.07/1.06 user, 0.57/0.46 system). This narrows
the residual-cost investigation without identifying a particular syscall.

Linux Arm large-message throughput improves 7.7%/37.6% on PCI/MMIO, against
0.4%/17.1% control gains. Worker/control throughput is 97.7%/99.4%, CPU/GiB
104.2%/98.6%, and p99 96.4%/105.8%. Both revisions still have Linux wake
coalescing; these results do not qualify its later restoration in `7b218d9`.

Windows PCI large-message throughput rises 125.1% for the worker and 120.3%
for the control; CPU/GiB falls 59.3%/58.0%. The resulting worker/control
throughput is 96.9%, CPU/GiB 102.4%, and p99 133.4%. MMIO throughput improves
4.8%/4.9%, leaving worker/control throughput at 97.7% and p99 at 137.6%.
The tail-latency deficit therefore remains despite the absolute speedup.
Small-message results are mixed and remain in the complete data, rather than
being hidden by the larger gains.

[network-rx-native-short.json.gz](network-rx-native-short.json.gz) retains
absolute values, paired ratios, schedules, environments, artifact digests,
every boot-record hash and the macOS process CPU decomposition. The subsequent
Unix partial-counter cancellation correction is not part of these runs.

## Cancellable partial pipe notifications

`4c13db5` removes an uncancellable `read_exact` after a short pipe read.
The receiver retains incomplete words while continuing to watch its separate
cancellation pipe; cancellation does not discard the fragment. A regression
fixture verifies cancellation and later completion, and closes the external
writer on timeout so cleanup cannot wait indefinitely for the missing bytes.
Local notification tests, strict Clippy and formatting passed.

Native macOS [run 46079568134](https://github.com/pichi-vm/dillo/actions/runs/46079568134)
passed the notification and network tests, then completed all 40 boots in a
balanced four-pair/two-second comparison with `73201a6`. Worker throughput
changes range from -0.1% to +0.9%, and CPU/GiB from -0.8% to +0.1%; this short
run does not establish equivalence or a latency benefit. The correctness fix
is retained on its own merits. Source identities, hashes, raw-record digests,
full ratios and the schedule are in
[notification-cancellation-macos-short.json.gz](notification-cancellation-macos-short.json.gz).

## Linux Arm wake restoration and cancellation follow-up

[Run 46079569774](https://github.com/pichi-vm/dillo/actions/runs/46079569774)
compares `4c13db5` with `73201a6`: the Linux per-frame wake restoration and
cancellable notification reader together. Native lifecycle, notification and
network checks passed, followed by 40 successful boots. Four two-second pairs
per case/revision balance binary and execution-mode order independently.
Executable hashes differ and guest assets match.

The latest worker/control PCI throughput is 96.2% for small echo and 93.5%
for large echo; CPU/GiB is 105.9%/106.7%, and p99 is 106.4%/109.9%. MMIO
throughput is 106.1%/95.6%, CPU/GiB 94.0%/109.2%, and p99 101.2%/107.1%.
Large-message worker throughput changes by +0.5%/+1.1% against the previous
binary, while its control changes by +1.0%/+2.7%. These short, mixed results
do not establish equivalence or isolate either change's effect. They remain
part of qualification rather than being replaced by the more favorable
earlier snapshot. Full observations, schedule and provenance are retained in
[notification-cancellation-arm-short.json.gz](notification-cancellation-arm-short.json.gz).

## macOS unused notification watcher experiment

`003f32a` delays kqueue registration until a receiver first reads. Exported
queue endpoints retain an unused parent receiver; this avoids registering
that receiver alongside the worker that actually waits. Cancellation and
partial-word state remain local to each receiver.

[Run 46081837796](https://github.com/pichi-vm/dillo/actions/runs/46081837796)
passed native notification/network checks and all 40 boots against `4c13db5`.
Four two-second pairs per case/revision balance order independently, with
different executables and identical guest assets. Worker throughput changes
range from +0.1% to +0.6%, and CPU/GiB from -1.2% to 0.0%. p99 changes are
mixed. These short observations do not establish a performance benefit; the
candidate remains outside the integrated branch. No descriptor-count or
private-memory reduction was measured.

The earlier run `46080767960` passed its native checks but could not fetch the
abbreviated baseline `4c13db5`. It produced no comparison. The corrected run
uses the full SHA without runner or confinement changes. Full successful-run
observations and provenance are in
[macos-lazy-watcher-short.json.gz](macos-lazy-watcher-short.json.gz).

## Longer x86 comparison rejects Linux-wide per-frame wakes

Apollo completed all 104 boots comparing `0c7c8bc` with `73201a6`: twelve
five-second pairs per transport/revision, plus warm-ups, on CPUs 24–27 with
no concurrent local compilation. Each binary/mode combination occupies each
execution position three times. Different frozen executables share the same
guest assets. The runtime changes are Linux's per-frame wake restoration and
the Unix partial-notification cancellation fix; KVM uses eventfd notifications.

Large-message worker throughput falls to 90.1% of the preceding binary on
PCI (95% interval 89.3–90.3%) and 93.8% on MMIO (93.2–94.3%). CPU/GiB rises
18.5%/11.6%, and p99 bounds rise 11.5%/7.1%. The control also slows: its
throughput ratios are 91.3%/94.2%. Restore wake coalescing on Linux x86 and
keep the per-frame policy confined to Linux Arm, where the earlier balanced
comparison supported it. The current Arm/RX composition still needs longer
qualification; this result cannot establish its optimal wake policy.

The rejected x86 candidate also remains below its same-revision control for
large-message throughput: 97.9% on PCI and 98.7% on MMIO, with CPU/GiB at
102.7%/102.5%. These smaller differences require calibrated noise before being
classified as residual costs. Full paired observations, intervals, schedule and
source/asset provenance are retained in
[network-integrated-x86-long.json.gz](network-integrated-x86-long.json.gz).

## Available-ring notification suppression

The network candidate `a7c0d20` checks the driver's standard NO_INTERRUPT flag
after publishing a batch. Unreadable flags preserve notification, and the
existing publication barrier orders the check. This does not negotiate
EVENT_IDX or change the worker protocol.

[Arm run 46082171694](https://github.com/pichi-vm/dillo/actions/runs/46082171694)
and [Windows run 46082174187](https://github.com/pichi-vm/dillo/actions/runs/46082174187)
passed their native checks and all 40 boots each against `4c13db5`. Each uses
four independently balanced two-second pairs with matching guest assets.
Arm large-message worker throughput changes by +0.5% on PCI and -1.6% on
MMIO; its PCI worker/control ratio is 91.1%, with CPU/GiB at 112.4% and p99
at 118.9%. Windows MMIO large-message throughput improves 7.4%, but its
control improves 8.1%; worker/control remains 98.0%, with p99 at 133.6%.
Windows PCI small-message CPU/GiB increases 4.7% against the baseline worker.
These mixed short results do not establish an overall benefit or parity.
The candidate remains outside the integrated branch. Full paired observations,
including small-message and unfavorable results, are retained in
[network-notification-suppression-short.json.gz](network-notification-suppression-short.json.gz).

## macOS shared-status call coalescing

[Run 46082983918](https://github.com/pichi-vm/dillo/actions/runs/46082983918)
compares `9d53cc9` with `4c13db5` using four balanced two-second pairs of
PCI-free block and network operations. All 40 boots and native notification
checks pass. The candidate publishes the used bit in shared host-only memory,
coalesces calls until guest ACK, and retains parent-side HVF injection. The
relay delivers already-published status without reasserting it after an ACK.

Block worker throughput changes range from -1.9% to 0.0% against the baseline;
worker/control throughput remains 89.3–92.2%. Large-message network throughput
improves 1.6%, while the control improves 1.0%; worker/control is 95.2%, with
CPU/GiB at 112.0% and p99 at 107.4%. Small-message results do not improve.
The added path has not demonstrated enough benefit to integrate. Pipe
notification and native injection costs remain; no interrupt-count attribution
is established by these rates. All observations and provenance are retained in
[macos-mmio-call-coalescing-short.json.gz](macos-mmio-call-coalescing-short.json.gz).

## Physical x86 suppression follow-up

`d0c2412` completed 40 boots against `d13eadd`, with wake coalescing restored
in both binaries. The four-pair/two-second schedule independently balances
revision and execution mode on CPUs 24–27; frozen executables differ and guest
assets match. No local compilation ran during measurement.

Large-message MMIO throughput improves 10.9% for the worker and 11.6% for its
control; worker/control remains 99.2%, with CPU/GiB at 101.2%. PCI large-message
throughput is nearly unchanged. PCI small-message worker throughput falls
6.5%, while its control improves 1.5%; worker CPU/GiB rises 9.5%. These short
results therefore do not justify promoting suppression as a universal
optimization. The next diagnostic counts actual queue completions and calls
to distinguish notification savings from the added available-flag reads.
[network-suppression-x86-short.json.gz](network-suppression-x86-short.json.gz)
retains every paired observation, executable hash and boot-record digest.

## Counting network notification requests

The diagnostic-only `f2e403a` build reports queue frames, drains, notification
requests, suppression decisions and RX buffer shortages once at shutdown.
There is no per-request logging or atomic counter. Counts cover the boot and
both echo sizes; they precede transport-level coalescing and must not be read
as native interrupt or syscall counts. Instrumented rates are not qualification.

Apollo and native runs [46085384776](https://github.com/pichi-vm/dillo/actions/runs/46085384776)
(macOS), [46085386462](https://github.com/pichi-vm/dillo/actions/runs/46085386462)
(Arm), and [46085388161](https://github.com/pichi-vm/dillo/actions/runs/46085388161)
(Windows) each complete 12 boots: two one-second pairs per transport plus
warm-ups. No run reports RX buffer starvation. Worker batches average roughly
six to eight frames. The available flag suppresses only 0.5–2.7% of eligible
TX batches on Linux/macOS, and 9–11% on Windows. RX suppression is 7–17% except
Linux x86 MMIO at 30%. Thus most batches still request notification; the
standard EVENT_IDX mechanism is the next candidate to measure.

[network-notification-counters.json.gz](network-notification-counters.json.gz)
retains every counter record, schedule, asset hash and boot digest. The
uninstrumented source and prior unfavorable performance evidence remain intact.

## Negotiated EVENT_IDX network experiment

`830ba5e` negotiates the standard split-ring EVENT_IDX feature for network
queues and checks the driver's used-event threshold after publication. Both
binaries retain the same diagnostic counters. Apollo and native runs
[macOS 46086224330](https://github.com/pichi-vm/dillo/actions/runs/46086224330),
[Arm 46086225913](https://github.com/pichi-vm/dillo/actions/runs/46086225913), and
[Windows 46086227779](https://github.com/pichi-vm/dillo/actions/runs/46086227779)
each complete all 40 boots against `f2e403a`: four independently balanced
two-second pairs per revision and transport. Executable hashes differ, guest
assets match, the candidate reports EVENT_IDX enabled in every queue, and no
run reports RX buffer starvation. Local queue/network tests and strict Clippy
passed; native workflow checks passed before measurement.

The effects vary by platform. On macOS, large-message worker CPU/GiB falls
3.4% on PCI and 2.5% on MMIO, with throughput nearly unchanged. Windows gains
4.6%/6.6% large-message throughput and reduces CPU/GiB by 6.3%/6.8%; its
worker/control p99 ratios still reach 146.9%/135.0%. Arm loses 7.3% large-message
PCI throughput and 8.3% small-message MMIO throughput. Physical x86 results
are mixed, including a 1.9% small-message PCI throughput reduction. These
short, instrumented observations do not justify promoting the feature as a
general optimization or establish parity.

RX notification-request suppression rises on Windows from about 16–17% to
26–32%, and on macOS from 8–9% to about 14–15%. Most batches still request a
notification. These are queue requests before transport coalescing, not
native interrupt counts. The candidate stays separate. All 160 boot records,
counter observations, paired ratios, schedules and artifact provenance are
retained in [network-event-index-short.json.gz](network-event-index-short.json.gz).

## Reusing the network transmit buffer

`06e7517` gives each TX worker one scratch buffer and borrows the assembled
frame when calling its backend. This removes per-descriptor allocation and
two intermediate copies; the user-network backend still owns its queued
frame. It changes neither public interfaces nor notification policy. The
existing TX fixture now also checks a shorter subsequent frame, a header split
across descriptors, and a header-only frame. All 57 local network tests and
strict Clippy pass; four external-network tests remain ignored.

Physical x86 and native [macOS](https://github.com/pichi-vm/dillo/actions/runs/46087385999),
[Arm](https://github.com/pichi-vm/dillo/actions/runs/46087693165), and
[Windows](https://github.com/pichi-vm/dillo/actions/runs/46088042390) comparisons
each completed 40 boots: four balanced two-second pairs per revision and
transport plus warm-ups. Baselines are `aa9bbff` (native) and its unchanged
runtime `d13eadd` (local); the candidate and baseline use identical guest assets.
These are short, uninstrumented comparisons, not parity qualification.

On x86, large-message worker CPU/GiB falls 5.8% on PCI and 4.8% on MMIO. On
macOS it falls 5.3%/5.7%, while throughput rises about 2%; its control also
improves and the isolation gap remains. Windows large-message PCI CPU/GiB
falls 3.3%, but MMIO rises 0.9%. Arm is mixed: large-message PCI worker
throughput rises 4.7%, while MMIO falls 2.2%; small-message MMIO falls 4.5%.
The Arm control also moves substantially in opposite directions between
transports. Longer balanced comparisons are required before promotion. All
observations, including unfavorable results, are retained in
[network-tx-scratch-short.json.gz](network-tx-scratch-short.json.gz).

## macOS scheduling diagnostic

[Run 46089105144](https://github.com/pichi-vm/dillo/actions/runs/46089105144)
completed eight boots at `1681340`, with unchanged production runtime and five
`ps -M` observations during each large-message phase. Every captured thread
reports priority `20T`, in both execution modes and transports. This does not
support a thread-priority mismatch as the explanation for the observed cost.
It does not measure QoS class or performance/efficiency-core placement, and
the instrumented rates are not performance qualification. No scheduling
policy was changed. All 40 snapshots and provenance are retained in
[macos-thread-priorities.json.gz](macos-thread-priorities.json.gz).

## Longer physical x86 transmit comparison

The twelve-pair, five-second comparison of `06e7517` against `d13eadd`
completed all 104 boots on CPUs 24–27, without concurrent local compilation.
For large messages, worker throughput rises 2.8% on PCI and 3.4% on MMIO;
paired 95% intervals are +0.6–3.4% and +2.9–3.6%. CPU/GiB falls 7.3%/5.8%,
and p99 bounds fall 5.1%/3.1%. The small-message estimates remain uncertain.
The larger follow-up supports an improvement in the common TX path, while
retaining the uncertainty in the other comparisons.

Against its equally optimized control, large-message PCI still retains
97.6% throughput (95% interval 96.3–99.6%), uses 102.8% CPU/GiB and has a
102.4% p99 bound. Large-message MMIO is closer at 100.3% throughput and
100.3% CPU/GiB, but these intervals do not establish the full milestone.
An eight-pair extension is running to retain twenty observations where the
twelve-pair estimates remain inconclusive. The recorded dirty flags identify
only Python analysis bytecode; Rust source and frozen binaries were unchanged.
All observations, schedule, hashes and intervals are retained in
[network-tx-scratch-x86-long.json.gz](network-tx-scratch-x86-long.json.gz).

## Native macOS wake primitive probe

[Run 46090539469](https://github.com/pichi-vm/dillo/actions/runs/46090539469)
at `9928e4e` compares six alternating pairs of blocking-pipe and shared-futex
ping-pong between two native processes. Each trial warms up for 1,000 exchanges
then times 100,000. The futex uses two different virtual addresses for the same
file-backed page, lock-free aligned atomic words, and Apple's public shared
wait/wake flags. Every child exits successfully. Its median paired round-trip
cost is 38.5% higher than the blocking pipe, and total process-tree CPU is
51.7% higher. The CPU observation includes warm-up and process lifetime costs.

This is a primitive probe, with no guest, sandbox, vhost-user or native interrupt
injection. Dillo's current notification reader also uses kqueue for cancellable
readiness; a follow-up includes that additional operation before drawing an
implementation conclusion. No notification or protocol change has been made.
The complete observations and provenance are in
[macos-native-wake.json](macos-native-wake.json).

The follow-up [run 46090753159](https://github.com/pichi-vm/dillo/actions/runs/46090753159)
at `1c4e901` adds persistent kqueue read readiness before each pipe receive.
Six trials rotate all three methods through each execution position equally.
Median round-trip times are 3.10 microseconds for the blocking pipe, 3.62 for
pipe plus kqueue, and 4.40 for the shared futex. Paired against pipe plus
kqueue, the futex costs 22.3% more round-trip time and 31.1% more total CPU.
This probe does not reproduce Dillo's cancellation registration, batching or
sandbox. It supplies no evidence to justify a new shared-memory notification
endpoint or negotiated protocol extension. The existing pipe path is retained;
all 18 observations are in [macos-native-wake-kqueue.json](macos-native-wake-kqueue.json).

## Twenty-pair x86 transmit comparison

The prespecified eight-pair extension of `06e7517` completed successfully.
Together with the original twelve pairs, this retains all 176 boots, including
both warm-up sets. Both batches used identical frozen executables and guest
assets, five-second operations and CPUs 24–27, without concurrent compilation.
Large-message worker throughput improves 2.6% on PCI and 3.3% on MMIO versus
the prior worker; paired 95% intervals are +0.6–3.0% and +2.9–3.5%. CPU/GiB
falls 7.0%/5.8%, and p99 bounds fall 4.6%/3.1%. Small-message throughput changes
remain inconclusive.

The equally optimized control still matters. Large-message PCI worker/control
throughput is 97.3% (96.6–98.8%), CPU/GiB is 102.8% (102.0–103.6%), and p99 is
102.4% (101.2–103.1%). MMIO throughput is 99.8% (98.9–100.3%) and CPU/GiB is
100.8% (100.1–101.8%). These differences require noise calibration; parity
within measured noise satisfies the clarified target. Both batches and
their combined estimates are in
[network-tx-scratch-x86-twenty.json.gz](network-tx-scratch-x86-twenty.json.gz).

## Longer Arm transmit comparison

[Run 46089194689](https://github.com/pichi-vm/dillo/actions/runs/46089194689)
completed all 104 boots at `06e7517` against `aa9bbff`: twelve balanced
five-second pairs per transport/revision plus warm-ups. Native lifecycle and
network checks passed, executable hashes differ, and guest assets match within
the comparison. Every PCI-free guest report contains no PCI devices. These are
physical Arm KVM results, separate from the x86 series.

The longer run contains an unfavorable observation: large-message PCI worker
throughput is 4.6% lower than the prior worker (95% interval −6.3% to −1.0%),
and its p99 bound is 9.3% higher (+0.3–23.1%). MMIO CPU/GiB is 2.3% lower
(−5.5% to −1.1%), but its throughput change and p99 change remain uncertain.
Against its optimized control, large-message worker throughput is 90.8% on
PCI and 95.3% on MMIO; CPU/GiB is 112.8%/109.7%. The four-pair results did not
establish these effects. The candidate remains separate rather than promoting
the x86 gains across all platforms. All observations, intervals, hashes and
run provenance are retained in
[network-tx-scratch-arm-long.json.gz](network-tx-scratch-arm-long.json.gz).

These observations do not establish that the code caused the difference.
Three successive balanced four-pair blocks show throughput changes of −5.6%,
−6.9% and +0.8%; the earlier four-pair experiment showed +4.7%. The original
interval resamples individual pairs and does not account for dependence across
time. A post-hoc block-resampling sensitivity check includes zero, but with
only three blocks it is not a replacement qualification or proof of runner
noise. The Arm runner is self-hosted bare metal; exclusive host/CPU reservation
and per-phase contention/frequency evidence are absent. An A/A comparison of
the same executable is needed to calibrate noise before attributing these
small differences to implementation. The candidate remains unpromoted because
its effect is unresolved, not because a regression has been established.
[arm-tx-order-sensitivity.json](arm-tx-order-sensitivity.json) preserves the
original estimate and the sensitivity calculation.

## Longer macOS and Windows transmit comparisons

[macOS run 46090968077](https://github.com/pichi-vm/dillo/actions/runs/46090968077)
and [Windows run 46090537665](https://github.com/pichi-vm/dillo/actions/runs/46090537665)
each completed all 104 boots at `06e7517` against `aa9bbff`, using twelve
balanced five-second pairs per transport/revision. Both retain matched guest
assets and successful PCI-free assertions. Windows uses the existing prebuilt
WSL clock diagnostic kernel and native MSVC executable. These are observations
pending noise calibration, not causal attribution or milestone qualification.

On macOS, large-message worker throughput is 2.9%/2.7% higher on PCI/MMIO than
the prior worker; CPU/GiB is 6.8% lower on both. Against the equally optimized
control, however, throughput is 94.0%/95.6%, CPU/GiB is 116.4%/114.8%, and p99
is 108.2%/106.9%. The common allocation reduction does not remove those gaps.

On Windows, large-message worker throughput changes +1.5%/−0.7% versus the
prior worker; CPU/GiB changes remain inconclusive. Worker/control throughput
is 96.3%/96.9%, CPU/GiB is 102.1%/101.9%, and p99 is 136.5%/133.5%. No
cross-platform promotion follows from these results. Full observations,
intervals, execution order and artifact provenance are retained in
[network-tx-scratch-macos-long.json.gz](network-tx-scratch-macos-long.json.gz)
and [network-tx-scratch-windows-long.json.gz](network-tx-scratch-windows-long.json.gz).

## KVM resampler lifetime and failure reporting

The experimental wired binding now attempts native irqfd deassignment before
waking and joining its resampler, and attempts both cleanup stages on error.
Asynchronous resampler errors and panics notify the existing worker supervisor;
the original error is also retained for join. The callback uses the existing
weak session owner without taking the worker lifecycle barrier. The benchmark
in-process control has no such observer and retains join-time reporting.

Native x86 and [Arm run 46092675530](https://github.com/pichi-vm/dillo/actions/runs/46092675530)
pass the level/ACK/reassertion/stale-export checks at `0f0bfb6`, which includes
the preceding retirement correction `4390fea`. Focused checks cover error and
panic notification before join and normal shutdown without a failure. Related
MMIO/worker compilation, library checks and strict Clippy pass locally. The
Arm run also completes four PCI-free block smoke boots. This is correctness
evidence; the one-second smoke schedule does not qualify performance.
[kvm-resampler-lifecycle.json](kvm-resampler-lifecycle.json) retains the exact
source, native job evidence and boot hashes. Shared-status interoperability,
concurrent ACK/reset qualification and WHP level/EOI behavior remain open.

## WHP level-triggered EOI boundary

[Native run 46095825972](https://github.com/pichi-vm/dillo/actions/runs/46095825972)
at `a84e4b0` passes a protected-mode guest probe for both edge and level
triggers. The guest accepts vector 0x41, increments a memory counter and
writes LAPIC EOI. Only level delivery returns the documented
[APIC EOI exit](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/apiceoi),
with the matching vector; resuming reaches the following guest completion
marker. Both cases record exactly one handler entry. Existing native trigger
retirement checks and four PCI-free block smoke boots also pass.

This establishes the native exit mechanism, not a complete IOAPIC level,
remote-IRR, concurrent ACK or reset implementation. Production still uses the
existing edge-injecting path. The new fixture changes no production API or
delivery policy. The initial probe build failed the unsafe-code lint before
execution; the correction scopes the existing native-test allowance to this
function. [whp-level-eoi-probe.json](whp-level-eoi-probe.json) records both runs
and the successful artifact provenance. These smoke timings are not parity
evidence.

## Identical-binary network calibration

The local x86 run, [Arm run 46094858600](https://github.com/pichi-vm/dillo/actions/runs/46094858600)
and [macOS run 46094860785](https://github.com/pichi-vm/dillo/actions/runs/46094860785)
each completed 104 boots: twelve balanced five-second pairs per transport,
plus warm-ups. Both comparison labels use the same executable path, hash and
guest assets. All four label/mode combinations occupy each schedule position
equally. Like-mode comparisons below therefore measure variation without a
code change; worker/control comparisons still measure real isolation costs.
The calibration source is `8e8e5b4`, with runtime equivalent to `06e7517`.

For Arm's large PCI echo, identical workers show an apparent 3.3% throughput
loss and 6.7% p99 increase. Ordinary paired intervals are [−6.1%, +3.0%] and
[+1.0%, +20.7%]. Even the latter excludes zero despite identical code: pair
resampling does not account for temporal dependence. This undermines attributing
the prior observed 4.6% throughput loss to the TX change. It does not identify
the environmental cause or prove that every Arm difference is noise.

On x86, identical workers show a 5.5% small-PCI throughput difference, with an
interval spanning [−8.0%, +3.0%]. Large-message PCI/MMIO throughput differences
are +0.6%/−0.3%, with intervals [−1.1%, +3.0%]/[−0.9%, +0.6%]. macOS throughput
and CPU/GiB calibration intervals stay within about 0.7% of unity; p99 varies
more. The previously observed macOS 14.8–16.4% CPU/GiB overhead remains much
larger than that calibration. A single tolerance cannot describe every host
or metric, and these network results do not calibrate storage workloads.

There is no exclusive-host claim. In particular, the local host also had an
unrelated long-lived VM; its ownership and state were left untouched. Full
paired results, temporal block medians, schedules, hashes and provenance are in
[network-noise-x86.json.gz](network-noise-x86.json.gz),
[network-noise-arm.json.gz](network-noise-arm.json.gz) and
[network-noise-macos.json.gz](network-noise-macos.json.gz). No discarded samples
or rerun-until-success qualification is used, and no full platform/transport
qualification follows from this
network-only calibration.

[Windows run 46094862882](https://github.com/pichi-vm/dillo/actions/runs/46094862882)
also completed all 104 boots with identical binaries/assets and the same
balanced schedule. Bulk worker throughput differences are −1.2%/+0.4% for
PCI/MMIO, with intervals [−1.8%, +1.1%]/[−2.4%, +3.8%]. CPU/GiB intervals are
wider, within roughly ±5%. PCI bulk p99 varies substantially: an apparent
+5.0% change has interval [−5.8%, +13.5%]. This does not explain the entire
previous 33–37% worker/control p99 gap. The clock remains the unmodified
prebuilt WSL kernel's Hyper-V clock. All observations and artifact provenance
are retained in [network-noise-windows.json.gz](network-noise-windows.json.gz).

## Remaining host-user work

Eight local boots at `8a8233d` retain optimized, symbolized host-user cycle
profiles for large TCP echo. All guests and profile commands succeed; the
reports record no lost samples. In the measured pair, region construction
and destruction together account for about 26–30% of worker samples and
30–33% of control samples across MMIO/PCI. This is substantial common work,
not an attribution of isolation overhead or total CPU including kernel/guest.
It supports revisiting the existing small `219fa22` ownership experiment,
whose earlier storage comparison had ordering bias, rather than adding a new
mechanism for the same cost. Profiled rates do not qualify performance.
[network-user-profile-x86.json.gz](network-user-profile-x86.json.gz) retains
all eight reports, phase windows, result records and raw-file hashes.

[Arm run 46098122194](https://github.com/pichi-vm/dillo/actions/runs/46098122194)
at `f29b960` completes the same eight-boot diagnostic. Region construction and
destruction account for about 28–30% of worker samples and 27% of control
samples in the measured pair. Atomic helpers and mapped-slice lookup are also
prominent, but leaf samples do not identify their callers. Unresolved and
guest/kernel-tagged addresses remain unassigned; this is not a complete CPU
cost decomposition. The first attempt stopped before measurement because
`perf` was absent; job-local tool provisioning resolved that without changing
host permissions. All successful reports, observations, hashes and both run
identities are in [network-user-profile-arm.json.gz](network-user-profile-arm.json.gz).

The existing 16-line mapping-owner change is replayed as `ab4c264` against
`ad6ac6a`, with no other runtime changes. All 51 memory/virtqueue tests and
strict Clippy pass. Its prespecified comparison uses independent revision/mode
rotation, five-second operations and twelve pairs. Local x86 first calibrates
PCI-free block noise, then compares that storage case and both network
transports; native macOS/Windows compare PCI-free block and network. This
replaces the earlier confounded ordering, retaining that earlier evidence.
Neither the profiles nor an unfinished comparison justify promotion.

## macOS CPU accounting split

Reanalysis of the 48 measured candidate boots in run 46090968077 uses the
original phase samples and byte rates; it is not another experiment. For
64-KiB echo, the median paired worker overhead is 0.73/0.68 CPU seconds per GiB
on PCI/MMIO. The OS-reported system-time component adds 0.50/0.44 seconds,
about two-thirds of that overhead. The remaining component is user time.
Parent accounting includes vCPU execution; these counters do not distinguish
IPC, wakeups, sandbox checks or individual syscalls. They support investigating
native-call and scheduling costs alongside the common allocation work, without
attributing all overhead to a sampled user-space function.

The analyzer now retains both components. Recomputing all four identical-binary
calibrations verifies that user plus system time reproduces the existing total
for all 768 measured operations. Paired components, intervals, provenance and
input hashes are retained in [network-macos-cpu-split.json.gz](network-macos-cpu-split.json.gz).

## Calibrated network status

These are the completed identical-binary calibrations at runtime `06e7517`,
excluding the pending mapping-owner and Windows socket changes. Within each
balanced round, combine both identical labels' worker/control ratios by their
geometric mean, then report the median of twelve rounds. No label is selected
or discarded. All primary sizes, round values, temporal blocks, calibrations
and source hashes are retained in
[network-calibrated-status.json.gz](network-calibrated-status.json.gz).

For 64-KiB TCP echo, 100% is the equally optimized in-process control. Higher
throughput is better; lower CPU/GiB and p99 are better. These descriptive noise
assessments do not establish whole-platform or storage qualification.

| Platform / architecture | Transport | Throughput | CPU/GiB | p99 | Remaining gap relative to calibration |
| --- | --- | ---: | ---: | ---: | --- |
| Linux x86-64 | PCI | 98.1% | 102.4% | 101.9% | Small CPU excess; throughput/tail borderline |
| Linux x86-64 | PCI-free MMIO | 99.4% | 101.5% | 101.4% | No clearly established bulk gap |
| Linux AArch64 | PCI | 93.6% | 109.7% | 111.6% | CPU excess; throughput borderline, tail noisy |
| Linux AArch64 | PCI-free MMIO | 97.2% | 106.8% | 100.9% | CPU unresolved because of drift |
| macOS AArch64 | PCI | 93.9% | 116.7% | 108.6% | All three |
| macOS AArch64 | PCI-free MMIO | 95.5% | 114.8% | 107.3% | All three |
| Windows x86-64 | PCI | 95.6% | 103.1% | 131.6% | Tail latency clearly; throughput unresolved |
| Windows x86-64 | PCI-free MMIO | 98.0% | 102.0% | 133.1% | Tail latency clearly |

The 64-byte cases also leave clear macOS gaps: roughly 2–4% less throughput,
12–18% more CPU and 6–7% worse p99. Linux/Windows differences are mostly within
noise or borderline; x86 MMIO retains a small CPU excess. Borderline remains
unresolved, not a pass or an established regression caused by a code change.

## Physical x86 storage calibration

The prespecified PCI-free block calibration completed all 52 boots before the
mapping-owner comparison began. Both labels run the same frozen `ad6ac6a`
binary and assets; harness source is `ab4c264`. Twelve balanced five-second
rounds retain warmups, hashes, per-operation results and temporal blocks in
[storage-noise-x86.json.gz](storage-noise-x86.json.gz). Affinity remains CPUs
24–27, with no simultaneous local compilation or added VM tests. The unrelated
long-lived VM remains present, so this is not an exclusive-host measurement.

Identical-worker random-read throughput and CPU/GiB intervals stay within
0.5% of unity. Random-write throughput varies from −6.6% to +0.4%, with a last
four-round block around −7%; sequential throughput intervals span roughly ±6%.
That distinguishes a stable read measurement from storage drift and prevents
treating a small write difference as a code effect. The random-read worker
itself retains about 99.1% of control throughput with 101.8% CPU/GiB; those small
costs remain visible above its much narrower calibration. Write and sequential
results remain less resolved. This calibration covers this host, transport and
backing only; the network noise bands are not reused for storage.

## Balanced mapping-owner comparison on macOS

[Run 46098627713](https://github.com/pichi-vm/dillo/actions/runs/46098627713),
attempt 2, completes all 104 boots at `ab4c264` against `ad6ac6a`: twelve
balanced five-second pairs per revision for PCI-free block and network.
Both source trees are clean, executable hashes differ, guest assets match,
and every guest reports no PCI devices. The first attempt failed during
toolchain installation before any measurement; that failure remains recorded.

The 16-line mapping-owner change improves worker sequential read/write
throughput by 8.8%/7.1%, with CPU/GiB falling 8.1%/6.7%. Bulk network throughput
improves 5.2% (paired 95% interval +5.0–5.4%) and CPU/GiB falls 8.6%
(−9.0% to −8.4%). All three four-round blocks have the same direction.
Random-read throughput is essentially unchanged; its +0.6% CPU/GiB observation
needs storage-specific noise calibration before attribution. Random writes
improve 3.0% in the worker but fall 1.6% in the control.

This is useful common-path work, not a solution to isolation overhead. The
bulk network control improves 6.1% in throughput and 11.1% in CPU/GiB, leaving
the worker at 94.2% throughput, 116.1% CPU/GiB and 108.9% p99 relative to it.
The larger relative gap does not erase the worker's absolute improvement.
Storage gaps also remain. No PCI or whole-platform qualification follows.
[mapping-owner-macos-balanced.json.gz](mapping-owner-macos-balanced.json.gz)
retains both modes, all observations, temporal blocks, hashes and provenance.
A separate identical-binary PCI-free storage calibration at `ab4c264` is
running; no result from that unfinished series is included here.

## Balanced mapping-owner comparison on Arm and Windows

[Arm run 46099095912](https://github.com/pichi-vm/dillo/actions/runs/46099095912)
and [Windows run 46098629522](https://github.com/pichi-vm/dillo/actions/runs/46098629522)
each complete all 104 boots of the same `ab4c264` versus `ad6ac6a` comparison.
Executable hashes differ, guest assets match, both source trees are clean,
and all guests report no PCI devices. Twelve balanced five-second pairs per
case retain both revision and execution-mode comparisons.

Arm bulk network throughput rises 9.2% (paired interval +5.1% to +14.4%) and
CPU/GiB falls 12.5% (−14.2% to −10.9%). All three four-pair blocks agree in
direction. Worker/control ratios become 98.4% throughput, 103.4% CPU/GiB and
102.8% p99; these ratios do not alone establish parity. Sequential-read
throughput rises 7.7%, while random-write results vary substantially across
blocks and their intervals span both improvement and regression.

Windows bulk network throughput rises 3.4% (+2.0% to +4.3%) and CPU/GiB falls
6.9% (−9.2% to −5.7%). Bulk p99 is essentially unchanged, leaving it at 130.0%
of the control. This experiment does not include the separate TCP_NODELAY
correction. Sequential-read/write throughput rises 2.2%/3.6%; their p99
observations rise 6.3%/9.8%, with substantial variation. Storage-specific
calibration is needed before attributing those tail changes to the source.

These are common-path improvements, not full isolation qualification. Local
x86 comparison remains in progress; no candidate is promoted from these
partial-platform results. Full observations, temporal blocks, hashes and
provenance are retained in [mapping-owner-arm-balanced.json.gz](mapping-owner-arm-balanced.json.gz)
and [mapping-owner-windows-balanced.json.gz](mapping-owner-windows-balanced.json.gz).

## Windows TCP policy comparison

[Run 46099573387](https://github.com/pichi-vm/dillo/actions/runs/46099573387)
completes 104 boots at `243c756` against `e5538b1`, using twelve balanced
five-second pairs for each network transport. The one-line change sets
TCP_NODELAY before exporting a Windows worker socket, matching the existing
in-process connector. Native WHP lifecycle and notification/network checks
pass before measurement; the unchanged prebuilt WSL kernel supplies the
high-resolution guest clock.

The setting does not explain the bulk tail gap. Worker p99 changes by +0.4%
on PCI (paired interval −6.7% to +2.3%) and −1.4% on PCI-free MMIO (−2.8% to
+2.1%). Throughput changes by +0.1%/+0.6%, and CPU/GiB by +2.4%/−1.1%; these
do not establish a performance win. Worker/control bulk p99 remains
134.5%/129.6%. The setting is retained to make the two connection paths follow
the same TCP policy, not as a claimed tail-latency optimization. No protocol,
resource authority or lifetime changes are involved.

[windows-network-nodelay-balanced.json.gz](windows-network-nodelay-balanced.json.gz)
retains all boots, comparisons, temporal blocks, asset/source hashes and
artifact provenance. This experiment excludes the mapping-owner change.

## Physical x86 mapping-owner comparison

All 156 boots at `ab4c264` against `ad6ac6a` complete: twelve balanced
five-second pairs for PCI-free block and both network transports. Sources
are clean, frozen executable hashes match the predeclared comparison, and
guest assets match. No local compilation or additional VM tests ran during
measurement; the unrelated long-lived VM was left untouched.

Bulk PCI network throughput rises 5.9% (paired interval +5.7% to +6.0%) and
CPU/GiB falls 9.5% (−9.9% to −9.3%), consistently across temporal blocks.
PCI-free bulk throughput is essentially unchanged, with CPU/GiB falling
2.6% (−3.1% to −2.1%). Small-message differences remain uncertain.
Random-read throughput rises 1.1% and CPU/GiB falls 1.9%, beyond the much
narrower preceding read calibration.

Random-write throughput instead appears 4.9% lower and CPU/GiB 7.9% higher,
with broad intervals. The preceding identical-binary write calibration also
shows changes through −6.6%/+9.3%, so the source effect remains unresolved.
The prespecified single extension to twenty storage pairs is now running:
eight additional pairs, unchanged binaries/assets and affinity, with the
original twelve and all warmups retained. This is not a new search for a
favorable run. [mapping-owner-x86-balanced.json.gz](mapping-owner-x86-balanced.json.gz)
retains the completed first series independently.

## macOS storage calibration

[Run 46102319802](https://github.com/pichi-vm/dillo/actions/runs/46102319802)
completes all 52 PCI-free block boots using the identical `ab4c264` executable
and assets under both labels. Random-read throughput/CPU calibration intervals
stay within about 0.3% of unity; random-write intervals span roughly 1.3%/1.0%.
Identical sequential writers nevertheless show a 1.2% throughput difference,
with all three temporal blocks agreeing. Thus an ordinary interval excluding
zero still does not by itself establish a code effect.

The earlier mapping-owner random-read CPU observation of +0.6% remains open:
it is small but cannot simply be dismissed using this narrower calibration.
The large sequential-read/write improvements exceed the observed calibration.
All observations, hashes and temporal blocks are retained in
[storage-noise-macos.json.gz](storage-noise-macos.json.gz). These measurements
do not transfer noise bounds to other hosts or establish storage parity.

## macOS notification syscall diagnostic

[Run 46104433049](https://github.com/pichi-vm/dillo/actions/runs/46104433049)
completes eight boots at `ba3bda8`, whose runtime is the `ab4c264` mapping-owner
candidate. One measured five-second pair per network transport, plus warmups,
records public `PROC_PIDTASKINFO` counters alongside the usual samples. The
native layout and counter-growth selfcheck passes. Every active window has
stable process identities and valid, monotone counters; no sampling errors or
saturated counters occur. The hostname, OS and Apple M1 model match the earlier
Hermes measurements. This instrumented diagnostic does not qualify performance.

For each echo, total Unix syscalls rise from 17.4 to 23.6 on PCI and 17.6 to
23.4 on PCI-free MMIO with 64-byte messages. With 64-KiB messages, they rise
from 54.3 to 77.6 and 52.7 to 74.0 respectively. Bulk context switches rise
from 16.2 to 23.9 and 15.9 to 22.1 per echo. Mach-call counts remain below
0.05 per operation in every case. Counts are normalized using the sampled
window duration and guest operation rate; the retained records include raw
counter endpoints, process identities and all sample windows.

This narrows the investigation to the extra Unix notification/scheduling work,
but does not identify individual syscalls or assign CPU cost to them. The pipe
reader already batches up to 256 bytes in one read after each readiness wait;
it does not perform an extra drain-to-EAGAIN read. The earlier direct-reader
experiment also batched words, so repeating it as a new batching optimization
is not supported by this evidence. `xctrace` is unavailable on the runner.
[macos-task-counters.json.gz](macos-task-counters.json.gz) retains all eight
boots, counters, normalized observations, source and artifact hashes.

## Completed storage noise checks and x86 extension

The single prespecified x86 extension completes 36 more boots. Combining all
twelve original storage pairs with all eight new pairs preserves their order,
binaries, assets and four-round balance. Random-read throughput improves 1.2%
and CPU/GiB falls 1.9%; sequential-read throughput improves 5.1% and CPU/GiB
falls 6.5%. Random-write throughput is 3.3% lower (paired interval −6.0% to
+1.1%), with CPU/GiB 5.9% higher (−1.8% to +10.0%). Those write observations
still overlap the earlier identical-binary variation; the extension does not
establish their cause. No further repetition to seek a favorable result is
scheduled. [The extension](mapping-owner-x86-storage-extension.json.gz) and
[combined twenty pairs](mapping-owner-x86-storage-twenty.json.gz) retain both
series rather than replacing the initial result.

[Arm run 46103662489](https://github.com/pichi-vm/dillo/actions/runs/46103662489)
and [Windows run 46103663630](https://github.com/pichi-vm/dillo/actions/runs/46103663630)
each complete 52 PCI-free block boots with identical `ab4c264` executables and
assets under both labels. Arm random writes show an apparent 4.8% throughput
loss and 6.4% CPU/GiB increase despite identical code; all three temporal blocks
have that direction. This further undermines assigning the earlier 3.8% write
observation to the owner change. Windows sequential-read p99 varies from
90.9% to 112.0% and sequential-write p99 from 78.2% to 105.1% across paired
calibration intervals. The prior tail observations therefore remain unresolved,
not demonstrated regressions or a parity result. Full observations are in
[storage-noise-arm.json.gz](storage-noise-arm.json.gz) and
[storage-noise-windows.json.gz](storage-noise-windows.json.gz).

These checks calibrate this QD1 PCI-free storage workload, not PCI or concurrent
storage. The mapping-owner candidate remains separate, including the small
macOS random-read CPU observation recorded above.

## Windows scheduler diagnostic and TCP readiness candidate

[Run 46104224464](https://github.com/pichi-vm/dillo/actions/runs/46104224464)
completes eight instrumented boots at `873af3b`, with the `72fc019` runtime.
The hash-pinned PerfView 4.0.2 capture retains 2,981,588 context-switch and
1,884,880 ready-thread events involving observed Dillo PIDs. Analysis restricts
events to their actual process lifetimes, excludes phase boundaries, and
separates blocked time from ready-to-run delay. Two duplicate ready events and
unmatched transitions are retained. Decode logs contain symbol/stack warnings
but no reported event loss; this is not a fully symbolicated CPU profile.

For the measured bulk MMIO pair, network-loop ready-to-run p99 is 53/49 µs
for control/worker, while vCPU p99 is 75/119 µs. Some longer stalls occur,
especially in the PCI pair, but this short trace does not establish a general
millisecond-scale scheduler delay as the cause of the network tail gap. The
network-loop thread instead spends about 3.9–4.2 seconds running in each
trimmed bulk window of roughly 4.7 seconds, in both execution modes.
[windows-scheduler-diagnostic.json.gz](windows-scheduler-diagnostic.json.gz)
retains phase/process data, distributions, unknown transitions, analysis code,
logs, raw-event hashes and artifact provenance. Instrumented rates are not
used for qualification.

Source inspection identifies a concrete candidate: Mio 1.2.1 rearms all
registered interests after `WouldBlock` on Windows, while Dillo leaves
`WRITABLE` registered for an established stream even without pending output.
The separate 80-line `ceda4c5` change retains writable interest for connection
completion and pending guest bytes, removing it after draining. Existing
backpressure and half-close paths remain; failed interest changes reset the
flow through its existing error path. All 58 Linux network tests and strict
Clippy pass. A Windows native fixture checks the old repeated readiness and
the new quiet state before [run 46106783368](https://github.com/pichi-vm/dillo/actions/runs/46106783368)
compares four balanced five-second pairs on both transports. The candidate
is not integrated and no performance benefit is claimed before that result.

## Current macOS network stacks

[Run 46107215606](https://github.com/pichi-vm/dillo/actions/runs/46107215606)
completes eight boots at `f58b360`, with the mapping-owner candidate's runtime
and an optimized symbolized build. Each transport has an unprofiled warmup
pair and one measured ten-second pair. Ten three-second process profiles
cover the measured parents and their children. Every profiler exits normally;
report timestamps lie inside the bulk phase, process identities match the
recorded tree, and each parsed thread's leaf counts sum to its observation
count. PCI-free reports contain no PCI devices.

Control receivers, control senders and resource-grant receivers remain in
waits throughout their captured observations. The user-network thread spends
about 66–69% of wall-clock observations in `kevent`, in both execution modes.
The worker queues retain their pipe/condition-variable waits, and the parent
completion threads show pipe reads followed by native GIC delivery. Memory
region creation and payload copies remain visible in the active queue stacks.
There is no observed steady-state control RPC or Windows-style writable spin
in these macOS captures.

These are wall-clock stack observations, including sleeping threads and guest
execution. They do not apportion host CPU, qualify performance, or prove that
notification cost alone explains the remaining gap. The full stack reports,
profiler logs, boot records, parsing checks, timestamps and archive hashes are
retained in [macos-network-stacks-current.json.gz](macos-network-stacks-current.json.gz).

## Windows writable-readiness screening

[Run 46106783368](https://github.com/pichi-vm/dillo/actions/runs/46106783368)
completes all 40 boots at `ceda4c5` against `8937f91`: four balanced
five-second pairs per network transport, with matched assets and distinct
executables. Native network checks reproduce repeated writable events after
blocked reads under the original interest set, then verify that removing idle
writable interest prevents them. The change retains writable interest for
connection completion and pending guest output.

Worker CPU per operation falls about 40%/42% for small PCI/MMIO messages and
13%/19% for bulk traffic. All four CPU ratios improve in each case. There is
also a throughput tradeoff: small PCI messages lose 10.5%, and bulk PCI/MMIO
lose about 4%; small MMIO messages improve 2.8%. The small PCI throughput loss
appears in all four pairs and affects the control too. These short observations
are a reason to investigate the tradeoff, not to promote the candidate.

The host reports AMD family 26/model 2; the earlier Windows noise and NODELAY
comparisons report family 25/model 1. The unchanged baseline's median bulk
worker/control p99 is now about 109.8%/101.1% on PCI/MMIO, rather than the
previous roughly 130% values. The candidate's 103.5%/102.4% therefore cannot be
credited with resolving the earlier tail gap. The generic runner hostname is
not evidence of identical hardware. All observations, including the large
second-pair PCI tail in both revisions, remain in
[network-write-interest-windows-short.json.gz](network-write-interest-windows-short.json.gz).

A separate 50-line follow-up at `2619d65` retains read readiness until
WouldBlock, then waits for a readable/closed/error event instead of retrying
blocked host reads on unrelated guest wakes. It preserves readiness when the
guest cannot accept more data and removes a temporary readiness-token vector.
All 58 applicable local network tests and strict Clippy pass; four
hardware-dependent/external tests remain intentionally ignored. A new native
Windows comparison against `ceda4c5` is running. Neither candidate is integrated
into the performance branch or treated as final parity qualification.

## macOS thread CPU attribution

[Run 46108797906](https://github.com/pichi-vm/dillo/actions/runs/46108797906)
completes eight boots at `27ae6f6`, whose runtime retains the mapping-owner
candidate. One ten-second pair per network transport, plus warmups, records
public libproc thread CPU counters at the existing two-second memory sampling
points. There is no stack sampler. The native counter self-check observes
20.028 ms of CPU for its 20 ms spin. This is attribution evidence, not a
performance comparison or calibrated parity result.

All active intervals retain the same process creation times, pthread addresses
and thread names. Every counter is monotonic, no thread query fails, and the
largest difference between summed thread CPU and the separately sampled
process CPU is 0.143 ms. This establishes actual CPU use rather than the
sleep-inclusive wall observations in the earlier stack reports.

During bulk traffic, the worker parent's unnamed helper threads consume
0.142 CPU cores on PCI and 0.108 on MMIO. The source's unnamed completion
relays and the earlier stack reports identify this as the completion-helper
path; the counter API itself provides no stack identity. The worker network
thread consumes about 0.40 cores, compared with 0.38–0.39 in process. The two
network queue threads consume about 0.44 cores in the worker, compared with
0.39–0.41 for their in-process counterparts. Lower worker throughput means
these similar absolute CPU rates still imply more work per completed echo.

Using the whole phase's operation rate to approximate the sampled interval,
the worker completion helpers cost about 28 microseconds per bulk echo on
PCI and 22 on MMIO. Queue threads cost about 88 microseconds versus 74–75 in
process; the network loop costs about 79 versus 71–72. The vCPU cost is much
closer: approximately 119 versus 116 on PCI and 126 versus 125 on MMIO.
These approximations do not isolate syscall cost, prove a scheduling cause,
or justify attributing the entire gap to interrupt delivery.

The eight complete boot records, sparse snapshots, per-thread deltas, process
cross-checks, warmups, input hashes and reproducing analysis are retained in
[macos-network-thread-cpu.json.gz](macos-network-thread-cpu.json.gz). The
protocol/control threads remain effectively idle. The next optimization must
address measured queue/notification work rather than remove idle control RPC.

## Linux x86 combined readiness screen

Apollo completes forty boots comparing `2619d65` with `8937f91`: four balanced
five-second pairs per network transport, with distinct frozen executables,
matched guest assets, CPUs 24–27, and no concurrent local compilation. The
unrelated existing VM was left running; this is not an exclusive-host claim.
All boot reports and sampling records validate, including PCI-free guests.

Bulk PCI worker throughput rises 3.9% and CPU/GiB falls 4.5%; all four pairs
have those directions. Bulk MMIO throughput falls 5.1% and CPU/GiB rises 3.0%,
also in every pair. The same-revision controls show the same transport split:
PCI throughput rises about 4.3%, while MMIO falls about 7.5%. Small-message
results are mixed and noisy. This screen does not support a universal policy
change, even though the candidate's MMIO worker/control ratio looks favorable.

The two changes respectively remove idle writable interest and defer blocked
reads until a readiness event. A narrow follow-up will permit one optimistic
read after a successful host write, when a reply might already be available,
without retrying blocked reads on unrelated guest activity. That is a
hypothesis to measure, not an established explanation of the transport split.
All observations, including the losses, are retained in
[network-readiness-x86-short.json.gz](network-readiness-x86-short.json.gz).

## Windows read-readiness follow-up

[Run 46108670292](https://github.com/pichi-vm/dillo/actions/runs/46108670292)
completes forty boots comparing `2619d65` with `ceda4c5`. Both revisions already
remove idle writable interest; this comparison isolates the subsequent read
readiness tracking. Four balanced five-second pairs per network transport use
matched guest assets, distinct binaries, and the Hyper-V-clock diagnostic
kernel. Native WHP checks and all 52 applicable network tests pass; four
external-network tests remain ignored. Boot reports and sampling validate.

Bulk worker throughput is essentially unchanged on PCI and 1.6% lower on
MMIO. CPU/GiB changes by −1.7% on PCI and +2.8% on MMIO, with mixed individual
pairs. Small-message median throughput changes are −1.6%/−0.7%; an unusually
slow baseline PCI pair is retained. Four pairs do not establish precision or
justify promoting the additional tracking as a performance improvement.

The runner reports AMD family 25/model 1, matching the family/model of the
earlier calibration rather than the intervening family 26 writable-interest
screen. Bulk worker/control p99 remains 131.3% on PCI and 129.5% on MMIO.
The unchanged baseline ratios in this run are 129.8% and 140.3%. The additional
read tracking has not resolved the recurring tail gap. These comparisons
must not be multiplied across different runs to estimate a combined gain.

[network-read-ready-windows-short.json.gz](network-read-ready-windows-short.json.gz)
retains both revisions, all paired values, warmups, source identities and
artifact hashes. The separate six-line reply-probe candidate `281772e` is
being screened locally; no result from it is included here.

## Completed readiness screens and reply probe

The combined writable-interest/read-tracking candidate `2619d65` completed
[macOS run 46109756741](https://github.com/pichi-vm/dillo/actions/runs/46109756741)
and [Arm run 46109764877](https://github.com/pichi-vm/dillo/actions/runs/46109764877).
Both compare with `8937f91`: four balanced five-second pairs per network
transport, 40 boots including warmups, shared completion, sampling and QD1.
All boots, matched guest assets, distinct frozen binaries, clean source state
and PCI-free declarations validate. Native prerequisite checks also pass.

On macOS, bulk worker CPU/GiB falls 1.9% on PCI and 2.2% on MMIO, with every
pair lower. Control CPU falls by similar amounts; throughput changes are
under 1%. Small-message worker CPU falls 5.3%/2.4%, while throughput falls
0.4%/0.8%. These are short screens, not a new calibrated matrix. Bulk
worker/control CPU remains 115.7%/113.3%, with throughput 93.7%/95.4% and p99
109.4%/106.0%. The isolation cost is still present.

Arm small-PCI worker throughput improves 2.6% with 4.2% lower CPU, but small
MMIO throughput falls 2.1%. Bulk PCI pairs vary in direction; bulk MMIO
worker throughput falls in all four pairs (median 5.4%), with higher CPU
(median 4.0%). The control also varies, including a 15.3% MMIO throughput
drop in one pair. Keep these observations without inferring a scheduling
cause or accepting the policy as a general improvement.

The local six-line reply probe `281772e` compares with `2619d65`. It permits
one host read after successfully writing guest bytes, even before a readable
event arrives. The completed 40-boot screen uses the same balanced design
and CPUs 24–27; no local compilation or extra test VM ran during measurement.
The unrelated long-lived VM remained untouched, so this is not an exclusive
host measurement. Bulk PCI worker throughput falls 5.3% and CPU rises 5.4%;
all four pairs worsen, as do the control pairs. Bulk MMIO throughput rises
5.9%, with 3.0% lower CPU; the control improves too. Small PCI improves, while
small MMIO changes little. This reverses the preceding PCI/MMIO tradeoff
rather than establishing a policy that benefits both transports. Neither
candidate is promoted; gains from separate runs are not multiplied together.

All paired observations, warmups, hashes and run identities are retained in
[network-readiness-macos-short.json.gz](network-readiness-macos-short.json.gz),
[network-readiness-arm-short.json.gz](network-readiness-arm-short.json.gz), and
[network-reply-probe-x86-short.json.gz](network-reply-probe-x86-short.json.gz).
Four pairs do not justify narrow confidence intervals or a parity conclusion.

## Shared-status negotiation fallback

The parent previously sent the private shared-status request whenever the
transport supplied a status page, even if the backend had not negotiated the
optional feature. The 81-line change `75b3cc6` retains the negotiated choice
and uses the ordinary parent status/call relay when the feature is absent.
Native PCI calls without shared status retain their export path. The existing
process fixture now also withholds the feature from the backend's reply and
checks actual I/O, status publication, endpoint replacement and reactivation.

With only production `parent.rs` restored to its old version, that fixture
fails at the unnegotiated private request. The fixed full worker suite,
formatting and strict all-target/all-feature Clippy pass locally.
[Windows run 46111595241](https://github.com/pichi-vm/dillo/actions/runs/46111595241)
also passes the real process fixture over ALPC, including direct, shared and
unnegotiated calls. Its separate old `worker::vhost_user` filter selected zero
tests; it is not channel-unit evidence. The workflow now selects the owning
`dillo-windows-channel` crate instead. Runtime source integrated at `715a13a`
is identical to the native-tested source; only benchmark reports differ.

[Integrated Windows run 46112198993](https://github.com/pichi-vm/dillo/actions/runs/46112198993)
checks out `31e4eeb` and passes the worker fixture again. The corrected channel
step runs eight passing tests (one ignored), including bidirectional handles,
connection shutdown, peer-death cleanup and listener survival. Network checks
pass 51 tests, with four external-network cases ignored. The complete native
logs are retained; expected failure-case diagnostics are not removed.

[shared-isr-negotiation.json.gz](shared-isr-negotiation.json.gz) retains the
negative-control and fixed logs, native log, source identities and scope.
This establishes optional-feature fallback, not an assigned extension,
complete external-backend interoperability, or all ACK/EOI/reset races.

## Windows reply-probe failure

[Run 46112447857](https://github.com/pichi-vm/dillo/actions/runs/46112447857)
at `281772e` passes its native prerequisites and builds both executables, but
fails during the first PCI worker warmup. The guest reports `Connection reset
by peer (os error 104)` and produces no measured operations. Dillo itself
exits zero; the harness correctly rejects the guest's error report. No baseline
boot or measured pair completes, so this run supplies no performance ratio.
The failure does not by itself establish whether the reply probe caused the
reset. No automatic performance rerun is used to replace this observation.

All seven artifact files, including the failed guest report and both streams,
are retained with hashes and source/run identity in
[network-reply-probe-windows-failed.json.gz](network-reply-probe-windows-failed.json.gz).
The source remains experimental. The separate memory/TX combined candidate
does not include any writable-interest, read-tracking or reply-probe change.

## Combined mapping-owner and TX-storage candidate

Candidate `8196bb4` composes the separately measured mapping-owner change
(`604c9de`, 16 changed lines) and TX storage reuse (`c2531a9`, 94 changed lines)
on the current performance branch's `1b8a795` baseline. The latter now also
releases oversized TX allocations after each frame, so one guest-selected
descriptor size cannot leave a large cache while the worker waits for its
next kick. This is a cache policy, not a new transmit-size refusal. Its fixture
checks that a large frame is still forwarded and its scratch capacity released.

Local validation passes 23 MMIO, 28 virtio and 57 network tests (four external
network cases ignored), formatting and strict all-target/all-feature Clippy.
The workflow adds a four-case primary selection and native memory/virtio
checks. Prespecified comparisons cover block and network over both PCI and
PCI-free MMIO: four balanced five-second pairs, QD1, sampling, shared status
and 80 boots per host including warmups. Windows retains its prebuilt clock
diagnostic kernel. Frozen executables have matched guest assets. This is a
combined candidate screen; the prior macOS random-read CPU observation and
other storage variation remain open, and no parity result is claimed yet.

Native comparisons run on [macOS 46113398827](https://github.com/pichi-vm/dillo/actions/runs/46113398827),
[Arm Linux 46113400098](https://github.com/pichi-vm/dillo/actions/runs/46113400098)
and [Windows 46113636413](https://github.com/pichi-vm/dillo/actions/runs/46113636413).
The local x86 comparison freezes both release builds before measurement and
uses CPUs 24–27; no additional local compilation or test VM runs during timing.
The unrelated long-lived VM remains present, so no host exclusivity is claimed.

The local x86, macOS, Arm and Windows comparisons each complete all 80 boots. Source
and executable hashes, matched guest assets, balanced schedules, minimum
five-second operations and empty guest/sampling error lists are verified.
The PCI-free images report no PCI devices. These are four-pair screens;
their medians do not replace the twelve-pair calibrated network table.

Bulk-network worker CPU/GiB falls by 10.6%/13.0% on x86, 15.0%/14.7% on
Arm, and 14.6%/15.2% on macOS (PCI/MMIO respectively). The same changes also
benefit the control. macOS worker/control bulk CPU/GiB remains 118.1%/114.7%,
with throughput 92.4%/94.5%; the common-path improvement does not remove its
isolation cost.

Storage observations remain mixed. On x86, PCI-free sequential writes lose
8.6% throughput and use 11.6% more CPU/GiB relative to the old worker; all
four pairs have that direction while the control improves in three. This
result is retained rather than discarded using the earlier write-variation
evidence, which does not establish this observation's cause. Sequential
reads improve on both transports, but the new worker still trails the new
control. Arm PCI random reads lose 2.3% throughput and use 2.2% more CPU,
while PCI-free random reads improve by 6.0%/7.3%. macOS sequential I/O
improves, but the earlier small PCI-free random-read CPU concern remains:
this screen observes +0.4%. No storage parity or blanket promotion follows.

Windows bulk network CPU/GiB falls by 14.2%/10.9% against the previous worker
(PCI/MMIO). PCI p99 falls by 23.6%, but the new worker/control comparison is
still 94.7% throughput, 108.2% CPU/GiB and 105.3% p99. MMIO is 96.1%, 99.2%
and 132.4% respectively. These four-pair observations do not replace the
calibrated table: this runner reports AMD family 25/model 17, whereas the
earlier Windows calibration used family 25/model 1. The sampling-on/off
diagnostic remains a separate experiment, not an assumed explanation.

All workload metrics, both execution modes, every paired value and provenance
are retained in [x86](memory-tx-integration-x86-short.json.gz),
[Arm](memory-tx-integration-arm-short.json.gz),
[macOS](memory-tx-integration-macos-short.json.gz) and
[Windows](memory-tx-integration-windows-short.json.gz).

## Concurrent PCI-free block workload

The harness now runs the existing four-disk concurrent snuffler workload over
PCI-free MMIO as well as PCI. The image declares five MMIO slots for its
console and four disks, and the guest's PCI inventory must be empty.
The first new smoke guest completed successfully, but the harness rejected
its `block-group` report because the validator expected per-disk operation
rows. The corrected validator accepts the aggregate while requiring all four
disk names and the expected total in-flight bound.

At harness `3383874`, using frozen runtime `8196bb4`, all eight subsequent
smoke boots pass: a warmup and one 500-ms pair on each transport, queue depth
eight per disk. Every boot contains four 64-MiB disks, four grouped operations,
a bound of 32 in flight and verified writes. The sampled process counts are
two for the control and six for the isolated configuration. Both the initial
validator failure and the complete corrected records are retained in
[concurrent-mmio-smoke.json.gz](concurrent-mmio-smoke.json.gz).
This establishes workload execution and report validation, not performance
parity.

The prespecified four-pair, five-second screens completed all 20 boots on
each of local x86, [Arm](https://github.com/pichi-vm/dillo/actions/runs/46116324563)
and [macOS](https://github.com/pichi-vm/dillo/actions/runs/46116323086). Each
transport has four disks at queue depth eight, with 32 requests allowed in
flight. Every boot retains all four operation reports and verified writes;
MMIO reports no PCI devices. Runtime is the combined candidate above, with
only the workload/validator changes at source `3383874`.

Concurrent sequential reads show why throughput and CPU cannot substitute
for latency. Ratios below are isolated worker / same-binary in-process control:

| Host | Transport | Throughput | CPU/GiB | p99 |
| --- | --- | ---: | ---: | ---: |
| Linux x86-64 | PCI | 98.2% | 100.3% | 101.6% |
| Linux x86-64 | PCI-free MMIO | 92.3% | 111.6% | 111.4% |
| Linux AArch64 | PCI | 150.4% | 58.2% | 225.1% |
| Linux AArch64 | PCI-free MMIO | 157.3% | 57.5% | 265.5% |
| macOS AArch64 | PCI | 130.9% | 58.8% | 253.7% |
| macOS AArch64 | PCI-free MMIO | 124.4% | 58.6% | 342.5% |

Arm sequential-read p99 rises from roughly 1.9–2.1 ms to 4.3–5.4 ms;
macOS rises from 1.0–1.6 ms to 2.7–4.5 ms. These are short screens without a
matched concurrent-workload noise calibration, so they do not establish
parity or identify a scheduling/interrupt cause. PCI random-read p99 on x86
also remains about 30% above control in all four pairs. All other operations,
including the slow individual x86 write/read pairs, remain in the evidence.

Full raw reports, logs, schedules, hashes and analyses are retained in
[x86](concurrent-transports-x86-short.json.gz),
[Arm](concurrent-transports-arm-short.json.gz) and
[macOS](concurrent-transports-macos-short.json.gz). Windows will run the same
prespecified screen after its sampling diagnostic ends.

Source inspection also limits the meaning of the `shared` experiment label:
the launcher currently enables the shared interrupt-status factory only on
Linux and Windows. macOS still uses the parent completion relay and its
existing interrupt status; the environment flag alone does not establish
shared-status operation there.

## macOS shared-status prototype

The isolated experiment `experiment/hvf-shared-status` adds the existing
shared-status hook to HVF. Source `abb279b` provides the status mapping using
the existing unlinked POSIX shared-memory allocator. Darwin's
[shm implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/posix_shm.c)
refuses resizing after the first allocation; the native fixture also verifies
that both shrinking and growing an exported backing fail.

Runtime `8f558ff` binds a call receiver to one activation. It exports the same
Unix pipe type already used by workers, retains one receiver across that
activation's queues, and skips pipe/thread creation for the in-process path.
The worker sets the negotiated shared latch before signaling, coalescing
notifications while the status remains pending. Declared edge sources pulse;
level sources follow the latch. ACK and delivery share a lock and re-read the
status so a stale zero observation cannot lower a newer level. Retirement
revokes delivery before waking/joining the receiver, and repeated retirement
does not lower a replacement binding's line. This uses the existing private
experimental protocol feature; it is not a newly assigned vhost-user facility.

The first qualification run `46119245700` compiled and passed the regular
macOS suites, then failed before the native check because Bash could not
create a heredoc temporary file. The harness-only correction `f8dc0ed` moves
that code into a checked-in Python script. In
[run 46119474739](https://github.com/pichi-vm/dillo/actions/runs/46119474739),
the signed GIC check passes for edge/level injection, a controlled stale-ACK
interleaving, retired endpoints and replacement activation. All eight
500-ms PCI-free block/network smoke boots then succeed, across local/worker
execution. The local MMIO transport suite and strict Clippy pass; the three
KVM completion checks also pass after the shared transport ACK adjustment.

Both run logs, all smoke outputs/hashes and local checks are retained in
[hvf-shared-status-smoke.json.gz](hvf-shared-status-smoke.json.gz). This is
bounded correctness evidence, not a concurrent stress proof or performance
result. The predeclared comparison against `8196bb4` uses four balanced
five-second pairs across PCI/MMIO block and network cases. The runtime remains
outside the main optimization branch pending those measurements and remaining
shared-status qualification.
