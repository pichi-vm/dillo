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
IP autoconfiguration, so it does not yet qualify the network measurements.

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
checks are underway. The raw comparison remains in the candidate worktree's
`target/performance/region-owner` directory.

A ten-pair/five-second follow-up now interleaves both binaries and both modes
on the same host, rather than measuring the complete baseline first. Its
predeclared 88-boot order and raw results are under
`target/performance/region-owner-interleaved` in the candidate worktree. This
specifically investigates the sequential-write regression. A follow-up CPU
trace of the stripped release candidate is also retained; its unresolved
Rust symbols cannot establish that a particular function's sampled cost fell.
