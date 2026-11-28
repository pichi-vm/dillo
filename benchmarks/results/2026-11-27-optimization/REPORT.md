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
102.7%/102.5%. Those repeatable smaller gaps remain open despite falling within
the 5% measurement band. Full paired observations, intervals, schedule and
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
