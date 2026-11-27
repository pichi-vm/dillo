# Device isolation benchmark milestone

Completed measurements: [2026-11-27 report](results/2026-11-27/REPORT.md).

Active milestone: [device performance optimization](OPTIMIZATION.md).

The harness explicitly selects its disposable virtio disks with
`dillo.bench_devices=vda` (comma-separated for multiple disks, empty for network
cases). Snuffler reports a missing selection as an error. Without this option,
its timed mode keeps probing all nonempty whole disks. This prevents a kernel's
built-in RAM disks from silently becoming additional timed workloads.

## Question and completion criteria

Measure the cost of Dillo's out-of-process virtio devices, starting from
`ba7fafc7a1598dab86e1afc61c250a55673deb48`. Use snuffler for guest workloads.
Produce reproducible raw results, paired comparisons, and an explanation of
the costs before choosing optimizations. Keep this work on a benchmark branch;
it does not authorize an upstream submission or change DESIGN.md.

The milestone completes with native Linux/KVM, macOS/HVF, and Windows/MSVC/WHP
measurements, or an explicit reproducible platform limitation. Correctness
failures are investigated before using a sample. After reporting, pause for
reflection. A throughput improvement is not required for completion.

## Controlled comparison

- Build one release executable with a benchmark-only opt-in for direct device
  execution. The default remains the production confined worker path.
- Run the same current block or user-network implementation directly in the
  parent for the control. Keep the guest image, backend, queue sizes, transport,
  compiler, and host settings identical within each pair. Do not compare old
  whole-source revisions and attribute all differences to process isolation.
- Keep the console in its production worker in both modes. Change only the
  device under measurement; record and verify the expected process counts.
- Block uses the same raw backing and device factory. User networking uses the
  same stack, with direct host resource creation in the control. Report the
  latter's omitted resource broker as part of Dillo's isolation implementation,
  rather than an intrinsic cost imposed by vhost-user.
- This comparison includes the proxy, memory-access boundary, notifications,
  process lifecycle, and confinement. It is not a measurement of ALPC alone.
  The earlier RPC revision already used workers and is not an in-process control.
- The control is deliberately unsuitable for production. Compile it only with
  the benchmark feature, make mode selection explicit, and reject unsupported
  device kinds. Do not duplicate device protocol implementations.

## Workloads

1. One raw virtio-block device over PCI: sequential 64 KiB and random 4 KiB
   reads/writes, queue depth one. Use a fully initialized disposable 64 MiB
   backing, guest O_DIRECT, deterministic offsets and data verification.
2. Repeat block over MMIO to expose notification-path differences.
3. Four block devices: measure idle footprint/startup scaling and repeat the
   same workload. Report serial per-device execution; do not call it a
   multi-queue saturation test.
4. One user-network device over PCI: repeated verified local TCP exchanges,
   small messages for round-trip latency and bulk messages for useful rate.
   Exclude the public Internet and DNS variability. Clearly distinguish echo
   round-trip goodput from one-way network capacity.

Extend snuffler's existing probes with an opt-in timed mode, bounded warm-up,
bounded latency histograms, and recorded workload parameters. Preserve the
existing quick boot-test defaults. Use a guest idle interval for host sampling
and an explicit ready marker before workloads. Writes use disposable disks;
they measure completion through the host cache, not persistence or fsync rate.

Filesystem, console, and vsock remain correctness-tested production devices.
This milestone makes no performance claim about them, multi-queue saturation,
native bridging/vmnet, external vhost-user servers, or confidential computing.
Add a further workload only if the first results show it answers a distinct
architectural question.

## Experiment procedure

- First run correctness and a short pilot on the available physical Linux
  host. Use the pilot only to check the harness, never as the final result.
- Use at least five measured pairs per workload/platform, plus an unmeasured
  warm-up pair. Alternate execution order AB/BA. Use at least one second per
  operation; use longer runs for the principal physical-host comparison.
- Run both modes within the same CI job/host allocation. Record host identity,
  CPU/OS, virtualization context, toolchain, source SHA, binary/image hashes,
  guest RAM/vCPUs, transport, disk preparation, and workload configuration.
- Native macOS and Arm Linux runners provide physical-host evidence. Hosted
  Windows/Linux results are paired within a job but remain virtualized-runner
  evidence, not universal hardware performance claims. Dillo uses native
  Windows MSVC, not MinGW.
- Keep disk files warm and identically initialized; do not flush global host
  caches or change host power/CPU policies. Record competing host load.
- Bound each VM by a timeout, retain stdout/stderr and host samples, and reap
  the whole process tree after failure. Never silently discard a failed run.
- Report every pair and median paired ratios with spread. Repeat only when
  failures or noise make a result inconclusive; preserve initial samples.
  A small difference within run-to-run variation is inconclusive.

## Measurements and attribution

- Guest: bytes, operations, elapsed time, throughput/IOPS, bounded-histogram
  p50/p95/p99/max latency, I/O mode, verification/errors, kernel-to-init time.
  Histogram percentile bounds and synchronous queue depth are explicit.
- Host startup: process spawn to guest-ready marker, plus existing Dillo boot
  trace stages separating setup and device attachment. This is not firmware
  time inferred from the timestamp of the final report.
- Host: parent and every descendant's CPU time, thread/process counts, context
  switches where supported, and idle/active memory. Sample with stable PID and
  creation-time identities; report collection errors and missed short-lived
  processes as limits. Keep the echo server outside the measured process tree.
- Memory: never sum RSS and call it physical footprint. Preserve per-process
  RSS for diagnosis; use summed proportional memory on Linux where available,
  recording huge-page accounting separately. Report private residency or
  private commit under its actual OS definition on other systems. List the
  single guest backing allocation separately; do not add it to a metric which
  already includes those pages. Do not invent a cross-OS total when the native
  counters cannot deduplicate shared mappings.
- Measure sampler cost separately from the VM. Use sparse memory snapshots
  and cheap CPU sampling during timed I/O; heavy mapping walks must not run
  per request. Run a sampler-disabled control if instrumentation is material.
- Code: count production, tests, benchmark code, dependencies, and unsafe
  sites separately. Identify the pre-isolation revision for a historical
  footprint comparison, and enumerate unrelated changes in that history.
  Historical code growth is context, not a clean causal experiment.

## Deliverables

- Plan, scripts, minimal snuffler extensions, and explicitly isolated control.
- Exact source/build/CI provenance; raw guest reports, console logs, host
  samples, and environment manifests for every run.
- A concise report of absolute results and paired overhead, including failures
  and uncertainty, followed by a short ranked list of evidenced bottlenecks.
- A separation between protocol requirements and Dillo-specific choices such
  as helper threads, broker requests, polling, and confinement setup.
- No optimization or security weakening justified solely by noisy timings.

Memory metric definitions follow [psutil's API documentation](https://psutil.readthedocs.io/stable/index.html#psutil.Process.memory_full_info).

## Reproduce

Install Python 3.9+ and `psutil==7.2.2` in a virtual environment. With the
repository's pinned Rust toolchain and a working native hypervisor:

```sh
export DILLO_BENCH_DIR="$PWD/target/benchmarks"
cargo --config .copr/cargo-config.toml test --locked --release -p dillo \
  --features vm-tests,bench-in-process --test boot \
  benchmark::benchmark_assets -- --ignored --exact --nocapture
python benchmarks/run.py --assets target/benchmarks/assets.json \
  --output target/benchmark-results --pairs 5 --duration-ms 1000
```

Use a new output directory for each experiment. `--cases block-pci` selects a
single workload; `--no-sample` checks instrumentation sensitivity while keeping
guest timing and logs. Native Windows uses `CARGO_BUILD_TARGET=x86_64-pc-windows-msvc`.
The asset fixture signs the macOS executable with its existing HVF entitlement.
Linux needs permission to use `/dev/kvm` and 128 free 2 MiB huge pages per VM.

`--cases block-mmio-only,net-mmio-only` measures PCI-free guests. The producer
declares zero PCI slots and two MMIO slots; both the console and the workload
use MMIO. The harness rejects any PCI device in the guest report and retains
the image build command and digest. These cases use the same kernel as the
PCI comparisons, so PCI driver support may be compiled in but no PCI hardware
is declared. The older `block-mmio` case retains its PCI console and platform
for comparison with prior measurements. The CI workflow's `pci-free` selection
runs just the two PCI-free cases; `all` includes them too.

For the optimization milestone, `--queue-depth 8` or `--queue-depth 32` uses
that many guest threads, with one blocking O_DIRECT request per thread and
disjoint disk ranges. It bounds requests in flight; it does not assert that
the virtqueue stays full. Warm-up and measurement windows are synchronized,
and merged latency samples cover individual requests, including final
requests that finish after the deadline. Reported elapsed time includes those
completions. Write verification happens afterward. The default remains the
original single-thread path. Use separate output directories for each depth.

`--cases block4-concurrent-pci` measures all four disks in the same window.
Each has the chosen concurrency bound and independent ranges and buffers;
the report's `block-group` operation aggregates their bytes and latency
samples. With the default depth, its total in-flight bound is four. The old
`block4-pci` case continues to run each disk separately.

`environment.json` records provenance. Every run directory retains the full
console, stderr, guest report, observed phase timestamps, and native process
samples. `metrics.json` contains absolute measurements; `summary.json` contains
worker/local ratios for every measured pair. Pair zero is a retained warm-up
and is excluded from summaries. Startup marker precision is one sampling
interval; the existing boot-stage trace has microsecond resolution.

Steady-state CPU metrics estimate cores and CPU seconds per GiB between active
samples, including every discovered VM process. Whole-run CPU is sampled and
can miss the final interval; it includes startup, idle, and verification work.
Context-switch fields retain the OS API's scope (on Linux they describe the
main thread); they are not an aggregate of all device threads. Huge-page
private residency is removed from the Linux private-overhead metric and kept
separate. Native PSS omits hugetlb pages. Do not interpret either as total
guest-plus-host physical residency.

Run `python benchmarks/analyze.py RESULTS --output RESULTS/comparison.json`
to export absolute medians and every paired ratio as JSON and CSV. With at
least ten pairs, it also reports a deterministic 10,000-resample paired
bootstrap 95% interval for the median ratio. Shorter diagnostic runs leave
that interval unset. These intervals describe one host/workload combination;
they do not turn hosted runners or coarse guest clocks into native evidence.
The report
includes compressed copies of these comparisons; raw console/process samples
are retained separately. `benchmarks/plot.py RESULTS` regenerates its chart
with matplotlib 3.10.8. `benchmarks/footprint.py OLD NEW` inventories source
with tree-sitter 0.25.2 and tree-sitter-rust 0.24.0; these are analysis-only
dependencies, not Dillo build or measurement dependencies.

Timing and memory availability must be checked per run. The initial Windows
guest used `refined-jiffies`, which cannot resolve individual fast requests;
its latency percentiles are not usable as microsecond measurements. The
macOS runner could not supply detailed memory queries. Neither limitation is a zero
cost result. The guest's `boot_to_userspace_ns` captures entry before probes;
`uptime_secs` is read later and must not be used as boot latency.
