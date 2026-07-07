// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Wire schema shared between the guest-side e2e fixture and the host-side
//! test harness. The fixture observes the system it boots into (mounts
//! /proc + /sys, walks /sys/{block,bus/pci,class/net} and /proc) and emits
//! a [`Report`] as JSON. The harness deserialises the same [`Report`] and
//! asserts whatever the test cares about — the fixture itself contains no
//! test logic; it only describes what it sees.

use serde::{Deserialize, Serialize};

/// Sentinel pair the fixture brackets the JSON report with on stdout. The
/// kernel also writes its own printks to hvc0 when `console=hvc0` is in
/// cmdline, so the host harness needs unambiguous markers to extract the
/// report from interleaved kernel log noise.
pub const REPORT_BEGIN: &str = "<<<DILLO-E2E-REPORT>>>";
pub const REPORT_END: &str = "<<<END>>>";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub arch: String,
    pub cmdline: String,
    pub uptime_secs: f64,
    /// High-resolution nanoseconds from kernel start (CLOCK_MONOTONIC) captured
    /// at snuffler entry, *before* any probing — the kernel+initramfs boot time
    /// to userspace at ns resolution (vs `uptime_secs`' 10ms `/proc/uptime`
    /// granularity, read post-probe). Populated only when the kernel cmdline
    /// carries `dillo.uptime_ns`; `None` otherwise. Additive and gated, so
    /// default report behavior is unchanged.
    #[serde(default)]
    pub boot_to_userspace_ns: Option<u64>,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub consoles: Vec<String>,
    pub pci: Vec<PciDevice>,
    pub block: Vec<BlockDevice>,
    pub net: Vec<NetIf>,
    /// Enumerated serial / UART ports the kernel sees, walked from
    /// `/sys/class/tty/ttyS*/`. Empty when arma built the
    /// PMI without `--serial`. Each entry carries the bound IRQ
    /// (0 = polled-mode fallback, nonzero = interrupt-driven), the
    /// I/O port or MMIO address, and the auto-detected UART type.
    #[serde(default)]
    pub serial: Vec<SerialPort>,
    /// Guest-selected timekeeping surfaces. This helps distinguish "host
    /// spent time in the VMM" from "guest selected a slow/poor clock path".
    #[serde(default)]
    pub clock: ClockInfo,
    /// Full guest kernel ring buffer captured immediately before the fixture
    /// emits the report.
    #[serde(default)]
    pub kernel_log: KernelLog,
    /// Lowercase hex of `/proc/device-tree/chosen/kaslr-seed` (8 bytes, the FDT's
    /// big-endian order) as the kernel received it — the guest-entropy seed tatu
    /// patched into the measured base DTB. A `CONFIG_RANDOMIZE_BASE` kernel zeroes
    /// it after consuming it; a non-KASLR kernel leaves tatu's value intact.
    /// `None` when the property is absent (x86, which has no device tree).
    #[serde(default)]
    pub kaslr_seed: Option<String>,
    /// Result of the guest-side virtio-vsock probe. `None` unless the kernel
    /// cmdline carries `dillo.vsock_port=N`, in which case the probe opens an
    /// `AF_VSOCK` stream to host CID 2 on that port and round-trips a message.
    #[serde(default)]
    pub vsock: Option<VsockResult>,
    /// Result of the guest-side virtio-fs probe on the read-write share. `None`
    /// unless the kernel cmdline carries `dillo.virtiofs_tag=TAG`, in which case
    /// the probe mounts that tag with `-t virtiofs`, lists the share root, reads
    /// `dillo.virtiofs_file=NAME` back, and writes a probe file to verify the
    /// guest→host write path.
    #[serde(default)]
    pub virtiofs: Option<FsResult>,
    /// Result of the guest-side virtio-fs probe on a *read-only* share. `None`
    /// unless `dillo.virtiofs_ro_tag=TAG` is present. The probe mounts it and
    /// attempts a write, which must be rejected (`wrote == false`).
    #[serde(default)]
    pub virtiofs_ro: Option<FsResult>,
    /// Result of the guest-side virtio-net probe. `None` unless the kernel
    /// cmdline carries `dillo.net_mac=MAC`, in which case the probe looks for a
    /// network interface whose MAC matches the host-assigned one — proving the
    /// guest's virtio-net driver bound the device and read its config-space MAC.
    #[serde(default)]
    pub net_probe: Option<NetProbe>,
    /// Result of the guest-side virtio-net **datapath** probe. `None` unless the
    /// cmdline requests it (`dillo.net_echo=IP:PORT` etc). Exercises the user-
    /// mode backend end to end: a TCP echo round-trip (with throughput), an
    /// optional UDP echo, and an optional inbound-forward accept.
    #[serde(default)]
    pub net_bench: Option<NetBench>,
}

/// Guest-side virtio-net datapath results. Like [`BlkBench`], snuffler measures
/// and verifies but asserts nothing; throughput is telemetry, only the
/// correctness invariants (bytes moved, errors == 0, verified) are gated in CI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetBench {
    /// Guest → host bytes (what the guest transmitted to the echo server).
    pub tx: NetOp,
    /// Host → guest bytes (the echo the guest read back); `verified` is whether
    /// it matched the transmitted payload byte-for-byte.
    pub rx: NetOp,
    /// A UDP echo round-trip via the gateway matched, when requested
    /// (`dillo.net_udp=IP:PORT`).
    #[serde(default)]
    pub udp_ok: Option<bool>,
    /// An inbound-forwarded host→guest connection was accepted and echoed, when
    /// requested (`dillo.net_listen=PORT`).
    #[serde(default)]
    pub forward_ok: Option<bool>,
    /// The guest reached the **real internet** through the user-mode proxy
    /// (masquerade): a TCP connection to a well-known external endpoint
    /// established and stayed up past the proxy's connect-timeout window (an
    /// unreachable host is RST within it). Set when requested
    /// (`dillo.net_reach=…`). Port-agnostic, so it works through firewalls that
    /// only permit outbound 443.
    #[serde(default)]
    pub external_ok: Option<bool>,
    /// Set when the datapath probe could not run to completion.
    #[serde(default)]
    pub error: Option<String>,
}

/// One direction of a [`NetBench`] transfer (mirrors [`BlkOp`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetOp {
    /// Total bytes transferred in this direction.
    pub bytes: u64,
    /// Number of read/write calls issued.
    pub ops: u64,
    /// Wall-clock duration in microseconds.
    pub duration_us: u64,
    /// `bytes / duration` in MiB/s (telemetry — noisy in a VM; do not gate CI).
    pub throughput_mibps: f64,
    /// Count of failed read/write calls.
    pub errors: u64,
    /// Whether the bytes were verified correct (echo matched). `None` when not
    /// applicable.
    #[serde(default)]
    pub verified: Option<bool>,
}

/// Outcome of the guest-side virtio-net probe: did an interface with the
/// host-assigned MAC appear, and what does the guest see about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetProbe {
    /// The MAC the host asked the guest to look for (`dillo.net_mac=MAC`).
    pub requested_mac: String,
    /// An interface with that MAC was found.
    pub found: bool,
    /// The matching interface name (e.g. `"eth0"`).
    #[serde(default)]
    pub iface: Option<String>,
    /// The interface's MAC as the guest reports it.
    #[serde(default)]
    pub mac: Option<String>,
    /// The interface MTU.
    #[serde(default)]
    pub mtu: Option<u32>,
    /// `/sys/class/net/<if>/operstate` (e.g. `"up"`, `"down"`, `"unknown"`).
    #[serde(default)]
    pub operstate: Option<String>,
    /// `/sys/class/net/<if>/carrier` as a bool, when readable (only when the
    /// link is administratively up).
    #[serde(default)]
    pub carrier: Option<bool>,
}

/// The fixed contents the virtio-fs probe writes into the share, so the host
/// harness can verify the guest→host write byte-for-byte.
pub const VIRTIOFS_PROBE_CONTENT: &str = "dillo-virtiofs-guest-write";
/// The file name the probe creates in the share root.
pub const VIRTIOFS_PROBE_FILE: &str = "dillo-probe.txt";

/// Outcome of the guest-side virtio-fs probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsResult {
    /// Mount tag the guest mounted.
    pub tag: String,
    /// The `mount -t virtiofs` succeeded.
    pub mounted: bool,
    /// Names in the share root, sorted (proves the READDIR path works).
    #[serde(default)]
    pub entries: Vec<String>,
    /// File the probe was asked to read (`dillo.virtiofs_file=NAME`).
    #[serde(default)]
    pub file: Option<String>,
    /// Contents read back from `file`, when the read succeeded.
    #[serde(default)]
    pub content: Option<String>,
    /// Whether the probe's create+write of [`VIRTIOFS_PROBE_FILE`] succeeded.
    #[serde(default)]
    pub wrote: bool,
    /// Error from the write attempt (expected/present on a read-only share).
    #[serde(default)]
    pub write_error: Option<String>,
    /// Failure detail, if any earlier stage errored.
    #[serde(default)]
    pub error: Option<String>,
}

/// Outcome of the guest-side virtio-vsock connectivity probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockResult {
    /// Host port the guest dialed (CID 2, `dillo.vsock_port=N`).
    pub port: u32,
    /// The `AF_VSOCK` connect succeeded.
    pub connected: bool,
    /// The host echoed the probe message back byte-for-byte.
    pub echo_ok: bool,
    /// Failure detail, if any stage errored.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    /// Number of CPUs the guest sees online.
    pub online_count: usize,
    /// Raw `/sys/devices/system/cpu/online` string (e.g. "0-1").
    pub online_list: String,
    /// First `model name` from `/proc/cpuinfo`, if present.
    pub model_name: Option<String>,
    /// `flags` line from `/proc/cpuinfo`, split on whitespace.
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_kib: u64,
    pub free_kib: u64,
    pub available_kib: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PciDevice {
    /// Bus:device.function (e.g. "0000:00:01.0").
    pub bdf: String,
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    /// Driver name from `/sys/bus/pci/devices/<bdf>/driver` symlink, if bound.
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDevice {
    /// `/sys/block/<name>` (e.g. "vda").
    pub name: String,
    /// `size` sysfs entry * 512.
    pub size_bytes: u64,
    pub vendor: Option<String>,
    pub model: Option<String>,
    /// `/sys/block/<name>/ro` (read-only). Default false for older reports.
    #[serde(default)]
    pub ro: bool,
    /// Raw-device I/O benchmark results, when the probe could open and exercise
    /// the device. `None` if benchmarking was skipped or failed (see
    /// [`BlkBench::error`] when present).
    #[serde(default)]
    pub bench: Option<BlkBench>,
}

/// Per-device raw I/O benchmark. snuffler measures throughput and verifies the
/// data path; it asserts nothing — host harnesses decide what matters. Numbers
/// are useful for finding bottlenecks outside CI; in CI only the correctness
/// invariants (bytes moved, zero errors, writes verified, RO rejected) are
/// stable enough to assert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlkBench {
    /// `"o_direct"` when the device was opened `O_DIRECT` (I/O bypasses the page
    /// cache and traverses virtio-blk), else `"buffered"`.
    pub mode: String,
    /// Sequential read of up to ~16 MiB in 64 KiB blocks from offset 0.
    pub seq_read: BlkOp,
    /// Random 4 KiB reads at aligned offsets.
    pub rand_read: BlkOp,
    /// Sequential write (read-write devices only).
    #[serde(default)]
    pub seq_write: Option<BlkOp>,
    /// Random 4 KiB writes at aligned offsets (read-write devices only).
    #[serde(default)]
    pub rand_write: Option<BlkOp>,
    /// Read-only devices only: whether opening the device `O_RDWR` was correctly
    /// rejected by the kernel (proves `VIRTIO_BLK_F_RO` enforcement).
    #[serde(default)]
    pub ro_write_rejected: Option<bool>,
    /// Set when the device could not be opened / benchmarked.
    #[serde(default)]
    pub error: Option<String>,
}

/// One benchmark operation's results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlkOp {
    /// Total bytes transferred.
    pub bytes: u64,
    /// Number of individual read/write calls issued.
    pub ops: u64,
    /// Wall-clock duration in microseconds.
    pub duration_us: u64,
    /// `bytes / duration` in MiB/s (telemetry — noisy in a VM; do not gate CI).
    pub throughput_mibps: f64,
    /// Count of failed read/write calls.
    pub errors: u64,
    /// For write ops: whether a full read-back matched the written pattern.
    /// `None` for read ops.
    #[serde(default)]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetIf {
    pub name: String,
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    pub operstate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialPort {
    /// `/sys/class/tty` entry name (e.g. `"ttyS0"`).
    pub name: String,
    /// `"port"` for I/O-port-mapped UARTs (8250 family), `"mem"` for
    /// MMIO UARTs (MMIO 8250), `"unknown"` otherwise.
    pub io_type: String,
    /// I/O port number (for `io_type == "port"`) or MMIO base address
    /// (for `io_type == "mem"`).
    pub address: Option<u64>,
    /// IRQ assigned to this port. `Some(0)` means polled-mode fallback
    /// (the driver couldn't find an IRQ in firmware tables); nonzero
    /// means interrupt-driven. `None` means the `irq` sysfs attribute
    /// wasn't readable (some drivers don't expose it).
    pub irq: Option<u32>,
    /// 8250 driver type code from `/sys/class/tty/<name>/type`. 5 =
    /// 16550A; absent for non-8250 drivers.
    pub uart_type_id: Option<u32>,
    /// Clock frequency (Hz) from `/sys/class/tty/<name>/uartclk` —
    /// `baud_base × 16` for the 8250 family.
    pub uartclk_hz: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClockInfo {
    /// `/sys/devices/system/clocksource/clocksource0/current_clocksource`.
    pub current_source: Option<String>,
    /// Split `/sys/devices/system/clocksource/clocksource0/available_clocksource`.
    pub available_sources: Vec<String>,
    /// `/sys/devices/system/clockevents/clockevent*/current_device`, sorted by CPU/index.
    pub event_devices: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KernelLog {
    /// Parsed kernel log records in ring-buffer order.
    pub entries: Vec<KernelLogEntry>,
    /// Error text if the fixture could not read `/proc/kmsg` via syslog(2).
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelLogEntry {
    /// Original kmsg line, without the trailing newline.
    pub raw: String,
    /// printk priority from the leading `<N>` prefix when present.
    pub level: Option<u8>,
    /// Seconds since boot from the leading `[ seconds ]` timestamp when present.
    pub timestamp_secs: Option<f64>,
    /// Message text after the printk prefix and timestamp when both parse.
    pub message: String,
}
