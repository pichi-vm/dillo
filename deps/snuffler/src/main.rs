// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! snuffler — the guest probe.
//!
//! Runs as PID 1 inside a guest booted from a PMI. Mounts /proc + /sys + /dev,
//! snuffles out the system the kernel sees (CPU/memory/cmdline/consoles/
//! PCI/block/net), benchmarks each block device, emits a [`Report`] JSON
//! bracketed by sentinels, then poweroffs. The probe contains no test logic —
//! host harnesses assert whatever they want against the [`Report`] (the crate's
//! library half).
//!
//! Output: bracketed JSON on stdout (which is /dev/console / hvc0 for PID 1
//! given `console=hvc0`). Free-form debug lines go to stderr.
//!
//! Linux-only (it's a Linux guest probe). All syscalls go through `rustix`'s
//! safe wrappers — no `unsafe`, no `libc`.

// The probe's entry point (`fn main`) is `#[cfg(not(test))]`, so under the
// `test` cfg it drops out and the whole init call tree it roots becomes
// unreachable dead code. The bin declares `test = false` (it has no unit
// tests — it is validated by real boots), but `cargo clippy --all-targets`
// still compiles it as a test target and flags every helper. Scope the allow
// to the `test` cfg only: the real bin (built via `--bins`) uses all of it.
#![cfg_attr(test, allow(dead_code))]

use std::fs;
use std::path::Path;

use rustix::fd::{AsFd, BorrowedFd};
use rustix::fs::{Mode, OFlags};
use snuffler::{
    BlockDevice, ClockInfo, CpuInfo, FsResult, KernelLog, KernelLogEntry, MemoryInfo, NetBench,
    NetIf, NetOp, NetProbe, PciDevice, REPORT_BEGIN, REPORT_END, Report, SerialPort,
    VIRTIOFS_PROBE_CONTENT, VIRTIOFS_PROBE_FILE, VsockResult,
};

mod bench;

#[cfg(not(test))]
fn main() {
    run();
}

/// Nanoseconds since kernel start (CLOCK_MONOTONIC), for high-resolution boot
/// timing captured at snuffler entry before any probing.
fn monotonic_ns() -> u64 {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn run() {
    // FIRST thing: stamp boot->userspace time before any probe work runs.
    let entry_ns = monotonic_ns();
    setup_mounts();
    reopen_console_stdio();
    // Cmdline-gated + additive: with `dillo.panic_report`, a panic (which as PID 1
    // would otherwise become abort()->`hlt`->GP-fault->kernel "Attempted to kill
    // init") is instead printed bracketed on the console and the VM is powered
    // off, making the panic diagnosable. Default behavior is unchanged.
    if std::fs::read_to_string("/proc/cmdline")
        .unwrap_or_default()
        .contains("dillo.panic_report")
    {
        std::panic::set_hook(Box::new(|info| {
            use std::io::Write as _;
            println!("<<<SNUFFLER-PANIC>>>{info}<<<END>>>");
            eprintln!("<<<SNUFFLER-PANIC>>>{info}<<<END>>>");
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();
            #[cfg(not(test))]
            poweroff();
        }));
    }
    let mut report = observe();
    // Gated + additive: only surface the ns timestamp when explicitly requested.
    if report
        .cmdline
        .split_whitespace()
        .any(|t| t == "dillo.uptime_ns")
    {
        report.boot_to_userspace_ns = Some(entry_ns);
    }
    let json = serde_json::to_string(&report)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialize: {e}\"}}"));
    write_report(&json);
    rustix::fs::sync();
    #[cfg(not(test))]
    poweroff();
}

/// Read the kernel ring buffer from `/dev/kmsg` (non-draining: yields the whole
/// buffer from the oldest record). Each `read` returns one record formatted as
/// `priority,seq,ts_usec,flags;message`.
fn read_kernel_log() -> KernelLog {
    let fd = match rustix::fs::open(
        "/dev/kmsg",
        OFlags::RDONLY | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => {
            return KernelLog {
                entries: Vec::new(),
                error: Some(format!("open /dev/kmsg: {e}")),
            };
        }
    };
    let mut entries = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match rustix::io::read(&fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let line = String::from_utf8_lossy(&buf[..n]);
                entries.push(parse_kmsg_record(line.trim_end_matches('\n')));
            }
            // AGAIN: ring buffer drained. EPIPE: records were overwritten while
            // reading — stop either way.
            Err(rustix::io::Errno::AGAIN) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => break,
        }
    }
    KernelLog {
        entries,
        error: None,
    }
}

/// Parse one `/dev/kmsg` record: `priority,seq,ts_usec,flags;message`. The
/// `message` text matches the printk message (what harnesses grep for); the
/// level is the printk priority and the timestamp is seconds since boot.
fn parse_kmsg_record(raw: &str) -> KernelLogEntry {
    let (meta, message) = raw.split_once(';').unwrap_or(("", raw));
    let mut fields = meta.split(',');
    let level = fields
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .map(|p| p & 0x07);
    let _seq = fields.next();
    let timestamp_secs = fields
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|us| us / 1_000_000.0);
    KernelLogEntry {
        raw: raw.to_owned(),
        level,
        timestamp_secs,
        message: message.to_owned(),
    }
}

fn setup_mounts() {
    // arma's cpio wrapper only stages /init; create every mountpoint we rely on
    // before mounting. devtmpfs in particular won't be auto-mounted by
    // CONFIG_DEVTMPFS_MOUNT because /dev doesn't exist on the initramfs rootfs.
    let _ = fs::create_dir("/proc");
    let _ = fs::create_dir("/sys");
    let _ = fs::create_dir("/dev");
    mount("proc", "/proc", "proc");
    mount("sysfs", "/sys", "sysfs");
    mount("devtmpfs", "/dev", "devtmpfs");
}

fn mount(src: &str, target: &str, fstype: &str) {
    use rustix::mount::{MountFlags, mount as do_mount};
    if let Err(e) = do_mount(src, target, fstype, MountFlags::empty(), None) {
        eprintln!("fixture: mount {src} -> {target} ({fstype}) failed: {e}");
    }
}

fn reopen_console_stdio() {
    // The kernel can start PID 1 with fd 0/1/2 closed if /dev/console was not
    // available before devtmpfs was mounted. Rebind them after setup_mounts().
    for path in ["/dev/hvc0", "/dev/console", "/dev/ttyS0"] {
        if let Ok(fd) = rustix::fs::open(path, OFlags::RDWR | OFlags::NONBLOCK, Mode::empty()) {
            let _ = rustix::stdio::dup2_stdin(&fd);
            let _ = rustix::stdio::dup2_stdout(&fd);
            let _ = rustix::stdio::dup2_stderr(&fd);
            return;
        }
    }
}

fn write_report(json: &str) {
    // Keep report emission independent of Rust stdio startup. This fixture runs
    // as PID 1 in a minimal initramfs.
    write_report_fd(rustix::stdio::stdout(), json);
    for path in ["/dev/hvc0", "/dev/console"] {
        if let Ok(fd) = rustix::fs::open(path, OFlags::WRONLY | OFlags::NONBLOCK, Mode::empty()) {
            write_report_fd(fd.as_fd(), json);
        }
    }
}

fn write_report_fd(fd: BorrowedFd<'_>, json: &str) {
    for bytes in [
        REPORT_BEGIN.as_bytes(),
        json.as_bytes(),
        REPORT_END.as_bytes(),
        b"\n",
    ] {
        write_all_fd(fd, bytes);
    }
}

fn write_all_fd(fd: BorrowedFd<'_>, mut bytes: &[u8]) {
    // The console fds are O_NONBLOCK, so a full UART FIFO / virtio-console ring
    // returns EAGAIN partway through a multi-KiB report. The original code gave up
    // on any error (EAGAIN included), silently truncating the report on a slow or
    // MMIO serial console so the host saw no `<<<DILLO-E2E-REPORT>>>…<<<END>>>`.
    // Retry EAGAIN with a bounded spin budget — enough for the FIFO to drain, but
    // finite so a genuinely dead console (no reader) can never hang PID 1.
    let mut eagain_budget: u32 = 50_000_000;
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(0) => return,
            Ok(n) => bytes = &bytes[n..],
            Err(rustix::io::Errno::AGAIN) if eagain_budget > 0 => {
                eagain_budget -= 1;
                core::hint::spin_loop();
            }
            Err(_) => return,
        }
    }
}

fn observe() -> Report {
    let cmdline = read_trim("/proc/cmdline");
    let vsock = probe_vsock(&cmdline);
    let (virtiofs, virtiofs_ro) = probe_virtiofs(&cmdline);
    let net = walk_net();
    let net_probe = probe_net(&cmdline, &net);
    let net_bench = probe_net_io(&cmdline);
    Report {
        arch: uname_machine(),
        uptime_secs: parse_uptime(),
        // Set later in run() when the cmdline requests it; None keeps the
        // report byte-identical by default.
        boot_to_userspace_ns: None,
        cpu: read_cpu(),
        memory: read_memory(),
        consoles: read_consoles(),
        pci: walk_pci(),
        block: walk_block(),
        net,
        serial: walk_serial(),
        clock: read_clock(),
        kernel_log: read_kernel_log(),
        kaslr_seed: read_kaslr_seed(),
        vsock,
        virtiofs,
        virtiofs_ro,
        net_probe,
        net_bench,
        cmdline,
    }
}

/// Probe virtio-net when the cmdline requests it (`dillo.net_mac=MAC`): find the
/// interface whose MAC matches the host-assigned one, proving the guest's
/// virtio-net driver bound the device and read its config-space MAC. `None` when
/// the token is absent, so ordinary boots never run it.
fn probe_net(cmdline: &str, ifaces: &[NetIf]) -> Option<NetProbe> {
    let requested_mac = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("dillo.net_mac="))?
        .to_owned();
    let matched = ifaces.iter().find(|n| {
        n.mac
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case(&requested_mac))
    });
    let carrier = matched.and_then(|n| {
        read_opt(Path::new(&format!("/sys/class/net/{}/carrier", n.name))).map(|s| s == "1")
    });
    Some(NetProbe {
        requested_mac,
        found: matched.is_some(),
        iface: matched.map(|n| n.name.clone()),
        mac: matched.and_then(|n| n.mac.clone()),
        mtu: matched.and_then(|n| n.mtu),
        operstate: matched.and_then(|n| n.operstate.clone()),
        carrier,
    })
}

/// Probe the virtio-net *datapath* when the cmdline requests it
/// (`dillo.net_echo=IP:PORT`). The guest is IP-configured by the kernel `ip=`
/// cmdline (`CONFIG_IP_PNP=y`), so this is pure `std::net` — no tooling, no
/// libc, no unsafe (mirroring the vsock probe). `None` when the token is absent.
///
/// - `dillo.net_echo=IP:PORT`  — TCP echo round-trip + throughput (required).
/// - `dillo.net_udp=IP:PORT`   — UDP echo round-trip (optional).
/// - `dillo.net_listen=PORT`   — accept one inbound-forwarded connection and
///   echo it, proving the host→guest direction (optional).
fn probe_net_io(cmdline: &str) -> Option<NetBench> {
    let echo = cmdline_token(cmdline, "dillo.net_echo=")?;
    let mut bench = run_tcp_echo(&echo);
    if let Some(udp) = cmdline_token(cmdline, "dillo.net_udp=") {
        bench.udp_ok = Some(run_udp_echo(&udp));
    }
    if let Some(port) = cmdline_token(cmdline, "dillo.net_listen=").and_then(|s| s.parse().ok()) {
        bench.forward_ok = Some(run_inbound_accept(port));
    }
    if let Some(endpoints) = cmdline_token(cmdline, "dillo.net_reach=") {
        bench.external_ok = Some(run_external_reach_probe(&endpoints));
    }
    Some(bench)
}

fn cmdline_token(cmdline: &str, prefix: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(prefix))
        .map(str::to_owned)
}

fn net_mibps(bytes: u64, us: u64) -> f64 {
    if us == 0 {
        0.0
    } else {
        (bytes as f64 / 1_048_576.0) / (us as f64 / 1_000_000.0)
    }
}

fn zero_net_op() -> NetOp {
    NetOp {
        bytes: 0,
        ops: 0,
        duration_us: 0,
        throughput_mibps: 0.0,
        errors: 0,
        verified: None,
    }
}

/// Connect to `addr` (IP:PORT), send a recognizable payload, and read the echo
/// back, measuring each direction and verifying the bytes round-trip intact.
fn run_tcp_echo(addr: &str) -> NetBench {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let mut bench = NetBench {
        tx: zero_net_op(),
        rx: zero_net_op(),
        udp_ok: None,
        forward_ok: None,
        external_ok: None,
        error: None,
    };

    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            bench.error = Some(format!("tcp connect {addr}: {e}"));
            return bench;
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    // 256 KiB of a recognizable pattern (multi-segment, but quick).
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();

    let t0 = Instant::now();
    let tx_err = stream.write_all(&payload).is_err();
    let _ = stream.flush();
    let tx_us = t0.elapsed().as_micros() as u64;
    bench.tx = NetOp {
        bytes: payload.len() as u64,
        ops: 1,
        duration_us: tx_us,
        throughput_mibps: net_mibps(payload.len() as u64, tx_us),
        errors: u64::from(tx_err),
        verified: None,
    };

    let mut got = vec![0u8; payload.len()];
    let t1 = Instant::now();
    let rx_res = stream.read_exact(&mut got);
    let rx_us = t1.elapsed().as_micros() as u64;
    let ok = rx_res.is_ok() && got == payload;
    bench.rx = NetOp {
        bytes: if rx_res.is_ok() {
            payload.len() as u64
        } else {
            0
        },
        ops: 1,
        duration_us: rx_us,
        throughput_mibps: net_mibps(payload.len() as u64, rx_us),
        errors: u64::from(rx_res.is_err()),
        verified: Some(ok),
    };
    bench
}

/// Send one UDP datagram to `addr` and confirm it echoes back byte-for-byte.
fn run_udp_echo(addr: &str) -> bool {
    use std::net::UdpSocket;
    use std::time::Duration;

    const MSG: &[u8] = b"dillo-udp-ping";
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    if sock.connect(addr).is_err() || sock.send(MSG).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    match sock.recv(&mut buf) {
        Ok(n) => &buf[..n] == MSG,
        Err(_) => false,
    }
}

/// Open a listener on `port` and echo one inbound (host→guest forwarded)
/// connection, proving the inbound direction. Bounded by a deadline so a missing
/// peer can't hang PID 1.
fn run_inbound_accept(port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) else {
        return false;
    };
    let _ = listener.set_nonblocking(true);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 4096];
                let mut echoed_any = false;
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                            echoed_any = true;
                        }
                    }
                }
                let _ = stream.flush();
                return echoed_any;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

/// Prove real-internet reach through the user-mode proxy (masquerade), without a
/// TLS stack and in a way that works through firewalls that only allow outbound
/// 443. For each comma-separated `IP:PORT` in `endpoints`, connect (the guest
/// reaches the proxy, which then dials the real host) and read with a timeout
/// longer than the proxy's connect-timeout:
///
/// - if the real host is **reachable**, the proxy holds the connection open and
///   the read times out (`WouldBlock`/`TimedOut`) with the connection still up
///   — reach proven;
/// - if it is **unreachable**, the proxy fails its connect and RSTs the guest
///   within its connect-timeout, so the read returns a connection error.
///
/// Returns `true` on the first endpoint that proves reachable (several are tried
/// so one flaky host can't fail it).
fn run_external_reach_probe(endpoints: &str) -> bool {
    use std::io::Read;
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    // Must exceed the proxy's 5s host-connect timeout so an unreachable host's
    // RST arrives before this read returns.
    const READ_TIMEOUT: Duration = Duration::from_secs(7);

    for endpoint in endpoints.split(',').filter(|s| !s.is_empty()) {
        // Endpoints are numeric IP:PORT (the reach probe asserts raw masquerade,
        // independent of name resolution), so this parse never hits the network.
        let Ok(mut addrs) = endpoint.to_socket_addrs() else {
            continue;
        };
        let Some(addr) = addrs.next() else { continue };
        // Connecting reaches the proxy (which accepts immediately, then dials the
        // real host); a short connect timeout is fine here.
        let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let mut buf = [0u8; 16];
        match (&stream).read(&mut buf) {
            // Data, or a clean close from the real host: it was reached.
            Ok(_) => return true,
            // Read timed out with the connection still up: reached and held.
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return true;
            }
            // A reset/abort (proxy couldn't reach the host): try the next one.
            Err(_) => continue,
        }
    }
    false
}

/// Probe virtio-fs when the cmdline requests it. `dillo.virtiofs_tag=TAG` drives
/// the read-write probe (mount, list, read `dillo.virtiofs_file=NAME`, then write
/// a probe file); `dillo.virtiofs_ro_tag=TAG` drives a read-only probe (mount,
/// attempt a write that must be rejected). Either is absent → `None`, so
/// ordinary boots never touch virtio-fs. Returns `(read_write, read_only)`.
fn probe_virtiofs(cmdline: &str) -> (Option<FsResult>, Option<FsResult>) {
    let token = |key: &str| {
        cmdline
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
            .map(str::to_owned)
    };
    let file = token("dillo.virtiofs_file=");
    let rw = token("dillo.virtiofs_tag=")
        .map(|tag| run_virtiofs_probe("/mnt-virtiofs", tag, file.clone()));
    let ro = token("dillo.virtiofs_ro_tag=")
        .map(|tag| run_virtiofs_probe("/mnt-virtiofs-ro", tag, None));
    (rw, ro)
}

fn run_virtiofs_probe(mountpoint: &str, tag: String, file: Option<String>) -> FsResult {
    use rustix::mount::{MountFlags, mount as do_mount};

    let mut res = FsResult {
        tag: tag.clone(),
        mounted: false,
        entries: Vec::new(),
        file: file.clone(),
        content: None,
        wrote: false,
        write_error: None,
        error: None,
    };

    let _ = fs::create_dir(mountpoint);
    // Mount read-write (no MountFlags::RDONLY): write rejection is enforced by
    // the *device* on a read-only share, which is what we want to exercise — not
    // the guest kernel's own mount flag.
    if let Err(e) = do_mount(
        tag.as_str(),
        mountpoint,
        "virtiofs",
        MountFlags::empty(),
        None,
    ) {
        res.error = Some(format!("mount: {e}"));
        return res;
    }
    res.mounted = true;

    if let Ok(rd) = fs::read_dir(mountpoint) {
        let mut entries: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        entries.sort();
        res.entries = entries;
    }

    if let Some(name) = file {
        match fs::read_to_string(format!("{mountpoint}/{name}")) {
            Ok(s) => res.content = Some(s),
            Err(e) => res.error = Some(format!("read {name}: {e}")),
        }
    }

    // Exercise the guest→host write path (create + write a probe file). On a
    // read-only share this is expected to fail with EROFS.
    match fs::write(
        format!("{mountpoint}/{VIRTIOFS_PROBE_FILE}"),
        VIRTIOFS_PROBE_CONTENT,
    ) {
        Ok(()) => res.wrote = true,
        Err(e) => res.write_error = Some(format!("write: {e}")),
    }

    res
}

/// Probe virtio-vsock when the cmdline requests it (`dillo.vsock_port=N`):
/// open an `AF_VSOCK` stream to host CID 2 on port N and round-trip a message.
/// `None` when the token is absent, so ordinary boots never touch vsock.
fn probe_vsock(cmdline: &str) -> Option<VsockResult> {
    let port = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("dillo.vsock_port="))
        .and_then(|v| v.parse::<u32>().ok())?;
    Some(run_vsock_probe(port))
}

fn run_vsock_probe(port: u32) -> VsockResult {
    use std::io::{Read, Write};

    /// Well-known host CID (`VMADDR_CID_HOST`).
    const VMADDR_CID_HOST: u32 = 2;
    const MSG: &[u8] = b"dillo-vsock-ping";

    let mut res = VsockResult {
        port,
        connected: false,
        echo_ok: false,
        error: None,
    };

    let mut stream =
        match vsock::VsockStream::connect(&vsock::VsockAddr::new(VMADDR_CID_HOST, port)) {
            Ok(s) => s,
            Err(e) => {
                res.error = Some(format!("connect cid={VMADDR_CID_HOST} port={port}: {e}"));
                return res;
            }
        };
    res.connected = true;

    // Bound the round-trip so a missing host peer can't hang PID 1 until the
    // harness's boot timeout.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));

    if let Err(e) = stream.write_all(MSG) {
        res.error = Some(format!("write: {e}"));
        return res;
    }

    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(n) => {
            res.echo_ok = &buf[..n] == MSG;
            if !res.echo_ok {
                res.error = Some(format!("echo mismatch ({n} bytes)"));
            }
        }
        Err(e) => res.error = Some(format!("read: {e}")),
    }
    res
}

/// Read the 8-byte `/chosen/kaslr-seed` the kernel received, as lowercase hex
/// (FDT big-endian order). `None` if absent (x86 / no device tree) or malformed.
fn read_kaslr_seed() -> Option<String> {
    let bytes = fs::read("/proc/device-tree/chosen/kaslr-seed").ok()?;
    if bytes.len() != 8 {
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn read_trim(p: &str) -> String {
    fs::read_to_string(p).unwrap_or_default().trim().to_owned()
}

fn uname_machine() -> String {
    rustix::system::uname()
        .machine()
        .to_string_lossy()
        .into_owned()
}

fn parse_uptime() -> f64 {
    read_trim("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0)
}

fn read_cpu() -> CpuInfo {
    let online_list = read_trim("/sys/devices/system/cpu/online");
    let online_count = count_cpu_range(&online_list);
    let (model_name, flags) = parse_cpuinfo();
    CpuInfo {
        online_count,
        online_list,
        model_name,
        flags,
    }
}

/// Parse a Linux cpulist (e.g. "0-3,5,7-8") into a count.
fn count_cpu_range(s: &str) -> usize {
    let mut n = 0usize;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>())
                && b >= a
            {
                n += b - a + 1;
            }
        } else if part.parse::<usize>().is_ok() {
            n += 1;
        }
    }
    n
}

fn parse_cpuinfo() -> (Option<String>, Vec<String>) {
    let s = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut model = None;
    let mut flags = Vec::new();
    for line in s.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if k == "model name" && model.is_none() {
            model = Some(v.to_owned());
        } else if (k == "flags" || k == "Features") && flags.is_empty() {
            // x86 uses "flags"; aarch64 uses "Features".
            flags = v.split_whitespace().map(str::to_owned).collect();
        }
    }
    (model, flags)
}

fn read_memory() -> MemoryInfo {
    let s = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let kv = |key: &str| -> u64 {
        for line in s.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            if k.trim() != key {
                continue;
            }
            return v
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        }
        0
    };
    MemoryInfo {
        total_kib: kv("MemTotal"),
        free_kib: kv("MemFree"),
        available_kib: kv("MemAvailable"),
    }
}

fn read_clock() -> ClockInfo {
    let base = "/sys/devices/system/clocksource/clocksource0";
    let current_source = read_opt(&Path::new(base).join("current_clocksource"));
    let available_sources = read_trim(&format!("{base}/available_clocksource"))
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let mut event_devices = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/devices/system/clockevents") {
        for e in entries.flatten() {
            let path = e.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with("clockevent") {
                continue;
            }
            if let Some(device) = read_opt(&path.join("current_device")) {
                event_devices.push(format!("{name}:{device}"));
            }
        }
    }
    event_devices.sort();
    ClockInfo {
        current_source,
        available_sources,
        event_devices,
    }
}

fn read_consoles() -> Vec<String> {
    fs::read_to_string("/proc/consoles")
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn walk_pci() -> Vec<PciDevice> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        let bdf = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        let driver = fs::read_link(path.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        out.push(PciDevice {
            bdf,
            vendor: read_hex(&path.join("vendor")) as u16,
            device: read_hex(&path.join("device")) as u16,
            class: read_hex(&path.join("class")),
            driver,
        });
    }
    out.sort_by(|a, b| a.bdf.cmp(&b.bdf));
    out
}

fn read_hex(p: &Path) -> u32 {
    let s = fs::read_to_string(p).unwrap_or_default();
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).unwrap_or(0)
}

fn walk_block() -> Vec<BlockDevice> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        let size_sectors: u64 = fs::read_to_string(path.join("size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let vendor = read_opt(&path.join("device/vendor"));
        let model = read_opt(&path.join("device/model"));
        let ro = read_opt(&path.join("ro")).as_deref() == Some("1");
        let size_bytes = size_sectors.saturating_mul(512);
        let bench = bench::benchmark_device(&name, size_bytes, ro);
        out.push(BlockDevice {
            name,
            size_bytes,
            vendor,
            model,
            ro,
            bench,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn walk_net() -> Vec<NetIf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        let mac = read_opt(&path.join("address"));
        let mtu = fs::read_to_string(path.join("mtu"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let operstate = read_opt(&path.join("operstate"));
        out.push(NetIf {
            name,
            mac,
            mtu,
            operstate,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn read_opt(p: &Path) -> Option<String> {
    let s = fs::read_to_string(p).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

fn walk_serial() -> Vec<SerialPort> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/tty") else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        // Only enumerate UART-shaped tty entries — ttyS* (8250). Skip ttyN (vt),
        // tty, pts/*, etc.
        if !name.starts_with("ttyS") {
            continue;
        }
        // /sys/class/tty/<n>/type is the kernel's `tmp.type` value — 0 means
        // PORT_UNKNOWN, what the kernel reports for every pre-allocated 8250 slot
        // the driver never bound. Skip those; only emit ports the driver owns.
        let uart_type_id: Option<u32> = read_opt(&path.join("type")).and_then(|s| s.parse().ok());
        if uart_type_id.is_none_or(|t| t == 0) {
            continue;
        }
        // io_type is the numeric UPIO_* constant: 0 = PORT (I/O port), 2 = MEM
        // (8-bit MMIO), 3 = MEM32 (32-bit MMIO).
        let io_type_raw = read_opt(&path.join("io_type"));
        let (io_type, address) = match io_type_raw.as_deref() {
            Some("0") => (
                "port".to_string(),
                read_opt(&path.join("port")).and_then(parse_hex_or_dec_u64),
            ),
            Some("2") | Some("3") => (
                "mem".to_string(),
                read_opt(&path.join("iomem_base")).and_then(parse_hex_or_dec_u64),
            ),
            _ => ("unknown".to_string(), None),
        };
        let irq = read_opt(&path.join("irq")).and_then(|s| s.parse().ok());
        let uartclk_hz = read_opt(&path.join("uartclk")).and_then(|s| s.parse().ok());
        out.push(SerialPort {
            name,
            io_type,
            address,
            irq,
            uart_type_id,
            uartclk_hz,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn parse_hex_or_dec_u64(s: String) -> Option<u64> {
    let trimmed = s.trim();
    if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(rest, 16).ok()
    } else {
        trimmed.parse().ok()
    }
}

#[cfg(not(test))]
fn poweroff() -> ! {
    let _ = rustix::system::reboot(rustix::system::RebootCommand::PowerOff);
    // Defensive: if reboot somehow returns, never let PID 1 exit (the kernel
    // would panic).
    loop {
        std::thread::park();
    }
}
