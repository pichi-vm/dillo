// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! dillo entrypoint.
//!
//! Parse PMI, build the launch plan, select the host Machine, and boot it.

use std::sync::atomic::AtomicBool;

use argh::FromArgs;
use dillo_machine::Host;
use machine_select::machine;
use machine_select::runner;

static SUPERVISOR_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// VMM that boots PMI files (Linux/KVM today).
#[derive(FromArgs, Debug)]
struct Args {
    /// path to the PMI file to boot — required in boot mode, ignored
    /// in backend mode.
    #[argh(option)]
    pmi: Option<std::path::PathBuf>,

    /// guest RAM in MiB (default 1024).
    #[argh(option, default = "1024")]
    memory: u32,

    /// number of vCPUs (default 1).
    #[argh(option, default = "1")]
    cpus: u32,

    /// console device. `stdio` (default), or key/value with placement, e.g.
    /// `endpoint=stdio,bus=mmio,slot=0`.
    #[argh(option)]
    console: Option<dillo_config::ConsoleSpec>,

    /// default bus for devices that don't pin one, when the DTB exposes both:
    /// `pci` (default) or `mmio`.
    #[argh(option)]
    bus: Option<dillo_config::Bus>,

    /// virtio-blk device (raw image). Repeatable. Key/value:
    /// `path=P[,readonly][,bus=pci|mmio][,slot=N]`.
    #[argh(option)]
    blk: Vec<dillo_config::BlkSpec>,

    /// virtualized-GPT device (one GPT synthesized over its partitions).
    /// Repeatable. Key/value, e.g.
    /// `partitions=[[path=P,partuuid=U,typeguid=U,label=S]][,bus=pci|mmio][,slot=N]`;
    /// `device-id`/`disk-guid` are derived from the PARTUUIDs if omitted.
    #[argh(option)]
    gpt: Vec<dillo_config::GptSpec>,

    /// virtio-vsock device (host CID 2 ⇄ guest). Repeatable. Key/value:
    /// `cid=N,uds=PATH[,bus=pci|mmio][,slot=N]`. Guest connections to port N
    /// bridge to `PATH/N.sock` on the host. Unix hosts only.
    #[cfg(unix)]
    #[argh(option)]
    vsock: Vec<dillo_config::VsockSpec>,

    /// virtio-fs device: share a host directory into the guest (read-write by
    /// default; pass `readonly` to forbid guest writes). Repeatable. Key/value:
    /// `tag=NAME,source=DIR[,readonly][,bus=pci|mmio][,slot=N]`. The guest mounts
    /// it with `mount -t virtiofs NAME <dir>`.
    #[argh(option)]
    fs: Vec<dillo_config::FsSpec>,

    /// virtio-net device. Repeatable. Key/value:
    /// `[backend=user|bridge|macvtap][,iface=NAME][,mac=aa:bb:cc:dd:ee:ff]`
    /// `[,forwards=[2222:22,udp:5353:53]][,bus=pci|mmio][,slot=N]`.
    /// `user` (the default) is cross-platform user-mode NAT with inbound port
    /// forwarding and needs no privilege; `bridge` (Linux/macOS, needs
    /// CAP_NET_ADMIN/root) joins the host's L2 segment via `iface`; `macvtap`
    /// is Linux-only.
    #[argh(option)]
    net: Vec<dillo_config::NetSpec>,

    /// path to a JSON device layout file. Mutually exclusive with
    /// `--blk`/`--gpt`/`--vsock`/`--fs`/`--net`/`--bus`/`--console`.
    #[argh(option)]
    layout: Option<std::path::PathBuf>,

    /// eagerly commit all guest RAM up front (fallocate) so hugepage-pool
    /// exhaustion fails at launch instead of a mid-run SIGBUS. Default is
    /// lazy first-touch commit (faster boot, denser warm pools). Linux/KVM
    /// only; ignored on other backends.
    #[argh(switch)]
    preallocate: bool,
}

/// Boot-time tracer for decomposing VMM setup latency (PMI parse, placement,
/// memslot/vCPU bring-up) from in-guest boot time; the guest side is measured
/// separately via snuffler's `uptime_secs`. [`mark`] logs `<label> +<micros>us`
/// at `trace` level under the `dillo::boot` target — enable with
/// `RUST_LOG=dillo::boot=trace`. Off by default, and the clock is not even read
/// unless the target is enabled, so it never perturbs a normal boot.
mod boot_trace {
    use std::sync::OnceLock;
    use std::time::Instant;

    /// t0 anchor, set lazily on the first mark while tracing is enabled.
    static START: OnceLock<Instant> = OnceLock::new();

    pub(crate) fn mark(label: &str) {
        if !log::log_enabled!(target: "dillo::boot", log::Level::Trace) {
            return;
        }
        let start = START.get_or_init(Instant::now);
        log::trace!(target: "dillo::boot", "{label} +{}us", start.elapsed().as_micros());
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    boot_trace::mark("start");
    let args: Args = argh::from_env();

    // Validate BEFORE entering raw mode — otherwise a validation
    // failure hits std::process::exit(2), which bypasses the RawStdio
    // Drop guard and leaves the terminal mangled.
    if let Err(e) = validate(&args) {
        eprintln!("dillo: {e}");
        std::process::exit(2);
    }
    // Guest-RAM commit policy. Lazy first-touch by default; `--preallocate`
    // opts into eager fallocate. Only the KVM backend honors this (hugetlb);
    // it is accepted but inert on other backends.
    #[cfg(target_os = "linux")]
    machine::set_preallocate(args.preallocate);
    #[cfg(not(target_os = "linux"))]
    let _ = args.preallocate;
    let pmi = args.pmi.clone().expect("validated");
    let memory = args.memory;
    let cpus = args.cpus;

    let launch = match launch::LaunchPlan::read(
        &pmi,
        <machine::Vm as Host>::ARCH,
        <machine::Vm as Host>::cpu_compatible(),
        memory,
        cpus,
    ) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("dillo: {e}");
            std::process::exit(e.exit_code());
        }
    };
    let launch::LaunchPlan {
        parsed,
        platform,
        merged_dtb,
        memory: memory_plan,
        guest_writes,
        pmi: pmi_image,
    } = launch;
    boot_trace::mark("launch_read");

    // Resolve the device layout, open backing files, and allocate bus/slots
    // NOW so config/I/O/placement errors surface before we enter raw terminal
    // mode (which a process::exit would leave mangled).
    let placements = match build_placements(&args, &platform) {
        Ok(placements) => placements,
        Err(e) => {
            eprintln!("dillo: {e:#}");
            std::process::exit(2);
        }
    };

    let preflight = runner::Preflight::new(
        parsed,
        platform,
        merged_dtb,
        memory_plan.memslots.iter().map(|r| runner::RunRegion {
            gpa: r.gpa,
            size: r.size,
        }),
        memory_plan.memory_nodes.iter().map(|r| runner::RunRegion {
            gpa: r.gpa,
            size: r.size,
        }),
        guest_writes.into_iter().map(|w| runner::RunWrite {
            section: w.section,
            gpa: w.gpa,
            data: w.data,
        }),
        placements,
        pmi_image,
    );
    boot_trace::mark("preflight");

    // Per ARCH §13.5: if stdin is a TTY, enter raw mode for the
    // session. A Drop guard restores cooked mode at exit; a custom
    // panic hook restores it before printing the panic message so
    // the user's terminal isn't left mangled after a crash.
    let _raw_guard = <machine::Vm as Host>::enter_raw_stdio_if_tty();
    <machine::Vm as Host>::install_panic_terminal_restore();

    // Per ARCH §13.2: 1st SIGINT/SIGTERM asks for graceful guest
    // shutdown with a ~5s grace; 2nd SIGINT or SIGQUIT hard-kills.
    // Install the watcher BEFORE starting any vCPU threads so
    // signals aren't silently dropped during boot. SIGWINCH is also
    // blocked so the watcher can forward terminal-resize events to
    // the (future Phase 3) console child.
    <machine::Vm as Host>::install_signal_watchers(&SUPERVISOR_SHUTDOWN);

    log::info!(
        "dillo starting: pmi={} memory={}MiB cpus={}",
        pmi.display(),
        memory,
        cpus,
    );

    boot_trace::mark("run_enter");
    match runner::run(preflight, cpus, &SUPERVISOR_SHUTDOWN) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("dillo: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                eprintln!("  caused by: {s}");
                src = s.source();
            }
            std::process::exit(e.exit_code());
        }
    }
}

fn validate(args: &Args) -> Result<(), &'static str> {
    if args.pmi.is_none() {
        return Err("--pmi required");
    }
    if args.memory == 0 || !args.memory.is_multiple_of(2) {
        return Err("--memory must be a positive even number of MiB");
    }
    if args.cpus == 0 {
        return Err("--cpus must be >= 1");
    }
    Ok(())
}

/// Build the parsed [`dillo_config::Layout`] from the CLI flags or a `--layout` JSON
/// file. The two are mutually exclusive.
fn layout_from_args(args: &Args) -> anyhow::Result<dillo_config::Layout> {
    use anyhow::Context as _;
    if let Some(path) = &args.layout {
        anyhow::ensure!(
            args.blk.is_empty()
                && args.gpt.is_empty()
                && args.fs.is_empty()
                && args.net.is_empty()
                && args.bus.is_none()
                && args.console.is_none(),
            "--layout is mutually exclusive with --blk/--gpt/--fs/--vsock/--net/--bus/--console"
        );
        #[cfg(unix)]
        anyhow::ensure!(
            args.vsock.is_empty(),
            "--layout is mutually exclusive with --blk/--gpt/--fs/--vsock/--bus/--console"
        );
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading layout file {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("parsing layout file {}", path.display()))
    } else {
        // argh collects --blk/--gpt/--fs into separate vecs, so the interleaved
        // command-line order is not preserved; blk precede gpt precede fs.
        // Use `slot=`/`--layout` for exact ordering control.
        // `mut` is only needed for the cfg(unix) vsock extension below; on
        // non-Unix the binding is never mutated.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut devices: Vec<dillo_config::Device> = args
            .blk
            .iter()
            .cloned()
            .map(dillo_config::Device::Blk)
            .chain(args.gpt.iter().cloned().map(dillo_config::Device::Gpt))
            .chain(args.fs.iter().cloned().map(dillo_config::Device::Fs))
            .chain(args.net.iter().cloned().map(dillo_config::Device::Net))
            .collect();
        #[cfg(unix)]
        devices.extend(args.vsock.iter().cloned().map(dillo_config::Device::Vsock));
        Ok(dillo_config::Layout {
            bus: args.bus,
            console: args.console.clone(),
            devices,
        })
    }
}

/// Resolve the layout, open backing files, and allocate a bus + slot for the
/// console and every device. Runs before raw terminal mode so all config / I/O
/// / placement errors surface cleanly.
fn build_placements(
    args: &Args,
    platform: &dillo_devtree::platform::Machine,
) -> anyhow::Result<Vec<runner::DevicePlacement>> {
    use dillo_virtio::VirtioDevice;

    let resolved = dillo_config::resolve(layout_from_args(args)?)?;

    // Requests + constructed devices, console first.
    let mut requests: Vec<dillo_config::Placement> = Vec::with_capacity(resolved.devices.len() + 1);
    let mut built: Vec<(u16, &'static str, Box<dyn VirtioDevice>)> = Vec::new();

    requests.push(resolved.console.placement.clone());
    built.push((
        3, // 2 queues + config
        "virtio-console",
        Box::new(dillo_virtio_console::VirtioConsole::new()),
    ));

    for device in &resolved.devices {
        requests.push(device.placement().clone());
        match device {
            #[cfg(unix)]
            dillo_config::ResolvedDevice::Vsock { cid, uds, .. } => {
                // 3 queues (rx/tx/event) + 1 config vector.
                built.push((
                    4,
                    "virtio-vsock",
                    Box::new(dillo_virtio_vsock::VirtioVsock::new(*cid, uds.clone())),
                ));
            }
            #[cfg(not(unix))]
            dillo_config::ResolvedDevice::Vsock { .. } => {
                anyhow::bail!("virtio-vsock is only supported on Unix hosts");
            }
            dillo_config::ResolvedDevice::Fs {
                tag,
                source,
                readonly,
                ..
            } => {
                use anyhow::Context as _;
                // 1 hiprio + 1 request queue + 1 config vector.
                let fs = dillo_virtio_fs::VirtioFs::passthrough(tag, source.clone(), *readonly)
                    .with_context(|| format!("sharing virtio-fs source {}", source.display()))?;
                built.push((3, "virtio-fs", Box::new(fs)));
            }
            dillo_config::ResolvedDevice::Net {
                backend,
                iface,
                mac,
                forwards,
                ..
            } => {
                let net = build_net_device(*backend, iface.as_deref(), *mac, forwards)?;
                // 2 queues (rx/tx) + 1 config vector.
                built.push((3, "virtio-net", Box::new(net)));
            }
            other => {
                let (name, blk) = build_block_device(other)?;
                built.push((2, name, Box::new(blk)));
            }
        }
    }

    let capacity = capacity_from_platform(platform);
    let default_bus = resolved.default_bus.unwrap_or(dillo_config::Bus::Pci);
    let placed = dillo_config::allocate(&capacity, default_bus, &requests)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(placed
        .into_iter()
        .zip(built)
        .map(
            |(placed, (msix_vectors, name, device))| runner::DevicePlacement {
                bus: placed.bus,
                index: placed.index,
                msix_vectors,
                name,
                device,
            },
        )
        .collect())
}

/// Construct the `VirtioBlk` for one resolved device (opening its backing files).
fn build_block_device(
    device: &dillo_config::ResolvedDevice,
) -> anyhow::Result<(&'static str, dillo_virtio_blk::VirtioBlk)> {
    use anyhow::Context as _;
    use dillo_virtio_blk::VirtioBlk;
    match device {
        dillo_config::ResolvedDevice::Blk { path, readonly, .. } => {
            let blk = VirtioBlk::open_raw(path, *readonly)
                .with_context(|| format!("opening blk image {}", path.display()))?;
            Ok(("virtio-blk", blk))
        }
        dillo_config::ResolvedDevice::Gpt {
            device_id,
            disk_guid,
            partitions,
            ..
        } => {
            let specs = partitions
                .iter()
                .map(|p| dillo_virtio_gpt::PartitionSpec {
                    path: p.path.clone(),
                    partuuid: p.partuuid,
                    typeguid: p.typeguid,
                    label: p.label.clone(),
                    attrs: p.attrs,
                })
                .collect();
            let backing = dillo_virtio_gpt::assemble(*device_id, *disk_guid, specs)?;
            // Virtualized-GPT is read-only by construction (no writable fd).
            Ok((
                "virtio-gpt",
                VirtioBlk::new(std::sync::Arc::new(backing), None, true),
            ))
        }
        // vsock/fs devices are dispatched in `build_placements` before reaching
        // here.
        dillo_config::ResolvedDevice::Vsock { .. } => {
            anyhow::bail!("internal: build_block_device called for a vsock device")
        }
        dillo_config::ResolvedDevice::Fs { .. } => {
            anyhow::bail!("internal: build_block_device called for a fs device")
        }
        dillo_config::ResolvedDevice::Net { .. } => {
            anyhow::bail!("internal: build_block_device called for a net device")
        }
    }
}

/// Construct a `VirtioNet` with the requested host backend. The `user` backend
/// (default, no privilege) works on every host; `bridge`/`macvtap` need
/// privilege and surface a clean error where unsupported.
fn build_net_device(
    backend: dillo_config::NetBackendKind,
    iface: Option<&str>,
    mac: [u8; 6],
    forwards: &[dillo_config::ResolvedForward],
) -> anyhow::Result<dillo_virtio_net::VirtioNet> {
    use dillo_config::NetBackendKind;
    use dillo_virtio_net::{NetBackend, VirtioNet};

    // `iface` is consumed only by the Linux bridge/macvtap arms.
    #[cfg(not(target_os = "linux"))]
    let _ = iface;

    let backend: std::sync::Arc<dyn NetBackend> = match backend {
        NetBackendKind::User => {
            use anyhow::Context as _;
            let rules: Vec<dillo_virtio_net::Forward> =
                forwards.iter().map(translate_forward).collect();
            let user = dillo_virtio_net::UserNetBackend::new(rules)
                .context("starting user-mode network (smoltcp)")?;
            std::sync::Arc::new(user)
        }
        #[cfg(target_os = "linux")]
        NetBackendKind::Bridge => {
            use anyhow::Context as _;
            let name = iface.context("net backend `bridge` requires iface=<bridge-name>")?;
            let bridge = dillo_virtio_net::BridgeBackend::open(name).with_context(|| {
                format!("creating+enslaving a tap on bridge {name:?} (needs CAP_NET_ADMIN)")
            })?;
            log::info!(
                "virtio-net: bridge backend, tap {:?} on {:?}",
                bridge.tap_name(),
                bridge.bridge()
            );
            std::sync::Arc::new(bridge)
        }
        #[cfg(target_os = "linux")]
        NetBackendKind::Macvtap => {
            use anyhow::Context as _;
            let name = iface.context("net backend `macvtap` requires iface=<macvtapN>")?;
            let mv = dillo_virtio_net::MacvtapBackend::open(name)
                .with_context(|| format!("attaching macvtap {name:?}"))?;
            std::sync::Arc::new(mv)
        }
        #[cfg(target_os = "macos")]
        NetBackendKind::Bridge => {
            use anyhow::Context as _;
            let name = iface.context("net backend `bridge` requires iface=<physical-interface>")?;
            let vmnet = dillo_virtio_net::VmnetBackend::open(name).with_context(|| {
                format!("starting vmnet bridged mode on {name:?} (needs root/entitlement)")
            })?;
            log::info!("virtio-net: vmnet bridge on {:?}", vmnet.physical());
            std::sync::Arc::new(vmnet)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        NetBackendKind::Bridge => {
            anyhow::bail!("net backend `bridge` is unsupported on this host (Windows)");
        }
        #[cfg(not(target_os = "linux"))]
        NetBackendKind::Macvtap => {
            anyhow::bail!("net backend `macvtap` is Linux-only; use backend=user on this host");
        }
    };
    Ok(VirtioNet::new(mac, backend))
}

/// Translate a resolved config forward into the net crate's own `Forward` type
/// (which is independent of `dillo-config`).
fn translate_forward(f: &dillo_config::ResolvedForward) -> dillo_virtio_net::Forward {
    let proto = match f.proto {
        dillo_config::Proto::Tcp => dillo_virtio_net::Proto::Tcp,
        dillo_config::Proto::Udp => dillo_virtio_net::Proto::Udp,
    };
    dillo_virtio_net::Forward {
        proto,
        host_ip: f.ip,
        host_port: f.host_port,
        guest_port: f.guest_port,
    }
}

/// Derive placement capacity from the surveyed platform: PCI functions (device
/// numbers 1..=N, bounded by the BAR window) when PCIe is present, plus the
/// declared virtio-mmio slot count.
fn capacity_from_platform(platform: &dillo_devtree::platform::Machine) -> dillo_config::Capacity {
    // Each virtio PCI function consumes one 0x2000 BAR stride in the MMIO window.
    const BAR_STRIDE: u64 = 0x2000;
    let pci = platform.has_pcie.then(|| {
        let by_window = (platform.pcie.mmio_size / BAR_STRIDE) as u32;
        by_window.min(31) // PCI device numbers 1..=31 (slot 0 = host bridge)
    });
    dillo_config::Capacity {
        pci,
        mmio: platform.virtio_mmio.len() as u32,
    }
}

mod fdt_writer {

    #![allow(clippy::cast_possible_truncation)]

    const FDT_MAGIC: u32 = 0xD00D_FEED;
    const FDT_VERSION: u32 = 17;
    const FDT_LAST_COMPATIBLE: u32 = 16;

    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_END: u32 = 9;

    /// Builder that accumulates structure and strings blocks, then emits
    /// a complete FDT v17 blob via [`Self::finish`].
    pub(crate) struct FdtBuilder {
        structure: Vec<u8>,
        strings: Vec<u8>,
        string_offsets: Vec<(String, u32)>,
    }

    impl FdtBuilder {
        pub(crate) fn new() -> Self {
            Self {
                structure: Vec::with_capacity(1024),
                strings: Vec::with_capacity(256),
                string_offsets: Vec::new(),
            }
        }

        pub(crate) fn begin_node(&mut self, name: &str) {
            self.structure
                .extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
            self.structure.extend_from_slice(name.as_bytes());
            self.structure.push(0);
            self.pad4();
        }

        pub(crate) fn end_node(&mut self) {
            self.structure
                .extend_from_slice(&FDT_END_NODE.to_be_bytes());
        }

        pub(crate) fn property(&mut self, name: &str, value: &[u8]) {
            let off = self.intern_string(name);
            self.structure.extend_from_slice(&FDT_PROP.to_be_bytes());
            self.structure
                .extend_from_slice(&(value.len() as u32).to_be_bytes());
            self.structure.extend_from_slice(&off.to_be_bytes());
            self.structure.extend_from_slice(value);
            self.pad4();
        }

        pub(crate) fn property_u32(&mut self, name: &str, v: u32) {
            self.property(name, &v.to_be_bytes());
        }

        pub(crate) fn property_string(&mut self, name: &str, v: &str) {
            let mut bytes = Vec::with_capacity(v.len() + 1);
            bytes.extend_from_slice(v.as_bytes());
            bytes.push(0);
            self.property(name, &bytes);
        }

        /// Emit a `reg = <hi32 lo32 hi32 lo32>` property from a single
        /// (base, size) pair, encoded as four big-endian u32 cells.
        pub(crate) fn property_reg_2cells(&mut self, name: &str, base: u64, size: u64) {
            let cells: [u32; 4] = [
                (base >> 32) as u32,
                base as u32,
                (size >> 32) as u32,
                size as u32,
            ];
            let mut bytes = Vec::with_capacity(16);
            for c in cells {
                bytes.extend_from_slice(&c.to_be_bytes());
            }
            self.property(name, &bytes);
        }

        pub(crate) fn finish(mut self) -> Vec<u8> {
            // Append FDT_END at end of structure block.
            self.structure.extend_from_slice(&FDT_END.to_be_bytes());

            // Header is 40 bytes.
            let header_len: u32 = 40;
            // Memreserve block: one terminator (16 bytes of zeros).
            let memrsv_len: u32 = 16;
            // Layout: [header][memreserve][structure][strings]
            let off_mem_rsvmap = header_len;
            let off_dt_struct = off_mem_rsvmap + memrsv_len;
            let size_dt_struct = self.structure.len() as u32;
            let off_dt_strings = off_dt_struct + size_dt_struct;
            let size_dt_strings = self.strings.len() as u32;
            let totalsize = off_dt_strings + size_dt_strings;

            let mut out = Vec::with_capacity(totalsize as usize);
            out.extend_from_slice(&FDT_MAGIC.to_be_bytes());
            out.extend_from_slice(&totalsize.to_be_bytes());
            out.extend_from_slice(&off_dt_struct.to_be_bytes());
            out.extend_from_slice(&off_dt_strings.to_be_bytes());
            out.extend_from_slice(&off_mem_rsvmap.to_be_bytes());
            out.extend_from_slice(&FDT_VERSION.to_be_bytes());
            out.extend_from_slice(&FDT_LAST_COMPATIBLE.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
            out.extend_from_slice(&size_dt_strings.to_be_bytes());
            out.extend_from_slice(&size_dt_struct.to_be_bytes());
            // Memreserve terminator.
            out.extend_from_slice(&[0u8; 16]);
            // Structure block.
            out.extend_from_slice(&self.structure);
            // Strings block.
            out.extend_from_slice(&self.strings);
            out
        }

        fn pad4(&mut self) {
            while !self.structure.len().is_multiple_of(4) {
                self.structure.push(0);
            }
        }

        fn intern_string(&mut self, name: &str) -> u32 {
            if let Some((_, off)) = self.string_offsets.iter().find(|(n, _)| n == name) {
                return *off;
            }
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            self.string_offsets.push((name.to_string(), off));
            off
        }
    }
}

mod placement {

    use thiserror::Error;

    const HUGE_PAGE: u64 = 2 << 20;

    /// One contiguous region for either a memslot or a `/memory@N` node.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Region {
        pub(crate) gpa: u64,
        pub(crate) size: u64,
    }

    #[derive(Debug, Clone, Copy)]
    struct Interval {
        start: u64,
        end: u64, // exclusive
    }

    /// The full memory plan: memslots == memory_nodes by construction.
    #[derive(Debug)]
    pub(crate) struct MemoryPlan {
        pub(crate) memslots: Vec<Region>,
        pub(crate) memory_nodes: Vec<Region>,
    }

    #[derive(Debug, Error)]
    pub(crate) enum PlanError {
        #[error(
            "--memory {requested_mib} MiB is less than the {islands_mib} MiB required to cover \
             loaded sections + reset trampoline"
        )]
        TooLittleMemory {
            requested_mib: u64,
            islands_mib: u64,
        },
        #[error(
            "no contiguous {remaining_mib} MiB chunk fits below the 4 GiB identity-map ceiling \
             after carving out islands and device regions"
        )]
        NoSpaceForBigChunk { remaining_mib: u64 },
    }

    /// Identity-map ceiling on x86: 4 GiB. Big chunk must end at or below this
    /// (so its GPAs are reachable from tatu's 4 GiB identity pgtable).
    const IDENTITY_CEILING: u64 = 1u64 << 32;

    pub(crate) fn plan_around_regions<I>(
        must_cover: &[(u64, u64)],
        memory_mib: u32,
        device_regions: I,
    ) -> Result<MemoryPlan, PlanError>
    where
        I: IntoIterator<Item = (u64, u64)>,
    {
        let budget = round_up_2mib(u64::from(memory_mib) * (1 << 20));

        // ── 1. Islands ────────────────────────────────────────────────
        let mut islands: Vec<Interval> = must_cover
            .iter()
            .filter(|(_, s)| *s > 0)
            .map(|&(gpa, size)| Interval {
                start: gpa & !(HUGE_PAGE - 1),
                end: round_up_2mib(gpa.saturating_add(size)),
            })
            .collect();
        merge_intervals(&mut islands);

        let islands_total: u64 = islands.iter().map(|i| i.end - i.start).sum();

        log::debug!(
            "placement: budget={} MiB, islands={} ({} MiB)",
            budget >> 20,
            islands.len(),
            islands_total >> 20,
        );
        for i in &islands {
            log::debug!(
                "  island [{:#x}..{:#x}) ({} MiB)",
                i.start,
                i.end,
                (i.end - i.start) >> 20,
            );
        }

        if islands_total > budget {
            return Err(PlanError::TooLittleMemory {
                requested_mib: budget >> 20,
                islands_mib: islands_total >> 20,
            });
        }
        let remaining = budget - islands_total;

        // ── 2. Big chunk ─────────────────────────────────────────────
        let mut holes: Vec<Interval> = device_holes(device_regions);
        holes.extend(islands.iter().copied());
        merge_intervals(&mut holes);

        log::debug!("placement: device+island holes ({} ranges):", holes.len());
        for h in &holes {
            log::debug!("  hole [{:#x}..{:#x})", h.start, h.end);
        }

        let big_chunk = if remaining == 0 {
            None
        } else {
            Some(find_lowest_fit(remaining, &holes, IDENTITY_CEILING).ok_or(
                PlanError::NoSpaceForBigChunk {
                    remaining_mib: remaining >> 20,
                },
            )?)
        };

        if let Some(c) = big_chunk {
            log::debug!(
                "placement: big_chunk [{:#x}..{:#x}) ({} MiB)",
                c.start,
                c.end,
                (c.end - c.start) >> 20,
            );
        }

        // ── 3. Assemble final region set ─────────────────────────────
        let mut regions: Vec<Region> = islands.iter().map(to_region).collect();
        if let Some(c) = big_chunk {
            regions.push(to_region(&c));
        }
        regions.sort_by_key(|r| r.gpa);

        Ok(MemoryPlan {
            memslots: regions.clone(),
            memory_nodes: regions,
        })
    }

    /// Device MMIO regions, rounded outward to 2 MiB.
    fn device_holes<I>(regions: I) -> Vec<Interval>
    where
        I: IntoIterator<Item = (u64, u64)>,
    {
        regions
            .into_iter()
            .filter(|(_, size)| *size > 0)
            .map(|(base, size)| Interval {
                start: base & !(HUGE_PAGE - 1),
                end: round_up_2mib(base.saturating_add(size)),
            })
            .collect()
    }

    fn to_region(i: &Interval) -> Region {
        Region {
            gpa: i.start,
            size: i.end - i.start,
        }
    }

    /// Merge overlapping or touching intervals in-place. Result is sorted.
    fn merge_intervals(v: &mut Vec<Interval>) {
        if v.is_empty() {
            return;
        }
        v.sort_by_key(|i| i.start);
        let mut out: Vec<Interval> = Vec::with_capacity(v.len());
        out.push(v[0]);
        for cur in v.iter().skip(1) {
            let last = out.last_mut().expect("non-empty");
            if cur.start <= last.end {
                last.end = last.end.max(cur.end);
            } else {
                out.push(*cur);
            }
        }
        *v = out;
    }

    /// Find the lowest 2 MiB-aligned start such that `[start, start + size)`
    /// is clear of every hole and ends at or below `ceiling`.
    fn find_lowest_fit(size: u64, holes: &[Interval], ceiling: u64) -> Option<Interval> {
        let mut cursor: u64 = 0;
        for h in holes {
            let candidate_end = cursor.saturating_add(size);
            if candidate_end <= h.start && candidate_end <= ceiling {
                return Some(Interval {
                    start: cursor,
                    end: candidate_end,
                });
            }
            cursor = cursor.max(h.end);
            cursor = round_up_2mib(cursor);
        }
        let candidate_end = cursor.saturating_add(size);
        if candidate_end <= ceiling {
            Some(Interval {
                start: cursor,
                end: candidate_end,
            })
        } else {
            None
        }
    }

    fn round_up_2mib(n: u64) -> u64 {
        (n + HUGE_PAGE - 1) & !(HUGE_PAGE - 1)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn merge_intervals_basic() {
            let mut v = vec![
                Interval { start: 10, end: 20 },
                Interval { start: 30, end: 40 },
                Interval { start: 15, end: 32 },
            ];
            merge_intervals(&mut v);
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].start, 10);
            assert_eq!(v[0].end, 40);
        }

        #[test]
        fn find_lowest_fit_skips_holes() {
            let holes = vec![
                Interval {
                    start: 0x10_0000,
                    end: 0x20_0000,
                },
                Interval {
                    start: 0x40_0000,
                    end: 0x60_0000,
                },
            ];
            let r = find_lowest_fit(0x10_0000, &holes, u64::MAX).unwrap();
            assert_eq!(r.start, 0);
            assert_eq!(r.end, 0x10_0000);

            let r = find_lowest_fit(0x20_0000, &holes, u64::MAX).unwrap();
            assert_eq!(r.start, 0x20_0000);
            assert_eq!(r.end, 0x40_0000);

            let r = find_lowest_fit(0x40_0000, &holes, u64::MAX).unwrap();
            assert_eq!(r.start, 0x60_0000);
        }

        #[test]
        fn find_lowest_fit_respects_ceiling() {
            let holes = vec![Interval {
                start: 0x10_0000,
                end: 0x20_0000,
            }];
            // Need 0x40_0000, ceiling 0x50_0000, hole at [1M, 2M)
            // → candidate at 0 (size 4M) ends at 4M, ≤ ceiling? No — overlaps hole.
            // → candidate at 2M ends at 6M > 5M → rejected.
            assert!(find_lowest_fit(0x40_0000, &holes, 0x50_0000).is_none());
        }

        #[test]
        fn plan_around_regions_uses_declared_holes() {
            let plan = plan_around_regions(&[(0, 0x20_0000)], 8, [(0x20_0000, 0x20_0000)])
                .expect("placement");

            assert_eq!(plan.memslots.len(), 2);
            assert_eq!(plan.memslots[0].gpa, 0);
            assert_eq!(plan.memslots[0].size, 0x20_0000);
            assert_eq!(plan.memslots[1].gpa, 0x40_0000);
            assert_eq!(plan.memslots[1].size, 0x60_0000);
        }
    }
}

mod overlay {

    use anyhow::{Result, anyhow};

    use crate::fdt_writer::FdtBuilder;
    use crate::placement::Region;

    pub(crate) fn synthesize_dtbo(
        regions: &[Region],
        vcpus: u32,
        enable_method: Option<&str>,
        cpu_compatible: Option<&str>,
        reserved_size: u64,
    ) -> Result<Vec<u8>> {
        let mut fdt = FdtBuilder::new();

        // root
        fdt.begin_node("");
        fdt.property_u32("#address-cells", 2);
        fdt.property_u32("#size-cells", 2);

        // /fragment@0 — authors the entire /cpus subtree under root. The base
        // declares nothing CPU-related (no /cpus); per merged.md §1+§2 cat 1 the
        // host overlay creates the /cpus container (with #address-cells/#size-cells)
        // and every cpu@N: device_type, a unique reg, status, and — where the
        // platform provides them — the bring-up method (`enable-method`) and the
        // MIDR-derived `compatible`. x86 cpus carry neither (no DT enable-method;
        // no consumer for a cpu compatible). The fragment targets `/` because the
        // base has no /cpus node for an overlay to extend.
        fdt.begin_node("fragment@0");
        fdt.property_string("target-path", "/");
        fdt.begin_node("__overlay__");
        fdt.begin_node("cpus");
        fdt.property_u32("#address-cells", 1);
        fdt.property_u32("#size-cells", 0);
        for n in 0..vcpus {
            let name = format!("cpu@{n}");
            fdt.begin_node(&name);
            fdt.property_string("device_type", "cpu");
            fdt.property_u32("reg", n);
            fdt.property_string("status", "okay");
            if let Some(em) = enable_method {
                fdt.property_string("enable-method", em);
            }
            if let Some(compat) = cpu_compatible {
                fdt.property_string("compatible", compat);
            }
            fdt.end_node(); // cpu@n
        }
        fdt.end_node(); // cpus
        fdt.end_node(); // __overlay__
        fdt.end_node(); // fragment@0

        // /fragment@1 — extends root `/` with /memory@<base> regions.
        // No properties on `/` here — tatu's merged-extension allowlist
        // (pmi/spec/merged.md §2) rejects any property addition on root.
        // The base DTB already declares #address-cells/#size-cells.
        fdt.begin_node("fragment@1");
        fdt.property_string("target-path", "/");
        fdt.begin_node("__overlay__");
        for r in regions {
            let name = format!("memory@{:x}", r.gpa);
            fdt.begin_node(&name);
            fdt.property_string("device_type", "memory");
            fdt.property_reg_2cells("reg", r.gpa, r.size);
            fdt.end_node(); // memory@N
        }
        fdt.end_node(); // __overlay__
        fdt.end_node(); // fragment@1

        fdt.end_node(); // root

        let bytes = fdt.finish();
        if bytes.len() as u64 > reserved_size {
            return Err(anyhow!(
                "synthesized DTBO ({} bytes) exceeds reserved .dtbo section size ({} bytes)",
                bytes.len(),
                reserved_size
            ));
        }
        Ok(bytes)
    }

    #[cfg(test)]
    mod tests {
        use dillo_devtree::devtree::{NodeView, PropertyView, Tree, TreeView};

        use super::*;

        fn synth(vcpus: u32, enable_method: Option<&str>, compatible: Option<&str>) -> Vec<u8> {
            synthesize_dtbo(&[], vcpus, enable_method, compatible, 1 << 20).expect("synth")
        }

        fn pstr<N: NodeView>(node: &N, name: &str) -> Option<String> {
            node.property(name)
                .and_then(|p| p.as_str().map(str::to_owned))
        }
        fn pu32<N: NodeView>(node: &N, name: &str) -> Option<u32> {
            node.property(name).and_then(|p| p.as_u32())
        }

        /// O1: the overlay authors the whole /cpus subtree — the container (with
        /// its cell properties) and every cpu instance (incl. cpu@0), unique reg,
        /// no phandle.
        #[test]
        fn authors_whole_cpus_subtree_with_unique_reg() {
            let dtbo = synth(4, None, None);
            let tree: Tree<'_> = Tree::parse(&dtbo).unwrap();
            let cpus = tree
                .find_path("/fragment@0/__overlay__/cpus")
                .expect("overlay authors /cpus container");
            assert_eq!(pu32(&cpus, "#address-cells"), Some(1));
            assert_eq!(pu32(&cpus, "#size-cells"), Some(0));
            for n in 0..4u32 {
                let cpu = tree
                    .find_path(&format!("/fragment@0/__overlay__/cpus/cpu@{n}"))
                    .unwrap_or_else(|| panic!("cpu@{n} present"));
                assert_eq!(pstr(&cpu, "device_type").as_deref(), Some("cpu"));
                assert_eq!(pu32(&cpu, "reg"), Some(n));
                assert_eq!(pstr(&cpu, "status").as_deref(), Some("okay"));
                assert!(cpu.property("phandle").is_none());
                assert!(cpu.property("linux,phandle").is_none());
            }
        }

        /// O3: x86-style cpus carry no enable-method and no compatible.
        #[test]
        fn x86_cpus_have_no_enable_method_or_compatible() {
            let dtbo = synth(2, None, None);
            let tree: Tree<'_> = Tree::parse(&dtbo).unwrap();
            let cpu0 = tree
                .find_path("/fragment@0/__overlay__/cpus/cpu@0")
                .unwrap();
            assert!(cpu0.property("enable-method").is_none());
            assert!(cpu0.property("compatible").is_none());
        }

        /// O2: aarch64-style cpus carry psci + the registered compatible.
        #[test]
        fn aarch64_cpus_carry_psci_and_compatible_when_known() {
            let dtbo = synth(2, Some("psci"), Some("arm,neoverse-v2"));
            let tree: Tree<'_> = Tree::parse(&dtbo).unwrap();
            for n in 0..2u32 {
                let cpu = tree
                    .find_path(&format!("/fragment@0/__overlay__/cpus/cpu@{n}"))
                    .unwrap();
                assert_eq!(pstr(&cpu, "enable-method").as_deref(), Some("psci"));
                assert_eq!(pstr(&cpu, "compatible").as_deref(), Some("arm,neoverse-v2"));
            }
        }

        /// O2 (unknown core) + single-cpu: psci kept, compatible omitted, cpu@0 authored.
        #[test]
        fn aarch64_unknown_core_omits_compatible_but_keeps_psci() {
            let dtbo = synth(1, Some("psci"), None);
            let tree: Tree<'_> = Tree::parse(&dtbo).unwrap();
            let cpu0 = tree
                .find_path("/fragment@0/__overlay__/cpus/cpu@0")
                .unwrap();
            assert_eq!(pstr(&cpu0, "enable-method").as_deref(), Some("psci"));
            assert!(cpu0.property("compatible").is_none());
        }
    }
}

mod launch {

    // The PMI File (fd) is held for the VM lifetime so the mapping — and any
    // reboot re-map — is pinned to that inode, not re-resolved by path. Read/Seek
    // are only used by the non-Linux read_to_end fallback (Linux mmaps the fd).
    use std::fs::File;
    #[cfg(not(target_os = "linux"))]
    use std::io::{Read, Seek};
    use std::path::Path;

    use dillo_devtree::platform::{Arch, Machine as PlatformMachine, SurveyError};
    use dillo_machine::HostArchitecture;
    use thiserror::Error;

    use crate::placement::{self, MemoryPlan};
    use dillo::pmi_parse::{Action as PmiAction, FillKind, HostArch, ParseOptions};

    /// The PMI byte source. Raw section loads are copied straight from it into
    /// guest RAM (one copy) instead of being staged into owned `Vec`s (two
    /// copies). On Linux the backing is an mmap; elsewhere a `read_to_end`
    /// buffer. The backing is resident only while sections are being copied:
    /// after the initial load the caller [`release`](Pmi::release)s it so
    /// the mapping does not stay resident for the VM's lifetime, and the rare
    /// guest-reboot replay [`remap`](Pmi::remap)s it from `path`.
    pub(crate) struct Pmi {
        /// Held open for the VM lifetime: the mapping and any reboot re-map are
        /// pinned to this fd's inode, so a replay is always the exact bytes that
        /// were loaded and measured — never whatever the path resolves to later.
        file: File,
        /// Retained for error messages only; never used to re-open the file.
        path: std::path::PathBuf,
        backing: Option<PmiBacking>,
    }

    enum PmiBacking {
        #[cfg(target_os = "linux")]
        Mapped(mmarinus::Map<mmarinus::perms::Read>),
        #[cfg(not(target_os = "linux"))]
        Owned(Vec<u8>),
    }

    impl Pmi {
        /// Open the PMI at `path`, hold the fd, and map (Linux) / read (other) it
        /// resident.
        pub(crate) fn open(path: &Path) -> Result<Self, LaunchError> {
            let file = File::open(path).map_err(|source| LaunchError::ReadPmi {
                path: path.display().to_string(),
                source,
            })?;
            let mut img = Pmi {
                file,
                path: path.to_path_buf(),
                backing: None,
            };
            img.remap()?;
            Ok(img)
        }

        /// (Re-)acquire the backing store from the held fd. Used for the initial
        /// load and to replay launch writes on guest reboot after a [`release`].
        pub(crate) fn remap(&mut self) -> Result<(), LaunchError> {
            // Owned label up front so the error path doesn't borrow `self` while
            // we mutably borrow `self.file` for the mapping.
            let path = self.path.display().to_string();
            #[cfg(target_os = "linux")]
            {
                let len = self
                    .file
                    .metadata()
                    .map_err(|source| LaunchError::ReadPmi {
                        path: path.clone(),
                        source,
                    })?
                    .len() as usize;
                let m = mmarinus::Map::bytes(len)
                    .anywhere()
                    .from(&mut self.file, 0)
                    .with(mmarinus::perms::Read)
                    .map_err(|e| LaunchError::ReadPmi {
                        path: path.clone(),
                        source: std::io::Error::other(format!("mmap: {e:?}")),
                    })?;
                self.backing = Some(PmiBacking::Mapped(m));
            }
            #[cfg(not(target_os = "linux"))]
            {
                self.file.rewind().map_err(|source| LaunchError::ReadPmi {
                    path: path.clone(),
                    source,
                })?;
                let mut b = Vec::new();
                self.file
                    .read_to_end(&mut b)
                    .map_err(|source| LaunchError::ReadPmi {
                        path: path.clone(),
                        source,
                    })?;
                self.backing = Some(PmiBacking::Owned(b));
            }
            Ok(())
        }

        /// Drop the backing store (munmap on Linux), freeing its resident pages
        /// while keeping the fd open for a possible reboot re-map. Safe to call
        /// once sections have been copied into guest RAM.
        pub(crate) fn release(&mut self) {
            self.backing = None;
        }

        pub(crate) fn bytes(&self) -> &[u8] {
            match self.backing.as_ref().expect("PMI backing released") {
                #[cfg(target_os = "linux")]
                PmiBacking::Mapped(m) => &m[..],
                #[cfg(not(target_os = "linux"))]
                PmiBacking::Owned(v) => v,
            }
        }
    }

    impl std::fmt::Debug for Pmi {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.backing {
                Some(_) => write!(f, "Pmi({} bytes, resident)", self.bytes().len()),
                None => write!(f, "Pmi(released)"),
            }
        }
    }

    /// Source of a launch-time write's bytes: either bytes derived by dillo
    /// (DTB overlay, cmdline, cpu bootstate), or a byte range of the PMI image
    /// (raw `load` sections — copied directly from [`Pmi`], never staged).
    #[derive(Debug, Clone)]
    pub(crate) enum WriteSrc {
        Owned(Vec<u8>),
        Image { offset: usize, len: usize },
    }

    /// Target-neutral launch facts derived before backend construction.
    #[derive(Debug)]
    pub(crate) struct LaunchPlan {
        pub(crate) parsed: dillo::pmi_parse::ParsedPmi,
        pub(crate) merged_dtb: Vec<u8>,
        pub(crate) platform: PlatformMachine,
        pub(crate) memory: MemoryPlan,
        pub(crate) guest_writes: Vec<GuestWrite>,
        pub(crate) pmi: Pmi,
    }

    /// One launch-time write into guest RAM.
    #[derive(Debug)]
    pub(crate) struct GuestWrite {
        pub(crate) section: String,
        pub(crate) gpa: u64,
        pub(crate) data: WriteSrc,
    }

    impl LaunchPlan {
        /// Read a PMI file, validate target-neutral launch facts, and compute RAM
        /// placement from the DTB-declared platform.
        pub(crate) fn read(
            pmi_path: &Path,
            host_arch: HostArchitecture,
            cpu_compatible: Option<&str>,
            memory_mib: u32,
            vcpus: u32,
        ) -> Result<Self, LaunchError> {
            // Map the PMI read-only rather than reading it whole. The PMI
            // granularity spec places sections at aligned offsets precisely so a
            // VMM can map the file and touch only the section bytes; a 70MB PMI is
            // mostly 2M zero padding that read_to_end would copy needlessly. On
            // Linux we mmap via mmarinus (safe wrapper — no caller unsafe, so the
            // workspace unsafe_code=deny lint still holds); other hosts fall back
            // to read_to_end. `bytes` borrows the backing store, which lives for
            // the rest of this function (its data is copied into owned buffers by
            // parse/guest_writes before we return), so nothing escapes the map.
            let pmi = Pmi::open(pmi_path)?;
            let bytes: &[u8] = pmi.bytes();

            crate::boot_trace::mark("pmi_read");
            let pmi_arch = pmi_arch(host_arch);
            let parsed = dillo::pmi_parse::parse(
                bytes,
                &ParseOptions {
                    host_arch: pmi_arch,
                    memory_mib,
                },
            )?;
            validate_cpu_profile(parsed.cpu_profile.as_str(), pmi_arch)?;
            crate::boot_trace::mark("pmi_parsed");

            let dtb = merged_dtb(bytes, &parsed)?.to_vec();
            let platform = PlatformMachine::survey(&dtb, platform_arch(host_arch))
                .map_err(LaunchError::Coverage)?;

            let load_ranges: Vec<(String, u64, u64)> = parsed
                .sections
                .iter()
                .map(|(name, section)| (name.clone(), section.gpa, section.virtual_size))
                .collect();
            platform
                .plan
                .cross_validate_loads(&load_ranges, platform.min_addr_space_bits())
                .map_err(LaunchError::DtbCrossValidate)?;

            let must_cover: Vec<(u64, u64)> = parsed
                .sections
                .values()
                .map(|section| (section.gpa, section.virtual_size))
                .collect();
            let memory = placement::plan_around_regions(
                &must_cover,
                memory_mib,
                platform.placement_regions(),
            )?;
            let guest_writes = guest_writes(
                bytes,
                &parsed,
                &memory,
                platform.arch,
                cpu_compatible,
                vcpus,
            )?;
            crate::boot_trace::mark("guest_writes_built");

            // `bytes` (a borrow of `pmi`) is unused past here, so `pmi` can move
            // into the plan: raw section loads reference it by offset and are
            // copied straight from it into guest RAM at apply time (single copy).
            Ok(Self {
                parsed,
                merged_dtb: dtb,
                platform,
                memory,
                guest_writes,
                pmi,
            })
        }
    }

    fn pmi_arch(host_arch: HostArchitecture) -> HostArch {
        match host_arch {
            HostArchitecture::X86_64 => HostArch::X86_64,
            HostArchitecture::Aarch64 => HostArch::Aarch64,
        }
    }

    fn platform_arch(host_arch: HostArchitecture) -> Arch {
        match host_arch {
            HostArchitecture::X86_64 => Arch::X86_64,
            HostArchitecture::Aarch64 => Arch::Aarch64,
        }
    }

    /// Error produced by target-neutral launch preflight.
    #[derive(Debug, Error)]
    pub(crate) enum LaunchError {
        #[error("read PMI {path}: {source}")]
        ReadPmi {
            path: String,
            #[source]
            source: std::io::Error,
        },

        #[error("PMI parse: {0}")]
        PmiParse(#[from] dillo::pmi_parse::Error),

        #[error("merged_dtb section missing from parsed.sections")]
        MissingMergedDtb,

        #[error("base DTB coverage: {0}")]
        Coverage(SurveyError),

        #[error("base DTB / PE cross-validation: {0}")]
        DtbCrossValidate(SurveyError),

        #[error("merged_dtb section lies outside the PMI file")]
        MalformedMergedDtb,

        #[error("memory placement: {0}")]
        Placement(#[from] placement::PlanError),

        #[error("unrecognized cpu:profile {0:?} for {1:?}")]
        UnknownCpuProfile(String, HostArch),

        #[error("load section `{0}` lies outside the PMI file")]
        MalformedLoadSection(String),

        #[error("synthesize host DTBO: {0}")]
        DtboSynth(#[source] anyhow::Error),
    }

    impl LaunchError {
        /// Map to the documented dillo launch exit code categories.
        #[must_use]
        pub(crate) fn exit_code(&self) -> i32 {
            match self {
                Self::ReadPmi { .. } | Self::PmiParse(_) => 10,
                Self::MissingMergedDtb
                | Self::Coverage(_)
                | Self::DtbCrossValidate(_)
                | Self::MalformedMergedDtb
                | Self::MalformedLoadSection(_)
                | Self::DtboSynth(_) => 11,
                Self::Placement(_) => 13,
                Self::UnknownCpuProfile(_, _) => 12,
            }
        }
    }

    fn guest_writes(
        bytes: &[u8],
        parsed: &dillo::pmi_parse::ParsedPmi,
        memory: &MemoryPlan,
        arch: Arch,
        cpu_compatible: Option<&str>,
        vcpus: u32,
    ) -> Result<Vec<GuestWrite>, LaunchError> {
        let mut writes = Vec::new();
        for action in &parsed.actions {
            match action {
                PmiAction::Load { section } => {
                    let s = &parsed.sections[section];
                    if s.file_size == 0 {
                        continue;
                    }
                    // Bounds-check the section against the image (as the old copy
                    // path did), but record the byte range instead of copying it:
                    // apply_load_sections copies it straight from the PMI image
                    // into guest RAM (one copy, not two).
                    read_section(bytes, s.file_offset, s.file_size)
                        .ok_or_else(|| LaunchError::MalformedLoadSection(section.clone()))?;
                    writes.push(GuestWrite {
                        section: section.clone(),
                        gpa: s.gpa,
                        data: WriteSrc::Image {
                            offset: s.file_offset as usize,
                            len: s.file_size as usize,
                        },
                    });
                }
                PmiAction::Fill {
                    section,
                    kind: FillKind::MergedDtbo,
                } => {
                    let s = &parsed.sections[section];
                    let data = crate::overlay::synthesize_dtbo(
                        &memory.memory_nodes,
                        vcpus,
                        arch.cpu_enable_method(),
                        cpu_compatible,
                        s.virtual_size,
                    )
                    .map_err(LaunchError::DtboSynth)?;
                    writes.push(GuestWrite {
                        section: section.clone(),
                        gpa: s.gpa,
                        data: WriteSrc::Owned(data),
                    });
                }
            }
        }
        Ok(writes)
    }

    fn merged_dtb<'a>(
        bytes: &'a [u8],
        parsed: &dillo::pmi_parse::ParsedPmi,
    ) -> Result<&'a [u8], LaunchError> {
        let dtb_info = parsed
            .sections
            .get(&parsed.merged_dtb_section)
            .ok_or(LaunchError::MissingMergedDtb)?;
        read_section(bytes, dtb_info.file_offset, dtb_info.file_size)
            .ok_or(LaunchError::MalformedMergedDtb)
    }

    fn read_section(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let size = usize::try_from(size).ok()?;
        let end = start.checked_add(size)?;
        bytes.get(start..end)
    }

    /// Validate the `cpu:profile` name against the PMI machine architecture.
    pub(crate) fn validate_cpu_profile(profile: &str, arch: HostArch) -> Result<(), LaunchError> {
        let recognized = match arch {
            HostArch::Aarch64 => parse_armv_profile(profile).is_some(),
            HostArch::X86_64 => matches!(
                profile,
                "x86-64-v1" | "x86-64-v2" | "x86-64-v3" | "x86-64-v4"
            ),
        };
        if recognized {
            Ok(())
        } else {
            Err(LaunchError::UnknownCpuProfile(profile.to_string(), arch))
        }
    }

    fn parse_armv_profile(s: &str) -> Option<(u32, u32)> {
        let body = s.strip_prefix("armv")?.strip_suffix("-a")?;
        let (major, minor) = body.split_once('.')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cpu_profile_validation_accepts_known_x86_levels() {
            for profile in ["x86-64-v1", "x86-64-v2", "x86-64-v3", "x86-64-v4"] {
                validate_cpu_profile(profile, HostArch::X86_64).expect(profile);
            }
        }

        #[test]
        fn cpu_profile_validation_accepts_armv_profiles() {
            validate_cpu_profile("armv8.0-a", HostArch::Aarch64).expect("armv8.0-a");
            validate_cpu_profile("armv9.2-a", HostArch::Aarch64).expect("armv9.2-a");
        }

        #[test]
        fn cpu_profile_validation_rejects_arch_mismatch() {
            assert!(validate_cpu_profile("armv8.0-a", HostArch::X86_64).is_err());
            assert!(validate_cpu_profile("x86-64-v2", HostArch::Aarch64).is_err());
        }

        #[test]
        fn read_section_checks_bounds() {
            assert_eq!(read_section(b"abcdef", 1, 3), Some(&b"bcd"[..]));
            assert!(read_section(b"abcdef", 4, 3).is_none());
            assert!(read_section(b"abcdef", u64::MAX, 1).is_none());
        }
    }
}

mod machine_select {
    #[cfg(target_os = "linux")]
    pub(crate) use dillo_machine_kvm as machine;

    #[cfg(target_os = "macos")]
    pub(crate) use dillo_machine_hvf as machine;

    #[cfg(target_os = "windows")]
    pub(crate) use dillo_machine_whp as machine;

    pub(crate) mod runner {
        mod error {

            use thiserror::Error;

            /// Exit-code-bearing error for the VM-side run loop. Each variant
            /// corresponds to one of ARCH §13.4's documented categories.
            #[derive(Debug, Error)]
            #[allow(dead_code)]
            pub(crate) enum RunError {
                // ── exit 10 — PMI parse / validation ───────────────────────────
                #[error("read PMI {path}: {source}")]
                ReadPmi {
                    path: String,
                    #[source]
                    source: std::io::Error,
                },

                #[error("PMI parse: {0}")]
                PmiParse(#[from] dillo::pmi_parse::Error),

                // ── exit 11 — DTB parse / validation ───────────────────────────
                #[error("base DTB extraction: {0}")]
                DtbExtract(dillo_devtree::platform::SurveyError),

                #[error("base DTB coverage (undeclared hardware / unclaimed node): {0}")]
                Coverage(dillo_devtree::platform::SurveyError),

                #[error("base DTB ↔ PE cross-validation: {0}")]
                DtbCrossValidate(dillo_devtree::platform::SurveyError),

                #[error("base DTB is missing required device `{0}`")]
                MissingRequiredDevice(&'static str),

                #[error("synthesize host DTBO: {0}")]
                DtboSynth(#[source] anyhow::Error),

                #[error("write DTBO section `{section}` to GPA {gpa:#x}: {source}")]
                DtboWrite {
                    section: String,
                    gpa: u64,
                    #[source]
                    source: anyhow::Error,
                },

                // ── exit 12 — Hypervisor init failed ───────────────────────────
                #[error("machine: {0}")]
                Machine(String),

                #[error("write load section `{section}` to GPA {gpa:#x}: {source}")]
                SectionWrite {
                    section: String,
                    gpa: u64,
                    #[source]
                    source: anyhow::Error,
                },

                // ── exit 13 — Host RAM check ───────────────────────────────────
                #[error(
                    "host RAM ({available_mib} MiB) insufficient for guest ({requested_mib} MiB) + \
                     {overhead_mib} MiB overhead"
                )]
                HostRam {
                    requested_mib: u64,
                    overhead_mib: u64,
                    available_mib: u64,
                },

                #[error("memory placement: {source}")]
                Placement {
                    #[source]
                    source: anyhow::Error,
                },
                // ── exit 20 — Guest crash ──────────────────────────────────────
            }

            impl RunError {
                pub(crate) fn machine(source: impl std::error::Error) -> Self {
                    Self::Machine(source.to_string())
                }

                /// Map to the documented exit code from ARCH §13.4.
                #[must_use]
                pub(crate) fn exit_code(&self) -> i32 {
                    match self {
                        Self::ReadPmi { .. } | Self::PmiParse(_) => 10,
                        Self::DtbExtract(_)
                        | Self::Coverage(_)
                        | Self::DtbCrossValidate(_)
                        | Self::MissingRequiredDevice(_)
                        | Self::DtboSynth(_)
                        | Self::DtboWrite { .. } => 11,
                        Self::Machine(_) | Self::SectionWrite { .. } => 12,
                        Self::HostRam { .. } | Self::Placement { .. } => 13,
                    }
                }
            }
        }

        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::thread;

        use super::machine as selected_machine;
        use dillo_devtree::platform::Machine as PlatformMachine;
        use dillo_devtree::platform::{MsiParentage, WiredInterrupt};
        use dillo_machine::{
            BootVcpuState, Cpu as MachineCpu, CpuState as MachineCpuState, LaunchConfig, Machine,
            Memory as MachineMemory, RamRange, VcpuStop,
        };
        use dillo_mmio::syscon;
        use dillo_mmio::{
            Attach, InterruptSource, MessageInterruptSource, MmioAttachment,
            MmioInterruptRequirement, MmioWindow,
        };
        use dillo_pci::PciRoot;
        use dillo_pci_virtio::VirtioPciAdapter;

        pub(crate) use self::error::RunError;

        /// One launch-derived RAM region passed in by the top-level `dillo` launcher.
        #[derive(Debug, Clone, Copy)]
        pub(crate) struct RunRegion {
            pub(crate) gpa: u64,
            pub(crate) size: u64,
        }

        /// One launch-time write into guest RAM, already derived by `dillo`.
        #[derive(Debug)]
        pub(crate) struct RunWrite {
            pub(crate) section: String,
            pub(crate) gpa: u64,
            pub(crate) data: crate::launch::WriteSrc,
        }

        #[derive(Debug)]
        struct RunMemoryPlan {
            memslots: Vec<RunRegion>,
            memory_nodes: Vec<RunRegion>,
        }

        impl RunMemoryPlan {
            fn ram_ranges(&self) -> Vec<RamRange> {
                self.memslots
                    .iter()
                    .map(|range| RamRange {
                        gpa: range.gpa,
                        size: range.size,
                    })
                    .collect()
            }
        }

        /// One device with its allocated bus + slot, ready to attach. Built by
        /// `build_placements` (console + each virtio-blk/gpt device).
        pub(crate) struct DevicePlacement {
            pub(crate) bus: dillo_config::Bus,
            /// PCI device number (when `bus == Pci`) or virtio-mmio slot index.
            pub(crate) index: u32,
            pub(crate) msix_vectors: u16,
            pub(crate) name: &'static str,
            pub(crate) device: Box<dyn dillo_virtio::VirtioDevice>,
        }

        impl std::fmt::Debug for DevicePlacement {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("DevicePlacement")
                    .field("bus", &self.bus)
                    .field("index", &self.index)
                    .field("msix_vectors", &self.msix_vectors)
                    .field("name", &self.name)
                    .finish_non_exhaustive()
            }
        }

        /// Target-neutral launch facts already derived by `dillo`.
        #[derive(Debug)]
        pub(crate) struct Preflight {
            parsed: dillo::pmi_parse::ParsedPmi,
            platform: PlatformMachine,
            dtb: Vec<u8>,
            memslots: Vec<RunRegion>,
            memory_nodes: Vec<RunRegion>,
            guest_writes: Vec<RunWrite>,
            placements: Vec<DevicePlacement>,
            pmi: crate::launch::Pmi,
        }

        impl Preflight {
            pub(crate) fn new(
                parsed: dillo::pmi_parse::ParsedPmi,
                platform: PlatformMachine,
                dtb: Vec<u8>,
                memslots: impl IntoIterator<Item = RunRegion>,
                memory_nodes: impl IntoIterator<Item = RunRegion>,
                guest_writes: impl IntoIterator<Item = RunWrite>,
                placements: Vec<DevicePlacement>,
                pmi: crate::launch::Pmi,
            ) -> Self {
                Self {
                    parsed,
                    platform,
                    dtb,
                    memslots: memslots.into_iter().collect(),
                    memory_nodes: memory_nodes.into_iter().collect(),
                    guest_writes: guest_writes.into_iter().collect(),
                    placements,
                    pmi,
                }
            }

            fn into_parts(
                self,
            ) -> (
                dillo::pmi_parse::ParsedPmi,
                PlatformMachine,
                Vec<u8>,
                RunMemoryPlan,
                Vec<RunWrite>,
                Vec<DevicePlacement>,
                crate::launch::Pmi,
            ) {
                (
                    self.parsed,
                    self.platform,
                    self.dtb,
                    RunMemoryPlan {
                        memslots: self.memslots,
                        memory_nodes: self.memory_nodes,
                    },
                    self.guest_writes,
                    self.placements,
                    self.pmi,
                )
            }
        }

        #[derive(Debug)]
        struct SupervisorControl {
            supervisor_shutdown: &'static AtomicBool,
        }

        impl SupervisorControl {
            fn stop_requested(&self) -> Option<VcpuStop> {
                self.supervisor_shutdown
                    .load(Ordering::Acquire)
                    .then_some(VcpuStop::Stopped)
            }
        }

        fn syscon_register(syscon: dillo_devtree::platform::Syscon) -> syscon::SysconRegister {
            syscon::SysconRegister {
                base: syscon.base,
                offset: syscon.offset,
                value: syscon.value,
                mask: syscon.mask,
            }
        }

        fn interrupt_source(interrupt: &WiredInterrupt) -> InterruptSource {
            let mut cells = [0u32; 4];
            for (dst, src) in cells.iter_mut().zip(interrupt.cells.iter().copied()) {
                *dst = src;
            }
            InterruptSource {
                controller: interrupt.controller.phandle,
                cells,
                cell_count: interrupt.cells.len().min(cells.len()) as u8,
            }
        }

        fn line_requirement(interrupt: &WiredInterrupt) -> MmioInterruptRequirement {
            MmioInterruptRequirement::Line {
                source: interrupt_source(interrupt),
            }
        }

        fn message_requirement(msi: &MsiParentage, vectors: u16) -> MmioInterruptRequirement {
            MmioInterruptRequirement::MessageDomain {
                source: Some(MessageInterruptSource {
                    controller: msi.controller.phandle,
                }),
                vectors,
            }
        }

        fn optional_message_requirement(
            msi: Option<&MsiParentage>,
            vectors: u16,
        ) -> MmioInterruptRequirement {
            match msi {
                Some(msi) => message_requirement(msi, vectors),
                None => MmioInterruptRequirement::MessageDomain {
                    source: None,
                    vectors,
                },
            }
        }

        /// Attach every placed device (console + virtio-blk/gpt) on the bus the
        /// allocator chose. PCI-assigned devices share one [`PciRoot`] (each at
        /// its own slot + BAR stride, MSI-X vectors auto-isolated per slot);
        /// MMIO-assigned devices each get their own virtio-mmio transport with
        /// an independent wired-line IRQ.
        fn attach_devices<M, E>(
            vm: &mut M,
            platform: &PlatformMachine,
            placements: Vec<DevicePlacement>,
        ) -> Result<(), RunError>
        where
            E: std::error::Error + Send + Sync + 'static,
            M: Machine<Error = E>,
            M: Attach<Arc<PciRoot>, Error = E, Output = Arc<dyn MmioAttachment>>,
            M: Attach<
                    Arc<dillo_mmio_virtio::VirtioMmio>,
                    Error = E,
                    Output = Arc<dyn MmioAttachment>,
                >,
        {
            use dillo_config::Bus;

            let (mut pci, mmio): (Vec<DevicePlacement>, Vec<DevicePlacement>) =
                placements.into_iter().partition(|p| p.bus == Bus::Pci);

            // --- PCI: one root, one function per placement ---
            if !pci.is_empty() {
                // Each virtio function uses BAR 0 (4 KiB cfg) + BAR 2 (4 KiB
                // MSI-X) — one 0x2000 stride in the PCI MMIO window. Strides are
                // packed in registration order; the PCI device number is the
                // allocator-assigned slot.
                const BAR_STRIDE: u64 = 0x2000;
                let mmio_base = platform.pcie.mmio_base;
                pci.sort_by_key(|p| p.index);

                let ecam = MmioWindow {
                    base: platform.pcie.ecam_base,
                    size: platform.pcie.ecam_size,
                };
                // PciRoot recomputes the MSI-X domain size from registered
                // devices, so the seed vector count here is irrelevant.
                let mut pci_root = PciRoot::with_interrupt_requirement(
                    ecam,
                    optional_message_requirement(platform.pcie.msi.as_ref(), 0),
                );

                for (stride, placement) in pci.into_iter().enumerate() {
                    let bar0 = mmio_base + (stride as u64) * BAR_STRIDE;
                    let bar2 = bar0 + 0x1000;
                    let dev = dillo_pci_virtio::VirtioPciDevice::new(
                        Arc::new(std::sync::Mutex::new(placement.device)),
                        placement.msix_vectors,
                        bar0,
                        bar2,
                    );
                    pci_root.register(placement.index as u8, Box::new(VirtioPciAdapter::new(dev)));
                    log::debug!(
                        "{} on PCI slot {} (BAR0 {bar0:#x})",
                        placement.name,
                        placement.index
                    );
                }

                let pci_root = Arc::new(pci_root);
                let attachment =
                    Attach::attach(vm, Arc::clone(&pci_root)).map_err(RunError::machine)?;
                pci_root.set_attachment(attachment);
            }

            // --- MMIO: one transport per placement ---
            for placement in mmio {
                let slot = &platform.virtio_mmio[placement.index as usize];
                let int_status = Arc::new(AtomicU32::new(0));
                let irq = dillo_mmio_virtio::WiredIrq::unresolved(slot.irq);
                let transport =
                    Arc::new(dillo_mmio_virtio::VirtioMmio::with_interrupt_requirement(
                        MmioWindow {
                            base: slot.base,
                            size: slot.size,
                        },
                        placement.device,
                        Arc::clone(&int_status),
                        irq.clone(),
                        line_requirement(&slot.interrupt),
                    ));
                let attachment =
                    Attach::attach(vm, Arc::clone(&transport)).map_err(RunError::machine)?;
                transport.set_attachment(attachment);
                log::debug!(
                    "{} on virtio-mmio slot {} ({:#x}, SPI {})",
                    placement.name,
                    placement.index,
                    slot.base,
                    irq.intid()
                );
            }

            Ok(())
        }

        fn attach_uart<M, E>(vm: &mut M, platform: &PlatformMachine) -> Result<(), RunError>
        where
            E: std::error::Error + Send + Sync + 'static,
            M: Machine<Error = E>,
            M: Attach<Arc<dillo_mmio_uart::Ns16550>, Error = E, Output = Arc<dyn MmioAttachment>>,
        {
            let Some(uart) = platform.uart.as_ref() else {
                log::warn!("no UART in Machine - guest console output will be dropped");
                return Ok(());
            };
            let serial = Arc::new(dillo_mmio_uart::Ns16550::with_interrupt_requirement(
                MmioWindow {
                    base: uart.base,
                    size: uart.size,
                },
                uart.reg_shift,
                line_requirement(&uart.interrupt),
                // Guest console output goes to stdout (like virtio-console), so
                // dillo's own logging on stderr stays cleanly separable.
                Box::new(std::io::stdout()),
            ));
            let attachment = Attach::attach(vm, Arc::clone(&serial)).map_err(RunError::machine)?;
            serial.set_attachment(attachment.as_ref());
            log::debug!(
                "serial: ns16550a @ {:#x} (size {:#x}, reg-shift {}, IRQ {})",
                uart.base,
                uart.size,
                uart.reg_shift,
                uart.irq
            );
            Ok(())
        }

        fn attach_syscon<M, E>(vm: &mut M, platform: &PlatformMachine) -> Result<(), RunError>
        where
            E: std::error::Error + Send + Sync + 'static,
            M: Machine<Error = E>,
            M: Attach<Arc<syscon::SysconDevice>, Error = E>,
        {
            let Some(poweroff) = platform.poweroff else {
                return Ok(());
            };
            Attach::attach(
                vm,
                Arc::new(syscon::SysconDevice::new(
                    syscon_register(poweroff),
                    syscon::SysconAction::Poweroff,
                )),
            )
            .map_err(RunError::machine)?;
            if let Some(reboot) = platform.reboot {
                Attach::attach(
                    vm,
                    Arc::new(syscon::SysconDevice::new(
                        syscon_register(reboot),
                        syscon::SysconAction::Reboot,
                    )),
                )
                .map_err(RunError::machine)?;
            }
            Ok(())
        }

        fn apply_load_sections<M: Machine>(
            vm: &mut M,
            guest_writes: &[RunWrite],
            pmi_bytes: &[u8],
        ) -> Result<(), RunError> {
            use crate::launch::WriteSrc;
            for write in guest_writes {
                // Raw `load` sections are copied straight from the PMI image;
                // derived writes (DTB overlay, cmdline, cpu state) carry owned bytes.
                let data: &[u8] = match &write.data {
                    WriteSrc::Owned(v) => v,
                    WriteSrc::Image { offset, len } => pmi_bytes
                        .get(*offset..offset.saturating_add(*len))
                        .ok_or_else(|| {
                            RunError::Machine(format!(
                                "launch section `{}` range {:#x}+{:#x} out of PMI bounds",
                                write.section, offset, len
                            ))
                        })?,
                };
                log::debug!(
                    "writing launch section `{}` to GPA {:#x} ({} bytes)",
                    write.section,
                    write.gpa,
                    data.len()
                );
                vm.write_guest(write.gpa, data).map_err(RunError::machine)?;
            }
            Ok(())
        }

        fn run_vcpus<M, E>(
            vm: &mut M,
            count: u32,
            cpu_profile: &str,
            boot_state: &dyn BootVcpuState,
            control: Arc<SupervisorControl>,
        ) -> Result<VcpuStop, RunError>
        where
            E: std::error::Error + Send + Sync + 'static,
            M: Machine<Error = E>,
            M: Attach<M::CpuState, Error = E, Output = Arc<M::Cpu>>,
        {
            let mut cpus = Vec::with_capacity(count as usize);
            for index in 0..count {
                let state = M::CpuState::new(index, cpu_profile, Some(boot_state))
                    .map_err(RunError::machine)?;
                cpus.push(Attach::attach(vm, state).map_err(RunError::machine)?);
            }
            vm.prepare_vcpu_run().map_err(RunError::machine)?;

            let shutdown = Arc::new(AtomicBool::new(false));
            let mut first_stop = VcpuStop::Stopped;
            let mut first_error = None;

            thread::scope(|scope| {
                let mut joins = Vec::with_capacity(cpus.len());
                for cpu in &cpus {
                    let cpu = Arc::clone(cpu);
                    let all_cpus = cpus.clone();
                    let shutdown = Arc::clone(&shutdown);
                    joins.push(scope.spawn(move || -> Result<VcpuStop, String> {
                        if shutdown.load(Ordering::Acquire) {
                            return Ok(VcpuStop::Stopped);
                        }
                        let result = cpu.run().map_err(|e| e.to_string());
                        shutdown.store(true, Ordering::Release);
                        for cpu in &all_cpus {
                            let _ = cpu.stop();
                        }
                        result
                    }));
                }

                let monitor = {
                    let control = Arc::clone(&control);
                    let cpus = cpus.clone();
                    let shutdown = Arc::clone(&shutdown);
                    scope.spawn(move || {
                        let mut stop_requested = false;
                        while !shutdown.load(Ordering::Acquire) {
                            if stop_requested || control.stop_requested().is_some() {
                                stop_requested = true;
                                for cpu in &cpus {
                                    let _ = cpu.stop();
                                }
                            }
                            thread::sleep(std::time::Duration::from_millis(10));
                        }
                    })
                };

                for join in joins {
                    match join.join() {
                        Ok(Ok(stop)) => {
                            if matches!(stop, VcpuStop::GuestReset | VcpuStop::GuestPoweroff) {
                                first_stop = stop;
                            }
                            for cpu in &cpus {
                                let _ = cpu.stop();
                            }
                        }
                        Ok(Err(error)) => {
                            first_error.get_or_insert(error);
                            for cpu in &cpus {
                                let _ = cpu.stop();
                            }
                        }
                        Err(_) => {
                            first_error.get_or_insert_with(|| "vCPU thread panicked".to_string());
                            for cpu in &cpus {
                                let _ = cpu.stop();
                            }
                        }
                    }
                }
                shutdown.store(true, Ordering::Release);
                monitor.join().expect("vCPU stop monitor panicked");
                if let Some(stop) = control.stop_requested() {
                    first_stop = stop;
                }
                Ok::<(), RunError>(())
            })?;

            if let Some(error) = first_error {
                return Err(RunError::Machine(error));
            }
            Ok(first_stop)
        }

        fn run_selected<M, E>(
            preflight: Preflight,
            vcpus: u32,
            supervisor_shutdown: &'static AtomicBool,
        ) -> Result<i32, RunError>
        where
            E: std::error::Error + Send + Sync + 'static,
            M: Machine<Error = E>,
            M: Attach<M::Memory, Error = E, Output = ()>,
            M: Attach<M::CpuState, Error = E, Output = Arc<M::Cpu>>,
            M: Attach<Arc<PciRoot>, Error = E, Output = Arc<dyn MmioAttachment>>,
            M: Attach<
                    Arc<dillo_mmio_virtio::VirtioMmio>,
                    Error = E,
                    Output = Arc<dyn MmioAttachment>,
                >,
            M: Attach<Arc<dillo_mmio_uart::Ns16550>, Error = E, Output = Arc<dyn MmioAttachment>>,
            M: Attach<Arc<syscon::SysconDevice>, Error = E>,
        {
            let (parsed, platform, dtb, plan, guest_writes, placements, mut pmi) =
                preflight.into_parts();
            log::debug!(
                "PMI parsed: arch={:?}, {} actions, merged_dtb={}",
                parsed.arch,
                parsed.actions.len(),
                parsed.merged_dtb_section
            );
            log::debug!(
                "coverage: base DTB fully claimed - {} declared region(s), pcie={}",
                platform.plan.regions().len(),
                platform.has_pcie
            );
            let total_backed: u64 = plan.memslots.iter().map(|r| r.size).sum();
            log::debug!(
                "memslots: {} region(s), {} bytes",
                plan.memslots.len(),
                total_backed
            );
            log::debug!("/memory@N nodes: {} region(s)", plan.memory_nodes.len());
            for r in &plan.memory_nodes {
                log::debug!("  [{:#x}..{:#x}) ({} bytes)", r.gpa, r.gpa + r.size, r.size);
            }

            let mut vm = M::from_launch_config(LaunchConfig {
                dtb,
                vcpus,
                min_addr_space_bits: platform.min_addr_space_bits(),
            })
            .map_err(RunError::machine)?;
            crate::boot_trace::mark("vm_created");
            let memory = M::Memory::from_ranges(&plan.ram_ranges()).map_err(RunError::machine)?;
            Attach::attach(&mut vm, memory).map_err(RunError::machine)?;
            crate::boot_trace::mark("mem_attached");
            apply_load_sections(&mut vm, &guest_writes, pmi.bytes())?;
            // Sections are now in guest RAM; drop the PMI backing so it does not
            // stay resident for the VM's lifetime. A guest reboot re-maps it.
            pmi.release();
            crate::boot_trace::mark("sections_loaded");

            attach_uart(&mut vm, &platform)?;
            attach_syscon(&mut vm, &platform)?;
            attach_devices(&mut vm, &platform, placements)?;

            let control = Arc::new(SupervisorControl {
                supervisor_shutdown,
            });
            let cpu_profile = parsed.cpu_profile.as_str();
            crate::boot_trace::mark("guest_loaded");
            let mut outcome = run_vcpus::<M, E>(
                &mut vm,
                vcpus,
                cpu_profile,
                &parsed.vcpu as &dyn BootVcpuState,
                control,
            )?;
            while matches!(outcome, VcpuStop::GuestReset) {
                log::info!("guest requested reboot - replaying launch writes");
                vm.reset_for_reboot().map_err(RunError::machine)?;
                // Re-map the PMI just to replay the raw section loads, then drop
                // it again — it is not held resident between boots.
                pmi.remap().map_err(RunError::machine)?;
                apply_load_sections(&mut vm, &guest_writes, pmi.bytes())?;
                pmi.release();
                let control = Arc::new(SupervisorControl {
                    supervisor_shutdown,
                });
                outcome = run_vcpus::<M, E>(
                    &mut vm,
                    vcpus,
                    cpu_profile,
                    &parsed.vcpu as &dyn BootVcpuState,
                    control,
                )?;
            }

            if matches!(outcome, VcpuStop::GuestPoweroff) {
                dillo_virtio_console::flush_output();
            }
            Ok(0)
        }

        /// Top-level VM-child entry point for the selected host machine.
        pub(crate) fn run(
            preflight: Preflight,
            vcpus: u32,
            supervisor_shutdown: &'static AtomicBool,
        ) -> Result<i32, RunError> {
            run_selected::<selected_machine::Vm, selected_machine::Error>(
                preflight,
                vcpus,
                supervisor_shutdown,
            )
        }
    }
}
