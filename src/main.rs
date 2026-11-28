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

mod device_worker;

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

    /// console device. Specify a bus with key/value placement, e.g.
    /// `endpoint=stdio,bus=mmio,slot=0`. Add named MULTIPORT ports alongside
    /// the unnamed hvc0 with
    /// `endpoint=stdio,bus=mmio,ports=[[name=build,rx=pipe:3,tx=pipe:4],[name=log,tx=pipe:5]]`:
    /// `rx` is host→guest and `tx` is guest→host, each `pipe:N` an inherited
    /// descriptor the parent process created; an omitted direction is closed,
    /// and each port must set at least one. `endpoint` is required once
    /// `ports=` is present. Closing console input requests VM shutdown;
    /// a parent process must retain the writer for the VM's lifetime.
    #[argh(option)]
    console: Option<dillo_config::ConsoleSpec>,

    /// private local endpoint for console resize updates: columns then rows
    /// as two little-endian u16s, one four-byte update per connection.
    #[argh(option)]
    console_resize: Option<std::path::PathBuf>,

    /// virtio-blk device (raw image). Repeatable. Key/value:
    /// `path=P[,readonly],bus=pci|mmio[,slot=N]`.
    #[argh(option)]
    blk: Vec<dillo_config::BlkSpec>,

    /// virtualized-GPT device (one GPT synthesized over its partitions).
    /// Repeatable. Key/value, e.g.
    /// `partitions=[[path=P,partuuid=U,typeguid=U,label=S]],bus=pci|mmio[,slot=N]`;
    /// `device-id`/`disk-guid` are derived from the PARTUUIDs if omitted.
    #[argh(option)]
    gpt: Vec<dillo_config::GptSpec>,

    /// virtio-vsock device (host CID 2 ⇄ guest). Repeatable. Key/value:
    /// `cid=N,uds=PATH,bus=pci|mmio[,slot=N]`. Guest connections to port N
    /// bridge to `PATH/N.sock` on the host. Unix hosts only.
    #[cfg(unix)]
    #[argh(option)]
    vsock: Vec<dillo_config::VsockSpec>,

    /// virtio-fs device: share a host directory into the guest (read-write by
    /// default; pass `readonly` to forbid guest writes). Repeatable. Key/value:
    /// `tag=NAME,source=DIR[,readonly],bus=pci|mmio[,slot=N]`. The guest mounts
    /// it with `mount -t virtiofs NAME <dir>`.
    #[argh(option)]
    fs: Vec<dillo_config::FsSpec>,

    /// virtio-net device. Repeatable. Key/value:
    /// `[backend=user|bridge|macvtap][,iface=NAME][,mac=aa:bb:cc:dd:ee:ff]`
    /// `[,forwards=[2222:22,udp:5353:53]],bus=pci|mmio[,slot=N]`.
    /// `user` (the default) is cross-platform user-mode NAT with inbound port
    /// forwarding and needs no privilege; `bridge` (Linux/macOS, needs
    /// CAP_NET_ADMIN/root) joins the host's L2 segment via `iface`; `macvtap`
    /// is Linux-only.
    #[argh(option)]
    net: Vec<dillo_config::NetSpec>,

    /// path to a JSON device layout file. Mutually exclusive with
    /// `--blk`/`--gpt`/`--vsock`/`--fs`/`--net`/`--console`.
    #[argh(option)]
    layout: Option<std::path::PathBuf>,

    /// eagerly commit all guest RAM up front (fallocate) so hugepage-pool
    /// exhaustion fails at launch instead of a mid-run SIGBUS. Default is
    /// lazy first-touch commit (faster boot, denser warm pools). Linux/KVM
    /// only; ignored on other backends.
    #[argh(switch)]
    preallocate: bool,

    /// path to an out-of-band base DTB. Required to launch a detached image (a
    /// `dt:dtb` fill with no bundled base); in optional mode it overrides the
    /// bundled fallback. Rejected for a bundled image, whose base is loaded and
    /// measured and cannot be substituted.
    #[argh(option)]
    dtb: Option<std::path::PathBuf>,

    /// bootconfig text for the image's lbc:bootconfig fill. Omitted or empty
    /// input leaves the reservation zero-filled. Linux parses the text.
    #[argh(option)]
    bootconfig: Option<std::path::PathBuf>,
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
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--dillo-worker")
    {
        // SAFETY: dispatch precedes logging, threads and resource acquisition.
        // The parent grants only its retained ordinary-RAM backing to this
        // fresh process; native handles arrive on the private bootstrap channel.
        #[allow(unsafe_code)]
        let result = unsafe {
            dillo_worker::run_prepared::<machine::worker::Worker, _>(
                device_worker::prepare,
                device_worker::device::<machine::worker::Worker>,
            )
        };
        if let Err(error) = result {
            eprintln!("dillo device worker: {error}");
            std::process::exit(1);
        }
        return;
    }
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
    if let Err(error) =
        dillo_virtio_console::liveness::InputLifetime::watch_stdin(&SUPERVISOR_SHUTDOWN)
    {
        eprintln!("dillo: console lifetime: {error}");
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
        || <machine::Vm as dillo_machine::Machine>::guest_address_bits().map_err(Into::into),
        memory,
        cpus,
        args.dtb.as_deref(),
        args.bootconfig.as_deref(),
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
        memory_plan,
        guest_writes,
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

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn global_bus_flag_is_rejected() {
        assert!(Args::from_args(&["dillo"], &["--bus", "pci"]).is_err());
    }

    #[test]
    fn explicit_device_bus_does_not_require_a_numeric_slot() {
        let args = Args::from_args(
            &["dillo"],
            &[
                "--pmi",
                "guest.pmi",
                "--console",
                "endpoint=stdio,bus=mmio",
                "--blk",
                "path=disk,bus=pci",
            ],
        )
        .unwrap();
        let layout = layout_from_args(&args).unwrap();
        let resolved = dillo_config::resolve(layout).unwrap();
        assert_eq!(
            resolved.console.placement.bus,
            Some(dillo_config::Bus::Mmio)
        );
        assert_eq!(resolved.console.placement.slot, None);
        assert_eq!(
            resolved.devices[0].placement().bus,
            Some(dillo_config::Bus::Pci)
        );
        assert_eq!(resolved.devices[0].placement().slot, None);
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
                && args.console.is_none(),
            "--layout is mutually exclusive with --blk/--gpt/--fs/--vsock/--net/--console"
        );
        #[cfg(unix)]
        anyhow::ensure!(
            args.vsock.is_empty(),
            "--layout is mutually exclusive with --blk/--gpt/--fs/--vsock/--console"
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
    use device_worker::Device as Process;

    let resolved = dillo_config::resolve(layout_from_args(args)?)?;

    // Requests + constructed devices, console first. Each device reports the
    // queues it will use; the MSI-X table gets one vector per queue plus one
    // for config-space changes.
    let mut requests: Vec<dillo_config::Placement> = Vec::with_capacity(resolved.devices.len() + 1);
    let mut built: Vec<(&'static str, device_worker::Device)> = Vec::new();

    requests.push(resolved.console.placement.clone());
    built.push((
        "virtio-console",
        Process(build_console_device(
            &resolved.console,
            args.console_resize.as_deref(),
        )?),
    ));

    for device in &resolved.devices {
        requests.push(device.placement().clone());
        match device {
            #[cfg(unix)]
            dillo_config::ResolvedDevice::Vsock { cid, uds, .. } => {
                built.push((
                    "virtio-vsock",
                    Process({
                        let directory = uds.clone();
                        dillo_worker::Prepared::new(
                            dillo_worker::DeviceInfo {
                                kind: 19,
                                queues: vec![128; 3],
                                config_len: 8,
                            },
                            &device_worker::Backing::Vsock { cid: *cid },
                            Vec::new(),
                        )?
                        .with_grants(move |request, _channel| {
                            let port = u32::from_ne_bytes(
                                request
                                    .try_into()
                                    .map_err(|_| std::io::ErrorKind::InvalidInput)?,
                            );
                            let stream = dillo_virtio_vsock::connect_port(&directory, port)?;
                            Ok(dillo_machine::worker::Message {
                                bytes: Vec::new(),
                                resources: vec![stream.into()],
                            }
                            .into())
                        })
                    }),
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
                let mut authority = device_worker::filesystem::Authority::new(source, *readonly)
                    .with_context(|| format!("sharing virtio-fs source {}", source.display()))?;
                let fs = dillo_worker::Prepared::new(
                    dillo_worker::DeviceInfo {
                        kind: 26,
                        queues: vec![128; 2],
                        config_len: 40,
                    },
                    &device_worker::Backing::Fs {
                        tag: tag.clone(),
                        readonly: *readonly,
                    },
                    Vec::new(),
                )?
                .with_grants(move |request, _| authority.serve(request));
                built.push(("virtio-fs", Process(fs)));
            }
            dillo_config::ResolvedDevice::Net {
                backend,
                iface,
                mac,
                forwards,
                ..
            } => {
                let device = build_net_device(*backend, iface.as_deref(), *mac, forwards)?;
                built.push(("virtio-net", device));
            }
            other => {
                let (name, blk) = build_block_device(other)?;
                built.push((name, Process(blk)));
            }
        }
    }

    let capacity = capacity_from_platform(platform);
    let placed =
        dillo_config::allocate(&capacity, &requests).map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(placed
        .into_iter()
        .zip(built)
        .map(|(placed, (name, device))| runner::DevicePlacement {
            bus: placed.bus,
            index: placed.index,
            // One MSI-X vector per virtqueue, plus one for config-space
            // changes. Taken from the constructed device, so a MULTIPORT
            // console with N named ports gets its 2N+4 queues' worth.
            msix_vectors: msix_vectors_for(device.num_queues()),
            name,
            device,
        })
        .collect())
}

/// MSI-X table entries for a device: one per virtqueue plus one for config.
fn msix_vectors_for(queues: usize) -> u16 {
    u16::try_from(queues)
        .unwrap_or(u16::MAX - 1)
        .saturating_add(1)
}

/// Build the virtio-console, adopting each named port's inherited `pipe:N`
/// ends. Runs inside `build_placements`, i.e. before raw-terminal mode, so a
/// bad descriptor is a plain startup error rather than a mid-boot surprise.
fn build_console_device(
    console: &dillo_config::ResolvedConsole,
    resize: Option<&std::path::Path>,
) -> anyhow::Result<dillo_worker::Prepared> {
    use dillo_virtio_console::pipe::{Direction, PipeEnd};
    let (bridge, input, output) = dillo_virtio_console::stdio::Bridge::new()?;
    let mut files = vec![input, output];
    let forwarder = if let Some(path) = resize {
        let (forwarder, pipe) = dillo_virtio_console::resize::Forwarder::bind(path)?;
        files.push(pipe);
        Some(forwarder)
    } else {
        None
    };
    let mut ports = Vec::with_capacity(console.ports.len());
    for port in &console.ports {
        for (direction, pipe) in [(Direction::Rx, port.rx), (Direction::Tx, port.tx)] {
            if let Some(pipe) = pipe {
                files.push(PipeEnd::adopt(&port.name, direction, pipe.number())?.into_file());
            }
        }
        ports.push(device_worker::Port {
            name: port.name.clone(),
            rx: port.rx.is_some(),
            tx: port.tx.is_some(),
        });
    }
    let multiport = !ports.is_empty() || resize.is_some();
    let queues = if multiport { 4 + 2 * ports.len() } else { 2 };
    let mut prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 3,
            queues: vec![dillo_virtio_console::QUEUE_MAX; queues],
            config_len: 12,
        },
        &device_worker::Backing::Console {
            ports,
            resize: resize.is_some(),
        },
        files,
    )?
    .retain(bridge);
    if let Some(mut forwarder) = forwarder {
        prepared = prepared.with_config_poll(move || forwarder.poll());
    }
    Ok(prepared)
}

/// Construct the `VirtioBlk` for one resolved device (opening its backing files).
fn build_block_device(
    device: &dillo_config::ResolvedDevice,
) -> anyhow::Result<(&'static str, dillo_worker::Prepared)> {
    use anyhow::Context as _;
    use device_worker::{Backing, Partition};
    match device {
        dillo_config::ResolvedDevice::Blk {
            path,
            readonly,
            format,
            ..
        } => {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(!readonly)
                .open(path)
                .with_context(|| format!("opening blk image {}", path.display()))?;
            let backing = match format {
                dillo_config::BlockFormat::Raw => Backing::Raw {
                    readonly: *readonly,
                },
                dillo_config::BlockFormat::Qcow2 => {
                    use imago::{StorageExt, StorageOpenOptions};
                    if !file.metadata()?.is_file() {
                        anyhow::bail!("qcow2 requires a regular file");
                    }
                    if *readonly {
                        file.try_lock_shared()?;
                    } else {
                        file.try_lock()?;
                    }
                    if !readonly {
                        // Probe a disposable sibling on the same filesystem; never
                        // punch an unknown range in the actual image.
                        let parent = path
                            .parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .unwrap_or(std::path::Path::new("."));
                        let probe = tempfile::NamedTempFile::new_in(parent)?;
                        let storage = imago::file::File::from_open_file(
                            probe.reopen()?,
                            StorageOpenOptions::new().write(true),
                        )?;
                        storage.write(&vec![0x5a; 1024 * 1024][..], 0)?;
                        storage
                            .reclaim(0, 1024 * 1024)
                            .context("qcow2 requires host hole punching")?;
                    }

                    Backing::Qcow2 {
                        readonly: *readonly,
                    }
                }
            };
            Ok((
                "virtio-blk",
                dillo_worker::Prepared::new(device_worker::block_info(), &backing, vec![file])?,
            ))
        }
        dillo_config::ResolvedDevice::Gpt {
            device_id,
            disk_guid,
            partitions,
            ..
        } => {
            let files = partitions
                .iter()
                .map(|p| std::fs::File::open(&p.path))
                .collect::<std::io::Result<Vec<_>>>()?;
            let parts = partitions
                .iter()
                .map(|p| Partition {
                    partuuid: *p.partuuid.as_bytes(),
                    typeguid: *p.typeguid.as_bytes(),
                    label: p.label.clone(),
                    attrs: p.attrs,
                })
                .collect();
            Ok((
                "virtio-gpt",
                dillo_worker::Prepared::new(
                    device_worker::block_info(),
                    &Backing::Gpt {
                        device_id: *device_id,
                        disk_guid: *disk_guid,
                        partitions: parts,
                    },
                    files,
                )?,
            ))
        }
        _ => anyhow::bail!("internal: non-block device passed to block factory"),
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
) -> anyhow::Result<device_worker::Device> {
    #[cfg(unix)]
    use anyhow::Context as _;
    use device_worker::Device as Process;
    use dillo_config::NetBackendKind;

    match backend {
        NetBackendKind::User => Ok(Process(device_worker::network::prepare(
            mac,
            forwards.iter().map(translate_forward).collect(),
        )?)),
        #[cfg(target_os = "linux")]
        NetBackendKind::Bridge | NetBackendKind::Macvtap => {
            let name = iface.context("native network backend requires iface=<interface>")?;
            let file = match backend {
                NetBackendKind::Bridge => dillo_virtio_net::BridgeBackend::open(name)
                    .with_context(|| {
                        format!("creating tap on bridge {name:?} (needs CAP_NET_ADMIN)")
                    })?
                    .into_file(),
                _ => dillo_virtio_net::MacvtapBackend::open(name)
                    .with_context(|| format!("attaching macvtap {name:?}"))?
                    .into_file(),
            };
            Ok(Process(dillo_worker::Prepared::new(
                dillo_worker::DeviceInfo {
                    kind: 1,
                    queues: vec![256; 2],
                    config_len: 8,
                },
                &device_worker::Backing::FrameNet { mac },
                vec![file],
            )?))
        }
        #[cfg(target_os = "macos")]
        NetBackendKind::Bridge => {
            let name = iface.context("net backend `bridge` requires iface=<physical-interface>")?;
            Ok(Process(dillo_worker::Prepared::new(
                dillo_worker::DeviceInfo {
                    kind: 1,
                    queues: vec![256; 2],
                    config_len: 8,
                },
                &device_worker::Backing::Vmnet {
                    mac,
                    interface: name.to_owned(),
                },
                Vec::new(),
            )?))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        NetBackendKind::Bridge => {
            let _ = iface;
            anyhow::bail!("net backend `bridge` is unsupported on this host (Windows)");
        }
        #[cfg(not(target_os = "linux"))]
        NetBackendKind::Macvtap => {
            anyhow::bail!("net backend `macvtap` is Linux-only; use backend=user on this host");
        }
    }
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
    let pci = platform.has_pcie().then(|| {
        let by_window = (platform.pcie().mmio_size / BAR_STRIDE) as u32;
        by_window.min(31) // PCI device numbers 1..=31 (slot 0 = host bridge)
    });
    dillo_config::Capacity {
        pci,
        mmio: platform.virtio_mmio().len() as u32,
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

    use dillo_machine::RamRange;
    use thiserror::Error;

    const HUGE_PAGE: u64 = 2 << 20;

    #[derive(Debug, Clone, Copy)]
    struct Interval {
        start: u64,
        end: u64, // exclusive
    }

    /// The RAM extents used for both native registration and the guest overlay.
    #[derive(Debug)]
    pub(crate) struct MemoryPlan {
        ranges: Vec<RamRange>,
    }

    impl MemoryPlan {
        pub(crate) fn ranges(&self) -> &[RamRange] {
            &self.ranges
        }

        pub(crate) fn into_ranges(self) -> Vec<RamRange> {
            self.ranges
        }
    }

    #[derive(Debug, Error)]
    pub(crate) enum PlanError {
        #[error("guest range {base:#x} + {size:#x} overflows after 2 MiB rounding")]
        AddressOverflow { base: u64, size: u64 },
        #[error("invalid guest address width {0}")]
        InvalidAddressBits(u32),
        #[error("range [{start:#x}..{end:#x}) exceeds the {address_bits}-bit guest address space")]
        OutOfRange {
            start: u64,
            end: u64,
            address_bits: u32,
        },
        #[error(
            "--memory {requested_mib} MiB is less than the {islands_mib} MiB required to cover \
             loaded sections + reset trampoline"
        )]
        TooLittleMemory {
            requested_mib: u64,
            islands_mib: u64,
        },
        #[error(
            "requested {requested_mib} MiB, but only {available_mib} MiB fits in the \
             {address_bits}-bit guest address space after excluding device regions"
        )]
        InsufficientCapacity {
            requested_mib: u64,
            available_mib: u64,
            address_bits: u32,
        },
        #[error(
            "RAM region [{ram_start:#x}..{ram_end:#x}) overlaps declared device region \
             [{device_start:#x}..{device_end:#x}) after 2 MiB rounding"
        )]
        RamOverlapsDevice {
            ram_start: u64,
            ram_end: u64,
            device_start: u64,
            device_end: u64,
        },
    }

    pub(crate) fn plan_around_regions<I>(
        address_bits: u32,
        must_cover: &[(u64, u64)],
        memory_mib: u32,
        device_regions: I,
    ) -> Result<MemoryPlan, PlanError>
    where
        I: IntoIterator<Item = (u64, u64)>,
    {
        let ceiling = 1u64
            .checked_shl(address_bits)
            .filter(|_| address_bits > 0)
            .ok_or(PlanError::InvalidAddressBits(address_bits))?;
        let budget = round_up_2mib(u64::from(memory_mib) * (1 << 20))
            .expect("a u32 MiB budget fits in u64 after rounding");

        // ── 1. Islands ────────────────────────────────────────────────
        let mut islands: Vec<Interval> = must_cover
            .iter()
            .filter(|(_, s)| *s > 0)
            .map(|&(gpa, size)| rounded_interval(gpa, size))
            .collect::<Result<_, _>>()?;
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
        let mut remaining = budget - islands_total;

        // ── 2. Fill available gaps, lowest addresses first ────────────
        let device_regions: Vec<_> = device_regions.into_iter().collect();
        let mut holes: Vec<Interval> = device_holes(device_regions.iter().copied())?;
        for range in islands.iter().chain(&holes) {
            if range.end > ceiling {
                return Err(PlanError::OutOfRange {
                    start: range.start,
                    end: range.end,
                    address_bits,
                });
            }
        }
        holes.extend(islands.iter().copied());
        merge_intervals(&mut holes);

        log::debug!("placement: device+island holes ({} ranges):", holes.len());
        for h in &holes {
            log::debug!("  hole [{:#x}..{:#x})", h.start, h.end);
        }

        let mut ranges = islands;
        let mut cursor = 0;
        let limit = Interval {
            start: ceiling,
            end: ceiling,
        };
        for hole in holes.iter().chain(std::iter::once(&limit)) {
            let size = remaining.min(hole.start - cursor);
            if size > 0 {
                ranges.push(Interval {
                    start: cursor,
                    end: cursor + size,
                });
                remaining -= size;
            }
            if remaining == 0 {
                break;
            }
            cursor = hole.end;
        }
        if remaining > 0 {
            return Err(PlanError::InsufficientCapacity {
                requested_mib: budget >> 20,
                available_mib: (budget - remaining) >> 20,
                address_bits,
            });
        }

        // ── 3. Assemble final region set ─────────────────────────────
        merge_intervals(&mut ranges);
        let regions: Vec<_> = ranges
            .into_iter()
            .map(|interval| RamRange {
                gpa: interval.start,
                size: interval.end - interval.start,
            })
            .collect();

        // Section-byte validation cannot see devices in the padding added by
        // hugepage rounding. Check every final RAM extent before publishing
        // the plan.
        for ram in &regions {
            let ram_end = ram.gpa + ram.size;
            for &(device_start, device_size) in &device_regions {
                // Nonempty device ranges were checked by device_holes.
                let device_end = device_start + device_size;
                if device_size > 0 && ram.gpa < device_end && device_start < ram_end {
                    return Err(PlanError::RamOverlapsDevice {
                        ram_start: ram.gpa,
                        ram_end,
                        device_start,
                        device_end,
                    });
                }
            }
        }

        Ok(MemoryPlan { ranges: regions })
    }

    /// Device MMIO regions, rounded outward to 2 MiB.
    fn device_holes<I>(regions: I) -> Result<Vec<Interval>, PlanError>
    where
        I: IntoIterator<Item = (u64, u64)>,
    {
        regions
            .into_iter()
            .filter(|(_, size)| *size > 0)
            .map(|(base, size)| rounded_interval(base, size))
            .collect()
    }

    fn rounded_interval(base: u64, size: u64) -> Result<Interval, PlanError> {
        let end = base
            .checked_add(size)
            .and_then(round_up_2mib)
            .ok_or(PlanError::AddressOverflow { base, size })?;
        Ok(Interval {
            start: base & !(HUGE_PAGE - 1),
            end,
        })
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

    fn round_up_2mib(n: u64) -> Option<u64> {
        n.checked_add(HUGE_PAGE - 1)
            .map(|end| end & !(HUGE_PAGE - 1))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn budgets_cross_four_gib_without_allocating_backing() {
            for memory_mib in [3072, 4096, 8192] {
                let plan = plan_around_regions(36, &[(0, HUGE_PAGE)], memory_mib, [])
                    .expect("budget fits guest width");
                assert_eq!(
                    plan.ranges().iter().map(|r| r.size).sum::<u64>(),
                    u64::from(memory_mib) << 20
                );
            }
        }

        #[test]
        fn width_bounds_islands_even_when_no_ram_remains() {
            let top = 1 << 36;
            let plan = plan_around_regions(36, &[(top - HUGE_PAGE, HUGE_PAGE)], 2, []).unwrap();
            assert_eq!(plan.ranges()[0].gpa + plan.ranges()[0].size, top);
            assert!(matches!(
                plan_around_regions(36, &[(top - HUGE_PAGE, HUGE_PAGE + 1)], 4, []),
                Err(PlanError::OutOfRange { .. })
            ));
            assert!(matches!(
                plan_around_regions(36, &[], 2, [(top, 1)]),
                Err(PlanError::OutOfRange { .. })
            ));
        }

        #[test]
        fn exact_address_space_capacity_and_one_page_more() {
            let plan = plan_around_regions(23, &[], 8, []).unwrap();
            assert_eq!(plan.ranges()[0].size, 8 << 20);
            assert!(matches!(
                plan_around_regions(23, &[], 10, []),
                Err(PlanError::InsufficientCapacity { .. })
            ));
            for bits in [0, 64, 128] {
                assert!(matches!(
                    plan_around_regions(bits, &[], 2, []),
                    Err(PlanError::InvalidAddressBits(_))
                ));
            }
        }

        #[test]
        fn fragmented_capacity_is_combined_and_counted_exactly() {
            // Eight 2 MiB pages, with device holes in pages 1, 3 and 6.
            // The other five pages fit even though no gap holds the budget.
            let devices = [(2 << 20, 2 << 20), (6 << 20, 2 << 20), (12 << 20, 2 << 20)];
            let plan = plan_around_regions(24, &[(8 << 20, 1)], 10, devices).unwrap();
            let ranges = plan
                .ranges()
                .iter()
                .map(|r| (r.gpa, r.size))
                .collect::<Vec<_>>();
            assert_eq!(
                ranges,
                vec![
                    (0, 2 << 20),
                    (4 << 20, 2 << 20),
                    (8 << 20, 4 << 20),
                    (14 << 20, 2 << 20)
                ]
            );
            assert!(matches!(
                plan_around_regions(24, &[(8 << 20, 1)], 12, devices),
                Err(PlanError::InsufficientCapacity {
                    requested_mib: 12,
                    available_mib: 10,
                    ..
                })
            ));
        }

        #[test]
        fn every_eight_page_fragmentation_matches_usable_capacity() {
            for mask in 0u8..=255 {
                let devices = (0..8)
                    .filter(|page| mask & (1 << page) != 0)
                    .map(|page| (page * HUGE_PAGE, HUGE_PAGE))
                    .collect::<Vec<_>>();
                let available = 8 - mask.count_ones();
                for pages in 0..=9 {
                    let result = plan_around_regions(24, &[], pages * 2, devices.iter().copied());
                    if pages > available {
                        assert!(matches!(
                            result,
                            Err(PlanError::InsufficientCapacity { .. })
                        ));
                        continue;
                    }
                    let plan = result.unwrap();
                    assert_eq!(
                        plan.ranges().iter().map(|r| r.size).sum::<u64>(),
                        u64::from(pages) * HUGE_PAGE
                    );
                    for range in plan.ranges() {
                        for page in range.gpa / HUGE_PAGE..(range.gpa + range.size) / HUGE_PAGE {
                            assert!(page < 8 && mask & (1 << page) == 0);
                        }
                    }
                }
            }
        }

        #[test]
        fn rounded_islands_share_the_budget_and_coalesce() {
            let islands = [(1, 1), (HUGE_PAGE - 1, 2)];
            assert!(matches!(
                plan_around_regions(32, &islands, 2, []),
                Err(PlanError::TooLittleMemory { islands_mib: 4, .. })
            ));
            let plan = plan_around_regions(32, &islands, 5, []).unwrap();
            assert_eq!(plan.ranges().len(), 1);
            assert_eq!((plan.ranges()[0].gpa, plan.ranges()[0].size), (0, 6 << 20));
        }

        #[test]
        fn four_gib_budget_fills_both_sides_of_device_holes() {
            let devices = [(0xfec0_0000, 0x1000), (0xfee0_0000, 0x1000)];
            let plan = plan_around_regions(36, &[(0x100_0000, HUGE_PAGE)], 4096, devices).unwrap();
            assert_eq!(plan.ranges().iter().map(|r| r.size).sum::<u64>(), 1 << 32);
            assert!(plan.ranges().iter().any(|r| r.gpa + r.size > 1 << 32));
            assert!(matches!(
                plan_around_regions(32, &[(0x100_0000, HUGE_PAGE)], 4096, devices),
                Err(PlanError::InsufficientCapacity {
                    available_mib: 4092,
                    ..
                })
            ));
        }

        #[test]
        fn rejects_range_and_alignment_overflow() {
            for range in [(u64::MAX, 2), (u64::MAX - 1, 1)] {
                assert!(matches!(
                    plan_around_regions(32, &[range], 2, []),
                    Err(PlanError::AddressOverflow { .. })
                ));
                assert!(matches!(
                    plan_around_regions(32, &[], 2, [range]),
                    Err(PlanError::AddressOverflow { .. })
                ));
            }
        }

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
        fn plan_around_regions_uses_declared_holes() {
            let plan = plan_around_regions(32, &[(0, 0x20_0000)], 8, [(0x20_0000, 0x20_0000)])
                .expect("placement");

            assert_eq!(plan.ranges().len(), 2);
            assert_eq!(plan.ranges()[0].gpa, 0);
            assert_eq!(plan.ranges()[0].size, 0x20_0000);
            assert_eq!(plan.ranges()[1].gpa, 0x40_0000);
            assert_eq!(plan.ranges()[1].size, 0x60_0000);
        }

        #[test]
        fn plan_around_regions_rejects_ram_overlapping_devices() {
            for (must_cover, device) in [
                // Byte-disjoint section and device in the same hugepage.
                ((0x10_0000, 0x1000), (0x10_1000, 0x1000)),
                // Device in the padding before a section.
                ((0x10_1000, 0x1000), (0x10_0000, 0x1000)),
                // A section spans multiple hugepages; device in its final page.
                ((0x10_0000, 0x20_0001), (0x30_1000, 0x1000)),
                // Direct byte overlap remains invalid.
                ((0x10_0000, 0x1000), (0x10_0000, 4)),
            ] {
                // Exercise both an island-only plan and one with additional RAM.
                let island_mib = if must_cover.1 > HUGE_PAGE { 4 } else { 2 };
                for memory_mib in [island_mib, 8] {
                    let err = plan_around_regions(32, &[must_cover], memory_mib, [device])
                        .expect_err("RAM must not cover a device");
                    assert!(
                        matches!(err, PlanError::RamOverlapsDevice {
                            device_start, device_end, ..
                        } if device_start == device.0 && device_end == device.0 + device.1),
                        "unexpected error for section {must_cover:x?}, device {device:x?}: {err}"
                    );
                }
            }
        }

        #[test]
        fn plan_around_regions_rejects_device_in_load_and_fill_island() {
            // The issue #5 layout: the DTB load and DTBO fill share a page;
            // neither section's bytes touch the poweroff register.
            let err = plan_around_regions(
                32,
                &[(0, 0x8_0000), (0x8_0000, 0x1000)],
                2,
                [(0x10_0000, 4)],
            )
            .unwrap_err();
            assert!(matches!(
                err,
                PlanError::RamOverlapsDevice {
                    ram_start: 0,
                    ram_end: 0x20_0000,
                    device_start: 0x10_0000,
                    device_end: 0x10_0004,
                }
            ));
        }

        #[test]
        fn plan_around_regions_accepts_adjacent_device_pages() {
            let devices = [(0x1f_f000, 0x1000), (0x40_0000, 4)];
            for memory_mib in [2, 8] {
                let plan = plan_around_regions(32, &[(0x20_1000, 0x1000)], memory_mib, devices)
                    .expect("devices outside the rounded section");
                assert_eq!(plan.ranges()[0].gpa, 0x20_0000);
                assert_eq!(plan.ranges()[0].size, 0x20_0000);
                assert_eq!(
                    plan.ranges().iter().map(|r| r.size).sum::<u64>(),
                    u64::from(memory_mib) << 20
                );
                for ram in plan.ranges() {
                    for (base, size) in devices {
                        assert!(ram.gpa + ram.size <= base || base + size <= ram.gpa);
                    }
                }
            }
        }

        #[test]
        fn plan_around_regions_ignores_zero_sized_regions() {
            let plan = plan_around_regions(
                32,
                &[(0x10_0000, 0), (0x20_1000, 0x1000)],
                2,
                [(0x10_0000, 4), (0x20_1000, 0)],
            )
            .expect("empty sections and device regions do not overlap RAM");
            assert_eq!(plan.ranges().len(), 1);
            assert_eq!(plan.ranges()[0].gpa, 0x20_0000);
            assert_eq!(plan.ranges()[0].size, 0x20_0000);
        }
    }
}

mod overlay {

    use anyhow::{Result, anyhow};
    use dillo_machine::RamRange;

    use crate::fdt_writer::FdtBuilder;

    pub(crate) fn synthesize_dtbo(
        regions: &[RamRange],
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
    mod bootconfig;

    #[cfg(test)]
    mod delegation_tests;

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
    use crate::runner::RunError;
    use dillo_launch::pmi_parse::{ActionKind, FillKind, HostArch, ParseOptions};

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

    /// Bytes synthesized by Dillo or a section loaded directly from the PMI.
    #[derive(Debug)]
    enum WriteSrc {
        Owned(Vec<u8>),
        Image { offset: usize, len: usize },
    }

    /// Target-neutral launch facts derived before backend construction.
    #[derive(Debug)]
    pub(crate) struct LaunchPlan {
        pub(crate) parsed: dillo_launch::pmi_parse::ParsedPmi,
        pub(crate) platform: PlatformMachine,
        pub(crate) memory: MemoryPlan,
        pub(crate) guest_writes: Vec<GuestWrite>,
        pub(crate) pmi: Pmi,
    }

    /// One launch-time write into guest RAM.
    #[derive(Debug)]
    pub(crate) struct GuestWrite {
        section: String,
        gpa: u64,
        data: WriteSrc,
        zero_tail: u64,
    }

    impl GuestWrite {
        pub(crate) fn apply(
            &self,
            pmi_bytes: &[u8],
            mut write_guest: impl FnMut(u64, &[u8]) -> Result<(), RunError>,
        ) -> Result<(), RunError> {
            static ZEROES: [u8; 64 * 1024] = [0; 64 * 1024];
            let data = match &self.data {
                WriteSrc::Owned(v) => v.as_slice(),
                WriteSrc::Image { len: 0, .. } => &[],
                WriteSrc::Image { offset, len } => pmi_bytes
                    .get(*offset..offset.saturating_add(*len))
                    .ok_or_else(|| {
                        RunError::Machine(format!(
                            "launch section `{}` range {:#x}+{:#x} out of PMI bounds",
                            self.section, offset, len
                        ))
                    })?,
            };
            let mut zero_tail = self.zero_tail;
            log::debug!(
                "writing launch section `{}` to GPA {:#x} ({} bytes)",
                self.section,
                self.gpa,
                data.len() as u64 + zero_tail
            );
            if !data.is_empty() {
                write_guest(self.gpa, data)?;
            }
            let mut gpa = self.gpa + data.len() as u64;
            while zero_tail > 0 {
                let len = zero_tail.min(ZEROES.len() as u64) as usize;
                write_guest(gpa, &ZEROES[..len])?;
                gpa += len as u64;
                zero_tail -= len as u64;
            }
            Ok(())
        }
    }

    impl LaunchPlan {
        /// Read a PMI file, validate target-neutral launch facts, and compute RAM
        /// placement from the DTB-declared platform.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn read(
            pmi_path: &Path,
            host_arch: HostArchitecture,
            cpu_compatible: Option<&str>,
            address_bits: impl FnOnce() -> anyhow::Result<u32>,
            memory_mib: u32,
            vcpus: u32,
            base_dtb_path: Option<&Path>,
            bootconfig_path: Option<&Path>,
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
            let parsed = dillo_launch::pmi_parse::parse(
                bytes,
                &ParseOptions {
                    host_arch: pmi_arch,
                    memory_mib,
                },
            )?;
            if bootconfig_path.is_some()
                && !parsed
                    .actions
                    .iter()
                    .any(|action| action.kind == ActionKind::Fill(FillKind::LbcBootconfig))
            {
                return Err(bootconfig::Error::Undeclared.into());
            }
            crate::boot_trace::mark("pmi_parsed");

            // Resolve the launch base DTB per channel mode: an out-of-band
            // `--dtb` (detached, or optional override), else the bundled base
            // the `dt:dtb` attribute names (bundled load / optional fallback).
            let oob_base: Option<Vec<u8>> = match base_dtb_path {
                Some(p) => Some(std::fs::read(p).map_err(|source| LaunchError::ReadBaseDtb {
                    path: p.to_path_buf(),
                    source,
                })?),
                None => None,
            };
            let dtb = resolve_base(bytes, &parsed, oob_base)?;
            let platform = PlatformMachine::survey(dtb, platform_arch(host_arch))
                .map_err(LaunchError::Coverage)?;

            // The survey supports delegated CPUs and memory only: fixed CPU
            // declarations are rejected, and fixed memory is unclaimed. Require
            // the channel that delivers their allocation before planning RAM.
            if !parsed
                .actions
                .iter()
                .any(|action| action.kind == ActionKind::Fill(FillKind::DtDtbo))
            {
                return Err(LaunchError::DelegatedAllocationRequiresDtbo);
            }

            // Invalid images must still fail without requiring a hypervisor.
            let address_bits = address_bits().map_err(LaunchError::AddressSpaceProbe)?;
            let action_ranges: Vec<_> = parsed
                .actions
                .iter()
                .map(|action| {
                    (
                        action.section.clone(),
                        action.gpa,
                        action.source.virtual_size,
                    )
                })
                .collect();
            let required_bits = platform.min_addr_space_bits();
            if required_bits > address_bits {
                return Err(LaunchError::AddressSpace {
                    required_bits,
                    available_bits: address_bits,
                });
            }
            platform
                .plan()
                .cross_validate_loads(&action_ranges, address_bits)
                .map_err(LaunchError::DtbCrossValidate)?;

            let must_cover: Vec<_> = action_ranges
                .iter()
                .map(|&(_, gpa, size)| (gpa, size))
                .collect();
            let memory = placement::plan_around_regions(
                address_bits,
                &must_cover,
                memory_mib,
                platform.placement_regions(),
            )?;
            let guest_writes = guest_writes(
                &parsed,
                &memory,
                platform.arch(),
                cpu_compatible,
                vcpus,
                FillInputs {
                    base_dtb: platform.dtb(),
                    bootconfig: bootconfig_path,
                },
            )?;
            crate::boot_trace::mark("guest_writes_built");

            // `bytes` (a borrow of `pmi`) is unused past here, so `pmi` can move
            // into the plan: raw section loads reference it by offset and are
            // copied straight from it into guest RAM at apply time (single copy).
            Ok(Self {
                parsed,
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
        #[error("guest address space: {0}")]
        AddressSpaceProbe(#[source] anyhow::Error),
        #[error("platform requires {required_bits} address bits; guest provides {available_bits}")]
        AddressSpace {
            required_bits: u32,
            available_bits: u32,
        },
        #[error("read PMI {path}: {source}")]
        ReadPmi {
            path: String,
            #[source]
            source: std::io::Error,
        },

        #[error("PMI parse: {0}")]
        PmiParse(#[from] dillo_launch::pmi_parse::Error),

        #[error("read base DTB {path}: {source}")]
        ReadBaseDtb {
            path: std::path::PathBuf,
            #[source]
            source: std::io::Error,
        },

        #[error(
            "this PMI delivers its base DTB out-of-band (detached); pass the base \
             with --dtb <path>"
        )]
        DetachedBaseRequiresDtb,

        #[error(
            "--dtb was given, but this PMI bundles its base DTB (no dt:dtb fill); \
             a bundled base is measured and cannot be substituted"
        )]
        UnexpectedBaseOverride,

        #[error("base DTB ({actual} bytes) exceeds its reserved fill section ({cap} bytes)")]
        BaseDtbTooLarge { actual: u64, cap: u64 },

        #[error("base DTB coverage: {0}")]
        Coverage(SurveyError),

        #[error("delegated CPU and memory allocation requires a dt:dtbo fill")]
        DelegatedAllocationRequiresDtbo,

        #[error("base DTB / PE cross-validation: {0}")]
        DtbCrossValidate(SurveyError),

        #[error("merged_dtb section lies outside the PMI file")]
        MalformedMergedDtb,

        #[error("memory placement: {0}")]
        Placement(#[from] placement::PlanError),

        #[error("synthesize host DTBO: {0}")]
        DtboSynth(#[source] anyhow::Error),

        #[error("bootconfig: {0}")]
        Bootconfig(#[from] bootconfig::Error),
    }

    impl LaunchError {
        /// Map to the documented dillo launch exit code categories.
        #[must_use]
        pub(crate) fn exit_code(&self) -> i32 {
            match self {
                Self::ReadPmi { .. } | Self::PmiParse(_) | Self::ReadBaseDtb { .. } => 10,
                Self::DetachedBaseRequiresDtb
                | Self::UnexpectedBaseOverride
                | Self::BaseDtbTooLarge { .. }
                | Self::Coverage(_)
                | Self::DelegatedAllocationRequiresDtbo
                | Self::DtbCrossValidate(_)
                | Self::MalformedMergedDtb
                | Self::DtboSynth(_)
                | Self::Bootconfig(_) => 11,
                Self::Placement(_) | Self::AddressSpace { .. } | Self::AddressSpaceProbe(_) => 13,
            }
        }
    }

    struct FillInputs<'a> {
        base_dtb: &'a [u8],
        bootconfig: Option<&'a Path>,
    }

    fn guest_writes(
        parsed: &dillo_launch::pmi_parse::ParsedPmi,
        memory: &MemoryPlan,
        arch: Arch,
        cpu_compatible: Option<&str>,
        vcpus: u32,
        inputs: FillInputs<'_>,
    ) -> Result<Vec<GuestWrite>, LaunchError> {
        let base_dtb = inputs.base_dtb;
        let mut writes = Vec::with_capacity(parsed.actions.len());
        for action in &parsed.actions {
            let source = &action.source;
            // Parsing validated the enclosing backing extent.
            let size = source
                .virtual_size
                .next_multiple_of(dillo_launch::pmi_parse::caps::SMALL_PAGE);
            let (data, zero_tail) = match action.kind {
                ActionKind::Fill(FillKind::LbcBootconfig) => {
                    let reservation =
                        bootconfig::Reservation::read(source.virtual_size, inputs.bootconfig)?;
                    (
                        WriteSrc::Owned(reservation.bytes),
                        size - source.virtual_size,
                    )
                }
                ActionKind::Load => (
                    WriteSrc::Image {
                        offset: source.file_offset as usize,
                        len: source.file_size as usize,
                    },
                    size - source.file_size,
                ),
                ActionKind::Fill(FillKind::DtDtbo) => {
                    let data = crate::overlay::synthesize_dtbo(
                        memory.ranges(),
                        vcpus,
                        arch.cpu_enable_method(),
                        cpu_compatible,
                        source.virtual_size,
                    )
                    .map_err(LaunchError::DtboSynth)?;
                    (WriteSrc::Owned(data), 0)
                }
                ActionKind::Fill(FillKind::DtDtb) => {
                    // Deliver the resolved measured base into its reserved Zero
                    // section (detached/optional). The base was resolved once in
                    // `read` (out-of-band `--dtb`, or the bundled fallback).
                    if base_dtb.len() as u64 > source.virtual_size {
                        return Err(LaunchError::BaseDtbTooLarge {
                            actual: base_dtb.len() as u64,
                            cap: source.virtual_size,
                        });
                    }
                    (WriteSrc::Owned(base_dtb.to_vec()), 0)
                }
            };
            writes.push(GuestWrite {
                section: action.section.clone(),
                gpa: action.gpa,
                data,
                zero_tail,
            });
        }
        Ok(writes)
    }

    /// Resolve the launch base DTB for this channel mode. An out-of-band base
    /// (`--dtb`) is used when the image expects a filled base (detached, or an
    /// optional override); otherwise the bundled base named by the `dt:dtb`
    /// attribute is used (bundled load source, or optional fallback). A detached
    /// image with no `--dtb` cannot launch; an out-of-band base is rejected for
    /// a bundled image, whose base is loaded and measured.
    fn resolve_base(
        bytes: &[u8],
        parsed: &dillo_launch::pmi_parse::ParsedPmi,
        oob: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, LaunchError> {
        let has_fill = parsed
            .actions
            .iter()
            .any(|a| a.kind == ActionKind::Fill(FillKind::DtDtb));
        match oob {
            Some(_) if !has_fill => Err(LaunchError::UnexpectedBaseOverride),
            Some(base) => Ok(base),
            None => {
                let src = parsed
                    .dt_dtb_source
                    .as_ref()
                    .ok_or(LaunchError::DetachedBaseRequiresDtb)?;
                read_section(bytes, src.file_offset, src.file_size)
                    .map(<[u8]>::to_vec)
                    .ok_or(LaunchError::MalformedMergedDtb)
            }
        }
    }

    fn read_section(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let size = usize::try_from(size).ok()?;
        let end = start.checked_add(size)?;
        bytes.get(start..end)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
                PmiParse(#[from] dillo_launch::pmi_parse::Error),

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
        use std::sync::atomic::{AtomicBool, AtomicU32};

        use super::machine as selected_machine;
        use dillo_devtree::platform::Machine as PlatformMachine;
        use dillo_devtree::platform::{MsiParentage, WiredInterrupt};
        use dillo_machine::{LaunchConfig, Machine, VcpuStop};
        use dillo_mmio::syscon;
        use dillo_mmio::{
            Attach, InterruptSource, MessageInterruptSource, MmioAttachment,
            MmioInterruptRequirement, MmioWindow,
        };
        use dillo_pci::PciRoot;
        use dillo_pci_virtio::VirtioPciAdapter;

        use crate::launch::GuestWrite;
        use crate::placement::MemoryPlan;

        pub(crate) use self::error::RunError;

        /// One device with its allocated bus + slot, ready to attach. Built by
        /// `build_placements` (console + each virtio-blk/gpt device).
        pub(crate) struct DevicePlacement {
            pub(crate) bus: dillo_config::Bus,
            /// PCI device number (when `bus == Pci`) or virtio-mmio slot index.
            pub(crate) index: u32,
            pub(crate) msix_vectors: u16,
            pub(crate) name: &'static str,
            pub(crate) device: crate::device_worker::Device,
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
            parsed: dillo_launch::pmi_parse::ParsedPmi,
            platform: PlatformMachine,
            memory: MemoryPlan,
            guest_writes: Vec<GuestWrite>,
            placements: Vec<DevicePlacement>,
            pmi: crate::launch::Pmi,
        }

        impl Preflight {
            pub(crate) fn new(
                parsed: dillo_launch::pmi_parse::ParsedPmi,
                platform: PlatformMachine,
                memory: MemoryPlan,
                guest_writes: Vec<GuestWrite>,
                placements: Vec<DevicePlacement>,
                pmi: crate::launch::Pmi,
            ) -> Self {
                Self {
                    parsed,
                    platform,
                    memory,
                    guest_writes,
                    placements,
                    pmi,
                }
            }

            fn into_parts(
                self,
            ) -> (
                dillo_launch::pmi_parse::ParsedPmi,
                PlatformMachine,
                MemoryPlan,
                Vec<GuestWrite>,
                Vec<DevicePlacement>,
                crate::launch::Pmi,
            ) {
                (
                    self.parsed,
                    self.platform,
                    self.memory,
                    self.guest_writes,
                    self.placements,
                    self.pmi,
                )
            }
        }

        fn syscon_register(syscon: dillo_devtree::platform::Syscon) -> syscon::SysconRegister {
            syscon::SysconRegister {
                base: syscon.base,
                size: syscon.size,
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
            workers: &mut Vec<dillo_worker::Control>,
            shutdown: &'static AtomicBool,
        ) -> Result<(), RunError>
        where
            E: std::error::Error + Send + Sync + 'static,
            M: Machine<Error = E>,
            M: Attach<Arc<PciRoot>, Error = E, Output = Arc<dyn MmioAttachment>>,
            M: Attach<Arc<dillo_mmio_virtio::EmptySlot>, Error = E>,
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
                let mmio_base = platform.pcie().mmio_base;
                pci.sort_by_key(|p| p.index);

                let ecam = MmioWindow {
                    base: platform.pcie().ecam_base,
                    size: platform.pcie().ecam_size,
                };
                // PciRoot recomputes the MSI-X domain size from registered
                // devices, so the seed vector count here is irrelevant.
                let mut pci_root = PciRoot::with_interrupt_requirement(
                    ecam,
                    optional_message_requirement(platform.pcie().msi.as_ref(), 0),
                );

                for (stride, placement) in pci.into_iter().enumerate() {
                    let bar0 = mmio_base + (stride as u64) * BAR_STRIDE;
                    let bar2 = bar0 + 0x1000;
                    let dev = dillo_pci_virtio::VirtioPciDevice::new(
                        Arc::new(std::sync::Mutex::new(
                            placement
                                .device
                                .bind(vm, workers, shutdown)
                                .map_err(RunError::machine)?,
                        )),
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

            for (index, slot) in platform.virtio_mmio().iter().enumerate() {
                if mmio
                    .iter()
                    .any(|placement| placement.index as usize == index)
                {
                    continue;
                }
                Attach::attach(
                    vm,
                    Arc::new(dillo_mmio_virtio::EmptySlot {
                        window: MmioWindow {
                            base: slot.base,
                            size: slot.size,
                        },
                    }),
                )
                .map_err(RunError::machine)?;
            }

            // --- MMIO: one transport per placement ---
            for placement in mmio {
                let slot = &platform.virtio_mmio()[placement.index as usize];
                let int_status = Arc::new(AtomicU32::new(0));
                let irq = dillo_mmio_virtio::WiredIrq::unresolved(slot.irq);
                let transport =
                    Arc::new(dillo_mmio_virtio::VirtioMmio::with_interrupt_requirement(
                        MmioWindow {
                            base: slot.base,
                            size: slot.size,
                        },
                        placement
                            .device
                            .bind(vm, workers, shutdown)
                            .map_err(RunError::machine)?,
                        Arc::clone(&int_status),
                        irq.clone(),
                        line_requirement(&slot.interrupt),
                    ));
                let attachment =
                    Attach::attach(vm, Arc::clone(&transport)).map_err(RunError::machine)?;
                transport.set_attachment(attachment);
                #[cfg(all(
                    any(target_os = "linux", target_os = "windows", target_os = "macos"),
                    feature = "bench-in-process"
                ))]
                if std::env::var_os("DILLO_BENCH_SHARED_ISR").is_some() {
                    transport.set_notification_state_factory(
                        <M::Worker as dillo_machine::worker::WorkerHost>::create_notification_state,
                    );
                }
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
            let Some(uart) = platform.uart() else {
                // UART is optional; a virtio console can carry guest output.
                log::debug!("platform declares no UART");
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
            let Some(poweroff) = platform.poweroff() else {
                return Ok(());
            };
            Attach::attach(
                vm,
                Arc::new(
                    syscon::SysconDevice::new(
                        syscon_register(poweroff),
                        syscon::SysconAction::Poweroff,
                    )
                    .map_err(RunError::machine)?,
                ),
            )
            .map_err(RunError::machine)?;
            if let Some(reboot) = platform.reboot() {
                Attach::attach(
                    vm,
                    Arc::new(
                        syscon::SysconDevice::new(
                            syscon_register(reboot),
                            syscon::SysconAction::Reboot,
                        )
                        .map_err(RunError::machine)?,
                    ),
                )
                .map_err(RunError::machine)?;
            }
            Ok(())
        }

        fn run_selected<M, E>(
            preflight: Preflight,
            vcpus: u32,
            supervisor_shutdown: &'static AtomicBool,
        ) -> Result<i32, RunError>
        where
            E: std::error::Error + Send + Sync + 'static,
            M: Machine<Error = E, Platform = PlatformMachine>,
            M: Attach<Arc<PciRoot>, Error = E, Output = Arc<dyn MmioAttachment>>,
            M: Attach<Arc<dillo_mmio_virtio::EmptySlot>, Error = E>,
            M: Attach<
                    Arc<dillo_mmio_virtio::VirtioMmio>,
                    Error = E,
                    Output = Arc<dyn MmioAttachment>,
                >,
            M: Attach<Arc<dillo_mmio_uart::Ns16550>, Error = E, Output = Arc<dyn MmioAttachment>>,
            M: Attach<Arc<syscon::SysconDevice>, Error = E>,
        {
            let (parsed, platform, plan, guest_writes, placements, mut pmi) =
                preflight.into_parts();
            log::debug!(
                "PMI parsed: arch={:?}, {} actions, dt:dtb source={:?}",
                parsed.arch,
                parsed.actions.len(),
                parsed.dt_dtb_source.is_some()
            );
            log::debug!(
                "coverage: base DTB fully claimed - {} declared region(s), pcie={}",
                platform.plan().regions().len(),
                platform.has_pcie()
            );
            let ranges = plan.ranges();
            let total_backed: u64 = ranges.iter().map(|r| r.size).sum();
            log::debug!(
                "memslots: {} region(s), {} bytes",
                ranges.len(),
                total_backed
            );
            log::debug!("/memory@N nodes: {} region(s)", ranges.len());
            for r in ranges {
                log::debug!("  [{:#x}..{:#x}) ({} bytes)", r.gpa, r.gpa + r.size, r.size);
            }

            let mut vm = M::from_launch_config(LaunchConfig {
                platform: &platform,
                vcpus,
                ram: plan.into_ranges(),
            })
            .map_err(RunError::machine)?;
            crate::boot_trace::mark("machine_ready");
            for write in &guest_writes {
                write.apply(pmi.bytes(), |gpa, data| {
                    vm.write_guest(gpa, data).map_err(RunError::machine)
                })?;
            }
            // Sections are now in guest RAM; drop the PMI backing so it does not
            // stay resident for the VM's lifetime. A guest reboot re-maps it.
            pmi.release();
            crate::boot_trace::mark("sections_loaded");

            attach_uart(&mut vm, &platform)?;
            attach_syscon(&mut vm, &platform)?;
            let mut workers = Vec::new();
            attach_devices(
                &mut vm,
                &platform,
                placements,
                &mut workers,
                supervisor_shutdown,
            )?;
            drop(platform);

            let cpu_profile = parsed.cpu_profile;
            crate::boot_trace::mark("guest_loaded");
            let mut outcome =
                dillo_runtime::run_cpus(&mut vm, vcpus, cpu_profile, supervisor_shutdown)
                    .map_err(RunError::machine)?;
            while matches!(outcome, VcpuStop::GuestReset) {
                log::info!("guest requested reboot - replaying launch writes");
                for worker in &workers {
                    worker.reset().map_err(RunError::machine)?;
                }
                vm.reset_for_reboot().map_err(RunError::machine)?;
                // Re-map the PMI just to replay the raw section loads, then drop
                // it again — it is not held resident between boots.
                pmi.remap().map_err(RunError::machine)?;
                for write in &guest_writes {
                    write.apply(pmi.bytes(), |gpa, data| {
                        vm.write_guest(gpa, data).map_err(RunError::machine)
                    })?;
                }
                pmi.release();
                outcome = dillo_runtime::run_cpus(&mut vm, vcpus, cpu_profile, supervisor_shutdown)
                    .map_err(RunError::machine)?;
            }

            for worker in &workers {
                worker.shutdown().map_err(RunError::machine)?;
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

        #[cfg(test)]
        mod tests {
            use super::*;
            use dillo_devtree::devtree::{OwnedNode, OwnedProperty, OwnedTree};
            use dillo_devtree::platform::Arch;
            use dillo_mmio::{MmioBus, MmioDevice, MmioWriteOutcome};

            fn reg(base: u64, size: u64) -> OwnedProperty {
                OwnedProperty::new("reg").with_u32s(&[
                    (base >> 32) as u32,
                    base as u32,
                    (size >> 32) as u32,
                    size as u32,
                ])
            }

            #[test]
            fn surveyed_syscon_extents_preserve_adjacent_resources() {
                const BASE: u64 = 0x901_0000;
                for size in [4, 0x24, 0x2000] {
                    let mut root = OwnedNode::new("")
                        .with_property(OwnedProperty::new("#address-cells").with_u32(2))
                        .with_property(OwnedProperty::new("#size-cells").with_u32(2));
                    for (base, compat, phandle) in [
                        (0xfee0_0000, "intel,ce4100-lapic", 1),
                        (0xfec0_0000, "intel,ce4100-ioapic", 2),
                    ] {
                        root.set_child(
                            OwnedNode::new(&format!("interrupt-controller@{base:x}"))
                                .with_property(OwnedProperty::new("compatible").with_str(compat))
                                .with_property(reg(base, 0x1000))
                                .with_property(OwnedProperty::new("#interrupt-cells").with_u32(2))
                                .with_property(OwnedProperty::new("interrupt-controller"))
                                .with_property(OwnedProperty::new("phandle").with_u32(phandle)),
                        );
                    }
                    for (name, compat, base, value) in [
                        ("poweroff", "syscon-poweroff", BASE, 0x34),
                        ("reboot", "syscon-reboot", BASE + size, 1),
                    ] {
                        root.set_child(
                            OwnedNode::new(&format!("{name}@{base:x}"))
                                .with_property(OwnedProperty::new("compatible").with_str(compat))
                                .with_property(reg(base, size))
                                .with_property(OwnedProperty::new("value").with_u32(value)),
                        );
                    }
                    let dtb = OwnedTree::new(root).encode().expect("encode syscon DT");
                    let platform = PlatformMachine::survey(dtb, Arch::X86_64).expect("survey");
                    let mut bus = MmioBus::new();
                    for (register, action, outcome) in [
                        (
                            platform.poweroff().unwrap(),
                            syscon::SysconAction::Poweroff,
                            MmioWriteOutcome::GuestPoweroff,
                        ),
                        (
                            platform.reboot().unwrap(),
                            syscon::SysconAction::Reboot,
                            MmioWriteOutcome::GuestReset,
                        ),
                    ] {
                        let device = Arc::new(
                            syscon::SysconDevice::new(syscon_register(register), action)
                                .expect("construct syscon"),
                        );
                        let window = device.windows()[0];
                        assert_eq!(window.size, size);
                        assert!(
                            platform
                                .plan()
                                .regions()
                                .iter()
                                .any(|region| region.gpa == window.base
                                    && region.size == window.size)
                        );
                        bus.register_device(device);
                        assert_eq!(
                            bus.write(register.base, &register.value.to_le_bytes())
                                .unwrap(),
                            Some(outcome)
                        );
                    }
                    let mut data = [0xff; 4];
                    assert!(bus.read(BASE + size - 4, &mut data).unwrap());
                    assert_eq!(data, [0; 4]);
                    assert!(!bus.read(BASE + size - 1, &mut [0; 2]).unwrap());
                    assert_eq!(bus.write(BASE + size - 1, &[0; 2]).unwrap(), None);
                    assert!(!bus.read(BASE + 2 * size, &mut [0; 1]).unwrap());
                    assert_eq!(bus.write(BASE + 2 * size, &[0; 1]).unwrap(), None);
                    assert!(!bus.read(BASE - 1, &mut [0; 1]).unwrap());
                }
            }
        }
    }
}
