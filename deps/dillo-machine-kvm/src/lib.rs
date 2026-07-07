// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

#[cfg(target_arch = "x86_64")]
mod cpuid_x86;
mod hypervisor;
mod irq;
mod memory;
mod msi;

/// Reasons a KVM vCPU run returned to backend code.
#[derive(Debug)]
enum VmExit {
    MmioRead { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: [u8; 8], size: u8 },
    PioRead { port: u16, size: u8 },
    PioWrite { port: u16, data: [u8; 4], size: u8 },
    Shutdown,
    Interrupted,
    Halted,
    Unknown(String),
}

mod imp {
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::{Arc, Mutex};
    use std::sync::{OnceLock, atomic::AtomicBool, atomic::AtomicU8, atomic::Ordering};
    use std::thread;
    use std::time::Duration;

    #[cfg(target_arch = "aarch64")]
    use dillo_devtree::{
        FromDevTree,
        devtree::{NodeView, OwnedTree, PropertyView, Tree},
    };
    use dillo_machine::{BootVcpuState, Host, HostArchitecture, LaunchConfig, RamRange, VcpuStop};
    use dillo_mmio::{
        Attach, InterruptError, InterruptLine, MmioAttachment, MmioBus, MmioDevice,
        MmioDeviceHandle, MmioInterrupt, MmioInterruptRequirement, MmioRunToken, MmioSpawnError,
        MmioWriteOutcome, SharedMemory,
    };
    use vmm_sys_util::eventfd::EventFd;

    use crate::VmExit;
    pub use crate::hypervisor::Error;
    use crate::irq::IrqManager;
    use crate::memory;
    pub use crate::memory::set_preallocate;
    use crate::msi::KvmMessageInterruptDomain;

    const VCPU_KICK_SIGNAL: nix::sys::signal::Signal = nix::sys::signal::Signal::SIGUSR1;

    extern "C" fn vcpu_kick_signal_handler(_: libc::c_int) {}

    /// Install KVM/Linux host signal handling for the dillo supervisor.
    fn install_signal_watchers(supervisor_shutdown: &'static AtomicBool) {
        use nix::sys::signal::{SigSet, Signal};
        use nix::sys::signalfd::{SfdFlags, SignalFd};

        let mut mask = SigSet::empty();
        mask.add(Signal::SIGINT);
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGQUIT);
        mask.add(Signal::SIGWINCH);
        mask.thread_block().expect("block signals on main thread");

        let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC).expect("signalfd creation");

        thread::Builder::new()
            .name("dillo-signals".into())
            .spawn(move || {
                static SEEN: AtomicU8 = AtomicU8::new(0);
                loop {
                    match sfd.read_signal() {
                        Ok(Some(sig)) => {
                            let signo = sig.ssi_signo.cast_signed();
                            if signo == Signal::SIGWINCH as i32 {
                                log::trace!("SIGWINCH - no console child to forward to yet");
                                continue;
                            }
                            let count = SEEN.fetch_add(1, Ordering::SeqCst);
                            let name = match signo {
                                n if n == Signal::SIGINT as i32 => "SIGINT",
                                n if n == Signal::SIGTERM as i32 => "SIGTERM",
                                n if n == Signal::SIGQUIT as i32 => "SIGQUIT",
                                _ => "signal",
                            };
                            if signo == Signal::SIGQUIT as i32 || count >= 1 {
                                log::warn!("{name} - hard exit");
                                std::process::exit(128 + signo);
                            }
                            log::warn!(
                                "{name} - graceful shutdown requested; waiting 5s for guest before hard exit"
                            );
                            supervisor_shutdown.store(true, Ordering::Release);

                            let signo_for_timer = signo;
                            thread::Builder::new()
                                .name("dillo-shutdown-watchdog".into())
                                .spawn(move || {
                                    thread::sleep(Duration::from_secs(5));
                                    log::warn!("guest did not shut down within 5s - hard exit");
                                    std::process::exit(128 + signo_for_timer);
                                })
                                .expect("spawn shutdown watchdog");
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            log::error!("signalfd read: {e}");
                            return;
                        }
                    }
                }
            })
            .expect("spawn dillo-signals thread");
    }

    static ORIGINAL_TERMIOS: OnceLock<libc::termios> = OnceLock::new();

    /// Raw terminal guard for KVM/Linux supervisor sessions.
    #[derive(Debug)]
    pub struct RawStdio {
        armed: bool,
    }

    impl RawStdio {
        fn enter_if_tty() -> Self {
            use std::os::fd::{AsFd, AsRawFd};
            let stdin = std::io::stdin();
            let fd = stdin.as_fd().as_raw_fd();
            #[allow(unsafe_code)]
            let is_tty = unsafe { libc::isatty(fd) } == 1;
            if !is_tty {
                return Self { armed: false };
            }
            #[allow(unsafe_code)]
            let original = unsafe {
                let mut t: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &raw mut t) != 0 {
                    return Self { armed: false };
                }
                t
            };
            let mut raw = original;
            raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
            #[allow(unsafe_code)]
            unsafe {
                if libc::tcsetattr(fd, libc::TCSANOW, &raw const raw) != 0 {
                    return Self { armed: false };
                }
            }
            if ORIGINAL_TERMIOS.set(original).is_ok() {
                #[allow(unsafe_code)]
                unsafe {
                    libc::atexit(restore_termios_atexit);
                }
            }
            Self { armed: true }
        }
    }

    impl Drop for RawStdio {
        fn drop(&mut self) {
            if self.armed {
                restore_termios();
            }
        }
    }

    fn restore_termios() {
        use std::os::fd::{AsFd, AsRawFd};
        if let Some(orig) = ORIGINAL_TERMIOS.get() {
            let stdin = std::io::stdin();
            let fd = stdin.as_fd().as_raw_fd();
            #[allow(unsafe_code)]
            unsafe {
                let _ = libc::tcsetattr(fd, libc::TCSANOW, orig);
            }
        }
    }

    extern "C" fn restore_termios_atexit() {
        restore_termios();
    }

    fn install_panic_terminal_restore() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_termios();
            prev(info);
        }));
    }

    #[derive(Clone)]
    pub struct Vm {
        inner: crate::hypervisor::Vm,
        mmio_bus: Arc<Mutex<MmioBus>>,
        exit_requester: VcpuExitRequester,
        shared_memory: Vec<Arc<dyn SharedMemory>>,
        mapped_memory: Option<Arc<memory::MappedMemory>>,
        irq_manager: Arc<Mutex<IrqManager>>,
    }

    impl std::fmt::Debug for Vm {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Vm")
                .field("inner", &self.inner)
                .field("mmio_bus", &self.mmio_bus)
                .field("exit_requester", &self.exit_requester)
                .field("shared_memory", &self.shared_memory.len())
                .field("mapped_memory", &self.mapped_memory.is_some())
                .field("irq_manager", &"<backend-owned>")
                .finish()
        }
    }

    impl Host for Vm {
        type RawStdioGuard = RawStdio;

        #[cfg(target_arch = "x86_64")]
        const ARCH: HostArchitecture = HostArchitecture::X86_64;
        #[cfg(target_arch = "aarch64")]
        const ARCH: HostArchitecture = HostArchitecture::Aarch64;

        fn cpu_compatible() -> Option<&'static str> {
            #[cfg(target_arch = "aarch64")]
            {
                host_cpu_compatible()
            }
            #[cfg(target_arch = "x86_64")]
            {
                None
            }
        }

        fn enter_raw_stdio_if_tty() -> Self::RawStdioGuard {
            RawStdio::enter_if_tty()
        }

        fn install_panic_terminal_restore() {
            install_panic_terminal_restore();
        }

        fn install_signal_watchers(supervisor_shutdown: &'static AtomicBool) {
            install_signal_watchers(supervisor_shutdown);
        }
    }

    /// The host CPU's registered `compatible` for authoring cpu instances in
    /// the overlay. KVM passes through the host CPU model, so the host MIDR is
    /// the only source of truth for this guest-visible property.
    #[cfg(target_arch = "aarch64")]
    fn host_cpu_compatible() -> Option<&'static str> {
        let raw =
            std::fs::read_to_string("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1")
                .ok()?;
        let s = raw.trim();
        let s = s.strip_prefix("0x").unwrap_or(s);
        let midr = u64::from_str_radix(s, 16).ok()?;
        midr_to_compatible(midr)
    }

    /// Map an aarch64 `MIDR_EL1` value to its registered devicetree
    /// `compatible`. Implementer is bits `[31:24]`, part number `[15:4]`.
    #[cfg(target_arch = "aarch64")]
    fn midr_to_compatible(midr: u64) -> Option<&'static str> {
        let implementer = (midr >> 24) & 0xff;
        let partnum = (midr >> 4) & 0xfff;
        match (implementer, partnum) {
            (0x41, 0xd03) => Some("arm,cortex-a53"),
            (0x41, 0xd07) => Some("arm,cortex-a57"),
            (0x41, 0xd08) => Some("arm,cortex-a72"),
            (0x41, 0xd0b) => Some("arm,cortex-a76"),
            (0x41, 0xd0c) => Some("arm,neoverse-n1"),
            (0x41, 0xd40) => Some("arm,neoverse-v1"),
            (0x41, 0xd49) => Some("arm,neoverse-n2"),
            (0x41, 0xd4f) => Some("arm,neoverse-v2"),
            _ => None,
        }
    }

    #[cfg(all(test, target_arch = "aarch64"))]
    mod cpu_compatible_tests {
        use super::*;

        fn midr(implementer: u64, part: u64) -> u64 {
            (implementer << 24) | (part << 4)
        }

        #[test]
        fn known_cores_map_to_registered_compatibles() {
            assert_eq!(
                midr_to_compatible(midr(0x41, 0xd0c)),
                Some("arm,neoverse-n1")
            );
            assert_eq!(
                midr_to_compatible(midr(0x41, 0xd4f)),
                Some("arm,neoverse-v2")
            );
            assert_eq!(
                midr_to_compatible(midr(0x41, 0xd08)),
                Some("arm,cortex-a72")
            );
            assert_eq!(
                midr_to_compatible(midr(0x41, 0xd03)),
                Some("arm,cortex-a53")
            );
        }

        #[test]
        fn unknown_core_is_none_no_generic() {
            assert_eq!(midr_to_compatible(midr(0x41, 0xfff)), None);
            assert_eq!(midr_to_compatible(midr(0x61, 0x022)), None);
        }
    }

    impl Vm {
        fn add_memslot(&self, slot: u32, gpa: u64, host_addr: u64, size: u64) -> Result<(), Error> {
            self.inner.add_memslot(slot, gpa, host_addr, size)
        }

        fn attach_mapped_memory(&mut self, mapped: Arc<memory::MappedMemory>) -> Result<(), Error> {
            for (slot_idx, region) in mapped.regions().iter().enumerate() {
                log::info!(
                    "registering KVM memslot {}: [{:#x}..{:#x}) host={:#x}",
                    slot_idx,
                    region.gpa(),
                    region.gpa() + region.size(),
                    region.host_addr()
                );
                self.add_memslot(
                    slot_idx as u32,
                    region.gpa(),
                    region.host_addr(),
                    region.size(),
                )?;
            }
            self.shared_memory = vec![Arc::new(dillo_mmio::MappedSharedMemory::for_guest_memory(
                mapped.guest_memory(),
                dillo_mmio::SharedAccess::ReadWrite,
            ))];
            self.mapped_memory = Some(mapped);
            Ok(())
        }

        fn create_vcpu_inner(&self, idx: u32, cpu_profile: &str) -> Result<Vcpu, Error> {
            Ok(Vcpu {
                inner: self.inner.create_vcpu(idx, cpu_profile)?,
                mmio_bus: Arc::clone(&self.mmio_bus),
                exit_requester: self.exit_requester(),
                registered_thread: AtomicBool::new(false),
            })
        }

        fn exit_requester(&self) -> VcpuExitRequester {
            self.exit_requester.clone()
        }

        fn resolve_interrupts(
            &self,
            requirements: &[MmioInterruptRequirement],
        ) -> Result<Vec<MmioInterrupt>, Error> {
            requirements
                .iter()
                .map(|requirement| match requirement {
                    MmioInterruptRequirement::Line { source } => {
                        let irq = Self::wired_irq_from_cells(&source.cells, source.cell_count)?;
                        self.create_line_interrupt(irq).map(MmioInterrupt::Line)
                    }
                    MmioInterruptRequirement::MessageDomain { vectors, .. } => {
                        Ok(MmioInterrupt::MessageDomain(
                            self.create_message_interrupt_domain(*vectors),
                        ))
                    }
                })
                .collect()
        }

        #[cfg(target_arch = "aarch64")]
        fn wired_irq_from_cells(cells: &[u32; 4], cell_count: u8) -> Result<u32, Error> {
            if cell_count >= 2 {
                Ok(cells[1])
            } else {
                Err(Error::UnhandledExit(
                    "wired interrupt source has too few GIC cells".to_string(),
                ))
            }
        }

        #[cfg(target_arch = "x86_64")]
        fn wired_irq_from_cells(cells: &[u32; 4], cell_count: u8) -> Result<u32, Error> {
            if cell_count >= 1 {
                Ok(cells[0])
            } else {
                Err(Error::UnhandledExit(
                    "wired interrupt source has too few IOAPIC cells".to_string(),
                ))
            }
        }

        fn create_line_interrupt(&self, source: u32) -> Result<dillo_mmio::Interrupt, Error> {
            // Both arches deliver via irqfd + an EventFdInterruptLine; only the
            // routing differs. x86 binds to a pre-existing IOAPIC GSI; aarch64
            // adds an IRQCHIP route to GIC SPI `source` (no GICv3 defaults).
            let mut mgr = self
                .irq_manager
                .lock()
                .expect("KVM IRQ manager lock poisoned");
            #[cfg(target_arch = "x86_64")]
            let eventfd = mgr
                .register_irqfd_at_gsi(source)
                .map_err(|e| Error::Irq(e.to_string()))?;
            #[cfg(target_arch = "aarch64")]
            let eventfd = mgr
                .register_spi_irqfd(source)
                .map_err(|e| Error::Irq(e.to_string()))?;
            drop(mgr);
            Ok(dillo_mmio::Interrupt::new(Arc::new(
                EventFdInterruptLine::new(eventfd),
            )))
        }

        fn create_message_interrupt_domain(
            &self,
            vectors: u16,
        ) -> Arc<dyn dillo_mmio::MessageInterruptDomain> {
            Arc::new(KvmMessageInterruptDomain::new(
                Arc::clone(&self.irq_manager),
                vectors,
            ))
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Aarch64Substrate {
        pub(crate) dist_base: u64,
        pub(crate) redist_base: u64,
        pub(crate) spi_count: u32,
    }

    #[derive(Debug, Clone)]
    struct Config {
        #[cfg(target_arch = "aarch64")]
        dtb: Vec<u8>,
    }

    impl TryFrom<Config> for Vm {
        type Error = Error;

        fn try_from(config: Config) -> Result<Self, Self::Error> {
            let exit_requester = VcpuExitRequester::new();
            #[cfg(target_arch = "x86_64")]
            let inner = {
                let _ = config;
                crate::hypervisor::Vm::new()?
            };
            #[cfg(target_arch = "aarch64")]
            let inner = {
                let parsed: Tree<'_> = Tree::parse(&config.dtb).map_err(Error::ParseDtb)?;
                let mut tree = OwnedTree::materialize(&parsed);
                let substrate = Aarch64Substrate::from_devtree(&mut tree)?
                    .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;
                crate::hypervisor::Vm::new_with_gic(&substrate)?
            };
            let irq_manager = Arc::new(Mutex::new(
                IrqManager::new(inner.vm_fd_arc()).map_err(|e| Error::Irq(e.to_string()))?,
            ));
            Ok(Self {
                inner,
                mmio_bus: Arc::new(Mutex::new(MmioBus::new())),
                exit_requester,
                shared_memory: Vec::new(),
                mapped_memory: None,
                irq_manager,
            })
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl FromDevTree for Aarch64Substrate {
        type Error = Error;

        fn from_devtree(tree: &mut OwnedTree) -> Result<Option<Self>, Self::Error> {
            let root = tree.root_mut();
            let intc_name = root
                .children()
                .find(|node| {
                    node.name().starts_with("interrupt-controller@")
                        && compatible_contains(*node, "arm,gic-v3")
                })
                .map(|node| node.name().to_string())
                .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;
            let mut intc = root
                .remove_child(&intc_name)
                .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;
            consume_compatible(&mut intc, "/interrupt-controller", "arm,gic-v3")?;
            let reg = intc
                .remove_property("reg")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/interrupt-controller",
                    prop: "reg",
                    reason: "missing",
                })?;
            let (dist_base, _) = reg_pair(&reg, 0).ok_or(Error::BadSubstrateProperty {
                node: "/interrupt-controller",
                prop: "reg",
                reason: "missing GICD pair",
            })?;
            let (redist_base, _) = reg_pair(&reg, 1).ok_or(Error::BadSubstrateProperty {
                node: "/interrupt-controller",
                prop: "reg",
                reason: "missing GICR pair",
            })?;
            let _ = intc.remove_property("#interrupt-cells");
            let _ = intc.remove_property("interrupt-controller");
            let _ = intc.remove_property("phandle");

            let v2m_name = root
                .children()
                .find(|node| {
                    node.name().starts_with("msi-controller@")
                        && compatible_contains(*node, "arm,gic-v2m-frame")
                })
                .map(|node| node.name().to_string())
                .ok_or(Error::MissingSubstrate("/msi-controller@*"))?;
            let mut v2m = root
                .remove_child(&v2m_name)
                .ok_or(Error::MissingSubstrate("/msi-controller@*"))?;
            consume_compatible(&mut v2m, "/msi-controller", "arm,gic-v2m-frame")?;
            let spi_count = v2m
                .remove_property("arm,msi-num-spis")
                .and_then(|prop| prop.as_u32())
                .ok_or(Error::BadSubstrateProperty {
                    node: "/msi-controller",
                    prop: "arm,msi-num-spis",
                    reason: "missing or not a u32",
                })?;
            let _ = v2m.remove_property("reg");
            let _ = v2m.remove_property("arm,msi-base-spi");
            let _ = v2m.remove_property("msi-controller");
            let _ = v2m.remove_property("phandle");

            Ok(Some(Self {
                dist_base,
                redist_base,
                spi_count,
            }))
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn compatible_contains<N: NodeView>(node: N, value: &str) -> bool {
        let Some(prop) = node.property("compatible") else {
            return false;
        };
        stringlist_contains(prop.as_ref(), value)
    }

    #[cfg(target_arch = "aarch64")]
    fn consume_compatible(
        node: &mut dillo_devtree::devtree::OwnedNode,
        node_name: &'static str,
        value: &str,
    ) -> Result<(), Error> {
        let prop = node
            .remove_property("compatible")
            .ok_or(Error::BadSubstrateProperty {
                node: node_name,
                prop: "compatible",
                reason: "missing",
            })?;
        if stringlist_contains(prop.as_ref(), value) {
            Ok(())
        } else {
            Err(Error::BadSubstrateProperty {
                node: node_name,
                prop: "compatible",
                reason: "unsupported compatible",
            })
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn stringlist_contains(bytes: &[u8], value: &str) -> bool {
        bytes
            .split(|byte| *byte == 0)
            .filter(|item| !item.is_empty())
            .any(|item| item == value.as_bytes())
    }

    #[cfg(target_arch = "aarch64")]
    fn reg_pair<P: PropertyView>(prop: P, pair_index: usize) -> Option<(u64, u64)> {
        let cells: Vec<u32> = prop.as_u32s()?.collect();
        let base = cells.get(pair_index * 4..pair_index * 4 + 2)?;
        let size = cells.get(pair_index * 4 + 2..pair_index * 4 + 4)?;
        Some((
            (u64::from(base[0]) << 32) | u64::from(base[1]),
            (u64::from(size[0]) << 32) | u64::from(size[1]),
        ))
    }

    impl dillo_machine::Machine for Vm {
        type Error = Error;
        type Cpu = Cpu;
        type CpuState = CpuState;
        type Memory = Memory;

        fn from_launch_config(config: LaunchConfig) -> Result<Self, Self::Error> {
            #[cfg(target_arch = "x86_64")]
            let _ = config;
            Self::try_from(Config {
                #[cfg(target_arch = "aarch64")]
                dtb: config.dtb,
            })
        }

        fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Self::Error> {
            let memory = self
                .mapped_memory
                .as_ref()
                .ok_or_else(|| Error::UnhandledExit("guest RAM is not attached".to_string()))?;
            memory
                .gpa_map()
                .write(gpa, data)
                .map_err(|e| Error::UnhandledExit(e.to_string()))
        }

        fn prepare_vcpu_run(&mut self) -> Result<(), Self::Error> {
            #[cfg(target_arch = "aarch64")]
            {
                // The vGIC needs vCPUs (created just before this) to initialize;
                // only then can KVM_IRQFD bind the wired SPIs deferred at attach.
                self.inner.init_gic()?;
                self.irq_manager
                    .lock()
                    .expect("KVM IRQ manager lock poisoned")
                    .flush_pending_wired()
                    .map_err(|e| Error::Irq(e.to_string()))?;
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct Memory {
        mapped: Arc<memory::MappedMemory>,
    }

    impl dillo_machine::Memory for Memory {
        type Error = Error;

        fn from_ranges(ranges: &[RamRange]) -> Result<Self, Self::Error> {
            let mapped =
                memory::MappedMemory::new(ranges.iter().map(|range| (range.gpa, range.size)))
                    .map_err(|e| Error::UnhandledExit(e.to_string()))?;
            Ok(Self {
                mapped: Arc::new(mapped),
            })
        }
    }

    impl Attach<Memory> for Vm {
        type Error = Error;
        type Output = ();

        fn attach(&mut self, item: Memory) -> Result<Self::Output, Self::Error> {
            self.attach_mapped_memory(item.mapped)
        }
    }

    #[derive(Debug)]
    pub struct CpuState {
        index: u32,
        cpu_profile: String,
        #[cfg(target_arch = "x86_64")]
        boot_state: Option<pmi::vm::vcpu::x86_64::CpuState>,
        #[cfg(target_arch = "aarch64")]
        boot_state: Option<pmi::vm::vcpu::aarch64::CpuState>,
    }

    impl dillo_machine::CpuState for CpuState {
        type Error = Error;

        fn new(
            index: u32,
            cpu_profile: &str,
            boot_state: Option<&dyn BootVcpuState>,
        ) -> Result<Self, Self::Error> {
            #[cfg(target_arch = "x86_64")]
            let boot_state = (index == 0)
                .then_some(boot_state)
                .flatten()
                .map(|state| {
                    state
                        .x86_64()
                        .cloned()
                        .ok_or_else(|| Error::UnhandledExit("boot vCPU state is not x86_64".into()))
                })
                .transpose()?;
            #[cfg(target_arch = "aarch64")]
            let boot_state = (index == 0)
                .then_some(boot_state)
                .flatten()
                .map(|state| {
                    state.aarch64().cloned().ok_or_else(|| {
                        Error::UnhandledExit("boot vCPU state is not aarch64".into())
                    })
                })
                .transpose()?;
            Ok(Self {
                index,
                cpu_profile: cpu_profile.into(),
                boot_state,
            })
        }
    }

    impl Attach<CpuState> for Vm {
        type Error = Error;
        type Output = Arc<Cpu>;

        fn attach(&mut self, item: CpuState) -> Result<Self::Output, Self::Error> {
            let mut vcpu = self.create_vcpu_inner(item.index, &item.cpu_profile)?;
            #[cfg(target_arch = "x86_64")]
            if let Some(state) = &item.boot_state {
                vcpu.set_x86_64_state(state)?;
            }
            #[cfg(target_arch = "aarch64")]
            if let Some(state) = &item.boot_state {
                vcpu.set_aarch64_state(state)?;
            }
            let exit_requester = vcpu.exit_requester.clone();
            Ok(Arc::new(Cpu {
                vcpu: Mutex::new(vcpu),
                exit_requester,
            }))
        }
    }

    pub struct Cpu {
        vcpu: Mutex<Vcpu>,
        exit_requester: VcpuExitRequester,
    }

    impl std::fmt::Debug for Cpu {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Cpu").finish_non_exhaustive()
        }
    }

    impl dillo_machine::Cpu for Cpu {
        type Error = Error;

        fn run(&self) -> Result<VcpuStop, Self::Error> {
            self.vcpu
                .lock()
                .expect("KVM vCPU lock poisoned")
                .run_to_stop()
        }

        fn stop(&self) -> Result<(), Self::Error> {
            self.exit_requester.request_exit();
            Ok(())
        }
    }

    // Cross-arch irqfd-backed line: writing the eventfd makes KVM inject the
    // interrupt in-kernel per the GSI's routing entry (IOAPIC pin on x86, GIC
    // SPI on aarch64). Same delivery on both arches.
    #[derive(Debug)]
    struct EventFdInterruptLine {
        eventfd: EventFd,
    }

    impl EventFdInterruptLine {
        fn new(eventfd: EventFd) -> Self {
            Self { eventfd }
        }
    }

    impl InterruptLine for EventFdInterruptLine {
        fn signal(&self) {
            if let Err(e) = self.eventfd.write(1) {
                log::warn!("KVM irqfd interrupt signal failed: {e}");
            }
        }

        fn set_level(&self, level: bool) -> Result<(), InterruptError> {
            if level {
                self.eventfd
                    .write(1)
                    .map_err(|e| InterruptError::Delivery(e.to_string()))?;
            }
            Ok(())
        }
    }

    impl<D> Attach<Arc<D>> for Vm
    where
        D: MmioDevice + 'static,
    {
        type Error = Error;
        type Output = Arc<dyn MmioAttachment>;

        fn attach(&mut self, item: Arc<D>) -> Result<Self::Output, Self::Error> {
            if !item.shared_memory().is_empty() {
                return Err(Error::UnhandledExit(format!(
                    "MMIO device requested {} fixed shared-memory requirement(s), but KVM attachment does not realize machine-mediated shared-memory capabilities yet",
                    item.shared_memory().len()
                )));
            }
            let interrupts = self.resolve_interrupts(item.interrupts())?;
            self.mmio_bus
                .lock()
                .expect("MMIO bus lock poisoned")
                .register_device(item);
            Ok(Arc::new(MachineMmioAttachment {
                interrupts,
                shared_memory: self.shared_memory.clone(),
            }))
        }
    }

    struct MachineMmioAttachment {
        interrupts: Vec<MmioInterrupt>,
        shared_memory: Vec<Arc<dyn SharedMemory>>,
    }

    impl std::fmt::Debug for MachineMmioAttachment {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MachineMmioAttachment")
                .field("interrupts", &self.interrupts.len())
                .field("shared_memory", &self.shared_memory.len())
                .finish()
        }
    }

    impl MmioAttachment for MachineMmioAttachment {
        fn interrupts(&self) -> &[MmioInterrupt] {
            &self.interrupts
        }

        fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
            &self.shared_memory
        }

        fn spawn(
            self: Arc<Self>,
            run: dillo_mmio::MmioDeviceRun,
        ) -> Result<MmioDeviceHandle, MmioSpawnError> {
            let shutdown = Arc::new(AtomicBool::new(false));
            let token_shutdown = Arc::clone(&shutdown);
            let token = MmioRunToken::from_fn(move || token_shutdown.load(Ordering::Acquire));
            let join = thread::spawn(move || run(token));
            Ok(MmioDeviceHandle::new(
                move || {
                    shutdown.store(true, Ordering::Release);
                    Ok(())
                },
                move || match join.join() {
                    Ok(result) => result,
                    Err(_) => Err(dillo_mmio::MmioJoinError::Panicked),
                },
            ))
        }
    }

    struct Vcpu {
        inner: crate::hypervisor::Vcpu,
        mmio_bus: Arc<Mutex<MmioBus>>,
        exit_requester: VcpuExitRequester,
        registered_thread: AtomicBool,
    }

    #[derive(Clone, Debug)]
    struct VcpuExitRequester {
        threads: Arc<Mutex<Vec<libc::pthread_t>>>,
        requested: Arc<AtomicBool>,
    }

    impl VcpuExitRequester {
        fn new() -> Self {
            Self::install_kick_handler();
            Self {
                threads: Arc::new(Mutex::new(Vec::new())),
                requested: Arc::new(AtomicBool::new(false)),
            }
        }

        fn install_kick_handler() {
            static INSTALLED: OnceLock<()> = OnceLock::new();
            INSTALLED.get_or_init(|| {
                let action = nix::sys::signal::SigAction::new(
                    nix::sys::signal::SigHandler::Handler(vcpu_kick_signal_handler),
                    nix::sys::signal::SaFlags::empty(),
                    nix::sys::signal::SigSet::empty(),
                );
                // SAFETY: installs a trivial async-signal-safe handler for a
                // process-local wake signal used only to interrupt KVM_RUN.
                #[allow(unsafe_code)]
                unsafe {
                    nix::sys::signal::sigaction(VCPU_KICK_SIGNAL, &action)
                        .expect("install vCPU kick signal handler");
                }
            });
        }

        fn register_current_thread(&self) {
            // SAFETY: pthread_self returns the current thread identifier. It is
            // stored only so request_exit can send the wake signal while
            // the vCPU worker thread may be blocked in KVM_RUN.
            #[allow(unsafe_code)]
            let thread = unsafe { libc::pthread_self() };
            let mut threads = self.threads.lock().expect("vCPU thread list poisoned");
            if !threads.contains(&thread) {
                threads.push(thread);
            }
            drop(threads);
            if self.requested.load(Ordering::Acquire) {
                Self::kick_thread(thread);
            }
        }

        fn request_exit(&self) {
            self.requested.store(true, Ordering::Release);
            for thread in self
                .threads
                .lock()
                .expect("vCPU thread list poisoned")
                .iter()
            {
                Self::kick_thread(*thread);
            }
        }

        fn requested(&self) -> bool {
            self.requested.load(Ordering::Acquire)
        }

        fn kick_thread(thread: libc::pthread_t) {
            // SAFETY: pthread_t values come from vCPU worker threads that
            // registered themselves before entering KVM_RUN. If a thread
            // has already exited, pthread_kill returns ESRCH and there is
            // nothing left to wake.
            #[allow(unsafe_code)]
            let rc = unsafe { libc::pthread_kill(thread, VCPU_KICK_SIGNAL as libc::c_int) };
            if rc != 0 && rc != libc::ESRCH {
                log::warn!("failed to kick vCPU thread with signal: errno {rc}");
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum VcpuExit {
        MmioWrite { addr: u64, data: [u8; 8], size: u8 },

        Interrupted,

        Shutdown,

        GuestPoweroff,

        GuestReset,
    }

    impl std::fmt::Debug for Vcpu {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Vcpu")
                .field("inner", &self.inner)
                .field("mmio_bus", &self.mmio_bus)
                .finish_non_exhaustive()
        }
    }

    impl Vcpu {
        #[cfg(target_arch = "x86_64")]
        fn set_x86_64_state(
            &mut self,
            state: &pmi::vm::vcpu::x86_64::CpuState,
        ) -> Result<(), Error> {
            self.inner.set_x86_64_state(state)
        }

        #[cfg(target_arch = "aarch64")]
        fn set_aarch64_state(
            &mut self,
            state: &pmi::vm::vcpu::aarch64::CpuState,
        ) -> Result<(), Error> {
            self.inner.set_aarch64_state(state)
        }

        fn run(&mut self) -> Result<VcpuExit, Error> {
            loop {
                let bus = Arc::clone(&self.mmio_bus);
                let exit = self.inner.run(
                    |_port, _size| u32::MAX,
                    move |addr, data| {
                        let handled = bus.lock().expect("MMIO bus lock poisoned").read(addr, data);
                        if !handled {
                            log::debug!(
                                "MMIO read from unmapped {:#x} (size {}); returning zeros",
                                addr,
                                data.len(),
                            );
                        }
                        handled
                    },
                )?;
                match exit {
                    VmExit::MmioRead { addr, size } => {
                        let _ = (addr, size);
                        continue;
                    }
                    VmExit::PioRead { port, size } => {
                        let _ = (port, size);
                        continue;
                    }
                    VmExit::PioWrite { port, data, size } => {
                        let _ = (port, data, size);
                    }
                    VmExit::MmioWrite { addr, data, size } => {
                        let outcome = self
                            .mmio_bus
                            .lock()
                            .expect("MMIO bus lock poisoned")
                            .write(addr, &data[..size as usize]);
                        let Some(outcome) = outcome else {
                            log::warn!(
                                "MMIO write to unmapped {:#x} (size {}, data {:02x?})",
                                addr,
                                size,
                                &data[..size as usize],
                            );
                            return Ok(VcpuExit::MmioWrite { addr, data, size });
                        };
                        match outcome {
                            MmioWriteOutcome::Continue => {}
                            MmioWriteOutcome::GuestPoweroff => return Ok(VcpuExit::GuestPoweroff),
                            MmioWriteOutcome::GuestReset => return Ok(VcpuExit::GuestReset),
                        }
                        return Ok(VcpuExit::MmioWrite { addr, data, size });
                    }
                    VmExit::Interrupted => return Ok(VcpuExit::Interrupted),
                    VmExit::Halted => continue,
                    VmExit::Shutdown => return Ok(VcpuExit::Shutdown),
                    VmExit::Unknown(reason) => return Err(Error::UnhandledExit(reason)),
                }
            }
        }

        fn run_to_stop(&mut self) -> Result<VcpuStop, Error> {
            if !self.registered_thread.swap(true, Ordering::AcqRel) {
                self.exit_requester.register_current_thread();
            }
            loop {
                if self.exit_requester.requested() {
                    return Ok(VcpuStop::Stopped);
                }
                match self.run()? {
                    VcpuExit::MmioWrite { .. } => {}
                    VcpuExit::Interrupted => return Ok(VcpuStop::Stopped),
                    VcpuExit::GuestPoweroff => return Ok(VcpuStop::GuestPoweroff),
                    VcpuExit::GuestReset => return Ok(VcpuStop::GuestReset),
                    VcpuExit::Shutdown => {
                        log::warn!(
                            "guest shutdown via KVM_EXIT_SHUTDOWN; treating as guest poweroff"
                        );
                        return Ok(VcpuStop::GuestPoweroff);
                    }
                }
            }
        }
    }

    impl AsRawFd for Vcpu {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }
}

pub use imp::*;
