// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

#[cfg(target_arch = "x86_64")]
mod amd_tsc;
#[cfg(target_arch = "x86_64")]
mod cpuid_x86;
mod hypervisor;
mod launch_input;

pub use launch_input::CapturedLaunchInput;
#[cfg(target_arch = "x86_64")]
mod intc_x86;
mod irq;
mod memory;
mod msi;
mod notification;

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

    use dillo_devtree::devtree::{OwnedTree, Tree};
    #[cfg(target_arch = "aarch64")]
    use dillo_devtree::{CompatMismatch, FromDevTree, NodeExt, OwnedNodeExt, PropExt};
    use dillo_machine::attachment::{Attach, DeviceAttachment};
    use dillo_machine::execution::{DeviceHandle, RunToken, SpawnError};
    use dillo_machine::interrupt::{
        InterruptError, InterruptLine, InterruptRequirement, InterruptResource,
    };
    use dillo_machine::memory::SharedMemory;
    use dillo_machine::{Host, HostArchitecture, LaunchConfig, RamRange, VcpuStop};
    use dillo_mmio::{MmioBus, MmioDevice, MmioWriteOutcome};
    use vmm_sys_util::eventfd::EventFd;

    pub use crate::hypervisor::Error;
    use crate::irq::IrqManager;
    use crate::memory;
    pub use crate::memory::set_preallocate;
    use crate::msi::KvmMessageInterruptDomain;
    use crate::{CapturedLaunchInput, VmExit};

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
        shared_memory: Vec<Arc<dyn SharedMemory>>,
        irq_manager: Arc<Mutex<IrqManager>>,
    }

    impl std::fmt::Debug for Vm {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Vm")
                .field("inner", &self.inner)
                .field("mmio_bus", &self.mmio_bus)
                .field("shared_memory", &self.shared_memory.len())
                .field("irq_manager", &"<backend-owned>")
                .finish()
        }
    }

    impl Host for Vm {
        type RawStdioGuard = RawStdio;
        type LaunchInput = CapturedLaunchInput;

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
        fn attach_mapped_memory(&mut self, mapped: Arc<memory::MappedMemory>) -> Result<(), Error> {
            self.inner.attach_memory(mapped)?;
            self.shared_memory = vec![Arc::new(
                dillo_machine::memory::MappedSharedMemory::for_guest_memory(
                    self.inner.guest_memory()?,
                    dillo_machine::memory::SharedAccess::ReadWrite,
                ),
            )];
            Ok(())
        }

        #[cfg(all(test, target_arch = "x86_64"))]
        fn create_vcpu_inner(&self, idx: u32, cpu_profile: &str) -> Result<Vcpu, Error> {
            if self.inner.guest_memory().is_err() {
                self.inner.attach_memory(Arc::new(
                    memory::MappedMemory::test_backing(&[(0, 0x1000)])
                        .map_err(Error::AllocateMemory)?,
                ))?;
            }
            Ok(Vcpu {
                inner: self.inner.create_vcpu(idx, cpu_profile)?,
                mmio_bus: Arc::clone(&self.mmio_bus),
                exit_requester: CpuInterrupt::new(),
            })
        }

        fn resolve_interrupts(
            &self,
            requirements: &[InterruptRequirement],
        ) -> Result<Vec<InterruptResource>, Error> {
            requirements
                .iter()
                .map(|requirement| match requirement {
                    InterruptRequirement::Line { source } => {
                        let irq = Self::wired_irq_from_cells(&source.cells, source.cell_count)?;
                        self.create_line_interrupt(irq).map(InterruptResource::Line)
                    }
                    InterruptRequirement::MessageDomain { vectors, .. } => {
                        Ok(InterruptResource::MessageDomain(
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

        fn create_line_interrupt(
            &self,
            source: u32,
        ) -> Result<dillo_machine::interrupt::Interrupt, Error> {
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
            Ok(dillo_machine::interrupt::Interrupt::new(Arc::new(
                EventFdInterruptLine::new(eventfd),
            )))
        }

        fn create_message_interrupt_domain(
            &self,
            vectors: u16,
        ) -> Arc<dyn dillo_machine::interrupt::MessageInterruptDomain> {
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
        dtb: Vec<u8>,
    }

    impl TryFrom<Config> for Vm {
        type Error = Error;

        fn try_from(config: Config) -> Result<Self, Self::Error> {
            // The devicetree is the machine contract: the interrupt-controller
            // substrate is constructed from what it declares, on both arches.
            let parsed: Tree<'_> = Tree::parse(&config.dtb).map_err(Error::ParseDtb)?;
            let mut tree = OwnedTree::materialize(&parsed);
            #[cfg(target_arch = "x86_64")]
            let inner = {
                let intc = crate::intc_x86::X86Intc::from_tree(&mut tree)?;
                crate::hypervisor::Vm::new_with_intc(intc)?
            };
            #[cfg(target_arch = "aarch64")]
            let inner = {
                let substrate = Aarch64Substrate::from_devtree(&mut tree)?
                    .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;
                crate::hypervisor::Vm::new_with_gic(&substrate)?
            };
            let irq_manager = Arc::new(Mutex::new(
                IrqManager::new(inner.clone()).map_err(|e| Error::Irq(e.to_string()))?,
            ));
            Ok(Self {
                inner,
                mmio_bus: Arc::new(Mutex::new(MmioBus::new())),
                shared_memory: Vec::new(),
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
                        && node.compatible_contains("arm,gic-v3")
                })
                .map(|node| node.name().to_string())
                .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;
            let mut intc = root
                .remove_child(&intc_name)
                .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;
            intc.take_compatible("arm,gic-v3").map_err(|e| match e {
                CompatMismatch::Missing => Error::BadSubstrateProperty {
                    node: "/interrupt-controller",
                    prop: "compatible",
                    reason: "missing",
                },
                CompatMismatch::Unsupported => Error::BadSubstrateProperty {
                    node: "/interrupt-controller",
                    prop: "compatible",
                    reason: "unsupported compatible",
                },
            })?;
            let reg = intc
                .remove_property("reg")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/interrupt-controller",
                    prop: "reg",
                    reason: "missing",
                })?;
            let (dist_base, _) = (&reg).reg_pair(0).ok_or(Error::BadSubstrateProperty {
                node: "/interrupt-controller",
                prop: "reg",
                reason: "missing GICD pair",
            })?;
            let (redist_base, _) = (&reg).reg_pair(1).ok_or(Error::BadSubstrateProperty {
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
                        && node.compatible_contains("arm,gic-v2m-frame")
                })
                .map(|node| node.name().to_string())
                .ok_or(Error::MissingSubstrate("/msi-controller@*"))?;
            let mut v2m = root
                .remove_child(&v2m_name)
                .ok_or(Error::MissingSubstrate("/msi-controller@*"))?;
            v2m.take_compatible("arm,gic-v2m-frame")
                .map_err(|e| match e {
                    CompatMismatch::Missing => Error::BadSubstrateProperty {
                        node: "/msi-controller",
                        prop: "compatible",
                        reason: "missing",
                    },
                    CompatMismatch::Unsupported => Error::BadSubstrateProperty {
                        node: "/msi-controller",
                        prop: "compatible",
                        reason: "unsupported compatible",
                    },
                })?;
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

    impl dillo_machine::Machine for Vm {
        type Error = Error;
        type CpuPreparation = CpuPreparation;
        type Memory = Memory;

        fn cpu_preparation(
            &mut self,
            index: u32,
            cpu_profile: dillo_machine::CpuProfile,
        ) -> Result<CpuPreparation, Error> {
            #[cfg(target_arch = "x86_64")]
            let matches = matches!(cpu_profile, dillo_machine::CpuProfile::X86_64(_));
            #[cfg(target_arch = "aarch64")]
            let matches = matches!(cpu_profile, dillo_machine::CpuProfile::Aarch64(_));
            if !matches {
                return Err(Error::UnhandledExit(
                    "CPU profile architecture mismatch".into(),
                ));
            }
            self.inner.guest_memory()?;
            Ok(CpuPreparation {
                index,
                cpu_profile,
                vm: self.inner.clone(),
                mmio_bus: Arc::clone(&self.mmio_bus),
                interrupt: CpuInterrupt::new(),
            })
        }

        fn guest_address_bits() -> Result<u32, Self::Error> {
            crate::hypervisor::guest_address_bits()
        }

        fn from_launch_config(config: LaunchConfig) -> Result<Self, Self::Error> {
            let vm = Self::try_from(Config { dtb: config.dtb })?;
            let available = Self::guest_address_bits()?;
            if config.min_addr_space_bits > available {
                return Err(Error::AddressSpace(format!(
                    "launch requires {} bits; backend provides {available}",
                    config.min_addr_space_bits
                )));
            }
            Ok(vm)
        }

        fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.inner.write_guest(gpa, data)
        }

        fn zero_guest(&mut self, mut gpa: u64, mut len: u64) -> Result<(), Self::Error> {
            gpa.checked_add(len)
                .ok_or_else(|| Error::AddressSpace("guest zero range overflows".into()))?;
            let zeros = [0u8; 4096];
            while len > 0 {
                let count = len.min(zeros.len() as u64) as usize;
                <Self as dillo_machine::Machine>::write_guest(self, gpa, &zeros[..count])?;
                gpa += count as u64;
                len -= count as u64;
            }
            Ok(())
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
                    .map_err(Error::AllocateMemory)?;
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
    pub struct CpuPreparation {
        index: u32,
        cpu_profile: dillo_machine::CpuProfile,
        vm: crate::hypervisor::Vm,
        mmio_bus: Arc<Mutex<MmioBus>>,
        interrupt: CpuInterrupt,
    }
    impl dillo_machine::CpuPreparation for CpuPreparation {
        type Error = Error;
        type Interrupt = CpuInterrupt;
        type Runner = CpuRunner;
        fn interrupt(&self) -> CpuInterrupt {
            self.interrupt.clone()
        }
        fn prepare(self) -> Result<CpuRunner, Error> {
            let mut vcpu = Vcpu {
                inner: self.vm.create_vcpu(self.index, self.cpu_profile.as_str())?,
                mmio_bus: self.mmio_bus,
                exit_requester: self.interrupt,
            };
            if self.index == 0 {
                vcpu.initialize_bsp()?;
            }
            #[cfg(target_arch = "aarch64")]
            let admitted = {
                let dillo_machine::CpuProfile::Aarch64(profile) = self.cpu_profile else {
                    return Err(Error::UnhandledExit(
                        "CPU profile architecture mismatch".into(),
                    ));
                };
                vcpu.inner.admit_arm_profile(profile)?
            };
            Ok(CpuRunner {
                vcpu,
                #[cfg(target_arch = "aarch64")]
                _admitted: admitted,
                _owner: std::marker::PhantomData,
            })
        }
    }

    /// Native execution and destruction remain on the preparing thread.
    ///
    /// ```compile_fail
    /// fn move_owner(runner: dillo_machine_kvm::CpuRunner) {
    ///     std::thread::spawn(move || drop(runner));
    /// }
    /// ```
    #[derive(Debug)]
    pub struct CpuRunner {
        vcpu: Vcpu,
        #[cfg(target_arch = "aarch64")]
        _admitted: dillo_machine::aarch64::AdmittedCpu,
        _owner: std::marker::PhantomData<std::rc::Rc<()>>,
    }
    impl dillo_machine::CpuRunner for CpuRunner {
        type Error = Error;
        fn run(
            &mut self,
            termination: &dyn dillo_machine::CpuTermination,
        ) -> Result<VcpuStop, Error> {
            self.vcpu.run_to_stop(termination)
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
        type Output = Arc<dyn DeviceAttachment>;

        fn attach(&mut self, item: Arc<D>) -> Result<Self::Output, Self::Error> {
            if !item.shared_memory().is_empty() {
                return Err(Error::UnhandledExit(format!(
                    "MMIO device requested {} fixed shared-memory requirement(s), but KVM attachment does not realize machine-mediated shared-memory capabilities yet",
                    item.shared_memory().len()
                )));
            }
            let interrupts = self.resolve_interrupts(item.interrupts())?;
            let notifications = crate::notification::Notifications::new(
                self.inner.clone(),
                item.windows().to_vec(),
            );
            self.mmio_bus
                .lock()
                .expect("MMIO bus lock poisoned")
                .register_device(item);
            Ok(Arc::new(MachineMmioAttachment {
                notifications,
                interrupts,
                shared_memory: self.shared_memory.clone(),
            }))
        }
    }

    struct MachineMmioAttachment {
        notifications: crate::notification::Notifications,
        interrupts: Vec<InterruptResource>,
        shared_memory: Vec<Arc<dyn SharedMemory>>,
    }

    impl std::fmt::Debug for MachineMmioAttachment {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MachineMmioAttachment")
                .field("interrupts", &self.interrupts.len())
                .field("shared_memory", &self.shared_memory.len())
                .finish_non_exhaustive()
        }
    }

    impl DeviceAttachment for MachineMmioAttachment {
        fn write_notification(
            &self,
            window: dillo_machine::memory::AddressRange,
            offset: u64,
            value: u32,
        ) -> std::io::Result<Option<Arc<dyn dillo_machine::notification::WriteNotification>>>
        {
            self.notifications.register(window, offset, value)
        }

        fn interrupts(&self) -> &[InterruptResource] {
            &self.interrupts
        }

        fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
            &self.shared_memory
        }

        fn spawn(
            self: Arc<Self>,
            run: dillo_machine::execution::DeviceRun,
        ) -> Result<DeviceHandle, SpawnError> {
            let shutdown = Arc::new(AtomicBool::new(false));
            let token_shutdown = Arc::clone(&shutdown);
            let token = RunToken::from_fn(move || token_shutdown.load(Ordering::Acquire));
            let join = thread::spawn(move || run(token));
            Ok(DeviceHandle::new(
                move || {
                    shutdown.store(true, Ordering::Release);
                    Ok(())
                },
                move || match join.join() {
                    Ok(result) => result,
                    Err(_) => Err(dillo_machine::execution::JoinError::Panicked),
                },
            ))
        }
    }

    struct Vcpu {
        inner: crate::hypervisor::Vcpu,
        mmio_bus: Arc<Mutex<MmioBus>>,
        exit_requester: CpuInterrupt,
    }

    #[derive(Clone, Debug)]
    pub struct CpuInterrupt {
        threads: Arc<Mutex<Vec<libc::pthread_t>>>,
    }

    impl CpuInterrupt {
        fn new() -> Self {
            Self::install_kick_handler();
            Self {
                threads: Arc::new(Mutex::new(Vec::new())),
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

        fn register_current_thread(&self) -> VcpuRegistration {
            // SAFETY: pthread_self returns the current thread identifier. It is
            // stored only so request_exit can send the wake signal while
            // the vCPU worker thread may be blocked in KVM_RUN.
            #[allow(unsafe_code)]
            let thread = unsafe { libc::pthread_self() };
            let mut threads = self
                .threads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            threads.push(thread);
            drop(threads);
            VcpuRegistration {
                requester: self.clone(),
                thread,
                _thread_bound: std::marker::PhantomData,
            }
        }

        fn request_exit(&self) -> Result<(), Error> {
            for thread in self
                .threads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
            {
                Self::kick_thread(*thread)?;
            }
            Ok(())
        }

        fn kick_thread(thread: libc::pthread_t) -> Result<(), Error> {
            // SAFETY: pthread_t values come from vCPU worker threads that
            // registered themselves before entering KVM_RUN. Remote kicks
            // hold the list lock to prevent retirement; registration can also
            // kick its own still-running thread after releasing that lock.
            #[allow(unsafe_code)]
            let rc = unsafe { libc::pthread_kill(thread, VCPU_KICK_SIGNAL as libc::c_int) };
            if rc == 0 {
                Ok(())
            } else {
                Err(Error::CpuInterrupt(std::io::Error::from_raw_os_error(rc)))
            }
        }
    }

    impl dillo_machine::CpuInterrupt for CpuInterrupt {
        type Error = Error;
        fn interrupt(&self) -> Result<(), Error> {
            self.request_exit()
        }
    }

    struct VcpuRegistration {
        requester: CpuInterrupt,
        thread: libc::pthread_t,
        _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    impl Drop for VcpuRegistration {
        fn drop(&mut self) {
            self.requester
                .threads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|thread| *thread != self.thread);
        }
    }

    #[cfg(test)]
    mod registration_tests {
        use super::*;

        #[test]
        fn finished_workers_are_not_signalled() {
            let requester = CpuInterrupt::new();
            let worker_requester = requester.clone();
            std::thread::spawn(move || {
                let _registration = worker_requester.register_current_thread();
                assert_eq!(worker_requester.threads.lock().unwrap().len(), 1);
            })
            .join()
            .unwrap();
            assert!(requester.threads.lock().unwrap().is_empty());
            requester.request_exit().unwrap();
        }

        #[test]
        fn unwinding_retires_registration() {
            let requester = CpuInterrupt::new();
            let _ = std::panic::catch_unwind(|| {
                let _registration = requester.register_current_thread();
                panic!("worker failure");
            });
            assert!(requester.threads.lock().unwrap().is_empty());
            requester.request_exit().unwrap();
        }
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    mod stop_signal_tests {
        use super::*;
        use nix::sys::signal::{SigSet, SigmaskHow};

        struct RestoreMask(SigSet);

        impl Drop for RestoreMask {
            fn drop(&mut self) {
                self.0.thread_set_mask().unwrap();
            }
        }

        fn assert_current_mask(expected: SigSet) {
            let actual = SigSet::thread_get_mask().unwrap();
            // SigSet equality omits realtime signals. Compare membership in
            // every Linux signal instead of comparing libc's unused padding.
            for signal in 1..=libc::SIGRTMAX() {
                // SAFETY: both signal sets are initialized and signal is in
                // the supported Linux range.
                #[allow(unsafe_code)]
                unsafe {
                    assert_eq!(
                        libc::sigismember(actual.as_ref(), signal),
                        libc::sigismember(expected.as_ref(), signal),
                        "signal {signal}",
                    );
                }
            }
        }

        #[test]
        fn stop_before_guest_entry_interrupts_kvm_run() {
            let kvm = kvm_ioctls::Kvm::new().unwrap();
            let vm = kvm.create_vm().unwrap();
            let mut cpu = vm.create_vcpu(0).unwrap();
            let requester = CpuInterrupt::new();
            let _restore = RestoreMask(
                SigSet::all()
                    .thread_swap_mask(SigmaskHow::SIG_SETMASK)
                    .unwrap(),
            );
            let previous = SigSet::thread_get_mask().unwrap();
            let mask = crate::hypervisor::block_kick_signal(&cpu, VCPU_KICK_SIGNAL).unwrap();
            let registration = requester.register_current_thread();
            requester.request_exit().unwrap();
            assert_eq!(cpu.run().unwrap_err().errno(), libc::EINTR);
            drop(registration);
            drop(mask);
            assert_current_mask(previous);
        }

        #[test]
        fn signal_mask_is_restored_on_failure_and_unwind() {
            let mut populated = SigSet::all();
            populated.remove(VCPU_KICK_SIGNAL);
            let _restore =
                RestoreMask(populated.thread_swap_mask(SigmaskHow::SIG_SETMASK).unwrap());
            let previous = SigSet::thread_get_mask().unwrap();
            let file = std::fs::File::open("/dev/null").unwrap();
            assert!(crate::hypervisor::block_kick_signal(&file, VCPU_KICK_SIGNAL).is_err());
            assert_current_mask(previous);
            let kvm = kvm_ioctls::Kvm::new().unwrap();
            let vm = kvm.create_vm().unwrap();
            let cpu = vm.create_vcpu(0).unwrap();
            let result = std::panic::catch_unwind(|| {
                let _mask = crate::hypervisor::block_kick_signal(&cpu, VCPU_KICK_SIGNAL).unwrap();
                let mut blocked = previous;
                blocked.add(VCPU_KICK_SIGNAL);
                assert_current_mask(blocked);
                panic!("worker failure");
            });
            assert!(result.is_err());
            assert_current_mask(previous);
        }
    }

    #[cfg(test)]
    mod owner_tests {
        use super::*;
        use dillo_machine::{CpuInterrupt as _, CpuPreparation as _, CpuRunner as _, Machine as _};

        #[test]
        fn exported_region_outlives_machine_and_then_reclaims_mapping() {
            let (vm, _, base) = machine_fixture();
            let probe = memory::MappingProbe::from_view(&vm.inner.guest_memory().unwrap());
            let region = vm.shared_memory[0]
                .region(dillo_machine::memory::SharedRange {
                    gpa: base,
                    size: 0x1000,
                    access: dillo_machine::memory::SharedAccess::ReadWrite,
                })
                .unwrap();
            drop(vm);
            assert!(probe.mappings() > 0);
            region.write(0x80, b"retained export").unwrap();
            let mut data = [0; 15];
            region.read(0x80, &mut data).unwrap();
            assert_eq!(&data, b"retained export");
            drop(region);
            assert_eq!(probe.mappings(), 0);
        }

        #[test]
        fn standalone_preparation_and_native_runner_retain_machine_ram() {
            let (mut vm, profile, _) = machine_fixture();
            let probe = memory::MappingProbe::from_view(&vm.inner.guest_memory().unwrap());
            let input = vm.cpu_preparation(0, profile).unwrap();
            drop(vm);
            assert!(
                probe.mappings() > 0,
                "unconsumed preparation retains the native context"
            );
            let (ready, prepared) = std::sync::mpsc::channel();
            let (release, wait) = std::sync::mpsc::channel();
            let owner = thread::spawn(move || {
                let mut runner = input.prepare()?;
                let _ = ready.send(());
                let _ = wait.recv();
                runner.run(&AtomicBool::new(true))
            });
            let prepared = prepared.recv_timeout(Duration::from_secs(2));
            let retained = probe.mappings() > 0;
            let _ = release.send(());
            let result = owner.join();
            assert!(prepared.is_ok(), "standalone native owner must prepare");
            assert!(retained, "native runner retains real RAM mappings");
            assert_eq!(result.unwrap().unwrap(), VcpuStop::Stopped);
            assert_eq!(probe.mappings(), 0);
        }

        #[test]
        fn irq_and_notification_services_each_retain_registered_ram() {
            for notification_last in [true, false] {
                let (vm, _, _) = machine_fixture();
                let probe = memory::MappingProbe::from_view(&vm.inner.guest_memory().unwrap());
                let irq = Arc::clone(&vm.irq_manager);
                let window = dillo_machine::memory::AddressRange {
                    base: 0x0b00_0000,
                    size: 0x1000,
                };
                let registrar =
                    crate::notification::Notifications::new(vm.inner.clone(), vec![window]);
                let notification = registrar
                    .register(window, 0x50, 0)
                    .unwrap()
                    .expect("native ioeventfd is required");
                drop(registrar);
                drop(vm);
                if notification_last {
                    drop(irq);
                    notification.write(5).unwrap();
                    assert_eq!(notification.read().unwrap(), 5);
                    assert!(probe.mappings() > 0);
                    drop(notification);
                } else {
                    drop(notification);
                    assert!(probe.mappings() > 0);
                    drop(irq);
                }
                assert_eq!(probe.mappings(), 0);
            }
        }

        fn machine_fixture() -> (Vm, dillo_machine::CpuProfile, u64) {
            #[cfg(target_arch = "x86_64")]
            let (tree, profile, base, entry, code) = (
                crate::intc_x86::tests::tree(0xfee0_0000, 0x1000, 0xfec0_0000, 0x1000),
                dillo_machine::CpuProfile::X86_64(pmi::x86_64::Profile::V1),
                0xffff_f000,
                0xffff_fff0,
                vec![0xeb, 0xfe],
            );
            #[cfg(target_arch = "aarch64")]
            let (tree, profile, base, entry, code) = {
                use dillo_devtree::devtree::{OwnedNode, OwnedProperty};
                let root = OwnedNode::new("")
                    .with_property(OwnedProperty::new("#address-cells").with_u32(2))
                    .with_property(OwnedProperty::new("#size-cells").with_u32(2))
                    .with_child(
                        OwnedNode::new("interrupt-controller@8000000")
                            .with_property(OwnedProperty::new("compatible").with_str("arm,gic-v3"))
                            .with_property(OwnedProperty::new("reg").with_u32s(&[
                                0,
                                0x0800_0000,
                                0,
                                0x1_0000,
                                0,
                                0x080a_0000,
                                0,
                                0x4_0000,
                            ])),
                    )
                    .with_child(
                        OwnedNode::new("msi-controller@8020000")
                            .with_property(
                                OwnedProperty::new("compatible").with_str("arm,gic-v2m-frame"),
                            )
                            .with_property(OwnedProperty::new("arm,msi-num-spis").with_u32(64)),
                    );
                (
                    OwnedTree::new(root),
                    dillo_machine::CpuProfile::Aarch64(pmi::aarch64::Profile::V8_0),
                    0,
                    0,
                    0x1400_0000u32.to_le_bytes().to_vec(),
                )
            };
            let mut vm = Vm::from_launch_config(LaunchConfig {
                dtb: tree.encode().unwrap(),
                vcpus: 2,
                min_addr_space_bits: 32,
            })
            .expect("native KVM is required");
            vm.attach_mapped_memory(Arc::new(
                memory::MappedMemory::test_backing(&[(base, 0x1000)]).unwrap(),
            ))
            .unwrap();
            // Spin at PMI's fixed BSP entry; AP gets no guest startup request.
            vm.write_guest(entry, &code).unwrap();
            (vm, profile, base)
        }

        #[test]
        fn native_owners_keep_ap_parked_and_pure_interrupts_do_not_terminate() {
            let (mut vm, profile, _) = machine_fixture();
            let termination = Arc::new(AtomicBool::new(false));
            let mut owners = Vec::new();
            let mut releases = Vec::new();
            let (ready, receiver) = std::sync::mpsc::channel();
            for index in 0..2 {
                let input = vm.cpu_preparation(index, profile).unwrap();
                let interrupt = input.interrupt();
                let token = Arc::clone(&termination);
                let ready = ready.clone();
                let (release, gate) = std::sync::mpsc::channel();
                releases.push(release);
                let join = thread::spawn(move || {
                    let owner = thread::current().id();
                    let mut runner = input.prepare().unwrap();
                    assert_eq!(thread::current().id(), owner);
                    ready.send(()).unwrap();
                    if gate.recv().is_err() {
                        return Ok(VcpuStop::Stopped);
                    }
                    let result = runner.run(token.as_ref());
                    drop(runner);
                    result
                });
                owners.push((interrupt, join));
            }
            drop(ready);
            let ready_count = (0..2)
                .filter(|_| receiver.recv_timeout(Duration::from_secs(2)).is_ok())
                .count();
            let machine_prepared = vm.prepare_vcpu_run();
            for release in releases {
                let _ = release.send(());
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while owners
                .iter()
                .any(|(interrupt, _)| interrupt.threads.lock().unwrap().is_empty())
                && std::time::Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(1));
            }
            let registered = owners
                .iter()
                .all(|(interrupt, _)| !interrupt.threads.lock().unwrap().is_empty());
            for (interrupt, _) in &owners {
                interrupt.interrupt().unwrap();
            }
            thread::sleep(Duration::from_millis(20));
            let pure_wake_preserved_owners = owners.iter().all(|(_, join)| !join.is_finished());
            termination.store(true, Ordering::Release);
            while owners.iter().any(|(_, join)| !join.is_finished()) {
                for (interrupt, _) in &owners {
                    interrupt.interrupt().unwrap();
                }
                thread::sleep(Duration::from_millis(1));
            }
            for (interrupt, join) in owners {
                assert_eq!(join.join().unwrap().unwrap(), VcpuStop::Stopped);
                assert!(interrupt.threads.lock().unwrap().is_empty());
                interrupt.interrupt().unwrap();
            }
            assert_eq!(ready_count, 2);
            machine_prepared.unwrap();
            assert!(registered, "both native owners must reach their entry path");
            assert!(
                pure_wake_preserved_owners,
                "native wake must not authorize termination or AP startup"
            );
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
        fn initialize_bsp(&mut self) -> Result<(), Error> {
            self.inner.initialize_bsp()
        }

        fn run(
            &mut self,
            termination: &dyn dillo_machine::CpuTermination,
        ) -> Result<VcpuExit, Error> {
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
                    termination,
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
                            // Unmapped probes are non-fatal, like reads above.
                            // Keep their details available in diagnostic logs.
                            log::debug!(
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

        fn run_to_stop(
            &mut self,
            termination: &dyn dillo_machine::CpuTermination,
        ) -> Result<VcpuStop, Error> {
            let _signal_mask = crate::hypervisor::block_kick_signal(&self.inner, VCPU_KICK_SIGNAL)?;
            let _registration = self.exit_requester.register_current_thread();
            loop {
                if termination.is_requested() {
                    return Ok(VcpuStop::Stopped);
                }
                match self.run(termination)? {
                    VcpuExit::MmioWrite { .. } => {}
                    VcpuExit::Interrupted => continue,
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

    // Declaration-to-realization tests for the x86 interrupt-controller
    // contract. These drive the real `Machine::from_launch_config` path against
    // `/dev/kvm` and then read back from KVM what was actually constructed, so
    // a backend that accepted the declaration without realizing it fails here.
    #[cfg(all(test, target_arch = "x86_64"))]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod intc_realization_tests {
        use dillo_machine::Machine as _;

        use super::*;
        use crate::intc_x86::{IOAPIC_FIXED_BASE, tests::tree};

        const LAPIC_STD: u64 = 0xFEE0_0000;

        /// Build a VM from a tree declaring the given controller windows.
        fn vm_from(
            lapic_base: u64,
            lapic_size: u64,
            ioapic_base: u64,
            ioapic_size: u64,
        ) -> Result<Vm, Error> {
            let dtb = tree(lapic_base, lapic_size, ioapic_base, ioapic_size)
                .encode()
                .expect("encode declaration");
            Vm::from_launch_config(LaunchConfig {
                dtb,
                vcpus: 1,
                min_addr_space_bits: 32,
            })
        }

        /// The base a freshly created vCPU's LAPIC actually decodes at.
        fn realized_lapic_base(vm: &Vm, idx: u32) -> u64 {
            vm.create_vcpu_inner(idx, "x86-64-v1")
                .expect("create vCPU")
                .inner
                .realized_lapic_base()
                .expect("read back IA32_APIC_BASE")
        }

        #[test]
        fn standard_layout_realizes_both_controllers() {
            let vm = vm_from(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, 0x1000)
                .expect("standard layout boots");
            assert_eq!(realized_lapic_base(&vm, 0), LAPIC_STD);
            assert_eq!(
                vm.inner.realized_ioapic_base().expect("read back IOAPIC"),
                IOAPIC_FIXED_BASE
            );
        }

        #[test]
        fn declared_lapic_base_moves_the_realized_lapic() {
            // Vary the LAPIC alone: the IOAPIC stays where the contract (and
            // KVM) put it, so a pass here is the LAPIC declaration reaching the
            // backend and nothing else.
            for base in [0x1100_0000u64, 0x4000_0000, 0xF000_0000] {
                let vm = vm_from(base, 0x1000, IOAPIC_FIXED_BASE, 0x1000)
                    .expect("relocated LAPIC realizable");
                assert_eq!(
                    realized_lapic_base(&vm, 0),
                    base,
                    "LAPIC declared at {base:#x} was not realized there"
                );
            }
        }

        #[test]
        fn every_vcpu_gets_the_declared_lapic_base() {
            // IA32_APIC_BASE is per-vCPU, so a backend that programmed only the
            // boot vCPU would leave the others on KVM's default.
            let vm =
                vm_from(0x1100_0000, 0x1000, IOAPIC_FIXED_BASE, 0x1000).expect("VM constructed");
            for idx in 0..4 {
                assert_eq!(realized_lapic_base(&vm, idx), 0x1100_0000, "vCPU {idx}");
            }
        }

        #[test]
        fn declared_lapic_window_size_does_not_move_the_lapic() {
            // Size is varied independently of base: KVM decodes a fixed 4 KiB
            // span, and a larger declared window must not shift where it lands.
            for size in [0x1000u64, 0x2000, 0x10_0000] {
                let vm = vm_from(0x1100_0000, size, IOAPIC_FIXED_BASE, 0x1000)
                    .expect("LAPIC window realizable");
                assert_eq!(realized_lapic_base(&vm, 0), 0x1100_0000, "size {size:#x}");
            }
        }

        #[test]
        fn declared_ioapic_window_size_does_not_move_the_ioapic() {
            for size in [0x100u64, 0x1000] {
                let vm = vm_from(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, size)
                    .expect("IOAPIC window realizable");
                assert_eq!(
                    vm.inner.realized_ioapic_base().expect("read back IOAPIC"),
                    IOAPIC_FIXED_BASE,
                    "size {size:#x}"
                );
            }
        }

        #[test]
        fn unrealizable_lapic_is_refused_before_any_vcpu() {
            // Construction fails, so no vCPU is ever created — the declaration
            // is refused rather than quietly replaced by KVM's default.
            let err = vm_from(0x1100_0800, 0x1000, IOAPIC_FIXED_BASE, 0x1000)
                .expect_err("misaligned LAPIC refused");
            assert!(
                matches!(err, Error::UnsupportedLapicBase { .. }),
                "unexpected error: {err}"
            );

            let err = vm_from(LAPIC_STD, 0x800, IOAPIC_FIXED_BASE, 0x1000)
                .expect_err("short LAPIC window refused");
            assert!(
                matches!(err, Error::UnsupportedLapicSize { .. }),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn unrealizable_ioapic_is_refused_before_any_vcpu() {
            let err = vm_from(LAPIC_STD, 0x1000, 0x1200_0000, 0x1000)
                .expect_err("relocated IOAPIC refused");
            assert!(
                matches!(err, Error::UnsupportedIoapicBase { .. }),
                "unexpected error: {err}"
            );

            let err = vm_from(LAPIC_STD, 0x1000, IOAPIC_FIXED_BASE, 0x80)
                .expect_err("short IOAPIC window refused");
            assert!(
                matches!(err, Error::UnsupportedIoapicSize { .. }),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn missing_controller_declaration_is_refused() {
            let root = dillo_devtree::devtree::OwnedNode::new("");
            let dtb = OwnedTree::new(root).encode().expect("encode empty tree");
            let err = Vm::from_launch_config(LaunchConfig {
                dtb,
                vcpus: 1,
                min_addr_space_bits: 32,
            })
            .expect_err("undeclared controllers refused");
            assert!(
                matches!(err, Error::MissingSubstrate("/lapic")),
                "unexpected error: {err}"
            );
        }
    }
}

pub use imp::*;
