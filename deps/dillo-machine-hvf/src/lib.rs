// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

mod hypervisor;
pub mod worker;

use applevisor::prelude::VcpuHandle;
use dillo_devtree::platform::PsciMethod;

/// Reasons an HVF vCPU run returned to backend code.
#[derive(Debug)]
enum VmExit {
    MmioRead { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: [u8; 8], size: u8 },
    Smccc { method: PsciMethod, args: [u64; 8] },
    Halted,
    Interrupted,
    GuestPoweroff,
    GuestReset,
}

mod imp {
    use std::sync::OnceLock;
    use std::sync::{Arc, Mutex};
    use std::sync::{
        Condvar,
        atomic::{AtomicBool, Ordering},
    };

    use dillo_devtree::{
        CompatMismatch, FromDevTree, NodeExt, OwnedNodeExt, PropExt,
        devtree::{OwnedTree, Tree},
        platform::{Machine as PlatformMachine, PsciMethod},
    };
    use dillo_machine::{CpuProfile, Host, HostArchitecture, LaunchConfig, RamRange, VcpuStop};
    use dillo_mmio::{
        Attach, Interrupt, InterruptError, InterruptLine, MessageInterrupt, MessageInterruptDomain,
        MmioAttachment, MmioBus, MmioDevice, MmioDeviceHandle, MmioInterrupt,
        MmioInterruptRequirement, MmioRunToken, MmioSpawnError, MmioWriteOutcome, SharedMemory,
    };

    use crate::VcpuHandle;
    use crate::VmExit;
    pub use crate::hypervisor::Error;
    use crate::hypervisor::{CpuOnRequest, Vm as NativeVm};

    fn install_signal_watchers(_supervisor_shutdown: &'static AtomicBool) {}

    static ORIGINAL_TERMIOS: OnceLock<libc::termios> = OnceLock::new();

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

    pub struct Vm {
        inner: NativeVm,
        mmio_bus: Arc<Mutex<MmioBus>>,
        cpu_runtime: Arc<CpuRuntime>,
        shared_memory: Vec<Arc<dyn SharedMemory>>,
    }

    impl std::fmt::Debug for Vm {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Vm")
                .field("inner", &self.inner)
                .field("mmio_bus", &self.mmio_bus)
                .field("shared_memory", &self.shared_memory.len())
                .finish_non_exhaustive()
        }
    }

    impl Vm {
        fn new(
            gic: &crate::hypervisor::GicParams,
            min_addr_space_bits: u32,
            vcpus: u32,
            ram: &[RamRange],
            psci_method: PsciMethod,
        ) -> Result<Self, Error> {
            let inner = NativeVm::new(gic, min_addr_space_bits)?.with_memory(ram)?;
            let shared_memory: Vec<Arc<dyn SharedMemory>> =
                vec![Arc::new(dillo_mmio::MappedSharedMemory::for_guest_memory(
                    inner.guest_memory()?,
                    dillo_mmio::SharedAccess::ReadWrite,
                ))];
            Ok(Self {
                cpu_runtime: Arc::new(CpuRuntime::new(vcpus, inner.clone(), psci_method)),
                inner,
                mmio_bus: Arc::new(Mutex::new(MmioBus::new())),
                shared_memory,
            })
        }

        fn mmio_bus(&self) -> Arc<Mutex<MmioBus>> {
            Arc::clone(&self.mmio_bus)
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
                        Ok(MmioInterrupt::Line(self.create_line_interrupt(irq)))
                    }
                    MmioInterruptRequirement::MessageDomain { vectors, .. } => {
                        Ok(MmioInterrupt::MessageDomain(
                            self.create_message_interrupt_domain(*vectors),
                        ))
                    }
                })
                .collect()
        }

        fn wired_irq_from_cells(cells: &[u32; 4], cell_count: u8) -> Result<u32, Error> {
            if cell_count >= 2 {
                Ok(cells[1])
            } else {
                Err(Error::Hv(
                    "wired interrupt source has too few GIC cells".to_string(),
                ))
            }
        }

        fn create_line_interrupt(&self, source: u32) -> Interrupt {
            // `source` is the DTB SPI number (0-based); hv_gic's gic_set_spi
            // wants the absolute GIC INTID (SPI + 32 — INTIDs 0..31 are SGI/PPI,
            // so a raw SPI number is rejected as an invalid argument). This
            // mirrors gic_send_msi, which already uses absolute INTIDs (64-95).
            Interrupt::new(Arc::new(SpiInterruptLine {
                intid: source + 32,
                vm: self.inner.clone(),
            }))
        }

        fn create_message_interrupt_domain(&self, vectors: u16) -> Arc<dyn MessageInterruptDomain> {
            Arc::new(GicMessageInterruptDomain {
                inner: Arc::new(GicMessageInterruptDomainInner::new(vectors)),
                vm: self.inner.clone(),
            })
        }
    }

    impl Host for Vm {
        type RawStdioGuard = RawStdio;

        const ARCH: HostArchitecture = HostArchitecture::Aarch64;

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

    impl FromDevTree for crate::hypervisor::GicParams {
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
            let reg = v2m
                .remove_property("reg")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/msi-controller",
                    prop: "reg",
                    reason: "missing",
                })?;
            let (msi_base, _) = (&reg).reg_pair(0).ok_or(Error::BadSubstrateProperty {
                node: "/msi-controller",
                prop: "reg",
                reason: "missing MSI frame pair",
            })?;
            let msi_intid_base = v2m
                .remove_property("arm,msi-base-spi")
                .and_then(|prop| prop.as_u32())
                .ok_or(Error::BadSubstrateProperty {
                    node: "/msi-controller",
                    prop: "arm,msi-base-spi",
                    reason: "missing or not a u32",
                })?;
            let msi_intid_count = v2m
                .remove_property("arm,msi-num-spis")
                .and_then(|prop| prop.as_u32())
                .ok_or(Error::BadSubstrateProperty {
                    node: "/msi-controller",
                    prop: "arm,msi-num-spis",
                    reason: "missing or not a u32",
                })?;
            let _ = v2m.remove_property("msi-controller");
            let _ = v2m.remove_property("phandle");

            Ok(Some(Self {
                dist_base,
                redist_base,
                msi_base,
                msi_intid_base,
                msi_intid_count,
            }))
        }
    }

    #[derive(Debug)]
    struct SpiInterruptLine {
        intid: u32,
        vm: NativeVm,
    }

    impl InterruptLine for SpiInterruptLine {
        fn bind_status(
            &self,
            _: Arc<dillo_machine::worker::NotificationState>,
            _: Option<Arc<dyn dillo_mmio::InterruptUpdate>>,
        ) -> Result<Interrupt, InterruptError> {
            Ok(Interrupt::new(Arc::new(StatusCompletion(Mutex::new(
                Some(Self {
                    intid: self.intid,
                    vm: self.vm.clone(),
                }),
            )))))
        }

        // Edge-style notify (virtio-mmio): pulse the line so the GIC sees a
        // fresh 0→1 edge each time. Asserting without deasserting leaves the SPI
        // latched high — the guest takes one interrupt, ACKs the virtio queue,
        // then storms on the still-asserted line and the device wedges. (The
        // UART uses `set_level` directly for its level-triggered IRQ.)
        fn signal(&self) {
            if let Err(e) = self.set_level(true) {
                log::warn!("HVF SPI {} interrupt assert failed: {e}", self.intid);
            }
            if let Err(e) = self.set_level(false) {
                log::warn!("HVF SPI {} interrupt deassert failed: {e}", self.intid);
            }
        }

        fn set_level(&self, level: bool) -> Result<(), InterruptError> {
            self.vm
                .set_spi(self.intid, level)
                .map_err(|e| InterruptError::Delivery(e.to_string()))
        }
    }

    /// Keep native injection in the VM process and revoke it at reset, even
    /// if an obsolete completion callback remains retained by a caller.
    #[derive(Debug)]
    struct StatusCompletion(Mutex<Option<SpiInterruptLine>>);

    impl InterruptLine for StatusCompletion {
        fn signal(&self) {
            if let Some(line) = self.0.lock().unwrap().as_ref() {
                line.signal();
            }
        }

        fn set_level(&self, level: bool) -> Result<(), InterruptError> {
            if let Some(line) = self.0.lock().unwrap().as_ref() {
                line.set_level(level)?;
            }
            Ok(())
        }

        fn retire(&self) -> Result<(), InterruptError> {
            self.0.lock().unwrap().take();
            Ok(())
        }
    }

    #[derive(Debug)]
    struct GicMessageInterruptDomain {
        inner: Arc<GicMessageInterruptDomainInner>,
        vm: NativeVm,
    }

    #[derive(Debug, Clone, Copy)]
    struct GicMessage {
        message: MessageInterrupt,
        enabled: bool,
    }

    #[derive(Debug)]
    struct GicMessageInterruptDomainInner {
        vectors: Mutex<Vec<GicMessage>>,
    }

    impl GicMessageInterruptDomainInner {
        fn new(count: u16) -> Self {
            Self {
                vectors: Mutex::new(vec![
                    GicMessage {
                        message: MessageInterrupt {
                            address: 0,
                            data: 0,
                            masked: true,
                        },
                        enabled: false,
                    };
                    count as usize
                ]),
            }
        }

        fn message_for(&self, vector: u16) -> Option<MessageInterrupt> {
            let slot = *self
                .vectors
                .lock()
                .expect("message interrupt domain poisoned")
                .get(vector as usize)?;
            (slot.enabled && !slot.message.masked).then_some(slot.message)
        }

        fn update(&self, vector: u16, msg: MessageInterrupt) {
            let mut vectors = self
                .vectors
                .lock()
                .expect("message interrupt domain poisoned");
            if let Some(slot) = vectors.get_mut(vector as usize) {
                slot.message = msg;
            }
        }

        fn enabled(&self, vector: u16, enabled: bool) {
            let mut vectors = self
                .vectors
                .lock()
                .expect("message interrupt domain poisoned");
            if let Some(slot) = vectors.get_mut(vector as usize) {
                slot.enabled = enabled;
            }
        }
    }

    impl MessageInterruptDomain for GicMessageInterruptDomain {
        fn update(&self, vector: u16, msg: MessageInterrupt) -> Result<(), InterruptError> {
            self.inner.update(vector, msg);
            Ok(())
        }

        fn enabled(&self, vector: u16, enabled: bool) -> Result<(), InterruptError> {
            self.inner.enabled(vector, enabled);
            Ok(())
        }

        fn interrupt(&self, vector: u16) -> Option<Interrupt> {
            let domain = Arc::clone(&self.inner);
            let vm = self.vm.clone();
            Some(Interrupt::from_fn(move || {
                let Some(message) = domain.message_for(vector) else {
                    return;
                };
                if let Err(e) = vm.send_msi(message.address, message.data) {
                    log::warn!("HVF message interrupt inject (vector {vector}) failed: {e}");
                }
            }))
        }
    }

    impl dillo_machine::Machine for Vm {
        type Worker = crate::worker::Worker;
        type Error = Error;
        type Platform = PlatformMachine;
        type CpuPreparation = CpuPreparation;

        fn cpu_preparation(
            &mut self,
            index: u32,
            profile: CpuProfile,
        ) -> Result<Self::CpuPreparation, Self::Error> {
            if profile != CpuProfile::Aarch64(pmi::aarch64::Profile::V8_0) {
                return Err(Error::UnsupportedCpuProfile(profile));
            }
            self.inner.guest_memory()?;
            let index = index as usize;
            if index >= self.cpu_runtime.slots.len() {
                return Err(Error::Hv(format!(
                    "vCPU index {index} exceeds configured count"
                )));
            }
            Ok(CpuPreparation {
                index,
                mmio_bus: self.mmio_bus(),
                runtime: Arc::clone(&self.cpu_runtime),
            })
        }

        fn guest_address_bits() -> Result<u32, Self::Error> {
            crate::hypervisor::guest_address_bits()
        }

        fn worker_memory(&self) -> std::io::Result<dillo_machine::worker::MemoryExport> {
            let memory = self.inner.guest_memory().map_err(std::io::Error::other)?;
            dillo_machine_unix::export_memory(&memory)
        }

        fn from_launch_config(
            config: LaunchConfig<'_, Self::Platform>,
        ) -> Result<Self, Self::Error> {
            let psci = config
                .platform
                .psci()
                .ok_or(Error::MissingSubstrate("/psci"))?;
            let required = config
                .platform
                .required_address_bits_for_ram(config.ram.iter().map(|r| (r.gpa, r.size)))
                .map_err(|error| Error::Hv(error.to_string()))?;
            let parsed: Tree<'_> = Tree::parse(config.platform.dtb()).map_err(Error::ParseDtb)?;
            let mut tree = OwnedTree::materialize(&parsed);
            let gic = crate::hypervisor::GicParams::from_devtree(&mut tree)?
                .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;

            Self::new(&gic, required, config.vcpus, &config.ram, psci.method)
        }

        fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.inner.write_guest(gpa, data)
        }

        fn reset_for_reboot(&mut self) -> Result<(), Self::Error> {
            self.inner.reset_gic()
        }
    }

    #[derive(Debug)]
    pub struct CpuPreparation {
        index: usize,
        mmio_bus: Arc<Mutex<MmioBus>>,
        runtime: Arc<CpuRuntime>,
    }

    impl dillo_machine::CpuPreparation for CpuPreparation {
        type Error = Error;
        type Runner = CpuRunner;
        type Control = CpuControl;

        fn prepare(self) -> Result<(CpuRunner, CpuControl), Error> {
            let vcpu = Vcpu {
                inner: self.runtime.vm.create_vcpu_current_thread()?,
                mmio_bus: self.mmio_bus,
            };
            vcpu.set_mpidr(mpidr_for(self.index))?;
            if self.index == 0 {
                vcpu.inner.initialize_bsp()?;
            }
            vcpu.inner.admit_arm_v8_0()?;
            if self.index == 0 {
                self.runtime.slots[0].started.store(true, Ordering::SeqCst);
            }
            *self.runtime.handles[self.index]
                .lock()
                .expect("handle poisoned") = Some(vcpu.handle());
            let control = CpuControl {
                index: self.index,
                runtime: Arc::clone(&self.runtime),
            };
            Ok((
                CpuRunner {
                    vcpu,
                    index: self.index,
                    runtime: self.runtime,
                },
                control,
            ))
        }
    }

    #[derive(Debug)]
    pub struct CpuRunner {
        vcpu: Vcpu,
        index: usize,
        runtime: Arc<CpuRuntime>,
    }

    impl Drop for CpuRunner {
        fn drop(&mut self) {
            self.runtime.handles[self.index]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    impl dillo_machine::CpuRunner for CpuRunner {
        type Error = Error;

        fn run(&mut self) -> Result<VcpuStop, Self::Error> {
            let runtime = &self.runtime;
            if self.index != 0 {
                let Some(request) = runtime.slots[self.index].wait(&runtime.shutdown) else {
                    return Ok(VcpuStop::Stopped);
                };
                log::info!("vCPU{} powered on: pc={:#x}", self.index, request.entry);
                self.vcpu.inner.initialize_secondary(request)?;
            }
            runtime.run_vcpu_loop(self.index, &self.vcpu)
        }
    }

    #[derive(Debug)]
    pub struct CpuControl {
        index: usize,
        runtime: Arc<CpuRuntime>,
    }

    impl dillo_machine::CpuControl for CpuControl {
        type Error = Error;

        fn stop(&self) -> Result<(), Self::Error> {
            self.runtime.request_exit(self.index)
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
                return Err(Error::Hv(format!(
                    "MMIO device requested {} fixed shared-memory requirement(s), but HVF attachment does not realize machine-mediated shared-memory capabilities yet",
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
        fn notification(&self) -> std::io::Result<Option<Arc<dyn dillo_mmio::WriteNotification>>> {
            <crate::worker::Worker as dillo_machine::worker::WorkerHost>::queue_notification()
                .map(Some)
        }

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
            let join = std::thread::spawn(move || run(token));
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

    #[derive(Debug)]
    struct Vcpu {
        inner: crate::hypervisor::Vcpu,
        mmio_bus: Arc<Mutex<MmioBus>>,
    }

    impl Vcpu {
        fn set_mpidr(&self, mpidr: u64) -> Result<(), Error> {
            self.inner.set_mpidr(mpidr)
        }

        fn set_gpr(&self, n: u8, value: u64) -> Result<(), Error> {
            self.inner.set_gpr(n, value)
        }

        fn dispatch_psci(
            &self,
            method: PsciMethod,
            args: &[u64; 8],
        ) -> Result<psci::PsciAction, Error> {
            if method == PsciMethod::Smc {
                // SMC leaves PC at the instruction. HVC already advanced it.
                self.inner.advance_pc()?;
            }
            Ok(psci::dispatch(args))
        }

        fn el1_exception_state(&self) -> (u64, u64, u64) {
            self.inner.el1_exception_state()
        }

        fn handle(&self) -> VcpuHandle {
            self.inner.handle()
        }

        fn run(&self) -> Result<VmExit, Error> {
            loop {
                match self.inner.run()? {
                    VmExit::MmioRead { addr, size } => {
                        let mut data = [0u8; 8];
                        let size = (size as usize).min(8);
                        self.mmio_bus
                            .lock()
                            .expect("MMIO bus lock poisoned")
                            .read(addr, &mut data[..size])
                            .map_err(|error| Error::Hv(error.to_string()))?;
                        self.inner.complete_mmio_read(u64::from_le_bytes(data))?;
                    }
                    VmExit::MmioWrite { addr, data, size } => {
                        let size = (size as usize).min(8);
                        let outcome = self
                            .mmio_bus
                            .lock()
                            .expect("MMIO bus lock poisoned")
                            .write(addr, &data[..size])
                            .map_err(|error| Error::Hv(error.to_string()))?;
                        let Some(outcome) = outcome else {
                            log::warn!(
                                "HVF MMIO write to unmapped {:#x} (size {}, data {:02x?})",
                                addr,
                                size,
                                &data[..size],
                            );
                            return Ok(VmExit::MmioWrite {
                                addr,
                                data,
                                size: size as u8,
                            });
                        };
                        match outcome {
                            MmioWriteOutcome::Continue => {}
                            MmioWriteOutcome::GuestPoweroff => return Ok(VmExit::GuestPoweroff),
                            MmioWriteOutcome::GuestReset => return Ok(VmExit::GuestReset),
                        }
                        return Ok(VmExit::MmioWrite {
                            addr,
                            data,
                            size: size as u8,
                        });
                    }
                    other => return Ok(other),
                }
            }
        }
    }

    #[derive(Debug)]
    struct CpuRuntime {
        shutdown: AtomicBool,
        psci_method: PsciMethod,
        slots: Vec<CpuSlot>,
        handles: Vec<Mutex<Option<VcpuHandle>>>,
        vm: NativeVm,
    }

    impl CpuRuntime {
        fn new(vcpus: u32, vm: NativeVm, psci_method: PsciMethod) -> Self {
            let count = vcpus.max(1) as usize;
            Self {
                shutdown: AtomicBool::new(false),
                psci_method,
                slots: (0..count).map(|_| CpuSlot::new()).collect(),
                handles: (0..count).map(|_| Mutex::new(None)).collect(),
                vm,
            }
        }

        fn run_vcpu_loop(&self, idx: usize, vcpu: &Vcpu) -> Result<VcpuStop, Error> {
            loop {
                if self.shutdown.load(Ordering::SeqCst) {
                    return Ok(VcpuStop::Stopped);
                }
                match vcpu.run()? {
                    VmExit::MmioRead { .. } | VmExit::MmioWrite { .. } => {}
                    VmExit::GuestPoweroff => return Ok(VcpuStop::GuestPoweroff),
                    VmExit::GuestReset => return Ok(VcpuStop::GuestReset),
                    VmExit::Smccc { method, .. } if method != self.psci_method => {
                        return Err(Error::UnexpectedPsciConduit {
                            actual: method,
                            declared: self.psci_method,
                        });
                    }
                    VmExit::Smccc { method, args } => match vcpu.dispatch_psci(method, &args)? {
                        psci::PsciAction::SystemOff => {
                            log::info!("guest issued PSCI SYSTEM_OFF (vCPU{idx})");
                            return Ok(VcpuStop::GuestPoweroff);
                        }
                        psci::PsciAction::SystemReset => {
                            log::info!("guest issued PSCI SYSTEM_RESET (vCPU{idx})");
                            return Ok(VcpuStop::GuestReset);
                        }
                        psci::PsciAction::CpuOff => {
                            log::info!("vCPU{idx} PSCI CPU_OFF; parking");
                            self.slots[idx].started.store(false, Ordering::SeqCst);
                            match self.slots[idx].wait(&self.shutdown) {
                                Some(request) => vcpu.inner.initialize_secondary(request)?,
                                None => return Ok(VcpuStop::Stopped),
                            }
                        }
                        psci::PsciAction::CpuOn {
                            target,
                            entry,
                            context,
                        } => {
                            let tgt = (target & 0x00ff_ffff) as usize;
                            let code = if tgt >= self.slots.len() {
                                log::warn!(
                                    "vCPU{idx} CPU_ON target={target:#x} out of range (n={})",
                                    self.slots.len()
                                );
                                psci::ret::INVALID_PARAMETERS
                            } else if self.slots[tgt]
                                .try_deposit(|| vcpu.inner.cpu_on_request(entry, context))?
                            {
                                log::info!("vCPU{idx} powers on vCPU{tgt} at pc={entry:#x}");
                                psci::ret::SUCCESS
                            } else {
                                psci::ret::ALREADY_ON
                            };
                            vcpu.set_gpr(0, code)?;
                        }
                        psci::PsciAction::Return(value) => {
                            vcpu.set_gpr(0, value)?;
                        }
                    },
                    VmExit::Interrupted => return Ok(VcpuStop::Stopped),
                    other @ VmExit::Halted => {
                        let (esr, elr, far) = vcpu.el1_exception_state();
                        log::warn!(
                            "vCPU{idx} unhandled exit: {other:?}; guest EL1 state at first \
                             exception: ESR_EL1={esr:#x} (EC={:#x}) ELR_EL1={elr:#x} \
                             FAR_EL1={far:#x}",
                            esr >> 26
                        );
                        return Err(Error::Hv(format!("unhandled HVF exit: {other:?}")));
                    }
                }
            }
        }

        fn request_exit(&self, index: usize) -> Result<(), Error> {
            self.shutdown.store(true, Ordering::SeqCst);
            self.slots[index].wake();
            // Keep the handle bound through the native wake. The owner
            // clears this binding under the same lock before destruction.
            let handle = self.handles[index]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(handle) = handle.as_ref() {
                self.vm.force_vcpus_exit(std::slice::from_ref(handle))?;
            }
            Ok(())
        }
    }

    /// Per-vCPU power-on mailbox. A parked secondary waits here until another
    /// core's PSCI `CPU_ON` deposits a startup request.
    #[derive(Debug)]
    struct CpuSlot {
        started: AtomicBool,
        request: Mutex<Option<CpuOnRequest>>,
        cv: Condvar,
    }

    impl CpuSlot {
        fn new() -> Self {
            Self {
                started: AtomicBool::new(false),
                request: Mutex::new(None),
                cv: Condvar::new(),
            }
        }

        fn try_deposit(
            &self,
            make_request: impl FnOnce() -> Result<CpuOnRequest, Error>,
        ) -> Result<bool, Error> {
            let mut request = self.request.lock().expect("cpu-slot poisoned");
            if self.started.load(Ordering::SeqCst) {
                return Ok(false);
            }
            *request = Some(make_request()?);
            self.started.store(true, Ordering::SeqCst);
            drop(request);
            self.cv.notify_all();
            Ok(true)
        }

        fn wake(&self) {
            let _request = self
                .request
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.cv.notify_all();
        }

        fn wait(&self, shutdown: &AtomicBool) -> Option<CpuOnRequest> {
            let mut g = self.request.lock().expect("cpu-slot poisoned");
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    return None;
                }
                if let Some(req) = g.take() {
                    return Some(req);
                }
                g = self.cv.wait(g).expect("cpu-slot poisoned");
            }
        }
    }

    fn mpidr_for(idx: usize) -> u64 {
        0x8000_0000 | (idx as u64)
    }

    mod psci {
        mod fid {
            pub(super) const VERSION: u32 = 0x8400_0000;
            pub(super) const CPU_OFF: u32 = 0x8400_0002;
            pub(super) const CPU_ON_32: u32 = 0x8400_0003;
            pub(super) const CPU_ON_64: u32 = 0xC400_0003;
            pub(super) const AFFINITY_INFO_32: u32 = 0x8400_0004;
            pub(super) const AFFINITY_INFO_64: u32 = 0xC400_0004;
            pub(super) const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
            pub(super) const SYSTEM_OFF: u32 = 0x8400_0008;
            pub(super) const SYSTEM_RESET: u32 = 0x8400_0009;
            pub(super) const FEATURES: u32 = 0x8400_000A;
        }

        pub(super) mod ret {
            pub(crate) const SUCCESS: u64 = 0;
            pub(crate) const NOT_SUPPORTED: u64 = (-1i64) as u64;
            pub(crate) const INVALID_PARAMETERS: u64 = (-2i64) as u64;
            pub(crate) const ALREADY_ON: u64 = (-4i64) as u64;
            pub(crate) const AFF_ON: u64 = 0;
            pub(crate) const MIGRATE_NOT_REQUIRED: u64 = 2;
            pub(crate) const VERSION_1_1: u64 = 0x0001_0001;
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(super) enum PsciAction {
            CpuOn {
                target: u64,
                entry: u64,
                context: u64,
            },
            CpuOff,
            SystemOff,
            SystemReset,
            Return(u64),
        }

        pub(super) fn dispatch(args: &[u64; 8]) -> PsciAction {
            #[allow(clippy::cast_possible_truncation)]
            let function = args[0] as u32;
            match function {
                fid::VERSION => PsciAction::Return(ret::VERSION_1_1),
                fid::CPU_ON_32 | fid::CPU_ON_64 => PsciAction::CpuOn {
                    target: args[1],
                    entry: args[2],
                    context: args[3],
                },
                fid::CPU_OFF => PsciAction::CpuOff,
                fid::AFFINITY_INFO_32 | fid::AFFINITY_INFO_64 => PsciAction::Return(ret::AFF_ON),
                fid::MIGRATE_INFO_TYPE => PsciAction::Return(ret::MIGRATE_NOT_REQUIRED),
                fid::SYSTEM_OFF => PsciAction::SystemOff,
                fid::SYSTEM_RESET => PsciAction::SystemReset,
                fid::FEATURES => PsciAction::Return(features(args[1] as u32)),
                _ => PsciAction::Return(ret::NOT_SUPPORTED),
            }
        }

        fn features(queried: u32) -> u64 {
            match queried {
                fid::VERSION
                | fid::CPU_OFF
                | fid::CPU_ON_32
                | fid::CPU_ON_64
                | fid::AFFINITY_INFO_32
                | fid::AFFINITY_INFO_64
                | fid::MIGRATE_INFO_TYPE
                | fid::SYSTEM_OFF
                | fid::SYSTEM_RESET
                | fid::FEATURES => ret::SUCCESS,
                _ => ret::NOT_SUPPORTED,
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            fn call(fid: u64, a1: u64, a2: u64, a3: u64) -> PsciAction {
                dispatch(&[fid, a1, a2, a3, 0, 0, 0, 0])
            }

            #[test]
            fn version_reports_1_1() {
                assert_eq!(call(0x8400_0000, 0, 0, 0), PsciAction::Return(0x0001_0001));
            }

            #[test]
            fn cpu_on_decodes_target_entry_context() {
                let want = PsciAction::CpuOn {
                    target: 0x1,
                    entry: 0x4000_0000,
                    context: 0xABCD,
                };
                assert_eq!(call(0xC400_0003, 0x1, 0x4000_0000, 0xABCD), want);
                assert_eq!(call(0x8400_0003, 0x1, 0x4000_0000, 0xABCD), want);
            }

            #[test]
            fn shutdown_and_reset() {
                assert_eq!(call(0x8400_0008, 0, 0, 0), PsciAction::SystemOff);
                assert_eq!(call(0x8400_0009, 0, 0, 0), PsciAction::SystemReset);
            }

            #[test]
            fn cpu_off_and_affinity_and_migrate() {
                assert_eq!(call(0x8400_0002, 0, 0, 0), PsciAction::CpuOff);
                assert_eq!(call(0xC400_0004, 0, 0, 0), PsciAction::Return(0));
                assert_eq!(call(0x8400_0006, 0, 0, 0), PsciAction::Return(2));
            }

            #[test]
            fn features_known_vs_unknown() {
                assert_eq!(call(0x8400_000A, 0xC400_0003, 0, 0), PsciAction::Return(0));
                assert_eq!(
                    call(0x8400_000A, 0xDEAD_BEEF, 0, 0),
                    PsciAction::Return((-1i64) as u64)
                );
            }

            #[test]
            fn unknown_function_is_not_supported() {
                assert_eq!(
                    call(0x8400_00FF, 0, 0, 0),
                    PsciAction::Return((-1i64) as u64)
                );
            }
        }
    }

    #[cfg(test)]
    pub(super) mod tests {
        use std::sync::Arc;
        use std::thread;

        use super::*;

        #[cfg(target_arch = "aarch64")]
        pub(crate) fn check_psci_conduits(ram_size: u64) {
            use dillo_machine::{CpuPreparation as _, CpuRunner as _, Machine as _};
            use vm_memory::{Bytes, GuestAddress};

            let marker = 0x800;
            let not_returned = 0xa5a5_a5a5_a5a5_a5a5;
            for (name, declared) in [("hvc", PsciMethod::Hvc), ("smc", PsciMethod::Smc)] {
                let platform = psci_platform(name);
                for (instruction, actual, nonzero_immediate) in [
                    (0xd400_0002, PsciMethod::Hvc, false),
                    (0xd400_0003, PsciMethod::Smc, false),
                    (0xd400_0022, PsciMethod::Hvc, true),
                    (0xd400_0023, PsciMethod::Smc, true),
                ] {
                    if nonzero_immediate && declared != actual {
                        continue;
                    }
                    let mut vm = Vm::from_launch_config(LaunchConfig {
                        platform: &platform,
                        vcpus: 1,
                        ram: vec![RamRange {
                            gpa: 0,
                            size: ram_size,
                        }],
                    })
                    .unwrap();
                    // Try SYSTEM_OFF directly for nonzero immediates.
                    let first_function = if nonzero_immediate {
                        0x5280_0100u32
                    } else {
                        0x5280_0000u32
                    };
                    let code = [
                        0xd281_0001, // x1 = marker
                        first_function,
                        0x72b0_8000,
                        instruction,
                        0xf900_0020, // First call's result
                        0x5280_3200,
                        0x72b8_8000,
                        instruction,
                        0xf900_0420, // RSI_ABI_VERSION
                        0x5280_0100,
                        0x72b0_8000,
                        instruction,
                        0xf900_0820, // SYSTEM_OFF
                        0x1400_0000,
                    ];
                    let bytes: Vec<_> = code.into_iter().flat_map(u32::to_le_bytes).collect();
                    vm.write_guest(0, &bytes).unwrap();
                    vm.write_guest(marker, &[0xa5; 24]).unwrap();
                    let preparation = vm
                        .cpu_preparation(0, CpuProfile::Aarch64(pmi::aarch64::Profile::V8_0))
                        .unwrap();
                    let result = thread::spawn(move || {
                        let (mut runner, _control) = preparation.prepare().unwrap();
                        let result = runner.run();
                        runner.retire().unwrap();
                        result
                    })
                    .join()
                    .unwrap();
                    let memory = vm.inner.guest_memory().unwrap();
                    let read = |offset| {
                        memory
                            .read_obj::<u64>(GuestAddress(marker + offset))
                            .unwrap()
                    };
                    if nonzero_immediate {
                        let trap = match actual {
                            PsciMethod::Hvc => "hvf exception EC=0x16 ",
                            PsciMethod::Smc => "hvf exception EC=0x17 ",
                        };
                        assert!(
                            matches!(&result, Err(Error::Hv(reason)) if reason.starts_with(trap)),
                            "{result:?}"
                        );
                    } else if declared == actual {
                        assert_eq!(result.unwrap(), VcpuStop::GuestPoweroff);
                        assert_eq!(read(0), 0x0001_0001, "PSCI_VERSION");
                        assert_eq!(read(8), u64::MAX, "RSI_ABI_VERSION");
                    } else {
                        assert!(
                            matches!(
                                result,
                                Err(Error::UnexpectedPsciConduit { actual: observed, declared: config })
                                    if observed == actual && config == declared
                            ),
                            "{result:?}"
                        );
                    }
                    if nonzero_immediate || declared != actual {
                        assert_eq!([read(0), read(8)], [not_returned; 2]);
                    }
                    assert_eq!(read(16), not_returned, "SYSTEM_OFF returned");
                }
            }
        }

        #[cfg(target_arch = "aarch64")]
        pub(crate) fn check_psci_ap_start(ram_size: u64) {
            use dillo_machine::{
                CpuControl as _, CpuPreparation as _, CpuRunner as _, Machine as _,
            };
            use vm_memory::{Bytes, GuestAddress};

            let platform = psci_platform("smc");
            let mut vm = Vm::from_launch_config(LaunchConfig {
                platform: &platform,
                vcpus: 2,
                ram: vec![RamRange {
                    gpa: 0,
                    size: ram_size,
                }],
            })
            .unwrap();
            for (gpa, code) in [
                (
                    0,
                    &[
                        0xd281_0004u32, // x4 = 0x800
                        0xd538_0705,
                        0xd348_2ca5,
                        0x3900_6085, // Save MMFR0.BigEnd at 0x818.
                        0xb400_00a5, // Set EE only for mixed-endian EL1.
                        0xd538_1006,
                        0xb267_00c6,
                        0xd518_1006,
                        0xd503_3fdf, // Set EE; ISB.
                        0xd282_4683,
                        0xf900_0883, // Store caller's context bytes at 0x810.
                        0xd280_0060,
                        0xf2b8_8000,
                        0xd280_0021,
                        0xd288_0002,
                        0xd400_0003,
                        0xf900_0080, // CPU_ON(1, 0x4000, 0x1234); status at 0x800.
                        0xf940_0485,
                        0xb4ff_ffe5, // Wait for first AP store.
                        0xd538_1006,
                        0x9266_f8c6,
                        0xd518_1006,
                        0xd503_3fdf, // Clear EE; ISB.
                        0xd280_0060,
                        0xf2b8_8000,
                        0xd280_0021,
                        0xd288_0802,
                        0xd28a_cf03,
                        0xd400_0003, // CPU_ON(1, 0x4040, 0x5678)
                        0xb100_101f,
                        0x54ff_ff20, // Retry ALREADY_ON until the AP parks.
                        0xf900_1480,
                        0xf940_1085,
                        0xb4ff_ffe5, // Status at 0x828; wait for second store.
                        0x5280_0100,
                        0x72b0_8000,
                        0xd400_0003, // SYSTEM_OFF
                    ][..],
                ),
                (
                    0x4000,
                    &[
                        0xd281_0004,
                        0xf900_0480, // Save first context at 0x808.
                        0x5280_0040,
                        0x72b0_8000,
                        0xd400_0003, // CPU_OFF
                        0xd420_0000, // CPU_OFF must not return.
                    ][..],
                ),
                (0x4040, &[0xd281_0004, 0xf900_1080, 0x1400_0000][..]), // Second context at 0x820.
            ] {
                let bytes: Vec<_> = code.iter().copied().flat_map(u32::to_le_bytes).collect();
                vm.write_guest(gpa, &bytes).unwrap();
            }
            for status in [0x800, 0x828] {
                vm.write_guest(status, &[0xff; 8]).unwrap();
            }

            let profile = CpuProfile::Aarch64(pmi::aarch64::Profile::V8_0);
            let (mut bsp, _bsp_control) =
                vm.cpu_preparation(0, profile).unwrap().prepare().unwrap();
            let ap = vm.cpu_preparation(1, profile).unwrap();
            let (ready, prepared) = std::sync::mpsc::sync_channel(1);
            let ap = thread::spawn(move || {
                let (mut runner, control) = ap.prepare().unwrap();
                ready.send(control).unwrap();
                let stop = runner.run().unwrap();
                runner.retire().unwrap();
                stop
            });
            let control = prepared
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            let memory = vm.inner.guest_memory().unwrap();
            let read = |gpa| {
                let mut bytes = [0; 8];
                memory.read_slice(&mut bytes, GuestAddress(gpa)).unwrap();
                bytes
            };
            assert_eq!(read(0x808), [0; 8]);
            assert_eq!(read(0x820), [0; 8]);
            assert!(!vm.cpu_runtime.slots[1].started.load(Ordering::Acquire));
            assert_eq!(bsp.run().unwrap(), VcpuStop::GuestPoweroff);
            bsp.retire().unwrap();
            control.stop().unwrap();
            assert_eq!(ap.join().unwrap(), VcpuStop::Stopped);
            assert_eq!(read(0x800), [0; 8]);
            assert_eq!(read(0x828), [0; 8]);
            let first = if read(0x818)[0] != 0 {
                0x1234_u64.to_be_bytes()
            } else {
                0x1234_u64.to_le_bytes()
            };
            assert_eq!(read(0x810), first, "caller context bytes");
            assert_eq!(read(0x808), first, "first CPU_ON context bytes");
            assert_eq!(
                read(0x820),
                0x5678_u64.to_le_bytes(),
                "second CPU_ON context bytes"
            );
        }

        #[cfg(target_arch = "aarch64")]
        fn psci_platform(method: &str) -> PlatformMachine {
            use dillo_devtree::{
                devtree::{OwnedNode, OwnedProperty},
                platform::Arch,
            };

            let gic = OwnedNode::new("interrupt-controller@8000000")
                .with_property(OwnedProperty::new("compatible").with_str("arm,gic-v3"))
                .with_property(OwnedProperty::new("#interrupt-cells").with_u32(3))
                .with_property(OwnedProperty::new("interrupt-controller"))
                .with_property(OwnedProperty::new("reg").with_u32s(&[
                    0,
                    0x0800_0000,
                    0,
                    0x1_0000,
                    0,
                    0x0810_0000,
                    0,
                    0x200_0000,
                ]))
                .with_property(OwnedProperty::new("phandle").with_u32(1));
            let msi = OwnedNode::new("msi-controller@a100000")
                .with_property(OwnedProperty::new("compatible").with_str("arm,gic-v2m-frame"))
                .with_property(OwnedProperty::new("msi-controller"))
                .with_property(OwnedProperty::new("reg").with_u32s(&[0, 0x0a10_0000, 0, 0x1_0000]))
                .with_property(OwnedProperty::new("arm,msi-base-spi").with_u32(64))
                .with_property(OwnedProperty::new("arm,msi-num-spis").with_u32(32))
                .with_property(OwnedProperty::new("phandle").with_u32(3));
            let timer = OwnedNode::new("timer")
                .with_property(OwnedProperty::new("compatible").with_str("arm,armv8-timer"))
                .with_property(OwnedProperty::new("interrupt-parent").with_u32(1))
                .with_property(
                    OwnedProperty::new("interrupts")
                        .with_u32s(&[1, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4]),
                );
            let psci = OwnedNode::new("psci")
                .with_property(
                    OwnedProperty::new("compatible").with_strs(&["arm,psci-1.0", "arm,psci-0.2"]),
                )
                .with_property(OwnedProperty::new("method").with_str(method));
            let root = OwnedNode::new("")
                .with_property(OwnedProperty::new("#address-cells").with_u32(2))
                .with_property(OwnedProperty::new("#size-cells").with_u32(2))
                .with_child(gic)
                .with_child(msi)
                .with_child(timer)
                .with_child(psci);
            PlatformMachine::survey(OwnedTree::new(root).encode().unwrap(), Arch::Aarch64).unwrap()
        }

        #[test]
        fn message_vectors_keep_enable_and_mask_independent() {
            let domain = GicMessageInterruptDomainInner::new(2);
            let message = MessageInterrupt {
                address: 0x0808_0040,
                data: 48,
                masked: false,
            };
            domain.update(0, message);
            domain.update(1, message);
            assert_eq!(domain.message_for(0), None);
            domain.enabled(0, true);
            domain.enabled(1, true);
            domain.enabled(0, false);
            assert_eq!(domain.message_for(0), None);
            assert_eq!(domain.message_for(1), Some(message));
            domain.enabled(1, false);
            domain.enabled(0, true);
            assert_eq!(domain.message_for(0), Some(message));
            assert_eq!(domain.message_for(1), None);

            // Table programming must preserve a disabled vector's enable state.
            domain.update(1, message);
            assert_eq!(domain.message_for(1), None);
            domain.update(
                0,
                MessageInterrupt {
                    masked: true,
                    ..message
                },
            );
            domain.enabled(0, false);
            domain.enabled(0, true);
            domain.enabled(1, true);
            assert_eq!(domain.message_for(0), None);
            assert_eq!(domain.message_for(1), Some(message));
            domain.update(0, message);
            assert_eq!(domain.message_for(0), Some(message));
        }

        #[test]
        fn cpu_slot_deposit_wakes_waiter() {
            assert_eq!(mpidr_for(0), 0x8000_0000);
            assert_eq!(mpidr_for(3), 0x8000_0003);
            assert_eq!((mpidr_for(2) & 0x00ff_ffff) as usize, 2);

            let slot = Arc::new(CpuSlot::new());
            assert!(
                slot.try_deposit(|| Err(Error::Hv("read caller EE".into())))
                    .is_err()
            );
            assert!(!slot.started.load(Ordering::Acquire));
            let shutdown = Arc::new(AtomicBool::new(false));
            let s2 = Arc::clone(&slot);
            let sd2 = Arc::clone(&shutdown);
            let waiter = thread::spawn(move || s2.wait(&sd2));
            assert!(
                slot.try_deposit(|| Ok(CpuOnRequest {
                    entry: 0x4000_0000,
                    context: 0xabcd,
                    big_endian: true,
                }))
                .unwrap()
            );
            let request = waiter.join().unwrap().unwrap();
            assert_eq!(request.entry, 0x4000_0000);
            assert_eq!(request.context, 0xabcd);
            assert!(request.big_endian);
            assert!(
                !slot
                    .try_deposit(|| panic!("already-on target must skip reading caller EE"))
                    .unwrap()
            );

            let slot = Arc::new(CpuSlot::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let s2 = Arc::clone(&slot);
            let sd2 = Arc::clone(&shutdown);
            let waiter = thread::spawn(move || s2.wait(&sd2));
            shutdown.store(true, Ordering::SeqCst);
            slot.wake();
            assert!(waiter.join().unwrap().is_none());
        }
    }
}

pub use imp::*;
