// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

mod hypervisor;

use applevisor::prelude::VcpuHandle;

/// Reasons an HVF vCPU run returned to backend code.
#[derive(Debug)]
enum VmExit {
    MmioRead { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: [u8; 8], size: u8 },
    Hvc { args: [u64; 8] },
    Smc { args: [u64; 8] },
    Halted,
    GuestPoweroff,
    GuestReset,
    Unknown(String),
}

mod imp {
    use std::sync::OnceLock;
    use std::sync::{Arc, Mutex};
    use std::sync::{
        Condvar,
        atomic::{AtomicBool, Ordering},
    };

    use dillo_devtree::{
        FromDevTree,
        devtree::{NodeView, OwnedTree, PropertyView, Tree},
    };
    use dillo_machine::{BootVcpuState, Host, HostArchitecture, LaunchConfig, RamRange, VcpuStop};
    use dillo_mmio::{
        Attach, Interrupt, InterruptError, InterruptLine, MessageInterrupt, MessageInterruptDomain,
        MmioAttachment, MmioBus, MmioDevice, MmioDeviceHandle, MmioInterrupt,
        MmioInterruptRequirement, MmioRunToken, MmioSpawnError, MmioWriteOutcome, SharedMemory,
    };
    use vm_memory::mmap::MmapRegionBuilder;
    use vm_memory::{GuestAddress, GuestMemoryMmap, GuestRegionMmap};

    use crate::VcpuHandle;
    use crate::VmExit;
    pub use crate::hypervisor::Error;
    use crate::hypervisor::force_vcpus_exit;

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
        inner: crate::hypervisor::Vm,
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
        ) -> Result<Self, Error> {
            Ok(Self {
                inner: crate::hypervisor::Vm::new(gic, min_addr_space_bits)?,
                mmio_bus: Arc::new(Mutex::new(MmioBus::new())),
                cpu_runtime: Arc::new(CpuRuntime::new(vcpus)),
                shared_memory: Vec::new(),
            })
        }

        fn add_memory(&mut self, base: u64, size: u64) -> Result<(), Error> {
            self.inner.add_memory(base, size)
        }

        fn region_mappings(&self) -> Vec<(u64, u64, u64)> {
            self.inner.region_mappings()
        }

        fn mmio_bus(&self) -> Arc<Mutex<MmioBus>> {
            Arc::clone(&self.mmio_bus)
        }

        fn cpu_runtime(&self) -> Arc<CpuRuntime> {
            Arc::clone(&self.cpu_runtime)
        }

        /// Build a `vm-memory` view over HVF-mapped guest RAM.
        ///
        /// The returned regions borrow the mappings owned by this VM; dropping
        /// the `GuestMemoryMmap` must not unmap the backend-owned memory.
        fn guest_memory(&self) -> Result<GuestMemoryMmap, Error> {
            let mappings = self.region_mappings();
            let mut built: Vec<GuestRegionMmap> = Vec::with_capacity(mappings.len());
            for (gpa, host_addr, size) in mappings {
                #[allow(unsafe_code)]
                let region = unsafe {
                    MmapRegionBuilder::new(size as usize)
                        .with_raw_mmap_pointer(host_addr as *mut u8)
                }
                .build()
                .map_err(|e| Error::Hv(format!("MmapRegionBuilder: {e}")))?;
                let gr = GuestRegionMmap::new(region, GuestAddress(gpa)).ok_or_else(|| {
                    Error::Hv(format!(
                        "GuestRegionMmap: gpa+size overflow at {gpa:#x}+{size}"
                    ))
                })?;
                built.push(gr);
            }
            GuestMemoryMmap::from_regions(built)
                .map_err(|e| Error::Hv(format!("GuestMemoryMmap: {e:?}")))
        }

        // Mirrors the same method on the KVM/WHP backends (called as
        // `self.resolve_interrupts(..)`); HVF's interrupt factories happen to be
        // stateless, so `self` is unused here.
        #[allow(clippy::unused_self)]
        fn resolve_interrupts(
            &self,
            requirements: &[MmioInterruptRequirement],
        ) -> Result<Vec<MmioInterrupt>, Error> {
            requirements
                .iter()
                .map(|requirement| match requirement {
                    MmioInterruptRequirement::Line { source } => {
                        let irq = Self::wired_irq_from_cells(&source.cells, source.cell_count)?;
                        Ok(MmioInterrupt::Line(Self::create_line_interrupt(irq)))
                    }
                    MmioInterruptRequirement::MessageDomain { vectors, .. } => {
                        Ok(MmioInterrupt::MessageDomain(
                            Self::create_message_interrupt_domain(*vectors),
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

        fn create_line_interrupt(source: u32) -> Interrupt {
            // `source` is the DTB SPI number (0-based); hv_gic's gic_set_spi
            // wants the absolute GIC INTID (SPI + 32 — INTIDs 0..31 are SGI/PPI,
            // so a raw SPI number is rejected as an invalid argument). This
            // mirrors gic_send_msi, which already uses absolute INTIDs (64-95).
            Interrupt::new(Arc::new(SpiInterruptLine { intid: source + 32 }))
        }

        fn create_message_interrupt_domain(vectors: u16) -> Arc<dyn MessageInterruptDomain> {
            Arc::new(GicMessageInterruptDomain::new(vectors))
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

    #[derive(Debug, Clone)]
    struct Config {
        dtb: Vec<u8>,
        vcpus: u32,
        min_addr_space_bits: u32,
    }

    impl TryFrom<Config> for Vm {
        type Error = Error;

        fn try_from(config: Config) -> Result<Self, Self::Error> {
            let parsed: Tree<'_> = Tree::parse(&config.dtb).map_err(Error::ParseDtb)?;
            let mut tree = OwnedTree::materialize(&parsed);
            let gic = crate::hypervisor::GicParams::from_devtree(&mut tree)?
                .ok_or(Error::MissingSubstrate("/interrupt-controller@*"))?;
            Self::new(&gic, config.min_addr_space_bits, config.vcpus)
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
            let reg = v2m
                .remove_property("reg")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/msi-controller",
                    prop: "reg",
                    reason: "missing",
                })?;
            let (msi_base, _) = reg_pair(&reg, 0).ok_or(Error::BadSubstrateProperty {
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

    fn compatible_contains<N: NodeView>(node: N, value: &str) -> bool {
        let Some(prop) = node.property("compatible") else {
            return false;
        };
        stringlist_contains(prop.as_ref(), value)
    }

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

    fn stringlist_contains(bytes: &[u8], value: &str) -> bool {
        bytes
            .split(|byte| *byte == 0)
            .filter(|item| !item.is_empty())
            .any(|item| item == value.as_bytes())
    }

    fn reg_pair<P: PropertyView>(prop: P, pair_index: usize) -> Option<(u64, u64)> {
        let cells: Vec<u32> = prop.as_u32s()?.collect();
        let base = cells.get(pair_index * 4..pair_index * 4 + 2)?;
        let size = cells.get(pair_index * 4 + 2..pair_index * 4 + 4)?;
        Some((
            (u64::from(base[0]) << 32) | u64::from(base[1]),
            (u64::from(size[0]) << 32) | u64::from(size[1]),
        ))
    }

    #[derive(Debug)]
    struct SpiInterruptLine {
        intid: u32,
    }

    impl InterruptLine for SpiInterruptLine {
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
            crate::hypervisor::set_spi(self.intid, level)
                .map_err(|e| InterruptError::Delivery(e.to_string()))
        }
    }

    #[derive(Debug)]
    struct GicMessageInterruptDomain {
        inner: Arc<GicMessageInterruptDomainInner>,
    }

    #[derive(Debug)]
    struct GicMessageInterruptDomainInner {
        vectors: Mutex<Vec<MessageInterrupt>>,
        enabled: AtomicBool,
    }

    impl GicMessageInterruptDomain {
        fn new(count: u16) -> Self {
            Self {
                inner: Arc::new(GicMessageInterruptDomainInner {
                    vectors: Mutex::new(vec![
                        MessageInterrupt {
                            address: 0,
                            data: 0,
                            masked: true,
                        };
                        count as usize
                    ]),
                    enabled: AtomicBool::new(false),
                }),
            }
        }
    }

    impl GicMessageInterruptDomainInner {
        fn message_for(&self, vector: u16) -> Option<MessageInterrupt> {
            if !self.enabled.load(Ordering::SeqCst) {
                return None;
            }
            let message = *self
                .vectors
                .lock()
                .expect("message interrupt domain poisoned")
                .get(vector as usize)?;
            (!message.masked).then_some(message)
        }
    }

    impl MessageInterruptDomain for GicMessageInterruptDomain {
        fn update(&self, vector: u16, msg: MessageInterrupt) -> Result<(), InterruptError> {
            let mut vectors = self
                .inner
                .vectors
                .lock()
                .expect("message interrupt domain poisoned");
            if let Some(slot) = vectors.get_mut(vector as usize) {
                *slot = msg;
            }
            Ok(())
        }

        fn enabled(&self, enabled: bool) -> Result<(), InterruptError> {
            self.inner.enabled.store(enabled, Ordering::SeqCst);
            Ok(())
        }

        fn interrupt(&self, vector: u16) -> Option<Interrupt> {
            let domain = Arc::clone(&self.inner);
            Some(Interrupt::from_fn(move || {
                let Some(message) = domain.message_for(vector) else {
                    return;
                };
                if let Err(e) = crate::hypervisor::send_msi(message.address, message.data) {
                    log::warn!("HVF message interrupt inject (vector {vector}) failed: {e}");
                }
            }))
        }
    }

    impl dillo_machine::Machine for Vm {
        type Error = Error;
        type Cpu = Cpu;
        type CpuState = CpuState;
        type Memory = Memory;

        fn from_launch_config(config: LaunchConfig) -> Result<Self, Self::Error> {
            Self::try_from(Config {
                dtb: config.dtb,
                vcpus: config.vcpus,
                min_addr_space_bits: config.min_addr_space_bits,
            })
        }

        fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.inner.write_guest(gpa, data)
        }

        fn reset_for_reboot(&mut self) -> Result<(), Self::Error> {
            self.inner.reset_gic()
        }
    }

    #[derive(Debug, Clone)]
    pub struct Memory {
        ranges: Vec<RamRange>,
    }

    impl dillo_machine::Memory for Memory {
        type Error = Error;

        fn from_ranges(ranges: &[RamRange]) -> Result<Self, Self::Error> {
            Ok(Self {
                ranges: ranges.to_vec(),
            })
        }
    }

    impl Attach<Memory> for Vm {
        type Error = Error;
        type Output = ();

        fn attach(&mut self, item: Memory) -> Result<Self::Output, Self::Error> {
            for range in item.ranges {
                self.add_memory(range.gpa, range.size)?;
            }
            let guest_mem = self.guest_memory()?;
            self.shared_memory = vec![Arc::new(dillo_mmio::MappedSharedMemory::for_guest_memory(
                guest_mem,
                dillo_mmio::SharedAccess::ReadWrite,
            ))];
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct CpuState {
        index: u32,
        boot_state: Option<pmi::vm::vcpu::aarch64::CpuState>,
    }

    impl dillo_machine::CpuState for CpuState {
        type Error = Error;

        fn new(
            index: u32,
            _cpu_profile: &str,
            boot_state: Option<&dyn BootVcpuState>,
        ) -> Result<Self, Self::Error> {
            let boot_state = boot_state
                .map(|state| {
                    state
                        .aarch64()
                        .cloned()
                        .ok_or_else(|| Error::Hv("boot vCPU state is not aarch64".to_string()))
                })
                .transpose()?;
            Ok(Self { index, boot_state })
        }
    }

    impl Attach<CpuState> for Vm {
        type Error = Error;
        type Output = Arc<Cpu>;

        fn attach(&mut self, item: CpuState) -> Result<Self::Output, Self::Error> {
            let boot_state = item
                .boot_state
                .ok_or_else(|| Error::Hv("boot vCPU state is not aarch64".to_string()))?;
            Ok(Arc::new(Cpu {
                index: item.index as usize,
                boot_state,
                mmio_bus: self.mmio_bus(),
                runtime: self.cpu_runtime(),
            }))
        }
    }

    #[derive(Debug)]
    pub struct Cpu {
        index: usize,
        boot_state: pmi::vm::vcpu::aarch64::CpuState,
        mmio_bus: Arc<Mutex<MmioBus>>,
        runtime: Arc<CpuRuntime>,
    }

    impl dillo_machine::Cpu for Cpu {
        type Error = Error;

        fn run(&self) -> Result<VcpuStop, Self::Error> {
            self.runtime.run_cpu(self)
        }

        fn stop(&self) -> Result<(), Self::Error> {
            self.runtime.request_exit();
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

    fn create_vcpu_current_thread(mmio_bus: Arc<Mutex<MmioBus>>) -> Result<Vcpu, Error> {
        Ok(Vcpu {
            inner: crate::hypervisor::create_vcpu_current_thread()?,
            mmio_bus,
        })
    }

    impl Vcpu {
        fn set_aarch64_state(&self, state: &pmi::vm::vcpu::aarch64::CpuState) -> Result<(), Error> {
            self.inner.set_aarch64_state(state)
        }

        fn set_mpidr(&self, mpidr: u64) -> Result<(), Error> {
            self.inner.set_mpidr(mpidr)
        }

        fn set_gpr(&self, n: u8, value: u64) -> Result<(), Error> {
            self.inner.set_gpr(n, value)
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
                            .read(addr, &mut data[..size]);
                        self.inner.complete_mmio_read(u64::from_le_bytes(data))?;
                    }
                    VmExit::MmioWrite { addr, data, size } => {
                        let size = (size as usize).min(8);
                        let outcome = self
                            .mmio_bus
                            .lock()
                            .expect("MMIO bus lock poisoned")
                            .write(addr, &data[..size]);
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
        slots: Vec<CpuSlot>,
        handles: Vec<Mutex<Option<VcpuHandle>>>,
    }

    impl CpuRuntime {
        fn new(vcpus: u32) -> Self {
            let count = vcpus.max(1) as usize;
            Self {
                shutdown: AtomicBool::new(false),
                slots: (0..count).map(|_| CpuSlot::new()).collect(),
                handles: (0..count).map(|_| Mutex::new(None)).collect(),
            }
        }

        fn run_cpu(&self, cpu: &Cpu) -> Result<VcpuStop, Error> {
            let idx = cpu.index;
            let init = if idx == 0 {
                self.slots[0].started.store(true, Ordering::SeqCst);
                cpu.boot_state.clone()
            } else {
                match self.slots[idx].wait(&self.shutdown) {
                    Some((entry, context)) => secondary_state(entry, context, &cpu.boot_state),
                    None => return Ok(VcpuStop::Stopped),
                }
            };
            let vcpu = create_vcpu_current_thread(Arc::clone(&cpu.mmio_bus))?;
            vcpu.set_mpidr(mpidr_for(idx))?;
            vcpu.set_aarch64_state(&init)?;
            *self.handles[idx].lock().expect("handle poisoned") = Some(vcpu.handle());
            if idx != 0 {
                log::info!("vCPU{idx} powered on: pc={:#x}", init.pc);
            }

            let result = self.run_vcpu_loop(idx, &vcpu, &cpu.boot_state);
            self.shutdown.store(true, Ordering::SeqCst);
            self.wake_waiters();
            self.force_exit_live();
            result
        }

        fn run_vcpu_loop(
            &self,
            idx: usize,
            vcpu: &Vcpu,
            boot_state: &pmi::vm::vcpu::aarch64::CpuState,
        ) -> Result<VcpuStop, Error> {
            loop {
                if self.shutdown.load(Ordering::SeqCst) {
                    return Ok(VcpuStop::Stopped);
                }
                match vcpu.run()? {
                    VmExit::MmioRead { .. } | VmExit::MmioWrite { .. } => {}
                    VmExit::GuestPoweroff => return Ok(VcpuStop::GuestPoweroff),
                    VmExit::GuestReset => return Ok(VcpuStop::GuestReset),
                    VmExit::Hvc { args } => match psci::dispatch(&args) {
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
                                Some((entry, context)) => {
                                    let st = secondary_state(entry, context, boot_state);
                                    vcpu.set_aarch64_state(&st)?;
                                }
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
                            } else if self.slots[tgt].started.swap(true, Ordering::SeqCst) {
                                psci::ret::ALREADY_ON
                            } else {
                                log::info!("vCPU{idx} powers on vCPU{tgt} at pc={entry:#x}");
                                self.slots[tgt].deposit(entry, context);
                                psci::ret::SUCCESS
                            };
                            vcpu.set_gpr(0, code)?;
                        }
                        psci::PsciAction::Return(value) => {
                            vcpu.set_gpr(0, value)?;
                        }
                    },
                    VmExit::Smc { args } => {
                        log::warn!("unexpected SMC exit from HVF vCPU: args={args:?}");
                    }
                    VmExit::Unknown(reason) if self.shutdown.load(Ordering::SeqCst) => {
                        let _ = reason;
                        return Ok(VcpuStop::Stopped);
                    }
                    VmExit::Unknown(reason) => return Err(Error::Hv(reason)),
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

        fn request_exit(&self) {
            self.shutdown.store(true, Ordering::SeqCst);
            self.wake_waiters();
            self.force_exit_live();
        }

        fn wake_waiters(&self) {
            for slot in &self.slots {
                slot.cv.notify_all();
            }
        }

        fn force_exit_live(&self) {
            let live: Vec<VcpuHandle> = self
                .handles
                .iter()
                .filter_map(|h| h.lock().expect("handle poisoned").clone())
                .collect();
            let _ = force_vcpus_exit(&live);
        }
    }

    /// Per-vCPU power-on mailbox. A parked secondary waits here until another
    /// core's PSCI `CPU_ON` deposits a target entry point and context.
    #[derive(Debug)]
    struct CpuSlot {
        started: AtomicBool,
        request: Mutex<Option<(u64, u64)>>,
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

        fn deposit(&self, entry: u64, context: u64) {
            *self.request.lock().expect("cpu-slot poisoned") = Some((entry, context));
            self.cv.notify_all();
        }

        fn wait(&self, shutdown: &AtomicBool) -> Option<(u64, u64)> {
            let mut g = self.request.lock().expect("cpu-slot poisoned");
            loop {
                if let Some(req) = g.take() {
                    return Some(req);
                }
                if shutdown.load(Ordering::SeqCst) {
                    return None;
                }
                let (ng, _) = self
                    .cv
                    .wait_timeout(g, std::time::Duration::from_millis(100))
                    .expect("cpu-slot poisoned");
                g = ng;
            }
        }
    }

    fn secondary_state(
        entry: u64,
        context: u64,
        boot: &pmi::vm::vcpu::aarch64::CpuState,
    ) -> pmi::vm::vcpu::aarch64::CpuState {
        pmi::vm::vcpu::aarch64::CpuState {
            pc: entry,
            x0: context,
            pstate: boot.pstate,
            cpacr_el1: boot.cpacr_el1,
            ..Default::default()
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
    mod tests {
        use std::sync::Arc;
        use std::thread;

        use super::*;

        #[test]
        fn cpu_slot_deposit_wakes_waiter() {
            assert_eq!(mpidr_for(0), 0x8000_0000);
            assert_eq!(mpidr_for(3), 0x8000_0003);
            assert_eq!((mpidr_for(2) & 0x00ff_ffff) as usize, 2);

            let slot = Arc::new(CpuSlot::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let s2 = Arc::clone(&slot);
            let sd2 = Arc::clone(&shutdown);
            let waiter = thread::spawn(move || s2.wait(&sd2));
            slot.deposit(0x4000_0000, 0xABCD);
            assert_eq!(waiter.join().unwrap(), Some((0x4000_0000, 0xABCD)));

            let slot = Arc::new(CpuSlot::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let s2 = Arc::clone(&slot);
            let sd2 = Arc::clone(&shutdown);
            let waiter = thread::spawn(move || s2.wait(&sd2));
            shutdown.store(true, Ordering::SeqCst);
            slot.cv.notify_all();
            assert_eq!(waiter.join().unwrap(), None);
        }
    }
}

pub use imp::*;
