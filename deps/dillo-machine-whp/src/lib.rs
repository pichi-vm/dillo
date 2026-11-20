// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

mod hypervisor;
mod ioapic;

/// Reasons a WHP vCPU run returned to backend code.
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use dillo_devtree::{
        CompatMismatch, FromDevTree, NodeExt, OwnedNodeExt, PropExt,
        devtree::{OwnedTree, Tree},
        platform::Machine as PlatformMachine,
    };
    use dillo_machine::{CpuProfile, Host, HostArchitecture, LaunchConfig, RamRange, VcpuStop};
    use dillo_mmio::{
        Attach, Interrupt, InterruptError, InterruptLine, MessageInterrupt, MessageInterruptDomain,
        MmioAttachment, MmioBus, MmioDevice, MmioDeviceHandle, MmioInterrupt,
        MmioInterruptRequirement, MmioRunToken, MmioSpawnError, MmioWindow, MmioWriteOutcome,
        SharedMemory,
    };
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::VmExit;
    pub use crate::hypervisor::Error;
    use crate::hypervisor::InterruptController;
    use crate::ioapic::IoApic;

    fn install_signal_watchers(_supervisor_shutdown: &'static AtomicBool) {}

    fn install_panic_terminal_restore() {}

    #[derive(Debug)]
    pub struct RawStdio;

    impl RawStdio {
        fn enter_if_tty() -> Self {
            Self
        }
    }

    pub struct Vm {
        inner: crate::hypervisor::Vm,
        mmio_bus: Arc<Mutex<MmioBus>>,
        shared_memory: Vec<Arc<dyn SharedMemory>>,
        ioapic: Option<Arc<IoApic>>,
    }

    impl std::fmt::Debug for Vm {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Vm")
                .field("inner", &self.inner)
                .field("mmio_bus", &self.mmio_bus)
                .finish_non_exhaustive()
        }
    }

    impl Host for Vm {
        type RawStdioGuard = RawStdio;

        const ARCH: HostArchitecture = HostArchitecture::X86_64;

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

    impl Vm {
        fn new_x86_64(processor_count: u32, ioapic: Option<IoApic>) -> Result<Self, Error> {
            let mmio_bus = Arc::new(Mutex::new(MmioBus::new()));
            let ioapic = ioapic.map(Arc::new);
            if let Some(ioapic) = &ioapic {
                mmio_bus
                    .lock()
                    .expect("MMIO bus lock poisoned")
                    .register_device(Arc::clone(ioapic));
            }
            Ok(Self {
                inner: crate::hypervisor::Vm::new_x86_64_with_local_apic_count(processor_count)?,
                mmio_bus,
                shared_memory: Vec::new(),
                ioapic,
            })
        }

        fn set_memory(&mut self, memory: GuestMemoryMmap) -> Result<(), Error> {
            self.inner.set_memory(memory)
        }

        fn attach_guest_memory(&mut self, memory: GuestMemoryMmap) -> Result<(), Error> {
            self.set_memory(memory)?;
            let guest_mem = self.guest_memory()?;
            self.shared_memory = vec![Arc::new(dillo_mmio::MappedSharedMemory::for_guest_memory(
                guest_mem,
                dillo_mmio::SharedAccess::ReadWrite,
            ))];
            Ok(())
        }

        fn fixed_interrupt_requester(&self) -> FixedInterruptRequester {
            FixedInterruptRequester {
                interrupt_controller: self.inner.interrupt_controller(),
            }
        }

        fn guest_memory(&self) -> Result<GuestMemoryMmap, Error> {
            self.inner.guest_memory()
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

        fn wired_irq_from_cells(cells: &[u32; 4], cell_count: u8) -> Result<u32, Error> {
            if cell_count >= 1 {
                Ok(cells[0])
            } else {
                Err(Error::UnhandledExit(
                    "wired interrupt source has too few IOAPIC cells".to_string(),
                ))
            }
        }

        fn create_line_interrupt(&self, source: u32) -> Result<Interrupt, Error> {
            let ioapic = self
                .ioapic
                .as_ref()
                .ok_or(Error::MissingSubstrate("/ioapic"))?;
            Ok(Interrupt::new(Arc::new(IoApicInterruptLine::new(
                self.inner.interrupt_controller(),
                Arc::clone(ioapic),
                source,
            ))))
        }

        fn create_message_interrupt_domain(&self, vectors: u16) -> Arc<dyn MessageInterruptDomain> {
            Arc::new(FixedMessageInterruptDomain::new(
                self.fixed_interrupt_requester(),
                vectors,
            ))
        }
    }

    impl dillo_machine::Machine for Vm {
        type Error = Error;
        type Platform = PlatformMachine;
        type CpuPreparation = CpuPreparation;

        fn cpu_preparation(
            &mut self,
            index: u32,
            profile: CpuProfile,
        ) -> Result<Self::CpuPreparation, Self::Error> {
            let CpuProfile::X86_64(profile) = profile else {
                return Err(Error::UnsupportedCpuProfile(profile));
            };
            Ok(CpuPreparation {
                index,
                profile,
                machine: self.inner.clone(),
                mmio_bus: Arc::clone(&self.mmio_bus),
            })
        }

        fn guest_address_bits() -> Result<u32, Self::Error> {
            crate::hypervisor::guest_address_bits()
        }

        fn from_launch_config(
            config: LaunchConfig<'_, Self::Platform>,
        ) -> Result<Self, Self::Error> {
            let required = config
                .platform
                .required_address_bits_for_ram(config.ram.iter().map(|r| (r.gpa, r.size)))
                .map_err(|error| Error::AddressSpace(error.to_string()))?;
            let parsed: Tree<'_> = Tree::parse(config.platform.dtb()).map_err(Error::ParseDtb)?;
            let mut tree = OwnedTree::materialize(&parsed);
            let substrate = WhpX86Substrate::from_devtree(&mut tree)?
                .ok_or(Error::MissingSubstrate("/ioapic"))?;
            let available = Self::guest_address_bits()?;

            if required > available {
                return Err(Error::AddressSpace(format!(
                    "launch requires {required} bits; backend provides {available}"
                )));
            }
            let memory = guest_memory_from_ranges(config.ram)?;
            let mut vm = Self::new_x86_64(config.vcpus, Some(substrate.ioapic))?;
            vm.attach_guest_memory(memory)?;
            Ok(vm)
        }

        fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.inner.write_guest(gpa, data)
        }
    }

    #[derive(Debug)]
    struct WhpX86Substrate {
        ioapic: IoApic,
    }

    impl FromDevTree for WhpX86Substrate {
        type Error = Error;

        fn from_devtree(tree: &mut OwnedTree) -> Result<Option<Self>, Self::Error> {
            let root = tree.root_mut();
            let Some(name) = root
                .children()
                .find(|node| {
                    node.name().starts_with("interrupt-controller@")
                        && node.compatible_contains("intel,ce4100-ioapic")
                })
                .map(|node| node.name().to_string())
            else {
                return Ok(None);
            };
            let mut node = root
                .remove_child(&name)
                .ok_or(Error::MissingSubstrate("/ioapic"))?;
            node.take_compatible("intel,ce4100-ioapic")
                .map_err(|e| match e {
                    CompatMismatch::Missing => Error::BadSubstrateProperty {
                        node: "/ioapic",
                        prop: "compatible",
                        reason: "missing",
                    },
                    CompatMismatch::Unsupported => Error::BadSubstrateProperty {
                        node: "/ioapic",
                        prop: "compatible",
                        reason: "missing expected compatible",
                    },
                })?;
            let reg = node
                .remove_property("reg")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/ioapic",
                    prop: "reg",
                    reason: "missing",
                })?;
            let (base, size) = (&reg).reg_pair(0).ok_or(Error::BadSubstrateProperty {
                node: "/ioapic",
                prop: "reg",
                reason: "missing reg pair",
            })?;
            node.remove_property("#interrupt-cells")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/ioapic",
                    prop: "#interrupt-cells",
                    reason: "missing",
                })?;
            node.remove_property("interrupt-controller")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/ioapic",
                    prop: "interrupt-controller",
                    reason: "missing",
                })?;
            node.remove_property("phandle")
                .ok_or(Error::BadSubstrateProperty {
                    node: "/ioapic",
                    prop: "phandle",
                    reason: "missing",
                })?;
            if node.properties().next().is_some() || node.children().next().is_some() {
                return Err(Error::BadSubstrateProperty {
                    node: "/ioapic",
                    prop: "*",
                    reason: "unconsumed property or child",
                });
            }
            Ok(Some(Self {
                ioapic: IoApic::new(MmioWindow { base, size }),
            }))
        }
    }

    #[derive(Debug)]
    pub struct CpuPreparation {
        index: u32,
        profile: pmi::x86_64::Profile,
        machine: crate::hypervisor::Vm,
        mmio_bus: Arc<Mutex<MmioBus>>,
    }

    impl dillo_machine::CpuPreparation for CpuPreparation {
        type Error = Error;
        type Runner = CpuRunner;
        type Control = CpuControl;

        fn prepare(self) -> Result<(CpuRunner, CpuControl), Error> {
            let mut inner = self.machine.create_vcpu(self.index, self.profile)?;
            if self.index == 0
                && let Err(operation) = inner.initialize_bsp()
            {
                return Err(inner.cleanup_error(operation));
            }
            let target = Arc::new(StopTarget {
                requested: AtomicBool::new(false),
                cancel: Mutex::new(Some(inner.cancel_handle())),
            });
            Ok((
                CpuRunner {
                    inner,
                    mmio_bus: self.mmio_bus,
                    stop: Arc::clone(&target),
                },
                CpuControl(target),
            ))
        }
    }

    #[derive(Debug)]
    struct StopTarget {
        requested: AtomicBool,
        cancel: Mutex<Option<crate::hypervisor::VcpuCancel>>,
    }

    #[derive(Debug)]
    pub struct CpuControl(Arc<StopTarget>);

    impl dillo_machine::CpuControl for CpuControl {
        type Error = Error;

        fn stop(&self) -> Result<(), Self::Error> {
            self.0.requested.store(true, Ordering::Release);
            let cancel = self
                .0
                .cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cancel
                .as_ref()
                .map_or(Ok(()), crate::hypervisor::VcpuCancel::cancel)
        }
    }

    fn guest_memory_from_ranges(
        ranges: impl IntoIterator<Item = RamRange>,
    ) -> Result<GuestMemoryMmap, Error> {
        // Hyper-V TLFS defines 4 KiB GPA pages for x64.
        const PAGE_SIZE: u64 = 0x1000;
        let ranges: Vec<_> = ranges
            .into_iter()
            .map(|RamRange { gpa, size }| {
                if !gpa.is_multiple_of(PAGE_SIZE) || !size.is_multiple_of(PAGE_SIZE) {
                    return Err(Error::AddressSpace(format!(
                        "RAM base {gpa:#x} and size {size:#x} must be multiples of {PAGE_SIZE} bytes"
                    )));
                }
                Ok((GuestAddress(gpa), size as usize))
            })
            .collect::<Result<_, _>>()?;
        GuestMemoryMmap::from_ranges(&ranges).map_err(|e| Error::CreateGuestMemory(format!("{e}")))
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
                    "MMIO device requested {} fixed shared-memory requirement(s), but WHP attachment does not realize machine-mediated shared-memory capabilities yet",
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

    #[derive(Clone, Debug)]
    struct FixedInterruptRequester {
        interrupt_controller: InterruptController,
    }

    impl FixedInterruptRequester {
        fn request_fixed_interrupt(&self, destination: u32, vector: u8) -> Result<(), Error> {
            self.interrupt_controller
                .request_fixed_interrupt(destination, vector)
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct FixedMessage {
        address: u64,
        data: u32,
        masked: bool,
        enabled: bool,
    }

    #[derive(Debug)]
    struct FixedMessageInterruptDomain {
        inner: Arc<FixedMessageInterruptDomainInner>,
    }

    #[derive(Debug)]
    struct FixedMessageInterruptDomainInner {
        fixed_interrupts: FixedInterruptRequester,
        vectors: FixedMessageTable,
    }

    #[derive(Debug)]
    struct FixedMessageTable(Mutex<Vec<FixedMessage>>);

    impl FixedMessageInterruptDomain {
        fn new(fixed_interrupts: FixedInterruptRequester, count: u16) -> Self {
            Self {
                inner: Arc::new(FixedMessageInterruptDomainInner {
                    fixed_interrupts,
                    vectors: FixedMessageTable(Mutex::new(vec![
                        FixedMessage::default();
                        count as usize
                    ])),
                }),
            }
        }
    }

    impl FixedMessageTable {
        fn message_for(&self, vector: u16) -> Option<FixedMsi> {
            let vectors = self.0.lock().expect("message table poisoned");
            let message = *vectors.get(vector as usize)?;
            if !message.enabled || message.masked {
                return None;
            }
            decode_fixed_msi(message)
        }

        fn update(&self, vector: u16, msg: MessageInterrupt) {
            let mut vectors = self.0.lock().expect("message table poisoned");
            if let Some(slot) = vectors.get_mut(vector as usize) {
                *slot = FixedMessage {
                    address: msg.address,
                    data: msg.data,
                    masked: msg.masked,
                    enabled: slot.enabled,
                };
            }
        }

        fn enabled(&self, vector: u16, enabled: bool) {
            let mut vectors = self.0.lock().expect("message table poisoned");
            if let Some(slot) = vectors.get_mut(vector as usize) {
                slot.enabled = enabled;
            }
        }
    }

    impl MessageInterruptDomain for FixedMessageInterruptDomain {
        fn update(&self, vector: u16, msg: MessageInterrupt) -> Result<(), InterruptError> {
            self.inner.vectors.update(vector, msg);
            Ok(())
        }

        fn enabled(&self, vector: u16, enabled: bool) -> Result<(), InterruptError> {
            self.inner.vectors.enabled(vector, enabled);
            Ok(())
        }

        fn interrupt(&self, vector: u16) -> Option<Interrupt> {
            let domain = Arc::clone(&self.inner);
            Some(Interrupt::from_fn(move || {
                let Some(msi) = domain.vectors.message_for(vector) else {
                    return;
                };
                if let Err(e) = domain
                    .fixed_interrupts
                    .request_fixed_interrupt(msi.destination, msi.vector)
                {
                    log::warn!(
                        "WHP MSI inject failed for table vector {vector}, APIC destination {}, vector {:#x}: {e}",
                        msi.destination,
                        msi.vector,
                    );
                }
            }))
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FixedMsi {
        destination: u32,
        vector: u8,
    }

    fn decode_fixed_msi(message: FixedMessage) -> Option<FixedMsi> {
        const MSI_ADDR_BASE_MASK: u64 = 0xFFF0_0000;
        const MSI_ADDR_BASE: u64 = 0xFEE0_0000;
        const MSI_ADDR_DEST_SHIFT: u64 = 12;
        const MSI_ADDR_DEST_MASK: u64 = 0xFF;
        const MSI_ADDR_DEST_MODE_LOGICAL: u64 = 1 << 2;
        const MSI_DATA_VECTOR_MASK: u32 = 0xFF;
        const MSI_DATA_DELIVERY_MODE_MASK: u32 = 0x700;
        const MSI_DATA_DELIVERY_MODE_SHIFT: u32 = 8;
        const MSI_DATA_LEVEL_ASSERT: u32 = 1 << 14;
        const MSI_DATA_TRIGGER_LEVEL: u32 = 1 << 15;

        if (message.address & MSI_ADDR_BASE_MASK) != MSI_ADDR_BASE {
            log::warn!(
                "WHP MSI entry has non-local-APIC address {:#x}",
                message.address
            );
            return None;
        }
        // Fixed (0) and Lowest-Priority (1) both deliver a fixed vector; Linux
        // uses lowest-priority with a logical destination for MSI by default.
        let delivery = (message.data & MSI_DATA_DELIVERY_MODE_MASK) >> MSI_DATA_DELIVERY_MODE_SHIFT;
        if delivery != 0 && delivery != 1 {
            log::warn!(
                "WHP MSI entry uses unsupported delivery mode {delivery} data={:#x}",
                message.data
            );
            return None;
        }
        if message.data & (MSI_DATA_LEVEL_ASSERT | MSI_DATA_TRIGGER_LEVEL) != 0 {
            log::warn!(
                "WHP MSI entry uses unsupported level/trigger data={:#x}",
                message.data
            );
            return None;
        }

        let dest_field = ((message.address >> MSI_ADDR_DEST_SHIFT) & MSI_ADDR_DEST_MASK) as u32;
        let destination = if message.address & MSI_ADDR_DEST_MODE_LOGICAL != 0 {
            crate::ioapic::resolve_logical_destination(dest_field)
        } else {
            dest_field
        };

        Some(FixedMsi {
            destination,
            vector: (message.data & MSI_DATA_VECTOR_MASK) as u8,
        })
    }

    #[derive(Debug)]
    struct IoApicInterruptLine {
        interrupt_controller: InterruptController,
        ioapic: Arc<IoApic>,
        gsi: u32,
    }

    impl IoApicInterruptLine {
        fn new(interrupt_controller: InterruptController, ioapic: Arc<IoApic>, gsi: u32) -> Self {
            Self {
                interrupt_controller,
                ioapic,
                gsi,
            }
        }

        fn inject(&self) -> Result<(), InterruptError> {
            let Some(route) = self.ioapic.route(self.gsi) else {
                return Ok(());
            };
            self.interrupt_controller
                .request_fixed_interrupt(route.destination, route.vector)
                .map_err(|e| InterruptError::Delivery(e.to_string()))
        }
    }

    impl InterruptLine for IoApicInterruptLine {
        fn signal(&self) {
            if let Err(e) = self.inject() {
                log::warn!(
                    "WHP IOAPIC interrupt signal failed for GSI {}: {e}",
                    self.gsi
                );
            }
        }

        fn set_level(&self, level: bool) -> Result<(), InterruptError> {
            if level {
                self.inject()?;
            }
            Ok(())
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
    pub struct CpuRunner {
        inner: crate::hypervisor::Vcpu,
        mmio_bus: Arc<Mutex<MmioBus>>,
        stop: Arc<StopTarget>,
    }

    impl Drop for CpuRunner {
        fn drop(&mut self) {
            self.unbind_cancel();
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

    impl CpuRunner {
        fn unbind_cancel(&self) {
            // Serialize cancel against retirement before the VP index is deleted.
            self.stop
                .cancel
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }

        fn run_until_exit(&mut self) -> Result<VcpuExit, Error> {
            loop {
                let bus = Arc::clone(&self.mmio_bus);
                let exit = self.inner.run(
                    |_port, _size| u32::MAX,
                    move |addr, data| {
                        let handled = bus.lock().expect("MMIO bus lock poisoned").read(addr, data);
                        if !handled {
                            log::debug!(
                                "WHP MMIO read from unmapped {:#x} (size {}); returning zeros",
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
                                "WHP MMIO write to unmapped {:#x} (size {}, data {:02x?})",
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
    }

    impl dillo_machine::CpuRunner for CpuRunner {
        type Error = Error;

        fn retire(mut self) -> Result<(), Self::Error> {
            self.unbind_cancel();
            self.inner.retire()
        }

        fn run(&mut self) -> Result<VcpuStop, Error> {
            loop {
                if self.stop.requested.load(Ordering::Acquire) {
                    return Ok(VcpuStop::Stopped);
                }
                match self.run_until_exit()? {
                    VcpuExit::MmioWrite { .. } => {}
                    VcpuExit::Interrupted => return Ok(VcpuStop::Stopped),
                    VcpuExit::GuestPoweroff => return Ok(VcpuStop::GuestPoweroff),
                    VcpuExit::GuestReset => return Ok(VcpuStop::GuestReset),
                    VcpuExit::Shutdown => {
                        log::warn!("guest shutdown via WHP shutdown exit");
                        return Ok(VcpuStop::GuestPoweroff);
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            Error, FixedMessage, FixedMessageTable, FixedMsi, RamRange, decode_fixed_msi,
            guest_memory_from_ranges,
        };
        use dillo_mmio::MessageInterrupt;
        use std::sync::Mutex;

        #[test]
        fn guest_ram_requires_whole_pages_at_aligned_addresses() {
            for (gpa, size) in [(1, 0x1000), (0, 0x1001)] {
                let error = guest_memory_from_ranges([RamRange { gpa, size }]).unwrap_err();
                assert!(matches!(error, Error::AddressSpace(_)), "{error}");
            }
            guest_memory_from_ranges([RamRange {
                gpa: 0x1000,
                size: 0x1000,
            }])
            .unwrap();
        }

        #[test]
        fn message_vectors_keep_enable_and_mask_independent() {
            let domain = FixedMessageTable(Mutex::new(vec![FixedMessage::default(); 2]));
            let message = MessageInterrupt {
                address: 0xFEE0_3000,
                data: 0x45,
                masked: false,
            };
            let expected = Some(FixedMsi {
                destination: 3,
                vector: 0x45,
            });
            domain.update(0, message);
            domain.update(1, message);
            assert_eq!(domain.message_for(0), None);
            domain.enabled(0, true);
            domain.enabled(1, true);
            domain.enabled(0, false);
            assert_eq!(domain.message_for(0), None);
            assert_eq!(domain.message_for(1), expected);
            domain.enabled(1, false);
            domain.enabled(0, true);
            assert_eq!(domain.message_for(0), expected);
            assert_eq!(domain.message_for(1), None);
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
            assert_eq!(domain.message_for(1), expected);
            domain.update(0, message);
            assert_eq!(domain.message_for(0), expected);
        }

        #[test]
        fn decodes_fixed_physical_msi() {
            assert_eq!(
                decode_fixed_msi(FixedMessage {
                    address: 0xFEE0_3000,
                    data: 0x45,
                    masked: false,
                    enabled: true,
                }),
                Some(FixedMsi {
                    destination: 3,
                    vector: 0x45,
                })
            );
        }

        #[test]
        fn rejects_non_lapic_msi_address() {
            assert!(
                decode_fixed_msi(FixedMessage {
                    address: 0xDEAD_0000,
                    data: 0x45,
                    masked: false,
                    enabled: true,
                })
                .is_none()
            );
        }
    }
}

pub use imp::*;
