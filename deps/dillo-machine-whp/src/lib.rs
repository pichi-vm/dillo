// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

mod cpuid_x86;
mod hypervisor;
mod launch_input;

pub use launch_input::CapturedLaunchInput;
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
    };
    use dillo_machine::attachment::{Attach, DeviceAttachment};
    use dillo_machine::execution::{DeviceHandle, RunToken, SpawnError};
    use dillo_machine::interrupt::{
        Interrupt, InterruptError, InterruptLine, InterruptRequirement, InterruptResource,
        MessageInterrupt, MessageInterruptDomain,
    };
    use dillo_machine::memory::{AddressRange, SharedMemory};
    use dillo_machine::{Host, HostArchitecture, LaunchConfig, RamRange, VcpuStop};
    use dillo_mmio::{MmioBus, MmioDevice, MmioWriteOutcome};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    pub use crate::hypervisor::Error;
    use crate::hypervisor::InterruptController;
    use crate::ioapic::IoApic;
    use crate::{CapturedLaunchInput, VmExit};

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
        device_failures: dillo_machine::execution::DeviceFailureReporter,
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
        type LaunchInput = CapturedLaunchInput;

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
                device_failures: dillo_machine::execution::DeviceFailureReporter::default(),
                ioapic,
            })
        }

        fn set_memory(&mut self, memory: GuestMemoryMmap) -> Result<(), Error> {
            self.inner.set_memory(memory)
        }

        fn attach_guest_memory(&mut self, memory: GuestMemoryMmap) -> Result<(), Error> {
            self.set_memory(memory)?;
            let guest_mem = self.guest_memory()?;
            self.shared_memory = vec![Arc::new(
                dillo_machine::memory::MappedSharedMemory::for_guest_memory(
                    guest_mem,
                    dillo_machine::memory::SharedAccess::ReadWrite,
                ),
            )];
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

    #[derive(Debug, Clone)]
    struct Config {
        processor_count: u32,
        dtb: Vec<u8>,
    }

    impl TryFrom<Config> for Vm {
        type Error = Error;

        fn try_from(config: Config) -> Result<Self, Self::Error> {
            let parsed: Tree<'_> = Tree::parse(&config.dtb).map_err(Error::ParseDtb)?;
            let mut tree = OwnedTree::materialize(&parsed);
            let substrate = WhpX86Substrate::from_devtree(&mut tree)?
                .ok_or(Error::MissingSubstrate("/ioapic"))?;
            Self::new_x86_64(config.processor_count, Some(substrate.ioapic))
        }
    }

    impl dillo_machine::Machine for Vm {
        fn device_failures(&self) -> dillo_machine::execution::DeviceFailureObserver {
            self.device_failures.observer()
        }

        type Error = Error;
        type CpuPreparation = CpuPreparation;
        type Memory = Memory;

        fn cpu_preparation(
            &mut self,
            index: u32,
            cpu_profile: dillo_machine::CpuProfile,
        ) -> Result<CpuPreparation, Error> {
            if !matches!(cpu_profile, dillo_machine::CpuProfile::X86_64(_)) {
                return Err(Error::UnhandledExit(
                    "CPU profile architecture mismatch".into(),
                ));
            }
            Ok(CpuPreparation {
                index,
                cpu_profile,
                creator: self.inner.cpu_creator()?,
                mmio_bus: Arc::clone(&self.mmio_bus),
                interrupt: CpuInterrupt {
                    target: Arc::new(Mutex::new(None)),
                },
            })
        }

        fn guest_address_bits() -> Result<u32, Self::Error> {
            crate::hypervisor::guest_address_bits()
        }

        fn from_launch_config(config: LaunchConfig) -> Result<Self, Self::Error> {
            let vm = Self::try_from(Config {
                processor_count: config.vcpus,
                dtb: config.dtb,
            })?;
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
                ioapic: IoApic::new(AddressRange { base, size }),
            }))
        }
    }

    #[derive(Debug)]
    pub struct Memory {
        guest_memory: GuestMemoryMmap,
    }

    impl dillo_machine::Memory for Memory {
        type Error = Error;

        fn from_ranges(ranges: &[RamRange]) -> Result<Self, Self::Error> {
            Ok(Self {
                guest_memory: guest_memory_from_ranges(ranges.iter().copied())?,
            })
        }
    }

    impl Attach<Memory> for Vm {
        type Error = Error;
        type Output = ();

        fn attach(&mut self, item: Memory) -> Result<Self::Output, Self::Error> {
            self.attach_guest_memory(item.guest_memory)
        }
    }

    #[derive(Debug)]
    pub struct CpuPreparation {
        index: u32,
        cpu_profile: dillo_machine::CpuProfile,
        creator: crate::hypervisor::CpuCreator,
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
                inner: self.creator.create(self.index, self.cpu_profile.as_str())?,
                mmio_bus: self.mmio_bus,
            };
            if self.index == 0 {
                vcpu.initialize_bsp()?;
            }
            let binding = self.interrupt.bind(vcpu.inner.cancel_handle());
            Ok(CpuRunner {
                _binding: binding,
                vcpu,
                _owner: std::marker::PhantomData,
            })
        }
    }

    #[derive(Debug, Clone)]
    pub struct CpuInterrupt {
        target: Arc<Mutex<Option<crate::hypervisor::VcpuCancel>>>,
    }
    impl CpuInterrupt {
        fn bind(self, target: crate::hypervisor::VcpuCancel) -> InterruptBinding {
            *self
                .target
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(target);
            InterruptBinding { interrupt: self }
        }
    }
    impl dillo_machine::CpuInterrupt for CpuInterrupt {
        type Error = Error;
        fn interrupt(&self) -> Result<(), Error> {
            let target = self
                .target
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match target.as_ref() {
                Some(target) => target.cancel(),
                None => Ok(()),
            }
        }
    }
    #[derive(Debug)]
    struct InterruptBinding {
        interrupt: CpuInterrupt,
    }
    impl Drop for InterruptBinding {
        fn drop(&mut self) {
            self.interrupt
                .target
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    /// Native execution and destruction remain on the preparing thread.
    ///
    /// ```compile_fail
    /// fn move_owner(runner: dillo_machine_whp::CpuRunner) {
    ///     std::thread::spawn(move || drop(runner));
    /// }
    /// ```
    #[derive(Debug)]
    pub struct CpuRunner {
        // Drop clears the wake target under its call lock before native deletion.
        _binding: InterruptBinding,
        vcpu: Vcpu,
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

    fn guest_memory_from_ranges(
        ranges: impl IntoIterator<Item = RamRange>,
    ) -> Result<GuestMemoryMmap, Error> {
        let ranges: Vec<(GuestAddress, usize)> = ranges
            .into_iter()
            .map(|range| (GuestAddress(range.gpa), range.size as usize))
            .collect();
        GuestMemoryMmap::from_ranges(&ranges).map_err(|e| Error::CreateGuestMemory(format!("{e}")))
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
                    "MMIO device requested {} fixed shared-memory requirement(s), but WHP attachment does not realize machine-mediated shared-memory capabilities yet",
                    item.shared_memory().len()
                )));
            }
            let interrupts = self.resolve_interrupts(item.interrupts())?;
            let device_failures = self
                .device_failures
                .scoped(format!("MMIO {:?}", item.windows()));
            self.mmio_bus
                .lock()
                .expect("MMIO bus lock poisoned")
                .register_device(item);
            Ok(Arc::new(MachineMmioAttachment {
                interrupts,
                shared_memory: self.shared_memory.clone(),
                device_failures,
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
        interrupts: Vec<InterruptResource>,
        shared_memory: Vec<Arc<dyn SharedMemory>>,
        device_failures: dillo_machine::execution::DeviceFailureReporter,
    }

    impl std::fmt::Debug for MachineMmioAttachment {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MachineMmioAttachment")
                .field("interrupts", &self.interrupts.len())
                .field("shared_memory", &self.shared_memory.len())
                .field("device_failures", &self.device_failures)
                .finish()
        }
    }

    impl DeviceAttachment for MachineMmioAttachment {
        fn interrupts(&self) -> &[InterruptResource] {
            &self.interrupts
        }

        fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
            &self.shared_memory
        }

        fn spawn(
            self: Arc<Self>,
            name: String,
            run: dillo_machine::execution::DeviceRun,
        ) -> Result<DeviceHandle, SpawnError> {
            let shutdown = Arc::new(AtomicBool::new(false));
            let token_shutdown = Arc::clone(&shutdown);
            let token = RunToken::from_fn(move || token_shutdown.load(Ordering::Acquire));
            let reporter = self.device_failures.scoped(name);
            let worker_reporter = reporter.clone();
            let join = std::thread::Builder::new()
                .spawn(move || worker_reporter.run(run, token))
                .map_err(|error| {
                    reporter.report(dillo_machine::execution::JoinError::Spawn(
                        error.to_string(),
                    ));
                    SpawnError
                })?;
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
                                "WHP MMIO read from unmapped {:#x} (size {}); returning zeros",
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

        fn run_to_stop(
            &mut self,
            termination: &dyn dillo_machine::CpuTermination,
        ) -> Result<VcpuStop, Error> {
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
                        log::warn!("guest shutdown via WHP shutdown exit");
                        return Ok(VcpuStop::GuestPoweroff);
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod owner_tests {
        use super::*;
        use dillo_machine::{
            CpuInterrupt as _, CpuPreparation as _, CpuRunner as _, Machine as _, Memory as _,
        };
        use std::thread;

        #[test]
        fn attached_worker_failure_stops_native_cpus_and_preserves_retained_ram() {
            use dillo_machine::Machine as _;
            use dillo_machine::execution::JoinError;
            use dillo_machine::memory::{AddressRange, SharedAccess, SharedRange};
            use dillo_mmio::{MmioError, MmioWriteOutcome};
            use std::sync::mpsc;
            use std::time::Duration;

            struct WorkerEndpoint {
                window: [AddressRange; 1],
            }
            impl MmioDevice for WorkerEndpoint {
                fn windows(&self) -> &[AddressRange] {
                    &self.window
                }
                fn read(&self, _: AddressRange, _: u64, _: &mut [u8]) -> Result<(), MmioError> {
                    Err(MmioError::Unsupported)
                }
                fn write(
                    &self,
                    _: AddressRange,
                    _: u64,
                    _: &[u8],
                ) -> Result<MmioWriteOutcome, MmioError> {
                    Err(MmioError::Unsupported)
                }
            }

            let _guard = crate::hypervisor::whp_test_lock();
            if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
                crate::hypervisor::memory_tests::NativeMemoryTest::spawn("imp::owner_tests::attached_worker_failure_stops_native_cpus_and_preserves_retained_ram").verify();
                return;
            }
            for outcome in 0..6 {
                let mut vm = Vm::new_x86_64(2, None).expect("native WHP is required");
                let base = 0xffff_f000;
                vm.attach(
                    Memory::from_ranges(&[RamRange {
                        gpa: base,
                        size: 0x1000,
                    }])
                    .unwrap(),
                )
                .unwrap();
                let profile = dillo_machine::CpuProfile::X86_64(pmi::x86_64::Profile::V1);

                let observer = vm.device_failures();
                let probe = vm.inner.allocation_probe(0);
                let retained = vm.shared_memory[0]
                    .region(SharedRange {
                        gpa: base,
                        size: 0x1000,
                        access: SharedAccess::ReadWrite,
                    })
                    .unwrap();
                // PMI enters flat 32-bit protected mode. Store an aligned
                // dword in retained RAM, then spin without guest exits. This
                // fixture qualifies worker-failure cancellation, not WHP MMIO
                // instruction emulation in the fixed initial CPU state.
                vm.write_guest(
                    0xffff_fff0,
                    &[0xc7, 0x05, 0x80, 0xf0, 0xff, 0xff, 1, 0, 0, 0, 0xeb, 0xfe],
                )
                .unwrap();
                let progress = retained.clone();
                // Obtain the real machine-bound worker service; guest code
                // does not access this attachment's MMIO window.
                let attachment = vm
                    .attach(Arc::new(WorkerEndpoint {
                        window: [AddressRange {
                            base: 0x0b00_0000,
                            size: 0x1000,
                        }],
                    }))
                    .unwrap();
                let queue_memory: Arc<dyn dillo_virtio::QueueMemory> = Arc::new(
                    dillo_virtio::SharedQueueMemory::new(vm.shared_memory.clone()),
                );
                let worker = attachment
                    .spawn(
                        "native failing worker".into(),
                        Box::new(move |_| {
                            let deadline = std::time::Instant::now() + Duration::from_secs(3);
                            while progress.load_u32_le(0x80).map_err(|error| {
                                JoinError::Host(format!("guest progress missing: {error}"))
                            })? != 1
                            {
                                if std::time::Instant::now() >= deadline {
                                    return Err(JoinError::Host(
                                        "guest progress missing: timed out".into(),
                                    ));
                                }
                                thread::sleep(Duration::from_millis(1));
                            }
                            if outcome >= 2 {
                                let failed_write = outcome - 2;
                                let memory = dillo_virtio::test_support::FaultQueueMemory::new(
                                    queue_memory,
                                    failed_write,
                                );
                                let mut queue = dillo_virtio::queue::Queue::new(8);
                                queue.uses_notif_suppression = true;
                                queue.used_ring = vm_memory::GuestAddress(base + 0x200);
                                queue.next_avail = std::num::Wrapping(1);
                                let error = queue.add_used(&memory, 3, 4).unwrap_err();
                                assert_eq!(memory.attempts(), failed_write + 1);
                                assert_eq!(queue.next_used.0, u16::from(failed_write == 3));
                                assert_eq!(error.is_published(), failed_write == 3);
                                return Err(JoinError::Host(error.to_string()));
                            }
                            assert!(outcome != 1, "injected native attached worker panic");
                            Err(JoinError::Host(
                                "injected native attached worker error".into(),
                            ))
                        }),
                    )
                    .unwrap();
                let shutdown = Arc::new(AtomicBool::new(false));
                let rescue_shutdown = Arc::clone(&shutdown);
                let (done, completed) = mpsc::channel();
                let rescue = thread::spawn(move || {
                    let rescued = completed.recv_timeout(Duration::from_secs(5)).is_err();
                    if rescued {
                        rescue_shutdown.store(true, Ordering::Release);
                    }
                    rescued
                });
                let result = dillo_runtime::PreparingCpus::spawn(&mut vm, 2, profile)
                    .and_then(|cpus| cpus.prepare(shutdown.as_ref()))
                    .and_then(|cpus| cpus.run(shutdown.as_ref()));
                let _ = done.send(());
                let rescued = rescue.join().unwrap();
                let joined = worker.join();
                assert!(
                    !rescued,
                    "runtime required operator rescue after attached failure"
                );
                let error = result.unwrap_err().to_string();
                assert!(error.contains("native failing worker"), "{error}");
                assert!(!error.contains("guest progress missing"), "{error}");
                if outcome >= 2 {
                    assert!(error.contains("used-ring"), "{error}");
                    let failed_write = outcome - 2;
                    assert_eq!(
                        retained.load_u32_le(0x204).unwrap(),
                        if failed_write > 0 { 3 } else { 0 }
                    );
                    assert_eq!(
                        retained.load_u32_le(0x208).unwrap(),
                        if failed_write > 1 { 4 } else { 0 }
                    );
                    assert_eq!(
                        retained.load_u16_le(0x202).unwrap(),
                        u16::from(failed_write == 3)
                    );
                    assert_eq!(retained.load_u16_le(0x244).unwrap(), 0);
                }
                assert!(joined.is_err());
                assert!(observer.check().is_err());
                probe.assert_retained();
                drop(vm);
                probe.assert_retained();
                retained.write(0x80, b"retained").unwrap();
                let mut bytes = [0; 8];
                retained.read(0x80, &mut bytes).unwrap();
                assert_eq!(&bytes, b"retained");
                drop(retained);
                probe.assert_reclaimed();
            }
        }

        #[test]
        fn native_ram_exports_preserve_old_allocation_across_fresh_partitions() {
            use crate::hypervisor::memory_tests::NativeMemoryTest;
            use vm_memory::Bytes;
            let _guard = crate::hypervisor::whp_test_lock();
            if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
                NativeMemoryTest::spawn("imp::owner_tests::native_ram_exports_preserve_old_allocation_across_fresh_partitions").verify();
                return;
            }
            let mut vm = Vm::new_x86_64(1, None).expect("native WHP is required");
            vm.attach(
                Memory::from_ranges(&[RamRange {
                    gpa: 0x10000,
                    size: 0x1000,
                }])
                .unwrap(),
            )
            .unwrap();
            vm.write_guest(0x10100, &[0x11, 0x22]).unwrap();
            let original = vm.inner.allocation_probe(0);
            let export = vm.shared_memory[0]
                .region(dillo_machine::memory::SharedRange {
                    gpa: 0x10000,
                    size: 0x1000,
                    access: dillo_machine::memory::SharedAccess::ReadWrite,
                })
                .unwrap();
            drop(vm);
            original.assert_retained();
            let mut replacement = Vm::new_x86_64(1, None).unwrap();
            replacement
                .attach(
                    Memory::from_ranges(&[RamRange {
                        gpa: 0x10000,
                        size: 0x1000,
                    }])
                    .unwrap(),
                )
                .unwrap();
            replacement.write_guest(0x10100, &[0x33, 0x44]).unwrap();
            let fresh = replacement.inner.allocation_probe(0);
            let mut bytes = [0; 2];
            export.read(0x100, &mut bytes).unwrap();
            assert_eq!(bytes, [0x11, 0x22]);
            export.write(0x100, &[0x55, 0x66]).unwrap();
            replacement
                .guest_memory()
                .unwrap()
                .read_slice(&mut bytes, GuestAddress(0x10100))
                .unwrap();
            assert_eq!(bytes, [0x33, 0x44]);
            drop(export);
            original.assert_reclaimed();
            fresh.assert_retained();
            drop(replacement);
            fresh.assert_reclaimed();
        }

        #[test]
        fn native_preparation_runner_and_cancel_retain_registered_ram() {
            use crate::hypervisor::memory_tests::NativeMemoryTest;
            let _guard = crate::hypervisor::whp_test_lock();
            if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
                NativeMemoryTest::spawn(
                    "imp::owner_tests::native_preparation_runner_and_cancel_retain_registered_ram",
                )
                .verify();
                return;
            }
            let mut vm = Vm::new_x86_64(1, None).expect("native WHP is required");
            let profile = dillo_machine::CpuProfile::X86_64(pmi::x86_64::Profile::V1);
            assert!(matches!(
                vm.cpu_preparation(0, profile),
                Err(Error::MemoryNotReady)
            ));
            vm.attach(
                Memory::from_ranges(&[RamRange {
                    gpa: 0x10000,
                    size: 0x1000,
                }])
                .unwrap(),
            )
            .unwrap();
            // Native progress marker, followed by an infinite guest loop.
            vm.write_guest(0x10000, &[0xe6, 0x42, 0xeb, 0xfe]).unwrap();
            let original = vm.inner.allocation_probe(0);
            let input = vm.cpu_preparation(0, profile).unwrap();
            let interrupt = input.interrupt();
            drop(vm);
            original.assert_retained();
            let (progress, observed_progress) = std::sync::mpsc::channel();
            let (completed, observed_completion) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let termination = Arc::new(AtomicBool::new(false));
            thread::scope(|scope| {
                let token = Arc::clone(&termination);
                let worker = scope.spawn(move || {
                    let mut runner = input.prepare().unwrap();
                    runner
                        .vcpu
                        .inner
                        .initialize_test_real_mode(0x10000, 0x5a)
                        .unwrap();
                    let marker = runner
                        .vcpu
                        .inner
                        .run(|_, _| 0, |_, _| false, token.as_ref())
                        .unwrap();
                    assert!(
                        matches!(
                            marker,
                            VmExit::PioWrite {
                                port: 0x42,
                                data: [0x5a, ..],
                                size: 1
                            }
                        ),
                        "{marker:?}"
                    );
                    progress.send(()).unwrap();
                    let exit = runner
                        .vcpu
                        .inner
                        .run(|_, _| 0, |_, _| false, token.as_ref())
                        .unwrap();
                    assert!(matches!(exit, VmExit::Interrupted), "{exit:?}");
                    assert!(
                        !token.load(Ordering::Acquire),
                        "live cancellation must precede fallback termination"
                    );
                    completed.send(()).unwrap();
                    released
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                });
                let progress = observed_progress.recv_timeout(std::time::Duration::from_secs(5));
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut cancellation = None;
                let mut wake_error = None;
                // WHP only guarantees cancelling an active call. Repeated
                // native requests close the progress-marker/next-entry race.
                while progress.is_ok() && std::time::Instant::now() < deadline {
                    if let Err(error) = interrupt.interrupt() {
                        wake_error = Some(error);
                        break;
                    }
                    match observed_completion.recv_timeout(std::time::Duration::from_millis(1)) {
                        Ok(()) => {
                            cancellation = Some(());
                            break;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                if cancellation.is_some() {
                    original.assert_retained();
                    assert!(interrupt.target.lock().unwrap().is_some());
                }
                // Cleanup cannot turn a failed live-cancel assertion into a
                // pass. The receipt above was required while the token=false.
                termination.store(true, Ordering::Release);
                let _ = release.send(());
                let cleanup_deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !worker.is_finished() && std::time::Instant::now() < cleanup_deadline {
                    let _ = interrupt.interrupt();
                    std::thread::yield_now();
                }
                let result = worker.join();
                assert!(
                    progress.is_ok(),
                    "actual guest progress must precede cancellation: {progress:?}"
                );
                assert!(wake_error.is_none(), "native wake failed: {wake_error:?}");
                assert!(
                    cancellation.is_some(),
                    "live native cancellation must complete before fallback"
                );
                result.unwrap();
            });
            assert!(interrupt.target.lock().unwrap().is_none());
            interrupt.interrupt().expect("retired wake is harmless");
            original.assert_reclaimed();
        }

        #[test]
        fn native_line_and_msi_services_retain_their_partition_ram() {
            use crate::hypervisor::memory_tests::NativeMemoryTest;
            let _guard = crate::hypervisor::whp_test_lock();
            if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
                NativeMemoryTest::spawn(
                    "imp::owner_tests::native_line_and_msi_services_retain_their_partition_ram",
                )
                .verify();
                return;
            }
            let window = AddressRange {
                base: 0xfec0_0000,
                size: 0x1000,
            };
            let mut vm =
                Vm::new_x86_64(1, Some(IoApic::new(window))).expect("native WHP is required");
            vm.attach(
                Memory::from_ranges(&[RamRange {
                    gpa: 0x10000,
                    size: 0x1000,
                }])
                .unwrap(),
            )
            .unwrap();
            let original = vm.inner.allocation_probe(0);
            let ioapic = Arc::clone(vm.ioapic.as_ref().unwrap());
            ioapic.write(window, 0, &0x10u32.to_le_bytes()).unwrap();
            ioapic.write(window, 0x10, &0x40u32.to_le_bytes()).unwrap();
            let line = vm.create_line_interrupt(0).unwrap();
            let cpu = vm.inner.create_vcpu(0, "x86-64-v1").unwrap();
            drop(vm);
            line.set_level(true)
                .expect("native interrupt uses original partition");
            drop(cpu);
            original.assert_retained();
            drop(line);
            original.assert_reclaimed();

            let mut vm = Vm::new_x86_64(1, None).unwrap();
            vm.attach(
                Memory::from_ranges(&[RamRange {
                    gpa: 0x10000,
                    size: 0x1000,
                }])
                .unwrap(),
            )
            .unwrap();
            let original = vm.inner.allocation_probe(0);
            let domain = FixedMessageInterruptDomain::new(vm.fixed_interrupt_requester(), 1);
            domain
                .update(
                    0,
                    MessageInterrupt {
                        address: 0xfee0_0000,
                        data: 0x41,
                        masked: false,
                    },
                )
                .unwrap();
            domain.enabled(0, true).unwrap();
            let msi = domain.interrupt(0).unwrap();
            let cpu = vm.inner.create_vcpu(0, "x86-64-v1").unwrap();
            drop(vm);
            domain
                .inner
                .fixed_interrupts
                .request_fixed_interrupt(0, 0x41)
                .expect("native MSI requester uses original partition");
            drop(domain);
            msi.signal();
            drop(cpu);
            original.assert_retained();
            drop(msi);
            original.assert_reclaimed();
        }

        #[test]
        fn native_owner_wake_binding_retires_before_processor_replacement() {
            // Share the existing native fixture guard through all owner joins
            // and VM teardown, matching the hypervisor's other native tests.
            let _guard = crate::hypervisor::whp_test_lock();
            let mut vm = Vm::new_x86_64(2, None).expect("native WHP is required");
            vm.attach(
                Memory::from_ranges(&[RamRange {
                    gpa: 0xffff_f000,
                    size: 0x1000,
                }])
                .unwrap(),
            )
            .unwrap();
            vm.write_guest(0xffff_fff0, &[0xeb, 0xfe]).unwrap();
            let profile = dillo_machine::CpuProfile::X86_64(pmi::x86_64::Profile::V1);
            let input = vm.cpu_preparation(0, profile).unwrap();
            let interrupt = input.interrupt();
            let termination = Arc::new(AtomicBool::new(false));
            let token = Arc::clone(&termination);
            let (ready, receiver) = std::sync::mpsc::channel();
            let join = thread::spawn(move || {
                let mut runner = input.prepare().unwrap();
                ready.send(()).unwrap();
                runner.run(token.as_ref())
            });
            let ready = receiver.recv_timeout(std::time::Duration::from_secs(2));
            interrupt.interrupt().unwrap();
            thread::sleep(std::time::Duration::from_millis(20));
            let pure_wake_preserved_owner = !join.is_finished();
            termination.store(true, Ordering::Release);
            while !join.is_finished() {
                interrupt.interrupt().unwrap();
                thread::sleep(std::time::Duration::from_millis(1));
            }
            assert_eq!(join.join().unwrap().unwrap(), VcpuStop::Stopped);
            assert!(ready.is_ok(), "owner preparation must publish readiness");
            assert!(
                pure_wake_preserved_owner,
                "native cancel is a wake, not a termination request"
            );
            assert!(interrupt.target.lock().unwrap().is_none());
            // Reuse the native processor index. The retired endpoint must never
            // cancel the replacement owner, even while that owner exists.
            let input = vm.cpu_preparation(0, profile).unwrap();
            let replacement_interrupt = input.interrupt();
            thread::spawn(move || {
                let _runner = input.prepare().unwrap();
                interrupt.interrupt().unwrap();
            })
            .join()
            .unwrap();
            assert!(replacement_interrupt.target.lock().unwrap().is_none());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{FixedMessage, FixedMessageTable, FixedMsi, decode_fixed_msi};
        use dillo_machine::interrupt::MessageInterrupt;
        use std::sync::Mutex;

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
