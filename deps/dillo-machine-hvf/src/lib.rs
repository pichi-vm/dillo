// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

mod hypervisor;
mod launch_input;
mod memory;

pub use launch_input::CapturedLaunchInput;

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
    Interrupted,
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
        CompatMismatch, FromDevTree, NodeExt, OwnedNodeExt, PropExt,
        devtree::{OwnedTree, Tree},
    };
    use dillo_machine::attachment::{Attach, DeviceAttachment};
    use dillo_machine::execution::{DeviceHandle, RunToken, SpawnError};
    use dillo_machine::interrupt::{
        Interrupt, InterruptError, InterruptLine, InterruptRequirement, InterruptResource,
        MessageInterrupt, MessageInterruptDomain,
    };
    use dillo_machine::memory::SharedMemory;
    use dillo_machine::{Host, HostArchitecture, LaunchConfig, RamRange, VcpuStop};
    use dillo_mmio::{MmioBus, MmioDevice, MmioWriteOutcome};

    use crate::VcpuHandle;
    pub use crate::hypervisor::Error;
    use crate::{CapturedLaunchInput, VmExit};

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
        cpu_power: Arc<CpuPower>,
        shared_memory: Vec<Arc<dyn SharedMemory>>,
        device_failures: dillo_machine::execution::DeviceFailureReporter,
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
            let maximum = crate::hypervisor::Vcpu::max_count()?;
            if vcpus == 0 || vcpus > maximum {
                return Err(Error::Hv(format!(
                    "requested {vcpus} CPUs; HVF supports 1..={maximum}"
                )));
            }
            Ok(Self {
                inner: crate::hypervisor::Vm::new(gic, min_addr_space_bits)?,
                mmio_bus: Arc::new(Mutex::new(MmioBus::new())),
                cpu_power: Arc::new(CpuPower::new(vcpus)),
                shared_memory: Vec::new(),
                device_failures: dillo_machine::execution::DeviceFailureReporter::default(),
            })
        }

        fn mmio_bus(&self) -> Arc<Mutex<MmioBus>> {
            Arc::clone(&self.mmio_bus)
        }

        fn cpu_power(&self) -> Arc<CpuPower> {
            Arc::clone(&self.cpu_power)
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
                        Ok(InterruptResource::Line(self.create_line_interrupt(irq)))
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
                native: self.inner.cpu_instance(),
            }))
        }

        fn create_message_interrupt_domain(&self, vectors: u16) -> Arc<dyn MessageInterruptDomain> {
            Arc::new(GicMessageInterruptDomain::new(
                vectors,
                self.inner.cpu_instance(),
            ))
        }
    }

    impl Host for Vm {
        type RawStdioGuard = RawStdio;
        type LaunchInput = CapturedLaunchInput;

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
        native: crate::hypervisor::NativeVm,
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
            self.native
                .set_spi(self.intid, level)
                .map_err(|e| InterruptError::Delivery(e.to_string()))
        }
    }

    #[derive(Debug)]
    struct GicMessageInterruptDomain {
        inner: Arc<GicMessageInterruptDomainInner>,
    }

    #[derive(Debug, Clone, Copy)]
    struct GicMessage {
        message: MessageInterrupt,
        enabled: bool,
    }

    #[derive(Debug)]
    struct GicMessageInterruptDomainInner {
        native: crate::hypervisor::NativeVm,
        vectors: Mutex<Vec<GicMessage>>,
    }

    impl GicMessageInterruptDomain {
        fn new(count: u16, native: crate::hypervisor::NativeVm) -> Self {
            Self {
                inner: Arc::new(GicMessageInterruptDomainInner {
                    native,
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
                }),
            }
        }
    }

    impl GicMessageInterruptDomainInner {
        fn message_for(&self, vector: u16) -> Option<MessageInterrupt> {
            let slot = *self
                .vectors
                .lock()
                .expect("message interrupt domain poisoned")
                .get(vector as usize)?;
            (slot.enabled && !slot.message.masked).then_some(slot.message)
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
                slot.message = msg;
            }
            Ok(())
        }

        fn enabled(&self, vector: u16, enabled: bool) -> Result<(), InterruptError> {
            let mut vectors = self
                .inner
                .vectors
                .lock()
                .expect("message interrupt domain poisoned");
            if let Some(slot) = vectors.get_mut(vector as usize) {
                slot.enabled = enabled;
            }
            Ok(())
        }

        fn interrupt(&self, vector: u16) -> Option<Interrupt> {
            let domain = Arc::clone(&self.inner);
            Some(Interrupt::from_fn(move || {
                let Some(message) = domain.message_for(vector) else {
                    return;
                };
                if let Err(e) = domain.native.send_msi(message.address, message.data) {
                    log::warn!("HVF message interrupt inject (vector {vector}) failed: {e}");
                }
            }))
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
            profile: dillo_machine::CpuProfile,
        ) -> Result<Self::CpuPreparation, Self::Error> {
            let dillo_machine::CpuProfile::Aarch64(profile) = profile else {
                return Err(Error::Hv("CPU profile architecture mismatch".into()));
            };
            self.inner.cpu_instance().require_ram()?;
            let index = index as usize;
            let slot = self.cpu_power.slots.get(index).ok_or_else(|| {
                Error::Hv(format!("CPU index {index} exceeds declared CPU count"))
            })?;
            if slot.bound.swap(true, Ordering::AcqRel) {
                return Err(Error::Hv(format!("CPU index {index} already has an owner")));
            }
            let native = self.inner.cpu_instance();
            Ok(CpuPreparation {
                index,
                profile,
                native: native.clone(),
                mmio_bus: self.mmio_bus(),
                power: self.cpu_power(),
                interrupt: CpuInterrupt {
                    target: Arc::new(WakeTarget {
                        native,
                        handle: Mutex::new(None),
                        slot: Arc::clone(slot),
                    }),
                },
            })
        }

        fn guest_address_bits() -> Result<u32, Self::Error> {
            crate::hypervisor::guest_address_bits()
        }

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

        fn zero_guest(&mut self, mut gpa: u64, mut len: u64) -> Result<(), Self::Error> {
            gpa.checked_add(len)
                .ok_or_else(|| Error::Hv("guest zero range overflows".into()))?;
            let zeros = [0u8; 4096];
            while len > 0 {
                let count = len.min(zeros.len() as u64) as usize;
                <Self as dillo_machine::Machine>::write_guest(self, gpa, &zeros[..count])?;
                gpa += count as u64;
                len -= count as u64;
            }
            Ok(())
        }

        fn reset_for_reboot(&mut self) -> Result<(), Self::Error> {
            self.inner.reset_gic()?;
            // The shared owner runtime has joined every old CPU before this
            // existing warm-reset hook. Do not inherit an old CPU_ON request.
            self.cpu_power = Arc::new(CpuPower::new(self.cpu_power.slots.len() as u32));
            Ok(())
        }
    }

    /// Allocated RAM is consumed by attachment to exactly one native machine.
    #[derive(Debug)]
    pub struct Memory {
        backing: Arc<crate::memory::MappedMemory>,
    }

    impl dillo_machine::Memory for Memory {
        type Error = Error;

        fn from_ranges(ranges: &[RamRange]) -> Result<Self, Self::Error> {
            Ok(Self {
                backing: Arc::new(crate::memory::MappedMemory::new(ranges)?),
            })
        }
    }

    impl Attach<Memory> for Vm {
        type Error = Error;
        type Output = ();

        fn attach(&mut self, item: Memory) -> Result<Self::Output, Self::Error> {
            self.inner.attach(item.backing)?;
            let guest_mem = self.inner.guest_memory()?;
            self.shared_memory = vec![Arc::new(
                dillo_machine::memory::MappedSharedMemory::for_guest_memory(
                    guest_mem,
                    dillo_machine::memory::SharedAccess::ReadWrite,
                ),
            )];
            Ok(())
        }
    }

    /// Machine-bound input; every native affine object is created by prepare.
    #[derive(Debug)]
    pub struct CpuPreparation {
        index: usize,
        profile: pmi::aarch64::Profile,
        native: crate::hypervisor::NativeVm,
        mmio_bus: Arc<Mutex<MmioBus>>,
        power: Arc<CpuPower>,
        interrupt: CpuInterrupt,
    }

    impl dillo_machine::CpuPreparation for CpuPreparation {
        type Error = Error;
        type Interrupt = CpuInterrupt;
        type Runner = CpuRunner;

        fn interrupt(&self) -> Self::Interrupt {
            self.interrupt.clone()
        }

        fn prepare(self) -> Result<Self::Runner, Self::Error> {
            let vcpu = Vcpu {
                inner: crate::hypervisor::Vcpu::prepare(&self.native, self.profile)?,
                mmio_bus: self.mmio_bus,
            };
            vcpu.inner.prepare_affinity(mpidr_for(self.index))?;
            if self.index == 0 {
                vcpu.initialize_bsp()?;
                self.power.slots[0].started.store(true, Ordering::Release);
            }
            // Publish only a narrow wake target after preparation succeeds.
            // CPU existence never grants a secondary permission to run.
            let binding = CpuBinding::new(self.interrupt, vcpu.handle());
            Ok(CpuRunner {
                _binding: binding,
                vcpu,
                index: self.index,
                power: self.power,
            })
        }
    }

    #[derive(Debug)]
    struct WakeTarget {
        native: crate::hypervisor::NativeVm,
        handle: Mutex<Option<VcpuHandle>>,
        slot: Arc<CpuSlot>,
    }

    /// A pure wake endpoint. The shared runtime owns termination intent.
    #[derive(Debug, Clone)]
    pub struct CpuInterrupt {
        target: Arc<WakeTarget>,
    }

    impl dillo_machine::CpuInterrupt for CpuInterrupt {
        type Error = Error;

        fn interrupt(&self) -> Result<(), Self::Error> {
            {
                // Serialize with the mailbox's check-and-wait transition so a
                // termination kick cannot be lost just before an AP parks.
                let _mailbox = self
                    .target
                    .slot
                    .request
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.target.slot.cv.notify_all();
            }
            // Hold this lock through the native wake. Retirement takes the
            // same lock before native destruction, so no stale handle escapes.
            let handle = self
                .target
                .handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(handle) = handle.as_ref() {
                self.target
                    .native
                    .vcpus_exit(std::slice::from_ref(handle))?;
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct CpuBinding {
        interrupt: CpuInterrupt,
    }

    impl CpuBinding {
        fn new(interrupt: CpuInterrupt, handle: VcpuHandle) -> Self {
            *interrupt
                .target
                .handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
            Self { interrupt }
        }
    }

    impl Drop for CpuBinding {
        fn drop(&mut self) {
            *self
                .interrupt
                .target
                .handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }

    /// Native creation, entry and destruction all remain on this owner thread.
    #[derive(Debug)]
    pub struct CpuRunner {
        // Declaration order is intentional: invalidate the wake target before
        // applevisor destroys the affine native CPU, even during unwinding.
        _binding: CpuBinding,
        vcpu: Vcpu,
        index: usize,
        power: Arc<CpuPower>,
    }

    impl dillo_machine::CpuRunner for CpuRunner {
        type Error = Error;

        fn run(
            &mut self,
            termination: &dyn dillo_machine::CpuTermination,
        ) -> Result<VcpuStop, Self::Error> {
            if termination.is_requested() {
                return Ok(VcpuStop::Stopped);
            }
            if self.index != 0 {
                match self.power.slots[self.index].wait(termination) {
                    Some((entry, context)) => self.vcpu.initialize_secondary(entry, context)?,
                    None => return Ok(VcpuStop::Stopped),
                }
                log::info!("vCPU{} powered on by guest", self.index);
            }
            self.power
                .run_vcpu_loop(self.index, &self.vcpu, termination)
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
                return Err(Error::Hv(format!(
                    "MMIO device requested {} fixed shared-memory requirement(s), but HVF attachment does not realize machine-mediated shared-memory capabilities yet",
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

    #[derive(Debug)]
    struct Vcpu {
        inner: crate::hypervisor::Vcpu,
        mmio_bus: Arc<Mutex<MmioBus>>,
    }

    impl Vcpu {
        fn initialize_bsp(&self) -> Result<(), Error> {
            self.inner.initialize_bsp()
        }
        fn initialize_secondary(&self, entry: u64, context: u64) -> Result<(), Error> {
            self.inner.initialize_secondary(entry, context)
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

        fn run(&self, termination: &dyn dillo_machine::CpuTermination) -> Result<VmExit, Error> {
            loop {
                if termination.is_requested() {
                    return Ok(VmExit::Interrupted);
                }
                match self.inner.run(termination)? {
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

    /// Guest PSCI power state only; shared runtime owns worker supervision.
    #[derive(Debug)]
    struct CpuPower {
        slots: Vec<Arc<CpuSlot>>,
    }

    impl CpuPower {
        fn new(vcpus: u32) -> Self {
            Self {
                slots: (0..vcpus).map(|_| Arc::new(CpuSlot::new())).collect(),
            }
        }

        fn run_vcpu_loop(
            &self,
            idx: usize,
            vcpu: &Vcpu,
            termination: &dyn dillo_machine::CpuTermination,
        ) -> Result<VcpuStop, Error> {
            loop {
                if termination.is_requested() {
                    return Ok(VcpuStop::Stopped);
                }
                match vcpu.run(termination)? {
                    VmExit::MmioRead { .. } | VmExit::MmioWrite { .. } | VmExit::Interrupted => {}
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
                            match self.slots[idx].wait(termination) {
                                Some((entry, context)) => {
                                    vcpu.initialize_secondary(entry, context)?;
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
    }

    /// Per-vCPU power-on mailbox. A parked secondary waits here until another
    /// core's PSCI `CPU_ON` deposits a target entry point and context.
    #[derive(Debug)]
    struct CpuSlot {
        bound: AtomicBool,
        started: AtomicBool,
        request: Mutex<Option<(u64, u64)>>,
        cv: Condvar,
    }

    impl CpuSlot {
        fn new() -> Self {
            Self {
                bound: AtomicBool::new(false),
                started: AtomicBool::new(false),
                request: Mutex::new(None),
                cv: Condvar::new(),
            }
        }

        fn deposit(&self, entry: u64, context: u64) {
            *self.request.lock().expect("cpu-slot poisoned") = Some((entry, context));
            self.cv.notify_all();
        }

        fn wait(&self, termination: &dyn dillo_machine::CpuTermination) -> Option<(u64, u64)> {
            let mut g = self.request.lock().expect("cpu-slot poisoned");
            loop {
                if termination.is_requested() {
                    return None;
                }
                if let Some(req) = g.take() {
                    return Some(req);
                }
                let (ng, _) = self
                    .cv
                    .wait_timeout(g, std::time::Duration::from_millis(100))
                    .expect("cpu-slot poisoned");
                g = ng;
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
    mod tests {
        use std::sync::Arc;
        use std::thread;

        use super::*;
        use vm_memory::{Bytes, GuestAddress};

        #[test]
        fn attached_worker_failure_stops_native_cpus_and_preserves_retained_ram() {
            use dillo_machine::Machine as _;
            use dillo_machine::execution::JoinError;
            use dillo_machine::memory::{AddressRange, SharedAccess, SharedRange};
            use dillo_mmio::{MmioError, MmioWriteOutcome};
            use std::sync::mpsc;
            use std::time::Duration;

            struct Progress {
                window: [AddressRange; 1],
                entered: mpsc::Sender<()>,
            }
            impl MmioDevice for Progress {
                fn windows(&self) -> &[AddressRange] {
                    &self.window
                }
                fn read(&self, _: AddressRange, _: u64, data: &mut [u8]) -> Result<(), MmioError> {
                    data.fill(0);
                    Ok(())
                }
                fn write(
                    &self,
                    _: AddressRange,
                    _: u64,
                    _: &[u8],
                ) -> Result<MmioWriteOutcome, MmioError> {
                    let _ = self.entered.send(());
                    Ok(MmioWriteOutcome::Continue)
                }
            }

            if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
                crate::hypervisor::tests::SignedNativeTest::spawn("imp::tests::attached_worker_failure_stops_native_cpus_and_preserves_retained_ram").verify();
                return;
            }
            for outcome in 0..6 {
                let gic = crate::hypervisor::GicParams {
                    dist_base: 0x0800_0000,
                    redist_base: 0x0810_0000,
                    msi_base: 0x0a10_0000,
                    msi_intid_base: 64,
                    msi_intid_count: 32,
                };
                let mut vm = Vm::new(&gic, 36, 2).expect("native HVF/GIC is required");
                vm.attach(
                    <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                        gpa: 0,
                        size: 0x4000,
                    }])
                    .unwrap(),
                )
                .unwrap();
                let profile = dillo_machine::CpuProfile::Aarch64(pmi::aarch64::Profile::V8_0);
                let base = 0;

                let observer = vm.device_failures();
                let probe = vm.inner.mapping_probe(0);
                let retained = vm.shared_memory[0]
                    .region(SharedRange {
                        gpa: base,
                        size: 0x1000,
                        access: SharedAccess::ReadWrite,
                    })
                    .unwrap();
                // Write an actual MMIO progress marker, then spin without guest exits.
                vm.write_guest(
                    0,
                    &[0xd2a1_6000u32, 0x5280_0021, 0xb900_0001, 0x1400_0000]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                let (entered, progress) = mpsc::channel();
                let attachment = vm
                    .attach(Arc::new(Progress {
                        window: [AddressRange {
                            base: 0x0b00_0000,
                            size: 0x1000,
                        }],
                        entered,
                    }))
                    .unwrap();
                let queue_memory: Arc<dyn dillo_virtio::QueueMemory> = Arc::new(
                    dillo_virtio::SharedQueueMemory::new(vm.shared_memory.clone()),
                );
                let worker = attachment
                    .spawn(
                        "native failing worker".into(),
                        Box::new(move |_| {
                            progress
                                .recv_timeout(Duration::from_secs(3))
                                .map_err(|error| {
                                    JoinError::Host(format!("guest progress missing: {error}"))
                                })?;
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
                assert!(probe.is_mapped());
                drop(vm);
                assert!(
                    probe.is_mapped(),
                    "export retains original RAM after CPU and device retirement"
                );
                retained.write(0x80, b"retained").unwrap();
                let mut bytes = [0; 8];
                retained.read(0x80, &mut bytes).unwrap();
                assert_eq!(&bytes, b"retained");
                drop(retained);
                assert!(!probe.is_mapped(), "failure observer does not retain RAM");
            }
        }

        #[test]
        fn hvf_host_exports_outlive_retirement_without_retargeting() {
            use dillo_machine::Machine as _;
            use vm_memory::{GuestMemory as _, VolatileMemory as _};
            if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
                crate::hypervisor::tests::SignedNativeTest::spawn(
                    "imp::tests::hvf_host_exports_outlive_retirement_without_retargeting",
                )
                .verify();
                return;
            }
            let gic = crate::hypervisor::GicParams {
                dist_base: 0x0800_0000,
                redist_base: 0x0810_0000,
                msi_base: 0x0a10_0000,
                msi_intid_base: 64,
                msi_intid_count: 32,
            };
            let mut vm = Vm::new(&gic, 36, 1).unwrap();
            vm.attach(
                <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                    gpa: 0,
                    size: 0x4000,
                }])
                .unwrap(),
            )
            .unwrap();
            let probe = vm.inner.mapping_probe(0);
            let alias = probe.alias();
            assert_ne!(
                alias.as_ptr(),
                vm.inner
                    .guest_memory()
                    .unwrap()
                    .iter()
                    .next()
                    .unwrap()
                    .as_ptr(),
                "scalar observation uses an independent host mapping"
            );
            let export = vm.shared_memory[0]
                .region(dillo_machine::memory::SharedRange {
                    gpa: 0,
                    size: 0x4000,
                    access: dillo_machine::memory::SharedAccess::ReadWrite,
                })
                .unwrap();
            vm.write_guest(8, &[0x11, 0x22]).unwrap();
            drop(vm);
            assert!(
                probe.is_mapped(),
                "host export retains original allocation after native retirement"
            );
            let mut replacement =
                Vm::new(&gic, 36, 1).expect("successful retirement reopens process slot");
            replacement
                .attach(
                    <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                        gpa: 0,
                        size: 0x4000,
                    }])
                    .unwrap(),
                )
                .unwrap();
            let replacement_probe = replacement.inner.mapping_probe(0);
            replacement.write_guest(8, &[0x33, 0x44]).unwrap();
            let mut bytes = [0; 2];
            export.read(8, &mut bytes).unwrap();
            assert_eq!(bytes, [0x11, 0x22]);
            export.write(8, &[0x55, 0x66]).unwrap();
            replacement
                .inner
                .guest_memory()
                .unwrap()
                .read_slice(&mut bytes, GuestAddress(8))
                .unwrap();
            assert_eq!(
                bytes,
                [0x33, 0x44],
                "old export never retargets a replacement VM"
            );
            // These accesses still address the retired VM's original shared
            // object while a replacement VM is alive at the same GPAs.
            let independent = alias.as_volatile_slice();
            export.store_u16_le(0x20, 0x00ff).unwrap();
            export.store_u32_le(0x24, 0x89ab_cdef).unwrap();
            assert_eq!(
                u16::from_le(independent.load(0x20, Ordering::Relaxed).unwrap()),
                0x00ff
            );
            assert_eq!(
                u32::from_le(independent.load(0x24, Ordering::Relaxed).unwrap()),
                0x89ab_cdef
            );
            independent
                .store(0x0100u16.to_le(), 0x20, Ordering::Relaxed)
                .unwrap();
            independent
                .store(0x0123_4567u32.to_le(), 0x24, Ordering::Relaxed)
                .unwrap();
            independent
                .store(0x8877_6655_4433_2211u64.to_le(), 0x30, Ordering::Relaxed)
                .unwrap();
            assert_eq!(export.load_u16_le(0x20).unwrap(), 0x0100);
            assert_eq!(export.load_u32_le(0x24).unwrap(), 0x0123_4567);
            assert_eq!(export.load_u64_le(0x30).unwrap(), 0x8877_6655_4433_2211);
            drop(export);
            assert!(!probe.is_mapped());
            assert!(replacement_probe.is_mapped());
            drop(replacement);
            assert!(!replacement_probe.is_mapped());
        }

        #[test]
        fn hvf_native_services_retain_their_original_vm() {
            if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
                crate::hypervisor::tests::SignedNativeTest::spawn(
                    "imp::tests::hvf_native_services_retain_their_original_vm",
                )
                .verify();
                return;
            }
            let gic = crate::hypervisor::GicParams {
                dist_base: 0x0800_0000,
                redist_base: 0x0810_0000,
                msi_base: 0x0a10_0000,
                msi_intid_base: 64,
                msi_intid_count: 32,
            };
            let mut vm = Vm::new(&gic, 36, 1).unwrap();
            vm.attach(
                <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                    gpa: 0,
                    size: 0x4000,
                }])
                .unwrap(),
            )
            .unwrap();
            let probe = vm.inner.mapping_probe(0);
            let spi = vm.create_line_interrupt(8);
            drop(vm);
            assert!(Vm::new(&gic, 36, 1).is_err());
            assert!(probe.is_mapped());
            spi.set_level(true).unwrap();
            spi.set_level(false).unwrap();
            drop(spi);

            assert!(!probe.is_mapped());

            let mut vm = Vm::new(&gic, 36, 1).unwrap();
            vm.attach(
                <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                    gpa: 0,
                    size: 0x4000,
                }])
                .unwrap(),
            )
            .unwrap();
            let probe = vm.inner.mapping_probe(0);
            let domain = GicMessageInterruptDomain::new(1, vm.inner.cpu_instance());
            domain
                .update(
                    0,
                    MessageInterrupt {
                        address: gic.msi_base,
                        data: 64,
                        masked: false,
                    },
                )
                .unwrap();
            domain.enabled(0, true).unwrap();
            let msi = domain.interrupt(0).unwrap();
            drop(domain);
            drop(vm);
            assert!(
                Vm::new(&gic, 36, 1).is_err(),
                "MSI closure alone retains native VM authority"
            );
            assert!(probe.is_mapped());
            msi.signal();
            drop(msi);
            assert!(!probe.is_mapped());
            drop(Vm::new(&gic, 36, 1).unwrap());
        }

        #[test]
        fn hvf_preparation_runner_and_wake_own_registered_ram() {
            use dillo_machine::{CpuPreparation as _, CpuRunner as _, Machine as _};
            if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
                crate::hypervisor::tests::SignedNativeTest::spawn(
                    "imp::tests::hvf_preparation_runner_and_wake_own_registered_ram",
                )
                .verify();
                return;
            }
            let gic = crate::hypervisor::GicParams {
                dist_base: 0x0800_0000,
                redist_base: 0x0810_0000,
                msi_base: 0x0a10_0000,
                msi_intid_base: 64,
                msi_intid_count: 32,
            };
            let mut vm = Vm::new(&gic, 36, 1).unwrap();
            let profile = dillo_machine::CpuProfile::Aarch64(pmi::aarch64::Profile::V8_0);
            assert!(
                vm.cpu_preparation(0, profile).is_err(),
                "RAM absence must not reserve a CPU slot"
            );
            vm.attach(
                <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                    gpa: 0,
                    size: 0x4000,
                }])
                .unwrap(),
            )
            .unwrap();
            let probe = vm.inner.mapping_probe(0);
            let preparation = vm.cpu_preparation(0, profile).unwrap();
            drop(vm);
            assert!(probe.is_mapped());
            assert!(
                Vm::new(&gic, 36, 1).is_err(),
                "unconsumed preparation alone owns native context"
            );
            let (ready, prepared) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let owner = thread::spawn(move || {
                let mut runner = preparation
                    .prepare()
                    .expect("standalone preparation retains actual RAM");
                ready.send(()).unwrap();
                released.recv().unwrap();
                assert_eq!(
                    runner.run(&AtomicBool::new(true)).unwrap(),
                    VcpuStop::Stopped
                );
            });
            prepared.recv().unwrap();
            let mapped = probe.is_mapped();
            let busy = Vm::new(&gic, 36, 1).is_err();
            release.send(()).unwrap();
            owner.join().unwrap();
            assert!(
                mapped && busy,
                "prepared native runner retains actual registration until owner-thread destruction"
            );
            assert!(!probe.is_mapped());

            let mut vm = Vm::new(&gic, 36, 1).unwrap();
            vm.attach(
                <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                    gpa: 0,
                    size: 0x4000,
                }])
                .unwrap(),
            )
            .unwrap();
            let probe = vm.inner.mapping_probe(0);
            let preparation = vm.cpu_preparation(0, profile).unwrap();
            let wake = preparation.interrupt();
            drop(preparation);
            drop(vm);
            assert!(probe.is_mapped());
            assert!(
                Vm::new(&gic, 36, 1).is_err(),
                "wake authority retains its original VM even without a live handle"
            );
            dillo_machine::CpuInterrupt::interrupt(&wake).unwrap();
            drop(wake);
            assert!(!probe.is_mapped());
            drop(Vm::new(&gic, 36, 1).unwrap());
        }

        #[test]
        fn message_vectors_keep_enable_and_mask_independent() {
            if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
                crate::hypervisor::tests::SignedNativeTest::spawn(
                    "imp::tests::message_vectors_keep_enable_and_mask_independent",
                )
                .verify();
                return;
            }
            let gic = crate::hypervisor::GicParams {
                dist_base: 0x0800_0000,
                redist_base: 0x0810_0000,
                msi_base: 0x0a10_0000,
                msi_intid_base: 64,
                msi_intid_count: 32,
            };
            let vm = Vm::new(&gic, 36, 1).expect("native HVF/GIC required");
            let domain = GicMessageInterruptDomain::new(2, vm.inner.cpu_instance());
            let message = MessageInterrupt {
                address: 0x0808_0040,
                data: 48,
                masked: false,
            };
            domain.update(0, message).unwrap();
            domain.update(1, message).unwrap();
            assert_eq!(domain.inner.message_for(0), None);
            domain.enabled(0, true).unwrap();
            domain.enabled(1, true).unwrap();
            domain.enabled(0, false).unwrap();
            assert_eq!(domain.inner.message_for(0), None);
            assert_eq!(domain.inner.message_for(1), Some(message));
            domain.enabled(1, false).unwrap();
            domain.enabled(0, true).unwrap();
            assert_eq!(domain.inner.message_for(0), Some(message));
            assert_eq!(domain.inner.message_for(1), None);

            // Table programming must preserve a disabled vector's enable state.
            domain.update(1, message).unwrap();
            assert_eq!(domain.inner.message_for(1), None);
            domain
                .update(
                    0,
                    MessageInterrupt {
                        masked: true,
                        ..message
                    },
                )
                .unwrap();
            domain.enabled(0, false).unwrap();
            domain.enabled(0, true).unwrap();
            domain.enabled(1, true).unwrap();
            assert_eq!(domain.inner.message_for(0), None);
            assert_eq!(domain.inner.message_for(1), Some(message));
            domain.update(0, message).unwrap();
            assert_eq!(domain.inner.message_for(0), Some(message));
        }

        #[test]
        fn termination_precedes_a_pending_guest_cpu_on() {
            let slot = CpuSlot::new();
            slot.deposit(0x4000_0000, 0xabcd);
            let termination = AtomicBool::new(true);
            assert_eq!(slot.wait(&termination), None);
            assert_eq!(*slot.request.lock().unwrap(), Some((0x4000_0000, 0xabcd)));
        }

        #[test]
        fn hvf_owner_preparation_keeps_aps_parked_and_retires_wake_targets() {
            use applevisor::prelude::Reg;
            use dillo_machine::{
                CpuInterrupt as _, CpuPreparation as _, CpuRunner as _, Machine as _,
            };

            if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
                crate::hypervisor::tests::SignedNativeTest::spawn(
                    "imp::tests::hvf_owner_preparation_keeps_aps_parked_and_retires_wake_targets",
                )
                .verify();
                return;
            }
            let gic = crate::hypervisor::GicParams {
                dist_base: 0x0800_0000,
                redist_base: 0x0810_0000,
                msi_base: 0x0a10_0000,
                msi_intid_base: 64,
                msi_intid_count: 32,
            };
            let mut vm = Vm::new(&gic, 36, 2).expect("native HVF/GIC is required");
            let memory = <Memory as dillo_machine::Memory>::from_ranges(&[RamRange {
                gpa: 0,
                size: 0x4000,
            }])
            .unwrap();
            vm.attach(memory).unwrap();
            let profile = dillo_machine::CpuProfile::Aarch64(pmi::aarch64::Profile::V8_0);
            let ap = vm.cpu_preparation(1, profile).unwrap();
            let bsp = vm.cpu_preparation(0, profile).unwrap();
            let ap_interrupt = ap.interrupt();
            let bsp_interrupt = bsp.interrupt();
            assert!(ap_interrupt.target.handle.lock().unwrap().is_none());
            assert!(bsp_interrupt.target.handle.lock().unwrap().is_none());
            assert!(
                vm.cpu_preparation(1, profile).is_err(),
                "duplicate owner must fail"
            );
            assert!(
                vm.cpu_preparation(2, profile).is_err(),
                "out-of-range CPU must fail"
            );

            let termination = Arc::new(AtomicBool::new(false));
            let creation = std::sync::Barrier::new(3);
            let (ready, prepared) = std::sync::mpsc::channel();
            let (bsp_release, bsp_wait) = std::sync::mpsc::channel();
            let (done, completed) = std::sync::mpsc::channel();
            let results = std::thread::scope(|scope| {
                let ap_ready = ready.clone();
                let ap_done = done.clone();
                let ap_termination = Arc::clone(&termination);
                let creation_ref = &creation;
                let ap_owner = scope.spawn(move || {
                    creation_ref.wait();
                    let mut runner = ap.prepare().expect("prepare AP on its owner");
                    ap_ready
                        .send((1, runner.vcpu.inner.native_identity().unwrap()))
                        .unwrap();
                    drop(ap_ready);
                    let result = runner.run(ap_termination.as_ref());
                    ap_done.send(()).unwrap();
                    result
                });
                let bsp_termination = Arc::clone(&termination);
                let bsp_creation = &creation;
                let bsp_owner = scope.spawn(move || {
                    bsp_creation.wait();
                    let mut runner = bsp.prepare().expect("prepare BSP on its owner");
                    assert_eq!(runner.vcpu.inner.read_register(Reg::PC).unwrap(), 0);
                    assert_eq!(runner.vcpu.inner.read_register(Reg::X0).unwrap(), 0);
                    assert_eq!(runner.vcpu.inner.read_register(Reg::X30).unwrap(), 0);
                    assert_eq!(runner.vcpu.inner.read_register(Reg::CPSR).unwrap(), 0x3c5);
                    ready
                        .send((0, runner.vcpu.inner.native_identity().unwrap()))
                        .unwrap();
                    drop(ready);
                    bsp_wait.recv().unwrap();
                    runner.run(bsp_termination.as_ref())
                });
                drop(done);
                creation.wait();
                let facts = [prepared.recv(), prepared.recv()];
                // A wake alone neither powers on nor terminates a parked AP.
                let pure_wake = ap_interrupt.interrupt();
                let early_completion = completed.recv_timeout(std::time::Duration::from_millis(20));
                termination.store(true, Ordering::Release);
                let final_wake = ap_interrupt.interrupt();
                let release = bsp_release.send(());
                let ap_result = ap_owner.join();
                let bsp_result = bsp_owner.join();
                (
                    facts,
                    pure_wake,
                    early_completion,
                    final_wake,
                    release,
                    ap_result,
                    bsp_result,
                )
            });
            let (facts, pure_wake, early, final_wake, release, ap, bsp) = results;
            pure_wake.unwrap();
            assert!(early.is_err(), "pure wake must leave AP execution parked");
            final_wake.unwrap();
            release.unwrap();
            assert_eq!(ap.unwrap().unwrap(), VcpuStop::Stopped);
            assert_eq!(bsp.unwrap().unwrap(), VcpuStop::Stopped);
            let facts: Vec<_> = facts.into_iter().map(Result::unwrap).collect();
            assert_ne!(
                facts[0].1.0, facts[1].1.0,
                "native CPU handles must be distinct"
            );
            assert_ne!(
                facts[0].1.2, facts[1].1.2,
                "redistributor regions must be distinct"
            );
            for (index, (_, mpidr, redistributor, typer)) in facts {
                assert_eq!(mpidr, mpidr_for(index));
                assert_eq!(typer >> 32, index as u64);
                assert!(redistributor >= gic.redist_base);
            }
            assert!(!vm.cpu_power.slots[1].started.load(Ordering::Acquire));
            assert!(vm.cpu_power.slots[1].request.lock().unwrap().is_none());
            assert!(ap_interrupt.target.handle.lock().unwrap().is_none());
            assert!(bsp_interrupt.target.handle.lock().unwrap().is_none());
            ap_interrupt.interrupt().expect("retired wake is harmless");
            bsp_interrupt.interrupt().expect("retired wake is harmless");
        }

        #[test]
        fn cpu_slot_deposit_wakes_waiter() {
            assert_eq!(mpidr_for(0), 0x8000_0000);
            assert_eq!(mpidr_for(3), 0x8000_0003);
            assert_eq!((mpidr_for(2) & 0x00ff_ffff) as usize, 2);

            let slot = Arc::new(CpuSlot::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let s2 = Arc::clone(&slot);
            let sd2 = Arc::clone(&shutdown);
            let waiter = thread::spawn(move || s2.wait(sd2.as_ref()));
            slot.deposit(0x4000_0000, 0xABCD);
            assert_eq!(waiter.join().unwrap(), Some((0x4000_0000, 0xABCD)));

            let slot = Arc::new(CpuSlot::new());
            let shutdown = Arc::new(AtomicBool::new(false));
            let s2 = Arc::clone(&slot);
            let sd2 = Arc::clone(&shutdown);
            let waiter = thread::spawn(move || s2.wait(sd2.as_ref()));
            shutdown.store(true, Ordering::SeqCst);
            slot.cv.notify_all();
            assert_eq!(waiter.join().unwrap(), None);
        }
    }
}

pub use imp::*;
