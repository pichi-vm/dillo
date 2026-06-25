// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PCI root complex and endpoint trait.
//!
//! Minimal root complex: no hotplug, no secondary-bus / root-port, and no
//! multi-function endpoints.

use std::sync::Arc;
use std::sync::Mutex;

pub use dillo_mmio::{
    MessageInterrupt, MessageInterruptDomain, MmioAttachment, MmioDeviceHandle, MmioDeviceRun,
    MmioInterrupt, MmioInterruptRequirement, MmioJoinError, MmioSpawnError, MmioWriteOutcome,
    SharedMemory,
};
use dillo_mmio::{MmioDevice, MmioError, MmioWindow};

/// ECAM MMIO address decoding.
pub mod address;
/// BAR type definitions and decoding.
pub mod bar;
/// PCI Bus/Device/Function address encoding.
pub mod bdf;
/// Standard PCI capability IDs.
pub mod capability;
/// 256-byte Type 0 PCI configuration space.
pub mod configuration;
/// MSI-X table, capability, and notifier trait.
pub mod msix;

pub use address::parse_ecam_offset;
pub use bar::BarType;
pub use bdf::PciBdf;
pub use capability::{CAP_ID_MSIX, CAP_ID_PCIE, CAP_ID_PM, CAP_ID_VENDOR};
pub use configuration::PciConfiguration;
pub use msix::{MsixCap, MsixNotifier, MsixTable, MsixTableEntry, NoopNotifier};

/// One BAR exposed by a PCI device, in GPA terms — used by the MMIO
/// bus to wire the BAR's range to the device's `bar_read`/`bar_write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarRegion {
    pub bar_idx: u8,
    pub base_gpa: u64,
    pub size: u64,
}

#[derive(Debug)]
pub enum PciError {
    Unsupported,
}

impl std::fmt::Display for PciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("PCI access is unsupported by the routed endpoint"),
        }
    }
}

impl std::error::Error for PciError {}

/// PCI device attached to the bus. One per slot.
pub trait PciDevice: Send + Sync + std::fmt::Debug {
    /// Read a 32-bit configuration register (`reg_idx` is the dword
    /// offset, not the byte offset).
    fn config_read(&self, reg_idx: usize) -> u32;

    /// Write to a configuration register. `offset` is the byte offset
    /// within the dword (for unaligned writes like a single u8 to the
    /// command register).
    fn config_write(&self, reg_idx: usize, offset: u64, data: &[u8]) -> Result<(), PciError>;

    /// Logging name (e.g. `"virtio-console"`).
    fn name(&self) -> &str;

    /// BARs this device exposes — used at startup to wire MMIO ranges.
    fn bar_regions(&self) -> &[BarRegion] {
        &[]
    }

    /// Number of MSI-X table entries this device exposes (0 if none).
    ///
    /// The root sums these across slots to size the shared message-interrupt
    /// domain, and assigns each slot a disjoint vector base so device-local
    /// vectors `0..N` map to a private sub-range of the domain. See
    /// [`PciBus::set_host`].
    fn msix_vectors(&self) -> u16 {
        0
    }

    /// MMIO read on a BAR range. Default: ignored.
    fn bar_read(&self, _bar_idx: u8, _offset: u64, _data: &mut [u8]) -> Result<(), PciError> {
        Err(PciError::Unsupported)
    }

    /// MMIO write on a BAR range. Default: ignored.
    fn bar_write(&self, _bar_idx: u8, _offset: u64, _data: &[u8]) -> Result<(), PciError> {
        Err(PciError::Unsupported)
    }

    /// Attach this endpoint to the root's backend-owned host service.
    fn set_host(&self, _host: Arc<dyn PciDeviceHost>) {}
}

/// Backend-owned host service inherited from the attached PCI root.
pub trait PciDeviceHost: Send + Sync + std::fmt::Debug {
    fn shared_memory(&self) -> &[Arc<dyn SharedMemory>];

    fn msix_notifier(&self) -> Option<Arc<dyn MsixNotifier>> {
        None
    }

    fn spawn(&self, run: MmioDeviceRun) -> Result<MmioDeviceHandle, MmioSpawnError>;
}

/// PCI MSI-X table adapter backed by a machine-owned message-interrupt domain.
pub struct MsixInterruptAdapter {
    domain: Arc<dyn MessageInterruptDomain>,
}

impl std::fmt::Debug for MsixInterruptAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsixInterruptAdapter")
            .finish_non_exhaustive()
    }
}

impl MsixInterruptAdapter {
    pub fn new(domain: Arc<dyn MessageInterruptDomain>) -> Self {
        Self { domain }
    }

    /// Interrupt for a device completion on `vector`.
    pub fn interrupt_for(&self, vector: u16) -> Option<dillo_mmio::Interrupt> {
        self.domain.interrupt(vector)
    }
}

impl MsixNotifier for MsixInterruptAdapter {
    fn vector_updated(&self, vector: u16, entry: &MsixTableEntry) {
        if let Err(e) = self.domain.update(
            vector,
            MessageInterrupt {
                address: (u64::from(entry.msg_addr_hi) << 32) | u64::from(entry.msg_addr_lo),
                data: entry.msg_data,
                masked: entry.is_masked(),
            },
        ) {
            log::warn!("PCI MSI-X vector {vector} update failed: {e}");
        }
    }

    fn msix_enabled(&self, enabled: bool) {
        if let Err(e) = self.domain.enabled(enabled) {
            log::warn!("PCI MSI-X enable={enabled} failed: {e}");
        }
    }

    fn interrupt_for(&self, vector: u16) -> Option<dillo_mmio::Interrupt> {
        MsixInterruptAdapter::interrupt_for(self, vector)
    }
}

/// Number of slots on the single PCI bus. PCIe spec allows 32 device
/// numbers per bus.
pub const NUM_SLOTS: usize = 32;

/// Single-bus PCI fabric. Slot 0 typically holds a host bridge; slots
/// 1..NUM_SLOTS hold device endpoints in CLI-declaration order.
#[derive(Default)]
pub struct PciBus {
    slots: Vec<Option<Box<dyn PciDevice>>>,
}

impl std::fmt::Debug for PciBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<_> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|d| (i, Some(d.name().to_string()))))
            .collect();
        f.debug_struct("PciBus")
            .field("populated_slots", &names)
            .finish()
    }
}

impl PciBus {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(NUM_SLOTS);
        for _ in 0..NUM_SLOTS {
            slots.push(None);
        }
        Self { slots }
    }

    /// Create with a pre-registered host bridge at slot 0. The bridge
    /// gives the kernel something to find at 00:00.0 during its PCIe
    /// enumeration walk so it doesn't conclude the bus is empty.
    pub fn new_with_host_bridge() -> Self {
        let mut bus = Self::new();
        bus.register(0, Box::new(HostBridge::new()));
        bus
    }

    /// Place `device` at `slot`. Panics if the slot is already
    /// occupied or out of range — both are wiring bugs.
    pub fn register(&mut self, slot: u8, device: Box<dyn PciDevice>) {
        assert!((slot as usize) < NUM_SLOTS, "PCI slot {slot} out of range");
        assert!(
            self.slots[slot as usize].is_none(),
            "PCI slot {slot} already occupied"
        );
        log::info!("PCI: registered '{}' at 00:{:02x}.0", device.name(), slot);
        self.slots[slot as usize] = Some(device);
    }

    /// Total MSI-X vectors across all populated slots — the size of the shared
    /// message-interrupt domain the root must request from the machine.
    pub fn total_msix_vectors(&self) -> u16 {
        self.slots
            .iter()
            .flatten()
            .map(|d| d.msix_vectors())
            .fold(0u16, u16::saturating_add)
    }

    pub fn set_host(&self, host: Arc<dyn PciDeviceHost>) {
        // The whole bus shares one message-interrupt domain (a flat pool of
        // vectors). Give each slot a disjoint vector base — a running sum in
        // slot order — so two functions' device-local vectors `0..N` never
        // alias in that pool. Slots without MSI-X get the host unwrapped.
        let mut base: u16 = 0;
        for device in self.slots.iter().flatten() {
            let n = device.msix_vectors();
            let host_for_device: Arc<dyn PciDeviceHost> = if n == 0 {
                Arc::clone(&host)
            } else {
                Arc::new(OffsetPciDeviceHost {
                    inner: Arc::clone(&host),
                    vector_base: base,
                })
            };
            device.set_host(host_for_device);
            base = base.saturating_add(n);
        }
    }

    /// Read a config register. Single-bus, single-function only:
    /// `bus != 0` or `function != 0` returns the all-1s "no device"
    /// response, matching real hardware for unpopulated addresses.
    pub fn config_read(&self, bus: u8, device: u8, function: u8, reg_idx: usize) -> u32 {
        if bus != 0 || function != 0 || (device as usize) >= NUM_SLOTS {
            return 0xFFFF_FFFF;
        }
        match &self.slots[device as usize] {
            None => 0xFFFF_FFFF,
            Some(device) => device.config_read(reg_idx),
        }
    }

    pub fn config_write(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) {
        if bus != 0 || function != 0 || (device as usize) >= NUM_SLOTS {
            return;
        }
        if let Some(device) = &self.slots[device as usize] {
            let _ = device.config_write(reg_idx, offset, data);
        }
    }

    /// Walk every populated slot and return each BAR's `(slot, region)`.
    /// The startup wiring uses this to register MMIO bus handlers.
    pub fn enumerate_bars(&self) -> Vec<(u8, BarRegion)> {
        let mut out = Vec::new();
        for (slot, device) in self.slots.iter().enumerate() {
            if let Some(device) = device {
                out.extend(
                    device
                        .bar_regions()
                        .iter()
                        .copied()
                        .map(|region| (slot as u8, region)),
                );
            }
        }
        out
    }

    /// BAR-range MMIO read. Caller has already matched the address to
    /// `(slot, bar_idx, base_gpa)`.
    pub fn bar_read(
        &self,
        slot: u8,
        bar_idx: u8,
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), PciError> {
        match &self.slots.get(slot as usize).and_then(|s| s.as_ref()) {
            None => Err(PciError::Unsupported),
            Some(device) => device.bar_read(bar_idx, offset, data),
        }
    }

    pub fn bar_write(
        &self,
        slot: u8,
        bar_idx: u8,
        offset: u64,
        data: &[u8],
    ) -> Result<(), PciError> {
        match &self.slots.get(slot as usize).and_then(|s| s.as_ref()) {
            None => Err(PciError::Unsupported),
            Some(device) => device.bar_write(bar_idx, offset, data),
        }
    }
}

/// PCIe root complex declared by the base DTB.
///
/// The root owns the ECAM MMIO window and the single downstream PCI bus.
/// Legacy CF8/CFC PIO is intentionally absent so x86 guests use ECAM.
pub struct PciRoot {
    window: MmioWindow,
    windows: Vec<MmioWindow>,
    interrupts: Vec<MmioInterruptRequirement>,
    bus: PciBus,
}

impl std::fmt::Debug for PciRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PciRoot")
            .field("window", &self.window)
            .field("windows", &self.windows)
            .field("bus", &self.bus)
            .finish_non_exhaustive()
    }
}

impl PciRoot {
    pub fn new(window: MmioWindow) -> Self {
        Self {
            window,
            windows: vec![window],
            interrupts: Vec::new(),
            bus: PciBus::new_with_host_bridge(),
        }
    }

    pub fn with_interrupt_requirement(
        window: MmioWindow,
        interrupt: MmioInterruptRequirement,
    ) -> Self {
        Self {
            window,
            windows: vec![window],
            interrupts: vec![interrupt],
            bus: PciBus::new_with_host_bridge(),
        }
    }

    pub fn register(&mut self, slot: u8, device: Box<dyn PciDevice>) {
        self.bus.register(slot, device);
        self.refresh_windows();
        self.refresh_interrupts();
    }

    pub fn set_attachment(&self, attachment: Arc<dyn MmioAttachment>) {
        self.bus.set_host(Arc::new(PciRootHost { attachment }));
    }

    pub fn config_read(&self, bus: u8, device: u8, function: u8, reg_idx: usize) -> u32 {
        self.bus.config_read(bus, device, function, reg_idx)
    }

    pub fn config_write(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) {
        self.bus
            .config_write(bus, device, function, reg_idx, offset, data);
    }

    pub fn enumerate_bars(&self) -> Vec<(u8, BarRegion)> {
        self.bus.enumerate_bars()
    }

    pub fn bar_read(
        &self,
        slot: u8,
        bar_idx: u8,
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), PciError> {
        self.bus.bar_read(slot, bar_idx, offset, data)
    }

    pub fn bar_write(
        &self,
        slot: u8,
        bar_idx: u8,
        offset: u64,
        data: &[u8],
    ) -> Result<(), PciError> {
        self.bus.bar_write(slot, bar_idx, offset, data)
    }

    fn decode_ecam(offset: u64) -> (u8, u8, u8, usize, usize) {
        let (bus, device, function, register) = parse_ecam_offset(offset);
        let reg_byte = register as usize;
        (bus, device, function, reg_byte >> 2, reg_byte & 0x3)
    }

    fn bar_window(_slot: u8, bar: &BarRegion) -> MmioWindow {
        MmioWindow {
            base: bar.base_gpa,
            size: bar.size,
        }
    }

    fn refresh_windows(&mut self) {
        self.windows.clear();
        self.windows.push(self.window);
        self.windows.extend(
            self.enumerate_bars()
                .into_iter()
                .map(|(slot, bar)| Self::bar_window(slot, &bar)),
        );
    }

    /// Size the requested message-interrupt domain to the sum of all populated
    /// slots' MSI-X tables. Each slot is later handed a disjoint sub-range via
    /// [`PciBus::set_host`], so the one flat domain backs every function.
    fn refresh_interrupts(&mut self) {
        let total = self.bus.total_msix_vectors();
        for req in &mut self.interrupts {
            if let MmioInterruptRequirement::MessageDomain { vectors, .. } = req {
                *vectors = total;
            }
        }
    }

    fn bar_route(&self, window: MmioWindow) -> Option<(u8, u8)> {
        self.enumerate_bars()
            .into_iter()
            .find(|(_, bar)| bar.base_gpa == window.base && bar.size == window.size)
            .map(|(slot, bar)| (slot, bar.bar_idx))
    }
}

#[derive(Debug)]
struct PciRootHost {
    attachment: Arc<dyn MmioAttachment>,
}

impl PciDeviceHost for PciRootHost {
    fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
        self.attachment.shared_memory()
    }

    fn msix_notifier(&self) -> Option<Arc<dyn MsixNotifier>> {
        self.attachment
            .interrupts()
            .iter()
            .find_map(|interrupt| match interrupt {
                MmioInterrupt::MessageDomain(domain) => {
                    Some(Arc::new(MsixInterruptAdapter::new(Arc::clone(domain)))
                        as Arc<dyn MsixNotifier>)
                }
                MmioInterrupt::Line(_) => None,
            })
    }

    fn spawn(&self, run: MmioDeviceRun) -> Result<MmioDeviceHandle, MmioSpawnError> {
        Arc::clone(&self.attachment).spawn(run)
    }
}

/// `VIRTIO_MSI_NO_VECTOR` / unprogrammed MSI-X table sentinel.
const MSI_NO_VECTOR: u16 = 0xFFFF;

/// Per-slot wrapper installed by [`PciBus::set_host`] that shifts a device's
/// MSI-X vectors into its disjoint sub-range of the root's shared
/// message-interrupt domain. Config-space and BAR routing already carry the
/// slot dimension; this extends the same per-slot isolation to MSI-X.
#[derive(Debug)]
struct OffsetPciDeviceHost {
    inner: Arc<dyn PciDeviceHost>,
    vector_base: u16,
}

impl PciDeviceHost for OffsetPciDeviceHost {
    fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
        self.inner.shared_memory()
    }

    fn msix_notifier(&self) -> Option<Arc<dyn MsixNotifier>> {
        self.inner.msix_notifier().map(|inner| {
            Arc::new(OffsetMsixNotifier {
                inner,
                vector_base: self.vector_base,
            }) as Arc<dyn MsixNotifier>
        })
    }

    fn spawn(&self, run: MmioDeviceRun) -> Result<MmioDeviceHandle, MmioSpawnError> {
        self.inner.spawn(run)
    }
}

/// MSI-X notifier that shifts device-local vectors by a fixed base before
/// addressing the shared domain. The no-vector sentinel passes through
/// unshifted so "no interrupt" stays "no interrupt".
struct OffsetMsixNotifier {
    inner: Arc<dyn MsixNotifier>,
    vector_base: u16,
}

impl MsixNotifier for OffsetMsixNotifier {
    fn vector_updated(&self, vector: u16, entry: &MsixTableEntry) {
        self.inner
            .vector_updated(vector.saturating_add(self.vector_base), entry);
    }

    fn msix_enabled(&self, enabled: bool) {
        self.inner.msix_enabled(enabled);
    }

    fn interrupt_for(&self, vector: u16) -> Option<dillo_mmio::Interrupt> {
        if vector == MSI_NO_VECTOR {
            return None;
        }
        self.inner
            .interrupt_for(vector.saturating_add(self.vector_base))
    }
}

impl MmioDevice for PciRoot {
    fn windows(&self) -> &[MmioWindow] {
        &self.windows
    }

    fn interrupts(&self) -> &[MmioInterruptRequirement] {
        &self.interrupts
    }

    fn read(&self, window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
        if window.base == self.window.base && window.size == self.window.size {
            let (bus, device, function, reg_idx, in_dword) = Self::decode_ecam(offset);
            let value = self.config_read(bus, device, function, reg_idx);
            let bytes = value.to_le_bytes();
            for (i, slot) in data.iter_mut().enumerate() {
                *slot = *bytes.get(in_dword + i).unwrap_or(&0xFF);
            }
            return Ok(());
        }

        if let Some((slot, bar_idx)) = self.bar_route(window) {
            return self
                .bar_read(slot, bar_idx, offset, data)
                .map_err(|_| MmioError::Unsupported);
        }

        Err(MmioError::Unsupported)
    }

    fn write(
        &self,
        window: MmioWindow,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError> {
        if window.base == self.window.base && window.size == self.window.size {
            let (bus, device, function, reg_idx, in_dword) = Self::decode_ecam(offset);
            self.config_write(bus, device, function, reg_idx, in_dword as u64, data);
            return Ok(MmioWriteOutcome::Continue);
        }

        if let Some((slot, bar_idx)) = self.bar_route(window) {
            self.bar_write(slot, bar_idx, offset, data)
                .map_err(|_| MmioError::Unsupported)?;
            return Ok(MmioWriteOutcome::Continue);
        }

        Err(MmioError::Unsupported)
    }
}

/// Minimal Intel-440FX-style host bridge. Pure config-space placeholder
/// so the kernel's PCIe enumeration walk finds something at 00:00.0.
pub struct HostBridge {
    config: Mutex<PciConfiguration>,
}

impl std::fmt::Debug for HostBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostBridge").finish_non_exhaustive()
    }
}

impl Default for HostBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl HostBridge {
    pub(crate) fn new() -> Self {
        let mut config = PciConfiguration::new();
        // Intel 440FX — vendor 0x8086, device 0x1237.
        config.set_vendor_device(0x8086, 0x1237);
        // Class code: 0x06 (bridge) / 0x00 (host bridge).
        config.set_class(0x06, 0x00, 0x00, 0x00);
        config.set_header_type(0x00);
        Self {
            config: Mutex::new(config),
        }
    }
}

impl PciDevice for HostBridge {
    fn config_read(&self, reg_idx: usize) -> u32 {
        self.config
            .lock()
            .expect("host bridge config poisoned")
            .read_reg(reg_idx)
    }
    fn config_write(&self, reg_idx: usize, offset: u64, data: &[u8]) -> Result<(), PciError> {
        self.config
            .lock()
            .expect("host bridge config poisoned")
            .write_reg(reg_idx, offset, data);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "host-bridge"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const BAR_REGIONS: [BarRegion; 1] = [BarRegion {
        bar_idx: 2,
        base_gpa: 0x8000_0000,
        size: 0x1000,
    }];

    #[test]
    fn empty_slots_return_all_ones() {
        let bus = PciBus::new();
        assert_eq!(bus.config_read(0, 0, 0, 0), 0xFFFF_FFFF);
        assert_eq!(bus.config_read(0, 31, 0, 0), 0xFFFF_FFFF);
    }

    #[test]
    fn host_bridge_vendor_device() {
        let bus = PciBus::new_with_host_bridge();
        // Reg 0 = vendor (low 16) + device (high 16).
        let val = bus.config_read(0, 0, 0, 0);
        assert_eq!(val, 0x1237_8086);
    }

    #[test]
    fn non_zero_bus_function_returns_all_ones() {
        let bus = PciBus::new_with_host_bridge();
        assert_eq!(bus.config_read(1, 0, 0, 0), 0xFFFF_FFFF);
        assert_eq!(bus.config_read(0, 0, 1, 0), 0xFFFF_FFFF);
    }

    #[test]
    fn out_of_range_device_returns_all_ones() {
        let bus = PciBus::new_with_host_bridge();
        assert_eq!(bus.config_read(0, 32, 0, 0), 0xFFFF_FFFF);
    }

    #[test]
    fn pci_root_ecam_reads_host_bridge_config() {
        let root = PciRoot::new(MmioWindow {
            base: 0x3000_0000,
            size: 0x1000_0000,
        });
        let mut data = [0u8; 4];

        root.read(root.window, 0, &mut data)
            .expect("host bridge read");

        assert_eq!(u32::from_le_bytes(data), root.config_read(0, 0, 0, 0));
        assert_eq!(data, [0x86, 0x80, 0x37, 0x12]);
    }

    #[test]
    fn pci_root_ecam_reads_unaligned_bytes() {
        let root = PciRoot::new(MmioWindow {
            base: 0x3000_0000,
            size: 0x1000_0000,
        });
        let mut data = [0u8; 2];

        root.read(root.window, 1, &mut data)
            .expect("unaligned host bridge read");

        assert_eq!(data, [0x80, 0x37]);
    }

    #[test]
    fn pci_root_windows_include_ecam_and_bars() {
        struct BarDevice;

        impl std::fmt::Debug for BarDevice {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("BarDevice").finish()
            }
        }

        impl PciDevice for BarDevice {
            fn config_read(&self, _reg_idx: usize) -> u32 {
                0
            }

            fn config_write(
                &self,
                _reg_idx: usize,
                _offset: u64,
                _data: &[u8],
            ) -> Result<(), PciError> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "bar-device"
            }

            fn bar_regions(&self) -> &[BarRegion] {
                &BAR_REGIONS
            }
        }

        let mut root = PciRoot::new(MmioWindow {
            base: 0x3000_0000,
            size: 0x1000_0000,
        });
        root.register(1, Box::new(BarDevice));

        let windows = root.windows();

        assert!(windows.contains(&root.window));
        assert!(
            windows
                .iter()
                .any(|w| w.base == 0x8000_0000 && w.size == 0x1000)
        );
    }

    #[test]
    fn pci_root_routes_bar_window_reads() {
        struct BarDevice;

        impl std::fmt::Debug for BarDevice {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("BarDevice").finish()
            }
        }

        impl PciDevice for BarDevice {
            fn config_read(&self, _reg_idx: usize) -> u32 {
                0
            }

            fn config_write(
                &self,
                _reg_idx: usize,
                _offset: u64,
                _data: &[u8],
            ) -> Result<(), PciError> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "bar-device"
            }

            fn bar_regions(&self) -> &[BarRegion] {
                &BAR_REGIONS
            }

            fn bar_read(&self, bar_idx: u8, offset: u64, data: &mut [u8]) -> Result<(), PciError> {
                data[0] = bar_idx;
                data[1] = offset as u8;
                Ok(())
            }
        }

        let mut root = PciRoot::new(MmioWindow {
            base: 0x3000_0000,
            size: 0x1000_0000,
        });
        root.register(1, Box::new(BarDevice));
        let bar_window = root
            .windows()
            .iter()
            .copied()
            .find(|w| w.base == 0x8000_0000)
            .expect("BAR window");
        let mut data = [0u8; 2];

        root.read(bar_window, 0x42, &mut data)
            .expect("BAR read routed");

        assert_eq!(data, [2, 0x42]);
    }

    #[test]
    fn pci_root_attachment_reaches_endpoints() {
        #[derive(Debug)]
        struct FakeAttachment;

        impl MmioAttachment for FakeAttachment {
            fn interrupts(&self) -> &[dillo_mmio::MmioInterrupt] {
                &[]
            }

            fn shared_memory(&self) -> &[Arc<dyn dillo_mmio::SharedMemory>] {
                &[]
            }

            fn spawn(
                self: Arc<Self>,
                _run: dillo_mmio::MmioDeviceRun,
            ) -> Result<MmioDeviceHandle, MmioSpawnError> {
                Ok(MmioDeviceHandle::noop())
            }
        }

        struct HostAwareDevice {
            observed_host: Arc<AtomicBool>,
        }

        impl std::fmt::Debug for HostAwareDevice {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("HostAwareDevice").finish()
            }
        }

        impl PciDevice for HostAwareDevice {
            fn config_read(&self, _reg_idx: usize) -> u32 {
                0
            }

            fn config_write(
                &self,
                _reg_idx: usize,
                _offset: u64,
                _data: &[u8],
            ) -> Result<(), PciError> {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "host-aware-device"
            }

            fn set_host(&self, _host: Arc<dyn PciDeviceHost>) {
                self.observed_host.store(true, Ordering::Release);
            }
        }

        let observed_host = Arc::new(AtomicBool::new(false));
        let mut root = PciRoot::new(MmioWindow {
            base: 0x3000_0000,
            size: 0x1000_0000,
        });
        root.register(
            1,
            Box::new(HostAwareDevice {
                observed_host: Arc::clone(&observed_host),
            }),
        );

        root.set_attachment(Arc::new(FakeAttachment));

        assert!(observed_host.load(Ordering::Acquire));
    }

    #[test]
    fn two_msix_functions_get_disjoint_domain_vectors() {
        use dillo_mmio::{Interrupt, InterruptError, MmioInterrupt};

        // Domain that records the (global) vector index of every update.
        struct RecordingDomain {
            updates: Mutex<Vec<u16>>,
        }
        impl MessageInterruptDomain for RecordingDomain {
            fn update(&self, vector: u16, _msg: MessageInterrupt) -> Result<(), InterruptError> {
                self.updates.lock().unwrap().push(vector);
                Ok(())
            }
            fn enabled(&self, _enabled: bool) -> Result<(), InterruptError> {
                Ok(())
            }
            fn interrupt(&self, _vector: u16) -> Option<Interrupt> {
                None
            }
        }

        #[derive(Debug)]
        struct FakeAttachment {
            interrupts: Vec<MmioInterrupt>,
        }
        impl MmioAttachment for FakeAttachment {
            fn interrupts(&self) -> &[MmioInterrupt] {
                &self.interrupts
            }
            fn shared_memory(&self) -> &[Arc<dyn SharedMemory>] {
                &[]
            }
            fn spawn(
                self: Arc<Self>,
                _run: dillo_mmio::MmioDeviceRun,
            ) -> Result<MmioDeviceHandle, MmioSpawnError> {
                Ok(MmioDeviceHandle::noop())
            }
        }

        // Device that reports a configurable MSI-X vector count and captures the
        // per-slot host it was handed at set_host time.
        struct RecordingDevice {
            vectors: u16,
            host: Arc<Mutex<Option<Arc<dyn PciDeviceHost>>>>,
        }
        impl std::fmt::Debug for RecordingDevice {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("RecordingDevice").finish()
            }
        }
        impl PciDevice for RecordingDevice {
            fn config_read(&self, _reg_idx: usize) -> u32 {
                0
            }
            fn config_write(
                &self,
                _reg_idx: usize,
                _offset: u64,
                _data: &[u8],
            ) -> Result<(), PciError> {
                Ok(())
            }
            fn name(&self) -> &'static str {
                "rec"
            }
            fn msix_vectors(&self) -> u16 {
                self.vectors
            }
            fn set_host(&self, host: Arc<dyn PciDeviceHost>) {
                *self.host.lock().unwrap() = Some(host);
            }
        }

        let domain = Arc::new(RecordingDomain {
            updates: Mutex::new(Vec::new()),
        });

        let mut root = PciRoot::with_interrupt_requirement(
            MmioWindow {
                base: 0x3000_0000,
                size: 0x1000_0000,
            },
            MmioInterruptRequirement::MessageDomain {
                source: None,
                vectors: 0,
            },
        );

        let host_a = Arc::new(Mutex::new(None));
        let host_b = Arc::new(Mutex::new(None));
        root.register(
            1,
            Box::new(RecordingDevice {
                vectors: 3,
                host: Arc::clone(&host_a),
            }),
        );
        root.register(
            2,
            Box::new(RecordingDevice {
                vectors: 2,
                host: Arc::clone(&host_b),
            }),
        );

        // The root sized its requested domain to the sum of both functions.
        assert!(matches!(
            root.interrupts(),
            [MmioInterruptRequirement::MessageDomain { vectors: 5, .. }]
        ));

        root.set_attachment(Arc::new(FakeAttachment {
            interrupts: vec![MmioInterrupt::MessageDomain(domain.clone())],
        }));

        // Both functions program their device-local vector 0; they must land on
        // distinct global vectors (0 for slot 1, base 3 for slot 2) — the alias
        // bug this design fixes.
        let entry = MsixTableEntry::default();
        host_a
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .msix_notifier()
            .unwrap()
            .vector_updated(0, &entry);
        host_b
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .msix_notifier()
            .unwrap()
            .vector_updated(0, &entry);

        assert_eq!(
            domain.updates.lock().unwrap().as_slice(),
            &[0, 3],
            "function MSI-X vectors must not alias in the shared domain"
        );
    }

    #[test]
    fn msix_adapter_updates_message_domain() {
        struct FakeDomain {
            updates: Mutex<Vec<(u16, MessageInterrupt)>>,
            enabled: AtomicBool,
        }

        impl MessageInterruptDomain for FakeDomain {
            fn update(
                &self,
                vector: u16,
                msg: MessageInterrupt,
            ) -> Result<(), dillo_mmio::InterruptError> {
                self.updates
                    .lock()
                    .expect("updates lock poisoned")
                    .push((vector, msg));
                Ok(())
            }

            fn enabled(&self, enabled: bool) -> Result<(), dillo_mmio::InterruptError> {
                self.enabled.store(enabled, Ordering::Release);
                Ok(())
            }

            fn interrupt(&self, _vector: u16) -> Option<dillo_mmio::Interrupt> {
                None
            }
        }

        let domain = Arc::new(FakeDomain {
            updates: Mutex::new(Vec::new()),
            enabled: AtomicBool::new(false),
        });
        let adapter = MsixInterruptAdapter::new(domain.clone());

        adapter.vector_updated(
            2,
            &MsixTableEntry {
                msg_addr_lo: 0xFEE0_1000,
                msg_addr_hi: 0,
                msg_data: 0x45,
                vector_ctl: 1,
            },
        );
        adapter.msix_enabled(true);

        assert_eq!(
            domain
                .updates
                .lock()
                .expect("updates lock poisoned")
                .as_slice(),
            &[(
                2,
                MessageInterrupt {
                    address: 0xFEE0_1000,
                    data: 0x45,
                    masked: true,
                }
            )]
        );
        assert!(domain.enabled.load(Ordering::Acquire));
    }
}
