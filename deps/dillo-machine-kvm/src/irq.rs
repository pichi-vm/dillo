// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! IRQ management: GSI allocation, irqfd registration, and GSI routing for KVM.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Arc;

use kvm_bindings::{KVM_IRQ_ROUTING_IRQCHIP, kvm_irq_routing_entry, kvm_irq_routing_irqchip};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    KVM_IRQ_ROUTING_MSI, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    kvm_irq_routing_msi,
};
use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;

use thiserror::Error;

/// Errors from IRQ routing and irqfd management.
#[derive(Error, Debug)]
pub(crate) enum IrqError {
    #[error("Failed to allocate GSI routing table")]
    RoutingAllocation,
    #[error("KVM irqfd ioctl failed: {0}")]
    KvmIrqfd(kvm_ioctls::Error),
    #[error("KVM GSI routing ioctl failed: {0}")]
    KvmRouting(kvm_ioctls::Error),
    #[error("Failed to create eventfd: {0}")]
    EventFdCreate(std::io::Error),
    #[error("Failed to clone eventfd: {0}")]
    EventFdClone(std::io::Error),
}

/// First dynamically-allocated GSI. On x86 this clears the IOAPIC range (0-23);
/// on aarch64 the GSI is just an opaque routing-table key, so any base works.
const FIRST_MSI_GSI: u32 = 24;
/// Number of IOAPIC pins (default routing entries).
#[cfg(target_arch = "x86_64")]
const NUM_IOAPIC_PINS: u32 = 24;

/// Manages KVM irqfd registration and GSI routing table.
///
/// Maintains the full GSI routing table (IOAPIC defaults + MSI entries) and
/// atomically replaces it via `KVM_SET_GSI_ROUTING` on each change.
pub(crate) struct IrqManager {
    vm_fd: Arc<VmFd>,
    next_gsi: u32,
    /// Min-heap of released GSIs available for reuse (Reverse makes BinaryHeap a min-heap).
    free_gsis: BinaryHeap<Reverse<u32>>,
    routes: Vec<kvm_irq_routing_entry>,
    irqfds: Vec<(u32, EventFd)>,
    /// aarch64 wired SPIs whose irqfd can't be registered yet: KVM rejects
    /// KVM_IRQFD until the vGIC is initialized, which needs vCPUs (created after
    /// device attach). Recorded here as (SPI pin, kernel-side eventfd) and bound
    /// by [`flush_pending_wired`] once the vGIC is up.
    #[cfg(target_arch = "aarch64")]
    pending_wired: Vec<(u32, EventFd)>,
}

impl std::fmt::Debug for IrqManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrqManager")
            .field("next_gsi", &self.next_gsi)
            .field("free_gsis", &self.free_gsis)
            .field("routes", &self.routes.len())
            .field("irqfds", &self.irqfds.len())
            .finish_non_exhaustive()
    }
}

impl IrqManager {
    /// Create a new IrqManager with 24 default IOAPIC routing entries.
    ///
    /// GSIs 0-23 are mapped to IOAPIC pins 0-23. This preserves legacy device
    /// routing (e.g., serial UART on IRQ 4) when MSI entries are added later.
    pub(crate) fn new(vm_fd: Arc<VmFd>) -> Result<Self, IrqError> {
        // x86: KVM's in-kernel IOAPIC + PIC need their default GSI routes
        // (GSIs 0-23 → IOAPIC pins, plus the PIC mirror), 8 + 8 + 24 = 40 entries.
        // aarch64's GICv3 has no such defaults — every interrupt is an SPI routed
        // by an IRQCHIP entry added at device-attach time — so the table starts
        // empty and is first committed when the first device registers.
        #[cfg(target_arch = "x86_64")]
        let routes = {
            let mut routes = Vec::with_capacity(40 + 8);
            for pin in 0..8u32 {
                routes.push(make_irqchip_entry(pin, KVM_IRQCHIP_PIC_MASTER, pin));
            }
            for pin in 0..8u32 {
                routes.push(make_irqchip_entry(8 + pin, KVM_IRQCHIP_PIC_SLAVE, pin));
            }
            for pin in 0..NUM_IOAPIC_PINS {
                routes.push(make_irqchip_entry(pin, KVM_IRQCHIP_IOAPIC, pin));
            }
            routes
        };
        #[cfg(target_arch = "aarch64")]
        let routes: Vec<kvm_irq_routing_entry> = Vec::new();

        let mut mgr = Self {
            vm_fd,
            next_gsi: FIRST_MSI_GSI,
            free_gsis: BinaryHeap::new(),
            routes,
            irqfds: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            pending_wired: Vec::new(),
        };
        // Commit only a non-empty initial table. aarch64 starts empty and must
        // not call KVM_SET_GSI_ROUTING before the vGIC is initialized; its first
        // commit happens when a device registers its first route.
        if !mgr.routes.is_empty() {
            mgr.commit_routes()?;
        }
        Ok(mgr)
    }

    /// Allocate a GSI with an MSI routing entry and register an irqfd.
    ///
    /// Creates an `EventFd`, adds an MSI routing entry to the GSI routing table,
    /// commits the table to KVM, and registers the irqfd. Returns the allocated
    /// GSI and an `EventFd` clone that the device can write to fire interrupts.
    pub(crate) fn allocate_irqfd(
        &mut self,
        addr_lo: u32,
        addr_hi: u32,
        data: u32,
    ) -> Result<(u32, EventFd), IrqError> {
        let gsi = if let Some(Reverse(g)) = self.free_gsis.pop() {
            g
        } else {
            let g = self.next_gsi;
            self.next_gsi += 1;
            g
        };

        // Add the routing entry. x86 routes the MSI message in-kernel; aarch64
        // has no in-kernel ITS, so the guest-programmed message is a GICv2m
        // write whose `data` is the SPI INTID — route that GSI to the GIC SPI
        // (pin = INTID - 32) so the irqfd injects it in-kernel.
        #[cfg(target_arch = "x86_64")]
        self.routes
            .push(make_msi_entry(gsi, addr_lo, addr_hi, data));
        #[cfg(target_arch = "aarch64")]
        {
            let _ = (addr_lo, addr_hi);
            self.routes.push(make_spi_irqchip_entry(gsi, data - 32));
        }
        self.commit_routes()?;

        // Create eventfd with EFD_CLOEXEC so it does not leak across exec()
        // boundaries (prerequisite for exec-based reboot, ISOL-06).
        let eventfd = EventFd::new(libc::EFD_CLOEXEC).map_err(IrqError::EventFdCreate)?;
        self.vm_fd
            .register_irqfd(&eventfd, gsi)
            .map_err(IrqError::KvmIrqfd)?;

        // Store a clone for teardown
        let device_fd = eventfd.try_clone().map_err(IrqError::EventFdClone)?;
        self.irqfds.push((gsi, eventfd));

        Ok((gsi, device_fd))
    }

    /// aarch64: record a wired SPI `pin` (INTID = `pin` + 32) for deferred irqfd
    /// binding and return the device's eventfd. The IRQCHIP route + KVM_IRQFD are
    /// installed later by [`flush_pending_wired`]: KVM_IRQFD fails with EAGAIN
    /// until the vGIC is initialized, and the vGIC needs vCPUs that don't exist
    /// at device-attach time. (x86 binds eagerly to a pre-existing IOAPIC GSI via
    /// [`register_irqfd_at_gsi`]; its in-kernel IRQCHIP is ready from VM
    /// creation.)
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn register_spi_irqfd(&mut self, pin: u32) -> Result<EventFd, IrqError> {
        let eventfd = EventFd::new(libc::EFD_CLOEXEC).map_err(IrqError::EventFdCreate)?;
        let device_fd = eventfd.try_clone().map_err(IrqError::EventFdClone)?;
        self.pending_wired.push((pin, eventfd));
        Ok(device_fd)
    }

    /// aarch64: install IRQCHIP routes + KVM_IRQFDs for every wired SPI recorded
    /// by [`register_spi_irqfd`]. Must be called once after the vGIC is
    /// initialized (e.g. from `prepare_vcpu_run`).
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn flush_pending_wired(&mut self) -> Result<(), IrqError> {
        let pending = std::mem::take(&mut self.pending_wired);
        for (pin, eventfd) in pending {
            let gsi = if let Some(Reverse(g)) = self.free_gsis.pop() {
                g
            } else {
                let g = self.next_gsi;
                self.next_gsi += 1;
                g
            };
            self.routes.push(make_spi_irqchip_entry(gsi, pin));
            self.commit_routes()?;
            self.vm_fd
                .register_irqfd(&eventfd, gsi)
                .map_err(IrqError::KvmIrqfd)?;
            self.irqfds.push((gsi, eventfd));
        }
        Ok(())
    }

    /// Register an irqfd at an existing GSI (no new routing entry needed).
    ///
    /// For GSIs that already have routing entries (e.g., GSI 9 for SCI / ACPI),
    /// creates an `EventFd` and registers it with KVM at the given GSI. Unlike
    /// `allocate_irqfd`, this does NOT add a new routing entry -- it binds to
    /// the existing IOAPIC routing for the GSI.
    ///
    /// Returns an `EventFd` clone the caller can write to fire the interrupt.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn register_irqfd_at_gsi(&mut self, gsi: u32) -> Result<EventFd, IrqError> {
        let eventfd = EventFd::new(libc::EFD_CLOEXEC).map_err(IrqError::EventFdCreate)?;
        self.vm_fd
            .register_irqfd(&eventfd, gsi)
            .map_err(IrqError::KvmIrqfd)?;
        let device_fd = eventfd.try_clone().map_err(IrqError::EventFdClone)?;
        self.irqfds.push((gsi, eventfd));
        Ok(device_fd)
    }

    /// Update an existing MSI routing entry's address/data fields.
    ///
    /// Finds the route by GSI, updates the MSI fields, and commits the table.
    pub(crate) fn update_route(
        &mut self,
        gsi: u32,
        addr_lo: u32,
        addr_hi: u32,
        data: u32,
    ) -> Result<(), IrqError> {
        let entry = self
            .routes
            .iter_mut()
            .find(|e| e.gsi == gsi)
            .ok_or(IrqError::RoutingAllocation)?;

        #[cfg(target_arch = "x86_64")]
        {
            *entry = make_msi_entry(gsi, addr_lo, addr_hi, data);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let _ = (addr_lo, addr_hi);
            *entry = make_spi_irqchip_entry(gsi, data - 32);
        }
        self.commit_routes()
    }

    /// Unregister all irqfds and remove MSI routing entries.
    ///
    /// Keeps the 24 default IOAPIC entries intact. Commits the reduced table.
    #[cfg(all(test, target_arch = "x86_64"))]
    fn teardown_irqfds(&mut self) -> Result<(), IrqError> {
        for (gsi, fd) in self.irqfds.drain(..) {
            self.vm_fd
                .unregister_irqfd(&fd, gsi)
                .map_err(IrqError::KvmIrqfd)?;
        }
        // Remove MSI entries (keep only IOAPIC defaults at GSI 0-23)
        self.routes.retain(|e| e.type_ == KVM_IRQ_ROUTING_IRQCHIP);
        self.commit_routes()
    }

    /// Release a single irqfd and return its GSI to the free-list for reuse.
    ///
    /// Unregisters the irqfd with KVM, removes the MSI routing entry from the
    /// table, commits the updated table, and pushes the GSI onto the min-heap
    /// free-list so `allocate_irqfd` can reuse it.
    ///
    /// Idempotent: if `gsi` is not found in the irqfds list, logs a warning and
    /// returns `Ok(())` without panicking — safe for double-release scenarios.
    ///
    /// # Ordering
    /// (1) unregister irqfd → (2) remove routing entry → (3) commit routes →
    /// (4) push to free-list. The free-list push is last to ensure the GSI is
    /// only reusable after the kernel has fully torn down the old routing.
    #[cfg(all(test, target_arch = "x86_64"))]
    fn release_irqfd(&mut self, gsi: u32) -> Result<(), IrqError> {
        // Find the irqfd entry for this GSI.
        let pos = self.irqfds.iter().position(|(g, _)| *g == gsi);
        if let Some(idx) = pos {
            let (_, fd) = self.irqfds.remove(idx);
            // (1) Unregister irqfd with KVM.
            self.vm_fd
                .unregister_irqfd(&fd, gsi)
                .map_err(IrqError::KvmIrqfd)?;
        } else {
            // Idempotent: unknown GSI — log and return Ok.
            log::warn!(
                "release_irqfd: GSI {} not found — already released or never allocated",
                gsi
            );
            return Ok(());
        }
        // (2) Remove the MSI routing entry.
        self.routes
            .retain(|e| !(e.gsi == gsi && e.type_ == KVM_IRQ_ROUTING_MSI));
        // (3) Commit the updated routing table.
        self.commit_routes()?;
        // (4) Return GSI to the free-list (min-heap via Reverse wrapper).
        self.free_gsis.push(Reverse(gsi));
        Ok(())
    }

    /// Release a set of irqfds belonging to a single device (per-device teardown).
    ///
    /// Calls `release_irqfd` for each GSI in `gsis`. Each GSI is unregistered,
    /// its MSI routing entry removed, and its GSI returned to the free-list for
    /// reuse by subsequent `allocate_irqfd` calls.
    ///
    /// An empty slice is a no-op. Unknown GSIs are handled idempotently (via
    /// `release_irqfd`'s own idempotency guarantee).
    ///
    /// Use this for backend respawn: call with all GSIs allocated for the crashed
    /// backend, then reallocate them for the replacement backend.
    #[cfg(all(test, target_arch = "x86_64"))]
    fn teardown_device_irqfds(&mut self, gsis: &[u32]) -> Result<(), IrqError> {
        for &gsi in gsis {
            self.release_irqfd(gsi)?;
        }
        Ok(())
    }

    /// Returns the current number of routing entries.
    #[cfg(all(test, target_arch = "x86_64"))]
    fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Returns the current routing table entries (for testing).
    #[cfg(all(test, target_arch = "x86_64"))]
    fn routes(&self) -> &[kvm_irq_routing_entry] {
        &self.routes
    }

    /// Atomically replace the KVM GSI routing table with our current entries.
    fn commit_routes(&mut self) -> Result<(), IrqError> {
        let mut routing = kvm_bindings::KvmIrqRouting::new(self.routes.len())
            .map_err(|_| IrqError::RoutingAllocation)?;
        let entries = routing.as_mut_slice();
        for (i, entry) in self.routes.iter().enumerate() {
            entries[i] = *entry;
        }
        self.vm_fd
            .set_gsi_routing(&routing)
            .map_err(IrqError::KvmRouting)
    }
}

/// Number of default irqchip routing entries (PIC master 8 + PIC slave 8 + IOAPIC 24).
#[cfg(all(test, target_arch = "x86_64"))]
const NUM_DEFAULT_ROUTES: usize = 40;

/// aarch64: an IRQCHIP routing entry mapping `gsi` to GIC SPI `pin`. KVM's
/// `vgic_irqfd_set_irq` injects INTID `pin` + 32, so `pin` is the SPI index
/// (INTID − 32). irqchip 0 is the single GICv3.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
fn make_spi_irqchip_entry(gsi: u32, pin: u32) -> kvm_irq_routing_entry {
    // SAFETY: see make_irqchip_entry — the union is zeroed then the `irqchip`
    // variant written, matching type_ == KVM_IRQ_ROUTING_IRQCHIP.
    let mut entry = kvm_irq_routing_entry {
        gsi,
        type_: KVM_IRQ_ROUTING_IRQCHIP,
        flags: 0,
        pad: 0,
        u: unsafe { std::mem::zeroed() },
    };
    entry.u.irqchip = kvm_irq_routing_irqchip { irqchip: 0, pin };
    entry
}

/// Create an irqchip routing entry mapping a GSI to a specific irqchip pin.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn make_irqchip_entry(gsi: u32, irqchip: u32, pin: u32) -> kvm_irq_routing_entry {
    // SAFETY: kvm_irq_routing_entry contains a union field `u`. We initialize
    // it to all-zeros via mem::zeroed(), which is a valid bit pattern for any
    // union variant (all variants are integer-field structs with no validity
    // invariants beyond their types). We then immediately write the `irqchip`
    // variant, which is the correct active variant when type_ == KVM_IRQ_ROUTING_IRQCHIP.
    let mut entry = kvm_irq_routing_entry {
        gsi,
        type_: KVM_IRQ_ROUTING_IRQCHIP,
        flags: 0,
        pad: 0,
        u: unsafe { std::mem::zeroed() },
    };
    entry.u.irqchip = kvm_irq_routing_irqchip { irqchip, pin };
    entry
}

/// Create an MSI routing entry for the given GSI.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn make_msi_entry(gsi: u32, addr_lo: u32, addr_hi: u32, data: u32) -> kvm_irq_routing_entry {
    // SAFETY: Same as make_irqchip_entry above. The union is zeroed then the
    // `msi` variant is written, matching type_ == KVM_IRQ_ROUTING_MSI.
    // Default::default() on kvm_irq_routing_msi zeroes the pad field.
    let mut entry = kvm_irq_routing_entry {
        gsi,
        type_: KVM_IRQ_ROUTING_MSI,
        flags: 0,
        pad: 0,
        u: unsafe { std::mem::zeroed() },
    };
    entry.u.msi = kvm_irq_routing_msi {
        address_lo: addr_lo,
        address_hi: addr_hi,
        data,
        ..Default::default()
    };
    entry
}

// These tests drive the x86 in-kernel IRQCHIP (IOAPIC/PIC defaults + MSI
// routing) via create_irq_chip/set_tss, which are x86-only KVM facilities.
#[cfg(all(test, target_arch = "x86_64"))]
#[allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]
mod tests {
    use super::*;
    use kvm_bindings::kvm_pit_config;

    /// Helper: create a minimal KVM VM suitable for irqfd tests.
    ///
    /// Returns (vm_fd arc, kvm instance) with irqchip + PIT2 configured.
    fn create_test_vm() -> Arc<VmFd> {
        let kvm = kvm_ioctls::Kvm::new().expect("open /dev/kvm");
        let vm = kvm.create_vm().expect("create VM");
        vm.set_tss_address(0xFFFB_C000).expect("set TSS");
        vm.set_identity_map_address(0xFFFB_8000)
            .expect("set identity map");
        vm.create_irq_chip().expect("create irqchip");
        vm.create_pit2(kvm_pit_config::default())
            .expect("create PIT2");
        Arc::new(vm)
    }

    #[test]
    fn new_initializes_default_irqchip_routes() {
        let vm_fd = create_test_vm();
        let mgr = IrqManager::new(vm_fd).unwrap();
        // 8 PIC master + 8 PIC slave + 24 IOAPIC = 40 default routes
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES);

        // All should be IRQCHIP type
        for entry in mgr.routes() {
            assert_eq!(entry.type_, KVM_IRQ_ROUTING_IRQCHIP);
        }

        // Verify IOAPIC entries exist for all 24 pins
        let ioapic_count = mgr
            .routes()
            .iter()
            .filter(|e| unsafe { e.u.irqchip.irqchip } == KVM_IRQCHIP_IOAPIC)
            .count();
        assert_eq!(ioapic_count, 24);
    }

    #[test]
    fn allocate_irqfd_returns_gsi_starting_at_24() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();

        let (gsi1, _fd1) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        assert_eq!(gsi1, 24);

        let (gsi2, _fd2) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        assert_eq!(gsi2, 25);
    }

    #[test]
    fn allocate_irqfd_preserves_ioapic_defaults() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();

        mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        // Should have 40 defaults + 1 MSI = 41
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES + 1);

        // First 40 should still be IRQCHIP
        for entry in &mgr.routes()[..NUM_DEFAULT_ROUTES] {
            assert_eq!(entry.type_, KVM_IRQ_ROUTING_IRQCHIP);
        }

        // Last entry should be MSI
        let msi_entry = &mgr.routes()[NUM_DEFAULT_ROUTES];
        assert_eq!(msi_entry.gsi, 24);
        assert_eq!(msi_entry.type_, KVM_IRQ_ROUTING_MSI);
        // SAFETY: We know these are MSI entries (type_ checked above).
        unsafe {
            assert_eq!(msi_entry.u.msi.address_lo, 0xFEE0_0000);
            assert_eq!(msi_entry.u.msi.data, 0x41);
        }
    }

    #[test]
    fn update_route_modifies_existing_msi_entry() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();

        let (gsi, _fd) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();

        // Update the route with new MSI address/data
        mgr.update_route(gsi, 0xFEE0_1000, 0, 0x42).unwrap();

        let msi_entry = mgr
            .routes()
            .iter()
            .find(|e| e.gsi == gsi && e.type_ == KVM_IRQ_ROUTING_MSI)
            .unwrap();
        // SAFETY: We know this is an MSI entry (type_ filtered above).
        unsafe {
            assert_eq!(msi_entry.u.msi.address_lo, 0xFEE0_1000);
            assert_eq!(msi_entry.u.msi.data, 0x42);
        }
    }

    #[test]
    fn teardown_irqfds_removes_msi_keeps_ioapic() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();

        mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES + 2);

        mgr.teardown_irqfds().unwrap();
        // Should be back to 40 default irqchip entries
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES);
        for entry in mgr.routes() {
            assert_eq!(entry.type_, KVM_IRQ_ROUTING_IRQCHIP);
        }
    }

    #[test]
    fn commit_routes_builds_correct_entry_count() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();

        // After new(): 40 default entries committed
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES);

        // After 2 allocations: 42 entries
        mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES + 2);
    }

    /// Verify that irqfd EventFds are created with EFD_CLOEXEC so they do not
    /// leak across exec() boundaries (prerequisite for exec-based reboot).
    ///
    /// This test checks the original FD (not a clone) by directly creating
    /// an EventFd with EFD_CLOEXEC and verifying the flag is set.
    #[test]
    fn eventfd_with_efd_cloexec_has_cloexec_flag() {
        use std::os::unix::io::AsRawFd;

        // Verify that EventFd::new(EFD_CLOEXEC) sets FD_CLOEXEC.
        let fd = EventFd::new(libc::EFD_CLOEXEC).unwrap();
        // SAFETY: fcntl(F_GETFD) is safe on any valid file descriptor.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) failed");
        assert!(
            flags & libc::FD_CLOEXEC != 0,
            "EventFd::new(EFD_CLOEXEC) must have FD_CLOEXEC set (flags={flags:#x})"
        );
    }

    /// Verify that EventFd::new(0) does NOT have FD_CLOEXEC (to confirm
    /// our fix to EFD_CLOEXEC is actually necessary).
    #[test]
    fn eventfd_without_efd_cloexec_lacks_cloexec_flag() {
        use std::os::unix::io::AsRawFd;

        let fd = EventFd::new(0).unwrap();
        // SAFETY: fcntl(F_GETFD) is safe on any valid file descriptor.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) failed");
        assert!(
            flags & libc::FD_CLOEXEC == 0,
            "EventFd::new(0) must NOT have FD_CLOEXEC set — if this fails, EFD_CLOEXEC is redundant"
        );
    }

    // ---- GSI reclaim tests (Task 1) ----

    #[test]
    fn allocate_irqfd_monotonic_without_freelist() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        let (gsi1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        let (gsi2, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        let (gsi3, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x43).unwrap();
        assert_eq!(gsi1, 24);
        assert_eq!(gsi2, 25);
        assert_eq!(gsi3, 26);
    }

    #[test]
    fn release_irqfd_returns_gsi_to_freelist() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        let (gsi1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        let (gsi2, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        assert_eq!(gsi1, 24);
        assert_eq!(gsi2, 25);
        // Release GSI 25
        mgr.release_irqfd(gsi2).unwrap();
        // Next allocation should return the reclaimed GSI 25
        let (gsi_new, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x43).unwrap();
        assert_eq!(gsi_new, 25, "should reuse released GSI 25");
    }

    #[test]
    fn release_irqfd_min_heap_ordering() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        let (gsi1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        let (gsi2, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        assert_eq!(gsi1, 24);
        assert_eq!(gsi2, 25);
        // Release 25 first, then 24 — min-heap should still return 24 first
        mgr.release_irqfd(gsi2).unwrap();
        mgr.release_irqfd(gsi1).unwrap();
        let (first, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x43).unwrap();
        let (second, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x44).unwrap();
        assert_eq!(
            first, 24,
            "min-heap: smallest GSI should be allocated first"
        );
        assert_eq!(second, 25);
    }

    #[test]
    fn release_irqfd_decreases_route_count() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        let (gsi, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES + 1);
        mgr.release_irqfd(gsi).unwrap();
        assert_eq!(
            mgr.route_count(),
            NUM_DEFAULT_ROUTES,
            "route count should decrease after release"
        );
    }

    #[test]
    fn release_irqfd_idempotent_on_unknown_gsi() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        // Release a GSI that was never allocated — should return Ok without panic
        let result = mgr.release_irqfd(99);
        assert!(
            result.is_ok(),
            "release_irqfd on unknown GSI should return Ok"
        );
    }

    #[test]
    fn release_irqfd_reallocation_creates_valid_route() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        let (gsi, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        mgr.release_irqfd(gsi).unwrap();
        // Reallocate — should create a valid routing entry for the reused GSI
        let (gsi2, _) = mgr.allocate_irqfd(0xFEE0_1000, 0, 0x99).unwrap();
        assert_eq!(gsi2, gsi, "should reuse the released GSI");
        let msi_entry = mgr
            .routes()
            .iter()
            .find(|e| e.gsi == gsi2 && e.type_ == KVM_IRQ_ROUTING_MSI)
            .expect("MSI routing entry must exist for reallocated GSI");
        // SAFETY: type_ is KVM_IRQ_ROUTING_MSI, so u.msi is the active variant.
        unsafe {
            assert_eq!(msi_entry.u.msi.address_lo, 0xFEE0_1000);
            assert_eq!(msi_entry.u.msi.data, 0x99);
        }
    }

    #[test]
    fn teardown_irqfds_still_works_after_release() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        let (gsi1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        let (gsi2, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        // Release one, then tear down everything
        mgr.release_irqfd(gsi1).unwrap();
        mgr.teardown_irqfds().unwrap();
        // Full teardown should remove all MSI entries (only gsi2 remains active)
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES);
        for entry in mgr.routes() {
            assert_eq!(entry.type_, KVM_IRQ_ROUTING_IRQCHIP);
        }
        let _ = gsi2;
    }

    // ---- teardown_device_irqfds tests (Task 2) ----

    #[test]
    fn teardown_device_irqfds_removes_only_specified_gsis() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        // Allocate 4 irqfds: GSI 24, 25, 26, 27
        let (gsi0, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        let (gsi1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        let (gsi2, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x43).unwrap();
        let (gsi3, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x44).unwrap();
        assert_eq!(mgr.route_count(), NUM_DEFAULT_ROUTES + 4);

        // Tear down only gsi1 and gsi2
        mgr.teardown_device_irqfds(&[gsi1, gsi2]).unwrap();
        assert_eq!(
            mgr.route_count(),
            NUM_DEFAULT_ROUTES + 2,
            "only 2 of 4 MSI routes should remain"
        );

        // gsi0 and gsi3 should still have MSI routing entries
        let has_gsi0 = mgr
            .routes()
            .iter()
            .any(|e| e.gsi == gsi0 && e.type_ == KVM_IRQ_ROUTING_MSI);
        let has_gsi3 = mgr
            .routes()
            .iter()
            .any(|e| e.gsi == gsi3 && e.type_ == KVM_IRQ_ROUTING_MSI);
        assert!(has_gsi0, "gsi0 should still have an MSI route");
        assert!(has_gsi3, "gsi3 should still have an MSI route");
    }

    #[test]
    fn teardown_device_irqfds_empty_slice_is_noop() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        let count_before = mgr.route_count();

        mgr.teardown_device_irqfds(&[]).unwrap();
        assert_eq!(
            mgr.route_count(),
            count_before,
            "empty slice teardown must be a no-op"
        );
    }

    #[test]
    fn teardown_device_irqfds_keeps_gsi_count_bounded() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();

        // Run 10 cycles of allocate 3 + teardown 3
        // After the first cycle GSIs 24, 25, 26 are freed and reused from free-list.
        // next_gsi should never exceed 27 (24 + 3 fresh allocations before any free-list entries).
        for _ in 0..10 {
            let (g0, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
            let (g1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
            let (g2, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x43).unwrap();
            mgr.teardown_device_irqfds(&[g0, g1, g2]).unwrap();
        }
        // After all cycles, no MSI routes should remain (all returned to free-list)
        assert_eq!(
            mgr.route_count(),
            NUM_DEFAULT_ROUTES,
            "all MSI routes should be freed"
        );
        // next_gsi bounded: 3 fresh GSIs on first cycle, then all reused from free-list.
        // Allocate once more to verify reuse (GSI must be from free-list, not >= 27).
        let (recycled, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x45).unwrap();
        assert!(
            recycled < 27,
            "GSI must be recycled from free-list after 10 allocate+teardown cycles, got {recycled}"
        );
    }

    #[test]
    fn teardown_device_irqfds_released_gsis_available_for_realloc() {
        let vm_fd = create_test_vm();
        let mut mgr = IrqManager::new(vm_fd).unwrap();
        let (gsi0, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x41).unwrap();
        let (gsi1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x42).unwrap();
        assert_eq!(gsi0, 24);
        assert_eq!(gsi1, 25);

        mgr.teardown_device_irqfds(&[gsi1, gsi0]).unwrap();

        // Both GSIs should be back in the free-list; min-heap returns 24 first
        let (new0, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x43).unwrap();
        let (new1, _) = mgr.allocate_irqfd(0xFEE0_0000, 0, 0x44).unwrap();
        assert_eq!(new0, 24, "smallest GSI reallocated first");
        assert_eq!(new1, 25, "second GSI reallocated next");
    }
}
