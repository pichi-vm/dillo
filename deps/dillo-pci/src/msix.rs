// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Portions derived from Firecracker (https://github.com/firecracker-microvm/firecracker),
// licensed under Apache-2.0 OR BSD-3-Clause.

//! MSI-X table, capability structure, and notifier trait.

/// MSI-X capability structure (as stored in PCI config space).
#[derive(Debug, Clone, Copy)]
pub struct MsixCap {
    /// Message Control register: table size (bits 10:0), function mask (bit 14), enable (bit 15).
    pub msg_ctl: u16,
    /// Table offset (bits 31:3) and BIR (bits 2:0).
    pub table_offset_bir: u32,
    /// PBA offset (bits 31:3) and BIR (bits 2:0).
    pub pba_offset_bir: u32,
}

/// A single MSI-X table entry (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
pub struct MsixTableEntry {
    /// Low 32 bits of the MSI message address.
    pub msg_addr_lo: u32,
    /// High 32 bits of the MSI message address.
    pub msg_addr_hi: u32,
    /// MSI message data (interrupt vector and delivery mode).
    pub msg_data: u32,
    /// Vector control: bit 0 is the per-vector mask bit.
    pub vector_ctl: u32,
}

impl MsixCap {
    /// Create a new MSI-X capability.
    ///
    /// `table_size` is the actual number of entries (1-based, stored as N-1 in msg_ctl).
    /// `table_bir` / `pba_bir` are BAR indicator registers (0-5).
    /// `table_offset` / `pba_offset` are QWORD-aligned offsets within the BAR.
    pub fn new(
        table_size: u16,
        table_bir: u8,
        table_offset: u32,
        pba_bir: u8,
        pba_offset: u32,
    ) -> Self {
        // msg_ctl bits 10:0 = table_size - 1 (0-based encoding)
        let msg_ctl = (table_size - 1) & 0x07FF;
        Self {
            msg_ctl,
            table_offset_bir: (table_offset & !0x7) | (table_bir as u32 & 0x7),
            pba_offset_bir: (pba_offset & !0x7) | (pba_bir as u32 & 0x7),
        }
    }

    /// Number of table entries (table_size + 1, since 0-based in msg_ctl).
    pub fn table_size(&self) -> u16 {
        (self.msg_ctl & 0x07FF) + 1
    }

    /// Whether MSI-X is enabled (bit 15 of msg_ctl).
    pub fn enabled(&self) -> bool {
        self.msg_ctl & (1 << 15) != 0
    }

    /// Set the enable bit.
    pub fn set_enabled(&mut self, enable: bool) {
        if enable {
            self.msg_ctl |= 1 << 15;
        } else {
            self.msg_ctl &= !(1 << 15);
        }
    }

    /// Whether function-level mask is set (bit 14 of msg_ctl).
    pub fn function_masked(&self) -> bool {
        self.msg_ctl & (1 << 14) != 0
    }
}

impl MsixTableEntry {
    /// Whether this vector is masked (bit 0 of vector_ctl).
    pub fn is_masked(&self) -> bool {
        self.vector_ctl & 1 != 0
    }

    /// Set the mask bit.
    pub fn set_masked(&mut self, masked: bool) {
        if masked {
            self.vector_ctl |= 1;
        } else {
            self.vector_ctl &= !1;
        }
    }
}

/// VMM-agnostic callback trait for MSI-X notifications.
///
/// dillo-pci never touches a machine backend directly. Instead, the VMM implements this trait
/// to receive notifications when vectors change or MSI-X enable state changes.
pub trait MsixNotifier: Send + Sync {
    /// Called when a vector's address/data/mask is updated by the guest.
    fn vector_updated(&self, vector: u16, entry: &MsixTableEntry);

    /// Called when MSI-X effective enable state changes.
    ///
    /// `enabled` is true when MSI-X is enabled AND function mask is clear.
    fn msix_enabled(&self, enabled: bool);

    /// Interrupt handle for a device completion on `vector`, when the backend
    /// can currently deliver that MSI-X vector.
    fn interrupt_for(&self, _vector: u16) -> Option<Interrupt> {
        None
    }
}

/// No-op notifier for testing and devices that don't need callbacks yet.
#[derive(Debug)]
pub struct NoopNotifier;

impl MsixNotifier for NoopNotifier {
    fn vector_updated(&self, _vector: u16, _entry: &MsixTableEntry) {}
    fn msix_enabled(&self, _enabled: bool) {}
}

/// MSI-X table emulation layer.
///
/// Manages MSI-X table entries and Pending Bit Array (PBA). Handles BAR MMIO
/// reads and writes, notifying the VMM via [`MsixNotifier`] on state changes.
///
/// Extracted from Firecracker's MsixConfig pattern (Apache-2.0 OR BSD-3-Clause).
#[derive(Debug)]
pub struct MsixTable {
    entries: Vec<MsixTableEntry>,
    /// Pending Bit Array: 1 bit per vector, packed into u64s.
    pba: Vec<u64>,
    function_masked: bool,
    enabled: bool,
    table_bir: u8,
    table_offset: u32,
    pba_bir: u8,
    pba_offset: u32,
}

impl MsixTable {
    /// Create a new MSI-X table with `num_vectors` entries.
    ///
    /// All entries start masked (vector_ctl bit 0 = 1). MSI-X starts disabled.
    /// `table_bir`/`pba_bir` are the BAR indices for table and PBA regions.
    /// `table_offset`/`pba_offset` are byte offsets within those BARs.
    pub fn new(
        num_vectors: u16,
        table_bir: u8,
        table_offset: u32,
        pba_bir: u8,
        pba_offset: u32,
    ) -> Self {
        let mut entries = Vec::with_capacity(num_vectors as usize);
        for _ in 0..num_vectors {
            let mut entry = MsixTableEntry::default();
            entry.set_masked(true); // All entries start masked per PCIe spec
            entries.push(entry);
        }
        // PBA: 1 bit per vector, packed into u64s
        let pba_len = (num_vectors as usize).div_ceil(64);
        Self {
            entries,
            pba: vec![0u64; pba_len],
            function_masked: false,
            enabled: false,
            table_bir,
            table_offset,
            pba_bir,
            pba_offset,
        }
    }

    /// Number of MSI-X vectors (table entries).
    pub fn num_vectors(&self) -> u16 {
        self.entries.len() as u16
    }

    /// Whether MSI-X is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the MsixCap for config space registration.
    pub fn cap(&self) -> MsixCap {
        MsixCap::new(
            self.num_vectors(),
            self.table_bir,
            self.table_offset,
            self.pba_bir,
            self.pba_offset,
        )
    }

    /// Whether a vector is effectively masked.
    ///
    /// A vector is masked if any of: MSI-X not enabled, function mask set,
    /// or per-vector mask bit set.
    pub fn is_vector_masked(&self, vector: u16) -> bool {
        if !self.enabled || self.function_masked {
            return true;
        }
        let idx = vector as usize;
        if idx >= self.entries.len() {
            return true;
        }
        self.entries[idx].is_masked()
    }

    /// Set the pending bit for a vector.
    ///
    /// Used by the VMM when an interrupt arrives while the vector is masked.
    pub fn set_pending(&mut self, vector: u16) {
        let idx = vector as usize;
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.pba.len() {
            self.pba[word] |= 1u64 << bit;
        }
    }

    /// Clear the pending bit for a vector.
    fn clear_pending(&mut self, vector: u16) {
        let idx = vector as usize;
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.pba.len() {
            self.pba[word] &= !(1u64 << bit);
        }
    }

    /// Set the MSI-X enable state and notify.
    pub fn set_enabled(&mut self, enabled: bool, notifier: &dyn MsixNotifier) {
        self.enabled = enabled;
        // Effective enable = enabled && !function_masked
        let effective = enabled && !self.function_masked;
        notifier.msix_enabled(effective);
    }

    /// Set the function mask state and notify.
    pub fn set_function_masked(&mut self, masked: bool, notifier: &dyn MsixNotifier) {
        self.function_masked = masked;
        // Effective enable = enabled && !function_masked
        let effective = self.enabled && !masked;
        notifier.msix_enabled(effective);
    }

    /// Handle guest writes to the MSI-X Message Control register.
    ///
    /// Detects changes to enable (bit 15) and function mask (bit 14) bits.
    pub fn write_msg_ctl(&mut self, msg_ctl: u16, notifier: &dyn MsixNotifier) {
        let new_enabled = msg_ctl & (1 << 15) != 0;
        let new_function_masked = msg_ctl & (1 << 14) != 0;

        if new_enabled != self.enabled {
            self.set_enabled(new_enabled, notifier);
        }
        if new_function_masked != self.function_masked {
            self.set_function_masked(new_function_masked, notifier);
        }
    }

    /// Handle a BAR MMIO read.
    ///
    /// Returns `true` if the `bar_idx` matches the table or PBA BAR and the
    /// access was handled. Table reads return entry fields as LE bytes.
    /// PBA reads return pending bits as LE u64. Out-of-range fills 0.
    pub fn bar_read(&self, bar_idx: u8, offset: u64, data: &mut [u8]) -> bool {
        if bar_idx == self.table_bir && offset >= self.table_offset as u64 {
            let table_off = offset - self.table_offset as u64;
            if bar_idx == self.pba_bir
                && table_off >= self.pba_offset as u64 - self.table_offset as u64
            {
                // Falls into PBA region (same BAR)
                let pba_off = offset - self.pba_offset as u64;
                self.read_pba(pba_off, data);
                return true;
            }
            self.read_table(table_off, data);
            return true;
        }
        if bar_idx == self.pba_bir {
            if offset >= self.pba_offset as u64 {
                let pba_off = offset - self.pba_offset as u64;
                self.read_pba(pba_off, data);
                return true;
            }
            // If table_bir != pba_bir, we still need to check table region
            return false;
        }
        false
    }

    /// Handle a BAR MMIO write.
    ///
    /// Returns `true` if the `bar_idx` matches and the access was handled.
    /// Table writes update entry fields and call `notifier.vector_updated()`.
    /// PBA writes are ignored (read-only from guest perspective).
    pub fn bar_write(
        &mut self,
        bar_idx: u8,
        offset: u64,
        data: &[u8],
        notifier: &dyn MsixNotifier,
    ) -> bool {
        if bar_idx == self.table_bir && offset >= self.table_offset as u64 {
            let table_off = offset - self.table_offset as u64;
            // Check if this falls in PBA region (same BAR case)
            if bar_idx == self.pba_bir && offset >= self.pba_offset as u64 {
                // PBA writes are ignored (read-only)
                return true;
            }
            self.write_table(table_off, data, notifier);
            return true;
        }
        if bar_idx == self.pba_bir && offset >= self.pba_offset as u64 {
            // PBA writes are ignored (read-only)
            return true;
        }
        false
    }

    /// Read from the MSI-X table region.
    fn read_table(&self, offset: u64, data: &mut [u8]) {
        let entry_idx = (offset / 16) as usize;
        let field_offset = (offset % 16) as usize;
        if entry_idx >= self.entries.len() {
            data.fill(0);
            return;
        }
        let entry = &self.entries[entry_idx];
        let field_val = match field_offset {
            0 => entry.msg_addr_lo,
            4 => entry.msg_addr_hi,
            8 => entry.msg_data,
            12 => entry.vector_ctl,
            _ => 0,
        };
        let bytes = field_val.to_le_bytes();
        let byte_off = field_offset % 4;
        for (i, d) in data.iter_mut().enumerate() {
            *d = if byte_off + i < 4 {
                bytes[byte_off + i]
            } else {
                0
            };
        }
    }

    /// Write to the MSI-X table region.
    fn write_table(&mut self, offset: u64, data: &[u8], notifier: &dyn MsixNotifier) {
        let entry_idx = (offset / 16) as usize;
        let field_offset = (offset % 16) as usize;
        if entry_idx >= self.entries.len() {
            return;
        }

        // Read current value, apply write, detect mask changes
        let was_masked = self.entries[entry_idx].is_masked();

        let entry = &mut self.entries[entry_idx];
        let field_val = match field_offset {
            0 => entry.msg_addr_lo,
            4 => entry.msg_addr_hi,
            8 => entry.msg_data,
            12 => entry.vector_ctl,
            _ => return,
        };

        // Apply partial write
        let mut bytes = field_val.to_le_bytes();
        let byte_off = field_offset % 4;
        for (i, &b) in data.iter().enumerate() {
            if byte_off + i < 4 {
                bytes[byte_off + i] = b;
            }
        }
        let new_val = u32::from_le_bytes(bytes);

        match field_offset {
            0 => entry.msg_addr_lo = new_val,
            4 => entry.msg_addr_hi = new_val,
            8 => entry.msg_data = new_val,
            12 => entry.vector_ctl = new_val,
            _ => {}
        }

        // If vector was unmasked (mask bit cleared), clear PBA pending bit
        let is_masked = entry.is_masked();
        if was_masked && !is_masked {
            self.clear_pending(entry_idx as u16);
        }

        let entry_copy = self.entries[entry_idx];
        notifier.vector_updated(entry_idx as u16, &entry_copy);
    }

    /// Read from the PBA region.
    fn read_pba(&self, offset: u64, data: &mut [u8]) {
        let qword_idx = (offset / 8) as usize;
        if qword_idx >= self.pba.len() {
            data.fill(0);
            return;
        }
        let val = self.pba[qword_idx];
        let bytes = val.to_le_bytes();
        let byte_off = (offset % 8) as usize;
        for (i, d) in data.iter_mut().enumerate() {
            *d = if byte_off + i < 8 {
                bytes[byte_off + i]
            } else {
                0
            };
        }
    }
}
use dillo_mmio::Interrupt;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn msix_cap_table_size() {
        let cap = MsixCap::new(4, 0, 0, 0, 0);
        assert_eq!(cap.table_size(), 4);
    }

    #[test]
    fn msix_cap_enable() {
        let mut cap = MsixCap::new(1, 0, 0, 0, 0);
        assert!(!cap.enabled());
        cap.set_enabled(true);
        assert!(cap.enabled());
        cap.set_enabled(false);
        assert!(!cap.enabled());
    }

    #[test]
    fn msix_cap_function_mask() {
        let cap = MsixCap::new(1, 0, 0, 0, 0);
        assert!(!cap.function_masked());
    }

    #[test]
    fn msix_table_entry_mask() {
        let mut entry = MsixTableEntry::default();
        assert!(!entry.is_masked());
        entry.set_masked(true);
        assert!(entry.is_masked());
        entry.set_masked(false);
        assert!(!entry.is_masked());
    }

    #[test]
    fn msix_cap_bir_and_offset() {
        let cap = MsixCap::new(8, 2, 0x1000, 3, 0x2000);
        assert_eq!(cap.table_offset_bir & 0x7, 2, "table BIR");
        assert_eq!(cap.table_offset_bir & !0x7, 0x1000, "table offset");
        assert_eq!(cap.pba_offset_bir & 0x7, 3, "PBA BIR");
        assert_eq!(cap.pba_offset_bir & !0x7, 0x2000, "PBA offset");
    }

    // --- Recording notifier for tests ---

    struct RecordingNotifier {
        vector_updates: Mutex<Vec<(u16, MsixTableEntry)>>,
        enable_calls: Mutex<Vec<bool>>,
    }

    impl RecordingNotifier {
        fn new() -> Self {
            Self {
                vector_updates: Mutex::new(Vec::new()),
                enable_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl MsixNotifier for RecordingNotifier {
        fn vector_updated(&self, vector: u16, entry: &MsixTableEntry) {
            self.vector_updates.lock().unwrap().push((vector, *entry));
        }

        fn msix_enabled(&self, enabled: bool) {
            self.enable_calls.lock().unwrap().push(enabled);
        }
    }

    // --- MsixTable tests ---

    #[test]
    fn msix_table_new_creates_correct_capacity() {
        let table = MsixTable::new(4, 0, 0, 0, 0x1000);
        assert_eq!(table.num_vectors(), 4);
        assert!(!table.enabled());
    }

    #[test]
    fn msix_table_entries_start_masked() {
        let table = MsixTable::new(2, 0, 0, 0, 0x1000);
        assert!(table.is_vector_masked(0));
        assert!(table.is_vector_masked(1));
    }

    #[test]
    fn msix_table_bar_read_entry_addr_lo() {
        let mut table = MsixTable::new(1, 2, 0, 2, 0x1000);
        let notifier = NoopNotifier;
        // Write addr_lo via bar_write
        let val: u32 = 0xFEE0_0000;
        assert!(table.bar_write(2, 0, &val.to_le_bytes(), &notifier));
        // Read it back
        let mut buf = [0u8; 4];
        assert!(table.bar_read(2, 0, &mut buf));
        assert_eq!(u32::from_le_bytes(buf), 0xFEE0_0000);
    }

    #[test]
    fn msix_table_bar_read_all_fields() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = NoopNotifier;
        // Write all four fields
        table.bar_write(0, 0, &0xFEE0_1000u32.to_le_bytes(), &notifier); // addr_lo
        table.bar_write(0, 4, &0x0000_0000u32.to_le_bytes(), &notifier); // addr_hi
        table.bar_write(0, 8, &0x0000_0041u32.to_le_bytes(), &notifier); // data
        table.bar_write(0, 12, &0x0000_0001u32.to_le_bytes(), &notifier); // vector_ctl (masked)

        let mut buf = [0u8; 4];
        table.bar_read(0, 0, &mut buf);
        assert_eq!(u32::from_le_bytes(buf), 0xFEE0_1000, "addr_lo");
        table.bar_read(0, 4, &mut buf);
        assert_eq!(u32::from_le_bytes(buf), 0x0000_0000, "addr_hi");
        table.bar_read(0, 8, &mut buf);
        assert_eq!(u32::from_le_bytes(buf), 0x0000_0041, "data");
        table.bar_read(0, 12, &mut buf);
        assert_eq!(u32::from_le_bytes(buf), 0x0000_0001, "vector_ctl");
    }

    #[test]
    fn msix_table_bar_read_beyond_table_returns_zero() {
        let table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let mut buf = [0xFFu8; 4];
        // Entry 0 is at offset 0..16. Offset 16 is beyond.
        assert!(table.bar_read(0, 16, &mut buf));
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn msix_table_bar_write_calls_notifier() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = RecordingNotifier::new();
        let val: u32 = 0xFEE0_0000;
        table.bar_write(0, 0, &val.to_le_bytes(), &notifier);
        let updates = notifier.vector_updates.lock().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, 0); // vector 0
        assert_eq!(updates[0].1.msg_addr_lo, 0xFEE0_0000);
    }

    #[test]
    fn msix_table_bar_write_vector_ctl_sets_mask() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = NoopNotifier;
        // Initially masked (entries start masked)
        assert!(table.is_vector_masked(0));
        // Unmask
        table.bar_write(0, 12, &0u32.to_le_bytes(), &notifier);
        // Still masked because !enabled, but per-vector mask is off
        let mut buf = [0u8; 4];
        table.bar_read(0, 12, &mut buf);
        assert_eq!(u32::from_le_bytes(buf), 0);
    }

    #[test]
    fn msix_table_pba_read() {
        let mut table = MsixTable::new(4, 0, 0, 0, 0x1000);
        // Set pending on vector 1
        table.set_pending(1);
        let mut buf = [0u8; 8];
        assert!(table.bar_read(0, 0x1000, &mut buf));
        let pba = u64::from_le_bytes(buf);
        assert_eq!(pba & (1 << 1), 2, "vector 1 pending bit should be set");
        assert_eq!(pba & (1 << 0), 0, "vector 0 pending bit should be clear");
    }

    #[test]
    fn msix_table_pba_cleared_on_unmask() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = NoopNotifier;
        table.set_pending(0);
        // Unmask vector 0 via bar_write to vector_ctl
        table.bar_write(0, 12, &0u32.to_le_bytes(), &notifier);
        let mut buf = [0u8; 8];
        table.bar_read(0, 0x1000, &mut buf);
        let pba = u64::from_le_bytes(buf);
        assert_eq!(pba, 0, "PBA should be cleared after unmask");
    }

    #[test]
    fn msix_table_bar_read_wrong_bar_returns_false() {
        let table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let mut buf = [0u8; 4];
        assert!(!table.bar_read(3, 0, &mut buf));
    }

    #[test]
    fn msix_table_bar_write_wrong_bar_returns_false() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = NoopNotifier;
        assert!(!table.bar_write(3, 0, &[0; 4], &notifier));
    }

    #[test]
    fn msix_table_set_enabled_calls_notifier() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = RecordingNotifier::new();
        table.set_enabled(true, &notifier);
        assert!(table.enabled());
        let calls = notifier.enable_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0]);
    }

    #[test]
    fn msix_table_set_function_masked_calls_notifier_disabled() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = RecordingNotifier::new();
        table.set_enabled(true, &notifier);
        table.set_function_masked(true, &notifier);
        let calls = notifier.enable_calls.lock().unwrap();
        // set_enabled(true) -> msix_enabled(true)
        // set_function_masked(true) -> msix_enabled(false)
        assert_eq!(calls.len(), 2);
        assert!(calls[0]);
        assert!(!calls[1]);
    }

    #[test]
    fn msix_table_cap_returns_correct_values() {
        let table = MsixTable::new(4, 2, 0x1000, 3, 0x2000);
        let cap = table.cap();
        assert_eq!(cap.table_size(), 4);
        assert_eq!(cap.table_offset_bir & 0x7, 2);
        assert_eq!(cap.table_offset_bir & !0x7, 0x1000);
        assert_eq!(cap.pba_offset_bir & 0x7, 3);
        assert_eq!(cap.pba_offset_bir & !0x7, 0x2000);
    }

    #[test]
    fn msix_table_write_msg_ctl_enable() {
        let mut table = MsixTable::new(4, 0, 0, 0, 0x1000);
        let notifier = RecordingNotifier::new();
        // Set enable bit (bit 15) in msg_ctl
        table.write_msg_ctl(0x8003, &notifier); // 0x8000 = enable, 0x0003 = table_size field (ignored)
        assert!(table.enabled());
        let calls = notifier.enable_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0]);
    }

    #[test]
    fn msix_table_write_msg_ctl_function_mask() {
        let mut table = MsixTable::new(4, 0, 0, 0, 0x1000);
        let notifier = RecordingNotifier::new();
        // Enable + function mask (bits 15 and 14)
        table.write_msg_ctl(0xC003, &notifier);
        assert!(table.enabled());
        let calls = notifier.enable_calls.lock().unwrap();
        // Enable changed (false -> true) -> msix_enabled(true)
        // Then function_masked changed (false -> true) -> msix_enabled(false) (effectively disabled)
        assert_eq!(calls.len(), 2);
        assert!(calls[0]); // enabled
        assert!(!calls[1]); // function masked -> effectively disabled
    }

    #[test]
    fn msix_table_is_vector_masked_considers_function_mask() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = NoopNotifier;
        table.set_enabled(true, &notifier);
        // Unmask per-vector
        table.bar_write(0, 12, &0u32.to_le_bytes(), &notifier);
        assert!(!table.is_vector_masked(0));
        // Set function mask
        table.set_function_masked(true, &notifier);
        assert!(table.is_vector_masked(0));
    }

    #[test]
    fn msix_table_is_vector_masked_considers_enabled() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = NoopNotifier;
        // Unmask per-vector but don't enable MSI-X
        table.bar_write(0, 12, &0u32.to_le_bytes(), &notifier);
        assert!(
            table.is_vector_masked(0),
            "should be masked when MSI-X not enabled"
        );
    }

    #[test]
    fn noop_notifier_compiles() {
        let notifier = NoopNotifier;
        let entry = MsixTableEntry::default();
        notifier.vector_updated(0, &entry);
        notifier.msix_enabled(true);
    }

    #[test]
    fn msix_table_pba_write_ignored() {
        let mut table = MsixTable::new(1, 0, 0, 0, 0x1000);
        let notifier = NoopNotifier;
        table.set_pending(0);
        // Try to write PBA (should be ignored, PBA is read-only)
        assert!(table.bar_write(0, 0x1000, &0u64.to_le_bytes(), &notifier));
        // PBA bit should still be set
        let mut buf = [0u8; 8];
        table.bar_read(0, 0x1000, &mut buf);
        let pba = u64::from_le_bytes(buf);
        assert_eq!(pba & 1, 1, "PBA write should be ignored");
    }

    #[test]
    fn msix_table_separate_table_pba_bars() {
        // Table on BAR 0, PBA on BAR 2
        let mut table = MsixTable::new(2, 0, 0, 2, 0);
        let notifier = NoopNotifier;
        // Write to table on BAR 0
        assert!(table.bar_write(0, 0, &0xFEE0_0000u32.to_le_bytes(), &notifier));
        // Read PBA from BAR 2
        table.set_pending(0);
        let mut buf = [0u8; 8];
        assert!(table.bar_read(2, 0, &mut buf));
        let pba = u64::from_le_bytes(buf);
        assert_eq!(pba & 1, 1);
        // BAR 1 should not match
        assert!(!table.bar_read(1, 0, &mut buf));
    }
}
