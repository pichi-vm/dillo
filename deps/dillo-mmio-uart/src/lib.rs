// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ns16550a UART emulation (MMIO), `Platform`-driven attach.
//!
//! A 16550 backed by `vm-superio`'s `Serial`. The driver sees a register
//! file that responds to LCR/DLAB, the MCR loopback probe, IIR/FCR FIFO
//! control, and the LSR TX-ready bit — a hand-rolled stub fails one of
//! those probes and the kernel silently disables the console. Writes to
//! THR go to the configured host writer.
//!
//! Per the arma device model (see `arma/docs/device-model.md` §"Serial
//! port") the serial port is an **MMIO `ns16550a`** on every arch — there
//! is no legacy x86 `0x3f8` port-I/O UART. When the PMI Platform declares a
//! UART, dillo constructs an owned [`Ns16550`] with the node's register
//! window and attaches it to the MMIO bus (register `N` at offset
//! `N << reg_shift`). IRQ delivery is provided by the machine backend as a
//! resolved [`dillo_mmio::Interrupt`].
//!
//! ## THR-empty interrupt on enable
//!
//! A real 16550 asserts the THR-empty (THRE) interrupt *whenever* that
//! interrupt is enabled in IER while the transmit holding register is empty
//! — not only when the driver writes a byte. `vm-superio` raises THRE only
//! from the THR-write path (it never re-asserts on the IER-enable edge), so
//! interrupt-driven `ttyS0` TX never receives its kick: once the polled
//! earlycon is disabled the guest blocks forever in `serial8250_start_tx`,
//! waiting for a THRE interrupt that never comes. We layer the missing
//! behaviour on top of `vm-superio` ([`Ns16550`]): the THR is always empty
//! for this virtual device, so whenever the driver enables THRI we pulse the
//! interrupt, and we surface THRE in IIR while THRI stays enabled and
//! `vm-superio` has nothing else pending. This is what makes the serial a
//! fully usable console rather than an early-boot-only channel.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, RwLock};

use vm_superio::Serial;
use vm_superio::Trigger;
use vm_superio::serial::NoEvents;

use dillo_mmio::{
    Interrupt, MmioDevice, MmioError, MmioInterrupt, MmioInterruptRequirement, MmioWindow,
    MmioWriteOutcome,
};

// 16550 register offsets and bits we post-process on top of vm-superio.
// Offsets are pre-`reg_shift` register indices (0..=7).
/// Transmit holding register (write, DLAB=0).
const REG_THR: u8 = 0;
/// Interrupt enable register (DLAB=0).
const REG_IER: u8 = 1;
/// Interrupt identification register (read).
const REG_IIR: u8 = 2;
/// Line control register (holds the DLAB bit).
const REG_LCR: u8 = 3;
/// IER bit: enable the THR-empty interrupt.
const IER_THRE: u8 = 0b0000_0010;
/// IIR bit0: set when *no* interrupt is pending.
const IIR_NO_INT: u8 = 0b0000_0001;
/// IIR id: THR-empty interrupt pending.
const IIR_THRE: u8 = 0b0000_0010;
/// IIR high bits reported when the FIFO (16550A) is enabled.
const IIR_FIFO: u8 = 0b1100_0000;
/// LCR bit: divisor-latch access (remaps offsets 0/1 to the baud divisor).
const LCR_DLAB: u8 = 0b1000_0000;

/// `vm-superio` trigger backed by an optional backend-resolved interrupt.
#[derive(Clone, Debug)]
struct InterruptTrigger {
    interrupt: Arc<RwLock<Option<Interrupt>>>,
}

impl InterruptTrigger {
    fn new(interrupt: Arc<RwLock<Option<Interrupt>>>) -> Self {
        Self { interrupt }
    }
}

impl Trigger for InterruptTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        if let Some(interrupt) = self
            .interrupt
            .read()
            .expect("UART interrupt lock poisoned")
            .as_ref()
        {
            interrupt.signal();
        }
        Ok(())
    }
}

type Mmio16550 = Serial<InterruptTrigger, NoEvents, Box<dyn Write + Send>>;

/// MMIO ns16550a: a `vm-superio` `Serial` plus the THR-empty-on-enable
/// emulation it lacks (see module docs).
pub struct Ns16550 {
    window: MmioWindow,
    interrupts: Vec<MmioInterruptRequirement>,
    interrupt: Arc<RwLock<Option<Interrupt>>>,
    state: Mutex<Ns16550State>,
}

impl std::fmt::Debug for Ns16550 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ns16550")
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl Ns16550 {
    pub fn new(
        window: MmioWindow,
        reg_shift: u32,
        interrupt: Option<Interrupt>,
        out: Box<dyn Write + Send>,
    ) -> Self {
        let interrupt = Arc::new(RwLock::new(interrupt));
        Self::with_serial(
            window,
            Vec::new(),
            Arc::clone(&interrupt),
            reg_shift,
            Serial::new(InterruptTrigger::new(interrupt), out),
        )
    }

    pub fn with_interrupt_requirement(
        window: MmioWindow,
        reg_shift: u32,
        interrupt: MmioInterruptRequirement,
        out: Box<dyn Write + Send>,
    ) -> Self {
        let interrupt_state = Arc::new(RwLock::new(None));
        Self::with_serial(
            window,
            vec![interrupt],
            Arc::clone(&interrupt_state),
            reg_shift,
            Serial::new(InterruptTrigger::new(interrupt_state), out),
        )
    }

    pub fn set_attachment(&self, attachment: &dyn dillo_mmio::MmioAttachment) {
        if let Some(MmioInterrupt::Line(interrupt)) = attachment.interrupts().first() {
            self.set_interrupt(Some(interrupt.clone()));
        }
    }

    pub fn set_interrupt(&self, interrupt: Option<Interrupt>) {
        *self
            .interrupt
            .write()
            .expect("UART interrupt lock poisoned") = interrupt;
    }

    fn with_serial(
        window: MmioWindow,
        interrupts: Vec<MmioInterruptRequirement>,
        interrupt: Arc<RwLock<Option<Interrupt>>>,
        reg_shift: u32,
        serial: Mmio16550,
    ) -> Self {
        Self {
            window,
            interrupts,
            interrupt,
            state: Mutex::new(Ns16550State::new(reg_shift, serial)),
        }
    }
}

impl MmioDevice for Ns16550 {
    fn windows(&self) -> &[MmioWindow] {
        std::slice::from_ref(&self.window)
    }

    fn interrupts(&self) -> &[MmioInterruptRequirement] {
        &self.interrupts
    }

    fn read(&self, _window: MmioWindow, offset: u64, data: &mut [u8]) -> Result<(), MmioError> {
        data.fill(0);
        if let Some(slot) = data.first_mut()
            && let Ok(mut state) = self.state.lock()
        {
            *slot = state.read(offset);
        }
        Ok(())
    }

    fn write(
        &self,
        _window: MmioWindow,
        offset: u64,
        data: &[u8],
    ) -> Result<MmioWriteOutcome, MmioError> {
        if let Ok(mut state) = self.state.lock() {
            state.write(offset, data);
        }
        Ok(MmioWriteOutcome::Continue)
    }
}

struct Ns16550State {
    reg_shift: u32,
    serial: Mmio16550,
    /// Mirror of IER.THRE (DLAB-aware). When set, the THR-empty interrupt is
    /// enabled, so — the THR being permanently empty for this virtual device
    /// — we treat THRE as continuously assertable.
    thri_enabled: bool,
}

impl Ns16550State {
    fn new(reg_shift: u32, serial: Mmio16550) -> Self {
        Self {
            reg_shift,
            serial,
            thri_enabled: false,
        }
    }

    /// True when the divisor-latch is mapped over offsets 0/1.
    fn dlab(&mut self) -> bool {
        self.serial.read(REG_LCR) & LCR_DLAB != 0
    }

    /// MMIO write to the register file (`offset` within the node reg window).
    fn write(&mut self, offset: u64, data: &[u8]) {
        let Some(&byte) = data.first() else {
            return;
        };
        let reg = (offset >> self.reg_shift) as u8;
        let dlab = self.dlab();
        let _ = self.serial.write(reg, byte);
        match reg {
            // THR write — flush so the host sees the byte immediately.
            // vm-superio already asserted THRE for this write.
            REG_THR if !dlab => {
                let _ = self.serial.writer_mut().flush();
            }
            // IER write — track THRI and emulate the 16550's assert-on-enable:
            // a real UART raises THRE the instant THRI is enabled while THR is
            // empty. Pulse the interrupt on the disabled→enabled edge.
            REG_IER if !dlab => {
                let now = byte & IER_THRE != 0;
                if now && !self.thri_enabled {
                    let _ = self.serial.interrupt_evt().trigger();
                }
                self.thri_enabled = now;
            }
            _ => {}
        }
    }

    /// MMIO read from the register file.
    fn read(&mut self, offset: u64) -> u8 {
        let reg = (offset >> self.reg_shift) as u8;
        let value = self.serial.read(reg);
        // If THRI is enabled and vm-superio has nothing else pending, surface
        // THRE: the THR is always empty, so the interrupt is level-asserted.
        if reg == REG_IIR && value & IIR_NO_INT != 0 && self.thri_enabled {
            return IIR_THRE | IIR_FIFO;
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use dillo_mmio::{InterruptError, InterruptLine};

    #[derive(Debug)]
    struct CountLine {
        count: AtomicU64,
    }

    impl CountLine {
        fn new() -> Self {
            Self {
                count: AtomicU64::new(0),
            }
        }

        fn count(&self) -> u64 {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl InterruptLine for CountLine {
        fn signal(&self) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn set_level(&self, level: bool) -> Result<(), InterruptError> {
            if level {
                self.signal();
            }
            Ok(())
        }
    }

    /// Build an `Ns16550` whose trigger increments an observable counter.
    fn harness() -> (Ns16550State, Arc<CountLine>) {
        let line = Arc::new(CountLine::new());
        let out: Box<dyn Write + Send> = Box::new(io::sink());
        let interrupt = Arc::new(RwLock::new(Some(Interrupt::new(line.clone()))));
        let serial = Serial::new(InterruptTrigger::new(interrupt), out);
        (Ns16550State::new(0, serial), line)
    }

    /// Enabling THRI while THR is empty must immediately raise the interrupt
    /// (the behaviour vm-superio omits) and IIR must then report THRE — the
    /// 16550 contract `serial8250_start_tx` relies on for interrupt-driven TX.
    #[test]
    fn thri_enable_raises_thre_interrupt() {
        let (mut uart, line) = harness();

        // Nothing pending before THRI is enabled.
        assert_eq!(line.count(), 0, "spurious interrupt before enable");
        assert_eq!(uart.read(u64::from(REG_IIR)) & IIR_NO_INT, IIR_NO_INT);

        // Enable the THR-empty interrupt.
        uart.write(u64::from(REG_IER), &[IER_THRE]);

        // The enable edge must have fired the trigger exactly once...
        assert_eq!(line.count(), 1, "THRI enable did not fire the IRQ");
        // ...and IIR must identify it as the THR-empty interrupt.
        assert_eq!(uart.read(u64::from(REG_IIR)), IIR_THRE | IIR_FIFO);
    }

    /// THRE stays asserted while THRI is enabled (level-triggered): every IIR
    /// read with nothing else pending reports it, so a guest that re-checks
    /// after draining its buffer keeps making progress.
    #[test]
    fn thre_is_level_asserted_while_enabled() {
        let (mut uart, _efd) = harness();
        uart.write(u64::from(REG_IER), &[IER_THRE]);
        assert_eq!(uart.read(u64::from(REG_IIR)), IIR_THRE | IIR_FIFO);
        assert_eq!(uart.read(u64::from(REG_IIR)), IIR_THRE | IIR_FIFO);
    }

    /// Re-asserting an already-enabled THRI must not fire a fresh interrupt
    /// (edge-detected), and disabling it stops THRE being reported.
    #[test]
    fn thri_enable_is_edge_detected_and_clears() {
        let (mut uart, line) = harness();

        uart.write(u64::from(REG_IER), &[IER_THRE]);
        assert_eq!(line.count(), 1);

        // Writing the same enabled value again is not a fresh edge.
        uart.write(u64::from(REG_IER), &[IER_THRE]);
        assert_eq!(line.count(), 1, "non-edge write fired a spurious IRQ");

        // Disabling THRI stops THRE from being surfaced.
        uart.write(u64::from(REG_IER), &[0]);
        assert_eq!(uart.read(u64::from(REG_IIR)) & IIR_NO_INT, IIR_NO_INT);
    }

    /// While DLAB is set, offset 1 is the divisor-latch high byte, not IER —
    /// it must never be mistaken for a THRI enable.
    #[test]
    fn dlab_high_byte_is_not_an_ier_write() {
        let (mut uart, line) = harness();

        uart.write(u64::from(REG_LCR), &[LCR_DLAB]); // set DLAB
        uart.write(u64::from(REG_IER), &[IER_THRE]); // divisor high, not IER

        assert_eq!(line.count(), 0, "divisor write fired the THRE IRQ");
    }
}
