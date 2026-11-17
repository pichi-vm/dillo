// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use dillo_machine::{LaunchConfig, Memory, RamRange};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;

const PROFILE: CpuProfile = CpuProfile::X86_64(pmi::x86_64::Profile::V1);

#[derive(Clone, Copy, Debug)]
enum Behavior {
    Stop,
    Wait,
    Panic,
    PrepareError,
    PreparePanic,
    FailAfterPeer,
    AdmissionFailure(AdmissionRefusal),
    LostFirstInterrupt,
    CoObserved(Outcome),
}
#[derive(Clone, Copy, Debug)]
enum AdmissionRefusal {
    MissingFeature,
    MissingEvidence,
    V81MissingEvidence,
    V81MissingFeature,
    Contradiction,
    UnsupportedProfile,
}
#[derive(Clone, Copy, Debug)]
enum Outcome {
    Poweroff,
    Reset,
    Failure,
    OperatorTermination,
}
#[derive(Clone, Debug)]
enum Event {
    Prepared(usize, thread::ThreadId),
    Entered(usize),
    Returning(usize),
    Window,
    Destroyed(usize, thread::ThreadId),
    MachinePrepared,
}
#[derive(Debug)]
struct Trace {
    events: Mutex<Vec<Event>>,
    changed: Condvar,
    kicks: AtomicUsize,
    panic_on_interrupt: AtomicBool,
    operator_shutdown: AtomicBool,
}
impl Trace {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            changed: Condvar::new(),
            kicks: AtomicUsize::new(0),
            panic_on_interrupt: AtomicBool::new(false),
            operator_shutdown: AtomicBool::new(false),
        })
    }
    fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
        self.changed.notify_all();
    }
    fn wait(&self, predicate: impl Fn(&[Event]) -> bool) {
        let mut events = self.events.lock().unwrap();
        while !predicate(&events) {
            let (next, deadline) = self
                .changed
                .wait_timeout(events, Duration::from_secs(2))
                .unwrap();
            events = next;
            assert!(
                !deadline.timed_out(),
                "test synchronization timed out: {events:?}"
            );
        }
    }
    fn assert_no_entry_and_owners_destroyed(&self) {
        let events = self.events.lock().unwrap();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Entered(_))),
            "{events:?}"
        );
        for event in events.iter() {
            if let Event::Prepared(index, owner) = event {
                assert!(events.iter().any(|e| matches!(e, Event::Destroyed(i, thread) if i == index && thread == owner)), "{events:?}");
                assert_ne!(*owner, thread::current().id());
            }
        }
    }
}
impl CpuTermination for Trace {
    fn is_requested(&self) -> bool {
        self.operator_shutdown.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
struct Interrupt {
    trace: Arc<Trace>,
}
impl CpuInterrupt for Interrupt {
    type Error = std::io::Error;
    fn interrupt(&self) -> Result<(), Self::Error> {
        assert!(
            !self.trace.panic_on_interrupt.swap(false, Ordering::AcqRel),
            "injected native interrupt panic"
        );
        self.trace.kicks.fetch_add(1, Ordering::Release);
        self.trace.changed.notify_all();
        Ok(())
    }
}
struct Input {
    index: usize,
    behavior: Behavior,
    trace: Arc<Trace>,
}
impl CpuPreparation for Input {
    type Error = std::io::Error;
    type Interrupt = Interrupt;
    type Runner = Runner;
    fn interrupt(&self) -> Interrupt {
        Interrupt {
            trace: Arc::clone(&self.trace),
        }
    }
    fn prepare(self) -> Result<Runner, Self::Error> {
        match self.behavior {
            Behavior::PrepareError => {
                return Err(std::io::Error::other("injected preparation error"));
            }
            Behavior::PreparePanic => panic!("injected preparation panic"),
            Behavior::AdmissionFailure(refusal) => {
                use dillo_machine::aarch64::{AdmissionError, CpuSnapshot, Register};
                self.trace.wait(|events| {
                    events
                        .iter()
                        .any(|event| matches!(event, Event::Prepared(0, _)))
                });
                let profile = if matches!(refusal, AdmissionRefusal::UnsupportedProfile) {
                    pmi::aarch64::Profile::V8_2
                } else if matches!(
                    refusal,
                    AdmissionRefusal::V81MissingEvidence | AdmissionRefusal::V81MissingFeature
                ) {
                    pmi::aarch64::Profile::V8_1
                } else {
                    pmi::aarch64::Profile::V8_0
                };
                let result = CpuSnapshot::capture(|register| {
                    if register == Register::Mmfr1
                        && matches!(refusal, AdmissionRefusal::V81MissingEvidence)
                    {
                        return Err(AdmissionError::Unavailable {
                            register,
                            reason: "injected missing MMFR1 selector".into(),
                        });
                    }
                    if register == Register::Ctr
                        && matches!(refusal, AdmissionRefusal::MissingEvidence)
                    {
                        return Err(AdmissionError::Unavailable {
                            register,
                            reason: "injected missing native selector".into(),
                        });
                    }
                    Ok(match register {
                        Register::Pfr0 if matches!(refusal, AdmissionRefusal::Contradiction) => {
                            0x00f0_0011
                        }
                        Register::Pfr0 => 0x11,
                        Register::Ctr if matches!(refusal, AdmissionRefusal::MissingFeature) => {
                            1 << 14
                        }
                        Register::Ctr => 3 << 14,
                        Register::Isar0
                            if matches!(refusal, AdmissionRefusal::V81MissingFeature) =>
                        {
                            (1 << 16) | (2 << 20) | (1 << 28)
                        }
                        Register::Mmfr1
                            if matches!(refusal, AdmissionRefusal::V81MissingFeature) =>
                        {
                            (1 << 12) | (1 << 20)
                        }
                        _ => 0,
                    })
                })
                .and_then(|snapshot| snapshot.admit(profile));
                return Err(std::io::Error::other(result.unwrap_err()));
            }
            Behavior::FailAfterPeer => {
                self.trace
                    .wait(|events| events.iter().any(|e| matches!(e, Event::Prepared(0, _))));
                return Err(std::io::Error::other("injected delayed preparation error"));
            }
            _ => {}
        }
        self.trace
            .record(Event::Prepared(self.index, thread::current().id()));
        Ok(Runner {
            index: self.index,
            behavior: self.behavior,
            trace: self.trace,
            _owner: PhantomData,
        })
    }
}
struct Runner {
    index: usize,
    behavior: Behavior,
    trace: Arc<Trace>,
    _owner: PhantomData<Rc<()>>,
}
impl CpuRunner for Runner {
    type Error = std::io::Error;
    fn run(&mut self, termination: &dyn CpuTermination) -> Result<VcpuStop, Self::Error> {
        if termination.is_requested() {
            return Ok(VcpuStop::Stopped);
        }
        if matches!(self.behavior, Behavior::LostFirstInterrupt) {
            // Simulate a cancel arriving after the permission check but before
            // native entry: the first native cancel is lost, the next must wake.
            self.trace.record(Event::Window);
            while self.trace.kicks.load(Ordering::Acquire) < 2 {
                thread::yield_now();
            }
            assert!(
                termination.is_requested(),
                "termination must precede native kicks"
            );
            return Ok(VcpuStop::Stopped);
        }
        self.trace.record(Event::Entered(self.index));
        match self.behavior {
            Behavior::Panic => {
                self.trace
                    .wait(|events| events.iter().any(|e| matches!(e, Event::Entered(0))));
                panic!("injected owner panic while peer is active");
            }
            Behavior::Stop => Ok(VcpuStop::GuestPoweroff),
            Behavior::CoObserved(outcome) => {
                // Neither owner returns until both have entered. Termination
                // after this rendezvous must not discard either observed exit.
                self.trace.wait(|events| {
                    (0..2).all(|index| {
                        events
                            .iter()
                            .any(|event| matches!(event, Event::Entered(i) if *i == index))
                    })
                });
                self.trace.record(Event::Returning(self.index));
                match outcome {
                    Outcome::Poweroff => Ok(VcpuStop::GuestPoweroff),
                    Outcome::Reset => Ok(VcpuStop::GuestReset),
                    Outcome::Failure => Err(std::io::Error::other("co-observed owner failure")),
                    Outcome::OperatorTermination => {
                        self.trace.operator_shutdown.store(true, Ordering::Release);
                        Ok(VcpuStop::Stopped)
                    }
                }
            }
            _ => {
                let mut events = self.trace.events.lock().unwrap();
                while !termination.is_requested() {
                    events = self
                        .trace
                        .changed
                        .wait_timeout(events, POLL_INTERVAL)
                        .unwrap()
                        .0;
                }
                Ok(VcpuStop::Stopped)
            }
        }
    }
}
impl Drop for Runner {
    fn drop(&mut self) {
        self.trace
            .record(Event::Destroyed(self.index, thread::current().id()));
    }
}
struct TestMemory;
impl Memory for TestMemory {
    type Error = std::io::Error;
    fn from_ranges(_: &[RamRange]) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}
struct TestMachine {
    trace: Arc<Trace>,
    behaviors: Vec<Behavior>,
    construction_error: Option<usize>,
    machine_error: bool,
    machine_panic: bool,
    construction_panic: Option<usize>,
}
impl TestMachine {
    fn new(behaviors: Vec<Behavior>) -> Self {
        Self {
            trace: Trace::new(),
            behaviors,
            construction_error: None,
            machine_error: false,
            machine_panic: false,
            construction_panic: None,
        }
    }
}
impl Machine for TestMachine {
    type Error = std::io::Error;
    type CpuPreparation = Input;
    type Memory = TestMemory;
    fn cpu_preparation(&mut self, index: u32, _: CpuProfile) -> Result<Input, Self::Error> {
        assert_ne!(
            self.construction_panic,
            Some(index as usize),
            "injected CPU input construction panic"
        );
        if self.construction_error == Some(index as usize) {
            return Err(std::io::Error::other(
                "injected CPU input construction error",
            ));
        }
        Ok(Input {
            index: index as usize,
            behavior: self.behaviors[index as usize],
            trace: Arc::clone(&self.trace),
        })
    }
    fn guest_address_bits() -> Result<u32, Self::Error> {
        Ok(48)
    }
    fn from_launch_config(_: LaunchConfig) -> Result<Self, Self::Error> {
        unreachable!("tests construct their receiver")
    }
    fn write_guest(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
    fn zero_guest(&mut self, _: u64, _: u64) -> Result<(), Self::Error> {
        Ok(())
    }
    fn prepare_vcpu_run(&mut self) -> Result<(), Self::Error> {
        self.trace.assert_no_entry();
        self.trace.record(Event::MachinePrepared);
        assert!(!self.machine_panic, "injected machine preparation panic");
        if self.machine_error {
            Err(std::io::Error::other("injected machine preparation error"))
        } else {
            Ok(())
        }
    }
}
impl Trace {
    fn assert_no_entry(&self) {
        assert!(
            !self
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, Event::Entered(_)))
        );
    }
}

#[test]
fn initial_gate_includes_machine_preparation_and_preserves_owner_affinity() {
    let mut machine = TestMachine::new(vec![Behavior::Stop, Behavior::Wait]);
    let trace = Arc::clone(&machine.trace);
    let prepared = PreparingCpus::spawn(&mut machine, 2, PROFILE)
        .unwrap()
        .prepare(&AtomicBool::new(false))
        .unwrap();
    assert!(
        !trace
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Entered(_)))
    );
    assert_eq!(
        prepared.run(&AtomicBool::new(false)).unwrap(),
        VcpuStop::GuestPoweroff
    );
    let events = trace.events.lock().unwrap();
    let machine_prepared = events
        .iter()
        .position(|e| matches!(e, Event::MachinePrepared))
        .unwrap();
    for (position, event) in events.iter().enumerate() {
        if let Event::Entered(_) = event {
            assert!(position > machine_prepared);
        }
        if let Event::Prepared(index, owner) = event {
            assert_ne!(*owner, thread::current().id());
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, Event::Destroyed(i, t) if i == index && t == owner))
            );
        }
    }
}

#[test]
fn preparation_failures_before_and_after_peer_readiness_release_no_cpu() {
    for behaviors in [
        vec![Behavior::PrepareError, Behavior::Wait],
        vec![Behavior::Wait, Behavior::FailAfterPeer],
        vec![Behavior::PreparePanic, Behavior::Wait],
    ] {
        let mut machine = TestMachine::new(behaviors);
        let trace = Arc::clone(&machine.trace);
        assert!(
            PreparingCpus::spawn(&mut machine, 2, PROFILE)
                .unwrap()
                .prepare(&AtomicBool::new(false))
                .is_err()
        );
        trace.assert_no_entry_and_owners_destroyed();
    }
}

#[test]
fn construction_spawn_and_machine_preparation_failures_join_created_owners() {
    for failure in 0..4 {
        let mut machine = TestMachine::new(vec![Behavior::Wait, Behavior::Wait]);
        machine.construction_error = (failure == 0).then_some(1);
        machine.machine_error = failure == 2;
        let trace = Arc::clone(&machine.trace);
        let result = PreparingCpus::spawn_with(&mut machine, 2, PROFILE, |index, task| {
            assert!(!(failure == 3 && index == 1), "injected spawn panic");
            if failure == 1 && index == 1 {
                return Err(std::io::Error::other("injected spawn error"));
            }
            thread::Builder::new().spawn(task)
        })
        .and_then(|owners| owners.prepare(&AtomicBool::new(false)));
        assert!(result.is_err());
        drop(result);
        trace.assert_no_entry_and_owners_destroyed();
    }
}

#[test]
fn disconnected_readiness_is_an_error_and_joins_owners() {
    let mut machine = TestMachine::new(vec![Behavior::Wait]);
    let trace = Arc::clone(&machine.trace);
    let mut preparing = PreparingCpus::spawn(&mut machine, 1, PROFILE).unwrap();
    let (sender, receiver) = mpsc::channel();
    drop(sender);
    preparing.owners.ready = receiver;
    assert!(preparing.prepare(&AtomicBool::new(false)).is_err());
    trace.assert_no_entry_and_owners_destroyed();
}

#[test]
fn cancellation_before_release_and_drop_during_unwind_never_enter_guest() {
    for unwind in [false, true] {
        let mut machine = TestMachine::new(vec![Behavior::Wait, Behavior::Wait]);
        let trace = Arc::clone(&machine.trace);
        let prepared = PreparingCpus::spawn(&mut machine, 2, PROFILE)
            .unwrap()
            .prepare(&AtomicBool::new(false))
            .unwrap();
        if unwind {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owners = prepared;
                panic!("caller failure");
            }));
        } else {
            assert!(prepared.run(&AtomicBool::new(true)).is_err());
        }
        trace.assert_no_entry_and_owners_destroyed();
    }
}

#[test]
fn panic_completion_is_observed_before_joining_an_active_first_worker() {
    let mut machine = TestMachine::new(vec![Behavior::Wait, Behavior::Panic]);
    let trace = Arc::clone(&machine.trace);
    let error = PreparingCpus::spawn(&mut machine, 2, PROFILE)
        .unwrap()
        .prepare(&AtomicBool::new(false))
        .unwrap()
        .run(&AtomicBool::new(false))
        .unwrap_err();
    assert!(error.to_string().contains("panicked"));
    assert!(trace.kicks.load(Ordering::Acquire) > 0);
}

#[test]
fn repeated_interrupts_close_the_check_entry_race_during_wait_and_drop() {
    for drop_owners in [false, true] {
        let mut machine = TestMachine::new(vec![Behavior::LostFirstInterrupt]);
        let trace = Arc::clone(&machine.trace);
        let prepared = PreparingCpus::spawn(&mut machine, 1, PROFILE)
            .unwrap()
            .prepare(&AtomicBool::new(false))
            .unwrap();
        prepared.owners.gate.release();
        trace.wait(|events| events.iter().any(|e| matches!(e, Event::Window)));
        let running = RunningCpus {
            owners: prepared.owners,
        };
        if drop_owners {
            drop(running);
        } else {
            assert_eq!(
                running.wait(&AtomicBool::new(true)).unwrap(),
                VcpuStop::Stopped
            );
        }
        assert!(trace.kicks.load(Ordering::Acquire) >= 2);
    }
}

#[test]
fn construction_and_machine_hook_panics_join_every_created_owner() {
    for construction in [false, true] {
        let mut machine = TestMachine::new(vec![Behavior::Wait, Behavior::Wait]);
        machine.construction_panic = construction.then_some(1);
        machine.machine_panic = !construction;
        let trace = Arc::clone(&machine.trace);
        let result = PreparingCpus::spawn(&mut machine, 2, PROFILE)
            .and_then(|owners| owners.prepare(&AtomicBool::new(false)));
        assert!(result.unwrap_err().to_string().contains("panicked"));
        trace.assert_no_entry_and_owners_destroyed();
    }
}

#[test]
fn interrupt_panic_during_unwind_does_not_detach_or_double_panic() {
    let mut machine = TestMachine::new(vec![Behavior::Wait]);
    let trace = Arc::clone(&machine.trace);
    let prepared = PreparingCpus::spawn(&mut machine, 1, PROFILE)
        .unwrap()
        .prepare(&AtomicBool::new(false))
        .unwrap();
    trace.panic_on_interrupt.store(true, Ordering::Release);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owners = prepared;
            panic!("caller failure while native interruption panics");
        }))
        .is_err()
    );
    trace.assert_no_entry_and_owners_destroyed();
}

#[test]
fn co_observed_terminal_precedence_is_independent_of_cpu_index_and_joins_all_owners() {
    for (first, second, expected) in [
        (
            Outcome::Poweroff,
            Outcome::Reset,
            Ok(VcpuStop::GuestPoweroff),
        ),
        (Outcome::Failure, Outcome::Poweroff, Err(())),
        (Outcome::Failure, Outcome::Reset, Err(())),
        (
            Outcome::OperatorTermination,
            Outcome::Reset,
            Ok(VcpuStop::Stopped),
        ),
        (
            Outcome::OperatorTermination,
            Outcome::Poweroff,
            Ok(VcpuStop::Stopped),
        ),
        (Outcome::OperatorTermination, Outcome::Failure, Err(())),
    ] {
        for outcomes in [[first, second], [second, first]] {
            let mut machine =
                TestMachine::new(outcomes.into_iter().map(Behavior::CoObserved).collect());
            let trace = Arc::clone(&machine.trace);
            let result = PreparingCpus::spawn(&mut machine, 2, PROFILE)
                .unwrap()
                .prepare(trace.as_ref())
                .unwrap()
                .run(trace.as_ref());
            match expected {
                Ok(stop) => assert_eq!(result.unwrap(), stop, "{outcomes:?}"),
                Err(()) => assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("co-observed owner failure"),
                    "{outcomes:?}"
                ),
            }
            let events = trace.events.lock().unwrap();
            let first_return = events
                .iter()
                .position(|event| matches!(event, Event::Returning(_)))
                .unwrap();
            for index in 0..2 {
                let entry = events
                    .iter()
                    .position(|event| matches!(event, Event::Entered(i) if *i == index))
                    .unwrap();
                assert!(
                    entry < first_return,
                    "both owners must enter before either returns: {events:?}"
                );
                let owner = events
                    .iter()
                    .find_map(|event| match event {
                        Event::Prepared(i, owner) if *i == index => Some(owner),
                        _ => None,
                    })
                    .unwrap();
                assert!(
                    events
                        .iter()
                        .any(|event| matches!(event, Event::Returning(i) if *i == index)),
                    "{events:?}"
                );
                assert!(events.iter().any(|event| matches!(event, Event::Destroyed(i, thread) if *i == index && thread == owner)), "every owner must be destroyed before result publication: {events:?}");
            }
        }
    }
}

#[test]
fn architectural_admission_failure_cannot_release_a_prepared_peer() {
    for (refusal, diagnostic) in [
        (AdmissionRefusal::MissingFeature, "FEAT_IVIPT"),
        (AdmissionRefusal::MissingEvidence, "native selector"),
        (AdmissionRefusal::V81MissingEvidence, "MMFR1 selector"),
        (AdmissionRefusal::V81MissingFeature, "FEAT_LOR"),
        (AdmissionRefusal::Contradiction, "FP and AdvSIMD"),
        (
            AdmissionRefusal::UnsupportedProfile,
            "armv8.2-a admission is not implemented",
        ),
    ] {
        let mut machine =
            TestMachine::new(vec![Behavior::Wait, Behavior::AdmissionFailure(refusal)]);
        let trace = Arc::clone(&machine.trace);
        let error = PreparingCpus::spawn(&mut machine, 2, PROFILE)
            .unwrap()
            .prepare(&AtomicBool::new(false))
            .unwrap_err();
        assert!(error.to_string().contains(diagnostic), "{error}");
        trace.assert_no_entry_and_owners_destroyed();
    }
}
