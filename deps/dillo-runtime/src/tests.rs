// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::rc::Rc;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Instant;

use dillo_machine::LaunchConfig;

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    BindError,
    PrepareError,
    PreparePanic,
    FinalizeError,
    FinalizePanic,
    FinalizeShutdown,
    Poweroff,
    RunPanic,
}

struct Boot;
impl BootVcpuState for Boot {}

#[derive(Default)]
struct State {
    prepared: Mutex<Vec<(u32, ThreadId)>>,
    dropped: Mutex<Vec<(u32, ThreadId)>>,
    entered: AtomicBool,
    finalized: AtomicBool,
    shutdown: AtomicBool,
    stop: AtomicBool,
}

struct TestMachine(Scenario, Arc<State>);

impl Machine for TestMachine {
    type Error = io::Error;
    type Platform = ();
    type CpuPreparation = TestPreparation;

    fn guest_address_bits() -> Result<u32, Self::Error> {
        Ok(48)
    }

    fn from_launch_config(_: LaunchConfig<'_, ()>) -> Result<Self, Self::Error> {
        unreachable!()
    }

    fn write_guest(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        unreachable!()
    }

    fn cpu_preparation(
        &mut self,
        index: u32,
        _: &str,
        _: &dyn BootVcpuState,
    ) -> Result<TestPreparation, Self::Error> {
        if index == 1 && self.0 == Scenario::BindError {
            return Err(io::Error::other("bind fixture"));
        }
        Ok(TestPreparation(index, self.0, Arc::clone(&self.1)))
    }

    fn prepare_vcpu_run(&mut self) -> Result<(), Self::Error> {
        assert_eq!(self.1.prepared.lock().unwrap().len(), 2);
        assert!(!self.1.entered.load(Ordering::Acquire));
        match self.0 {
            Scenario::FinalizeError => return Err(io::Error::other("finalize fixture")),
            Scenario::FinalizePanic => panic!("finalize fixture"),
            Scenario::FinalizeShutdown => self.1.shutdown.store(true, Ordering::Release),
            _ => {}
        }
        self.1.finalized.store(true, Ordering::Release);
        Ok(())
    }
}

struct TestPreparation(u32, Scenario, Arc<State>);

impl CpuPreparation for TestPreparation {
    type Error = io::Error;
    type Runner = TestRunner;
    type Control = TestControl;

    fn prepare(self) -> Result<(TestRunner, TestControl), Self::Error> {
        let Self(index, scenario, state) = self;
        if index == 1 {
            match scenario {
                Scenario::PrepareError => return Err(io::Error::other("prepare fixture")),
                Scenario::PreparePanic => panic!("prepare fixture"),
                _ => {}
            }
        }
        state
            .prepared
            .lock()
            .unwrap()
            .push((index, thread::current().id()));
        let control = TestControl(Arc::clone(&state));
        Ok((
            TestRunner {
                index,
                scenario,
                state,
                _affine: Rc::new(()),
            },
            control,
        ))
    }
}

struct TestControl(Arc<State>);

impl CpuControl for TestControl {
    type Error = io::Error;

    fn stop(&self) -> Result<(), Self::Error> {
        self.0.stop.store(true, Ordering::Release);
        Ok(())
    }
}

struct TestRunner {
    index: u32,
    scenario: Scenario,
    state: Arc<State>,
    _affine: Rc<()>,
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        self.state
            .dropped
            .lock()
            .unwrap()
            .push((self.index, thread::current().id()));
    }
}

fn wait_for(flag: &AtomicBool) {
    let until = Instant::now() + Duration::from_secs(3);
    while !flag.load(Ordering::Acquire) {
        assert!(Instant::now() < until, "CPU did not receive wake");
        thread::sleep(Duration::from_millis(1));
    }
}

impl CpuRunner for TestRunner {
    type Error = io::Error;

    fn run(&mut self) -> Result<VcpuStop, Self::Error> {
        assert!(self.state.finalized.load(Ordering::Acquire));
        if self.index == 0 {
            self.state.entered.store(true, Ordering::Release);
            wait_for(&self.state.stop);
            return Ok(VcpuStop::Stopped);
        }
        wait_for(&self.state.entered);
        assert!(self.scenario != Scenario::RunPanic, "run fixture");
        Ok(VcpuStop::GuestPoweroff)
    }
}

fn run(scenario: Scenario, state: &Arc<State>) -> Result<VcpuStop, CpuError> {
    let mut machine = TestMachine(scenario, Arc::clone(state));
    run_cpus(&mut machine, 2, "fixture", &Boot, &state.shutdown)
}

fn assert_owners_released(state: &State, count: usize) {
    let prepared = state.prepared.lock().unwrap();
    let mut dropped = state.dropped.lock().unwrap();
    dropped.sort_by_key(|(index, _)| *index);
    assert_eq!(prepared.len(), count);
    assert_eq!(*prepared, *dropped);
    assert!(
        prepared
            .iter()
            .all(|(_, owner)| *owner != thread::current().id())
    );
}

#[test]
fn preparation_and_finalization_failures_prevent_entry() {
    for (scenario, error, count) in [
        (Scenario::BindError, "bind vCPU 1: bind fixture", 1),
        (Scenario::PrepareError, "prepare vCPU 1: prepare fixture", 1),
        (Scenario::PreparePanic, "vCPU 1 owner panicked", 1),
        (
            Scenario::FinalizeError,
            "finalize vCPUs: finalize fixture",
            2,
        ),
    ] {
        let state = Arc::new(State::default());
        assert_eq!(run(scenario, &state).unwrap_err().to_string(), error);
        assert!(!state.entered.load(Ordering::Acquire));
        assert_owners_released(&state, count);
    }
}

#[test]
fn shutdown_and_unwind_deny_initial_permission() {
    let state = Arc::new(State::default());
    assert_eq!(
        run(Scenario::FinalizeShutdown, &state).unwrap(),
        VcpuStop::Stopped
    );
    assert!(!state.entered.load(Ordering::Acquire));
    assert_owners_released(&state, 2);

    let state = Arc::new(State::default());
    assert!(catch_unwind(|| run(Scenario::FinalizePanic, &state)).is_err());
    assert!(!state.entered.load(Ordering::Acquire));
    assert_owners_released(&state, 2);
}

#[test]
fn later_owner_poweroff_or_panic_stops_earlier_waiter() {
    let state = Arc::new(State::default());
    assert_eq!(
        run(Scenario::Poweroff, &state).unwrap(),
        VcpuStop::GuestPoweroff
    );
    assert_owners_released(&state, 2);

    let state = Arc::new(State::default());
    assert_eq!(
        run(Scenario::RunPanic, &state).unwrap_err().to_string(),
        "vCPU 1 owner panicked"
    );
    assert_owners_released(&state, 2);
}
