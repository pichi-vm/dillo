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
    PrepareShutdown,
    FinalizeError,
    FinalizePanic,
    FinalizeShutdown,
    Poweroff,
    Reset,
    ResetThenPoweroff,
    ResetThenShutdown,
    RunError,
    RunPanic,
}

#[derive(Default)]
struct State {
    prepared: Mutex<Vec<(u32, ThreadId)>>,
    dropped: Mutex<Vec<(u32, ThreadId)>>,
    entered: AtomicBool,
    finalized: AtomicBool,
    shutdown: AtomicBool,
    stop: AtomicBool,
    retirement_error: Option<u32>,
    panic_on_retirement: bool,
}

struct TestMachine(Scenario, Arc<State>);

impl Machine for TestMachine {
    type Error = io::Error;
    type Platform = ();
    type CpuPreparation = TestPreparation;
    type Worker = ();

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
        _: CpuProfile,
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
        if scenario == Scenario::PrepareShutdown {
            state.shutdown.store(true, Ordering::Release);
        }
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
        if self.index == 0 && self.scenario == Scenario::ResetThenShutdown {
            self.state.shutdown.store(true, Ordering::Release);
        }
        self.state
            .dropped
            .lock()
            .unwrap()
            .push((self.index, thread::current().id()));
        assert!(
            self.index != 0 || !self.state.panic_on_retirement,
            "retirement fixture"
        );
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
            return Ok(if self.scenario == Scenario::ResetThenPoweroff {
                VcpuStop::GuestPoweroff
            } else {
                VcpuStop::Stopped
            });
        }
        wait_for(&self.state.entered);
        assert!(self.scenario != Scenario::RunPanic, "run fixture");
        if self.scenario == Scenario::RunError {
            return Err(io::Error::other("run fixture"));
        }
        Ok(match self.scenario {
            Scenario::Reset | Scenario::ResetThenPoweroff | Scenario::ResetThenShutdown => {
                VcpuStop::GuestReset
            }
            _ => VcpuStop::GuestPoweroff,
        })
    }

    fn retire(self) -> Result<(), Self::Error> {
        if self.state.retirement_error == Some(self.index) {
            return Err(io::Error::other("retirement fixture"));
        }
        Ok(())
    }
}

fn run(scenario: Scenario, state: &Arc<State>) -> Result<VcpuStop, CpuError> {
    let mut machine = TestMachine(scenario, Arc::clone(state));
    run_cpus(
        &mut machine,
        2,
        CpuProfile::X86_64(pmi::x86_64::Profile::V1),
        &state.shutdown,
    )
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
        for retirement_error in [None, Some(0)] {
            let state = Arc::new(State {
                retirement_error,
                ..Default::default()
            });
            let supervisor_state = Arc::clone(&state);
            let (send, receive) = mpsc::channel();
            let supervisor = thread::spawn(move || {
                let result = run(scenario, &supervisor_state);
                assert!(!supervisor_state.entered.load(Ordering::Acquire));
                assert_owners_released(&supervisor_state, count);
                send.send(result).unwrap();
            });
            let result = receive
                .recv_timeout(Duration::from_secs(3))
                .expect("owner retirement did not complete");
            supervisor.join().unwrap();
            let expected = if retirement_error.is_some() {
                format!("{error}. retire vCPU 0: retirement fixture")
            } else {
                error.into()
            };
            assert_eq!(result.unwrap_err().to_string(), expected);
        }
    }
}

#[test]
fn unwind_denies_initial_permission() {
    let state = Arc::new(State::default());
    assert!(catch_unwind(|| run(Scenario::FinalizePanic, &state)).is_err());
    assert!(!state.entered.load(Ordering::Acquire));
    assert_owners_released(&state, 2);
}

#[test]
fn startup_shutdown_reports_owner_retirement_failure() {
    for (scenario, count) in [
        (Scenario::PrepareShutdown, 1),
        (Scenario::FinalizeShutdown, 2),
    ] {
        for panic_on_retirement in [false, true] {
            let state = Arc::new(State {
                panic_on_retirement,
                ..Default::default()
            });
            let supervisor_state = Arc::clone(&state);
            let (send, receive) = mpsc::channel();
            let supervisor =
                thread::spawn(move || send.send(run(scenario, &supervisor_state)).unwrap());
            let result = receive
                .recv_timeout(Duration::from_secs(3))
                .expect("owner retirement timed out");
            supervisor.join().unwrap();
            if panic_on_retirement {
                assert_eq!(result.unwrap_err().to_string(), "vCPU 0 owner panicked");
            } else {
                assert_eq!(result.unwrap(), VcpuStop::Stopped);
            }
            assert!(!state.entered.load(Ordering::Acquire));
            assert_owners_released(&state, count);
        }
    }
}

#[test]
fn retirement_errors_prevent_success_and_preserve_run_failure() {
    for (scenario, index, count, error) in [
        (
            Scenario::PrepareShutdown,
            0,
            1,
            "retire vCPU 0: retirement fixture",
        ),
        (
            Scenario::FinalizeShutdown,
            0,
            2,
            "retire vCPU 0: retirement fixture",
        ),
        (
            Scenario::Poweroff,
            1,
            2,
            "retire vCPU 1: retirement fixture",
        ),
        (Scenario::Reset, 1, 2, "retire vCPU 1: retirement fixture"),
        (
            Scenario::RunError,
            1,
            2,
            "run vCPU 1: run fixture. retire vCPU 1: retirement fixture",
        ),
    ] {
        let state = Arc::new(State {
            retirement_error: Some(index),
            ..Default::default()
        });
        assert_eq!(run(scenario, &state).unwrap_err().to_string(), error);
        assert_owners_released(&state, count);
    }
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

#[test]
fn observed_termination_supersedes_pending_reset() {
    for (scenario, expected) in [
        (Scenario::Reset, VcpuStop::GuestReset),
        (Scenario::ResetThenPoweroff, VcpuStop::GuestPoweroff),
        (Scenario::ResetThenShutdown, VcpuStop::Stopped),
    ] {
        let state = Arc::new(State::default());
        assert_eq!(run(scenario, &state).unwrap(), expected);
        assert_owners_released(&state, 2);
    }
}

#[test]
fn delayed_entry_observes_operator_and_peer_termination() {
    for scenario in [Scenario::Poweroff, Scenario::RunPanic] {
        let state = Arc::new(State::default());
        let mut delayed = TestRunner {
            index: 0,
            scenario,
            state: Arc::clone(&state),
            _affine: Rc::new(()),
        };
        let gate = ExecutionGate(Mutex::new(true));
        state.shutdown.store(true, Ordering::Release);
        assert_eq!(
            gate.run(&mut delayed, 0, &state.shutdown).unwrap(),
            VcpuStop::Stopped
        );
        assert!(!state.entered.load(Ordering::Acquire));

        let peer_state = Arc::new(State::default());
        peer_state.entered.store(true, Ordering::Release);
        peer_state.finalized.store(true, Ordering::Release);
        let mut peer = TestRunner {
            index: 1,
            scenario,
            state: peer_state,
            _affine: Rc::new(()),
        };
        let gate = ExecutionGate(Mutex::new(true));
        let shutdown = AtomicBool::new(false);
        let result = gate.run(&mut peer, 1, &shutdown);
        assert_eq!(result.is_err(), scenario == Scenario::RunPanic);
        assert_eq!(
            gate.run(&mut delayed, 0, &shutdown).unwrap(),
            VcpuStop::Stopped
        );
        assert!(!state.entered.load(Ordering::Acquire));
    }
}
