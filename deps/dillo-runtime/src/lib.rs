// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Owner-thread CPU preparation and the initial execution barrier.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dillo_machine::{
    CpuInterrupt, CpuPreparation, CpuProfile, CpuRunner, CpuTermination, Machine, VcpuStop,
};

const POLL_INTERVAL: Duration = Duration::from_millis(5);
type WorkerResult = Result<VcpuStop, String>;
type WorkerTask = Box<dyn FnOnce() -> WorkerResult + Send>;
type InterruptOf<M> = <<M as Machine>::CpuPreparation as CpuPreparation>::Interrupt;

#[derive(Debug)]
pub struct CpuError(Vec<String>);

impl fmt::Display for CpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("; "))
    }
}
impl std::error::Error for CpuError {}

#[derive(Debug, Default)]
struct Termination(AtomicBool);
impl Termination {
    fn request(&self) {
        self.0.store(true, Ordering::Release);
    }
}
impl CpuTermination for Termination {
    fn is_requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
enum GateState {
    Closed,
    Released,
}

#[derive(Debug)]
struct InitialGate {
    state: Mutex<GateState>,
    changed: Condvar,
}
impl InitialGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(GateState::Closed),
            changed: Condvar::new(),
        }
    }
    fn wait(&self, termination: &Termination) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if termination.is_requested() {
                return false;
            }
            if matches!(*state, GateState::Released) {
                return !termination.is_requested();
            }
            state = self
                .changed
                .wait_timeout(state, POLL_INTERVAL)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
    fn release(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = GateState::Released;
        self.changed.notify_all();
    }
    fn wake(&self) {
        self.changed.notify_all();
    }
}

#[derive(Debug)]
enum WorkerState {
    Preparing(JoinHandle<WorkerResult>),
    Prepared(JoinHandle<WorkerResult>),
    Finished(WorkerResult),
}

#[derive(Debug)]
struct Worker<I> {
    index: usize,
    interrupt: I,
    state: WorkerState,
}
impl<I: CpuInterrupt> Worker<I> {
    fn prepared(self, index: usize) -> Self {
        let state = match self.state {
            WorkerState::Preparing(join) if self.index == index => WorkerState::Prepared(join),
            state => state,
        };
        Self { state, ..self }
    }
    fn poll(self) -> Self {
        let state = match self.state {
            WorkerState::Preparing(join) if join.is_finished() => WorkerState::Finished(
                join.join()
                    .unwrap_or_else(|_| Err(format!("CPU {} owner panicked", self.index))),
            ),
            WorkerState::Prepared(join) if join.is_finished() => WorkerState::Finished(
                join.join()
                    .unwrap_or_else(|_| Err(format!("CPU {} owner panicked", self.index))),
            ),
            state => state,
        };
        Self { state, ..self }
    }
}

/// Holds the machine borrow until every owner thread has completed. Even the
/// unwinding path keeps repeating native interruption while it joins owners.
struct Owners<'vm, M: Machine> {
    machine: &'vm mut M,
    workers: Vec<Worker<InterruptOf<M>>>,
    ready: mpsc::Receiver<usize>,
    gate: Arc<InitialGate>,
    termination: Arc<Termination>,
    wake_errors: BTreeMap<usize, String>,
}
impl<M: Machine> Owners<'_, M> {
    fn poll(&mut self) {
        self.workers = std::mem::take(&mut self.workers)
            .into_iter()
            .map(Worker::poll)
            .collect();
        while let Ok(index) = self.ready.try_recv() {
            self.workers = std::mem::take(&mut self.workers)
                .into_iter()
                .map(|w| w.prepared(index))
                .collect();
        }
    }
    fn terminate(&mut self) {
        self.termination.request(); // publication always precedes all native kicks
        self.gate.wake();
        for worker in &self.workers {
            if !matches!(worker.state, WorkerState::Finished(_)) {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker
                        .interrupt
                        .interrupt()
                        .map_err(|error| error.to_string())
                }));
                let error = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error),
                    Err(_) => Some(format!("CPU {} interrupt panicked", worker.index)),
                };
                if let Some(error) = error {
                    self.wake_errors.entry(worker.index).or_insert(error);
                }
            }
        }
    }
    fn join_all(&mut self) {
        loop {
            self.terminate();
            self.poll();
            if self
                .workers
                .iter()
                .all(|w| matches!(w.state, WorkerState::Finished(_)))
            {
                break;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
    fn errors(&self) -> Vec<String> {
        let mut errors: Vec<_> = self
            .workers
            .iter()
            .filter_map(|w| match &w.state {
                WorkerState::Finished(Err(error)) => Some(error.clone()),
                _ => None,
            })
            .collect();
        errors.extend(self.wake_errors.values().cloned());
        errors
    }
    fn fail(&mut self, error: impl Into<String>) -> CpuError {
        self.join_all();
        let mut errors = vec![error.into()];
        errors.extend(self.errors());
        CpuError(errors)
    }
}
impl<M: Machine> Drop for Owners<'_, M> {
    fn drop(&mut self) {
        self.join_all();
    }
}

/// Workers exist, but every guest remains behind the closed initial gate.
/// The machine cannot be reused or destroyed while any owner may reference it.
///
/// ```compile_fail
/// use dillo_machine::{CpuProfile, Machine};
/// use dillo_runtime::PreparingCpus;
/// fn reuse<M: Machine>(machine: &mut M, profile: CpuProfile) {
///     let owners = PreparingCpus::spawn(machine, 1, profile).unwrap();
///     machine.prepare_vcpu_run().unwrap();
///     drop(owners);
/// }
/// ```
///
/// ```compile_fail
/// use dillo_machine::{CpuProfile, Machine};
/// use dillo_runtime::PreparingCpus;
/// fn destroy<M: Machine>(mut machine: M, profile: CpuProfile) {
///     let owners = PreparingCpus::spawn(&mut machine, 1, profile).unwrap();
///     drop(machine);
///     drop(owners);
/// }
/// ```
pub struct PreparingCpus<'vm, M: Machine> {
    owners: Owners<'vm, M>,
}
/// Every owner and the machine's post-CPU setup have prepared successfully.
/// This does not certify complete-machine finalization.
pub struct PreparedCpus<'vm, M: Machine> {
    owners: Owners<'vm, M>,
}
/// Released CPU owners whose resources remain bound to their machine borrow.
pub struct RunningCpus<'vm, M: Machine> {
    owners: Owners<'vm, M>,
}

impl<M: Machine> fmt::Debug for PreparingCpus<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparingCpus")
            .field("workers", &self.owners.workers.len())
            .finish_non_exhaustive()
    }
}
impl<M: Machine> fmt::Debug for PreparedCpus<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCpus")
            .field("workers", &self.owners.workers.len())
            .finish_non_exhaustive()
    }
}
impl<M: Machine> fmt::Debug for RunningCpus<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunningCpus")
            .field("workers", &self.owners.workers.len())
            .finish_non_exhaustive()
    }
}

impl<'vm, M: Machine> PreparingCpus<'vm, M> {
    pub fn spawn(machine: &'vm mut M, count: u32, profile: CpuProfile) -> Result<Self, CpuError> {
        Self::spawn_with(machine, count, profile, |index, task| {
            thread::Builder::new()
                .name(format!("dillo-cpu-{index}"))
                .spawn(task)
        })
    }
    fn spawn_with(
        machine: &'vm mut M,
        count: u32,
        profile: CpuProfile,
        mut spawn: impl FnMut(usize, WorkerTask) -> std::io::Result<JoinHandle<WorkerResult>>,
    ) -> Result<Self, CpuError> {
        let (ready, receiver) = mpsc::channel();
        let mut owners = Owners {
            machine,
            workers: Vec::new(),
            ready: receiver,
            gate: Arc::new(InitialGate::new()),
            termination: Arc::new(Termination::default()),
            wake_errors: BTreeMap::new(),
        };
        if count == 0 {
            return Err(owners.fail("a CPU set requires a BSP"));
        }
        for index in 0..count {
            let input = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                owners.machine.cpu_preparation(index, profile)
            })) {
                Ok(Ok(input)) => input,
                Ok(Err(error)) => return Err(owners.fail(error.to_string())),
                Err(_) => {
                    return Err(owners.fail(format!("CPU {index} input construction panicked")));
                }
            };
            let Ok(interrupt) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| input.interrupt()))
            else {
                return Err(owners.fail(format!("CPU {index} interrupt construction panicked")));
            };
            let ready = ready.clone();
            let gate = Arc::clone(&owners.gate);
            let termination = Arc::clone(&owners.termination);
            let task = Box::new(move || {
                if termination.is_requested() {
                    return Ok(VcpuStop::Stopped);
                }
                let mut runner = input.prepare().map_err(|error| error.to_string())?;
                ready
                    .send(index as usize)
                    .map_err(|_| "CPU readiness receiver disconnected".to_string())?;
                if !gate.wait(&termination) || termination.is_requested() {
                    return Ok(VcpuStop::Stopped);
                }
                runner
                    .run(termination.as_ref())
                    .map_err(|error| error.to_string())
            });
            let join = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                spawn(index as usize, task)
            })) {
                Ok(Ok(join)) => join,
                Ok(Err(error)) => return Err(owners.fail(format!("spawn CPU {index}: {error}"))),
                Err(_) => return Err(owners.fail(format!("spawn CPU {index} panicked"))),
            };
            owners.workers.push(Worker {
                index: index as usize,
                interrupt,
                state: WorkerState::Preparing(join),
            });
        }
        drop(ready);
        Ok(Self { owners })
    }
    pub fn prepare(
        mut self,
        shutdown: &dyn CpuTermination,
    ) -> Result<PreparedCpus<'vm, M>, CpuError> {
        loop {
            self.owners.poll();
            if shutdown.is_requested() {
                return Err(self.owners.fail("CPU preparation terminated"));
            }
            if self
                .owners
                .workers
                .iter()
                .any(|w| matches!(w.state, WorkerState::Finished(_)))
            {
                return Err(self
                    .owners
                    .fail("CPU owner completed before initial release"));
            }
            if self
                .owners
                .workers
                .iter()
                .all(|w| matches!(w.state, WorkerState::Prepared(_)))
            {
                break;
            }
            match self.owners.ready.recv_timeout(POLL_INTERVAL) {
                Ok(index) => {
                    self.owners.workers = std::mem::take(&mut self.owners.workers)
                        .into_iter()
                        .map(|w| w.prepared(index))
                        .collect();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(self.owners.fail("CPU readiness channel disconnected"));
                }
            }
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.owners.machine.prepare_vcpu_run()
        })) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(self.owners.fail(error.to_string())),
            Err(_) => return Err(self.owners.fail("machine CPU preparation panicked")),
        }
        self.owners.poll();
        if shutdown.is_requested()
            || self
                .owners
                .workers
                .iter()
                .any(|w| matches!(w.state, WorkerState::Finished(_)))
        {
            return Err(self
                .owners
                .fail("CPU preparation canceled before initial release"));
        }
        Ok(PreparedCpus {
            owners: self.owners,
        })
    }
    pub fn abort(mut self) -> Result<(), CpuError> {
        self.owners.join_all();
        let errors = self.owners.errors();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(CpuError(errors))
        }
    }
}
impl<M: Machine> PreparedCpus<'_, M> {
    pub fn run(mut self, shutdown: &dyn CpuTermination) -> Result<VcpuStop, CpuError> {
        self.owners.poll();
        if shutdown.is_requested()
            || self
                .owners
                .workers
                .iter()
                .any(|w| matches!(w.state, WorkerState::Finished(_)))
        {
            return Err(self
                .owners
                .fail("CPU set terminated before initial release"));
        }
        if self.owners.termination.is_requested() {
            return Err(self.owners.fail("CPU set already terminated"));
        }
        self.owners.gate.release();
        RunningCpus {
            owners: self.owners,
        }
        .wait(shutdown)
    }
}
impl<M: Machine> RunningCpus<'_, M> {
    pub fn wait(mut self, shutdown: &dyn CpuTermination) -> Result<VcpuStop, CpuError> {
        loop {
            self.owners.poll();
            if shutdown.is_requested()
                || self
                    .owners
                    .workers
                    .iter()
                    .any(|w| matches!(w.state, WorkerState::Finished(_)))
            {
                break;
            }
            thread::sleep(POLL_INTERVAL);
        }
        self.owners.join_all();
        let errors = self.owners.errors();
        if !errors.is_empty() {
            return Err(CpuError(errors));
        }
        let stops: Vec<_> = self
            .owners
            .workers
            .iter()
            .filter_map(|w| match w.state {
                WorkerState::Finished(Ok(stop)) => Some(stop),
                _ => None,
            })
            .collect();
        if shutdown.is_requested() {
            return Ok(VcpuStop::Stopped);
        }
        if stops.contains(&VcpuStop::GuestPoweroff) {
            Ok(VcpuStop::GuestPoweroff)
        } else if stops.contains(&VcpuStop::GuestReset) {
            Ok(VcpuStop::GuestReset)
        } else {
            Ok(VcpuStop::Stopped)
        }
    }
}

#[cfg(test)]
mod tests;
