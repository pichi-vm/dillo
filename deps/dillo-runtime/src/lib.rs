// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Prepare native CPUs on their owner threads before granting guest execution.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread::{self, ScopedJoinHandle};
use std::time::Duration;

use dillo_machine::{CpuControl, CpuPreparation, CpuProfile, CpuRunner, Machine, VcpuStop};

const WAKE_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub struct CpuError(String);

impl CpuError {
    fn record(failure: &mut Option<Self>, error: Self) {
        if let Some(primary) = failure {
            primary.0.push_str(". ");
            primary.0.push_str(&error.0);
        } else {
            *failure = Some(error);
        }
    }
}

impl fmt::Display for CpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CpuError {}

struct ExecutionGate(Mutex<bool>);

impl ExecutionGate {
    fn admits(&self, shutdown: &AtomicBool) -> bool {
        self.0
            .lock()
            .is_ok_and(|permitted| *permitted && !shutdown.load(Ordering::Acquire))
    }

    fn revoke(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
    }

    fn run(
        &self,
        runner: &mut impl CpuRunner,
        index: u32,
        shutdown: &AtomicBool,
    ) -> Result<VcpuStop, CpuError> {
        if !self.admits(shutdown) {
            return Ok(VcpuStop::Stopped);
        }
        let result = catch_unwind(AssertUnwindSafe(|| runner.run()));
        self.revoke();
        result
            .map_err(|_| owner_panic(index))?
            .map_err(|error| CpuError(format!("run vCPU {index}: {error}")))
    }
}

struct Owners<'scope, C: CpuControl> {
    gate: &'scope ExecutionGate,
    threads: Vec<ScopedJoinHandle<'scope, ()>>,
    controls: Vec<C>,
}

impl<C: CpuControl> Drop for Owners<'_, C> {
    fn drop(&mut self) {
        // On unwind the gate guard has already denied entry. After permission,
        // keep waking owners until even a CPU entering native execution stops.
        self.gate.revoke();
        while self.threads.iter().any(|owner| !owner.is_finished()) {
            self.stop();
            thread::sleep(WAKE_INTERVAL);
        }
        for owner in self.threads.drain(..) {
            let _ = owner.join();
        }
    }
}

/// Prepare owners in logical CPU order, finalize the machine, and supervise it
/// until every CPU has stopped. The machine remains borrowed until owners exit.
pub fn run_cpus<M: Machine>(
    machine: &mut M,
    count: u32,
    profile: CpuProfile,
    shutdown: &AtomicBool,
) -> Result<VcpuStop, CpuError> {
    let gate = ExecutionGate(Mutex::new(false));
    thread::scope(|scope| {
        Owners {
            gate: &gate,
            threads: Vec::with_capacity(count as usize),
            controls: Vec::with_capacity(count as usize),
        }
        .run(scope, machine, count, profile, shutdown)
    })
}

impl<'scope, C: CpuControl> Owners<'scope, C> {
    fn stop(&self) {
        for control in &self.controls {
            if let Err(error) = control.stop() {
                log::debug!("vCPU stop wake failed: {error}");
            }
        }
    }

    fn run<M: Machine>(
        mut self,
        scope: &'scope thread::Scope<'scope, '_>,
        machine: &mut M,
        count: u32,
        profile: CpuProfile,
        shutdown: &'scope AtomicBool,
    ) -> Result<VcpuStop, CpuError>
    where
        M::CpuPreparation: CpuPreparation<Control = C>,
    {
        // This guard drops before self joins any owners on error or unwind.
        let gate = self.gate;
        let mut permitted = gate.0.lock().expect("initial execution gate");
        let (complete, results) = mpsc::channel();
        let prepare_owner = |index| -> Result<(), CpuError> {
            let preparation = machine
                .cpu_preparation(index, profile)
                .map_err(|error| CpuError(format!("bind vCPU {index}: {error}")))?;
            let (ready, prepared) = mpsc::sync_channel(1);
            let complete = complete.clone();
            let owner = thread::Builder::new()
                .name(format!("dillo-vcpu-{index}"))
                .spawn_scoped(scope, move || {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        let prepared = catch_unwind(AssertUnwindSafe(|| preparation.prepare()))
                            .map_err(|_| owner_panic(index))
                            .and_then(|result| {
                                result.map_err(|error| {
                                    CpuError(format!("prepare vCPU {index}: {error}"))
                                })
                            });
                        let (mut runner, control) = match prepared {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                let _ = ready.send(Err(error));
                                return Ok(VcpuStop::Stopped);
                            }
                        };
                        let ready_delivered = ready.send(Ok(control)).is_ok();
                        drop(ready);
                        let execution = if ready_delivered {
                            gate.run(&mut runner, index, shutdown)
                        } else {
                            Ok(VcpuStop::Stopped)
                        };
                        let retirement = catch_unwind(AssertUnwindSafe(|| {
                            runner
                                .retire()
                                .map_err(|error| CpuError(format!("retire vCPU {index}: {error}")))
                        }))
                        .unwrap_or_else(|_| Err(owner_panic(index)));
                        match (execution, retirement) {
                            (Err(execution), Err(retirement)) => {
                                Err(CpuError(format!("{execution}. {retirement}")))
                            }
                            (execution, retirement) => retirement.and(execution),
                        }
                    }));
                    let result = result.unwrap_or_else(|_| Err(owner_panic(index)));
                    if let Err(mpsc::SendError(Err(error))) = complete.send(result) {
                        log::error!("{error}");
                    }
                })
                .map_err(|error| CpuError(format!("spawn vCPU {index}: {error}")))?;
            self.threads.push(owner);
            let control = prepared.recv().map_err(|_| {
                CpuError(format!(
                    "vCPU {index} owner exited without reporting readiness"
                ))
            })??;
            self.controls.push(control);
            Ok(())
        };
        let mut failure = (0..count)
            .take_while(|_| !shutdown.load(Ordering::Acquire))
            .try_for_each(prepare_owner)
            .err();
        drop(complete);
        let mut remaining = self.threads.len();
        if failure.is_none() && remaining == count as usize && !shutdown.load(Ordering::Acquire) {
            failure = machine
                .prepare_vcpu_run()
                .map_err(|error| CpuError(format!("finalize vCPUs: {error}")))
                .err();
            *permitted = failure.is_none() && !shutdown.load(Ordering::Acquire);
        }
        drop(permitted);

        // Even without entry permission, retiring a prepared owner can fail.
        let mut outcome = VcpuStop::Stopped;
        while remaining > 0 {
            if !gate.admits(shutdown) {
                self.stop();
            }
            match results.recv_timeout(WAKE_INTERVAL) {
                Ok(result) => {
                    remaining -= 1;
                    match result {
                        Ok(VcpuStop::GuestPoweroff) => outcome = VcpuStop::GuestPoweroff,
                        Ok(VcpuStop::GuestReset) if outcome == VcpuStop::Stopped => {
                            outcome = VcpuStop::GuestReset;
                        }
                        Ok(_) => {}
                        Err(error) => CpuError::record(&mut failure, error),
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    CpuError::record(
                        &mut failure,
                        CpuError("vCPU owner exited without reporting its result".into()),
                    );
                    break;
                }
            }
        }
        drop(self);
        if let Some(error) = failure {
            Err(error)
        } else if shutdown.load(Ordering::Acquire) {
            Ok(VcpuStop::Stopped)
        } else {
            Ok(outcome)
        }
    }
}

fn owner_panic(index: u32) -> CpuError {
    CpuError(format!("vCPU {index} owner panicked"))
}

#[cfg(test)]
mod tests;
