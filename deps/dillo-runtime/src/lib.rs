// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Prepare native CPUs on their owner threads before granting guest execution.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread::{self, ScopedJoinHandle};
use std::time::Duration;

use dillo_machine::{BootVcpuState, CpuControl, CpuPreparation, CpuRunner, Machine, VcpuStop};

const WAKE_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub struct CpuError(String);

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
    profile: &str,
    boot_state: &dyn BootVcpuState,
    shutdown: &AtomicBool,
) -> Result<VcpuStop, CpuError> {
    let gate = ExecutionGate(Mutex::new(false));
    thread::scope(|scope| {
        Owners {
            gate: &gate,
            threads: Vec::with_capacity(count as usize),
            controls: Vec::with_capacity(count as usize),
        }
        .run(scope, machine, count, profile, boot_state, shutdown)
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
        profile: &str,
        boot_state: &dyn BootVcpuState,
        shutdown: &'scope AtomicBool,
    ) -> Result<VcpuStop, CpuError>
    where
        M::CpuPreparation: CpuPreparation<Control = C>,
    {
        // This guard drops before self joins any owners on error or unwind.
        let gate = self.gate;
        let mut permitted = gate.0.lock().expect("initial execution gate");
        let (complete, results) = mpsc::channel();
        for index in 0..count {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let preparation = machine
                .cpu_preparation(index, profile, boot_state)
                .map_err(|error| CpuError(format!("bind vCPU {index}: {error}")))?;
            let (ready, prepared) = mpsc::sync_channel(1);
            let complete = complete.clone();
            let owner = thread::Builder::new()
                .name(format!("dillo-vcpu-{index}"))
                .spawn_scoped(scope, move || {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        let (mut runner, control) = match preparation.prepare() {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                let _ = ready
                                    .send(Err(CpuError(format!("prepare vCPU {index}: {error}"))));
                                return Ok(VcpuStop::Stopped);
                            }
                        };
                        if ready.send(Ok(control)).is_err() {
                            return Ok(VcpuStop::Stopped);
                        }
                        drop(ready);
                        gate.run(&mut runner, index, shutdown)
                    }));
                    let _ = complete.send(result.unwrap_or_else(|_| Err(owner_panic(index))));
                })
                .map_err(|error| CpuError(format!("spawn vCPU {index}: {error}")))?;
            self.threads.push(owner);
            self.controls
                .push(prepared.recv().map_err(|_| owner_panic(index))??);
        }
        drop(complete);
        let mut remaining = self.threads.len();
        if remaining == count as usize && !shutdown.load(Ordering::Acquire) {
            machine
                .prepare_vcpu_run()
                .map_err(|error| CpuError(format!("finalize vCPUs: {error}")))?;
            *permitted = !shutdown.load(Ordering::Acquire);
        }
        drop(permitted);

        // Even without entry permission, retiring a prepared owner can fail.
        let mut outcome = VcpuStop::Stopped;
        let mut failure = None;
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
                        Err(error) => {
                            failure.get_or_insert(error);
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    failure.get_or_insert_with(|| {
                        CpuError("vCPU owner exited without reporting its result".into())
                    });
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
