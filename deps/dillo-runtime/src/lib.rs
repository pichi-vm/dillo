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

struct Owners<'scope, C: CpuControl> {
    threads: Vec<ScopedJoinHandle<'scope, ()>>,
    controls: Vec<C>,
}

impl<C: CpuControl> Owners<'_, C> {
    fn stop(&self) {
        for control in &self.controls {
            if let Err(error) = control.stop() {
                log::debug!("vCPU stop wake failed: {error}");
            }
        }
    }
}

impl<C: CpuControl> Drop for Owners<'_, C> {
    fn drop(&mut self) {
        // On unwind the gate guard has already denied entry. After permission,
        // keep waking owners until even a CPU entering native execution stops.
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
    let gate = Mutex::new(false);
    thread::scope(|scope| {
        let mut owners = Owners {
            threads: Vec::with_capacity(count as usize),
            controls: Vec::with_capacity(count as usize),
        };
        // Acquire after constructing Owners so any return drops the guard
        // before Owners waits for the prepared threads to finish.
        let mut permitted = gate.lock().expect("initial execution gate");
        let (complete, results) = mpsc::channel();
        for index in 0..count {
            if shutdown.load(Ordering::Acquire) {
                return Ok(VcpuStop::Stopped);
            }
            let preparation = machine
                .cpu_preparation(index, profile, boot_state)
                .map_err(|error| CpuError(format!("bind vCPU {index}: {error}")))?;
            let (ready, prepared) = mpsc::sync_channel(1);
            let complete = complete.clone();
            let gate = &gate;
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
                        if gate.lock().is_ok_and(|decision| *decision) {
                            runner
                                .run()
                                .map_err(|error| CpuError(format!("run vCPU {index}: {error}")))
                        } else {
                            Ok(VcpuStop::Stopped)
                        }
                    }));
                    let _ = complete.send(result.unwrap_or_else(|_| Err(owner_panic(index))));
                })
                .map_err(|error| CpuError(format!("spawn vCPU {index}: {error}")))?;
            owners.threads.push(owner);
            owners
                .controls
                .push(prepared.recv().map_err(|_| owner_panic(index))??);
        }
        drop(complete);
        machine
            .prepare_vcpu_run()
            .map_err(|error| CpuError(format!("finalize vCPUs: {error}")))?;
        if shutdown.load(Ordering::Acquire) {
            return Ok(VcpuStop::Stopped);
        }
        *permitted = true;
        drop(permitted);

        let mut outcome = None;
        let mut failure = None;
        let mut remaining = count;
        while remaining > 0 {
            if shutdown.load(Ordering::Acquire) {
                outcome.get_or_insert(VcpuStop::Stopped);
            }
            if outcome.is_some() || failure.is_some() {
                owners.stop();
            }
            match results.recv_timeout(WAKE_INTERVAL) {
                Ok(result) => {
                    remaining -= 1;
                    match result {
                        Ok(stop) => {
                            outcome.get_or_insert(stop);
                        }
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
        failure.map_or_else(|| Ok(outcome.unwrap_or(VcpuStop::Stopped)), Err)
    })
}

fn owner_panic(index: u32) -> CpuError {
    CpuError(format!("vCPU {index} owner panicked"))
}

#[cfg(test)]
mod tests;
