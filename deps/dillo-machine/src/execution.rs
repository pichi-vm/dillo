// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Device execution callbacks, shutdown requests and consuming joins.

use std::sync::{Arc, Mutex};

pub type DeviceRun = Box<dyn FnOnce(RunToken) -> Result<DeviceExit, JoinError> + Send + 'static>;

/// A worker's explicit reason for ending successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceExit {
    Cancelled,
    EndpointClosed,
}

/// First unexpected device failure, retained for this machine's lifetime.
#[derive(Debug, Clone, thiserror::Error)]
#[error("device {participant}: {cause}")]
pub struct DeviceFailure {
    pub participant: String,
    pub cause: JoinError,
}

/// Reporting authority bound to one machine and attachment.
#[derive(Debug, Clone, Default)]
pub struct DeviceFailureReporter {
    first: Arc<Mutex<Option<DeviceFailure>>>,
    participant: String,
}

/// Read-only observation; observing never consumes or clears a failure.
#[derive(Debug, Clone)]
pub struct DeviceFailureObserver(Arc<Mutex<Option<DeviceFailure>>>);

impl DeviceFailureReporter {
    /// Derive observation without granting clearing, reset, or machine control.
    pub fn observer(&self) -> DeviceFailureObserver {
        DeviceFailureObserver(Arc::clone(&self.first))
    }

    #[must_use]
    pub fn scoped(&self, participant: impl std::fmt::Display) -> Self {
        Self {
            first: Arc::clone(&self.first),
            participant: if self.participant.is_empty() {
                participant.to_string()
            } else {
                format!("{}/{}", self.participant, participant)
            },
        }
    }

    pub fn report(&self, cause: JoinError) {
        let mut first = self
            .first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if first.is_none() {
            *first = Some(DeviceFailure {
                participant: self.participant.clone(),
                cause,
            });
        }
    }

    /// Classify completion while the native handle still owns the worker.
    pub fn run(&self, run: DeviceRun, token: RunToken) -> Result<(), JoinError> {
        let result =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(token.clone()))) {
                Ok(Ok(DeviceExit::EndpointClosed)) => Ok(()),
                Ok(Ok(DeviceExit::Cancelled)) if token.is_shutdown_requested() => Ok(()),
                Ok(Ok(DeviceExit::Cancelled)) => Err(JoinError::UnexpectedExit),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(JoinError::Panicked),
            };
        if let Err(error) = &result {
            self.report(error.clone());
        }
        result
    }
}

impl DeviceFailureObserver {
    pub fn check(&self) -> Result<(), DeviceFailure> {
        match &*self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            Some(failure) => Err(failure.clone()),
            None => Ok(()),
        }
    }
}

/// Token passed to a running device thread host.
#[derive(Clone)]
pub struct RunToken {
    is_shutdown_requested: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for RunToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunToken").finish_non_exhaustive()
    }
}

impl RunToken {
    pub fn from_fn(is_shutdown_requested: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            is_shutdown_requested: Arc::new(is_shutdown_requested),
        }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        (self.is_shutdown_requested)()
    }
}

/// Handle for one running device host.
pub struct DeviceHandle {
    shutdown: Box<dyn Fn() -> Result<(), ShutdownError> + Send + Sync>,
    join: Option<Box<dyn FnOnce() -> Result<(), JoinError> + Send>>,
}

impl std::fmt::Debug for DeviceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceHandle").finish_non_exhaustive()
    }
}

impl DeviceHandle {
    pub fn new(
        shutdown: impl Fn() -> Result<(), ShutdownError> + Send + Sync + 'static,
        join: impl FnOnce() -> Result<(), JoinError> + Send + 'static,
    ) -> Self {
        Self {
            shutdown: Box::new(shutdown),
            join: Some(Box::new(join)),
        }
    }

    pub fn noop() -> Self {
        Self::new(|| Ok(()), || Ok(()))
    }

    pub fn shutdown(&self) -> Result<(), ShutdownError> {
        (self.shutdown)()
    }

    pub fn join(mut self) -> Result<(), JoinError> {
        let _ = self.shutdown();
        if let Some(join) = self.join.take() {
            join()
        } else {
            Ok(())
        }
    }
}

/// Error from spawning a device worker.
#[derive(Debug, thiserror::Error)]
pub struct SpawnError;

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MMIO device worker spawn failed")
    }
}

/// Error from requesting device worker shutdown.
#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    #[error("MMIO device worker shutdown is unsupported")]
    Unsupported,

    #[error("MMIO device worker shutdown I/O failed: {0}")]
    Io(std::io::Error),
}

/// Error from joining a device host.
#[derive(Debug, Clone, thiserror::Error)]
pub enum JoinError {
    #[error("MMIO device host panicked")]
    Panicked,

    #[error("MMIO device host failed: {0}")]
    Host(String),

    #[error("device worker returned before cancellation")]
    UnexpectedExit,

    #[error("device worker spawn failed: {0}")]
    Spawn(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_failure_is_sticky_and_bound_to_its_machine() {
        let machine = DeviceFailureReporter::default();
        let observer = machine.observer();
        let other = DeviceFailureReporter::default();
        let worker = machine.scoped("MMIO 0x1000").scoped("PCI slot 2/net TX");
        worker.report(JoinError::Spawn("out of resources".into()));
        machine.scoped("peer").report(JoinError::Panicked);
        drop(machine);
        for _ in 0..2 {
            let failure = observer.check().unwrap_err();
            assert_eq!(failure.participant, "MMIO 0x1000/PCI slot 2/net TX");
            assert!(matches!(failure.cause, JoinError::Spawn(_)));
        }
        assert!(other.observer().check().is_ok());
    }

    #[test]
    fn explicit_worker_exits_preserve_failure_over_cancellation() {
        for cancelled in [false, true] {
            for outcome in 0..4 {
                let failures = DeviceFailureReporter::default();
                let reporter = failures.scoped("queue");
                let result = reporter.run(
                    Box::new(move |_| match outcome {
                        0 => Ok(DeviceExit::Cancelled),
                        1 => Ok(DeviceExit::EndpointClosed),
                        2 => Err(JoinError::Host("request loop failed".into())),
                        _ => panic!("worker panic"),
                    }),
                    RunToken::from_fn(move || cancelled),
                );
                let fails = outcome >= 2 || (outcome == 0 && !cancelled);
                assert_eq!(result.is_err(), fails);
                assert_eq!(failures.observer().check().is_err(), fails);
                if outcome == 0 && !cancelled {
                    assert!(matches!(result, Err(JoinError::UnexpectedExit)));
                }
            }
        }
    }

    #[test]
    fn failure_during_consuming_join_is_published_after_cancellation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let failures = DeviceFailureReporter::default();
        let reporter = failures.scoped("blk final flush");
        let observer = failures.observer();
        let cancelled = Arc::new(AtomicBool::new(false));
        let token_cancelled = Arc::clone(&cancelled);
        let worker = std::thread::spawn(move || {
            reporter.run(
                Box::new(|token| {
                    while !token.is_shutdown_requested() {
                        std::thread::yield_now();
                    }
                    Err(JoinError::Host("late flush failure".into()))
                }),
                RunToken::from_fn(move || token_cancelled.load(Ordering::Acquire)),
            )
        });
        let handle = DeviceHandle::new(
            move || {
                cancelled.store(true, Ordering::Release);
                Ok(())
            },
            move || worker.join().unwrap(),
        );
        assert!(
            observer.check().is_ok(),
            "success is still only a candidate before retirement"
        );
        assert!(handle.join().is_err());
        assert!(
            observer
                .check()
                .unwrap_err()
                .to_string()
                .contains("late flush failure")
        );
    }

    #[test]
    fn handle_shutdown_and_join_are_invoked() {
        let shutdown_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let join_seen = Arc::clone(&shutdown_seen);
        let handle = DeviceHandle::new(
            {
                let shutdown_seen = Arc::clone(&shutdown_seen);
                move || {
                    shutdown_seen.store(true, std::sync::atomic::Ordering::Release);
                    Ok(())
                }
            },
            move || {
                assert!(join_seen.load(std::sync::atomic::Ordering::Acquire));
                Ok(())
            },
        );

        handle.shutdown().expect("shutdown requested");
        handle.join().expect("joined");
    }

    #[test]
    fn handle_error_reaches_join() {
        let handle = DeviceHandle::new(|| Ok(()), || Err(JoinError::Host("boom".into())));

        let err = handle.join().expect_err("host error");
        assert_eq!(err.to_string(), "MMIO device host failed: boom");
    }

    #[test]
    fn noop_handle_shutdown_and_join_are_harmless() {
        let handle = DeviceHandle::noop();

        handle.shutdown().expect("noop shutdown");
        handle.join().expect("noop join");
    }
}
