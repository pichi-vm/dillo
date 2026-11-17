// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Device execution callbacks, shutdown requests and consuming joins.

use std::sync::Arc;

pub type DeviceRun = Box<dyn FnOnce(RunToken) -> Result<(), JoinError> + Send + 'static>;

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
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("MMIO device host panicked")]
    Panicked,

    #[error("MMIO device host failed: {0}")]
    Host(String),
}

#[cfg(test)]
mod tests {
    use super::*;

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
