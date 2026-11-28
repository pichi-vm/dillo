// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A unique control owner for a ring; lifecycle and enablement are independent.
//!
//! ```compile_fail
//! use dillo_virtio::ring::{Ring, Started, Enabled};
//! fn configure(ring: Ring<Started, Enabled>, queue: dillo_virtio::Queue) {
//!     ring.configure(queue);
//! }
//! ```
//! ```compile_fail
//! use dillo_virtio::ring::{Ring, Unconfigured, Disabled};
//! fn start(ring: Ring<Unconfigured, Disabled>) { ring.start(); }
//! ```
use crate::{ActivateError, Queue, lifecycle::Drained, queue::QueueControl};
use std::{
    marker::PhantomData,
    sync::{Arc, atomic::Ordering},
};

mod private {
    pub trait Sealed {}
}
pub trait Life: private::Sealed {}
pub trait Enablement: private::Sealed {}
#[derive(Debug)]
pub struct Unconfigured;
#[derive(Debug)]
pub struct Stopped;
#[derive(Debug)]
pub struct Started;
#[derive(Debug)]
pub struct Enabled;
#[derive(Debug)]
pub struct Disabled;
impl private::Sealed for Unconfigured {}
impl Life for Unconfigured {}
impl private::Sealed for Stopped {}
impl Life for Stopped {}
impl private::Sealed for Started {}
impl Life for Started {}
impl private::Sealed for Enabled {}
impl Enablement for Enabled {}
impl private::Sealed for Disabled {}
impl Enablement for Disabled {}

#[derive(Debug)]
pub struct Ring<L: Life, E: Enablement> {
    control: Arc<QueueControl>,
    state: PhantomData<(L, E)>,
}
impl Ring<Unconfigured, Disabled> {
    pub fn new() -> Self {
        Self {
            control: Arc::default(),
            state: PhantomData,
        }
    }
}
impl Default for Ring<Unconfigured, Disabled> {
    fn default() -> Self {
        Self::new()
    }
}
impl<L: Life, E: Enablement> Ring<L, E> {
    fn transition<N: Life, F: Enablement>(self) -> Ring<N, F> {
        Ring {
            control: self.control,
            state: PhantomData,
        }
    }
    /// The worker endpoint has no authority to reconfigure or start the ring.
    pub fn worker_queue(&self, max: u16) -> Queue {
        let mut queue = Queue::new(max);
        queue.control_with(Arc::clone(&self.control));
        queue
    }
    pub fn enable(self, drained: &Drained<'_>) -> Result<Ring<L, Enabled>, (Self, ActivateError)> {
        if let Err(error) = drained.check(&self.control) {
            return Err((self, error));
        }
        self.control.enabled.store(true, Ordering::Release);
        Ok(self.transition())
    }
    pub fn disable(
        self,
        drained: &Drained<'_>,
    ) -> Result<Ring<L, Disabled>, (Self, ActivateError)> {
        if let Err(error) = drained.check(&self.control) {
            return Err((self, error));
        }
        self.control.enabled.store(false, Ordering::Release);
        Ok(self.transition())
    }
    fn install(self, queue: Queue) -> Result<Ring<Stopped, E>, (Self, ActivateError)> {
        if !queue.is_valid(u64::MAX) {
            return Err((
                self,
                ActivateError::InvalidConfig("invalid queue geometry".into()),
            ));
        }
        self.control.configure(queue);
        Ok(self.transition())
    }
}
impl<E: Enablement> Ring<Unconfigured, E> {
    pub fn configure(self, queue: Queue) -> Result<Ring<Stopped, E>, (Self, ActivateError)> {
        self.install(queue)
    }
}
impl<E: Enablement> Ring<Stopped, E> {
    pub fn configure(self, queue: Queue) -> Result<Self, (Self, ActivateError)> {
        self.install(queue)
    }
    pub fn start(self) -> Ring<Started, E> {
        self.control.started.store(true, Ordering::Release);
        self.transition()
    }
    pub fn base(&self) -> u16 {
        self.control.base()
    }
}
impl<E: Enablement> Ring<Started, E> {
    pub fn stop(self, drained: &Drained<'_>) -> Result<Ring<Stopped, E>, (Self, ActivateError)> {
        if let Err(error) = drained.check(&self.control) {
            return Err((self, error));
        }
        self.control.started.store(false, Ordering::Release);
        Ok(self.transition())
    }
}
