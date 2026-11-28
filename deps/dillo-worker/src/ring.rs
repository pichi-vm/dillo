// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Runtime vhost-user declarations select consuming core ring transitions.
use dillo_virtio::{
    Queue,
    lifecycle::Drained,
    ring::{Disabled, Enabled, Ring, Started, Stopped, Unconfigured},
};
use std::io;

pub(crate) enum State {
    NewDisabled(Ring<Unconfigured, Disabled>),
    NewEnabled(Ring<Unconfigured, Enabled>),
    StoppedDisabled(Ring<Stopped, Disabled>),
    StoppedEnabled(Ring<Stopped, Enabled>),
    StartedDisabled(Ring<Started, Disabled>),
    StartedEnabled(Ring<Started, Enabled>),
    Vacant,
}
macro_rules! transition {
    ($owner:ident, $expr:expr, $ok:ident, $err:ident) => {
        match $expr {
            Ok(ring) => {
                *$owner = Self::$ok(ring);
                Ok(())
            }
            Err((ring, error)) => {
                *$owner = Self::$err(ring);
                Err(io::Error::other(error))
            }
        }
    };
}
impl Default for State {
    fn default() -> Self {
        Self::NewDisabled(Ring::new())
    }
}
impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Vacant)
    }
    pub(crate) fn started(&self) -> bool {
        matches!(self, Self::StartedDisabled(_) | Self::StartedEnabled(_))
    }
    pub(crate) fn worker_queue(&self, max: u16) -> Queue {
        match self {
            Self::NewDisabled(r) => r.worker_queue(max),
            Self::NewEnabled(r) => r.worker_queue(max),
            Self::StoppedDisabled(r) => r.worker_queue(max),
            Self::StoppedEnabled(r) => r.worker_queue(max),
            Self::StartedDisabled(r) => r.worker_queue(max),
            Self::StartedEnabled(r) => r.worker_queue(max),
            Self::Vacant => unreachable!("ring transition interrupted"),
        }
    }
    pub(crate) fn configure(&mut self, queue: Queue) -> io::Result<()> {
        match self.take() {
            Self::NewDisabled(r) => {
                transition!(self, r.configure(queue), StoppedDisabled, NewDisabled)
            }
            Self::NewEnabled(r) => {
                transition!(self, r.configure(queue), StoppedEnabled, NewEnabled)
            }
            Self::StoppedDisabled(r) => {
                transition!(self, r.configure(queue), StoppedDisabled, StoppedDisabled)
            }
            Self::StoppedEnabled(r) => {
                transition!(self, r.configure(queue), StoppedEnabled, StoppedEnabled)
            }
            other => {
                *self = other;
                Err(io::ErrorKind::InvalidInput.into())
            }
        }
    }
    pub(crate) fn start(&mut self) -> io::Result<()> {
        *self = match self.take() {
            Self::StoppedDisabled(r) => Self::StartedDisabled(r.start()),
            Self::StoppedEnabled(r) => Self::StartedEnabled(r.start()),
            other @ (Self::StartedDisabled(_) | Self::StartedEnabled(_)) => other,
            other => {
                *self = other;
                return Err(io::ErrorKind::InvalidInput.into());
            }
        };
        Ok(())
    }
    pub(crate) fn stop(&mut self, drained: &Drained<'_>) -> io::Result<Option<u16>> {
        match self.take() {
            Self::StartedDisabled(r) => {
                transition!(self, r.stop(drained), StoppedDisabled, StartedDisabled)?;
            }
            Self::StartedEnabled(r) => {
                transition!(self, r.stop(drained), StoppedEnabled, StartedEnabled)?;
            }
            other => *self = other,
        }
        Ok(match self {
            Self::StoppedDisabled(r) => Some(r.base()),
            Self::StoppedEnabled(r) => Some(r.base()),
            _ => None,
        })
    }
    pub(crate) fn enable(&mut self, enabled: bool, drained: &Drained<'_>) -> io::Result<()> {
        match (self.take(), enabled) {
            (Self::NewDisabled(r), true) => {
                transition!(self, r.enable(drained), NewEnabled, NewDisabled)
            }
            (Self::StoppedDisabled(r), true) => {
                transition!(self, r.enable(drained), StoppedEnabled, StoppedDisabled)
            }
            (Self::StartedDisabled(r), true) => {
                transition!(self, r.enable(drained), StartedEnabled, StartedDisabled)
            }
            (Self::NewEnabled(r), false) => {
                transition!(self, r.disable(drained), NewDisabled, NewEnabled)
            }
            (Self::StoppedEnabled(r), false) => {
                transition!(self, r.disable(drained), StoppedDisabled, StoppedEnabled)
            }
            (Self::StartedEnabled(r), false) => {
                transition!(self, r.disable(drained), StartedDisabled, StartedEnabled)
            }
            (other, _) => {
                *self = other;
                Ok(())
            }
        }
    }
}
