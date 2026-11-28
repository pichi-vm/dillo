// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Device execution ownership. Wire adapters erase states only at their boundary.
//!
//! ```compile_fail
//! use dillo_virtio::lifecycle::{Backend, Device, Running};
//! fn reset<B: Backend>(device: Device<B, Running>) { device.reset(); }
//! ```
//! ```compile_fail
//! use dillo_virtio::lifecycle::{Backend, Device, Quiescing};
//! fn resume<B: Backend>(device: Device<B, Quiescing>) { device.resume(); }
//! ```

use crate::pause::Barrier;
use crate::{
    ActivateError, DeviceJoinError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
    VirtioDeviceHost, VirtioRunToken,
};
use std::{
    io,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

/// Device logic; execution state lives in `Device`, not in each backend.
/// Workers must checkpoint between admitted requests, after publication and
/// releasing locks. Activation failure must retire every worker it started.
pub trait Backend: Send + 'static {
    fn device_type(&self) -> u32;
    fn queue_max_sizes(&self) -> &[u16];
    fn num_queues(&self) -> usize {
        self.queue_max_sizes().len()
    }
    fn features(&self) -> u64;
    fn activate(&mut self, activation: VirtioActivate)
    -> Result<VirtioDeviceHandle, ActivateError>;
    fn read_config(&self, offset: u64, data: &mut [u8]);
    fn write_config(&mut self, offset: u64, data: &[u8]);
    fn reset(&mut self) -> Result<(), ActivateError>;
}

/// Temporary bridge for device implementations outside the two-device pilot.
#[derive(Debug)]
pub struct Legacy<T>(pub T);
impl<T: VirtioDevice + 'static> Backend for Legacy<T> {
    fn device_type(&self) -> u32 {
        self.0.device_type()
    }
    fn queue_max_sizes(&self) -> &[u16] {
        self.0.queue_max_sizes()
    }
    fn features(&self) -> u64 {
        self.0.features()
    }
    fn activate(&mut self, a: VirtioActivate) -> Result<VirtioDeviceHandle, ActivateError> {
        self.0.activate(a)
    }
    fn read_config(&self, o: u64, d: &mut [u8]) {
        self.0.read_config(o, d);
    }
    fn write_config(&mut self, o: u64, d: &[u8]) {
        self.0.write_config(o, d);
    }
    fn reset(&mut self) -> Result<(), ActivateError> {
        self.0.reset()
    }
}
impl Backend for Box<dyn Backend> {
    fn device_type(&self) -> u32 {
        (**self).device_type()
    }
    fn queue_max_sizes(&self) -> &[u16] {
        (**self).queue_max_sizes()
    }
    fn features(&self) -> u64 {
        (**self).features()
    }
    fn activate(&mut self, a: VirtioActivate) -> Result<VirtioDeviceHandle, ActivateError> {
        (**self).activate(a)
    }
    fn read_config(&self, o: u64, d: &mut [u8]) {
        (**self).read_config(o, d);
    }
    fn write_config(&mut self, o: u64, d: &[u8]) {
        (**self).write_config(o, d);
    }
    fn reset(&mut self) -> Result<(), ActivateError> {
        (**self).reset()
    }
}

mod private {
    pub trait Sealed {}
}
pub trait State: private::Sealed {}
#[derive(Debug)]
pub struct Unconfigured;
#[derive(Debug)]
pub struct Configured {
    features: u64,
}
#[derive(Debug)]
pub struct Running(Execution);
#[derive(Debug)]
pub struct Quiescing(Execution);
#[derive(Debug)]
pub struct Quiesced(Execution);
#[derive(Debug)]
pub struct Stopping(Execution);
// A failed start or join never confers permission to resume or reset.
#[derive(Debug)]
pub struct Failed {
    _execution: Execution,
}
macro_rules! states {
    ($($s:ty),*) => { $(impl private::Sealed for $s {} impl State for $s {})* };
}
states!(
    Unconfigured,
    Configured,
    Running,
    Quiescing,
    Quiesced,
    Stopping,
    Failed
);

#[derive(Debug)]
pub struct Device<B: Backend, S: State> {
    // Retire workers before dropping their backend's resources.
    state: S,
    backend: B,
}
impl<B: Backend, S: State> Device<B, S> {
    fn transition<T: State>(self, state: T) -> Device<B, T> {
        Device {
            backend: self.backend,
            state,
        }
    }
    pub fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.backend.read_config(offset, data);
    }
    pub fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.backend.write_config(offset, data);
    }
}
impl<B: Backend> Device<B, Unconfigured> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: Unconfigured,
        }
    }
    pub fn configure(self, features: u64) -> Result<Device<B, Configured>, (Self, ActivateError)> {
        if features & !self.backend.features() != 0 {
            return Err((self, invalid("unsupported device features")));
        }
        Ok(self.transition(Configured { features }))
    }
}
impl<B: Backend> Device<B, Configured> {
    pub fn start(
        mut self,
        mut activation: VirtioActivate,
    ) -> Result<Device<B, Running>, (Device<B, Failed>, ActivateError)> {
        let mut execution = Execution::default();
        activation = activation.with_negotiated_features(self.state.features);
        let result = activation.managed(&execution.barrier).and_then(|wakes| {
            execution.wakes = wakes;
            self.backend.activate(activation)
        });
        match result {
            Ok(handle) => {
                execution.handle = Some(handle);
                Ok(self.transition(Running(execution)))
            }
            Err(error) => Err((
                self.transition(Failed {
                    _execution: execution,
                }),
                error,
            )),
        }
    }
}
impl<B: Backend> Device<B, Running> {
    pub fn request_quiesce(self) -> Device<B, Quiescing> {
        let Device {
            backend,
            state: Running(mut execution),
        } = self;
        execution.barrier.requested.store(true, Ordering::Release);
        execution.wake_error = execution.wake().err();
        Device {
            backend,
            state: Quiescing(execution),
        }
    }
    pub fn request_stop(self) -> Device<B, Stopping> {
        let Device {
            backend,
            state: Running(mut execution),
        } = self;
        execution.stop();
        Device {
            backend,
            state: Stopping(execution),
        }
    }
}
impl<B: Backend> Device<B, Quiescing> {
    pub fn finish(
        mut self,
        timeout: Duration,
    ) -> Result<Device<B, Quiesced>, (Self, ActivateError)> {
        if let Some(error) = self.state.0.wake_error.take() {
            return Err((self, error.into()));
        }
        if !self.state.0.barrier.wait(timeout) {
            return Err((self, io::Error::from(io::ErrorKind::TimedOut).into()));
        }
        let Device {
            backend,
            state: Quiescing(execution),
        } = self;
        Ok(Device {
            backend,
            state: Quiesced(execution),
        })
    }
    pub fn request_stop(self) -> Device<B, Stopping> {
        let Device {
            backend,
            state: Quiescing(mut execution),
        } = self;
        execution.stop();
        Device {
            backend,
            state: Stopping(execution),
        }
    }
}
impl<B: Backend> Device<B, Quiesced> {
    pub fn reset(self) -> Result<Device<B, Unconfigured>, (Device<B, Failed>, ActivateError)> {
        self.request_stop().join()
    }
    pub fn resume(self) -> Result<Device<B, Running>, (Device<B, Quiescing>, ActivateError)> {
        let Device {
            backend,
            state: Quiesced(execution),
        } = self;
        // Wake before releasing the barrier. A failed wake leaves it held.
        if let Err(error) = execution.wake() {
            return Err((
                Device {
                    backend,
                    state: Quiescing(execution),
                },
                error.into(),
            ));
        }
        execution.barrier.resume();
        Ok(Device {
            backend,
            state: Running(execution),
        })
    }
    pub fn request_stop(self) -> Device<B, Stopping> {
        let Device {
            backend,
            state: Quiesced(mut execution),
        } = self;
        execution.stop();
        Device {
            backend,
            state: Stopping(execution),
        }
    }
}
impl<B: Backend> Device<B, Stopping> {
    pub fn join(self) -> Result<Device<B, Unconfigured>, (Device<B, Failed>, ActivateError)> {
        let Device {
            mut backend,
            state: Stopping(mut execution),
        } = self;
        let result = execution
            .join()
            .map_err(|e| invalid(&e.to_string()))
            .and_then(|()| backend.reset());
        match result {
            Ok(()) => Ok(Device::new(backend)),
            Err(error) => Err((
                Device {
                    backend,
                    state: Failed {
                        _execution: execution,
                    },
                },
                error,
            )),
        }
    }
}

#[derive(Debug, Default)]
struct Execution {
    handle: Option<VirtioDeviceHandle>,
    barrier: Arc<Barrier>,
    wakes: Vec<Kick>,
    wake_error: Option<io::Error>,
}
impl Execution {
    fn wake(&self) -> io::Result<()> {
        let mut first = None;
        for kick in &self.wakes {
            if let Err(error) = kick.write(1) {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
    fn stop(&mut self) {
        if let Some(handle) = &mut self.handle {
            handle.shutdown();
        }
        self.barrier.resume();
    }
    fn join(&mut self) -> Result<(), DeviceJoinError> {
        self.stop();
        self.handle.take().map_or(Ok(()), VirtioDeviceHandle::join)
    }
}
impl Drop for Execution {
    fn drop(&mut self) {
        if let Err(error) = self.join() {
            log::warn!("device retirement: {error}");
        }
    }
}

pub(crate) struct Host {
    pub(crate) inner: Arc<dyn VirtioDeviceHost>,
    pub(crate) barrier: Arc<Barrier>,
}
impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleHost").finish_non_exhaustive()
    }
}
impl VirtioDeviceHost for Host {
    fn notification(&self) -> io::Result<Kick> {
        self.inner.notification()
    }
    fn shared_memory(&self) -> Vec<Arc<dyn dillo_mmio::SharedMemory>> {
        self.inner.shared_memory()
    }
    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let participant = self.barrier.register();
        self.inner.spawn(Box::new(move |token| {
            let checkpoint = token.clone();
            run(token.with_checkpoint(move || {
                checkpoint.checkpoint();
                participant.checkpoint(&checkpoint);
            }))
        }))
    }
}

/// The dynamic boundary needed by transports and the wire decoder. Each
/// variant owns a complete typed device; there is no independent active flag.
#[derive(Debug)]
pub enum Slot<B: Backend> {
    Unconfigured(Device<B, Unconfigured>),
    Configured(Device<B, Configured>),
    Running(Device<B, Running>),
    Quiescing(Device<B, Quiescing>),
    Quiesced(Device<B, Quiesced>),
    Stopping(Device<B, Stopping>),
    Failed(Device<B, Failed>),
    Vacant,
}
impl<B: Backend> Slot<B> {
    pub fn new(backend: B) -> Self {
        Self::Unconfigured(Device::new(backend))
    }
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Vacant)
    }
    fn backend(&self) -> &B {
        match self {
            Self::Unconfigured(d) => &d.backend,
            Self::Configured(d) => &d.backend,
            Self::Running(d) => &d.backend,
            Self::Quiescing(d) => &d.backend,
            Self::Quiesced(d) => &d.backend,
            Self::Stopping(d) => &d.backend,
            Self::Failed(d) => &d.backend,
            Self::Vacant => panic!("device transition interrupted"),
        }
    }
    pub fn features(&self) -> u64 {
        self.backend().features()
    }
    pub fn queue_max_sizes(&self) -> &[u16] {
        self.backend().queue_max_sizes()
    }
    pub fn read_config(&self, o: u64, d: &mut [u8]) {
        self.backend().read_config(o, d);
    }
    pub fn write_config(&mut self, o: u64, data: &[u8]) {
        match self {
            Self::Unconfigured(d) => d.write_config(o, data),
            Self::Configured(d) => d.write_config(o, data),
            Self::Running(d) => d.write_config(o, data),
            Self::Quiescing(d) => d.write_config(o, data),
            Self::Quiesced(d) => d.write_config(o, data),
            Self::Stopping(d) => d.write_config(o, data),
            Self::Failed(d) => d.write_config(o, data),
            Self::Vacant => (),
        }
    }
    pub fn drained(&mut self) -> Result<Drained<'_>, ActivateError> {
        match self {
            Self::Quiesced(device) => Ok(device.drained()),
            Self::Unconfigured(_) | Self::Configured(_) => Ok(Drained { barrier: None }),
            _ => Err(invalid("device has not drained")),
        }
    }
    pub fn active(&self) -> bool {
        !matches!(self, Self::Unconfigured(_) | Self::Configured(_))
    }
    pub fn start(&mut self, activation: VirtioActivate) -> Result<(), ActivateError> {
        let features = activation.negotiated_features();
        let device = match self.take() {
            Self::Unconfigured(d) => d,
            other => {
                *self = other;
                return Err(invalid("device already started"));
            }
        };
        let device = match device.configure(features) {
            Ok(d) => d,
            Err((d, e)) => {
                *self = Self::Unconfigured(d);
                return Err(e);
            }
        };
        match device.start(activation) {
            Ok(d) => {
                *self = Self::Running(d);
                Ok(())
            }
            Err((d, e)) => {
                *self = Self::Failed(d);
                Err(e)
            }
        }
    }
    pub fn quiesce(&mut self) -> Result<(), ActivateError> {
        let d = match self.take() {
            Self::Running(d) => d.request_quiesce(),
            Self::Quiescing(d) => d,
            other @ (Self::Quiesced(_) | Self::Unconfigured(_) | Self::Configured(_)) => {
                *self = other;
                return Ok(());
            }
            other => {
                *self = other;
                return Err(invalid("device cannot drain"));
            }
        };
        match d.finish(Duration::from_secs(5)) {
            Ok(d) => {
                *self = Self::Quiesced(d);
                Ok(())
            }
            Err((d, e)) => {
                *self = Self::Quiescing(d);
                Err(e)
            }
        }
    }
    pub fn resume(&mut self) -> Result<(), ActivateError> {
        match self.take() {
            Self::Quiesced(d) => match d.resume() {
                Ok(d) => {
                    *self = Self::Running(d);
                    Ok(())
                }
                Err((d, e)) => {
                    *self = Self::Quiescing(d);
                    Err(e)
                }
            },
            other @ (Self::Running(_) | Self::Unconfigured(_) | Self::Configured(_)) => {
                *self = other;
                Ok(())
            }
            other => {
                *self = other;
                Err(invalid("device cannot resume before drain"))
            }
        }
    }
    pub fn request_stop(&mut self) {
        *self = match self.take() {
            Self::Running(d) => Self::Stopping(d.request_stop()),
            Self::Quiescing(d) => Self::Stopping(d.request_stop()),
            Self::Quiesced(d) => Self::Stopping(d.request_stop()),
            other => other,
        };
    }
    fn reset_idle(&mut self) -> Result<(), ActivateError> {
        match self {
            Self::Unconfigured(device) => device.backend.reset(),
            _ => Err(invalid("activation handle must be joined before reset")),
        }
    }

    pub fn reset(&mut self) -> Result<(), ActivateError> {
        self.request_stop();
        match self.take() {
            Self::Stopping(d) => match d.join() {
                Ok(d) => {
                    *self = Self::Unconfigured(d);
                    Ok(())
                }
                Err((d, e)) => {
                    *self = Self::Failed(d);
                    Err(e)
                }
            },
            Self::Unconfigured(mut d) => {
                let r = d.backend.reset();
                *self = Self::Unconfigured(d);
                r
            }
            other => {
                *self = other;
                Err(invalid(
                    "device cannot reset after failed activation or retirement",
                ))
            }
        }
    }
}

/// Borrowed proof that the corresponding execution domain has drained. The
/// borrow prevents resume while an adapter changes its rings or memory map.
#[derive(Debug)]
pub struct Drained<'a> {
    barrier: Option<&'a Arc<Barrier>>,
}
impl Drained<'_> {
    pub(crate) fn check(&self, control: &crate::queue::QueueControl) -> Result<(), ActivateError> {
        let domain = control.domain.lock().unwrap();
        match (
            domain.as_ref().and_then(std::sync::Weak::upgrade),
            self.barrier,
        ) {
            (None, None) => Ok(()),
            (Some(domain), Some(barrier)) if Arc::ptr_eq(&domain, barrier) => Ok(()),
            _ => Err(invalid("ring belongs to a different execution domain")),
        }
    }
}
impl<B: Backend> Device<B, Quiesced> {
    pub fn drained(&mut self) -> Drained<'_> {
        Drained {
            barrier: Some(&self.state.0.barrier),
        }
    }
}

fn invalid(message: &str) -> ActivateError {
    ActivateError::InvalidConfig(message.into())
}

/// Bridge for the existing PCI/MMIO transport API. Its shared control owner
/// exists only on the control path; workers never acquire this mutex.
#[derive(Debug)]
pub struct Local<B: Backend> {
    slot: Arc<Mutex<Slot<B>>>,
    kind: u32,
    sizes: Vec<u16>,
    features: u64,
}
impl<B: Backend> Local<B> {
    pub fn new(backend: B) -> Self {
        Self {
            kind: backend.device_type(),
            sizes: backend.queue_max_sizes().to_vec(),
            features: backend.features(),
            slot: Arc::new(Mutex::new(Slot::new(backend))),
        }
    }
}
impl<B: Backend> VirtioDevice for Local<B> {
    fn device_type(&self) -> u32 {
        self.kind
    }
    fn num_queues(&self) -> usize {
        self.sizes.len()
    }
    fn queue_max_sizes(&self) -> &[u16] {
        &self.sizes
    }
    fn features(&self) -> u64 {
        self.features
    }
    fn read_config(&self, o: u64, d: &mut [u8]) {
        self.slot.lock().unwrap().read_config(o, d);
    }
    fn write_config(&mut self, o: u64, d: &[u8]) {
        self.slot.lock().unwrap().write_config(o, d);
    }
    fn activate(
        &mut self,
        activation: VirtioActivate,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        self.slot.lock().unwrap().start(activation)?;
        let stop = Arc::clone(&self.slot);
        let join = Arc::clone(&self.slot);
        Ok(VirtioDeviceHandle::new(
            move || stop.lock().unwrap().request_stop(),
            move || {
                join.lock()
                    .unwrap()
                    .reset()
                    .map_err(|e| DeviceJoinError::Worker(e.to_string()))
            },
        ))
    }
    fn quiesce(&mut self) -> Result<(), ActivateError> {
        self.slot.lock().unwrap().quiesce()
    }
    fn resume(&mut self) -> Result<(), ActivateError> {
        self.slot.lock().unwrap().resume()
    }
    fn reset(&mut self) -> Result<(), ActivateError> {
        self.slot.lock().unwrap().reset_idle()
    }
}
