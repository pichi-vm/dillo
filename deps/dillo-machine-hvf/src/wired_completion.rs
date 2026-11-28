// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Experimental shared-status completion using the existing Unix call pipe.

use std::io;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use dillo_machine::worker::{NotificationRole, NotificationState, Resource, WriteNotification};
use dillo_mmio::{InterruptError, InterruptLine, InterruptUpdate};

use crate::hypervisor::Vm;

pub(crate) fn bind(
    vm: Vm,
    intid: u32,
    level: bool,
    state: Arc<NotificationState>,
    update: Option<Arc<dyn InterruptUpdate>>,
) -> Arc<Completion> {
    Arc::new(Completion {
        delivery: Arc::new(Delivery {
            vm,
            intid,
            level,
            state,
            lifetime: Mutex::new(Lifetime::Active),
        }),
        update,
        pipe: Mutex::new(None),
    })
}

#[derive(Debug)]
struct Delivery {
    vm: Vm,
    intid: u32,
    level: bool,
    state: Arc<NotificationState>,
    lifetime: Mutex<Lifetime>,
}

#[derive(Debug, PartialEq)]
enum Lifetime {
    Active,
    Retiring,
    Retired,
}

impl Delivery {
    fn refresh(&self, pulse: bool) -> io::Result<bool> {
        // ACK and call delivery take the same lock, then read the latch. An
        // ACK whose earlier zero observation is stale cannot lower a new level.
        let lifetime = self.lifetime.lock().unwrap();
        if *lifetime == Lifetime::Active {
            let pending = self.state.load() != 0;
            if self.level {
                self.vm
                    .set_spi(self.intid, pending)
                    .map_err(io::Error::other)?;
            } else if pulse && pending {
                let asserted = self.vm.set_spi(self.intid, true);
                let lowered = self.vm.set_spi(self.intid, false);
                asserted.and(lowered).map_err(io::Error::other)?;
            }
        }
        Ok(*lifetime == Lifetime::Active)
    }

    fn retire(&self) -> io::Result<()> {
        let mut lifetime = self.lifetime.lock().unwrap();
        if *lifetime != Lifetime::Retired {
            *lifetime = Lifetime::Retiring;
            self.vm
                .set_spi(self.intid, false)
                .map_err(io::Error::other)?;
            *lifetime = Lifetime::Retired;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Pipe {
    sender: Resource,
    receiver: Arc<dyn WriteNotification>,
    thread: JoinHandle<io::Result<()>>,
}

#[derive(Debug)]
pub(crate) struct Completion {
    delivery: Arc<Delivery>,
    update: Option<Arc<dyn InterruptUpdate>>,
    pipe: Mutex<Option<Pipe>>,
}

impl InterruptLine for Completion {
    fn signal(&self) {
        if let Err(error) = self.set_level(true) {
            if let Some(update) = &self.update {
                update.failed(format!("HVF wired completion: {error}"));
            }
            log::error!("HVF wired completion: {error}");
        }
    }

    fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        self.delivery.refresh(level).map(|_| ()).map_err(delivery)
    }

    fn export(&self) -> io::Result<Option<Resource>> {
        let mut pipe = self.pipe.lock().unwrap();
        if *self.delivery.lifetime.lock().unwrap() != Lifetime::Active {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if pipe.is_none() {
            let (read, sender) = dillo_machine_unix::notification::pair()?;
            let receiver = dillo_machine_unix::notification::adopt(read, NotificationRole::Wait)?;
            let waiting = Arc::clone(&receiver);
            let delivery = Arc::clone(&self.delivery);
            let update = self.update.clone();
            let thread = std::thread::Builder::new()
                .name("mmio-call".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        loop {
                            waiting.read()?;
                            if !delivery.refresh(true)? {
                                return Ok(());
                            }
                        }
                    }))
                    .unwrap_or_else(|_| Err(io::Error::other("completion receiver panicked")));
                    if let Err(error) = &result
                        && let Some(update) = update
                    {
                        update.failed(format!("HVF wired completion: {error}"));
                    }
                    result
                })?;
            *pipe = Some(Pipe {
                sender,
                receiver,
                thread,
            });
        }
        // All queues of this activation share one call receiver. The in-process
        // path never exports, so it needs neither a pipe nor a helper thread.
        pipe.as_ref().unwrap().sender.try_clone().map(Some)
    }

    fn retire(&self) -> Result<(), InterruptError> {
        let mut pipe = self.pipe.lock().unwrap();
        let revoked = self.delivery.retire();
        // Revocation precedes the wake/join, even if lowering the SPI fails.
        // No surviving writer can signal this or a replacement activation.
        let joined = if let Some(bound) = pipe.as_ref() {
            bound.receiver.write(1).and_then(|()| {
                pipe.take()
                    .unwrap()
                    .thread
                    .join()
                    .map_err(|_| io::Error::other("completion receiver panicked"))?
            })
        } else {
            Ok(())
        };
        revoked.and(joined).map_err(delivery)
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        if let Err(error) = self.retire() {
            log::error!("retire HVF wired completion: {error}");
        }
    }
}

fn delivery(error: impl std::fmt::Display) -> InterruptError {
    InterruptError::Delivery(error.to_string())
}
