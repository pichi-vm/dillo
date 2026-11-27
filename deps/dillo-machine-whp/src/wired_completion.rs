// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Experimental native completion for the existing edge-injecting IOAPIC.

use std::io;
use std::sync::{Arc, Mutex};

use dillo_machine::worker::{NotificationState, Resource, WorkerHost, WriteNotification};
use dillo_mmio::{InterruptError, InterruptLine, InterruptUpdate};

use crate::hypervisor::{InterruptController, Trigger};
use crate::ioapic::IoApicRoute;
use crate::worker::{Event, Worker};

#[derive(Debug)]
struct Binding {
    // The native action retires before its event is released.
    trigger: Option<Trigger>,
    event: Event,
    route: Option<IoApicRoute>,
    retired: bool,
}

#[derive(Debug)]
pub(crate) struct Completion {
    controller: InterruptController,
    status: Arc<NotificationState>,
    update: Option<Arc<dyn InterruptUpdate>>,
    binding: Mutex<Binding>,
}

impl Completion {
    pub(crate) fn new(
        controller: InterruptController,
        status: Arc<NotificationState>,
        update: Option<Arc<dyn InterruptUpdate>>,
    ) -> io::Result<Self> {
        Ok(Self {
            controller,
            status,
            update,
            binding: Mutex::new(Binding {
                trigger: None,
                event: Event(Worker::notification_pair()?.0),
                route: None,
                retired: false,
            }),
        })
    }

    pub(crate) fn configure(&self, route: Option<IoApicRoute>) -> io::Result<()> {
        {
            let binding = self.binding.lock().unwrap();
            if binding.retired || binding.route == route {
                return Ok(());
            }
        }
        // Do not hold binding while acquiring the worker lifecycle barrier:
        // activation exports this event while already holding that barrier.
        let mut change = || {
            let mut binding = self.binding.lock().unwrap();
            if binding.retired {
                return Ok(());
            }
            let (trigger, event) = if let Some(route) = route {
                let (trigger, event) = self
                    .controller
                    .trigger(route.destination, route.vector)
                    .map_err(native_error)?;
                (Some(trigger), event)
            } else {
                (None, Event(Worker::notification_pair()?.0))
            };
            if let Some(old) = binding.trigger.as_mut() {
                old.retire().map_err(native_error)?;
            }
            // Calls made while masked leave the shared bit set. Reassert on
            // the current route; an interrupt already requested on the old
            // route cannot be withdrawn by deleting its native trigger.
            if route.is_some() && self.status.load() != 0 {
                event.write(1)?;
            }
            *binding = Binding {
                trigger,
                event,
                route,
                retired: false,
            };
            Ok(())
        };
        if let Some(update) = &self.update {
            update.run(&mut change)
        } else {
            change()
        }
    }
}

impl InterruptLine for Completion {
    fn signal(&self) {
        if let Err(error) = self.set_level(true) {
            log::error!("WHP wired completion: {error}");
        }
    }

    fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        let binding = self.binding.lock().unwrap();
        if level && !binding.retired {
            binding
                .event
                .write(1)
                .map_err(|e| InterruptError::Delivery(e.to_string()))?;
        }
        Ok(())
    }

    fn export(&self) -> io::Result<Option<Resource>> {
        self.binding.lock().unwrap().event.export()
    }

    fn retire(&self) -> Result<(), InterruptError> {
        let mut binding = self.binding.lock().unwrap();
        binding.retired = true;
        if let Some(trigger) = binding.trigger.as_mut() {
            trigger
                .retire()
                .map_err(|e| InterruptError::Delivery(e.to_string()))?;
        }
        Ok(())
    }
}

fn native_error(status: crate::hypervisor::HResult) -> io::Error {
    io::Error::other(format!("WHP wired trigger: {status}"))
}
