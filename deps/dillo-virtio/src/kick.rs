// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Cross-platform virtqueue kick primitive.
//!
//! A kick signals "this queue has new descriptors". Backends may accelerate
//! guest notify writes internally, but portable virtio devices only observe a
//! queue kick through this target-neutral blocking counter.

use std::sync::{Arc, Condvar, Mutex};

/// Queue notification shared between the transport and a device worker.
#[derive(Clone, Debug)]
pub struct Kick(Arc<dyn dillo_mmio::WriteNotification>);

#[derive(Debug)]
struct Inner {
    count: Mutex<u64>,
    cv: Condvar,
}

impl Kick {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self(Arc::new(Inner {
            count: Mutex::new(0),
            cv: Condvar::new(),
        })))
    }

    pub fn from_notification(notification: Arc<dyn dillo_mmio::WriteNotification>) -> Self {
        Self(notification)
    }

    pub fn read(&self) -> std::io::Result<u64> {
        self.0.read()
    }

    pub fn write(&self, count: u64) -> std::io::Result<()> {
        self.0.write(count)
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(self.clone())
    }
}

impl dillo_mmio::WriteNotification for Inner {
    fn read(&self) -> std::io::Result<u64> {
        let mut count = self.count.lock().expect("kick mutex poisoned");
        while *count == 0 {
            count = self.cv.wait(count).expect("kick mutex poisoned");
        }
        Ok(std::mem::take(&mut *count))
    }

    fn write(&self, count: u64) -> std::io::Result<()> {
        let mut guard = self.count.lock().expect("kick mutex poisoned");
        *guard = guard.saturating_add(count);
        self.cv.notify_one();
        Ok(())
    }
}
