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
pub struct Kick(Arc<Inner>);

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

    pub fn read(&self) -> std::io::Result<u64> {
        let mut count = self.0.count.lock().expect("kick mutex poisoned");
        while *count == 0 {
            count = self.0.cv.wait(count).expect("kick mutex poisoned");
        }
        Ok(std::mem::take(&mut *count))
    }

    pub fn write(&self, count: u64) -> std::io::Result<()> {
        let mut guard = self.0.count.lock().expect("kick mutex poisoned");
        *guard = guard.saturating_add(count);
        self.0.cv.notify_one();
        Ok(())
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self(Arc::clone(&self.0)))
    }
}
