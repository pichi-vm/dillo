// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Default)]
struct State {
    workers: usize,
    parked: usize,
}

#[derive(Debug, Default)]
pub(super) struct Barrier {
    pub(super) requested: Arc<AtomicBool>,
    state: Mutex<State>,
    changed: Condvar,
}

impl Barrier {
    pub(super) fn register(self: &Arc<Self>) -> Participant {
        self.state.lock().unwrap().workers += 1;
        Participant(Arc::clone(self))
    }

    pub(super) fn wait(&self, timeout: std::time::Duration) -> bool {
        let (state, _) = self
            .changed
            .wait_timeout_while(self.state.lock().unwrap(), timeout, |s| {
                s.parked != s.workers
            })
            .unwrap();
        state.parked == state.workers
    }

    pub(super) fn resume(&self) {
        let _state = self.state.lock().unwrap();
        self.requested.store(false, Ordering::Release);
        self.changed.notify_all();
    }
}

pub(super) struct Participant(Arc<Barrier>);

impl Participant {
    pub(super) fn checkpoint(&self, token: &crate::VirtioRunToken) {
        if !self.0.requested.load(Ordering::Acquire) {
            return;
        }
        let mut state = self.0.state.lock().unwrap();
        if self.0.requested.load(Ordering::Acquire) && !token.is_shutdown_requested() {
            state.parked += 1;
            self.0.changed.notify_all();
            while self.0.requested.load(Ordering::Acquire) && !token.is_shutdown_requested() {
                (state, _) = self
                    .0
                    .changed
                    .wait_timeout(state, std::time::Duration::from_millis(10))
                    .unwrap();
            }
            state.parked -= 1;
        }
    }
}

impl Drop for Participant {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().workers -= 1;
        self.0.changed.notify_all();
    }
}
