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
pub(crate) struct Barrier {
    pub(crate) requested: Arc<AtomicBool>,
    state: Mutex<State>,
    changed: Condvar,
}

impl Barrier {
    pub(crate) fn register(self: &Arc<Self>) -> Participant {
        self.state.lock().unwrap().workers += 1;
        Participant(Arc::clone(self))
    }

    pub(crate) fn wait(&self) {
        let mut state = self.state.lock().unwrap();
        while state.parked != state.workers {
            state = self.changed.wait(state).unwrap();
        }
    }

    pub(crate) fn resume(&self) {
        let _state = self.state.lock().unwrap();
        self.requested.store(false, Ordering::Release);
        self.changed.notify_all();
    }

    pub(crate) fn wake(&self) {
        let _state = self.state.lock().unwrap();
        self.changed.notify_all();
    }
}

pub(crate) struct Participant(Arc<Barrier>);

impl Participant {
    pub(crate) fn checkpoint(&self, stopped: &AtomicBool) {
        if !self.0.requested.load(Ordering::Acquire) {
            return;
        }
        let mut state = self.0.state.lock().unwrap();
        if self.0.requested.load(Ordering::Acquire) && !stopped.load(Ordering::Acquire) {
            state.parked += 1;
            self.0.changed.notify_all();
            while self.0.requested.load(Ordering::Acquire) && !stopped.load(Ordering::Acquire) {
                state = self.0.changed.wait(state).unwrap();
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
