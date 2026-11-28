// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use dillo_virtio::lifecycle::{Backend, Device, Local};
use dillo_virtio::{
    ActivateError, DeviceJoinError, Queue, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
    VirtioDeviceHost, VirtioRunToken,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

#[derive(Debug, Default)]
struct Host {
    workers: Arc<AtomicUsize>,
    attempts: AtomicUsize,
    fail_after: Option<usize>,
}
impl VirtioDeviceHost for Host {
    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        if self.fail_after == Some(self.attempts.fetch_add(1, Ordering::Relaxed)) {
            return Err(io::Error::other("injected spawn refusal").into());
        }
        self.workers.fetch_add(1, Ordering::AcqRel);
        let workers = Arc::clone(&self.workers);
        let stop = Arc::new(AtomicBool::new(false));
        let token = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let result = run(VirtioRunToken::from_fn(move || {
                token.load(Ordering::Acquire)
            }));
            workers.fetch_sub(1, Ordering::AcqRel);
            result
        });
        Ok(VirtioDeviceHandle::new(
            move || stop.store(true, Ordering::Release),
            move || join.join().unwrap_or(Err(DeviceJoinError::Panicked)),
        ))
    }
}

#[derive(Debug)]
struct Gated {
    entered: mpsc::Sender<()>,
    release: Option<mpsc::Receiver<()>>,
    workers: Arc<AtomicUsize>,
    resets: Arc<AtomicUsize>,
}
impl Drop for Gated {
    fn drop(&mut self) {
        assert_eq!(
            self.workers.load(Ordering::Acquire),
            0,
            "backend dropped before worker retirement"
        );
    }
}
impl Backend for Gated {
    fn device_type(&self) -> u32 {
        2
    }
    fn queue_max_sizes(&self) -> &[u16] {
        &[]
    }
    fn features(&self) -> u64 {
        0
    }
    fn activate(
        &mut self,
        mut activation: dillo_virtio::lifecycle::Activation<'_>,
    ) -> Result<(), ActivateError> {
        let entered = self.entered.clone();
        let release = self.release.take().unwrap();
        activation.spawn(
            None,
            Box::new(move |token| {
                entered.send(()).unwrap();
                release.recv().unwrap(); // an admitted blocking backend operation
                while !token.is_shutdown_requested() {
                    token.checkpoint();
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(())
            }),
        )
    }
    fn read_config(&self, _: u64, _: &mut [u8]) {}
    fn write_config(&mut self, _: u64, _: &[u8]) {}
    fn reset(&mut self) -> Result<(), ActivateError> {
        self.resets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn drain_timeout_retains_owner_until_admitted_io_finishes() {
    let host = Arc::new(Host::default());
    let (entered, wait) = mpsc::channel();
    let (release, gated) = mpsc::channel();
    let resets = Arc::new(AtomicUsize::new(0));
    let device = Device::new(Gated {
        entered,
        release: Some(gated),
        workers: host.workers.clone(),
        resets: resets.clone(),
    });
    let device = device
        .configure(0)
        .unwrap()
        .start(VirtioActivate::with_host(vec![], vec![], host.clone()))
        .unwrap();
    wait.recv_timeout(Duration::from_secs(2)).unwrap();
    let (device, _) = device.request_quiesce().finish(Duration::ZERO).unwrap_err();
    assert_eq!(host.workers.load(Ordering::Acquire), 1);
    assert_eq!(resets.load(Ordering::Relaxed), 0);
    release.send(()).unwrap();
    let device = device.finish(Duration::from_secs(2)).unwrap();
    let device = device.resume().unwrap();
    drop(device); // dropping a running owner also retires before backend Drop
    assert_eq!(host.workers.load(Ordering::Acquire), 0);
}

fn console_stdio() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        dillo_virtio_console::worker_stdio(
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
        );
    });
}

#[test]
fn partial_console_start_retires_every_spawned_worker() {
    console_stdio();
    // Failure on each spawn boundary, including the shared control worker.
    for fail_after in 0..3 {
        let host = Arc::new(Host {
            fail_after: Some(fail_after),
            ..Host::default()
        });
        let backend = dillo_virtio_console::VirtioConsole::with_ports(vec![
            dillo_virtio_console::NamedPort::new("control-only".into(), None, None),
        ]);
        let queues = (0..6).map(|_| Queue::new(256)).collect();
        let kicks = (0..6).map(|_| dillo_virtio::Kick::new().unwrap()).collect();
        let device = Device::new(backend).configure(0).unwrap();
        let (failed, _) = device
            .start(VirtioActivate::with_host(queues, kicks, host.clone()))
            .unwrap_err();
        drop(failed);
        assert_eq!(host.workers.load(Ordering::Acquire), 0);
    }
}

#[test]
fn local_console_drains_resumes_and_requires_join_before_reset() {
    console_stdio();
    let host = Arc::new(Host::default());
    let mut console = Local::new(dillo_virtio_console::VirtioConsole::with_ports(vec![
        dillo_virtio_console::NamedPort::new("control-only".into(), None, None),
    ]));
    let activate = || {
        VirtioActivate::with_host(
            (0..6).map(|_| Queue::new(256)).collect(),
            (0..6).map(|_| dillo_virtio::Kick::new().unwrap()).collect(),
            host.clone(),
        )
    };
    for _ in 0..2 {
        let handle = console.activate(activate()).unwrap();
        assert!(console.reset().is_err());
        console.quiesce().unwrap();
        // The stdin worker may already have observed the fixture's EOF.
        assert!((2..=3).contains(&host.workers.load(Ordering::Acquire)));
        console.resume().unwrap();
        handle.join().unwrap();
        console.reset().unwrap();
        assert_eq!(host.workers.load(Ordering::Acquire), 0);
    }
}

#[test]
fn a_drain_from_another_device_cannot_stop_a_ring() {
    use dillo_virtio::{lifecycle::Slot, ring::Ring};
    console_stdio();
    let host = Arc::new(Host::default());
    let make = || dillo_virtio_console::VirtioConsole::new();
    let mut ring = Ring::new().configure(Queue::new(256)).unwrap().start();
    let mut owner = Slot::new(make());
    owner
        .start(VirtioActivate::with_host(
            vec![ring.worker_queue(256), Queue::new(256)],
            vec![
                dillo_virtio::Kick::new().unwrap(),
                dillo_virtio::Kick::new().unwrap(),
            ],
            host,
        ))
        .unwrap();
    let mut unrelated = Slot::new(make());
    let (retained, _) = ring.stop(&unrelated.drained().unwrap()).unwrap_err();
    ring = retained;
    owner.quiesce().unwrap();
    let stopped = ring.stop(&owner.drained().unwrap()).unwrap();
    assert_eq!(stopped.base(), 0);
    owner.reset().unwrap();
}
