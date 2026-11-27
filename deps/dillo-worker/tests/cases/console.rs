// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{
    Arc, AtomicUsize, Bytes, Duration, File, GuestAddress, Host, Instant, Interrupt, Kick,
    Ordering, Queue, VirtioActivate, VirtioDevice, Worker, WorkerHost, Write, io, memory, read_at,
};
use dillo_machine::worker::Resource;
use dillo_virtio_console::{
    NamedPort, VirtioConsole,
    pipe::{Direction, PipeEnd, Transfer},
};

pub(super) fn device(mut files: Vec<File>) -> Box<dyn VirtioDevice> {
    dillo_virtio_console::worker_stdio(files.remove(0), files.remove(0));
    let sizes = files.remove(0);
    let rx = PipeEnd::from_file("api", Direction::Rx, files.remove(0));
    let tx = PipeEnd::from_file("api", Direction::Tx, files.remove(0));
    Box::new(
        VirtioConsole::with_ports(vec![NamedPort::new("api".into(), Some(rx), Some(tx))])
            .with_size_pipe(sizes),
    )
}

use super::queues::{base, submit, wait_used};

pub(super) fn exercise() -> io::Result<()> {
    eprintln!("vhost process: multiqueue console");
    let (memory, export) = memory()?;
    let output = tempfile::tempfile()?;
    let (rx, mut host_tx) = io::pipe()?;
    let (host_rx, tx) = io::pipe()?;
    let rx = PipeEnd::nonblocking("api", Direction::Rx, File::from(Resource::from(rx)))?;
    let tx = PipeEnd::nonblocking("api", Direction::Tx, File::from(Resource::from(tx)))?;
    let host_rx = PipeEnd::nonblocking("api", Direction::Rx, File::from(Resource::from(host_rx)))?;
    let (size_rx, mut sizes) = io::pipe()?;
    let size_rx = PipeEnd::nonblocking("resize", Direction::Rx, Resource::from(size_rx).into())?;
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 3,
            queues: vec![dillo_virtio_console::QUEUE_MAX; 6],
            config_len: 12,
        },
        &serde_json::json!({"mode":"console"}),
        vec![
            tempfile::tempfile()?,
            output.try_clone()?,
            size_rx.into_file(),
            rx.into_file(),
            tx.into_file(),
        ],
    )?
    .with_config_poll(|| Ok(()));
    let (mut proxy, control) = prepared.start::<Worker>(export, || {})?;
    for epoch in 0..2 {
        let delivered = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let interrupts = delivered.each_ref().map(|count| {
            let count = Arc::clone(count);
            Interrupt::from_fn(move || {
                count.fetch_add(1, Ordering::Release);
            })
        });
        let mut queues = Vec::new();
        let mut kicks = Vec::new();
        for index in 0..6 {
            memory
                .write_slice(&[0; 16], GuestAddress(base(index) + 0x1000))
                .unwrap();
            memory
                .write_slice(&[0; 16], GuestAddress(base(index) + 0x2000))
                .unwrap();
            let mut queue = Queue::new(dillo_virtio_console::QUEUE_MAX);
            queue.size = 16;
            queue.ready = true;
            queue.desc_table = GuestAddress(base(index));
            queue.avail_ring = GuestAddress(base(index) + 0x1000);
            queue.used_ring = GuestAddress(base(index) + 0x2000);
            queues.push(queue);
            kicks.push(Kick::from_notification(Worker::queue_notification()?));
        }
        let active = proxy
            .activate(
                VirtioActivate::with_host_and_queue_interrupts(
                    queues,
                    kicks.clone(),
                    // Six queues share two interrupt owners. Native kicks need
                    // no relays, leaving exactly one receiver per owner.
                    Arc::new(Host(AtomicUsize::new(2))),
                    (0..6)
                        .map(|index| Some(interrupts[index / 3].clone()))
                        .collect(),
                )
                .with_negotiated_features(proxy.features()),
            )
            .map_err(io::Error::other)?;
        for (queue, bytes) in [(1, b"stdio".as_slice()), (5, b"api".as_slice())] {
            submit(&memory, queue, 1, bytes, false);
            kicks[queue as usize].write(1)?;
            wait_used(&memory, queue, 1)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while delivered[queue as usize / 3].load(Ordering::Acquire) == 0 {
                assert!(
                    Instant::now() < deadline,
                    "completion notification deadline"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut received = [0; 3];
        loop {
            if host_rx.read(&mut received)? == Transfer::Moved(3) {
                break;
            }
            assert!(Instant::now() < deadline, "named output deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(&received, b"api");
        // Guest opens named port 1 before input is delivered.
        submit(&memory, 3, 1, &[1, 0, 0, 0, 6, 0, 1, 0], false);
        kicks[3].write(1)?;
        wait_used(&memory, 3, 1)?;
        control.quiesce()?;
        submit(&memory, 4, 1, &[0; 3], true);
        host_tx.write_all(b"rx!")?;
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            memory
                .read_obj::<u16>(GuestAddress(base(4) + 0x2002))
                .unwrap(),
            0
        );
        control.resume()?;
        wait_used(&memory, 4, 1)?;
        memory
            .read_slice(&mut received, GuestAddress(0x10_4000))
            .unwrap();
        assert_eq!(&received, b"rx!");
        sizes.write_all(&[80 + epoch, 0, 25, 0])?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut config = [0; 4];
            proxy.read_config(0, &mut config);
            if config == [80 + epoch, 0, 25, 0] {
                break;
            }
            assert!(Instant::now() < deadline, "configuration deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
        active.join().map_err(io::Error::other)?;
    }
    control.shutdown()?;
    let mut bytes = [0; 10];
    read_at(&output, &mut bytes, 0)?;
    assert_eq!(&bytes, b"stdiostdio");
    Ok(())
}
