// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use dillo_ipc::{Channel, MemoryExport, encode};
use dillo_machine::worker::WorkerHost;
use dillo_mmio::{Interrupt, MappedSharedMemory, SharedAccess, SharedMemory};
use dillo_virtio::{
    ActivateError, DeviceJoinError, Kick, VirtioActivate, VirtioDevice, VirtioDeviceHandle,
    VirtioDeviceHost, VirtioRunToken,
};

use crate::protocol::{CONFIG_LEN, Command, Init, QUEUE_MAX, Request, Response};

struct Output(Mutex<Box<dyn Channel>>);

impl Output {
    fn send(&self, response: &Response) -> io::Result<()> {
        self.0.lock().unwrap().send(&encode(response)?, &[])
    }
}

struct Host {
    memory: Arc<dyn SharedMemory>,
    output: Arc<Output>,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

impl VirtioDeviceHost for Host {
    fn shared_memory(&self) -> Vec<Arc<dyn SharedMemory>> {
        vec![Arc::clone(&self.memory)]
    }

    fn spawn(
        &self,
        run: Box<dyn FnOnce(VirtioRunToken) -> Result<(), DeviceJoinError> + Send>,
    ) -> Result<VirtioDeviceHandle, ActivateError> {
        let stopping = Arc::new(AtomicBool::new(false));
        let token = Arc::clone(&stopping);
        let output = Arc::clone(&self.output);
        let worker = std::thread::Builder::new()
            .name("block-queue".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(VirtioRunToken::from_fn(move || {
                        token.load(Ordering::Acquire)
                    }))
                }))
                .unwrap_or(Err(DeviceJoinError::Panicked));
                if let Err(error) = &result {
                    let _ = output.send(&Response::Failed(error.to_string()));
                }
                result
            })?;
        Ok(VirtioDeviceHandle::new(
            move || stopping.store(true, Ordering::Release),
            move || worker.join().unwrap_or(Err(DeviceJoinError::Panicked)),
        ))
    }
}

/// Child entry. Native handles originate only from the parent channel; the
/// factory gets already-open files and runs after confinement, before queues.
pub fn run<H: WorkerHost>(
    factory: impl FnOnce(serde_json::Value, Vec<File>) -> io::Result<Box<dyn VirtioDevice>>,
) -> io::Result<()> {
    let mut channel = H::bootstrap()?;
    let mut message = channel.receive()?;
    let init: Init = message.decode()?;
    if init.version != 1 || init.files > message.resources.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let files = message
        .resources
        .drain(..init.files)
        .map(File::from)
        .collect::<Vec<_>>();
    let memory = H::map_memory(MemoryExport {
        views: init.memory,
        resources: message.resources,
    })?;
    let output = Arc::new(Output(Mutex::new(channel.try_clone()?)));
    let host: Arc<dyn VirtioDeviceHost> = Arc::new(Host {
        memory: Arc::new(MappedSharedMemory::for_guest_memory(
            memory.clone(),
            SharedAccess::ReadWrite,
        )),
        output: Arc::clone(&output),
    });
    #[cfg(unix)]
    let borrowed = {
        use std::os::fd::AsFd;
        files.iter().map(AsFd::as_fd).collect::<Vec<_>>()
    };
    #[cfg(windows)]
    let borrowed = {
        use std::os::windows::io::AsHandle;
        files.iter().map(AsHandle::as_handle).collect::<Vec<_>>()
    };
    H::confine(&borrowed)?;
    let mut device = factory(init.backend, files)?;
    if device.device_type() != 2 || device.queue_max_sizes() != [QUEUE_MAX] {
        return Err(io::Error::other(
            "worker factory returned an unsupported device",
        ));
    }
    let mut config = vec![0; CONFIG_LEN];
    device.read_config(0, &mut config);
    let features = device.features();
    output.send(&Response::Ready { features, config })?;
    let mut active: Option<(u64, Kick, VirtioDeviceHandle)> = None;
    let mut last_epoch = 0;
    let mut last_request = 0;
    loop {
        let mut message = channel.receive()?;
        let Request { id, command } = message.decode()?;
        let resources = usize::from(matches!(
            command,
            Command::Activate {
                native_kick: true,
                ..
            }
        ));
        if message.resources.len() != resources {
            return Err(io::Error::other("unexpected activation resources"));
        }
        if id <= last_request {
            return Err(io::Error::other("replayed worker command"));
        }
        last_request = id;
        let shutdown = matches!(command, Command::Shutdown);
        let result = (|| -> io::Result<()> {
            match command {
                Command::Activate {
                    epoch,
                    features: negotiated,
                    queue,
                    native_kick,
                } => {
                    if active.is_some()
                        || epoch <= last_epoch
                        || negotiated & !features != 0
                        || negotiated & (1 << 32) == 0
                    {
                        return Err(io::Error::other("invalid activation"));
                    }
                    let queue = queue.into_queue(&memory)?;
                    let kick = if native_kick {
                        Kick::from_notification(H::notification(message.resources.remove(0))?)
                    } else {
                        Kick::new()?
                    };
                    let events = Arc::clone(&output);
                    let interrupt = Interrupt::from_fn(move || {
                        if let Err(error) = events.send(&Response::Used { epoch }) {
                            log::error!("block interrupt relay: {error}");
                        }
                    });
                    let handle = device
                        .activate(
                            VirtioActivate::with_host_and_queue_interrupts(
                                vec![queue],
                                vec![kick.clone()],
                                Arc::clone(&host),
                                vec![Some(interrupt)],
                            )
                            .with_negotiated_features(negotiated),
                        )
                        .map_err(io::Error::other)?;
                    active = Some((epoch, kick, handle));
                    last_epoch = epoch;
                }
                Command::Kick { epoch } => {
                    let (_, kick, _) = active
                        .as_ref()
                        .filter(|(current, _, _)| *current == epoch)
                        .ok_or_else(|| io::Error::other("kick for inactive queue"))?;
                    kick.write(1)?;
                }
                Command::Reset { epoch } => {
                    if active
                        .as_ref()
                        .is_none_or(|(current, _, _)| *current != epoch)
                    {
                        return Err(io::Error::other("reset for inactive queue"));
                    }
                    let (_, _, handle) = active.take().unwrap();
                    handle.join().map_err(io::Error::other)?;
                    device.reset().map_err(io::Error::other)?;
                }
                Command::Quiesce { epoch } | Command::Resume { epoch } => {
                    if active
                        .as_ref()
                        .is_none_or(|(current, _, _)| *current != epoch)
                    {
                        return Err(io::Error::other("control for inactive queue"));
                    }
                    if matches!(command, Command::Quiesce { .. }) {
                        device.quiesce().map_err(io::Error::other)?;
                    } else {
                        device.resume().map_err(io::Error::other)?;
                    }
                }
                Command::Shutdown => {
                    if let Some((_, _, handle)) = active.take() {
                        handle.join().map_err(io::Error::other)?;
                    }
                }
            }
            Ok(())
        })();
        let failed = result.is_err();
        output.send(&Response::Reply {
            id,
            error: result.err().map(|error| error.to_string()),
        })?;
        if shutdown || failed {
            return Ok(());
        }
    }
}
