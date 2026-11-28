// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! macOS worker services; no parent Hypervisor.framework object enters a worker.

use std::io;

#[derive(Debug)]
pub struct Worker;

impl dillo_machine::worker::WorkerHost for Worker {
    fn create_notification_state()
    -> io::Result<std::sync::Arc<dillo_machine::worker::NotificationState>> {
        // Reuse the unlinked POSIX shm allocator. Darwin permits only the
        // initial ftruncate, so an exported descriptor cannot shrink it.
        let memory = dillo_machine_unix::allocate_memory(&[(vm_memory::GuestAddress(0), 4096)])?;
        let mut export = dillo_machine_unix::export_memory(&memory)?;
        drop(memory);
        // SAFETY: fresh fixed-size backing; no other accessors remain.
        #[allow(unsafe_code)]
        unsafe {
            Self::adopt_notification_state(export.resources.pop().unwrap())
        }
    }

    #[allow(unsafe_code)]
    unsafe fn adopt_notification_state(
        resource: dillo_machine::worker::Resource,
    ) -> io::Result<std::sync::Arc<dillo_machine::worker::NotificationState>> {
        let file = std::fs::File::from(resource);
        // Darwin rounds shm allocations to its native page size.
        if file.metadata()?.len() < 4096 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: the caller supplies this family's fixed-size shm backing
        // and guarantees aligned AtomicU32 accesses through retained aliases.
        unsafe {
            dillo_machine::worker::NotificationState::from_file(file).map(std::sync::Arc::new)
        }
    }

    fn notification_pair() -> io::Result<(
        dillo_machine::worker::Resource,
        dillo_machine::worker::Resource,
    )> {
        dillo_machine_unix::notification::pair()
    }

    fn notification_endpoint(
        resource: dillo_machine::worker::Resource,
        role: dillo_machine::worker::NotificationRole,
    ) -> io::Result<std::sync::Arc<dyn dillo_machine::worker::WriteNotification>> {
        dillo_machine_unix::notification::adopt(resource, role)
    }

    fn channel(
        resource: dillo_machine::worker::Resource,
    ) -> io::Result<Box<dyn dillo_machine::worker::Channel>> {
        Ok(dillo_machine_unix::vhost_user::adopt(resource))
    }

    fn spawn(
        executable: &std::path::Path,
        policy: dillo_machine::worker::Policy,
    ) -> io::Result<(
        Box<dyn dillo_machine::worker::Process>,
        Box<dyn dillo_machine::worker::Channel>,
    )> {
        if policy.network {
            return Err(io::ErrorKind::Unsupported.into());
        }
        dillo_machine_unix::spawn(executable)
    }

    #[allow(unsafe_code)]
    unsafe fn bootstrap() -> io::Result<Box<dyn dillo_machine::worker::Channel>> {
        // SAFETY: the caller provides the dedicated process entry contract.
        unsafe { dillo_machine_unix::bootstrap() }
    }

    #[allow(unsafe_code)]
    unsafe fn map_memory(
        memory: dillo_machine::worker::MemoryExport,
    ) -> io::Result<vm_memory::GuestMemoryMmap> {
        // SAFETY: the caller guarantees stable backing and synchronized aliases.
        unsafe { dillo_machine_unix::map_memory(memory) }
    }

    fn confine(
        _files: &[dillo_machine::worker::BorrowedResource<'_>],
        policy: dillo_machine::worker::Policy,
    ) -> io::Result<()> {
        if policy.network {
            return Err(io::ErrorKind::Unsupported.into());
        }
        // Already-open, explicitly transferred descriptors retain their access.
        // No new path, network connection, child process or Mach service is
        // granted. Initialization and RAM mapping precede this permanent step.
        let profile = c"(version 1)(deny default)(allow signal (target self))(allow process-info* (target self))";
        let mut error = std::ptr::null_mut();
        // SAFETY: both C strings and the out-pointer live for the call. The
        // library's allocated error is released with its matching function.
        #[allow(unsafe_code)]
        unsafe {
            if sandbox_check(libc::getpid(), std::ptr::null(), 0) != 0 {
                return Err(io::Error::other(
                    "worker inherited a Seatbelt sandbox; cannot install the device policy",
                ));
            }
            if sandbox_init(profile.as_ptr(), 0, &mut error) != 0 {
                let detail = if error.is_null() {
                    "Seatbelt initialization failed".into()
                } else {
                    std::ffi::CStr::from_ptr(error)
                        .to_string_lossy()
                        .into_owned()
                };
                if !error.is_null() {
                    sandbox_free_error(error);
                }
                return Err(io::Error::other(detail));
            }
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_check(
        pid: libc::pid_t,
        operation: *const libc::c_char,
        filter: libc::c_int,
        ...
    ) -> libc::c_int;
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        error: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(error: *mut libc::c_char);
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_machine::worker::WorkerHost;

    #[test]
    fn notification_state_has_shared_fixed_backing() {
        let state = Worker::create_notification_state().unwrap();
        let file = std::fs::File::from(state.export().unwrap());
        let len = file.metadata().unwrap().len();
        assert!(file.set_len(0).is_err());
        assert!(file.set_len(len * 2).is_err());
        assert_eq!(file.metadata().unwrap().len(), len);
        // SAFETY: this resource came from the factory; both views use only
        // NotificationState's aligned atomic accesses.
        #[allow(unsafe_code)]
        let peer = unsafe { Worker::adopt_notification_state(file.into()).unwrap() };
        assert!(peer.used());
        assert_eq!(state.load(), 1);
        assert!(!state.used());
        state.acknowledge(1);
        assert_eq!(peer.load(), 0);
        drop(state);
        assert!(peer.used());
    }
}
