// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! macOS worker services; no parent Hypervisor.framework object enters a worker.

use std::io;

#[derive(Debug)]
pub struct Worker;

impl dillo_machine::worker::WorkerHost for Worker {
    fn spawn(
        executable: &std::path::Path,
    ) -> io::Result<(
        Box<dyn dillo_machine::worker::Process>,
        Box<dyn dillo_machine::worker::Channel>,
    )> {
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

    fn confine(_files: &[dillo_machine::worker::BorrowedResource<'_>]) -> io::Result<()> {
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
