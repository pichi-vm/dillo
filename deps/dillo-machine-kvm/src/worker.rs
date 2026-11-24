// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux process and confinement services, without a KVM descriptor.

use dillo_machine::worker::WriteNotification;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::Arc;

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

    fn notification(
        resource: dillo_machine::worker::Resource,
    ) -> io::Result<Arc<dyn WriteNotification>> {
        Ok(Arc::new(Counter(std::fs::File::from(resource))))
    }

    fn confine(files: &[dillo_machine::worker::BorrowedResource<'_>]) -> io::Result<()> {
        confine(files)
    }
}

// The parent grants an eventfd counter, not a KVM registration or VM handle.
#[derive(Debug)]
struct Counter(std::fs::File);

impl WriteNotification for Counter {
    fn read(&self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        (&self.0).read_exact(&mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }
    fn write(&self, count: u64) -> io::Result<()> {
        (&self.0).write_all(&count.to_ne_bytes())
    }
    fn export(&self) -> io::Result<Option<dillo_machine::worker::Resource>> {
        use std::os::fd::AsFd;
        self.0.as_fd().try_clone_to_owned().map(Some)
    }
}

/// Deny new resources and process authority. Bootstrap has discarded ambient
/// descriptors; authorized files and mappings already exist. seccompiler owns
/// BPF generation, architecture checks and the all-thread installation.
fn confine(files: &[dillo_machine::worker::BorrowedResource<'_>]) -> io::Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };
    let mut rules = std::collections::BTreeMap::new();
    for syscall in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getrandom,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_clone3,
    ] {
        rules.insert(syscall, Vec::new());
    }
    let condition = |index, mask, value| -> io::Result<SeccompRule> {
        SeccompRule::new(vec![
            SeccompCondition::new(
                index,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(mask),
                value,
            )
            .map_err(io::Error::other)?,
        ])
        .map_err(io::Error::other)
    };
    // A thread may create another thread, never an independent process.
    rules.insert(
        libc::SYS_clone,
        vec![condition(
            0,
            libc::CLONE_THREAD as u64,
            libc::CLONE_THREAD as u64,
        )?],
    );
    for syscall in [libc::SYS_mmap, libc::SYS_mprotect] {
        rules.insert(syscall, vec![condition(2, libc::PROT_EXEC as u64, 0)?]);
    }
    for syscall in [
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_fstatfs,
        libc::SYS_statx,
    ] {
        if !files.is_empty() {
            rules.insert(
                syscall,
                files
                    .iter()
                    .map(|fd| condition(0, u32::MAX as u64, fd.as_raw_fd() as u64))
                    .collect::<io::Result<_>>()?,
            );
        }
    }
    rules.insert(
        libc::SYS_fcntl,
        vec![
            condition(1, u32::MAX as u64, libc::F_GETFL as u64)?,
            condition(1, u32::MAX as u64, libc::F_GETFD as u64)?,
        ],
    );
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(io::Error::other)?;
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(io::Error::other)?
    .try_into()
    .map_err(io::Error::other)?;
    // libc can fall back from clone3 to clone only on ENOSYS. Install that
    // refusal separately; both filters remain permanent and cover all threads.
    let fallback: BpfProgram = SeccompFilter::new(
        [(libc::SYS_clone3, Vec::new())].into(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(io::Error::other)?
    .try_into()
    .map_err(io::Error::other)?;
    seccompiler::apply_filter_all_threads(&fallback).map_err(io::Error::other)?;
    seccompiler::apply_filter_all_threads(&filter).map_err(io::Error::other)
}
