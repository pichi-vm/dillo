// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AppContainer worker launch and one-way, parent-authorized handle transfer.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::{ExitStatusExt, ProcThreadAttributeList};
use std::path::Path;
use std::process::ExitStatus;
use std::sync::Arc;

use dillo_ipc::{
    BorrowedResource, Channel, MAX_MESSAGE, MAX_RESOURCES, MemoryExport, Message, Process,
};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::WindowsProgramming::*;

#[derive(Debug)]
pub struct Worker;

impl dillo_machine::worker::WorkerHost for Worker {
    fn spawn(executable: &Path) -> io::Result<(Box<dyn Process>, Box<dyn Channel>)> {
        spawn(executable)
    }
    fn bootstrap() -> io::Result<Box<dyn Channel>> {
        bootstrap()
    }
    fn map_memory(memory: MemoryExport) -> io::Result<vm_memory::GuestMemoryMmap> {
        crate::memory::map(&memory)
    }
    fn confine(_files: &[BorrowedResource<'_>]) -> io::Result<()> {
        // Confinement was installed atomically at process creation. Verify it
        // before reporting readiness, including invocations of the private CLI.
        #[allow(unsafe_code)]
        unsafe {
            let mut token = std::ptr::null_mut();
            check(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            ))?;
            let token = OwnedHandle::from_raw_handle(token);
            let mut container = 0u32;
            let mut len = 0;
            check(GetTokenInformation(
                token.as_raw_handle(),
                TokenIsAppContainer,
                (&raw mut container).cast(),
                size_of::<u32>() as u32,
                &mut len,
            ))?;
            let mut in_job = 0;
            check(IsProcessInJob(
                GetCurrentProcess(),
                std::ptr::null_mut(),
                &mut in_job,
            ))?;
            if container != 1 || in_job == 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        Ok(())
    }
}

fn check(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn duplicate(resource: BorrowedResource<'_>, inherit: bool) -> io::Result<OwnedHandle> {
    let mut handle = std::ptr::null_mut();
    // SAFETY: both process handles refer to self; the source is borrowed, and
    // the successful duplicate is newly owned by this call.
    #[allow(unsafe_code)]
    unsafe {
        check(DuplicateHandle(
            GetCurrentProcess(),
            resource.as_raw_handle(),
            GetCurrentProcess(),
            &mut handle,
            0,
            i32::from(inherit),
            DUPLICATE_SAME_ACCESS,
        ))?;
        Ok(OwnedHandle::from_raw_handle(handle))
    }
}

struct Container {
    name: Vec<u16>,
    sid: Box<[u32]>,
    executable: tempfile::TempDir,
}

impl Container {
    fn new(executable: &Path) -> io::Result<Self> {
        let name = wide(std::ffi::OsStr::new(&format!(
            "dillo.worker.{}",
            uuid::Uuid::new_v4()
        )));
        let directory = tempfile::tempdir()?;
        let mut sid = std::ptr::null_mut();
        // SAFETY: terminated UTF-16 strings and a valid output pointer. A new,
        // unguessable identity is never shared with another worker.
        #[allow(unsafe_code)]
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid,
            )
        };
        if result < 0 {
            return Err(io::Error::other(format!(
                "create worker AppContainer: {result:#x}"
            )));
        }
        // Copy the SID into an aligned, owning Rust buffer. SID data is immutable
        // and has no thread affinity; the process owner remains naturally Send.
        #[allow(unsafe_code)]
        let owner = unsafe {
            let len = GetLengthSid(sid);
            let mut owner = Self {
                name,
                sid: vec![0u32; (len as usize).div_ceil(size_of::<u32>())].into_boxed_slice(),
                executable: directory,
            };
            let copied = check(CopySid(len, owner.sid.as_mut_ptr().cast(), sid));
            FreeSid(sid);
            copied?;
            owner
        };
        owner.allow_executable(owner.executable.path())?;
        let worker_exe = owner.executable.path().join("dillo.exe");
        std::fs::copy(executable, &worker_exe)?;
        owner.allow_executable(&worker_exe)?;
        Ok(owner)
    }

    fn allow_executable(&self, target: &Path) -> io::Result<()> {
        // Give this container only read/execute on its private copy. Do not
        // change ACLs on the user's installed executable or project checkout.
        let mut path = wide(target.as_os_str());
        #[allow(unsafe_code)]
        unsafe {
            let mut descriptor = std::ptr::null_mut();
            let mut old_acl = std::ptr::null_mut();
            let status = GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut old_acl,
                std::ptr::null_mut(),
                &mut descriptor,
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let access = EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_UNKNOWN,
                    ptstrName: self.sid.as_ptr().cast_mut().cast(),
                },
            };
            let mut acl = std::ptr::null_mut();
            let mut status = SetEntriesInAclW(1, &access, old_acl, &mut acl);
            if status == ERROR_SUCCESS {
                status = SetNamedSecurityInfoW(
                    path.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null(),
                );
            }
            if !acl.is_null() {
                LocalFree(acl.cast());
            }
            LocalFree(descriptor.cast());
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        Ok(())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            DeleteAppContainerProfile(self.name.as_ptr());
        }
    }
}

struct ChildProcess {
    child: OwnedHandle,
    _container: Container,
    _job: OwnedHandle,
}

impl std::fmt::Debug for ChildProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildProcess")
            .field("child", &self.child)
            .finish_non_exhaustive()
    }
}

impl ChildProcess {
    fn status(&self, timeout: u32) -> io::Result<Option<ExitStatus>> {
        // SAFETY: the process handle remains owned across the wait and query.
        #[allow(unsafe_code)]
        unsafe {
            match WaitForSingleObject(self.child.as_raw_handle(), timeout) {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    check(GetExitCodeProcess(self.child.as_raw_handle(), &mut code))?;
                    Ok(Some(ExitStatus::from_raw(code)))
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }
}

impl Process for ChildProcess {
    fn terminate(&mut self) -> io::Result<()> {
        // SAFETY: only this owner's child is terminated, never a borrowed PID.
        #[allow(unsafe_code)]
        unsafe {
            check(TerminateProcess(self.child.as_raw_handle(), 1))
        }
    }
    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.status(INFINITE)?
            .ok_or_else(|| io::Error::other("process wait timed out"))
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.status(0)
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        if !matches!(self.try_wait(), Ok(Some(_))) {
            let _ = self.terminate();
            let _ = self.wait();
        }
    }
}

#[derive(Debug)]
struct Connection {
    read: File,
    write: File,
    // Only the parent can grant handles. The child never receives this handle.
    child: Option<Arc<OwnedHandle>>,
}

impl Channel for Connection {
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()> {
        if bytes.len() > MAX_MESSAGE
            || resources.len() > MAX_RESOURCES
            || (self.child.is_none() && !resources.is_empty())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut handles = Vec::with_capacity(resources.len());
        for source in resources {
            let mut target = std::ptr::null_mut();
            // SAFETY: the parent owns the target process and source handle.
            // The duplicate is installed in that child's handle table only.
            #[allow(unsafe_code)]
            unsafe {
                check(DuplicateHandle(
                    GetCurrentProcess(),
                    source.as_raw_handle(),
                    self.child.as_ref().unwrap().as_raw_handle(),
                    &mut target,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                ))?;
            }
            handles.push(target as usize as u64);
        }
        self.write.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.write
            .write_all(&(handles.len() as u32).to_le_bytes())?;
        for handle in handles {
            self.write.write_all(&handle.to_le_bytes())?;
        }
        self.write.write_all(bytes)
    }

    fn receive(&mut self) -> io::Result<Message> {
        let mut header = [0u8; 8];
        self.read.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        if len > MAX_MESSAGE || count > MAX_RESOURCES || (self.child.is_some() && count != 0) {
            return Err(io::Error::other("invalid worker frame"));
        }
        let mut resources = Vec::with_capacity(count);
        for _ in 0..count {
            let mut bytes = [0; 8];
            self.read.read_exact(&mut bytes)?;
            let handle = usize::try_from(u64::from_le_bytes(bytes)).map_err(io::Error::other)?
                as *mut c_void;
            // SAFETY: this receive direction is exclusively the trusted parent,
            // which installed each handle once with DuplicateHandle before
            // writing it. Parent receive never adopts a child's numeric value.
            #[allow(unsafe_code)]
            resources.push(unsafe { OwnedHandle::from_raw_handle(handle) });
        }
        let mut bytes = vec![0; len];
        self.read.read_exact(&mut bytes)?;
        Ok(Message { bytes, resources })
    }

    fn try_clone(&self) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Self {
            read: self.read.try_clone()?,
            write: self.write.try_clone()?,
            child: self.child.clone(),
        }))
    }
}

fn spawn(executable: &Path) -> io::Result<(Box<dyn Process>, Box<dyn Channel>)> {
    let container = Container::new(executable)?;
    let (input, write) = std::io::pipe()?;
    let (read, output) = std::io::pipe()?;
    let input = duplicate(input.as_handle(), true)?;
    let output = duplicate(output.as_handle(), true)?;
    let log = duplicate(std::io::stderr().as_handle(), true)?;
    let handles = [
        input.as_raw_handle(),
        output.as_raw_handle(),
        log.as_raw_handle(),
    ];
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: container.sid.as_ptr().cast_mut().cast(),
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    // The job and child-process policy apply before any child instruction.
    #[allow(unsafe_code)]
    let job = unsafe {
        let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = OwnedHandle::from_raw_handle(raw);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        check(SetInformationJobObject(
            raw,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of_val(&limits) as u32,
        ))?;
        job
    };
    let job_list = [job.as_raw_handle()];
    let child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    // winnt.h: DEP + SEHOP, heap termination (bits 12-13), and disabled
    // extension points (bits 32-33). The attribute requires a 64-bit value.
    let mitigations: u64 = u64::from(
        PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
            | PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE,
    ) | (1 << 12)
        | (1 << 32);
    let attributes = ProcThreadAttributeList::build()
        .attribute(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &capabilities,
        )
        .attribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, &handles)
        .attribute(PROC_THREAD_ATTRIBUTE_JOB_LIST as usize, &job_list)
        .attribute(
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
            &child_policy,
        )
        .attribute(
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            &mitigations,
        )
        .finish()?;
    let executable = wide(container.executable.path().join("dillo.exe").as_os_str());
    let directory = wide(container.executable.path().as_os_str());
    // lpApplicationName is explicit; argv contains only a fixed name, a fixed
    // entry switch and decimal handle values, so no caller text is quoted.
    let mut command = wide(std::ffi::OsStr::new(&format!(
        "dillo.exe --dillo-block-worker {} {} {}",
        handles[0] as usize, handles[1] as usize, handles[2] as usize,
    )));
    let mut environment = Vec::new();
    // Windows initializes AppContainer and temporary-path state before main.
    // Pass only its bootstrap paths, never the caller's general environment.
    for key in ["LOCALAPPDATA", "SystemDrive", "SystemRoot", "TEMP", "TMP"] {
        let mut entry = std::ffi::OsString::from(format!("{key}="));
        entry.push(
            std::env::var_os(key)
                .ok_or_else(|| io::Error::other(format!("AppContainer launch requires {key}")))?,
        );
        environment.extend(wide(&entry));
    }
    environment.push(0);
    // std::Command duplicates standard handles independently of the supplied
    // HANDLE_LIST. Supply the same three handles in both structures so CRT
    // initialization and our private bootstrap see valid inherited handles.
    #[allow(unsafe_code)]
    let child = unsafe {
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.as_ptr().cast_mut().cast();
        let mut result = PROCESS_INFORMATION::default();
        check(CreateProcessW(
            executable.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            // This pipe-only worker needs no console host. A windowless
            // console can still require a host process, which is incompatible
            // with the job's one-process limit and child-process restriction.
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut result,
        ))
        .map_err(|e| io::Error::new(e.kind(), format!("launch block AppContainer: {e}")))?;
        // Both handles are newly owned on success. The thread needs no parent
        // operations; retaining the process is sufficient for kill and wait.
        drop(OwnedHandle::from_raw_handle(result.hThread));
        OwnedHandle::from_raw_handle(result.hProcess)
    };
    let process = ChildProcess {
        child,
        _container: container,
        _job: job,
    };
    let peer = Arc::new(process.child.try_clone()?);
    let read = File::from(OwnedHandle::from(read));
    let write = File::from(OwnedHandle::from(write));
    Ok((
        Box::new(process),
        Box::new(Connection {
            read,
            write,
            child: Some(peer),
        }),
    ))
}

fn bootstrap() -> io::Result<Box<dyn Channel>> {
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    };
    static ADOPTED: AtomicBool = AtomicBool::new(false);
    static LOG: OnceLock<OwnedHandle> = OnceLock::new();
    if ADOPTED.swap(true, Ordering::AcqRel) {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let handles = std::env::args()
        .skip(2)
        .map(|arg| arg.parse::<usize>().map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    if handles.len() != 3
        || handles
            .iter()
            .any(|handle| *handle == 0 || *handle == usize::MAX)
        || handles[0] == handles[1]
        || handles[0] == handles[2]
        || handles[1] == handles[2]
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    #[allow(unsafe_code)]
    unsafe {
        let mut flags = 0;
        check(GetHandleInformation(handles[2] as *mut c_void, &mut flags))?;
        let log = OwnedHandle::from_raw_handle(handles[2] as *mut c_void);
        check(SetStdHandle(STD_ERROR_HANDLE, log.as_raw_handle()))?;
        let _ = LOG.set(log);
        for handle in &handles {
            let mut flags = 0;
            check(GetHandleInformation(*handle as *mut c_void, &mut flags))?;
        }
        for handle in &handles[..2] {
            if GetFileType(*handle as *mut c_void) != FILE_TYPE_PIPE {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        // Only this early entry point owns the distinct, validated inherited
        // handles. stdio borrows their values; these owners close them.
        Ok(Box::new(Connection {
            read: File::from(OwnedHandle::from_raw_handle(handles[0] as *mut c_void)),
            write: File::from(OwnedHandle::from_raw_handle(handles[1] as *mut c_void)),
            child: None,
        }))
    }
}
