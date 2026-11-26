// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Share-scoped native operations. FUSE state and file contents stay in the worker.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use dillo_machine::worker::Message;
use dillo_virtio_fs::{Attr, DirEntry, FileContent, FsBackend, LinuxErrno, Passthrough, SetAttr};
use dillo_worker::grant::{Client, Grant};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const DIRECTORY_PAGE: usize = 256;

#[derive(Serialize, Deserialize)]
enum Request {
    Stat(PathBuf),
    ReadDir(PathBuf),
    ReadDirNext,
    Open(PathBuf, bool),
    ReadLink(PathBuf),
    Create(PathBuf, u32),
    Mkdir(PathBuf, u32),
    Unlink(PathBuf),
    Rmdir(PathBuf),
    Rename(PathBuf, PathBuf, u32),
    Link(PathBuf, PathBuf),
    Mknod(PathBuf, u32, u32),
    Allocate(PathBuf, u64, u64, u32),
    GetXattr(PathBuf, String),
    SetXattr(PathBuf, String, Vec<u8>, u32),
    ListXattr(PathBuf),
    RemoveXattr(PathBuf, String),
    SetAttr(PathBuf, SetAttr),
    Symlink(PathBuf, Vec<u8>),
}

impl Request {
    fn writes(&self) -> bool {
        !matches!(
            self,
            Self::Stat(_)
                | Self::ReadDir(_)
                | Self::ReadDirNext
                | Self::Open(_, false)
                | Self::ReadLink(_)
                | Self::GetXattr(..)
                | Self::ListXattr(_)
        )
    }
}

/// One opened share and its immutable access policy. No guest-memory authority.
pub(crate) struct Authority {
    root: Passthrough,
    readonly: bool,
    directory: Option<Box<dyn Iterator<Item = io::Result<DirEntry>> + Send>>,
}

impl Authority {
    pub(crate) fn new(path: &Path, readonly: bool) -> io::Result<Self> {
        Ok(Self {
            root: Passthrough::new(path)?,
            readonly,
            directory: None,
        })
    }

    pub(crate) fn serve(&mut self, bytes: &[u8]) -> io::Result<Grant> {
        let request: Request = serde_json::from_slice(bytes).map_err(io::Error::other)?;
        if self.readonly && request.writes() {
            return reply::<()>(Err(io::ErrorKind::ReadOnlyFilesystem.into()));
        }
        if !matches!(request, Request::ReadDirNext) {
            self.directory = None;
        }
        match request {
            Request::Stat(path) => reply(self.root.stat(&path)),
            Request::ReadDir(path) => {
                match self.root.entries(&path) {
                    Ok(entries) => self.directory = Some(Box::new(entries)),
                    Err(error) => return reply::<()>(Err(error)),
                }
                reply(self.directory_page())
            }
            Request::ReadDirNext => reply(self.directory_page()),
            Request::Open(path, write) => match self.root.open_file(&path, write) {
                Ok(file) => Ok(Message {
                    bytes: encode(Ok(()))?,
                    resources: vec![file.into()],
                }
                .into()),
                Err(error) => reply::<()>(Err(error)),
            },
            Request::ReadLink(path) => reply(self.root.readlink(&path)),
            Request::Create(path, mode) => reply(self.root.create(&path, mode)),
            Request::Mkdir(path, mode) => reply(self.root.mkdir(&path, mode)),
            Request::Unlink(path) => reply(self.root.unlink(&path)),
            Request::Rmdir(path) => reply(self.root.rmdir(&path)),
            Request::Rename(from, to, flags) => reply(self.root.rename(&from, &to, flags)),
            Request::Link(from, to) => reply(self.root.link(&from, &to)),
            Request::Mknod(path, mode, dev) => reply(self.root.mknod(&path, mode, dev)),
            Request::Allocate(path, offset, length, mode) => {
                reply(self.root.fallocate(&path, offset, length, mode))
            }
            Request::GetXattr(path, name) => reply(self.root.get_xattr(&path, &name)),
            Request::SetXattr(path, name, value, flags) => {
                if value.len() > 1 << 20 {
                    return reply::<()>(Err(io::ErrorKind::InvalidInput.into()));
                }
                reply(self.root.set_xattr(&path, &name, &value, flags))
            }
            Request::ListXattr(path) => reply(self.root.list_xattr(&path)),
            Request::RemoveXattr(path, name) => reply(self.root.remove_xattr(&path, &name)),
            Request::SetAttr(path, set) => reply(self.root.setattr(&path, &set)),
            Request::Symlink(path, target) => reply(self.root.symlink(&path, &target)),
        }
    }

    fn directory_page(&mut self) -> io::Result<Vec<DirEntry>> {
        let entries = self.directory.as_mut().ok_or(io::ErrorKind::InvalidInput)?;
        let page = entries.take(DIRECTORY_PAGE).collect::<io::Result<Vec<_>>>();
        if !page.as_ref().is_ok_and(|page| page.len() == DIRECTORY_PAGE) {
            self.directory = None;
        }
        page
    }
}

fn encode<T: Serialize>(result: io::Result<T>) -> io::Result<Vec<u8>> {
    serde_json::to_vec(&result.map_err(LinuxErrno::from)).map_err(io::Error::other)
}

fn reply<T: Serialize>(result: io::Result<T>) -> io::Result<Grant> {
    Ok(Message {
        bytes: encode(result)?,
        resources: Vec::new(),
    }
    .into())
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice::<Result<T, LinuxErrno>>(bytes)
        .map_err(io::Error::other)?
        .map_err(Into::into)
}

/// Native grants are separate from vhost-user. The worker never receives a
/// directory handle or the host path of the share.
pub(crate) struct GrantedFs(Mutex<Client>);

impl GrantedFs {
    pub(crate) fn new(client: Client) -> Self {
        Self(Mutex::new(client))
    }

    fn call<T: DeserializeOwned>(&self, request: &Request) -> io::Result<T> {
        Self::request(&mut self.0.lock().unwrap(), request)
    }

    fn request<T: DeserializeOwned>(client: &mut Client, request: &Request) -> io::Result<T> {
        let bytes = serde_json::to_vec(request).map_err(io::Error::other)?;
        client.request(&bytes, |message| {
            if !message.resources.is_empty() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            decode(&message.bytes)
        })
    }

    fn open(&self, path: &Path, write: bool) -> io::Result<FileContent> {
        let bytes =
            serde_json::to_vec(&Request::Open(path.into(), write)).map_err(io::Error::other)?;
        self.0.lock().unwrap().request(&bytes, |mut message| {
            decode::<()>(&message.bytes)?;
            if message.resources.len() != 1 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(FileContent::from(File::from(
                message.resources.pop().unwrap(),
            )))
        })
    }
}

impl FsBackend for GrantedFs {
    fn stat(&self, path: &Path) -> io::Result<Attr> {
        self.call(&Request::Stat(path.into()))
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let mut client = self.0.lock().unwrap();
        let mut page: Vec<DirEntry> = Self::request(&mut client, &Request::ReadDir(path.into()))?;
        let mut entries = Vec::new();
        loop {
            let complete = page.len() < DIRECTORY_PAGE;
            entries.extend(page);
            if complete {
                return Ok(entries);
            }
            page = Self::request(&mut client, &Request::ReadDirNext)?;
        }
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        self.open(path, false)?.read(offset, size)
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<u32> {
        self.open(path, true)?.write(offset, data)
    }

    fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.call(&Request::ReadLink(path.into()))
    }

    fn create(&self, path: &Path, mode: u32) -> io::Result<Attr> {
        self.call(&Request::Create(path.into(), mode))
    }

    fn mkdir(&self, path: &Path, mode: u32) -> io::Result<Attr> {
        self.call(&Request::Mkdir(path.into(), mode))
    }

    fn unlink(&self, path: &Path) -> io::Result<()> {
        self.call(&Request::Unlink(path.into()))
    }

    fn rmdir(&self, path: &Path) -> io::Result<()> {
        self.call(&Request::Rmdir(path.into()))
    }

    fn rename(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
        self.call(&Request::Rename(from.into(), to.into(), flags))
    }

    fn link(&self, from: &Path, to: &Path) -> io::Result<Attr> {
        self.call(&Request::Link(from.into(), to.into()))
    }

    fn mknod(&self, path: &Path, mode: u32, dev: u32) -> io::Result<Attr> {
        self.call(&Request::Mknod(path.into(), mode, dev))
    }

    fn fallocate(&self, path: &Path, offset: u64, length: u64, mode: u32) -> io::Result<()> {
        self.call(&Request::Allocate(path.into(), offset, length, mode))
    }

    fn get_xattr(&self, path: &Path, name: &str) -> io::Result<Vec<u8>> {
        self.call(&Request::GetXattr(path.into(), name.into()))
    }

    fn set_xattr(&self, path: &Path, name: &str, value: &[u8], flags: u32) -> io::Result<()> {
        self.call(&Request::SetXattr(
            path.into(),
            name.into(),
            value.into(),
            flags,
        ))
    }

    fn list_xattr(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.call(&Request::ListXattr(path.into()))
    }

    fn remove_xattr(&self, path: &Path, name: &str) -> io::Result<()> {
        self.call(&Request::RemoveXattr(path.into(), name.into()))
    }

    fn lseek(&self, path: &Path, offset: u64, whence: u32) -> io::Result<u64> {
        self.open(path, false)?.seek(offset, whence)
    }

    fn copy_file_range(
        &self,
        src: &Path,
        src_off: u64,
        dst: &Path,
        dst_off: u64,
        len: u64,
        flags: u32,
    ) -> io::Result<u32> {
        if flags != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.open(src, false)?
            .copy_to(src_off, &self.open(dst, true)?, dst_off, len)
    }

    fn setattr(&self, path: &Path, set: &SetAttr) -> io::Result<Attr> {
        self.call(&Request::SetAttr(path.into(), set.clone()))
    }

    fn symlink(&self, path: &Path, target: &[u8]) -> io::Result<Attr> {
        self.call(&Request::Symlink(path.into(), target.into()))
    }
}
