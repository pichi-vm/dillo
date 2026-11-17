// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, Permissions};
use std::io::{self, Read, Seek};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;

use mmarinus::{Map, perms::Read as ReadOnly};
use tempfile::TempDir;

/// A private file-backed launch capture. Only construction can write its file;
/// views never map the original mutable input or expose the retained descriptor.
///
/// The directory lives in the configured temporary storage, with private access
/// even where unnamed-file creation falls back to create/unlink. Storage may be
/// tmpfs. On a supporting filesystem a reflink avoids copying image padding;
/// elsewhere a bounded copy is completed before validation. Unmapping a view
/// retains this backing, without requiring its pages to remain resident.
#[derive(Debug)]
pub struct CapturedLaunchInput {
    file: File,
    len: usize,
    directory: TempDir,
}

/// A read-only view of a retained capture. Empty inputs reach the parser as an
/// empty slice instead of attempting an invalid zero-length mmap.
#[derive(Debug)]
pub struct LaunchView<'a> {
    mapping: Option<Map<ReadOnly>>,
    _directory: &'a TempDir,
}

impl AsRef<[u8]> for LaunchView<'_> {
    fn as_ref(&self) -> &[u8] {
        self.mapping.as_ref().map_or(&[], AsRef::as_ref)
    }
}

impl CapturedLaunchInput {
    fn capture_with(
        mut source: File,
        clone: impl FnOnce(&File, &File) -> io::Result<()>,
    ) -> io::Result<Self> {
        let source_len = source.metadata()?.len();
        usize::try_from(source_len)
            .map_err(|_| io::Error::other("launch input exceeds host address space"))?;
        let directory = tempfile::Builder::new()
            .prefix("dillo-launch-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir()?;
        let mut file = tempfile::tempfile_in(directory.path())?;
        match clone(&file, &source) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(
                        libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOTTY | libc::ENOSYS
                    )
                ) =>
            {
                // A failed clone does not authorize retaining partial contents.
                file.set_len(0)?;
                file.rewind()?;
                source.rewind()?;
                let copied = io::copy(&mut source.take(source_len), &mut file)?;
                if copied != source_len {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "launch input truncated during capture",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        let len = usize::try_from(file.metadata()?.len())
            .map_err(|_| io::Error::other("launch input exceeds host address space"))?;
        Ok(Self {
            file,
            len,
            directory,
        })
    }
}

impl dillo_machine::LaunchInput for CapturedLaunchInput {
    type View<'a> = LaunchView<'a>;

    fn capture(source: File) -> io::Result<Self> {
        Self::capture_with(source, |destination, source| {
            rustix::fs::ioctl_ficlone(destination, source).map_err(Into::into)
        })
    }

    fn view(&self) -> io::Result<Self::View<'_>> {
        let mapping = if self.len == 0 {
            None
        } else {
            // mmarinus takes a mutable reference to its AsRawFd argument, but
            // mapping only needs a borrowed descriptor and never writes it.
            let mut file = self.file.as_fd();
            Some(
                Map::bytes(self.len)
                    .anywhere()
                    .from(&mut file, 0)
                    .with(ReadOnly)
                    .map_err(io::Error::from)?,
            )
        };
        Ok(LaunchView {
            mapping,
            _directory: &self.directory,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dillo_machine::LaunchInput;
    use std::cell::Cell;
    use std::io::Write;

    #[test]
    fn copy_fallback_survives_source_overwrite_truncation_and_view_drop() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        let expected = vec![0x5a; 16384];
        source.write_all(&expected).unwrap();
        let capture =
            CapturedLaunchInput::capture_with(File::open(source.path()).unwrap(), |_, _| {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            })
            .unwrap();
        assert_eq!(
            capture
                .directory
                .path()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        {
            let view = capture.view().unwrap();
            source.as_file_mut().rewind().unwrap();
            source.write_all(&vec![0xa5; expected.len()]).unwrap();
            source.as_file().set_len(0).unwrap();
            assert_eq!(view.as_ref(), expected);
        }
        assert_eq!(capture.view().unwrap().as_ref(), expected);
    }

    #[test]
    fn native_clone_or_copy_retains_captured_contents() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        let expected = vec![0x33; 16384];
        source.write_all(&expected).unwrap();
        let cloned = Cell::new(false);
        let capture = CapturedLaunchInput::capture_with(
            File::open(source.path()).unwrap(),
            |destination, source| {
                rustix::fs::ioctl_ficlone(destination, source).map_err(io::Error::from)?;
                cloned.set(true);
                Ok(())
            },
        )
        .unwrap();
        eprintln!(
            "native launch capture used {}",
            if cloned.get() {
                "FICLONE"
            } else {
                "copy fallback"
            }
        );
        source.as_file_mut().rewind().unwrap();
        source.write_all(&vec![0xcc; expected.len()]).unwrap();
        source.as_file().set_len(0).unwrap();
        assert_eq!(capture.view().unwrap().as_ref(), expected);
    }

    #[test]
    fn copy_refuses_truncation_during_capture() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&[0x11; 8192]).unwrap();
        let error =
            CapturedLaunchInput::capture_with(File::open(source.path()).unwrap(), |_, _| {
                source.as_file().set_len(7).unwrap();
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn copy_bounds_source_growth_and_discards_failed_clone_contents() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"validated capture").unwrap();
        let capture = CapturedLaunchInput::capture_with(
            File::open(source.path()).unwrap(),
            |mut destination, _| {
                destination.write_all(&[0xcc; 8192]).unwrap();
                source.write_all(&[0xff; 8192]).unwrap();
                Err(io::Error::from_raw_os_error(libc::EXDEV))
            },
        )
        .unwrap();
        assert_eq!(capture.view().unwrap().as_ref(), b"validated capture");
    }

    #[test]
    fn unexpected_clone_failure_is_reported_without_copying() {
        let source = tempfile::tempfile().unwrap();
        let error = CapturedLaunchInput::capture_with(source, |_, _| {
            Err(io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn empty_capture_provides_an_empty_view() {
        let capture = CapturedLaunchInput::capture(tempfile::tempfile().unwrap()).unwrap();
        assert!(capture.view().unwrap().as_ref().is_empty());
    }
}
