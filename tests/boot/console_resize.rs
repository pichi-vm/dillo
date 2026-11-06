// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use interprocess::local_socket::{GenericFilePath, Stream, prelude::*};
use std::{
    io::Write,
    process::{Child, Stdio},
    time::Instant,
};

struct Vm(Child);
impl Drop for Vm {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn console_resize_reaches_guest_and_preserves_lifetime() {
    assert!(
        hypervisor_available(),
        "resize qualification requires a native hypervisor"
    );
    sign_dillo_for_hvf();
    let root = TempDir::new().unwrap();
    // Linux before 5326ab737a47 decodes RESIZE with rows/columns reversed.
    // Fedora 44's pinned 6.19 kernel contains the fix; the ordinary Firecracker
    // 6.1 boot fixture does not. Keep the guest assertion in actual cols/rows.
    let entry = KERNELS
        .iter()
        .find(|entry| entry.arch == host::ARCH && entry.url.contains("/fedora/linux/releases/44/"))
        .unwrap();
    let (kernel, config) = resolve(entry).expect("Fedora resize kernel unavailable");
    for symbol in ["VIRTIO_CONSOLE", "VIRTIO_PCI", "PCI"] {
        assert!(
            config_is_y(config.as_deref().unwrap(), symbol),
            "missing builtin {symbol}"
        );
    }
    let pmi = build_pmi_from_path(
        root.path(),
        &kernel,
        host::CONFIG,
        "console=hvc0 dillo.console_resize_probe",
        false,
    );
    #[cfg(unix)]
    let endpoint = root.path().join("resize.sock");
    #[cfg(windows)]
    let endpoint = PathBuf::from(format!(
        r"\\.\pipe\dillo-resize-{}-{}",
        std::process::id(),
        root.path().file_name().unwrap().to_string_lossy()
    ));
    let stdout = root.path().join("console.out");
    let stderr = root.path().join("console.err");
    let (reader, writer) = std::io::pipe().unwrap();
    let mut vm = Vm(Command::new(env!("CARGO_BIN_EXE_dillo"))
        .arg("--pmi")
        .arg(&pmi)
        .args(["--memory", "512", "--cpus", "1", "--bus", "pci"])
        .arg("--console-resize")
        .arg(&endpoint)
        .stdin(Stdio::from(reader))
        .stdout(File::create(&stdout).unwrap())
        .stderr(File::create(&stderr).unwrap())
        .spawn()
        .unwrap());
    // The first connection may precede the guest's control-queue negotiation.
    // Every later size uses a fresh connection, as a detached caller would.
    for dimensions in [(300, 77), (120, 41), (81, 25)] {
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut stream = loop {
            match Stream::connect(endpoint.as_path().to_fs_name::<GenericFilePath>().unwrap()) {
                Ok(stream) => break stream,
                Err(error) => {
                    assert!(
                        vm.0.try_wait().unwrap().is_none(),
                        "VM exited: {}",
                        std::fs::read_to_string(&stderr).unwrap()
                    );
                    assert!(
                        Instant::now() < deadline,
                        "resize connection deadline: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let size = dillo_config::ConsoleSize::try_from(dimensions).unwrap();
        stream.write_all(&<[u8; 4]>::from(size)).unwrap();
        // A test failure must not make Windows Drop wait for an unread flush.
        #[cfg(windows)]
        {
            let Stream::NamedPipe(pipe) = &stream;
            pipe.inner().assume_flushed();
        }
        let marker = format!("<<<CONSOLE-SIZE:{}x{}>>>", dimensions.0, dimensions.1);
        loop {
            let output = std::fs::read_to_string(&stdout).unwrap();
            if output.contains(&marker) {
                break;
            }
            assert!(
                vm.0.try_wait().unwrap().is_none(),
                "VM exited before {marker}: {output}\n{}",
                std::fs::read_to_string(&stderr).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "guest did not observe {marker}: {output}\n{}",
                std::fs::read_to_string(&stderr).unwrap()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(stream);
        assert!(
            vm.0.try_wait().unwrap().is_none(),
            "resize disconnect stopped VM"
        );
    }
    drop(writer);
    let status =
        vm.0.wait_timeout(Duration::from_secs(5))
            .unwrap()
            .expect("console loss must still stop VM after resize");
    assert!(status.success(), "cooperative stop: {status:?}");
    #[cfg(unix)]
    assert!(!endpoint.exists(), "resize endpoint survived VM teardown");
    println!("native VM resize: initial size, reconnect, rows/columns, cooperative zero exit");
}
