// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{
    io::{self, Write},
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

#[rstest]
#[case(false)]
#[case(true)]
fn console_close_stops_a_booted_vm(#[case] buffered: bool) {
    assert!(
        hypervisor_available(),
        "console lifetime qualification requires a native hypervisor"
    );
    sign_dillo_for_hvf();
    let root = TempDir::new().unwrap();
    let pmi = build_pmi(
        root.path(),
        "console=hvc0 dillo.console_lifetime_probe",
        false,
    );
    let stdout = root.path().join("console.out");
    let stderr = root.path().join("console.err");
    #[cfg(unix)]
    let (reader, mut writer, keep_listener) = {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let (reader, writer) = io::pipe().unwrap();
        fcntl(&writer, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        let owned: std::os::fd::OwnedFd = reader.into();
        (File::from(owned), writer, ())
    };
    #[cfg(windows)]
    let (reader, mut writer, keep_listener) = {
        use interprocess::os::windows::named_pipe::{PipeListenerOptions, pipe_mode::Bytes};
        let name = format!(
            r"\\.\pipe\dillo-lifetime-{}-{}",
            std::process::id(),
            root.path().file_name().unwrap().to_string_lossy()
        );
        let wide = widestring::U16CString::from_str(&name).unwrap();
        let listener = PipeListenerOptions::new()
            .path(wide.as_ucstr())
            .nonblocking(true)
            .output_buffer_size_hint(65536)
            .create_send_only::<Bytes>()
            .unwrap();
        let reader = File::options().read(true).open(&name).unwrap();
        let writer = listener.accept().unwrap();
        (reader, writer, listener)
    };
    let mut vm = Vm(Command::new(env!("CARGO_BIN_EXE_dillo"))
        .arg("--pmi")
        .arg(&pmi)
        .args(["--memory", "256", "--cpus", "1"])
        .args(["--console", "endpoint=stdio,bus=pci"])
        .stdin(Stdio::from(reader))
        .stdout(File::create(&stdout).unwrap())
        .stderr(File::create(&stderr).unwrap())
        .spawn()
        .unwrap());
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let output = std::fs::read_to_string(&stdout).unwrap();
        if parse_report(&output).is_some() {
            break;
        }
        assert!(
            vm.0.try_wait().unwrap().is_none(),
            "VM exited before its report: {}",
            std::fs::read_to_string(&stderr).unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "guest boot deadline: {output}\n{}",
            std::fs::read_to_string(&stderr).unwrap()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    writer.write_all(b"madrillo input\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(&stdout)
        .unwrap()
        .contains("<<<CONSOLE-INPUT-OK>>>")
    {
        assert!(
            Instant::now() < deadline,
            "stdin did not reach the running guest"
        );
        assert!(
            vm.0.try_wait().unwrap().is_none(),
            "VM exited while testing stdin"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        vm.0.try_wait().unwrap().is_none(),
        "input must not end VM lifetime"
    );
    if buffered {
        // The guest has switched to raw mode and stopped reading. Require
        // sustained backpressure before closing the writer, not one transient
        // full pipe while the stdin reader is catching up.
        let mut saturated = 0;
        let mut written = 0;
        for _ in 0..256 {
            match writer.write(&[b'x'; 8192]) {
                Ok(0) => saturated += 1,
                Ok(count) => {
                    written += count;
                    saturated = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => saturated += 1,
                Err(error) => panic!("fill console input: {error}"),
            }
            if saturated == 3 {
                break;
            }
            if saturated != 0 {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        assert!(written > 0);
        assert_eq!(saturated, 3, "guest input never stayed backpressured");
    }
    #[cfg(windows)]
    writer.assume_flushed();
    drop(writer);
    #[cfg(windows)]
    drop(keep_listener);
    #[cfg(unix)]
    let () = keep_listener;
    let status =
        vm.0.wait_timeout(Duration::from_secs(5))
            .unwrap()
            .expect("console closure must stop VM without force-kill");
    assert!(status.success(), "cooperative VM stop: {status:?}");
    assert!(
        std::fs::read_to_string(&stderr)
            .unwrap()
            .contains("console input closed; stopping VM")
    );
    println!("native VM console lifetime: buffered={buffered}, cooperative zero exit");
}

#[test]
fn null_console_input_requests_shutdown_without_a_flag() {
    assert!(
        hypervisor_available(),
        "console lifetime requires a native hypervisor"
    );
    sign_dillo_for_hvf();
    let root = TempDir::new().unwrap();
    let pmi = build_pmi(
        root.path(),
        "console=hvc0 dillo.console_lifetime_probe",
        false,
    );
    let stderr = root.path().join("console.err");
    let mut vm = Vm(Command::new(env!("CARGO_BIN_EXE_dillo"))
        .arg("--pmi")
        .arg(&pmi)
        .args(["--memory", "256", "--cpus", "1"])
        .args(["--console", "endpoint=stdio,bus=pci"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(File::create(&stderr).unwrap())
        .spawn()
        .unwrap());
    let status =
        vm.0.wait_timeout(Duration::from_secs(90))
            .unwrap()
            .expect("null console EOF must stop the VM");
    let diagnostics = std::fs::read_to_string(stderr).unwrap();
    assert!(status.success(), "{status:?}: {diagnostics}");
    assert!(
        diagnostics.contains("console input closed; stopping VM"),
        "{diagnostics}"
    );
}
