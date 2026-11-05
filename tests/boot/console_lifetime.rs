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

#[test]
fn managed_console_close_stops_a_booted_vm() {
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
    let (reader, mut writer) = io::pipe().unwrap();
    let mut vm = Vm(Command::new(env!("CARGO_BIN_EXE_dillo"))
        .arg("--pmi")
        .arg(&pmi)
        .args(["--memory", "256", "--cpus", "1", "--exit-on-stdin-close"])
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
    drop(writer);
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
    println!("native VM console lifetime: boot report, ordinary input, cooperative zero exit");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires MADRILLO_BIN and a native hypervisor; run explicitly for monitor qualification"]
fn monitor_crash_allows_cooperative_vm_teardown() {
    use nix::{
        sys::{
            prctl,
            signal::{Signal, kill},
            wait::{WaitPidFlag, WaitStatus, waitpid},
        },
        unistd::Pid,
    };
    use std::{
        io::Read,
        os::{
            fd::{AsFd, AsRawFd},
            unix::net::UnixStream,
        },
    };

    struct RestoreSubreaper(bool);
    impl Drop for RestoreSubreaper {
        fn drop(&mut self) {
            let _ = prctl::set_child_subreaper(self.0);
        }
    }
    struct MonitoredVm {
        monitor: Child,
        leader: Option<Pid>,
        diagnostics: std::path::PathBuf,
    }
    impl Drop for MonitoredVm {
        fn drop(&mut self) {
            if std::thread::panicking() {
                for name in ["monitor.err", "state/result.json", "state/console.log"] {
                    if let Ok(bytes) = std::fs::read(self.diagnostics.join(name)) {
                        eprintln!(
                            "{name} ({} bytes): {}",
                            bytes.len(),
                            String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(8192)..])
                        );
                    }
                }
            }
            if matches!(self.monitor.try_wait(), Ok(None)) {
                let _ = self.monitor.kill();
                let _ = self.monitor.wait();
            }
            if let Some(pid) = self.leader
                && matches!(
                    waitpid(pid, Some(WaitPidFlag::WNOHANG)),
                    Ok(WaitStatus::StillAlive)
                )
            {
                // Only an owned, unreaped child can reach this branch. Never
                // kill an ECHILD or a PID that was already reaped/reused.
                let _ = kill(pid, Signal::SIGKILL);
                let _ = waitpid(pid, None);
            }
        }
    }
    fn next(client: &mut UnixStream) -> serde_json::Value {
        let mut size = [0; 4];
        client.read_exact(&mut size).unwrap();
        let length = u32::from_be_bytes(size) as usize;
        assert!(length <= 1024 * 1024);
        let mut bytes = vec![0; length];
        client.read_exact(&mut bytes).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["version"], 1);
        response["message"].clone()
    }
    fn until(client: &mut UnixStream, needle: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut output = Vec::new();
        let mut received = 0;
        while !output.windows(needle.len()).any(|window| window == needle) {
            assert!(Instant::now() < deadline, "monitor output deadline");
            let message = next(client);
            assert_eq!(
                message["type"], "output",
                "unexpected monitor response: {message}"
            );
            let bytes: Vec<u8> = serde_json::from_value(message["bytes"].clone()).unwrap();
            received += bytes.len();
            let keep = output.len().saturating_sub(needle.len() - 1);
            output.drain(..keep);
            output.extend_from_slice(&bytes);
            assert!(received <= 2 * 1024 * 1024);
        }
    }
    let executable = std::env::var_os("MADRILLO_BIN")
        .expect("set MADRILLO_BIN to the tested monitor executable");
    assert!(hypervisor_available());
    let _restore = RestoreSubreaper(prctl::get_child_subreaper().unwrap());
    prctl::set_child_subreaper(true).unwrap();
    let root = TempDir::new().unwrap();
    let pmi = build_pmi(
        root.path(),
        "console=hvc0 dillo.console_lifetime_probe",
        false,
    );
    let (mut client, initial) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let flags = nix::fcntl::FdFlag::from_bits_truncate(
        nix::fcntl::fcntl(initial.as_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap(),
    );
    nix::fcntl::fcntl(
        initial.as_fd(),
        nix::fcntl::FcntlArg::F_SETFD(flags & !nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .unwrap();
    let mut vm = MonitoredVm {
        monitor: Command::new(executable)
            .arg("--state-dir")
            .arg(root.path().join("state"))
            .args([
                "--stdin",
                "--control",
                &initial.as_raw_fd().to_string(),
                "--",
            ])
            .arg(env!("CARGO_BIN_EXE_dillo"))
            .arg("--pmi")
            .arg(pmi)
            .args(["--memory", "256", "--cpus", "1", "--exit-on-stdin-close"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(root.path().join("monitor.err")).unwrap())
            .spawn()
            .unwrap(),
        leader: None,
        diagnostics: root.path().to_owned(),
    };
    drop(initial);
    assert_eq!(next(&mut client)["type"], "prepared");
    let started = next(&mut client);
    assert_eq!(started["type"], "started");
    vm.leader = Some(Pid::from_raw(
        i32::try_from(started["leader_pid"].as_u64().unwrap()).unwrap(),
    ));
    until(&mut client, REPORT_END.as_bytes());
    let request = serde_json::to_vec(&serde_json::json!({
        "version": 1, "message": {"type": "input", "bytes": b"madrillo input\n".to_vec()}
    }))
    .unwrap();
    client
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();
    client.write_all(&request).unwrap();
    until(&mut client, b"<<<CONSOLE-INPUT-OK>>>");
    assert!(vm.monitor.try_wait().unwrap().is_none());
    vm.monitor.kill().unwrap();
    assert!(!vm.monitor.wait().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match waitpid(vm.leader.unwrap(), Some(WaitPidFlag::WNOHANG)).unwrap() {
            WaitStatus::StillAlive => {
                assert!(
                    Instant::now() < deadline,
                    "VM survived monitor crash past cleanup deadline"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            status => {
                assert!(
                    matches!(status, WaitStatus::Exited(_, 0)),
                    "VM must exit cooperatively, got {status:?}"
                );
                vm.leader = None;
                break;
            }
        }
    }
    assert!(
        !root.path().join("state/result.json").exists(),
        "a killed monitor cannot claim finalization"
    );
    println!("madrillo crash: confirmed guest input, killed monitor, reaped dillo exit zero");
}
