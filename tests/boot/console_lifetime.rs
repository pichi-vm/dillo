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
