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
fn console_input_reaches_guest() {
    assert!(
        hypervisor_available(),
        "console input qualification requires a native hypervisor"
    );
    sign_dillo_for_hvf();
    let root = TempDir::new().unwrap();
    let pmi = build_pmi(root.path(), "console=hvc0 dillo.console_input_probe", false);
    let stdout = root.path().join("console.out");
    let stderr = root.path().join("console.err");
    let (reader, mut writer) = io::pipe().unwrap();
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
    // Early bytes can be discarded while the guest initializes its terminal.
    let deadline = Instant::now() + Duration::from_secs(90);
    while parse_report(&std::fs::read_to_string(&stdout).unwrap()).is_none() {
        assert!(
            vm.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "guest did not become ready: {}",
            std::fs::read_to_string(&stderr).unwrap()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    writer.write_all(b"madrillo input\n").unwrap();
    // The guest acknowledges input, then follows its normal shutdown path.
    let status =
        vm.0.wait_timeout(Duration::from_secs(90))
            .unwrap()
            .expect("guest did not finish the input probe");
    let output = std::fs::read_to_string(stdout).unwrap();
    let diagnostics = std::fs::read_to_string(stderr).unwrap();
    assert!(status.success(), "{status:?}: {diagnostics}");
    assert!(parse_report(&output).is_some(), "{output}\n{diagnostics}");
    assert!(
        output.contains("<<<CONSOLE-INPUT-OK>>>"),
        "stdin did not reach the guest: {output}\n{diagnostics}"
    );
}
