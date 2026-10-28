// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in Corium boot proof (`cargo test --test module_boot -- --ignored`).
//!
//! Requires QEMU/KVM and these fixture environment variables:
//! - ARMA_MODULE_KERNEL: x86_64 kernel with CONFIG_DM_VERITY=m; root-disk
//!   discovery drivers must be built in for the no-module negative control.
//! - ARMA_MODULE_CONFIG: that kernel's actual configuration.
//! - ARMA_MODULE_INIT: static Corium binary.
//! - ARMA_MODULE_DISK: Corium-compatible verified-root GPT disk whose systemd
//!   service prints `CORIUM-TEST-OK: systemd service started` and powers off.
//! - ARMA_MODULE_ROOT_HASH: the disk's 64-hex-digit root hash.
//! - ARMA_MODULE_TREE (optional): direct release-specific module directory;
//!   otherwise Arma discovers the installed tree matching the supplied kernel.
//!
//! Corium's tests/support/fixtures.rs root/base helpers can prepare the disk.
//! This boots the extracted initrd directly, not the complete PMI through Dillo.
#![cfg(target_os = "linux")]
mod common;

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

struct Guest(Child);
impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn input(name: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(|| panic!("required fixture: {name}"), PathBuf::from)
}

fn boot(work: &Path, name: &str, kernel: &Path, initrd: &Path, disk: &Path, root: &str) -> String {
    let serial = work.join(format!("{name}.serial.log"));
    let mut command = Command::new("qemu-system-x86_64");
    command
        .args([
            "-machine",
            "q35,accel=kvm",
            "-cpu",
            "host",
            "-m",
            "768M",
            "-smp",
            "1",
            "-display",
            "none",
            "-monitor",
            "none",
            "-no-reboot",
            "-qmp",
            "stdio",
            "-serial",
        ])
        .arg(format!("file:{}", serial.display()))
        .arg("-kernel")
        .arg(kernel)
        .arg("-initrd")
        .arg(initrd)
        .arg("-append")
        .arg(format!(
            "console=ttyS0 quiet panic=-1 corium={root} corium.log=debug"
        ))
        .arg("-drive")
        .arg(format!(
            "file={},format=raw,if=virtio,readonly=on",
            disk.display()
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(File::create(work.join(format!("{name}.qemu.stderr"))).unwrap());
    fs::write(
        work.join(format!("{name}.command.txt")),
        format!("{command:?}\n"),
    )
    .unwrap();
    let mut guest = Guest(command.spawn().expect("launch QEMU/KVM"));
    let output = guest.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut events = Vec::new();
    let shutdown = loop {
        let line = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("QMP timeout/closed stream; inspect saved serial log")
            .unwrap();
        let event: Value = serde_json::from_str(&line).unwrap();
        events.push(event.clone());
        if event.get("QMP").is_some() {
            let input = guest.0.stdin.as_mut().unwrap();
            input
                .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
                .unwrap();
            input.flush().unwrap();
        }
        assert!(event.get("error").is_none(), "QMP error: {event}");
        if event["event"] == "SHUTDOWN" {
            break event["data"].clone();
        }
    };
    fs::write(
        work.join(format!("{name}.qmp.json")),
        serde_json::to_vec_pretty(&events).unwrap(),
    )
    .unwrap();
    assert_eq!(shutdown["guest"], true);
    assert_eq!(shutdown["reason"], "guest-shutdown");
    let exit_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = guest.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < exit_deadline, "QEMU exit timeout");
        std::thread::sleep(Duration::from_millis(10));
    }
    reader.join().unwrap();
    fs::read_to_string(serial).unwrap()
}

#[test]
#[ignore = "requires QEMU/KVM, matching kernel/modules, static Corium and a verified-root disk; see fixture requirements at the top of this file"]
fn corium_handoff_requires_the_packaged_verity_driver() {
    let kernel = input("ARMA_MODULE_KERNEL");
    let config = input("ARMA_MODULE_CONFIG");
    let init = input("ARMA_MODULE_INIT");
    let disk = input("ARMA_MODULE_DISK");
    let root =
        std::env::var("ARMA_MODULE_ROOT_HASH").expect("required fixture: ARMA_MODULE_ROOT_HASH");
    assert_eq!(root.len(), 64);
    assert!(root.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .lines()
            .any(|line| line == "CONFIG_DM_VERITY=m"),
        "negative control requires modular dm_verity, not a built-in driver"
    );
    let work = tempfile::Builder::new()
        .prefix("arma-module-boot-")
        .tempdir()
        .unwrap()
        .keep();
    eprintln!("Module boot evidence: {}", work.display());
    for selected in [true, false] {
        let name = if selected {
            "selected"
        } else {
            "without-modules"
        };
        let pmi = work.join(format!("{name}.pmi"));
        let initrd = work.join(format!("{name}.cpio"));
        let mut command = Command::new(common::arma_bin());
        command
            .arg("build")
            .arg("--kernel")
            .arg(&kernel)
            .arg("--config")
            .arg(&config)
            .arg("--initrd")
            .arg(&init)
            .arg("--cmdline")
            .arg(format!("corium={root}"));
        if selected {
            // This is fixture policy, not an Arma default driver list.
            for module in [
                "virtio_pci",
                "virtio_blk",
                "dm_mod",
                "dm_zero",
                "dm_snapshot",
                "dm_verity",
                "ext4",
            ] {
                command.arg("--module").arg(module);
            }
            if let Some(tree) = std::env::var_os("ARMA_MODULE_TREE") {
                command.arg("--module-tree").arg(tree);
            }
        }
        let output = command.arg(&pmi).output().unwrap();
        fs::write(work.join(format!("{name}.arma.log")), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&pmi).unwrap();
        let pe = goblin::pe::PE::parse(&bytes).unwrap();
        let section = pe
            .sections
            .iter()
            .find(|s| s.name().unwrap() == ".initrd")
            .unwrap();
        let offset = section.pointer_to_raw_data as usize;
        fs::write(
            &initrd,
            &bytes[offset..offset + section.size_of_raw_data as usize],
        )
        .unwrap();
        let log = boot(&work, name, &kernel, &initrd, &disk, &root);
        if selected {
            assert!(log.contains("module loaded") && log.contains("dm-verity.ko"));
            assert!(log.contains("phase=\"modules\""));
            assert!(log.contains("phase=\"pivoted\""));
            assert!(log.contains("CORIUM-TEST-OK: systemd service started"));
            assert!(!log.contains("boot failed"));
        } else {
            assert!(log.contains("boot failed") && log.contains("assemble root:"));
            assert!(!log.contains("CORIUM-TEST-OK"));
        }
    }
}
