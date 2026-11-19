// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use imago::{
    file::File, qcow2::Qcow2, FormatAccess, FormatDriverBuilder, PermissiveImplicitOpenGate,
};
use std::{os::unix::fs::MetadataExt, process::Command};
fn allocated(p: &str) -> u64 {
    std::fs::metadata(p).unwrap().blocks() * 512
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let p = std::env::args().nth(1).unwrap();
    assert!(Command::new("qemu-img")
        .args([
            "create",
            "-f",
            "qcow2",
            "-o",
            "cluster_size=65536",
            &p,
            "1G"
        ])
        .status()?
        .success());
    let mut q = FormatAccess::new(
        Qcow2::<File>::builder_path(&p)
            .write(true)
            .open(PermissiveImplicitOpenGate::default())?,
    );
    println!("empty allocated={}", allocated(&p));
    let b = vec![0x5au8; 64 * 1024 * 1024];
    q.write(&b[..], 0)?;
    q.flush()?;
    q.sync()?;
    println!("written allocated={}", allocated(&p));
    q.discard_to_zero(0, b.len() as u64)?;
    q.flush()?;
    q.sync()?;
    println!("discarded allocated={}", allocated(&p));
    let mut r = vec![0xff; b.len()];
    q.read(&mut r[..], 0)?;
    assert!(r.iter().all(|x| *x == 0));
    drop(q);
    assert!(Command::new("qemu-img")
        .args(["check", "-f", "qcow2", &p])
        .status()?
        .success());
    Ok(())
}
