// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Raw block-device I/O benchmarks for snuffler.
//!
//! For each whole-disk device, open `/dev/<name>` (preferring `O_DIRECT` so the
//! I/O actually traverses virtio-blk rather than the page cache) and measure
//! sequential + random read, and — on read-write devices — sequential + random
//! write with a read-back integrity check. Read-only devices are probed for
//! correct `O_RDWR`-open rejection instead.
//!
//! snuffler measures and reports; it asserts nothing. Throughput is telemetry
//! (useful for finding bottlenecks outside CI); only the correctness invariants
//! are stable enough for a harness to gate on. Writes are destructive — snuffler
//! is a disposable-VM probe; do not attach real data to a snuffler VM.
//!
//! Linux-only, via `rustix` safe wrappers — no `unsafe`, no `libc`.

use std::time::Instant;

use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use snuffler::{BlkBench, BlkOp};

/// Sequential transfer block size.
const SEQ_BLK: usize = 64 * 1024;
/// Random transfer block size (also the O_DIRECT alignment we target).
const RAND_BLK: usize = 4096;
/// Cap total sequential transfer so boot stays quick.
const TOTAL_CAP: u64 = 16 * 1024 * 1024;
/// Number of random ops (scaled down for tiny devices).
const RAND_OPS: u64 = 256;

pub(crate) fn benchmark_device(name: &str, size_bytes: u64, ro: bool) -> Option<BlkBench> {
    if size_bytes < RAND_BLK as u64 {
        return Some(err_bench(format!(
            "device too small to benchmark ({size_bytes} bytes)"
        )));
    }

    let path = format!("/dev/{name}");
    let base = if ro { OFlags::RDONLY } else { OFlags::RDWR };
    let (fd, mode) = match rustix::fs::open(&path, base | OFlags::DIRECT, Mode::empty()) {
        Ok(fd) => (fd, "o_direct"),
        Err(_) => match rustix::fs::open(&path, base, Mode::empty()) {
            Ok(fd) => (fd, "buffered"),
            Err(e) => return Some(err_bench(format!("open {path}: {e}"))),
        },
    };

    let total = round_down(size_bytes.min(TOTAL_CAP), RAND_BLK as u64);
    let seed = fnv1a(name.as_bytes());
    let mut buf = AlignedBuf::new(SEQ_BLK);

    let seq_read = seq_op(&fd, total, &mut buf, IoDir::Read, 0);
    let rand_read = rand_op(&fd, size_bytes, &mut buf, seed, IoDir::Read);

    let mut seq_write = None;
    let mut rand_write = None;
    let mut ro_write_rejected = None;

    if ro {
        // Prove the *device* (not the fd mode) enforces read-only. Linux may
        // either reject an O_RDWR open outright (older behavior) or allow the
        // open and refuse the write with EROFS (6.x) — both count as enforced.
        // A read-only device also rejects the write at the device layer, so the
        // single buffered sector below never lands even if the kernel let it
        // through. (Snuffler VMs carry no real data, by contract.)
        ro_write_rejected = Some(match rustix::fs::open(&path, OFlags::RDWR, Mode::empty()) {
            Err(_) => true,
            Ok(rw) => {
                let sector = [0u8; 512];
                rustix::io::pwrite(&rw, &sector, 0).is_err()
            }
        });
    } else {
        seq_write = Some(seq_op(&fd, total, &mut buf, IoDir::Write, seed));
        rand_write = Some(rand_op(
            &fd,
            size_bytes,
            &mut buf,
            seed ^ 0xABCD_EF01,
            IoDir::Write,
        ));
    }

    Some(BlkBench {
        mode: mode.to_string(),
        seq_read,
        rand_read,
        seq_write,
        rand_write,
        ro_write_rejected,
        error: None,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IoDir {
    Read,
    Write,
}

/// Sequential read or write of `total` bytes from offset 0, in 64 KiB blocks.
/// For writes, each block is filled with a per-offset pattern and a full
/// read-back verifies it.
fn seq_op(fd: &OwnedFd, total: u64, buf: &mut AlignedBuf, dir: IoDir, seed: u64) -> BlkOp {
    let mut bytes = 0u64;
    let mut ops = 0u64;
    let mut errors = 0u64;
    let start = Instant::now();
    let mut off = 0u64;
    while off < total {
        let len = SEQ_BLK.min((total - off) as usize);
        let ok = match dir {
            IoDir::Read => pread_full(fd, &mut buf.as_mut_slice()[..len], off),
            IoDir::Write => {
                fill_pattern(&mut buf.as_mut_slice()[..len], seed ^ off);
                pwrite_full(fd, &buf.as_slice()[..len], off)
            }
        };
        if ok {
            bytes += len as u64;
        } else {
            errors += 1;
        }
        ops += 1;
        off += len as u64;
    }
    let duration_us = start.elapsed().as_micros() as u64;

    let verified = (dir == IoDir::Write).then(|| {
        if errors != 0 {
            return false;
        }
        let mut vbuf = AlignedBuf::new(SEQ_BLK);
        let mut o = 0u64;
        while o < total {
            let len = SEQ_BLK.min((total - o) as usize);
            if !pread_full(fd, &mut vbuf.as_mut_slice()[..len], o) {
                return false;
            }
            if !pattern_matches(&vbuf.as_slice()[..len], seed ^ o) {
                return false;
            }
            o += len as u64;
        }
        true
    });

    BlkOp {
        bytes,
        ops,
        duration_us,
        throughput_mibps: mibps(bytes, duration_us),
        errors,
        verified,
    }
}

/// Random 4 KiB read or write at aligned offsets. For writes, each block is
/// filled with a per-offset pattern and read back to verify.
fn rand_op(fd: &OwnedFd, size: u64, buf: &mut AlignedBuf, seed: u64, dir: IoDir) -> BlkOp {
    let nblocks = size / RAND_BLK as u64;
    if nblocks == 0 {
        return BlkOp {
            bytes: 0,
            ops: 0,
            duration_us: 0,
            throughput_mibps: 0.0,
            errors: 0,
            verified: (dir == IoDir::Write).then_some(true),
        };
    }
    let target = RAND_OPS.min(nblocks);
    let mut rng = Rng::new(seed);
    let offsets: Vec<u64> = (0..target)
        .map(|_| (rng.next_u64() % nblocks) * RAND_BLK as u64)
        .collect();

    let mut bytes = 0u64;
    let mut errors = 0u64;
    let start = Instant::now();
    for &off in &offsets {
        let ok = match dir {
            IoDir::Read => pread_full(fd, &mut buf.as_mut_slice()[..RAND_BLK], off),
            IoDir::Write => {
                fill_pattern(&mut buf.as_mut_slice()[..RAND_BLK], seed ^ off);
                pwrite_full(fd, &buf.as_slice()[..RAND_BLK], off)
            }
        };
        if ok {
            bytes += RAND_BLK as u64;
        } else {
            errors += 1;
        }
    }
    let duration_us = start.elapsed().as_micros() as u64;

    let verified = (dir == IoDir::Write).then(|| {
        if errors != 0 {
            return false;
        }
        let mut vbuf = AlignedBuf::new(RAND_BLK);
        for &off in &offsets {
            if !pread_full(fd, vbuf.as_mut_slice(), off) {
                return false;
            }
            if !pattern_matches(vbuf.as_slice(), seed ^ off) {
                return false;
            }
        }
        true
    });

    BlkOp {
        bytes,
        ops: offsets.len() as u64,
        duration_us,
        throughput_mibps: mibps(bytes, duration_us),
        errors,
        verified,
    }
}

/// Positional read that must fill the whole buffer (retrying on EINTR).
fn pread_full(fd: &OwnedFd, buf: &mut [u8], off: u64) -> bool {
    loop {
        match rustix::io::pread(fd, &mut *buf, off) {
            Ok(n) => return n == buf.len(),
            Err(Errno::INTR) => continue,
            Err(_) => return false,
        }
    }
}

/// Positional write that must write the whole buffer (retrying on EINTR).
fn pwrite_full(fd: &OwnedFd, buf: &[u8], off: u64) -> bool {
    loop {
        match rustix::io::pwrite(fd, buf, off) {
            Ok(n) => return n == buf.len(),
            Err(Errno::INTR) => continue,
            Err(_) => return false,
        }
    }
}

fn err_bench(msg: String) -> BlkBench {
    let zero = BlkOp {
        bytes: 0,
        ops: 0,
        duration_us: 0,
        throughput_mibps: 0.0,
        errors: 0,
        verified: None,
    };
    BlkBench {
        mode: "none".to_string(),
        seq_read: zero.clone(),
        rand_read: zero,
        seq_write: None,
        rand_write: None,
        ro_write_rejected: None,
        error: Some(msg),
    }
}

fn mibps(bytes: u64, us: u64) -> f64 {
    if us == 0 {
        0.0
    } else {
        (bytes as f64 / 1_048_576.0) / (us as f64 / 1_000_000.0)
    }
}

fn round_down(x: u64, align: u64) -> u64 {
    x & !(align - 1)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h | 1
}

/// Deterministic xorshift64 PRNG (reproducible random offsets, no deps).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn fill_pattern(buf: &mut [u8], seed: u64) {
    let mut rng = Rng::new(seed);
    let mut i = 0;
    while i + 8 <= buf.len() {
        buf[i..i + 8].copy_from_slice(&rng.next_u64().to_le_bytes());
        i += 8;
    }
    if i < buf.len() {
        let tail = rng.next_u64().to_le_bytes();
        let rem = buf.len() - i;
        buf[i..].copy_from_slice(&tail[..rem]);
    }
}

fn pattern_matches(buf: &[u8], seed: u64) -> bool {
    let mut expect = vec![0u8; buf.len()];
    fill_pattern(&mut expect, seed);
    expect == buf
}

/// Heap buffer aligned to [`RAND_BLK`] for O_DIRECT I/O, without `unsafe`: it
/// over-allocates and exposes the aligned sub-slice. The allocation never grows,
/// so the computed offset stays valid for the buffer's lifetime.
struct AlignedBuf {
    storage: Vec<u8>,
    offset: usize,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let storage = vec![0u8; len + RAND_BLK];
        let addr = storage.as_ptr() as usize;
        let offset = (RAND_BLK - (addr % RAND_BLK)) % RAND_BLK;
        Self {
            storage,
            offset,
            len,
        }
    }
    fn as_slice(&self) -> &[u8] {
        &self.storage[self.offset..self.offset + self.len]
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.offset..self.offset + self.len]
    }
}
