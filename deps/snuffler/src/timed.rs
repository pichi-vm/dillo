// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in longer runs of snuffler's existing block and network workloads.

use snuffler::performance::{Histogram, Operation, Performance};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

pub(crate) struct Config {
    pub duration: Duration,
    pub warmup: Duration,
}

impl Config {
    pub(crate) fn from_cmdline(cmdline: &str) -> Option<Self> {
        let ms = super::cmdline_token(cmdline, "dillo.bench_ms=")?;
        let duration = ms.parse::<u64>().expect("invalid dillo.bench_ms");
        let warmup = super::cmdline_token(cmdline, "dillo.bench_warmup_ms=")
            .map_or(250, |s| s.parse::<u64>().expect("invalid benchmark warmup"));
        assert!((100..=30_000).contains(&duration) && warmup <= 5_000);
        Some(Self {
            duration: Duration::from_millis(duration),
            warmup: Duration::from_millis(warmup),
        })
    }
}

pub(crate) fn mark(phase: &str) {
    println!("<<<SNUFFLER-BENCH:{phase}>>>");
    let _ = io::stdout().flush();
}

pub(crate) fn measure(
    config: &Config,
    device: &str,
    operation: &str,
    io_mode: &str,
    request_bytes: usize,
    mut call: impl FnMut(bool) -> io::Result<()>,
) -> io::Result<Operation> {
    mark(&format!("warmup:{device}:{operation}:{request_bytes}"));
    let start = Instant::now();
    while start.elapsed() < config.warmup {
        call(true)?;
    }
    mark(&format!("active:{device}:{operation}:{request_bytes}"));
    let mut latency = Histogram::default();
    let start = Instant::now();
    while start.elapsed() < config.duration {
        let before = Instant::now();
        call(false)?;
        latency.record(before.elapsed().as_nanos() as u64);
    }
    let elapsed_ns = start.elapsed().as_nanos() as u64;
    let latency = latency.summary();
    mark(&format!("verify:{device}:{operation}:{request_bytes}"));
    Ok(Operation {
        device: device.into(),
        operation: operation.into(),
        io_mode: io_mode.into(),
        request_bytes: request_bytes as u64,
        bytes: latency.count * request_bytes as u64,
        elapsed_ns,
        latency,
        verified: None,
    })
}

pub(crate) fn run(cmdline: &str, blocks: &[snuffler::BlockDevice], config: &Config) -> Performance {
    let mut report = Performance {
        duration_ms: config.duration.as_millis() as u64,
        warmup_ms: config.warmup.as_millis() as u64,
        operations: Vec::new(),
        errors: Vec::new(),
    };
    for block in blocks.iter().filter(|block| block.size_bytes != 0) {
        match super::bench::timed_device(&block.name, block.size_bytes, block.ro, config) {
            Ok(operations) => report.operations.extend(operations),
            Err(error) => report.errors.push(format!("{}: {error}", block.name)),
        }
    }
    if let Some(address) = super::cmdline_token(cmdline, "dillo.net_echo=") {
        match network(&address, config) {
            Ok(operations) => report.operations.extend(operations),
            Err(error) => report.errors.push(format!("net: {error}")),
        }
    }
    mark("idle-after");
    std::thread::sleep(Duration::from_secs(2));
    mark("done");
    report
}

fn network(address: &str, config: &Config) -> io::Result<Vec<Operation>> {
    let mut results = Vec::new();
    for len in [64, 64 * 1024] {
        let mut socket = std::net::TcpStream::connect(address)?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let payload = vec![0x5a; len];
        let mut received = vec![0; len];
        let mut result = measure(config, "net", "tcp_echo", "tcp_nodelay", len, |_| {
            socket.write_all(&payload)?;
            socket.read_exact(&mut received)?;
            if received != payload {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })?;
        result.verified = Some(true);
        results.push(result);
    }
    Ok(results)
}
