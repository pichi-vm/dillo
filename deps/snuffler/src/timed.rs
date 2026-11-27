// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in longer runs of snuffler's existing block and network workloads.

use snuffler::performance::{Histogram, Operation, Performance};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

pub(crate) struct Config {
    pub duration: Duration,
    pub warmup: Duration,
    pub queue_depth: usize,
}

impl Config {
    pub(crate) fn from_cmdline(cmdline: &str) -> Option<Self> {
        let ms = super::cmdline_token(cmdline, "dillo.bench_ms=")?;
        let duration = ms.parse::<u64>().expect("invalid dillo.bench_ms");
        let warmup = super::cmdline_token(cmdline, "dillo.bench_warmup_ms=")
            .map_or(250, |s| s.parse::<u64>().expect("invalid benchmark warmup"));
        assert!((100..=30_000).contains(&duration) && warmup <= 5_000);
        let queue_depth = super::cmdline_token(cmdline, "dillo.bench_qd=")
            .map_or(1, |s| s.parse().expect("invalid benchmark concurrency"));
        assert!(matches!(queue_depth, 1 | 8 | 32));
        Some(Self {
            duration: Duration::from_millis(duration),
            warmup: Duration::from_millis(warmup),
            queue_depth,
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
        max_in_flight: 1,
        bytes: latency.count * request_bytes as u64,
        elapsed_ns,
        latency,
        verified: None,
    })
}

/// One blocking request per thread, synchronized warm-up and measured windows.
/// Merge observations, not percentiles; include the final in-flight requests
/// in both byte counts and elapsed time. Allocation stays outside the window.
pub(crate) fn measure_parallel(
    config: &Config,
    device: &str,
    operation: &str,
    request_bytes: usize,
    calls: &mut [impl FnMut(bool) -> io::Result<()> + Send],
) -> io::Result<Operation> {
    use std::sync::{Barrier, Mutex};
    let count = calls.len();
    let barrier = Barrier::new(count + 1);
    let start = Mutex::new(Instant::now());
    let (latency, elapsed_ns) = std::thread::scope(|scope| {
        let threads: Vec<_> = calls
            .iter_mut()
            .map(|call| {
                let (barrier, start) = (&barrier, &start);
                scope.spawn(move || {
                    let mut latency = Histogram::default();
                    let mut error = None;
                    let mut elapsed_ns = 0;
                    for (warmup, duration) in [(true, config.warmup), (false, config.duration)] {
                        barrier.wait();
                        let start = *start.lock().unwrap();
                        if error.is_none() {
                            error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                while start.elapsed() < duration {
                                    let before = Instant::now();
                                    call(warmup)?;
                                    if !warmup {
                                        latency.record(before.elapsed().as_nanos() as u64);
                                    }
                                }
                                Ok::<_, io::Error>(())
                            }))
                            .unwrap_or_else(|_| Err(io::Error::other("benchmark call panicked")))
                            .err();
                        }
                        elapsed_ns = start.elapsed().as_nanos() as u64;
                        barrier.wait();
                    }
                    match error {
                        Some(error) => Err(error),
                        None => Ok((latency, elapsed_ns)),
                    }
                })
            })
            .collect();
        for phase in ["warmup", "active"] {
            mark(&format!("{phase}:{device}:{operation}:{request_bytes}"));
            *start.lock().unwrap() = Instant::now();
            barrier.wait();
            barrier.wait();
        }
        let mut latency = Histogram::default();
        let mut elapsed = 0;
        for thread in threads {
            let (samples, duration) = thread
                .join()
                .map_err(|_| io::Error::other("benchmark thread panicked"))??;
            latency.merge(&samples);
            elapsed = elapsed.max(duration);
        }
        Ok::<_, io::Error>((latency.summary(), elapsed))
    })?;
    mark(&format!("verify:{device}:{operation}:{request_bytes}"));
    Ok(Operation {
        device: device.into(),
        operation: operation.into(),
        io_mode: "o_direct_threads".into(),
        request_bytes: request_bytes as u64,
        max_in_flight: count,
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
    let blocks: Vec<_> = blocks
        .iter()
        .filter(|block| block.size_bytes != 0)
        .collect();
    let groups: Vec<_> = if cmdline
        .split_whitespace()
        .any(|word| word == "dillo.bench_concurrent")
    {
        vec![blocks]
    } else {
        blocks.into_iter().map(|block| vec![block]).collect()
    };
    for group in groups {
        match super::bench::timed_devices(&group, config) {
            Ok(operations) => report.operations.extend(operations),
            Err(error) => report.errors.push(format!("block: {error}")),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_failure_completes_both_phase_barriers() {
        let config = Config {
            duration: Duration::from_millis(1),
            warmup: Duration::from_millis(1),
            queue_depth: 8,
        };
        let mut calls: Vec<_> = (0..8)
            .map(|i| {
                move |_| {
                    if i == 0 {
                        Err(io::ErrorKind::UnexpectedEof.into())
                    } else {
                        Ok(())
                    }
                }
            })
            .collect();
        let error = measure_parallel(&config, "fixture", "read", 4096, &mut calls).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
