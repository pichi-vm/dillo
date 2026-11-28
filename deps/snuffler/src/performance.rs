// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bounded timing summaries shared by the guest probe and host reader.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Performance {
    pub duration_ms: u64,
    pub warmup_ms: u64,
    pub operations: Vec<Operation>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub device: String,
    pub operation: String,
    pub io_mode: String,
    pub request_bytes: u64,
    /// Closed-loop concurrency bound, not a claim that every slot stays busy.
    #[serde(default = "single_request")]
    pub max_in_flight: usize,
    pub bytes: u64,
    pub elapsed_ns: u64,
    pub latency: Latency,
    pub verified: Option<bool>,
}

fn single_request() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Latency {
    pub count: u64,
    /// Histogram upper bounds: exact below 128 ns; at most 1.5625% above a sample.
    pub p50_upper_ns: u64,
    pub p95_upper_ns: u64,
    pub p99_upper_ns: u64,
    pub max_ns: u64,
}

const PRECISION_BITS: u32 = 6;
const SUB_BUCKETS: usize = 1 << PRECISION_BITS;
const BINS: usize = 64 * SUB_BUCKETS;

/// Fixed storage: measurement memory does not grow with throughput.
#[derive(Debug)]
pub struct Histogram {
    bins: Box<[u64]>,
    count: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            bins: vec![0; BINS].into_boxed_slice(),
            count: 0,
            max: 0,
        }
    }
}

impl Histogram {
    pub fn merge(&mut self, other: &Self) {
        for (left, right) in self.bins.iter_mut().zip(other.bins.iter()) {
            *left += right;
        }
        self.count += other.count;
        self.max = self.max.max(other.max);
    }

    pub fn record(&mut self, ns: u64) {
        let shift = ns
            .checked_ilog2()
            .unwrap_or(0)
            .saturating_sub(PRECISION_BITS);
        self.bins[shift as usize * SUB_BUCKETS + (ns >> shift) as usize] += 1;
        self.count += 1;
        self.max = self.max.max(ns);
    }

    pub fn summary(&self) -> Latency {
        let percentile = |percent: u64| {
            let rank = (self.count * percent).div_ceil(100);
            let mut count = 0;
            for (index, n) in self.bins.iter().enumerate() {
                count += n;
                if rank != 0 && count >= rank {
                    let upper = if index < 2 * SUB_BUCKETS {
                        index as u64
                    } else {
                        (((index % SUB_BUCKETS + SUB_BUCKETS + 1) as u128)
                            << (index / SUB_BUCKETS - 1))
                            .saturating_sub(1)
                            .min(u64::MAX as u128) as u64
                    };
                    return upper;
                }
            }
            0
        };
        Latency {
            count: self.count,
            p50_upper_ns: percentile(50),
            p95_upper_ns: percentile(95),
            p99_upper_ns: percentile(99),
            max_ns: self.max,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_bounds_cover_samples_without_growing_storage() {
        for sample in [0, 1, 127, 128, 255, 256, 1_000, 1_000_000, u64::MAX] {
            let mut histogram = Histogram::default();
            histogram.record(sample);
            let result = histogram.summary();
            assert_eq!(result.count, 1);
            assert_eq!(result.max_ns, sample);
            assert!(result.p99_upper_ns >= sample);
            assert!((result.p99_upper_ns as u128) * 64 <= (sample as u128) * 65);
        }
        let mut histogram = Histogram::default();
        for sample in 1..=100 {
            histogram.record(sample);
        }
        let result = histogram.summary();
        assert_eq!(result.p50_upper_ns, 50);
        assert_eq!(result.p95_upper_ns, 95);
        assert_eq!(result.p99_upper_ns, 99);

        let mut lower = Histogram::default();
        let mut upper = Histogram::default();
        for sample in 1..=100 {
            if sample <= 50 {
                lower.record(sample);
            } else {
                upper.record(sample);
            }
        }
        lower.merge(&upper);
        let merged = lower.summary();
        assert_eq!(merged.count, result.count);
        assert_eq!(merged.p50_upper_ns, result.p50_upper_ns);
        assert_eq!(merged.p99_upper_ns, result.p99_upper_ns);
        assert_eq!(merged.max_ns, result.max_ns);
    }
}
