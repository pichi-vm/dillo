// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Wall-clock benchmark of `AcpiBuffer::populate` across the test DTB corpus.
//!
//! Run: `cargo run --release --example bench_populate`
//!
//! Times the full pipeline (DTB parse + count + emit). Reports
//! min/median/mean over N iterations per fixture so cache-warmth and
//! noise are visible.

use std::hint::black_box;
use std::time::Instant;

use devtree::Tree;
use dtb2acpi::{AcpiBuffer, OemIdentity};

const OEM: OemIdentity = OemIdentity {
    oem_id: *b"BENCH0",
    oem_table_id: *b"BENCHTBL",
    oem_revision: 1,
    creator_id: *b"BNCH",
    creator_revision: 1,
};

const ITERS: usize = 10_000;
const WARMUP: usize = 1_000;
const BUF_BYTES: usize = 32 * 1024;

struct Fixture {
    name: &'static str,
    dtb: &'static [u8],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "basic",
        dtb: include_bytes!("../tests/data/basic.dtb"),
    },
    Fixture {
        name: "numa",
        dtb: include_bytes!("../tests/data/numa.dtb"),
    },
    Fixture {
        name: "numa_memory_only",
        dtb: include_bytes!("../tests/data/numa_memory_only_domain.dtb"),
    },
    Fixture {
        name: "too_many_memory",
        dtb: include_bytes!("../tests/data/too_many_memory_regions.dtb"),
    },
    Fixture {
        name: "too_many_ecam",
        dtb: include_bytes!("../tests/data/too_many_ecam_regions.dtb"),
    },
    Fixture {
        name: "many_cpus_256",
        dtb: include_bytes!("../tests/data/many_cpus.dtb"),
    },
];

fn time_one(dtb: &[u8]) -> (u128, usize) {
    // Parse + populate together — the real call path callers see.
    let mut buf = Box::new(AcpiBuffer::<BUF_BYTES>::default());
    let base_gpa = AsRef::<[u8]>::as_ref(&*buf).as_ptr() as u64;

    let t0 = Instant::now();
    let tree: Tree<'_> = Tree::parse(black_box(dtb)).expect("parse");
    let n = buf.populate(&tree, &OEM, base_gpa).expect("populate");
    let ns = t0.elapsed().as_nanos();
    black_box(&buf);
    (ns, n)
}

fn time_populate_only(dtb: &[u8]) -> (u128, usize) {
    // Pre-parse to isolate the dtb2acpi work from devtree parsing.
    let tree: Tree<'_> = Tree::parse(dtb).expect("parse");
    let mut buf = Box::new(AcpiBuffer::<BUF_BYTES>::default());
    let base_gpa = AsRef::<[u8]>::as_ref(&*buf).as_ptr() as u64;

    let t0 = Instant::now();
    let n = buf
        .populate(black_box(&tree), &OEM, base_gpa)
        .expect("populate");
    let ns = t0.elapsed().as_nanos();
    black_box(&buf);
    (ns, n)
}

fn summarize(label: &str, dtb_bytes: usize, mut samples: Vec<u128>, out_bytes: usize) {
    samples.sort_unstable();
    let n = samples.len();
    let min = samples[0];
    let median = samples[n / 2];
    let p99 = samples[n.saturating_sub(n / 100).saturating_sub(1)];
    let sum: u128 = samples.iter().sum();
    let mean = sum / n as u128;
    println!(
        "  {label:<14} dtb={dtb_bytes:>6}B  out={out_bytes:>5}B   \
         min={min:>6}ns  med={median:>6}ns  mean={mean:>6}ns  p99={p99:>6}ns"
    );
}

fn main() {
    println!(
        "dtb2acpi populate() benchmark — {ITERS} iters/fixture (+{WARMUP} warmup), buf={BUF_BYTES}B\n"
    );

    for f in FIXTURES {
        // Warmup
        for _ in 0..WARMUP {
            let _ = time_one(f.dtb);
        }

        let mut full_samples = Vec::with_capacity(ITERS);
        let mut out_bytes = 0;
        for _ in 0..ITERS {
            let (ns, n) = time_one(f.dtb);
            full_samples.push(ns);
            out_bytes = n;
        }

        let mut emit_samples = Vec::with_capacity(ITERS);
        for _ in 0..ITERS {
            let (ns, _) = time_populate_only(f.dtb);
            emit_samples.push(ns);
        }

        println!("[{}]", f.name);
        summarize("parse+populate", f.dtb.len(), full_samples, out_bytes);
        summarize("populate-only ", f.dtb.len(), emit_samples, out_bytes);
        println!();
    }
}
