// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in RAM access evidence for the large-memory boot tests.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;

use snuffler::MemoryProbe;

pub(crate) fn probe(cmdline: &str) -> Option<MemoryProbe> {
    if !cmdline
        .split_ascii_whitespace()
        .any(|word| word == "dillo.memory_probe")
    {
        return None;
    }
    let mut report = MemoryProbe::default();
    if let Err(err) = check(&mut report) {
        report.error = Some(err.to_string());
    }
    Some(report)
}

fn check(report: &mut MemoryProbe) -> io::Result<()> {
    for line in fs::read_to_string("/proc/iomem")?.lines() {
        let Some((range, label)) = line.split_once(':') else {
            continue;
        };
        if label.trim() != "System RAM" {
            continue;
        }
        let (start, end) = range
            .trim()
            .split_once('-')
            .ok_or_else(|| io::Error::other("malformed System RAM range"))?;
        let start = u64::from_str_radix(start, 16).map_err(io::Error::other)?;
        let end = u64::from_str_radix(end, 16).map_err(io::Error::other)?;
        report.system_ram.push((
            start,
            end.checked_add(1)
                .ok_or_else(|| io::Error::other("System RAM range overflow"))?,
        ));
    }

    // Bound the probe to 256 MiB even for much larger guests. Touch every
    // page, retain the entire allocation, then verify unique per-page data.
    // No raw physical mapping or unsafe access to kernel-owned RAM is needed.
    let page_size = rustix::param::page_size();
    report.page_size = page_size as u64;
    let stride = page_size / size_of::<u64>();
    let mut buffer = vec![0u64; (256 << 20) / size_of::<u64>()];
    let pattern = 0x7a35_b19f_e840_c62d;
    for index in (0..buffer.len()).step_by(stride) {
        buffer[index] = index as u64 ^ pattern;
    }
    std::hint::black_box(&mut buffer);

    let pages = buffer.len() / stride;
    let base_page = buffer.as_ptr() as u64 / report.page_size;
    let mut pagemap = vec![0u8; pages * size_of::<u64>()];
    File::open("/proc/self/pagemap")?.read_exact_at(&mut pagemap, base_page * 8)?;
    for (page, entry) in pagemap.as_chunks::<8>().0.iter().enumerate() {
        let index = page * stride;
        if buffer[index] != index as u64 ^ pattern {
            return Err(io::Error::other(format!("memory mismatch on page {page}")));
        }
        let entry = u64::from_le_bytes(*entry);
        let pfn = entry & ((1 << 55) - 1);
        if entry & (1 << 63) == 0 || pfn == 0 {
            return Err(io::Error::other(
                "touched page is absent or its PFN is unavailable",
            ));
        }
        let address = pfn
            .checked_mul(report.page_size)
            .ok_or_else(|| io::Error::other("physical page address overflow"))?;
        if !report
            .system_ram
            .iter()
            .any(|&(start, end)| start <= address && address < end)
        {
            return Err(io::Error::other("touched page is outside System RAM"));
        }
        report.verified_pages += 1;
        report.high_pages += u64::from(address >= 1 << 32);
        report.highest_address = report.highest_address.max(address);
    }
    if report.high_pages == 0 {
        return Err(io::Error::other("no verified physical page above 4 GiB"));
    }
    Ok(())
}
