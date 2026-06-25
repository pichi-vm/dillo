// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: the user-mode virtio-net DNS query parser
//! (`dillo_virtio_net::fuzz_parse_dns_query`).
//!
//! Run with `cargo +nightly fuzz run dns_query` from this crate.
//!
//! The guest controls the DNS query bytes it sends to the gateway DNS responder,
//! so the parser runs on fully attacker-controlled input. This asserts that
//! parsing an arbitrary query never panics — malformed headers, labels, lengths,
//! and compression pointers must be rejected, never crash the host stack thread.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dillo_virtio_net::fuzz_parse_dns_query(data);
});
