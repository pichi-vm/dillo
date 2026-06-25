// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: the user-mode virtio-net DHCP request parser
//! (`dillo_virtio_net::fuzz_parse_dhcp`).
//!
//! Run with `cargo +nightly fuzz run dhcp_parse` from this crate.
//!
//! The guest controls the DHCP request bytes it broadcasts to the gateway DHCP
//! responder, so the parser runs on fully attacker-controlled input. This
//! asserts that parsing an arbitrary packet never panics — malformed BOOTP
//! headers, missing cookies, and truncated option TLVs must be rejected, never
//! crash the host stack thread.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dillo_virtio_net::fuzz_parse_dhcp(data);
});
