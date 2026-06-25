// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: the user-mode virtio-net Router Solicitation parser
//! (`dillo_virtio_net::fuzz_parse_router_solicit`).
//!
//! Run with `cargo +nightly fuzz run ndp_parse` from this crate.
//!
//! The guest controls the ICMPv6 frames it emits, so the RS detector runs on
//! fully attacker-controlled input. This asserts that parsing an arbitrary frame
//! never panics — malformed Ethernet/IPv6/ICMPv6/NDP must be rejected, never
//! crash the host stack thread.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dillo_virtio_net::fuzz_parse_router_solicit(data);
});
