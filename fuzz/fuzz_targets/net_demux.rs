// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: the user-mode virtio-net guest-frame demux/provisioning
//! decision path (`dillo_virtio_net::fuzz_inspect_frame`).
//!
//! Run with `cargo +nightly fuzz run net_demux` from this crate.
//!
//! Guest frames are fully attacker-controlled (the guest writes them onto the TX
//! virtqueue). This asserts that inspecting an arbitrary frame to decide whether
//! it opens a new flow never panics — malformed Ethernet/IPv4/TCP/UDP must be
//! dropped, never crash the host stack thread.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dillo_virtio_net::fuzz_inspect_frame(data);
});
