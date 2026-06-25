// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Bridge backend: put the guest on the host's real L2 segment.
//!
//! One CLI (`--net backend=bridge,iface=<name>`), per-OS implementations behind
//! a cfg-selected concrete type:
//!
//! - **Linux** ([`linux`]): create a tap and enslave it to the named bridge.
//! - **macOS** ([`macos`]): `vmnet` bridged mode on the named physical interface.
//! - **Windows**: unsupported (a clean error, surfaced by `main.rs`).
//!
//! All variants need privilege (`CAP_NET_ADMIN` / root); failures surface
//! cleanly rather than panicking.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::BridgeBackend;
#[cfg(target_os = "macos")]
pub use macos::VmnetBackend;
