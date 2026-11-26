// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native primitives shared by the two Unix Machine families.

#![cfg(unix)]

mod channel;
mod memory;
pub mod vhost_user;

pub use channel::{bootstrap, spawn};
#[cfg(target_os = "macos")]
pub use memory::allocate_memory;
pub use memory::{export_memory, map_memory};
