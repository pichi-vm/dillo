// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A parent keeps the transport; a confined child consumes its virtqueue.

mod child;
pub mod grant;
mod parent;
mod queue;
mod ring;

pub use child::{run, run_prepared};
pub use parent::{Control, DeviceInfo, Prepared, Proxy};
