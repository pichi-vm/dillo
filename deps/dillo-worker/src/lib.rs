// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A parent keeps the transport; a confined child consumes its virtqueue.

mod child;
mod parent;
mod pause;
mod queue;

pub use child::run;
pub use parent::{Control, DeviceInfo, Prepared, Proxy};
