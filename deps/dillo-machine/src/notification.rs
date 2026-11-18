// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Backend-owned guest-write notification counters.

/// Backend-owned blocking counter for an accelerated device notification.
/// The final owner releases the associated guest-write registration.
pub trait WriteNotification: Send + Sync + std::fmt::Debug {
    fn read(&self) -> std::io::Result<u64>;

    fn write(&self, count: u64) -> std::io::Result<()>;
}
