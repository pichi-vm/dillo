// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Virtio feature bit constants and device type identifiers.

/// Virtio 1.0+ modern device indicator (bit 32).
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Event index suppression for available/used rings (bit 29).
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;

/// Network device type.
pub const TYPE_NET: u32 = 1;

/// Block device type.
pub const TYPE_BLOCK: u32 = 2;

/// Console device type.
pub const TYPE_CONSOLE: u32 = 3;

/// Vsock device type.
pub const TYPE_VSOCK: u32 = 19;
