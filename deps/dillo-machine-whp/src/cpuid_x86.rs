// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `cpu:profile` → host CPUID validation for x86_64 (WHP).
//!
//! Policy lives in [`dillo_machine::cpuid_x86`]. WHP has no
//! `GET_SUPPORTED_CPUID` equivalent, so it only needs the native
//! host check. Dead KVM/`kvm_bindings` residue is not re-exported.

pub(crate) use dillo_machine::cpuid_x86::{X86Level, first_missing_native};
