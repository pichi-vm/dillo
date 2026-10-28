// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Display coverage for the public error surface. The Display impl
//! flows into operator-visible log/panic messages downstream of
//! `dillo`/`tatu`, so a write! formatting bug or stale arm after a
//! `#[non_exhaustive]` addition would only surface in production
//! without this test.
//!
//! `Error::Malformed`'s inner kind is crate-private; per-kind Display
//! coverage lives in `src/error.rs` unit tests.

use devtree::{Error, Limit};

fn render(e: Error) -> String {
    format!("{e}")
}

#[test]
fn every_limit_variant_renders_nonempty() {
    let variants: &[Limit] = &[
        Limit::Depth,
        Limit::Reservations,
        Limit::Fragments,
        Limit::Rewrites,
        Limit::Layers,
    ];
    for e in variants {
        let s = render(Error::LimitExceeded(*e));
        assert!(!s.is_empty(), "{e:?} -> empty Display");
        assert!(s.starts_with("limit exceeded:"), "{s:?}");
    }
}

#[test]
fn buffer_too_small_renders_nonempty() {
    let s = render(Error::BufferTooSmall { needed: 0 });
    assert!(!s.is_empty());
    assert!(s.starts_with("destination buffer"), "{s:?}");
}

#[test]
fn buffer_too_small_includes_needed_byte_count() {
    let s = render(Error::BufferTooSmall { needed: 7 });
    assert!(s.contains('7'), "expected '7' in {s:?}");
}

#[test]
fn error_implements_core_error() {
    fn accept(_: &dyn core::error::Error) {}
    accept(&Error::BufferTooSmall { needed: 0 });
}
