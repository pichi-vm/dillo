// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Negative tests for the overlay phandle pipeline. dtc auto-assigns
//! phandles starting from 1 and won't emit a base near u32::MAX, so
//! these tests construct the boundary blobs directly.
//!
//! Under the new contract, reserved-phandle values (0, u32::MAX) on
//! `phandle`/`linux,phandle` properties in the base are caught at
//! `Tree::parse` time, not at overlay-apply time.

use devtree::{Error, Overlay, OverlayView, Tree};

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_END: u32 = 0x9;
const HEADER: usize = 40;

pub(crate) struct DtbBuilder {
    structs: Vec<u8>,
    strings: Vec<u8>,
}

impl DtbBuilder {
    pub(crate) fn new() -> Self {
        Self {
            structs: Vec::new(),
            strings: Vec::new(),
        }
    }

    pub(crate) fn intern(&mut self, name: &str) -> u32 {
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        off
    }

    pub(crate) fn begin_node(&mut self, name: &str) -> &mut Self {
        self.structs
            .extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        self.structs.extend_from_slice(name.as_bytes());
        self.structs.push(0);
        while !self.structs.len().is_multiple_of(4) {
            self.structs.push(0);
        }
        self
    }

    pub(crate) fn end_node(&mut self) -> &mut Self {
        self.structs.extend_from_slice(&FDT_END_NODE.to_be_bytes());
        self
    }

    pub(crate) fn property(&mut self, name: &str, value: &[u8]) -> &mut Self {
        let off = self.intern(name);
        self.structs.extend_from_slice(&FDT_PROP.to_be_bytes());
        self.structs
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.structs.extend_from_slice(&off.to_be_bytes());
        self.structs.extend_from_slice(value);
        while !self.structs.len().is_multiple_of(4) {
            self.structs.push(0);
        }
        self
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.structs.extend_from_slice(&FDT_END.to_be_bytes());

        let memrsv_off = HEADER as u32;
        let memrsv_size: u32 = 16;
        let struct_off = memrsv_off + memrsv_size;
        let struct_size = self.structs.len() as u32;
        let strings_off = struct_off + struct_size;
        let strings_size = self.strings.len() as u32;
        let totalsize = strings_off + strings_size;

        let mut blob = Vec::with_capacity(totalsize as usize);
        blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        blob.extend_from_slice(&totalsize.to_be_bytes());
        blob.extend_from_slice(&struct_off.to_be_bytes());
        blob.extend_from_slice(&strings_off.to_be_bytes());
        blob.extend_from_slice(&memrsv_off.to_be_bytes());
        blob.extend_from_slice(&17u32.to_be_bytes());
        blob.extend_from_slice(&16u32.to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes());
        blob.extend_from_slice(&strings_size.to_be_bytes());
        blob.extend_from_slice(&struct_size.to_be_bytes());
        blob.extend_from_slice(&[0u8; 16]);
        blob.extend_from_slice(&self.structs);
        blob.extend_from_slice(&self.strings);
        blob
    }
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn base_with_target_phandle(ph: u32) -> Vec<u8> {
    let mut b = DtbBuilder::new();
    b.begin_node("")
        .begin_node("target")
        .property("phandle", &ph.to_be_bytes())
        .end_node()
        .end_node();
    b.finish()
}

fn overlay_with_phandle(overlay_ph: u32) -> Vec<u8> {
    let mut b = DtbBuilder::new();
    b.begin_node("")
        .begin_node("fragment@0")
        .property("target-path", &cstr("/target"))
        .begin_node("__overlay__")
        .property("phandle", &overlay_ph.to_be_bytes())
        .end_node()
        .end_node()
        .end_node();
    b.finish()
}

#[test]
fn base_phandle_zero_rejected_at_parse() {
    let base_blob = base_with_target_phandle(0);
    let result: Result<Tree, _> = Tree::parse(&base_blob);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

#[test]
fn base_phandle_max_rejected_at_parse() {
    let base_blob = base_with_target_phandle(u32::MAX);
    let result: Result<Tree, _> = Tree::parse(&base_blob);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

#[test]
fn overlay_phandle_shift_overflows() {
    // base max phandle = u32::MAX - 1 → shift = u32::MAX → any nonzero
    // overlay phandle overflows when shifted.
    let base_blob = base_with_target_phandle(u32::MAX - 1);
    let base: Tree = Tree::parse(&base_blob).expect("base parses");
    let overlay_blob = overlay_with_phandle(1);
    let overlay: Overlay = Overlay::parse(&overlay_blob).expect("overlay parses");
    // The shift itself (max+1=u32::MAX) computes; apply attempts to
    // add overlay phandle 1 to u32::MAX and overflows during the
    // single-pass merge walk.
    let needed = match overlay.apply(&base, &mut []) {
        Err(Error::BufferTooSmall { needed }) => needed,
        other => panic!("size probe: {other:?}"),
    };
    let mut buf = vec![0u8; needed];
    let result = overlay.apply(&base, &mut buf);
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "got {:?}",
        result
    );
}
