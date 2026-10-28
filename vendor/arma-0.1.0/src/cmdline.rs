// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `arma cmdline <dtb> [cmdline]` — read or rewrite the kernel command line
//! (`/chosen/bootargs`) in a DTB file.
//!
//! `bootargs` is the one DTB property fully decoupled from guest-physical
//! placement: editing it disturbs nothing else (not the device map, not the
//! initrd extent), so it is safe to change after a build. This is aimed at the
//! detached base DTB, which ships as a standalone file the VMM delivers
//! out-of-band — letting an operator retune the command line without rebuilding
//! the PMI.

use std::path::Path;

use anyhow::{Context, Result};
use devtree::{NodeView, OwnedNode, OwnedProperty, OwnedTree, PropertyView, Tree, TreeView};

use crate::fs_ext::AtomicWrite;

/// Read (`cmdline` = `None`) or rewrite (`Some`) `/chosen/bootargs` in the DTB
/// at `path`. Reads print the current command line; writes replace it verbatim
/// and rewrite the file in place.
pub(crate) fn run(path: &Path, cmdline: Option<&str>) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read DTB: {}", path.display()))?;
    match cmdline {
        None => {
            println!("{}", read_bootargs(&bytes)?);
            Ok(())
        }
        Some(new) => write_bootargs(path, &bytes, new),
    }
}

/// The current `/chosen/bootargs` string, or empty if the DTB declares none.
fn read_bootargs(bytes: &[u8]) -> Result<String> {
    let tree: Tree<'_> = Tree::parse(bytes).context("parse DTB")?;
    // `as_str` borrows the property, so bind it in the arm and own the string
    // before the borrow ends rather than returning it from a closure.
    let args = match tree
        .find_path("/chosen")
        .and_then(|c| c.property("bootargs"))
    {
        Some(prop) => prop.as_str().unwrap_or("").to_owned(),
        None => String::new(),
    };
    Ok(args)
}

/// Rewrite `/chosen/bootargs` to `new` and write the DTB back in place. The
/// whole tree is round-tripped through [`OwnedTree`] (which preserves the
/// memory-reservation block, phandles, and every other node), so only
/// `bootargs` changes; `/chosen` is created if absent.
fn write_bootargs(path: &Path, bytes: &[u8], new: &str) -> Result<()> {
    let tree: Tree<'_> = Tree::parse(bytes).context("parse DTB")?;
    let mut owned = OwnedTree::materialize(&tree);

    let root = owned.root_mut();
    if root.child_mut("chosen").is_none() {
        root.set_child(OwnedNode::new("chosen"));
    }
    let chosen = root
        .child_mut("chosen")
        .expect("chosen present (created above if it was missing)");
    chosen.set_property(OwnedProperty::new("bootargs").with_str(new));

    let out = owned.encode().context("re-encode DTB")?;
    path.atomic_write(&out)
}
