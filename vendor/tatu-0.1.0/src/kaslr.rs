// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! arm64 KASLR seed: a trusted overlay tatu merges onto the measured base DTB.
//!
//! `kaslr-seed` is guest-generated entropy, so it MUST NOT live in the measured
//! base DTB (it would make the launch measurement non-deterministic). Instead
//! tatu carries a tiny pre-serialized overlay — [`KASLR_OVERLAY_TEMPLATE`],
//! compiled from `kaslr_overlay.dts` with `dtc` and committed alongside it —
//! whose `/chosen/kaslr-seed` value is the unique sentinel [`SEED_SENTINEL`].
//! At boot tatu overwrites the sentinel with guest entropy via a plain byte
//! find/replace ([`patch_overlay_seed`]) — no DTB parsing — and merges the
//! overlay onto the base *before* the host overlay, so a `CONFIG_RANDOMIZE_BASE`
//! kernel reads a fresh, guest-controlled seed from the final merged DTB.
//!
//! The entropy source (guest `RNDR`) and the two-merge orchestration live in
//! `arch_aarch64`; the byte substitution lives here as a pure function so it can
//! be unit-tested on the host without a guest.

/// Pre-serialized kaslr-seed overlay (see `kaslr_overlay.dts`). Adds
/// `/chosen/kaslr-seed` via a `target-path` fragment; the seed is the
/// [`SEED_SENTINEL`] placeholder, patched at boot. Regenerate after editing the
/// `.dts`: `dtc -I dts -O dtb -o kaslr_overlay.dtbo kaslr_overlay.dts`.
pub(crate) const KASLR_OVERLAY_TEMPLATE: &[u8] = include_bytes!("kaslr_overlay.dtbo");

/// The 8-byte placeholder occupying the template's `kaslr-seed` value (ASCII
/// `"KASLRSED"` = `<0x4b41534c 0x52534544>` in the `.dts`). Chosen to be unique
/// within the blob so a byte find/replace hits exactly the seed and nothing
/// else; the DTB's structure block, strings, and offsets are untouched, so the
/// patched blob stays a valid overlay for the merge.
pub(crate) const SEED_SENTINEL: [u8; 8] = *b"KASLRSED";

/// Overwrite the 8-byte [`SEED_SENTINEL`] in `blob` with `seed` (big-endian, the
/// FDT property byte order). Returns `false` and leaves `blob` unchanged if the
/// sentinel is absent. Pure byte find/replace — no DTB parsing.
pub(crate) fn patch_overlay_seed(blob: &mut [u8], seed: u64) -> bool {
    let Some(pos) = blob
        .windows(SEED_SENTINEL.len())
        .position(|w| w == SEED_SENTINEL)
    else {
        return false;
    };
    blob[pos..pos + 8].copy_from_slice(&seed.to_be_bytes());
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use devtree::{NodeView, Overlay, OverlayView, PropertyView, Tree, TreeView};

    /// A base DTB shaped like arma's post-redesign output: /chosen with bootargs
    /// and NO kaslr-seed (the seed now comes from the overlay).
    const BASE_NO_SEED: &str = r#"/dts-v1/;
/ { #address-cells = <2>; #size-cells = <2>;
    chosen { bootargs = "console=ttyAMA0"; }; };"#;

    fn dtc_compile(dts: &str) -> Option<Vec<u8>> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("dtc")
            .args(["-I", "dts", "-O", "dtb"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(dts.as_bytes()).ok()?;
        let out = child.wait_with_output().ok()?;
        out.status.success().then_some(out.stdout)
    }

    fn count(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count()
    }

    #[test]
    fn template_has_exactly_one_sentinel() {
        // Uniqueness is what makes the byte find/replace safe.
        assert_eq!(count(KASLR_OVERLAY_TEMPLATE, &SEED_SENTINEL), 1);
    }

    #[test]
    fn patch_replaces_sentinel_with_seed_and_stays_parseable() {
        let mut blob = KASLR_OVERLAY_TEMPLATE.to_vec();
        let len_before = blob.len();
        let seed = 0x0123_4567_89AB_CDEF;
        assert!(patch_overlay_seed(&mut blob, seed));
        // Same length; sentinel gone; the seed bytes are present exactly once.
        assert_eq!(blob.len(), len_before);
        assert_eq!(count(&blob, &SEED_SENTINEL), 0);
        assert_eq!(count(&blob, &seed.to_be_bytes()), 1);
        // Still a structurally valid overlay for the merge.
        let reparsed: Result<Overlay<'_>, _> = Overlay::parse(&blob);
        assert!(reparsed.is_ok(), "patched blob still parses");
    }

    #[test]
    fn missing_sentinel_is_a_noop() {
        let mut blob = b"no sentinel here, just bytes".to_vec();
        let before = blob.clone();
        assert!(!patch_overlay_seed(&mut blob, 0xDEAD_BEEF));
        assert_eq!(blob, before, "absent sentinel leaves the blob unchanged");
    }

    /// End-to-end of the first merge: patch the committed template, merge it onto
    /// a seed-free base, and confirm the result carries the patched
    /// `/chosen/kaslr-seed` while the base's own /chosen content survives.
    #[test]
    fn merges_patched_seed_onto_base() {
        let Some(base_blob) = dtc_compile(BASE_NO_SEED) else {
            eprintln!("skipping: dtc not available");
            return;
        };
        let base: Tree<'_> = Tree::parse(&base_blob).unwrap();

        let mut tpl = KASLR_OVERLAY_TEMPLATE.to_vec();
        let seed = 0xCAFE_F00D_1234_5678;
        assert!(patch_overlay_seed(&mut tpl, seed));
        let overlay: Overlay<'_> = Overlay::parse(&tpl).unwrap();

        let mut out = [0u8; 16 * 1024];
        let n = overlay.apply(&base, &mut out).expect("merge ok");
        let merged: Tree<'_> = Tree::parse(&out[..n]).unwrap();

        let chosen = merged.find_path("/chosen").expect("/chosen present");
        let p = chosen.property("kaslr-seed").expect("seed merged in");
        assert_eq!(u64::from_be_bytes(p.as_ref().try_into().unwrap()), seed);
        // Base content preserved through the merge.
        assert_eq!(
            chosen.property("bootargs").unwrap().as_str().unwrap(),
            "console=ttyAMA0"
        );
    }
}
