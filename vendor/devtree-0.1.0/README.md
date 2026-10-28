# devtree

Zero-copy, `no_std`, `forbid(unsafe_code)` parser, writer, and overlay applier
for Flattened Devicetree (FDT v17) blobs.

Built to be resilient against adversarial input: every walk over untrusted
bytes is bounded, `Tree::parse` does full structural validation in one pass (so
later walks are infallible), and the overlay applier validates phandle math
against reserved values before observing or emitting them.

The `alloc` feature adds an owned, drainable representation atop the zero-copy
parser; it is off by default so bare-metal consumers stay pure `no_std`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
