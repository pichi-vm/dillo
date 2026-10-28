# devtree

## Rules

- Keep the default build pure `no_std`: new allocation goes behind the
  default-off `alloc` feature so bare-metal consumers (e.g. tatu) aren't forced
  to pull in `alloc`.
- Regenerate `tests/data/*.dtb{,o}` from the `*.dts{,o}` sources with
  `tests/data/regenerate.sh` (needs `dtc`); never hand-edit the binaries.

<!-- Shared rules are in the .agent submodule. If .agent/ is empty:
     git submodule update --init --recursive -->
@.agent/karpathy/CLAUDE.md
@.agent/pichi.md
@.agent/rust.md
