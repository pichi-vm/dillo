# arma

The PMI producer for pichi-vm. `arma build` turns a kernel (+ optional initrd
and cmdline) into a [Portable Machine Image](https://github.com/pichi-vm/pmi):
a single PE carrying the base platform devicetree, the `tatu` boot stub as
firmware, and the kernel — booted by a PMI VMM such as dillo.

This repository bundles `tatu` (the guest-side PMI boot stub, built bare-metal
and embedded as an artifact) and its `dtb2acpi` / `dtb2e820` helpers.

## Selected kernel modules

When `--initrd` is a static ELF (for example Corium), repeat `--module NAME`
to include named modules and their hard dependencies in the generated archive.
Arma detects the target kernel's release and discovers its installed module tree;
`--module-tree PATH` overrides the source with a release-specific directory.
See [module packaging](docs/module-packaging.md) for the interface, validation,
limitations, and acceptance criteria.

## License

Apache-2.0 — see [LICENSE](LICENSE).
