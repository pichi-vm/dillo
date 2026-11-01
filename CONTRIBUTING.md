# Contributing

## Cargo config

The checked-in `.cargo/config.toml` enables artifact dependencies, so a
fresh checkout builds with `cargo build`.

Tests cross-build a Linux guest probe and use the existing linker settings
in the packaging configuration:

```sh
cargo --config .copr/cargo-config.toml test --workspace
```

## Commit messages

Commits follow Conventional Commits and standard git formatting, enforced by
gitlint (see `.gitlint`) in CI.

- Subject: `type(scope): summary` — lowercase, imperative, no trailing period,
  at most 50 characters. Types: `feat`, `fix`, `docs`, `style`, `refactor`,
  `perf`, `test`, `build`, `ci`, `chore`, `revert`, `spec`.
- One blank line, then a body wrapped at 72 characters explaining what changed
  and why (not how — the diff shows how).
- Write each message to stand on its own: describe the change and its rationale
  for a reader with no knowledge of the project's history or how the work was
  produced. Do not reference internal process, prior iterations, or review
  back-and-forth. (gitlint cannot check this — it is a review responsibility.)

## COPR packages

The `npmccallum/pichi` COPR project builds `main` for Fedora on x86_64 and
aarch64. `.copr/Makefile` creates one source RPM; COPR builds the native
packages using the spec in `.copr/`. Binary builds need network access
for Cargo's locked dependencies. The unreleased RPM version is `0.1.0~dev`;
COPR's build ID in `Release` makes successive builds of that version upgrades.
