# Contributing

## Cargo config

`.cargo/config.toml` is committed, so a plain `cargo build` or `cargo test`
works from a fresh clone with no extra setup. It is the settings file that
Cargo, the Rust build tool, reads. It lets the tests build helper programs
such as the snuffler guest probe, and sets how that probe is linked.
`rust-toolchain.toml` names the exact Rust version to use, and rustup, the
usual Rust installer, picks it up on its own.

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
