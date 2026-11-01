# Contributing

## Cargo config

`.cargo/config.toml` supplies the settings for `cargo build`. It enables
artifact dependencies (helper programs built for another build step) and
links the Linux guest probe as a static executable.

The test suite uses the packaging configuration for its network settings:

```sh
cargo --config packaging/cargo-config.toml test --workspace
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
