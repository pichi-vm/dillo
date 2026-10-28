# Contributing

## Cargo config

`.cargo/config.toml` is not committed. Copy the developer config before
building or testing:

```
mkdir -p .cargo
cp packaging/cargo-config.toml .cargo/config.toml
```

That file enables artifact dependencies (`-Z bindeps`), sets the musl
rustflags used to cross-build the snuffler guest probe, and raises
smoltcp's interface address cap.

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
