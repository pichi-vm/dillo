# .agent

Shared Claude Code instructions for the [pichi-vm](https://github.com/pichi-vm)
repositories. This repo is the single source of truth; each project includes it
as a **git submodule** at `.agent/` and composes it with a repo-specific root
`CLAUDE.md`.

## Layout

- `pichi.md` — pichi-vm house rules (definition of done, boundaries, untrusted
  input). Imported by every repo.
- `rust.md` — Rust idioms not enforced by `cargo fmt`/`clippy`. Imported by Rust
  repos only.
- `karpathy/` — general LLM coding guidelines, a **submodule** of
  [multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills)
  (MIT). Repos import `karpathy/CLAUDE.md`.
- `CLAUDE.template.md` — starting point for a repo's root `CLAUDE.md`.

## Adopt in a repo

```sh
git submodule add https://github.com/pichi-vm/.agent .agent
git submodule update --init --recursive
```

Then create a root `CLAUDE.md` from `CLAUDE.template.md`, keeping the import
block at the end:

```
@.agent/karpathy/CLAUDE.md
@.agent/pichi.md
@.agent/rust.md        # omit in non-Rust repos
```

## Cloning a repo that uses it

```sh
git clone --recurse-submodules <repo>
# or, after a plain clone:
git submodule update --init --recursive
```

**Important:** without this, `.agent/` is empty and Claude's `@import` silently
loads nothing. This matters for anyone (human or agent) *working* in the repo —
not for CI: build/test/lint jobs don't read `.agent/`, so CI checkouts don't need
submodules unless a job specifically consumes the agent files.

## Updating

```sh
# in THIS repo — bump the vendored karpathy pin:
git submodule update --remote karpathy && git add karpathy && git commit

# in a consuming repo — bump the .agent pin:
git submodule update --remote .agent && git add .agent && git commit
```

## License

Our files (`pichi.md`, `rust.md`, `CLAUDE.template.md`) are Apache-2.0 — see
`LICENSE`. `karpathy/` retains its upstream MIT license.
