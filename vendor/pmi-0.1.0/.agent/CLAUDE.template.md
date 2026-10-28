# <repo>

<!-- Include ONLY what an agent can't discover from Cargo.toml, README,
     rust-toolchain.toml, ci.yml, or the code itself. Do NOT restate the
     purpose, stack, edition, dependencies, features, or build/test/lint
     commands — those live in their obvious places. ci.yml is the source of
     truth for how to check the repo. -->

## Crates

<Workspaces only: one line per member -> its role (roles aren't in Cargo.toml).
 Omit this section entirely for a single-crate repo.>

## Rules

<Repo-specific, non-discoverable only: interface contracts, invariants, boundaries
 (always / ask-first / never), and any non-obvious gotcha for running the gate
 (e.g. "boot tests need the patched cargo + KVM; see ci.yml"). Delete this
 placeholder; if there's nothing non-obvious, omit the section.>

<!-- Shared rules are in the .agent submodule. If .agent/ is empty:
     git submodule update --init --recursive -->
@.agent/karpathy/CLAUDE.md
@.agent/pichi.md
@.agent/rust.md
