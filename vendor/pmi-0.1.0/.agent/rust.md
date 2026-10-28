# Rust idioms

Conventions `cargo fmt` and `clippy` don't enforce. When you edit a file that
breaks one, bring it into line.

- **Methods over free functions.** A free function is almost always wrong without
  a reason; use an extension trait when you don't own the type.
- **Reach for std/core traits first.** `From`/`TryFrom` for conversions, `AsRef`
  for cheap views, `Iterator` for sequences — before writing a bespoke method.
- **Encode logic in types.** A good Rust program is mostly transitions across
  types, not a pile of function logic.
- **Errors mirror caller branches.** A variant exists when a caller would act
  differently. Group and nest (`enum E { Malformed(M), Io(I) }`) when the outer
  is the branch point and the inner carries the specific kind for context.
- **Typed wire layouts.** `#[repr(C[, packed])]` / `#[repr(uN)]` at binary
  boundaries so the type *is* the format; pin offsets with
  `const _: () = assert!(...)`.
- **Minimal public API.** `pub` only what callers use. Public fields when the
  shape is known (wire layouts) or types enforce validity (enums) — don't
  reflexively encapsulate.
- **Write it twice.** A complete first pass is context for a better second pass;
  don't ship the first.
- **Documented enum variants get a blank line above** (except the first).
