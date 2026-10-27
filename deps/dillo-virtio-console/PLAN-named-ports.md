# Consensus implementation plan — named virtio-console MULTIPORT

**Status:** consensus of Dillo + Claude Opus + Codex drafts  
**Design authority:** `deps/dillo-virtio-console/DESIGN-named-ports.md` (PR #24 @ a83471a)  
**Inputs:** `/tmp/dillo-console-ports/plans/{dillo,claude,codex}.md`  
**Implementer (step 3):** Claude Opus on Apollo under `~/Projects/pichi-vm/dillo`  
**Reviewers (step 4):** Codex + Dillo before any merge ask  
**Merge:** never without Nathaniel’s explicit yes via Lead  

This document settles divergences among the three drafts. Where drafts agree with the design, they are not re-litigated. Claude’s draft is the most tree-specific; this consensus keeps that specificity and locks the contested calls below.

---

## Settled decisions (were open / disagreed)

| # | Topic | Consensus |
|---|--------|-----------|
| S1 | `ConsoleSpec.endpoint` type | **`Option<String>`**. Empty/omitted `ports` ⇒ default `stdio` (incl. `--console bus=mmio`). Non-empty `ports` ⇒ endpoint key **must be present** and equal `stdio`. Bare `--console stdio` keeps working via the existing argh shim. |
| S2 | Both `rx` and `tx` omitted | **Reject** at `resolve()` — at least one of `rx` / `tx` required. Uni-directional (exactly one set) remains OK; omit still means that direction closed. No name-only ports. |
| S3 | Duplicate `pipe:N` across ports/directions | **Reject** at `resolve()` (one N → one direction on one port). |
| S4 | Queue map (MULTIPORT) | **0/1** port0 RX/TX; **2/3** control RX/TX; named port *i* (id = i, i≥1) at **2i+2 / 2i+3**. `max_nr_ports = 1+N`. |
| S5 | Port 0 under MULTIPORT | Port 0 stays **unnamed** (no `PORT_NAME`). Once MULTIPORT is negotiated, Linux only creates ports from control messages — so port 0 **must** still get `PORT_ADD(id=0)` + `CONSOLE_PORT(id=0,1)` + `PORT_OPEN(id=0)` (minus `PORT_NAME`). Named ports: `PORT_ADD` + `PORT_NAME` + `PORT_OPEN` (+ READY as required). |
| S6 | Who creates pipes | **Parent only.** dillo adopts inherited FD/handle `N`. Never creates anonymous pipes, named FIFOs, or alternate schemes. |
| S7 | `pipe:N` type width | Parse to **`u64`** (Windows HANDLE-sized). Unix narrows to `RawFd` at adopt time. |
| S8 | stdio FDs as port backends | **Reject `pipe:0/1/2`** for named-port rx/tx (reserve process stdio). |
| S9 | Cap | **`MAX_CONSOLE_PORTS = 31`** named entries (⇒ ≤66 queues / ≤67 MSI-X) — document arithmetic next to the constant. |
| S10 | MSI-X vector count in `build_placements` | Replace hardcoded `3` with **`num_queues + 1`** (or equivalent from the constructed device). |
| S11 | Host cfg lint | Use **`cfg(unix)` / `cfg(windows)` only** in `dillo-virtio-console` (portable-core crate rules). |
| S12 | RX shutdown | Unix: **`O_NONBLOCK` + existing poll cadence**. Windows: bounded/non-blocking read strategy in the Windows arm (no hang on join). |
| S13 | First-PR e2e | **Linux + Windows guest e2e** for named-port discovery, port0 stdio, and process inheritance (`pipe:N` FD/HANDLE). macOS: compile + unit (Unix inherit path covered by Linux). |
| S14 | FD liveness check | Grammar/uniqueness in `resolve()`; **adopt/open** (and fail naming port+direction) in `build_placements` **before** raw-terminal mode. |
| S15 | Branch / PR | `bot/dillo/feat-virtio-console-named-ports`, stacked on design tip (or main after #24 merges). One impl PR; **do not merge** until Nathaniel yes. House prefix `bot/dillo/…` (not `feat/…` alone). |
| S16 | Control sequence (ordering floor) | Wait for guest **`DEVICE_READY`** on the control path **before** any `PORT_ADD`. Per port: `PORT_ADD` → (`PORT_NAME` if named) → `PORT_OPEN` (+ READY handling as Linux requires). Unit-test this state machine; e2e confirms. `PORT_NAME` payload = control header + name bytes + **NUL**. Bound/validate names at config time (≤255, no NUL). |
| S17 | Pipe EOF / EPIPE | Direction teardown is **non-fatal** to the VM: EOF/EPIPE on a named-port pipe stops that direction's worker cleanly (no spin, no process abort); other ports and port 0 continue. |
| S18 | `O_NONBLOCK` + dup | After adopting, **dup** (or equivalent) into an owned FD/handle and apply `O_NONBLOCK` only on the owned copy so the flag does not leak to the caller's open file description; close/drop the original adopted number once owned. |

---

## Scope / non-goals

**In:** schema+CLI/JSON parity; MULTIPORT device + control plane; inherited `pipe:N`; port-0 stdio unchanged when ports absent **and** when ports present; focused unit + Linux/Windows e2e; CI green on pinned nightly.

**Out:** DTB/cmdline ports; second console device / new virtio ID; `--console-port` / follow-on `--console port,…` / loose `port=` / console in `devices[]`; non-`stdio` port-0 endpoints; named FIFOs; wiring host stdin into today’s inert port-0 RX (separate change).

---

## Work packages (ordered)

### WP1 — `dillo-config`
- `PipeRef` / parse `pipe:N` → `u64`; `ConsolePortSpec { name, rx, tx }`; `ports: Vec<_>` on `ConsoleSpec`.
- Nested `ports=[[…]]` like gpt partitions; `deny_unknown_fields`.
- `endpoint: Option<String>` + resolve rules S1–S3, S8–S9; carry ports on `ResolvedConsole`.
- Unit tests for locked CLI/JSON example and validation table (Claude V1–V15 as checklist; S2/S3/S8 mandatory).

### WP2 — Host pipe adopt (`dillo-virtio-console`)
- Small `pipe`/host module: adopt inherited Unix FD / Windows HANDLE; direction-appropriate read/write; clear errors naming port+direction.
- Duplicate-into-owned so parent FD table semantics stay sane; never create pipes.

### WP3 — MULTIPORT device
- Constructor takes resolved named ports (+ adopted ends or adopt inside builder).
- Features: VERSION_1 only when no ports; add `VIRTIO_CONSOLE_F_MULTIPORT` when non-empty.
- Queues/config per S4–S5; control worker + state machine per S16.
- Port-0 workers = today’s stdio path; named-port workers only for open directions (closed half ⇒ no worker). Both-omitted ports never reach the device (rejected in resolve, S2).
- Aggregate shutdown/join (S12).

### WP4 — `main` / runner
- Pass config into console construction in `build_placements`; MSI-X/vectors per S10.
- Adopt pipes before raw terminal (S14).
- Update `--console` help text.
- No DTB changes.

### WP5 — Tests & CI
- Config + device unit tests (features, queue count, `max_nr_ports`, control codec, closed directions, shutdown).
- Linux + Windows `vm-tests` e2e for named port visibility, hvc0, and process inheritance (S13).
- Bar: `.github/workflows` on `nightly-2026-07-06` (fmt, clippy `-D warnings`, workspace tests, matrix exclusions as today).

### WP6 — PR hygiene
- Branch S15; commits preferably: (1) config+tests (2) device+pipes+units (3) runner wire-up (4) Linux e2e/docs.
- PR cites design doc + this consensus; **Do not merge until Nathaniel says go.**
- Early schema stash on feat branch may be reused only if it matches this consensus; otherwise rewrite cleanly.

---

## Risks (accepted)

1. Control-plane ordering vs Linux — mitigate with S16 + unit/e2e.  
2. Windows HANDLE inheritance e2e — covered by `boots_with_named_console_ports` on windows-2025 (S13).  
3. Blocking pipe read vs run-token — mitigate with S12.  
4. Large `ports=` — mitigate with S9.  
5. Reviewer confusion that named-port RX “fixes” port-0 stdin — call out in PR; leave port-0 RX inert.

---

## Explicitly deferred (not blockers)

- macOS-specific named-port inheritance e2e (Unix path covered by Linux).  
- Non-stdio port-0 endpoints.  
- Host-stdin → hvc0 RX wiring.  
- Reserving or special-casing the name `dev.pichi.build` (free-form; consumer convention only).

---

## Done when

Local/CI green per WP5; feat PR open citing design + this consensus; Dillo+Codex internal review complete; still **no merge** until Nathaniel yes via Lead.

## Non-prescription

External schema (`ports`, `name`, `rx`, `tx`, `pipe:N`, polarity, DT-006) is locked by the design. Internal type/module names may vary if behavior matches this consensus.


---

## ACK ledger

- **Codex:** `ACK_CONSENSUS` (2026-10-26)
- **Claude Opus:** `DISSENT` then accepted via incorporation of five impl fixes into S5/S16/S17/S18 (port-0 `PORT_ADD` under MULTIPORT; DEVICE_READY floor; NUL `PORT_NAME`; EOF/EPIPE teardown; O_NONBLOCK on dup'd owned FD only)
- **Dillo:** accepts this document as the consensus plan for step 3


---

## Amendment (Nathaniel, Oct 26)

ConsolePortSpec validation: reject when both `rx` and `tx` are omitted; at least one
direction required. Uni-directional ports remain valid. Design + this plan updated;
implementers must enforce in `dillo_config::resolve` (not only docs).
