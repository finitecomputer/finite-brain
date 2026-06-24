# Goal Ledger: Rust v1 Product Parity

## Run

- Run ID: `2026-06-24-rust-v1-product-parity`
- Loop: Feature Dev
- Target repo: `finitecomputer/finite-brain`
- Base branch: `staging`
- Feature branch: `feature/rust-portable-v1-core`
- Human owner: Austin
- Started: 2026-06-24
- Current status: grilling with docs; graph/replay boundary resolved, OKF import execution pending
- Skill setup status: `AGENTS.md`, `CONTEXT.md`, and `docs/agents/*` already exist

## Goal

Get the remaining FiniteBrain v1 parity work done end to end on the Rust
implementation, with no backwards compatibility or legacy migration bridge.
This is a hard-cut continuation from the Rust Portable v1 core PR.

## Durable Artifacts

- CONTEXT updates: root `CONTEXT.md` now distinguishes `Product Client`,
  `Product Client Spine`, `Graph View`, `Graph Replay`, `Smoke UI`, and
  `Hard Cut`.
- ADRs: `docs/adr/0004-build-a-first-party-product-client.md`,
  `docs/adr/0005-derive-graph-and-replay-from-client-decrypted-indexes.md`
- PRD issue: pending.
- Slice issues: pending.
- Issue sessions: pending.
- Agent briefs: pending.
- Review packets: pending.
- Local CodeRabbit report: pending.
- PR URL: existing staging PR is `https://github.com/finitecomputer/finite-brain/pull/15`.

## Commands

- Install: `cargo fetch`
- Typecheck: `cargo check --all-targets`
- Test: `cargo test`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt --check`
- Build: `cargo build`
- Local app: `cargo run -p finite-brain-app`

## Scope

In scope:

- Product Client: a real trusted browser client, not the development Smoke UI.
- Product Client Spine: connect NIP-07 signer, load a Vault, open Folder Key
  Grants, decrypt/read accessible Pages, edit one Page, encrypt/write a signed
  revision, and pull/apply sync without discarding unresolved local edits.
- NIP-07 workflow: signer discovery, auth signing, NIP-44 encrypt/decrypt,
  Folder Key Grant opening, and session keyring behavior.
- Graph View and replay: local decrypted graph/search indexes plus an
  Obsidian-like graph and replay-capable projection.
- OKF import execution: client-side conflict planning, encryption, and upload.
- Agent working tree materialization: accessible decrypted content on disk with
  agent discovery rules and encrypted-sync boundaries.
- Production hardening: replay cache, rate limits, CORS allowlist, and
  deploy/runbook readiness that can be proven without production changes.

Out of scope:

- Backwards compatibility shims.
- Legacy route compatibility.
- Turnkey migration from old v1 storage/client runtime.
- Production deployment, production migrations, production config changes, or
  live data operations.

## Slice Ledger

| Issue | Type | Status | Review thread | Fixes needed | Verified |
| --- | --- | --- | --- | --- | --- |
| Pending | | | | | |

## Parked HITL Slices

| Issue | Why parked | Blocks | Required human action | Final PR decision |
| --- | --- | --- | --- | --- |
| None yet | | | | |

## Issue Session Ledger

| Issue | Fixed point | Worker session | Commit | Review result | Checks |
| --- | --- | --- | --- | --- | --- |
| Pending | | | | | |

## Resolved Decisions

- The Product Client is a first-party browser app served by the Rust app/server,
  not a SilverBullet compatibility surface. See
  `docs/adr/0004-build-a-first-party-product-client.md`.
- The minimum Product Client Spine must land before graph/replay, OKF import
  execution, and agent working-tree materialization build on top.
- Graph View and Graph Replay are derived from the Product Client's decrypted
  local Page index and applied sync history. The server remains sync/object
  metadata aware, not graph aware. See
  `docs/adr/0005-derive-graph-and-replay-from-client-decrypted-indexes.md`.

## Open Questions

- Should OKF import execution be entirely Product Client owned, or should the
  Rust server provide an import endpoint that accepts an OKF bundle and performs
  server-side encryption/upload work?

## Escalations

- None.
