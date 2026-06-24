# Goal Ledger: Rust v1 Product Parity

## Run

- Run ID: `2026-06-24-rust-v1-product-parity`
- Loop: Feature Dev
- Target repo: `finitecomputer/finite-brain`
- Base branch: `staging`
- Feature branch: `feature/rust-portable-v1-core`
- Human owner: Austin
- Started: 2026-06-24
- Current status: grilling with docs; first product-client boundary decision pending
- Skill setup status: `AGENTS.md`, `CONTEXT.md`, and `docs/agents/*` already exist

## Goal

Get the remaining FiniteBrain v1 parity work done end to end on the Rust
implementation, with no backwards compatibility or legacy migration bridge.
This is a hard-cut continuation from the Rust Portable v1 core PR.

## Durable Artifacts

- CONTEXT updates: root `CONTEXT.md` now distinguishes `Product Client`,
  `Smoke UI`, and `Hard Cut`.
- ADRs: pending only if a hard-to-reverse trade-off appears.
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

## Open Questions

- Should the first Rust Product Client be a first-party browser app served by
  the Rust server, replacing the Smoke UI as the primary local workflow, or
  should it reuse/embed a SilverBullet-style editor surface?

## Escalations

- None.
