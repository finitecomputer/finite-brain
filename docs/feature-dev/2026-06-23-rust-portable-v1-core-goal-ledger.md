# Goal Ledger: Rust Portable v1 Core

## Run

- Run ID: `2026-06-23-rust-portable-v1-core`
- Loop: Feature Dev
- Target repo: `finitecomputer/finite-brain`
- Companion repo: `finitecomputer/finite-nostr`
- Base branch: `staging`
- Feature branch: `feature/rust-portable-v1-core`
- Human owner: Austin
- Started: 2026-06-23
- Current status: setup and alignment
- Skill setup status: `AGENTS.md` and `docs/agents/*` created for both repos

## Goal

Implement the FiniteBrain Portable v1 specification end to end in Rust, focused
on core logic, spec correctness, validation, tests, security hardening, and
production-shaped server behavior. Keep reusable Nostr primitive logic in the
new `finite-nostr` Rust crate so other Finite repos can reuse it.

## Durable Artifacts

- CONTEXT updates: pending grill-with-docs
- ADRs: `docs/adr/0001-adopt-rust-workspace-and-finite-nostr.md`,
  `docs/adr/0002-use-sqlite-from-day-one.md`,
  `docs/adr/0003-keep-folder-object-crypto-in-finite-brain-core.md`
- PRD issue: pending
- Slice issues: pending
- Issue sessions: pending
- Agent briefs: pending
- Review packets: pending
- Local CodeRabbit report: pending
- PR URL: pending

## Commands

- Install: `cargo fetch`
- Typecheck: `cargo check --all-targets`
- Test: `cargo test`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt --check`
- Build: `cargo build`
- Visual verification: local development-only Smoke UI served by the Rust app

## Slice Ledger

| Issue | Type | Status | Review thread | Fixes needed | Verified |
| --- | --- | --- | --- | --- | --- |
| pending | pending | pending | pending | pending | pending |

## Parked HITL Slices

| Issue | Why parked | Blocks | Required human action | Final PR decision |
| --- | --- | --- | --- | --- |
| None | | | | |

## Issue Session Ledger

| Issue | Fixed point | Worker session | Commit | Review result | Checks |
| --- | --- | --- | --- | --- | --- |
| pending | pending | pending | pending | pending | pending |

## Open Questions

- None.

## Escalations

- None.
