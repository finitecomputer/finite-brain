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
- Current status: implementing slices
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
- PRD issue: `finitecomputer/finite-brain#1`
- Slice issues:
  - `finitecomputer/finite-nostr#1` reusable Nostr identity, event, and HTTP auth primitives
  - `finitecomputer/finite-nostr#2` reusable NIP-44 and NIP-59 wrapping primitives
  - `finitecomputer/finite-brain#2` Rust workspace and health smoke path
  - `finitecomputer/finite-brain#3` core domain model, path rules, and Vault bootstrap
  - `finitecomputer/finite-brain#4` Folder Object encryption, canonical hashes, and signed record validation
  - `finitecomputer/finite-brain#5` SQLite store for Vaults, Folders, access, and grants
  - `finitecomputer/finite-brain#6` sync append log, current projection, and conflict handling
  - `finitecomputer/finite-brain#7` Nostr-authenticated server shell and Vault metadata APIs
  - `finitecomputer/finite-brain#8` secure object routes and sync APIs
  - `finitecomputer/finite-brain#9` Folder Access, grant, Finish Setup, and rotation flows
  - `finitecomputer/finite-brain#10` singleton Vault Invitations and Share Links
  - `finitecomputer/finite-brain#11` Shared Folder Connections and mounted Folder projection
  - `finitecomputer/finite-brain#12` Encrypted Export, OKF Import/Export, and LLM Wiki privacy rules
  - `finitecomputer/finite-brain#13` development-only Smoke UI
  - `finitecomputer/finite-brain#14` Portable v1 hardening, compatibility, and end-to-end readiness
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
- Visual verification: `FINITE_BRAIN_ADDR=127.0.0.1:4015 cargo run -p finite-brain-app`, then `curl http://127.0.0.1:4015/health`

## Slice Ledger

| Issue | Type | Status | Review thread | Fixes needed | Verified |
| --- | --- | --- | --- | --- | --- |
| `finite-nostr#1` | AFK | complete | Direct review gate in orchestrator | None | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings` |
| `finite-nostr#2` | AFK | complete | Direct review gate in orchestrator | None | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `git diff --check` |
| `finite-brain#2` | AFK | complete | Direct review gate in orchestrator | Fixed README workspace docs and ledger command evidence | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `cargo build`; local `/health` curl |
| `finite-brain#3` | AFK | complete | Direct review gate in orchestrator | None | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `curl /smoke/bootstrap` |
| `finite-brain#4` | AFK | complete | Direct review gate in orchestrator | Added random-nonce public encrypt helper and deterministic vector helper before commit | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `git diff --check` |
| `finite-brain#5` | AFK | ready | None | None | Not started |
| `finite-brain#6` | AFK | blocked by `finite-brain#5` | None | None | Not started |
| `finite-brain#7` | AFK | blocked by `finite-nostr#1`, `finite-brain#5` | None | None | Not started |
| `finite-brain#8` | AFK | blocked by `finite-brain#6`, `finite-brain#7` | None | None | Not started |
| `finite-brain#9` | AFK | blocked by `finite-nostr#2`, `finite-brain#8` | None | None | Not started |
| `finite-brain#10` | AFK | blocked by `finite-brain#9` | None | None | Not started |
| `finite-brain#11` | AFK | blocked by `finite-brain#10` | None | None | Not started |
| `finite-brain#12` | AFK | blocked by `finite-brain#8`, `finite-brain#11` | None | None | Not started |
| `finite-brain#13` | AFK | blocked by `finite-brain#8`, `finite-brain#10`, `finite-brain#11`, `finite-brain#12` | None | None | Not started |
| `finite-brain#14` | AFK | blocked by `finite-nostr#2`, `finite-brain#13` | None | None | Not started |

## Parked HITL Slices

| Issue | Why parked | Blocks | Required human action | Final PR decision |
| --- | --- | --- | --- | --- |
| None | | | | |

## Issue Session Ledger

| Issue | Fixed point | Worker session | Commit | Review result | Checks |
| --- | --- | --- | --- | --- | --- |
| `finite-brain#4` | `48460ee442eac4b5d58c7ab6196e8e3ecbc5d0a5` | Orchestrator direct implementation | `ecc34fe` | Standards/spec review passed | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `git diff --check` |
| `finite-brain#3` | `041377794c23ab338bd1dee47b4e209bc2c2ef83` | Orchestrator direct implementation | `c43308d` | Standards/spec review passed | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `curl /health`; `curl /smoke/bootstrap` |
| `finite-nostr#2` | `f5c38f36f0377504d695d5509231fde332fa13d2` | Orchestrator direct implementation | `06cd71d` | Standards/spec review passed | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `git diff --check` |
| `finite-nostr#1` | `c92aaec05eef9f181cf62855743564a13dd4bfd0` | Orchestrator direct implementation | `f5c38f3` | Standards/spec review passed | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings` |
| `finite-brain#2` | `9148111454140fa22568cc035b5ea71db6ad1cfd` | Orchestrator direct implementation | `16ba2e4` | Standards/spec review passed after README and ledger fixes | `cargo fmt --check`; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `cargo build`; `curl /health` |

## Open Questions

- None.

## Escalations

- None.
