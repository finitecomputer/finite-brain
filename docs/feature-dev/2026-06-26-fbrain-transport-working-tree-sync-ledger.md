# Goal Ledger: fbrain Transport And Working Tree Sync

## Run

- Run ID: `2026-06-26-fbrain-transport-working-tree-sync`
- Loop: Feature Dev
- Target repo: `/Users/plebdev/Desktop/Projects/finite/finite-brain-fbrain`
- Base branch: `staging`
- Feature branch: `feature/fbrain-transport-working-tree-sync`
- Human owner: Austin
- Started: `2026-06-26T23:28:22Z`
- Current status: local implementation, review, and local CodeRabbit fixes complete
- Skill setup status: present (`AGENTS.md`, `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`, `docs/agents/domain.md`)

## Goal

Do missing rollout items 3 and 6 end to end: harden `fbrain` server transport configuration and wire the agent Vault Working Tree sync loop so agents can use normal files while `fbrain` pulls, decrypts, encrypts, signs, and pushes FiniteBrain object changes.

## Alignment

- Product intent: preserve the trusted-client plaintext boundary. The Agent Runtime may decrypt accessible Pages locally; the server remains encrypted-object only.
- Base branch note: `main` is currently ahead of `staging` in Product Client files, but CLI/core files are identical for this feature scope.
- Human gate: none. The requested items map directly to existing `CONTEXT.md` terms: Agent CLI, Agent Sync Daemon, Vault Working Tree, Local Agent Signer, and Blocked Sync State.

## Durable Artifacts

- CONTEXT updates: none planned unless implementation resolves new terminology
- ADRs: none planned
- PRD issue: `finitecomputer/finite-brain#43`
- Slice issues:
  - `finitecomputer/finite-brain#45` fbrain transport config and HTTPS
  - `finitecomputer/finite-brain#44` Vault Working Tree materialize/writeback sync
- Issue sessions:
  - `docs/feature-dev/2026-06-26-issue-45-fbrain-transport-session.md`
  - `docs/feature-dev/2026-06-26-issue-44-working-tree-sync-session.md`
- Agent briefs: this ledger
- Review packets:
  - `docs/feature-dev/2026-06-26-issue-45-fbrain-transport-review-packet.md`
  - `docs/feature-dev/2026-06-26-issue-44-working-tree-sync-review-packet.md`
- Local CodeRabbit report: `docs/feature-dev/2026-06-27-local-coderabbit-fbrain-transport-working-tree-sync.md`
- PR URL: pending

## Commands

- Install: existing Cargo workspace
- Typecheck: `cargo check -p finite-brain-cli`; `cargo check -p finite-brain-server`; `cargo check --workspace`
- Test: `cargo test -p finite-brain-cli`; targeted server tests; `cargo test --workspace`
- Build: `cargo build -p finite-brain-app -p finite-brain-cli`; `cargo build`
- Visual verification: not applicable for CLI-only slices
- Live smoke:
  - Temp DB: `/tmp/fbrain-sync-smoke.oC4srw/finite-brain.sqlite3`
  - Server: `http://127.0.0.1:4016`
  - Commands proved: `auth login`, `vault create personal-beta`, `open`, readable `home`, create/update/delete `home/smoke.md` through `sync now`, empty conflicts, final latest sequence `3`
  - Rerun after local CodeRabbit fixes used temp DB `/tmp/fbrain-sync-smoke.WWDQFD/finite-brain.sqlite3`, vault `personal-gamma`, and final latest sequence `3`

## Slice Ledger

| Issue | Type | Status | Review thread | Fixes needed | Verified |
| --- | --- | --- | --- | --- | --- |
| `#45` | AFK | implemented | direct review packet | none | yes |
| `#44` | AFK | implemented | direct review packet | none | yes |

## Parked HITL Slices

None.

## Issue Session Ledger

| Issue | Fixed point | Worker session | Commit | Review result | Checks |
| --- | --- | --- | --- | --- | --- |
| `#45` | `df69b01521d9e126f430d926a7730f4f4c641d05` | current thread | `8bf422f969aa689c7c0214d70f98df85f1eca7b7` | pass | `fmt`, `check`, `test`, `clippy`, `build`, live smoke |
| `#44` | `df69b01521d9e126f430d926a7730f4f4c641d05` | current thread | `8bf422f969aa689c7c0214d70f98df85f1eca7b7` | pass | `fmt`, `check`, `test`, `clippy`, `build`, live smoke |

## Review Notes

- Fixed point: `df69b01521d9e126f430d926a7730f4f4c641d05`
- Review skill: direct two-axis review used. Sub-agent review was skipped because available multi-agent tooling requires explicit user delegation.
- Standards sources: `AGENTS.md`, `CONTEXT.md`, `docs/agents/domain.md`, `docs/specs/finitebrain-portability-spec.md`, and relevant ADRs.
- Standards result: pass, no findings.
- Spec sources: `finitecomputer/finite-brain#43`, `#44`, and `#45`.
- Spec result: pass, no findings.

## Local CodeRabbit

- Command: `coderabbit review --agent --type all --base staging`
- Availability: completed through the free CLI allowance
- Findings: 8 addressed, 0 ignored
- Fix commit: `f17e40b03b90897e1a929088457b8d0e696c0639`
- Fix evidence:
  - Partial-success sync now rematerializes accepted writes and restores conflicted markdown edits.
  - `timestamp_from_unix` guards oversized values.
  - Folder readability requires the current Folder Key version.
  - Stale moved object paths are removed.
  - Bootstrap grant requests are validated against required recipients before conversion.
  - Plaintext HTTP is restricted to localhost/loopback.
  - `fbrain open` validates the server URL before persistence.
  - Bootstrap grant generation reuses one Folder Key per folder/key version across recipients.
  - Product Client asset test body cap was raised after full-suite verification found the checked-in HTML exceeded the stale 16 KiB test cap.

## Open Questions

- None.

## Escalations

- None.
