# Local CodeRabbit Round: fbrain Transport And Working Tree Sync

## Round

- Scope: local
- Round number: 1
- Command or trigger: `coderabbit review --agent --type all --base staging`
- Started: `2026-06-27`
- Completed: `2026-06-27`
- Availability: completed
- Fallback review thread: none
- Fix commit: `f17e40b03b90897e1a929088457b8d0e696c0639`

## Findings To Address

| Finding | Severity | Decision | Notes |
| --- | --- | --- | --- |
| Partial-success sync skipped rematerialization when any conflict existed. | major | fixed | Sync now rematerializes accepted writes and restores conflicted markdown edits after projection refresh. |
| `timestamp_from_unix` cast could wrap oversized `u64` values. | minor | fixed | Uses `i64::try_from` and falls back to Unix epoch. |
| Folder readability used any historical local key. | major | fixed | Empty readable folder materialization now requires the current folder key version. |
| Stale cleanup left old path after same-object move. | major | fixed | Cleanup compares current paths for matching `(folder_id, object_id)`. |
| Bootstrap grant requests needed route-level validation against required grants. | major | fixed | Route validates exact required folder/key/recipient set before conversion. |
| Plaintext `http://` accepted non-local hosts. | major | fixed | `http://` is restricted to localhost/loopback; other transports require `https://`. |
| `open` persisted server URLs before validation. | minor | fixed | `open` validates the resolved server URL before writing agent state. |
| Bootstrap grant generation created a new Folder Key per recipient. | major | fixed | One Folder Key is generated per `(folder_id, key_version)` and reused for all recipients in that group. |

## Findings Not Addressed

None.

## Result

- Continue: yes
- Escalate: no
- Notes:
  - Added focused regression tests for partial-success conflict preservation, historical key readability, stale moved-file cleanup, local-only HTTP, and bootstrap grant validation.
  - Full verification after fixes passed: `cargo fmt --check && cargo check --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo build && git diff --check`.
  - Live smoke after fixes passed against `http://127.0.0.1:4016` with temp DB `/tmp/fbrain-sync-smoke.WWDQFD/finite-brain.sqlite3`.

## Round 2

- Scope: local
- Round number: 2
- Command or trigger: `coderabbit review --agent --type all --base staging`
- Started: `2026-06-27`
- Completed: `2026-06-27`
- Availability: completed
- Fallback review thread: none
- Fix commits:
  - `a7ebbb8` Address fbrain CodeRabbit round 2 findings
  - `b73fb40` Fix fbrain HTTP port validation clippy

## Findings To Address

| Finding | Severity | Decision | Notes |
| --- | --- | --- | --- |
| Local `http://` host parsing accepted malformed bracketed hosts. | minor | fixed | Tightened bracket and port parsing and added loopback URL regression tests. |
| `ureq` followed redirects after validating only the original URL. | major | fixed | HTTP agent now disables redirects so validated command URLs cannot be redirected to an unvalidated host or scheme. |
| Conflict fake sync server read request bodies with a single socket read. | minor | fixed | Reused the full `read_http_request` helper so conflict tests wait for declared bodies before responding. |
| fbrain-encrypted sync writes did not preserve page paths for other machines. | major | fixed | fbrain-created Folder Object plaintext now uses an encrypted `finite-folder-object-page-v1` envelope containing `path` and `markdown`, while legacy raw markdown objects still decode with the prior fallback path behavior. |

## Findings Not Addressed

None.

## Result

- Continue: yes
- Escalate: no
- Notes:
  - Added cross-device materialization coverage for encrypted page paths with no prior local path override.
  - Clean full verification passed from `/tmp/fbrain-verify-worktree.KosIBG`: `cargo fmt --check && cargo check --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo build && git diff --check`.
  - Live smoke after round-two fixes passed against `http://127.0.0.1:4018` with temp DB `/tmp/fbrain-sync-smoke-round2.BzarH1/finite-brain.sqlite3`; create/update/delete of `home/round2.md` ended at `latestSequence=3` with `conflicts=[]`.
  - Branch hygiene: commit `331ccd0` restored Product Client asset parity because commit `f17e40b` had already added server asset assertions for Product Client controls. Verification passed with `cargo test -p finite-brain-server product_client_serves_spine_assets_and_config`, `node crates/finite-brain-server/src/product-client.test.js`, and `node scripts/verify-obsidian-product-client.mjs`.
