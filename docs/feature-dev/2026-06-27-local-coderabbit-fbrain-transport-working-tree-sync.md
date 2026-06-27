# Local CodeRabbit Round: fbrain Transport And Working Tree Sync

## Round

- Scope: local
- Round number: 1
- Command or trigger: `coderabbit review --agent --type all --base staging`
- Started: `2026-06-27`
- Completed: `2026-06-27`
- Availability: completed
- Fallback review thread: none

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
