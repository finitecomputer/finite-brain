---
name: finitebrain-agent
description: Operate as a trusted FiniteBrain agent inside Vault Working Trees with ordinary file tools plus the fbrain CLI. Use when gardening FiniteBrain vaults, syncing markdown wiki content, checking folder access, resolving fbrain sync state, or validating agent smoke/staging vault workflows.
---

# FiniteBrain Agent

## Quick Start

Use `fbrain` as the control plane and the Vault Working Tree as the content
surface. Prefer explicit `--config-dir` in agent runtimes because shell
environment can be reset between calls.

```sh
FBRAIN_CONFIG="$HOME/.config/fbrain-agent"
SERVER="https://brain.smoke.finite.computer"
VAULT="smoke"
TREE="$HOME/finitebrain/$VAULT"

fbrain --config-dir "$FBRAIN_CONFIG" doctor --server "$SERVER"
fbrain --config-dir "$FBRAIN_CONFIG" auth status --json
fbrain --config-dir "$FBRAIN_CONFIG" open "$VAULT" "$TREE" --server "$SERVER"
cd "$TREE"
fbrain --config-dir "$FBRAIN_CONFIG" sync now --summary
fbrain --config-dir "$FBRAIN_CONFIG" conflicts --json
```

## Operating Rules

1. Never print or expose private Nostr secrets, Folder Keys, grant plaintext,
   decrypted sync payload internals, or local auth files.
2. Assume the agent identity is provisioned by the runtime, `fauth`, or an
   explicit human runbook. Do not create or import keypairs unless the user or
   runbook explicitly asks.
3. Read the Vault Working Tree instructions before editing: root `AGENTS.md`,
   each readable Folder `AGENTS.md`, `_index.md`, and relevant `_wiki/` pages.
4. Treat readable Folder roots as normal files. Write curated wiki content under
   the folder conventions such as `raw/`, `compiled/`, and `output/`.
5. Do not edit `.finitebrain/` state, locked metadata-only folders, or generated
   convention files unless the user is explicitly asking to repair internals.
6. After meaningful edits, run `fbrain sync now --summary` and then
   `fbrain conflicts --json`.
7. If sync is blocked, stop broad edits and inspect with `fbrain status --json`,
   `fbrain conflicts --json`, and `fbrain access explain <folder>`.

## Gardening Workflow

1. Open or enter the Vault Working Tree.
2. Sync first, then check conflicts.
3. Inspect the existing structure with file tools.
4. Add or update the smallest coherent set of markdown pages.
5. Use wiki links, tags, and indexes so pages are navigable as an LLM wiki.
6. Sync with `--summary` and confirm conflicts are empty.
7. Report changed paths, sync status, latest sequence, and blockers.

## Useful Commands

```sh
fbrain --config-dir "$FBRAIN_CONFIG" status --json
fbrain --config-dir "$FBRAIN_CONFIG" sync now --summary
fbrain --config-dir "$FBRAIN_CONFIG" sync now --json
fbrain --config-dir "$FBRAIN_CONFIG" conflicts --json
fbrain --config-dir "$FBRAIN_CONFIG" activity
fbrain --config-dir "$FBRAIN_CONFIG" access explain general
fbrain --config-dir "$FBRAIN_CONFIG" daemon watch --once --json
```

## Final Report Shape

Report:

- acting npub when safe and relevant
- working tree path
- folders readable or locked
- pages created, updated, moved, or deleted
- `sync now --summary` status and latest sequence
- whether `conflicts --json` is empty
- blockers and the exact command/output category that exposed them
