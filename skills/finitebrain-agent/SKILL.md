---
name: finitebrain-agent
description: FiniteBrain Vault Working Tree operations through ordinary file edits plus the fbrain CLI control plane. Use when gardening FiniteBrain vaults, syncing markdown wiki content, inspecting sync/conflict state, checking Folder access, using fbrain daemon/watch, or performing vault, folder, permission, invitation, and share-link admin flows.
---

# FiniteBrain Agent

Use `fbrain` as the control plane and the Vault Working Tree as the content
surface. The repeatable loop is: verify identity, open or enter the tree, sync,
edit readable files, sync, prove conflicts are empty.

## Quick Start

Prefer explicit `--config-dir` in agent runtimes. The CLI default is
`$FBRAIN_CONFIG_DIR`, then `$HOME/.finitebrain/fbrain`, but explicit state avoids
surprises when shell environment resets between calls.

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

Read [fbrain-cli.md](references/fbrain-cli.md) when a command fails, when using
daemon/watch, access, vault, folder, permission, invite, or share commands, or
when working from the Rust repo where `cargo run -p finite-brain-cli --bin
fbrain -- <args>` may be the available entrypoint.

## Operating Loop

1. Verify runtime state with `doctor`, `auth status --json`, and `status --json`.
   Completion: acting identity, working tree path, server source, daemon state,
   sync state, and blockers are known.
2. Sync before reading broadly: run `sync now --summary`, then `conflicts --json`.
   Completion: latest sequence is recorded and open conflicts are either empty
   or named.
3. Read local instructions before editing: root `AGENTS.md`, each readable
   Folder `AGENTS.md`, `_index.md`, and relevant `_wiki/` pages.
   Completion: the target Folder conventions and existing wiki shape are known.
4. Edit only readable content roots with ordinary file tools. Keep curated wiki
   work under established folder conventions such as `raw/`, `compiled/`, and
   `output/`.
   Completion: the smallest coherent set of markdown files is changed.
5. Do not edit `.finitebrain/`, locked metadata-only folders, encrypted sync
   evidence, generated convention files, auth files, grant plaintext, or Folder
   Key material unless the user explicitly asks for internal repair.
   Completion: all edits stay on the safe content surface.
6. Sync after meaningful edits with `sync now --summary`, then run
   `conflicts --json`.
   Completion: pushed/applied status, latest sequence, and conflict state are
   known.

## Blocked State

If sync, access, or daemon work blocks, stop broad edits and inspect with
`status --json`, `sync status --json`, `conflicts --json`, `daemon status --json`,
and the relevant command in [fbrain-cli.md](references/fbrain-cli.md).

Treat `access revoke` without `--rotation-body` as a safety checklist, not a
failed command: Folder access removal requires key rotation and re-encrypted live
Folder objects.

## Security Rules

- Never print or expose private Nostr secrets, Folder Keys, grant plaintext,
  decrypted sync payload internals, local auth files, or rotation bodies.
- Assume identity is provisioned by the runtime, `fauth`, or a human runbook. Do
  not create, import, or ask for keypairs unless the user or runbook explicitly
  asks.
- Use `--json` for machine inspection, but summarize sensitive results instead
  of pasting raw payloads.

## Final Report

Report the working tree path, safe acting npub when relevant, folders readable or
locked, pages created/updated/moved/deleted, `sync now --summary` status, latest
sequence, whether `conflicts --json` is empty, and blockers with the command
category that exposed them.
