# FiniteBrain

FiniteBrain is being rebuilt from scratch in Rust.

The previous SilverBullet/TypeScript prototype is preserved as
[`finitecomputer/finite-brain-v1`](https://github.com/finitecomputer/finite-brain-v1).
This repository is the new Rust implementation target.

## Starting Point

The first implementation contract is the FiniteBrain Portable v1 specification:

- [`docs/specs/finitebrain-portability-spec.md`](docs/specs/finitebrain-portability-spec.md)

That spec captures the v1 product boundary, cryptographic records, vault model,
sync behavior, sharing model, OKF export/import shape, and hard-cut
compatibility rules.

## Development

This repo is a Cargo workspace:

- `crates/finite-brain-core`: Portable v1 domain and validation logic.
- `crates/finite-brain-cli`: `fbrain`, the agent-native CLI for Vault Working
  Trees.
- `crates/finite-brain-store`: SQLite storage and transaction boundary.
- `crates/finite-brain-server`: HTTP server and API surface.
- `crates/finite-brain-app`: application server binary that serves the Product
  Client, development Smoke UI, and HTTP routes.

```sh
cargo run -p finite-brain-app
cargo run -p finite-brain-cli --bin fbrain -- doctor
cargo test
```

The development smoke server listens on `127.0.0.1:3015` by default. Override
it with `FINITE_BRAIN_ADDR`:

```sh
FINITE_BRAIN_ADDR=127.0.0.1:4000 cargo run -p finite-brain-app
```

The app serves the Product Client at `/client` and the development-only Smoke
UI at `/smoke/ui`.

## Agent CLI

`fbrain` is the terminal control surface for trusted Agent Runtimes. Agents
work in a Vault Working Tree with ordinary file tools; `fbrain` handles the
state that normal filesystem operations cannot explain.

Use `fbrain` as the agent-facing command. During repo development, either run
the same command through Cargo from the repository root:
`cargo run -p finite-brain-cli --bin fbrain -- <args>`, or build once and run
`target/debug/fbrain`.

```sh
fbrain auth status
fbrain auth login --nsec <nsec-or-hex-secret>
fbrain signer public-key
fbrain signer sign --kind text --content "hello"
fbrain open <vault-id> ./my-vault
cd ./my-vault
fbrain status --json
fbrain daemon status
fbrain daemon watch --once --json
fbrain sync now --summary
fbrain sync now --json
fbrain unlock --all
fbrain conflicts
fbrain activity
fbrain access explain <folder>
fbrain vault metadata --vault <vault-id>
fbrain folder create notes --vault <vault-id> --name Notes --path Notes
fbrain permissions add-member --vault <vault-id> --target <npub>
fbrain invites create --vault <vault-id> --target <npub> --folder <folder-id>
fbrain share link --vault <vault-id> --folder <folder-id> --target <npub>
```

The current CLI provides the MVP local control surface, prototype local
Nostr-keypair auth, a simple NIP-07-like signer interface, Vault Working Tree
state files, automatic sync attempts on `open`/`daemon start`, strict sync
diagnostics through `sync now`, daemon status, blocked-state inspection, stable
JSON status, signed server calls for Vault metadata/export/create, Folder
creation, member/admin permission changes, Vault invitations, share links, and
shared Folder invitations. Agents still use ordinary filesystem reads and
writes for wiki work; `fbrain` owns the secure/control operations around that
flow.

`fbrain daemon watch` is a foreground resident sync loop for Agent Runtimes. Run
it under tmux, systemd, or an agent supervisor for continuous smoke use; use
`--once`, `--max-ticks`, and `--poll-secs` for bounded checks and tests.

The CLI resolves server URLs in this order: explicit `--server`, the saved
Vault Working Tree server URL, `FINITE_BRAIN_SERVER_URL`, then the legacy
`FINITE_BRAIN_PUBLIC_BASE_URL` fallback. The CLI HTTP client supports local
loopback `http://` endpoints and production-shaped `https://` endpoints.
Plain `http://` is accepted only for `localhost`, loopback IPs, and bracketed
IPv6 loopback addresses; LAN hosts and container hostnames must use `https://`.
Background supervisor packaging and lower-latency native file-system event
watching remain hardening work; command driven `open`, `daemon watch`,
`daemon start`, `daemon tick`, and `sync now` run the real sync path.

Use global `--config-dir <path>` when an agent needs a dedicated signer/config
directory without relying on shell-level environment persistence:

```sh
fbrain --config-dir "$HOME/.config/fbrain-smoke-agent" auth status
fbrain --config-dir "$HOME/.config/fbrain-smoke-agent" sync now --summary
```

`fbrain sync now` stays terse by default. Add `--summary` for a human-readable
local change report after batch wiki gardening, or use `--json` for
machine-readable `localChanges`, `remoteChanges`, and `conflicts` arrays. Sync
reports include paths, actions, Folder ids, Object ids, routes, and conflict
reasons only; they do not include plaintext contents, Folder Keys, grant
contents, or signer secrets.

Useful local environment variables:

- `FINITE_BRAIN_ADDR`: bind address, default `127.0.0.1:3015`.
- `FINITE_BRAIN_SERVER_URL`: agent/CLI transport base URL for `fbrain`
  commands. This can be a loopback-only `http://` endpoint or the
  smoke/staging `https://` endpoint.
- `FINITE_BRAIN_PUBLIC_BASE_URL`: browser-visible Product Client origin used
  by client config, Nostr auth URL checks, default CORS origin derivation, and
  as a legacy `fbrain` fallback when `FINITE_BRAIN_SERVER_URL` is unset.
- `FINITE_BRAIN_DB`: SQLite database path, default `finite-brain.sqlite3`.
- `FBRAIN_CONFIG_DIR`: local `fbrain` config directory for prototype signer
  state. Defaults to `~/.finitebrain/fbrain`. Prefer global `--config-dir`
  for scripts and agent runtimes that invoke `fbrain` across isolated shell
  calls.

For the full local/staging parity checklist, see
[`docs/runbooks/product-client-parity-local-staging.md`](docs/runbooks/product-client-parity-local-staging.md).
For the internal smoke alpha backup, restore, and old-route cutover handoff, see
[`docs/runbooks/smoke-alpha-backup-restore-cutover.md`](docs/runbooks/smoke-alpha-backup-restore-cutover.md).

## Packaged Agent Skill

This repository includes a minimal FiniteBrain agent skill at
[`skills/finitebrain-agent/SKILL.md`](skills/finitebrain-agent/SKILL.md). Keep
it in sync with `fbrain` CLI ergonomics, smoke-agent workflows, and Vault
Working Tree conventions. It lives here while the agent flow is still changing;
once stable, move or publish it through the shared `finite-skills` packaging
path.
