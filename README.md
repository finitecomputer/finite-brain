# FiniteBrain

FiniteBrain is Finite Computer's encrypted, folder-scoped knowledge system for
humans and agents.

If a human asks you to work in a FiniteBrain vault, use the `fbrain` CLI. A
Vault Working Tree is the editable local source of truth for an agent: sync
first, unlock readable Folders, edit ordinary markdown, then sync encrypted
changes back.

The current hosted smoke service is `https://brain.smoke.finite.computer`.
Use `https://brain.smoke.finite.computer/client` for the Product Client.

## Install `fbrain`

Install the latest release binary:

```sh
set -eu

repo="finitecomputer/finite-brain"
tmp="$(mktemp -d)"
os="$(uname -s)"
arch="$(uname -m)"

case "$os:$arch" in
  Darwin:arm64) asset="fbrain-macos-aarch64" ;;
  Darwin:x86_64) asset="fbrain-macos-x86_64" ;;
  Linux:x86_64) asset="fbrain-linux-x86_64" ;;
  *) echo "unsupported platform: $os $arch" >&2; exit 1 ;;
esac

base="https://github.com/$repo/releases/latest/download"
curl -fsSL "$base/$asset.tar.gz" -o "$tmp/$asset.tar.gz"
curl -fsSL "$base/$asset.tar.gz.sha256" -o "$tmp/$asset.tar.gz.sha256"

if command -v shasum >/dev/null 2>&1; then
  (cd "$tmp" && shasum -a 256 -c "$asset.tar.gz.sha256")
else
  (cd "$tmp" && sha256sum -c "$asset.tar.gz.sha256")
fi

tar -xzf "$tmp/$asset.tar.gz" -C "$tmp"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$tmp/fbrain" "$HOME/.local/bin/fbrain"
"$HOME/.local/bin/fbrain" --version
```

Make sure `$HOME/.local/bin` is on `PATH` before continuing.

## Discover The CLI

Start by asking `fbrain` what it can do:

```sh
fbrain --help
fbrain doctor --server https://brain.smoke.finite.computer
fbrain auth status --json
```

Prefer `--json` for commands whose output an agent needs to parse.

## Open A Vault Working Tree

Use an explicit config directory in agent runtimes so signer state does not
depend on shell persistence:

```sh
export FINITE_BRAIN_SERVER_URL=https://brain.smoke.finite.computer
export FBRAIN_CONFIG_DIR="$HOME/.config/finitebrain"

fbrain --config-dir "$FBRAIN_CONFIG_DIR" auth status --json
fbrain --config-dir "$FBRAIN_CONFIG_DIR" open <vault-id> "$HOME/finitebrain/<vault-id>"
cd "$HOME/finitebrain/<vault-id>"
fbrain --config-dir "$FBRAIN_CONFIG_DIR" sync now --summary
fbrain --config-dir "$FBRAIN_CONFIG_DIR" unlock --all
fbrain --config-dir "$FBRAIN_CONFIG_DIR" sync now --summary
fbrain --config-dir "$FBRAIN_CONFIG_DIR" conflicts --json
```

Before editing, read the Vault Working Tree's `AGENTS.md`, `HUMANS.md`,
Folder-local `_index.md`, `config.md`, and `log.md` files when present.

## Agent Rules

- Sync before editing and after meaningful changes.
- Only edit readable materialized Folder contents.
- Do not edit `.finitebrain/`, encrypted sync evidence, locked metadata-only
  folders, auth files, key material, or generated state files.
- Treat every readable top-level Folder as its own LLM wiki scope.
- Keep each Folder's `_index.md` and `log.md` local to that Folder.
- Never summarize restricted Folder contents into less-restricted Folders,
  indexes, logs, or outputs.
- Do not print or expose Nostr secrets, Folder Keys, grant plaintext, auth
  files, decrypted sync internals, or rotation bodies.

## Developers

If you want to understand, run, or modify FiniteBrain itself, see
[`development.md`](development.md).

The core implementation contract is the FiniteBrain Portable v1 specification:

- [`docs/specs/finitebrain-portability-spec.md`](docs/specs/finitebrain-portability-spec.md)

This repository is the active Rust implementation target and includes the
first-party Product Client prototype served at `/client`. The previous
SilverBullet/TypeScript fork is legacy archive material, not part of the active
workspace or compatibility surface.
