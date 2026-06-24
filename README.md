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
- `crates/finite-brain-store`: SQLite storage and transaction boundary.
- `crates/finite-brain-server`: HTTP server and API surface.
- `crates/finite-brain-app`: application server binary that serves the Product
  Client, development Smoke UI, and HTTP routes.

```sh
cargo run -p finite-brain-app
cargo test
```

The development smoke server listens on `127.0.0.1:3015` by default. Override
it with `FINITE_BRAIN_ADDR`:

```sh
FINITE_BRAIN_ADDR=127.0.0.1:4000 cargo run -p finite-brain-app
```

The app serves the Product Client at `/client` and the development-only Smoke
UI at `/smoke/ui`.

Useful local environment variables:

- `FINITE_BRAIN_ADDR`: bind address, default `127.0.0.1:3015`.
- `FINITE_BRAIN_PUBLIC_BASE_URL`: externally visible base URL used by client
  config, Nostr auth URL checks, and default CORS origin derivation.
- `FINITE_BRAIN_DB`: SQLite database path, default `finite-brain.sqlite3`.

For the full local/staging parity checklist, see
[`docs/runbooks/product-client-parity-local-staging.md`](docs/runbooks/product-client-parity-local-staging.md).
