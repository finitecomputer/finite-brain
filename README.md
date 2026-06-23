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

```sh
cargo run
cargo test
```

