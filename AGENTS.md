# Agent Guide

## Agent skills

### Issue tracker

Issues and PRDs live in GitHub Issues for `finitecomputer/finite-brain`. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default Matt Pocock skill label vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repo: read root `CONTEXT.md` and root `docs/adr/` when present. See `docs/agents/domain.md`.

## Engineering Style

FiniteBrain Rust follows the Finite engineering style:

- Keep authoritative server state in schema, constraints, and transactions.
- Use typed error enums at crate boundaries.
- Make safety invariants executable through validation and tests.
- Prefer explicit control flow for protocol, storage, sync, and crypto-adjacent code.
- Put explicit limits on loops, batches, payloads, fanout, sync windows, and retry work.
- Keep compatibility hard cuts before first users unless real user data exists.

