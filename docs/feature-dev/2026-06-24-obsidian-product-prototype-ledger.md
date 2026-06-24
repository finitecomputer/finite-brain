# Obsidian Product Prototype Ledger

## Run

- Target repo: `finitecomputer/finite-brain`
- Base branch: `staging`
- Feature branch: `feature/guided-smoke-vault-reader`
- Staging PR: `finitecomputer/finite-brain#30`
- Human goal: evolve the Product Client from a smoke-test dashboard into a
  lightweight but complete Obsidian-like prototype that preserves FiniteBrain
  Vault, Folder, Page, access, sharing, sync, graph, and crypto behavior.

## Skill Setup

- `AGENTS.md`: present.
- `docs/agents/issue-tracker.md`: GitHub Issues via `gh`.
- `docs/agents/triage-labels.md`: Matt Pocock default role labels.
- `docs/agents/domain.md`: single-context repo; read `CONTEXT.md` and `docs/adr/`.

## Alignment

- Product direction: copy Obsidian's basic layout and interaction model rather
  than inventing a new shell.
- FiniteBrain boundary: keep the Product Client first-party and local-trusted;
  do not introduce server plaintext search/import/graph behavior.
- UI scope: left ribbon, file explorer sidebar, top workspace tabs, Page view,
  Graph view, right-click menus, top buttons, status/access affordances, and
  FiniteBrain-specific Vault/Folder/share/access controls.
- Prototype boundary: static Rust-served HTML/CSS/JS remains acceptable for the
  internal prototype. A full rich Markdown editor and mobile parity are out of
  scope for this feature-dev run.

## Issues

- PRD: `#31` PRD: Obsidian-like Product Client prototype
- Slice 1: `#32` Add Obsidian workspace shell to Product Client
- Slice 2: `#33` Add Obsidian-style folder and Page context menus
- Slice 3: `#34` Promote Graph View into an Obsidian-like workspace pane
- Slice 4: `#35` Surface FiniteBrain access and sharing in the Obsidian shell
- Slice 5: `#36` Harden Obsidian Product Client prototype verification

## Verification Commands

- `node --check crates/finite-brain-server/src/product-client.js`
- `node crates/finite-brain-server/src/product-client.test.js`
- `cargo fmt --check`
- `cargo test -p finite-brain-server product_client_serves_spine_assets_and_config -- --nocapture`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `git diff --check`
- local browser/screenshot verification against `http://127.0.0.1:4015/client`

## Slice Sessions

### `#32` Obsidian Workspace Shell

- Baseline: `216e3f1`
- Status: implementation in progress; first local pass verified
- Owner: current orchestrator thread using direct implementation because the
  first slice is the shell foundation for later slices.
- Current implementation:
  - Replaced the dashboard body with an Obsidian-like shell: left ribbon,
    file sidebar, workspace tab strip, Page workspace, Graph View workspace,
    right property/activity rail, and status bar.
  - Added real sidebar modes for Files, Search, and Access.
  - Added expandable/collapsible folder rows and Page rows in the file tree.
  - Added prototype-safe folder/Page context menus with open, new Page, copy
    id, access/share, graph, and disabled delete affordances.
  - Kept advanced crypto/OKF/Page-loop controls available in a collapsed
    developer drawer rather than making them the primary product workflow.
  - Expanded `scripts/seed-smoke-doc-pages.mjs` so local smoke vaults can be
    deterministically filled with 53 real FiniteBrain docs-themed encrypted
    Pages across every seeded Folder.
- Verification:
  - `node --check scripts/seed-smoke-doc-pages.mjs`
  - `node --check crates/finite-brain-server/src/product-client.js`
  - `node crates/finite-brain-server/src/product-client.test.js`
  - `cargo test -p finite-brain-server product_client_serves_spine_assets_and_config -- --nocapture`
  - `cargo test --workspace`
  - `cargo fmt --check`
  - `git diff --check`
  - Runtime endpoint check against `http://127.0.0.1:4015/client`
  - Smoke DB has 53 encrypted current objects and all 53 opened through the
    Product Client keyring/decrypt path.
- Visual note: headless Chromium screenshot capture hung on this machine after
  loading browser background services; local server remains live for manual
  Chromium refresh.
