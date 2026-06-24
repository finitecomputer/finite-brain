# FiniteBrain Context

## Glossary

### FiniteBrain Portable v1

The hard-cut implementation target for the Rust rebuild. It is defined by
`docs/specs/finitebrain-portability-spec.md` and covers Vaults, Folders, Folder
Objects, Folder Key Grants, sync, sharing, OKF import/export, and compatibility.

### FiniteBrain Policy

Application-specific behavior for Vaults, Folders, access, sync, storage,
sharing, OKF, and smoke UI. FiniteBrain Policy belongs in the `finite-brain`
workspace, not in `finite-nostr`.

### Reusable Nostr Primitive

A generic Nostr operation that can be reused across Finite repos without
knowing about FiniteBrain Vaults or Folders. Examples include NIP-19 identity
encoding, event serialization and verification, NIP-44 encryption adapters,
NIP-59 gift-wrap helpers, and NIP-98-style HTTP authorization helpers.

### Smoke UI

A development-only HTML/CSS interface served by the Rust app for local
end-to-end verification. It is not the product client. It exists to inspect
Vaults, Folders, encrypted objects, sync state, grants, invitations, shares,
and mounts while the Rust core and server mature.

### Product Client

The trusted browser experience a User actually uses to open a Vault, connect a
NIP-07 signer, open Folder Key Grants, decrypt accessible Folder Objects,
materialize Pages, edit content, sync changes, run local search/graph indexes,
and perform OKF import/export. Unlike the Smoke UI, the Product Client owns the
normal user workflow.

### Product Client Spine

The minimum trusted-client workflow that later client features build on:
connect the User's NIP-07 signer, load Vault state, open current Folder Key
Grants, decrypt readable Pages, edit one Page, encrypt and write the Page back
as a signed revision, and pull/apply sync records without losing unresolved
local edits.

### Graph View

A Product Client view over the active User's decrypted accessible Pages. It
renders Page nodes and Page relationships only after Folder Keys are open and
visibility filtering has been applied.

### Graph Replay

A Product Client playback of graph/index changes derived from the client's
applied sync history and decrypted Page index. It is not a server-side graph
event log.

### OKF Import Execution

A Product Client workflow that parses readable OKF, plans import conflicts,
opens destination Folder Keys, encrypts imported Pages client-side, signs
Folder Object revisions, and uploads those revisions through normal secure
object routes. The Rust server does not parse readable OKF or receive
plaintext Page content during import.

### Vault Working Tree

A local agent-facing file projection built from already-decrypted accessible
Pages. It writes `AGENTS.md`, `_index.md`, `_wiki/`, `raw/`, `compiled/`, and
`output/` conventions for readable Folders, stores only safe locked metadata
for inaccessible Folders, and maps file changes back into Product Client
encrypted-object write, move, and delete intents.

### Hard Cut

A compatibility boundary where FiniteBrain does not carry legacy route,
storage, client, or migration behavior forward. Hard-cut work may import data
through explicit new-format flows such as OKF, but it does not preserve old v1
runtime compatibility as a feature requirement.
