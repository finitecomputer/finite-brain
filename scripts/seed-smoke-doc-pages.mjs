#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const dbPath = process.env.FINITE_BRAIN_DB || "/tmp/finite-brain-smoke-test.sqlite3";
const keyManifestPath =
  process.env.FINITE_BRAIN_SMOKE_KEYS || "/tmp/finite-brain-smoke-vault-keys.json";
const vaultId = process.env.FINITE_BRAIN_SMOKE_VAULT || "smoke";
const createdAtUnix = 1782320400;
const createdAtIso = new Date(createdAtUnix * 1000).toISOString();

function element() {
  return {
    children: [],
    className: "",
    disabled: false,
    textContent: "",
    value: "",
    addEventListener() {},
    appendChild(child) {
      this.children.push(child);
    },
    replaceChildren() {
      this.children = [];
    },
  };
}

function loadProductClient() {
  const elements = new Map();
  const context = {
    TextDecoder,
    TextEncoder,
    Uint8Array,
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
    console,
    crypto: crypto.webcrypto,
    document: {
      createElement: element,
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, element());
        return elements.get(id);
      },
    },
    window: {
      __FINITE_BRAIN_DISABLE_AUTOSTART__: true,
    },
  };
  context.globalThis = context;
  const source = fs.readFileSync(
    path.join(repoRoot, "crates/finite-brain-server/src/product-client.js"),
    "utf8"
  );
  vm.runInNewContext(source, context, { filename: "product-client.js" });
  return context.window.FiniteBrainProductClient;
}

function sqliteValue(sql) {
  return execFileSync("sqlite3", [dbPath, sql], { encoding: "utf8" }).trim();
}

function sqliteExec(sql) {
  execFileSync("sqlite3", [dbPath], { input: sql, encoding: "utf8" });
}

function sqlQuote(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function eventIdFor(page) {
  return crypto
    .createHash("sha256")
    .update(`finite-brain-smoke-doc-page:${vaultId}:${page.folderId}:${page.objectId}`)
    .digest("hex");
}

function fakeSignedEvent(template, page, authorNpub) {
  return {
    ...template,
    id: eventIdFor(page),
    pubkey: crypto.createHash("sha256").update(authorNpub).digest("hex"),
    sig: crypto
      .createHash("sha256")
      .update(`signature-placeholder:${vaultId}:${page.folderId}:${page.objectId}`)
      .digest("hex")
      .repeat(2),
  };
}

const pages = [
  {
    folderId: "docs",
    objectId: "fb_docs_context_map_0001",
    path: "context-map.md",
    title: "FiniteBrain Context Map",
    text: `# FiniteBrain Context Map

FiniteBrain Rust v1 is organized around a small product hierarchy: Vault -> Folder -> Page.

The current workspace keeps the implementation split into four crates:

- finite-brain-core owns domain validation, folder object crypto, portability helpers, and deterministic rules.
- finite-brain-store owns SQLite schema, migrations, sync append-log storage, and current-state projection.
- finite-brain-server owns HTTP routes, request validation, and protected route policy.
- finite-brain-app wires configuration, SQLite state, the Product Client, and the development smoke UI.

Useful entry points:

- [[Vault Model]] explains the product object hierarchy.
- [[Folder Keys]] explains why readable content stays client-side.
- [[Product Client]] explains the browser workflow used for smoke testing.
`,
  },
  {
    folderId: "docs",
    objectId: "fb_docs_readiness_0001",
    path: "readiness-matrix.md",
    title: "Portable v1 Readiness Matrix",
    text: `# Portable v1 Readiness Matrix

The current Rust implementation is intentionally SQLite-backed from day one.

Readiness checks cover:

- bootstrap and metadata visibility;
- protected route authorization;
- encrypted object writes and sync bootstrap;
- cursor expiry and rebootstrap behavior;
- filtered encrypted export;
- local Product Client static asset serving;
- local smoke UI route coverage.

The important smoke-test idea is simple: the server can store and order encrypted state, but readable Page content only exists inside a trusted client after Folder Keys are opened.

See also [[Sync Append Log]], [[Security Notes]], and [[Portable v1]].
`,
  },
  {
    folderId: "architecture",
    objectId: "fb_arch_workspace_0001",
    path: "rust-workspace.md",
    title: "Rust Workspace Architecture",
    text: `# Rust Workspace Architecture

FiniteBrain is a Rust workspace, not a single catch-all application crate.

The crate boundary is a design tool:

- core is pure logic and crypto policy;
- store is SQLite durability and transactional behavior;
- server is the route and validation shell;
- app is the runtime binary.

Reusable Nostr primitives live in finite-nostr so other Finite repos can share NIP helpers without inheriting FiniteBrain Vault or Folder concepts.

This keeps the rebuild production-shaped while still letting the Product Client move quickly.
`,
  },
  {
    folderId: "architecture",
    objectId: "fb_arch_server_store_0001",
    path: "server-store-boundary.md",
    title: "Server and Store Boundary",
    text: `# Server and Store Boundary

The server validates protected requests, checks Vault membership, checks Folder visibility, and delegates durable state changes to the store.

The store owns:

- schema migrations;
- folder hierarchy persistence;
- Folder Key Grant metadata;
- sync append-log insertion;
- current encrypted object projection;
- idempotency and duplicate event handling;
- SQLite backup and rebuild behavior.

This split keeps route handlers thin and lets storage invariants stay testable without a browser.
`,
  },
  {
    folderId: "crypto",
    objectId: "fb_crypto_folder_objects_0001",
    path: "folder-object-crypto.md",
    title: "Folder Object Crypto",
    text: `# Folder Object Crypto

FiniteBrain Page content is encrypted as Folder Objects.

The current envelope uses AES-256-GCM with associated data that binds ciphertext to:

- vaultId;
- folderId;
- objectId;
- keyVersion.

That AAD is why a payload encrypted for one Folder cannot be silently replayed as a different Folder Object.

The server stores envelopes and validates sync records, but it does not need plaintext Page content.
`,
  },
  {
    folderId: "crypto",
    objectId: "fb_crypto_grants_0001",
    path: "folder-key-grants.md",
    title: "Folder Key Grants",
    text: `# Folder Key Grants

Folder Keys are the practical access boundary for readable Pages.

In production shape, a Folder Key Grant is wrapped for a specific recipient using Nostr/NIP primitives. In this local smoke fixture, development grants are intentionally readable so the browser Product Client can auto-open seeded data for testing.

The important invariant stays the same:

- the server can know grant metadata;
- the client opens grants;
- only clients with the right Folder Key can decrypt Page content.
`,
  },
  {
    folderId: "sync",
    objectId: "fb_sync_projection_0001",
    path: "sync-current-projection.md",
    title: "Sync Current Projection",
    text: `# Sync Current Projection

FiniteBrain sync has two related shapes:

- an append-only Vault Record Index;
- a current encrypted object projection.

Clients bootstrap from the current projection, then pull later records by sequence. Duplicate event ids are ignored. Stale base revisions are rejected by the store.

If a cursor expires, the client discards the incremental cursor, runs bootstrap again, rebuilds local projection, and then resumes from the bootstrap latest sequence.
`,
  },
  {
    folderId: "sync",
    objectId: "fb_sync_conflicts_0001",
    path: "sync-conflicts.md",
    title: "Sync Conflict Policy",
    text: `# Sync Conflict Policy

The prototype conflict rule is deliberately small:

- creates start at revision 1;
- updates include baseRevision;
- the server rejects stale baseRevision writes;
- clients keep unresolved local drafts when a newer server revision appears.

This is enough to smoke test the encrypted object lifecycle without inventing a collaborative editor too early.

See [[Sync Append Log]] for the broader model.
`,
  },
  {
    folderId: "sharing",
    objectId: "fb_sharing_invites_0001",
    path: "vault-invites.md",
    title: "Vault Invites",
    text: `# Vault Invites

Vault Invitations are npub-bound and single use.

An invitation has a lifecycle:

- pending;
- accepted;
- revoked;
- expired.

Accepting an invite makes the recipient a Vault member and grants the initial Folder access selected by the admin.

This keeps organization membership separate from Folder-level sharing.
`,
  },
  {
    folderId: "sharing",
    objectId: "fb_sharing_mounts_0001",
    path: "shared-folder-mounts.md",
    title: "Shared Folder Mounts",
    text: `# Shared Folder Mounts

Mounted shared folders are source-backed projections, not copies.

That means:

- the source Vault keeps owning the Folder;
- writes route back to the source Folder;
- destination organization members need source access and Folder Key Grants;
- revocation changes what the destination can continue to read.

This is the Slack shared-channel style middle ground: organizations remain distinct, but a shared Folder can appear inside another organization.
`,
  },
  {
    folderId: "portability",
    objectId: "fb_port_okf_export_0001",
    path: "okf-export.md",
    title: "OKF Export Shape",
    text: `# OKF Export Shape

FiniteBrain portability uses an OKF-style bundle for readable export.

The export shape includes:

- okf-vault.json metadata;
- Markdown Pages;
- link rewriting for present Pages;
- omissions for inaccessible Folders;
- deterministic conflict behavior on import.

Unreadable or inaccessible Folders are not exported as plaintext. They remain encrypted server state.
`,
  },
  {
    folderId: "portability",
    objectId: "fb_port_working_tree_0001",
    path: "working-tree-projection.md",
    title: "Working Tree Projection",
    text: `# Working Tree Projection

The working-tree projection turns accessible decrypted Pages into a local folder/files view.

Conventions include:

- AGENTS.md for agent instructions;
- _index.md for folder summaries;
- _wiki/ for generated wiki material;
- raw, compiled, and output areas for agent workflows.

The projection is a client-side convenience. Authoritative server sync remains encrypted and ordered through the Vault Record Index.
`,
  },
  {
    folderId: "agent-wiki",
    objectId: "fb_agent_discovery_0001",
    path: "agent-discovery.md",
    title: "Agent Discovery Rules",
    text: `# Agent Discovery Rules

Agents should discover readable FiniteBrain context through the client-side decrypted projection.

Good discovery rules:

- start with AGENTS.md when present;
- read _index.md for folder intent;
- prefer curated _wiki/ material before raw dumps;
- avoid assuming inaccessible Folders are empty;
- keep generated reports separate from source notes.

This lets agents work with useful local plaintext without asking the server to index or inspect private Page content.
`,
  },
  {
    folderId: "agent-wiki",
    objectId: "fb_agent_reports_0001",
    path: "generated-reports.md",
    title: "Generated Reports",
    text: `# Generated Reports

Generated reports are useful smoke-test content because they exercise search, graph links, and folder organization.

Expected report areas:

- _wiki/ for durable generated summaries;
- output/ for one-off run artifacts;
- compiled/ for bundled context;
- raw/ for source material that should remain easy to audit.

Reports should link back to source Pages like [[Rust Workspace Architecture]] and [[Folder Object Crypto]].
`,
  },
  {
    folderId: "graph-smoke",
    objectId: "fb_graph_links_0001",
    path: "graph-link-fixture.md",
    title: "Graph Link Fixture",
    text: `# Graph Link Fixture

This Page exists to exercise the graph view.

Links:

- [[FiniteBrain Smoke Vault]]
- [[Vault Model]]
- [[Folder Keys]]
- [[Sync Append Log]]
- [[Shared Folder Mounts]]
- [[OKF Export Shape]]

The graph should show only Pages the active client can decrypt.
`,
  },
  {
    folderId: "graph-smoke",
    objectId: "fb_graph_replay_fixture_0001",
    path: "replay-fixture.md",
    title: "Replay Fixture",
    text: `# Replay Fixture

Graph replay is derived from local decrypted Page history.

For now, this fixture is static dummy content. It still helps test that graph surfaces are built from readable Pages and Folder Keys, not from server-side plaintext indexing.

Useful related notes:

- [[Graph Replay]]
- [[Sync Current Projection]]
- [[Product Client]]
`,
  },
  {
    folderId: "vault-ops",
    objectId: "fb_ops_smoke_admin_0001",
    path: "smoke-admin-checklist.md",
    title: "Smoke Admin Checklist",
    text: `# Smoke Admin Checklist

This admin-only Folder is for operational smoke checks.

Before handing the local client back to a human:

- verify /health returns ok;
- verify /client serves the Product Client;
- open accessible Folder Key Grants;
- pull sync bootstrap;
- click folders and Pages in the Vault Reader;
- confirm restricted content is visible only when the right Folder Key is open.

This Page is intentionally admin-only to keep the access model visible during demos.
`,
  },
  {
    folderId: "restricted-lab",
    objectId: "fb_restricted_rotation_0001",
    path: "restricted-rotation.md",
    title: "Restricted Rotation Notes",
    text: `# Restricted Rotation Notes

Restricted Folder access is binary in this prototype.

When access is removed, the expected secure path is:

- rotate the Folder Key;
- re-encrypt live objects;
- issue new grants only to remaining recipients;
- keep old encrypted records as historical sync records;
- update the current projection to the rotated revision.

This fixture is readable in the smoke setup because the seeded admin receives the Restricted Lab Folder Key.
`,
  },
];

async function main() {
  if (!fs.existsSync(dbPath)) throw new Error(`SQLite DB not found: ${dbPath}`);
  if (!fs.existsSync(keyManifestPath)) {
    throw new Error(`Folder key manifest not found: ${keyManifestPath}`);
  }

  const manifest = JSON.parse(fs.readFileSync(keyManifestPath, "utf8"));
  const client = loadProductClient();
  const keyring = client.createSessionKeyring();
  const adminNpub = manifest.seededAdminNpub || "npub-smoke-admin";

  for (const [folderId, folderKey] of Object.entries(manifest.folderKeys || {})) {
    await client.openFolderKeyGrantPlaintext(keyring, {
      version: "finite-folder-key-grant-v1",
      vaultId,
      folderId,
      keyVersion: 1,
      issuerNpub: adminNpub,
      recipientNpub: adminNpub,
      folderKey,
      issuedAt: createdAtIso,
    });
  }

  const objectIds = pages.map((page) => page.objectId);
  const quotedIds = objectIds.map(sqlQuote).join(", ");
  const statements = ["BEGIN;"];
  try {
    statements.push(
      `DELETE FROM current_encrypted_vault_objects WHERE vault_id = ${sqlQuote(
        vaultId
      )} AND object_id IN (${quotedIds});`
    );
    statements.push(
      `DELETE FROM vault_record_index WHERE vault_id = ${sqlQuote(
        vaultId
      )} AND object_id IN (${quotedIds});`
    );

    let sequence = Number(
      sqliteValue(
        `SELECT COALESCE(MAX(sequence), 0) FROM vault_record_index WHERE vault_id = ${sqlQuote(vaultId)};`
      )
    );

    for (const [index, page] of pages.entries()) {
      const nonceBytes = crypto
        .createHash("sha256")
        .update(`finite-brain-smoke-doc-page-nonce:${vaultId}:${page.folderId}:${page.objectId}`)
        .digest()
        .subarray(0, 12);
      const write = await client.buildPageWriteRequest(keyring, {
        authorNpub: adminNpub,
        baseRevision: null,
        createdAtUnix: createdAtUnix + index,
        folderId: page.folderId,
        keyVersion: 1,
        nonceBytes,
        objectId: page.objectId,
        plaintext: page.text,
        signEvent: (event) => fakeSignedEvent(event, page, adminNpub),
        vaultId,
      });
      const payloadJson = JSON.stringify({
        recordType: "folder_object_revision",
        folderId: page.folderId,
        objectId: page.objectId,
        baseRevision: null,
        keyVersion: write.keyVersion,
        cipher: write.cipher,
        ciphertext: write.ciphertext,
        revisionEvent: write.revisionEvent,
      });
      const acceptedAt = new Date((createdAtUnix + index) * 1000).toISOString();
      sequence += 1;
      statements.push(
        `INSERT INTO vault_record_index (
          vault_id, sequence, record_event_id, record_type, folder_id, object_id,
          revision, actor_npub, client_created_at, payload_json, accepted_at,
          record_event_kind
        ) VALUES (
          ${sqlQuote(vaultId)}, ${sequence}, ${sqlQuote(write.revisionEvent.id)},
          'folder_object_revision', ${sqlQuote(page.folderId)}, ${sqlQuote(page.objectId)},
          1, ${sqlQuote(adminNpub)}, ${sqlQuote(acceptedAt)}, ${sqlQuote(payloadJson)},
          ${sqlQuote(acceptedAt)}, ${write.revisionEvent.kind}
        );`
      );
      statements.push(
        `INSERT INTO current_encrypted_vault_objects (
          vault_id, folder_id, object_id, payload_json, revision, updated_at, deleted
        ) VALUES (
          ${sqlQuote(vaultId)}, ${sqlQuote(page.folderId)}, ${sqlQuote(page.objectId)},
          ${sqlQuote(payloadJson)}, 1, ${sqlQuote(acceptedAt)}, 0
        );`
      );
    }

    statements.push("COMMIT;");
    sqliteExec(statements.join("\n"));
  } catch (error) {
    throw error;
  }

  const existingPages = Array.isArray(manifest.pages) ? manifest.pages : [];
  const seededIds = new Set(objectIds);
  manifest.pages = [
    ...existingPages.filter((page) => !seededIds.has(page.objectId)),
    ...pages.map(({ folderId, objectId, path, title }) => ({ folderId, objectId, title, path })),
  ].sort((left, right) =>
    `${left.folderId}/${left.objectId}`.localeCompare(`${right.folderId}/${right.objectId}`)
  );
  manifest.seededAt = createdAtIso;
  fs.writeFileSync(keyManifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(
    `Seeded ${pages.length} FiniteBrain smoke doc Pages into ${dbPath} for vault ${vaultId}.`
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
