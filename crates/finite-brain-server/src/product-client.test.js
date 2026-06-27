const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function element() {
  return {
    attributes: {},
    className: "",
    disabled: false,
    hidden: false,
    textContent: "",
    value: "",
    children: [],
    appendChild(child) {
      this.children.push(child);
    },
    addEventListener() {},
    replaceChildren() {
      this.children = [];
    },
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    },
  };
}

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

const source = fs.readFileSync(path.join(__dirname, "product-client.js"), "utf8");
vm.runInNewContext(source, context, { filename: "product-client.js" });

const client = context.window.FiniteBrainProductClient;

function objectIdCandidateBaseForTest(value) {
  return `obj_${String(value || "page")
    .trim()
    .toLowerCase()
    .replace(/\.md$/i, "")
    .replace(/[^a-z0-9_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 88) || "page"}`.padEnd(16, "0").slice(0, 112);
}

assert.equal(client.deriveSignerState(null).status, "unavailable");
assert.equal(client.deriveSignerState({ getPublicKey() {} }).status, "unsupported");
assert.equal(
  client.deriveSignerState({
    getPublicKey() {},
    signEvent() {},
  }).status,
  "ready"
);

const folderRows = client.metadataFolderRows({
  folders: [
    {
      id: "general",
      path: "General",
      access: "all_members",
      accessUserIds: [],
      currentKeyVersion: 1,
      setupIncomplete: false,
      sharedFolderSource: false,
    },
    {
      id: "restricted",
      path: "Restricted",
      access: "restricted",
      accessUserIds: [],
      currentKeyVersion: 3,
      setupIncomplete: false,
      sharedFolderSource: true,
    },
  ],
});
assert.equal(folderRows[0].status, "ready");
assert.equal(folderRows[1].status, "locked");
assert.match(folderRows[1].detail, /source/);
assert.match(folderRows[1].detail, /locked/);
const badgeLabels = (badges) => Array.from(badges, (badge) => badge.label);
assert.deepEqual(
  badgeLabels(client.accessBadgesForFolder(folderRows[1], new Set(["restricted@3"]))),
  ["restricted", "shared", "locked", "key open", "v3"]
);
assert.deepEqual(
  badgeLabels(client.accessBadgesForFolder(folderRows[1], new Set(["restricted@2"]))),
  ["restricted", "shared", "locked", "v3"]
);
assert.deepEqual(
  badgeLabels(client.sidebarAccessBadgesForFolder(folderRows[0])),
  []
);
assert.deepEqual(
  badgeLabels(client.sidebarAccessBadgesForFolder(folderRows[1])),
  ["restricted", "shared", "locked"]
);
assert.equal(
  JSON.stringify(client.accessActionRoute("share-folder", { folderId: "restricted" })),
  JSON.stringify({ folderId: "restricted", intent: "share", sidebarMode: "access" })
);
assert.equal(
  JSON.stringify(client.accessActionRoute("manage-access", { folderId: "restricted" })),
  JSON.stringify({ folderId: "restricted", intent: "manage", sidebarMode: "access" })
);
assert.equal(client.accessActionRoute("delete-folder", { folderId: "restricted" }), null);
assert.equal(client.accessPanelState("share", folderRows[1]).status, "share");
assert.match(client.accessPanelState("share", folderRows[1]).detail, /Invite by npub/);
assert.equal(client.accessPanelState("manage", folderRows[1]).title, "Manage Restricted");
assert.match(client.accessPanelState("manage", folderRows[1]).detail, /Review access state/);
assert.equal(client.accessAudienceLabel(folderRows[0]), "All members");
assert.equal(client.accessAudienceLabel(folderRows[1]), "Restricted");
assert.equal(client.accessKeyStateLabel(folderRows[1], new Set(["restricted@3"])), "Open v3");
assert.equal(client.accessKeyStateLabel(folderRows[1], new Set(["restricted@2"])), "Locked v3");
assert.equal(client.accessPageStateLabel(folderRows[1]), "No pages");

(async () => {
  const event = await client.buildAuthEventTemplate(
    "post",
    "http://finite.test/_admin/vaults/smoke/metadata",
    "{\"name\":\"Smoke\"}"
  );
  assert.equal(event.kind, 27235);
  assert.deepEqual(Array.from(event.tags[0]), [
    "u",
    "http://finite.test/_admin/vaults/smoke/metadata",
  ]);
  assert.deepEqual(Array.from(event.tags[1]), ["method", "POST"]);
  assert.equal(event.tags[2][0], "payload");
  assert.equal(event.tags[2][1].length, 64);

  const keyring = client.createSessionKeyring();
  const folderKey = Buffer.alloc(32, 7).toString("base64");
  await client.openFolderKeyGrantPlaintext(keyring, {
    version: "finite-folder-key-grant-v1",
    vaultId: "smoke",
    folderId: "general",
    keyVersion: 1,
    issuerNpub: "npub-issuer",
    recipientNpub: "npub-recipient",
    folderKey,
    issuedAt: "2026-06-24T00:00:00.000Z",
  });
  assert.equal(keyring.openedGrants.length, 1);
  await client.openFolderKeyGrantPlaintext(keyring, {
    version: "finite-folder-key-grant-v1",
    vaultId: "smoke",
    folderId: "general",
    keyVersion: 1,
    issuerNpub: "npub-issuer",
    recipientNpub: "npub-recipient",
    folderKey,
    issuedAt: "2026-06-24T00:00:00.000Z",
  });
  assert.equal(keyring.openedGrants.length, 1);

  const devGrant = {
    id: "dev-grant",
    folderId: "general",
    wrappedEventJson: JSON.stringify({
      kind: 1059,
      content: JSON.stringify({
        version: "finite-folder-key-grant-v1",
        vaultId: "smoke",
        folderId: "general",
        keyVersion: 1,
        issuerNpub: "npub-issuer",
        recipientNpub: "npub-recipient",
        folderKey,
        issuedAt: "2026-06-24T00:00:00.000Z",
      }),
    }),
  };
  assert.equal(
    client.plaintextGrantFromExportGrant(devGrant, "npub-recipient").folderId,
    "general"
  );
  assert.equal(client.plaintextGrantFromExportGrant(devGrant, "npub-other"), null);
  const devKeyring = client.createSessionKeyring();
  const devOpen = await client.openDevelopmentFolderKeyGrants(
    devKeyring,
    { keyGrants: [devGrant, { id: "opaque", wrappedEventJson: "{\"kind\":1059}" }] },
    "npub-recipient"
  );
  assert.equal(devOpen.opened.length, 1);
  assert.equal(devOpen.skipped.length, 1);
  assert.equal(devKeyring.openedGrants.length, 1);

  const authorNpub = client.npubFromHex("00".repeat(32));
  assert.match(authorNpub, /^npub1/);

  const write = await client.buildPageWriteRequest(keyring, {
    authorNpub,
    baseRevision: null,
    createdAtUnix: 1780000000,
    folderId: "general",
    keyVersion: 1,
    nonceBytes: new Uint8Array(12),
    objectId: "obj_000000000001",
    plaintext: "# Hello\n\nEncrypted locally.",
    signEvent: async (template) => ({
      ...template,
      id: "revision-event-id",
      pubkey: "00".repeat(32),
      sig: "revision-signature",
    }),
    vaultId: "smoke",
  });
  assert.equal(write.baseRevision, null);
  assert.equal(write.keyVersion, 1);
  assert.equal(write.cipher, "AES-256-GCM");
  assert.equal(write.revisionEvent.kind, 30078);
  assert.match(write.revisionEvent.content, /finite-folder-object-revision-v1/);
  assert.match(write.revisionEvent.content, /ciphertextHash/);

  const openedPage = await client.openFolderObject(keyring, {
    vaultId: "smoke",
    folderId: "general",
    objectId: "obj_000000000001",
    revision: 1,
    ciphertext: write.ciphertext,
  });
  assert.equal(openedPage.status, "ready");
  assert.equal(openedPage.text, "# Hello\n\nEncrypted locally.");

  const openedSync = await client.openSyncObjects(keyring, {
    objects: [
      {
        vaultId: "smoke",
        folderId: "general",
        objectId: "obj_000000000001",
        revision: 1,
        ciphertext: write.ciphertext,
      },
    ],
  });
  assert.equal(openedSync.objects[0].status, "ready");
  assert.equal(openedSync.objects[0].title, "Hello");

  const readerFolders = client.readerFolderRows(
    {
      folders: [
        {
          id: "general",
          path: "General",
          access: "all_members",
          accessUserIds: [],
          currentKeyVersion: 1,
          setupIncomplete: false,
          sharedFolderSource: false,
        },
        {
          id: "restricted",
          path: "Restricted",
          access: "restricted",
          accessUserIds: [],
          currentKeyVersion: 1,
          setupIncomplete: false,
          sharedFolderSource: false,
        },
      ],
    },
    openedSync.objects
  );
  assert.equal(readerFolders[0].readableCount, 1);
  assert.equal(readerFolders[0].pageCount, 1);
  assert.equal(readerFolders[0].access, "all_members");
  assert.equal(readerFolders[0].accessLabel, "all members");
  assert.equal(readerFolders[1].status, "locked");
  assert.equal(readerFolders[1].accessLabel, "restricted");
  const compatibilityRows = client.metadataFolderRows({
    folders: [
      {
        id: "architecture",
        path: "Architecture",
        access_mode: "all_members",
        access_user_ids: [],
        current_key_version: 2,
        setup_incomplete: false,
        shared_folder_source: false,
      },
      {
        id: "vault-ops",
        path: "vault-ops",
        accessMode: "AdminOnly",
        accessUserIds: [],
        currentKeyVersion: 1,
        setupIncomplete: false,
        sharedFolderSource: false,
      },
    ],
  });
  assert.equal(compatibilityRows[0].access, "all_members");
  assert.equal(compatibilityRows[0].accessLabel, "all members");
  assert.equal(compatibilityRows[0].currentKeyVersion, 2);
  assert.equal(compatibilityRows[1].access, "admin_only");
  assert.equal(compatibilityRows[1].accessLabel, "admin only");
  assert.equal(
    client.readerFolderDetail(readerFolders[0]),
    "1 page readable - all members"
  );
  assert.equal(
    client.readerFolderDetail({
      accessLabel: "all members",
      pageCount: 0,
      readableCount: 0,
    }),
    "No pages yet - all members"
  );
  assert.equal(
    client.readerFolderDetail({
      accessLabel: "restricted",
      pageCount: 2,
      readableCount: 0,
    }),
    "2 pages present, Folder Key not open - restricted"
  );
  assert.equal(client.workspaceTabTitle(null, null), "Open a Vault");
  assert.equal(client.workspaceTabTitle({ name: "Smoke" }, null), "Smoke");
  assert.equal(
    client.workspaceTabTitle({ name: "Smoke" }, { title: "Folder Object Crypto" }),
    "Folder Object Crypto"
  );
  assert.equal(client.workspaceChromeState("page").shellView, "page");
  assert.equal(client.workspaceChromeState("page").pageHidden, false);
  assert.equal(client.workspaceChromeState("page").graphHidden, true);
  assert.equal(client.workspaceChromeState("graph").shellView, "graph");
  assert.equal(client.workspaceChromeState("graph").pageHidden, true);
  assert.equal(client.workspaceChromeState("graph").graphHidden, false);
  assert.match(client.workspaceChromeState("graph").graphTabClass, /active/);
  assert.equal(client.graphEmptyStateCopy().title, "No readable graph yet");
  assert.equal(
    client.graphEmptyStateCopy({ readablePageCount: 3 }).copy,
    "Readable Pages are open, but no Page links are available for this graph projection."
  );
  assert.equal(
    client.graphEmptyStateCopy({ filterText: "folder key", readablePageCount: 3 }).title,
    "No matching Pages"
  );
  assert.equal(
    client.graphEmptyStateCopy({ filterText: "folder key", readablePageCount: 0 }).title,
    "No readable graph yet"
  );
  assert.equal(client.normalizeSidebarMode("search"), "search");
  assert.equal(client.normalizeSidebarMode("access"), "access");
  assert.equal(client.normalizeSidebarMode("bogus"), "files");
  assert.equal(
    client.vaultOnboardingComplete({
      signerStatus: "connected",
      metadata: { name: "Smoke" },
      keyring: { openedGrants: [] },
    }),
    false
  );
  assert.equal(
    client.vaultOnboardingComplete({
      signerStatus: "connected",
      metadata: { name: "Smoke" },
      keyring: { openedGrants: [{ folderId: "general", keyVersion: 1 }] },
    }),
    true
  );
  assert.equal(
    client.vaultOnboardingComplete({
      signerStatus: "connected",
      metadata: { name: "Smoke" },
      projection: { pages: new Map([["index", { status: "ready", text: "# Page" }]]) },
    }),
    true
  );
  assert.equal(
    client.vaultOnboardingComplete({
      signerStatus: "connected",
      metadata: { name: "Smoke" },
      projection: { pages: new Map([["locked", { status: "locked" }]]) },
    }),
    false
  );
  assert.equal(
    client.vaultOnboardingComplete({
      signerStatus: "connected",
      metadata: null,
      keyring: { openedGrants: [] },
    }),
    false
  );
  assert.equal(client.vaultDockDetail({ readerBusy: true }, 0, 0), "Opening vault...");
  assert.equal(client.vaultDockDetail({ signerStatus: "checking" }, 0, 0), "Connect signer");
  assert.equal(
    client.vaultDockDetail({ signerStatus: "connected", metadata: null }, 0, 0),
    "Load vault"
  );
  assert.equal(
    client.vaultDockDetail({
      signerStatus: "connected",
      metadata: { name: "Smoke" },
      projection: { pages: new Map() },
    }),
    "Open vault"
  );
  assert.equal(
    client.vaultDockDetail(
      {
        signerStatus: "connected",
        metadata: { name: "Smoke" },
        keyring: { openedGrants: [{ folderId: "general" }, { folderId: "docs" }] },
      },
      53,
      2
    ),
    "53 readable, 2 keys"
  );
  const searchRows = client.searchPageRows("folder key", [
    {
      folderId: "crypto",
      objectId: "page-a",
      path: "folder-keys.md",
      status: "ready",
      text: "# Folder Keys\n\nReadable key material stays client-side.",
      title: "Folder Keys",
    },
    {
      folderId: "sync",
      objectId: "page-b",
      path: "sync.md",
      status: "ready",
      text: "# Sync\n\nCursor notes.",
      title: "Sync",
    },
  ]);
  assert.equal(searchRows.length, 1);
  assert.equal(searchRows[0].detail, "crypto/folder-keys.md");
  const folderMenu = client.contextMenuItemsForTarget({ type: "folder", folderId: "crypto" });
  assert.equal(folderMenu.some((item) => item.action === "new-page"), true);
  assert.equal(folderMenu.some((item) => item.action === "share-folder"), true);
  assert.equal(folderMenu.find((item) => item.action === "delete-folder").disabled, true);
  const pageMenu = client.contextMenuItemsForTarget({
    type: "page",
    folderId: "crypto",
    objectId: "page-a",
  });
  assert.equal(pageMenu.some((item) => item.action === "open-graph"), true);
  assert.equal(pageMenu.find((item) => item.action === "delete-page").disabled, true);
  const readerPages = client.readerPageRows("general", openedSync.objects);
  assert.equal(readerPages[0].label, "Hello");
  const emptyReadablePage = {
    folderId: "general",
    objectId: "obj_empty_page01",
    revision: 1,
    status: "ready",
    text: "",
  };
  const readerFoldersWithEmptyPage = client.readerFolderRows(
    {
      folders: [
        {
          id: "general",
          path: "General",
          access: "all_members",
          accessUserIds: [],
          currentKeyVersion: 1,
          setupIncomplete: false,
          sharedFolderSource: false,
        },
      ],
    },
    [...openedSync.objects, emptyReadablePage]
  );
  assert.equal(readerFoldersWithEmptyPage[0].pageCount, 2);
  assert.equal(readerFoldersWithEmptyPage[0].readableCount, 2);
  const emptyReaderPage = client.readerPageRows("general", [emptyReadablePage])[0];
  assert.equal(emptyReaderPage.label, "obj_empty_page01");
  assert.match(client.nextDraftObjectId(), /^obj_[A-Za-z0-9_-]{12,124}$/);
  assert.ok(client.nextDraftObjectId().length >= 16);

  const lockedPage = await client.openFolderObject(client.createSessionKeyring(), {
    vaultId: "smoke",
    folderId: "general",
    objectId: "obj_000000000001",
    revision: 1,
    ciphertext: write.ciphertext,
  });
  assert.equal(lockedPage.status, "locked");

  const lockedSync = await client.openSyncObjects(client.createSessionKeyring(), {
    objects: [
      {
        vaultId: "smoke",
        folderId: "general",
        objectId: "obj_000000000001",
        revision: 1,
        ciphertext: write.ciphertext,
      },
    ],
  });
  assert.equal(lockedSync.objects[0].status, "locked");

  const projection = client.createClientProjection();
  projection.localDrafts.set("general/obj_000000000001", {
    baseRevision: 1,
    text: "Unresolved local edit",
  });
  const merged = client.mergeSyncProjection(projection, {
    records: [{ recordEventId: "event-a" }, { recordEventId: "event-a" }],
    objects: [
      {
        folderId: "general",
        objectId: "obj_000000000001",
        revision: 2,
        ciphertext: write.ciphertext,
      },
    ],
  });
  assert.equal(merged.seenEventIds.size, 1);
  assert.equal(merged.conflicts.length, 1);
  assert.equal(merged.conflicts[0].status, "conflict");
  assert.equal(merged.localDrafts.has("general/obj_000000000001"), true);
  assert.equal(merged.pages.has("general/obj_000000000001"), false);

  assert.deepEqual(
    Array.from(client.extractPageLinks("[[Roadmap]] [Spec](Specs/OKF.md) [Web](https://example.com)")),
    ["roadmap", "specs/okf"]
  );
  assert.equal(
    JSON.stringify(client.inlineLinkSegments("Read [[Roadmap]] and [Spec](Specs/OKF.md).")),
    JSON.stringify([
      { kind: "text", text: "Read " },
      { kind: "internal", target: "roadmap", text: "Roadmap" },
      { kind: "text", text: " and " },
      { kind: "internal", target: "specs/okf", text: "Spec" },
      { kind: "text", text: "." },
    ])
  );
  assert.equal(
    JSON.stringify(client.inlineLinkSegments("Read [[Roadmap#Now|Q3 roadmap]].")),
    JSON.stringify([
      { kind: "text", text: "Read " },
      { kind: "internal", target: "roadmap", text: "Q3 roadmap" },
      { kind: "text", text: "." },
    ])
  );
  assert.equal(
    JSON.stringify(client.markdownPreviewBlocks("# Title\n\n- One\n- Two\n\n> Note\n\n```js\nconst ok = true;\n```")),
    JSON.stringify([
      { level: 1, text: "Title", type: "heading" },
      { items: ["One", "Two"], type: "list" },
      { text: "Note", type: "quote" },
      { text: "const ok = true;", type: "code" },
    ])
  );
  assert.equal(JSON.stringify(client.pageStatsForText("# Title\n\nSee [[Roadmap]] and words.")), JSON.stringify({
    links: 1,
    words: 6,
  }));
  const linkContext = client.pageLinkContext(
    {
      folderId: "general",
      key: "general/alpha",
      objectId: "alpha",
      status: "ready",
      text: "# Alpha\n\nSee [[Beta]] and [[Missing]].",
      title: "Alpha",
    },
    [
      {
        folderId: "general",
        key: "general/alpha",
        objectId: "alpha",
        status: "ready",
        text: "# Alpha\n\nSee [[Beta]] and [[Missing]].",
        title: "Alpha",
      },
      {
        folderId: "general",
        key: "general/beta",
        objectId: "beta",
        status: "ready",
        text: "# Beta\n\nBack to [[Alpha]].",
        title: "Beta",
      },
      {
        folderId: "restricted",
        key: "restricted/locked",
        objectId: "locked",
        status: "locked",
        text: "# Locked\n\n[[Alpha]]",
        title: "Locked",
      },
    ]
  );
  assert.equal(
    JSON.stringify(linkContext.outgoing.map((row) => [row.label, row.status])),
    JSON.stringify([
      ["Beta", "resolved"],
      ["missing", "missing"],
    ])
  );
  assert.equal(
    JSON.stringify(linkContext.backlinks.map((row) => [row.label, row.key])),
    JSON.stringify([["Beta", "general/beta"]])
  );
  const pathLinkContext = client.pageLinkContext(
    {
      folderId: "docs",
      key: "docs/intro",
      objectId: "intro",
      path: "docs/intro.md",
      status: "ready",
      text: "# Intro\n\nSee [Deep Dive](deep-dive.md).",
      title: "Intro",
    },
    [
      {
        folderId: "docs",
        key: "docs/intro",
        objectId: "intro",
        path: "docs/intro.md",
        status: "ready",
        text: "# Intro\n\nSee [Deep Dive](deep-dive.md).",
        title: "Intro",
      },
      {
        folderId: "docs",
        key: "docs/deep-dive",
        objectId: "deep-dive",
        path: "docs/deep-dive.md",
        status: "ready",
        text: "# Deep Dive\n\nBack to [Intro](intro.md).",
        title: "Deep Dive",
      },
    ]
  );
  assert.equal(
    JSON.stringify(pathLinkContext.outgoing.map((row) => [row.label, row.status])),
    JSON.stringify([["Deep Dive", "resolved"]])
  );
  assert.equal(
    JSON.stringify(pathLinkContext.backlinks.map((row) => [row.label, row.key])),
    JSON.stringify([["Deep Dive", "docs/deep-dive"]])
  );

  const okfInput = {
    manifest: {
      version: "finite-okf-vault-export-v1",
      objects: [
        {
          folderId: "source-concepts",
          objectId: "obj_source_alpha1",
          path: "content/Concepts/alpha.md",
          contentType: "text/markdown",
          contentHash: "hash-alpha",
        },
        {
          folderId: "source-concepts",
          objectId: "obj_source_beta01",
          path: "content/Concepts/beta.md",
          contentType: "text/markdown",
          contentHash: "hash-beta",
        },
      ],
      omissions: [{ folderId: "secret", displayPath: "Secret", reason: "inaccessible" }],
    },
    files: {
      "content/Concepts/alpha.md": "# Alpha\n\nSee [Beta](beta.md) and [[Loose Wiki]].",
      "content/Concepts/beta.md": "# Beta\n\nImported target.",
    },
  };
  const parsedOkf = client.parseOkfBundle(JSON.stringify(okfInput), {
    destinationFolderId: "general",
  });
  assert.equal(parsedOkf.pages.length, 2);
  assert.equal(parsedOkf.pages[0].folderId, "general");
  assert.equal(parsedOkf.pages[0].targetPath, "alpha.md");
  assert.deepEqual(Array.from(parsedOkf.pages[0].links), ["loose wiki", "beta"]);
  assert.equal(parsedOkf.omissions[0].reason, "inaccessible");

  const skipPlan = client.planOkfImport(
    parsedOkf,
    [
      {
        folderId: "general",
        objectId: "obj_existing_alpha_01",
        path: "alpha.md",
        revision: 3,
      },
      {
        folderId: "general",
        objectId: "obj_existing_beta_01",
        path: "beta.md",
        revision: 7,
      },
    ],
    { conflictMode: "skip" }
  );
  assert.equal(skipPlan.summary.skip, 2);
  assert.equal(skipPlan.entries.every((entry) => entry.action === "skip"), true);

  const copyPlan = client.planOkfImport(
    parsedOkf,
    [
      {
        folderId: "general",
        objectId: "obj_existing_beta_01",
        path: "beta.md",
        revision: 7,
      },
    ],
    { conflictMode: "copy" }
  );
  const copyAlpha = copyPlan.entries.find((entry) => entry.targetPath === "alpha.md");
  const copyBeta = copyPlan.entries.find((entry) => entry.action === "copy");
  assert.equal(copyPlan.summary.create, 1);
  assert.equal(copyPlan.summary.copy, 1);
  assert.equal(copyBeta.targetPath, "beta imported.md");
  assert.match(copyAlpha.markdown, /\[Beta\]\(beta imported\.md\)/);

  const saturatedObjectIdBase = objectIdCandidateBaseForTest("beta imported.md");
  const saturatedObjectPages = Array.from({ length: 1000 }, (_, index) => ({
    folderId: "general",
    objectId: index === 0 ? saturatedObjectIdBase : `${saturatedObjectIdBase}_${index + 1}`,
    path: `collision-${index}.md`,
    revision: 1,
  }));
  assert.throws(
    () =>
      client.planOkfImport(
        parsedOkf,
        [
          {
            folderId: "general",
            objectId: "obj_existing_beta_01",
            path: "beta.md",
            revision: 7,
          },
          ...saturatedObjectPages,
        ],
        { conflictMode: "copy" }
      ),
    /could not allocate import object id for beta imported\.md/
  );

  const overwritePlan = client.planOkfImport(
    parsedOkf,
    [
      {
        folderId: "general",
        objectId: "obj_existing_alpha_01",
        path: "alpha.md",
        revision: 3,
      },
    ],
    { conflictMode: "overwrite" }
  );
  assert.equal(overwritePlan.entries[0].action, "overwrite");
  assert.equal(overwritePlan.entries[0].baseRevision, 3);
  assert.equal(overwritePlan.entries[0].objectId, "obj_existing_alpha_01");

  await assert.rejects(
    () =>
      client.prepareOkfImportWrites(client.createSessionKeyring(), copyPlan, {
        authorNpub,
        signEvent: async (template) => template,
        vaultId: "smoke",
      }),
    /Folder Key is not open for general/
  );

  const preparedImport = await client.prepareOkfImportWrites(keyring, copyPlan, {
    authorNpub,
    createdAtUnix: 1780000001,
    nonceFactory: (index) => new Uint8Array(12).fill(index + 1),
    signEvent: async (template) => ({
      ...template,
      id: `import-event-${template.created_at}`,
      pubkey: "00".repeat(32),
      sig: "import-signature",
    }),
    vaultId: "smoke",
  });
  assert.equal(preparedImport.writes.length, 2);
  assert.equal(preparedImport.skipped.length, 0);
  assert.match(preparedImport.writes[0].path, /\/_admin\/vaults\/smoke\/folders\/general\/objects\/obj_/);
  assert.equal(preparedImport.writes[0].body.revisionEvent.kind, 30078);

  const openedImportedAlpha = await client.openFolderObject(keyring, {
    vaultId: "smoke",
    folderId: preparedImport.writes[0].folderId,
    objectId: preparedImport.writes[0].objectId,
    revision: 1,
    ciphertext: preparedImport.writes[0].body.ciphertext,
  });
  assert.equal(openedImportedAlpha.status, "ready");
  assert.match(openedImportedAlpha.text, /\[Beta\]\(beta imported\.md\)/);

  const graph = client.buildGraphProjection([
    {
      folderId: "general",
      objectId: "page-a",
      status: "ready",
      text: "# Alpha\n\nLinks to [[Beta]] and [[Hidden]].",
    },
    {
      folderId: "general",
      objectId: "page-b",
      status: "ready",
      text: "# Beta\n\nBack to [Alpha](Alpha.md).",
    },
    {
      folderId: "restricted",
      objectId: "page-hidden",
      status: "locked",
      text: "# Hidden\n\nThis must not appear.",
    },
  ]);
  assert.deepEqual(
    Array.from(graph.nodes.map((node) => node.title).sort()),
    ["Alpha", "Beta"]
  );
  assert.equal(graph.edges.length, 2);
  assert.equal(graph.edges.some((edge) => edge.id.includes("page-hidden")), false);
  const graphMetrics = client.graphStats(graph, 3);
  assert.equal(graphMetrics.edgeCount, 2);
  assert.equal(graphMetrics.filteredOutCount, 1);
  assert.equal(graphMetrics.nodeCount, 2);

  const filteredGraph = client.buildGraphProjection(
    [
      {
        folderId: "general",
        objectId: "page-a",
        status: "ready",
        text: "# Alpha\n\n[[Beta]]",
      },
      {
        folderId: "general",
        objectId: "page-b",
        status: "ready",
        text: "# Beta",
      },
    ],
    "beta"
  );
  assert.deepEqual(
    Array.from(filteredGraph.nodes.map((node) => node.title).sort()),
    ["Alpha", "Beta"]
  );
  const layout = client.graphLayout(graph, { height: 260, margin: 40, width: 320 });
  assert.equal(layout.size, 2);
  for (const position of layout.values()) {
    assert.equal(position.x >= 40 && position.x <= 280, true);
    assert.equal(position.y >= 40 && position.y <= 220, true);
  }
  assert.equal(
    JSON.stringify(Array.from(client.graphLayout(graph, { height: 260, margin: 40, width: 320 }).entries())),
    JSON.stringify(Array.from(layout.entries()))
  );
  const hubGraph = client.buildGraphProjection([
    {
      folderId: "general",
      objectId: "hub",
      status: "ready",
      text: "# Hub\n\n[[One]] [[Two]] [[Three]] [[Four]]",
    },
    { folderId: "general", objectId: "one", status: "ready", text: "# One" },
    { folderId: "general", objectId: "two", status: "ready", text: "# Two" },
    { folderId: "general", objectId: "three", status: "ready", text: "# Three" },
    { folderId: "general", objectId: "four", status: "ready", text: "# Four" },
  ]);
  const hubLayout = client.graphLayout(hubGraph, { height: 300, margin: 60, width: 400 });
  assert.equal(JSON.stringify(hubLayout.get("general/hub")), JSON.stringify({ x: 200, y: 150 }));

  const replay = client.buildReplayFrames([
    {
      sequence: 2,
      recordEventId: "event-b",
      page: {
        folderId: "general",
        objectId: "page-b",
        status: "ready",
        text: "# Beta",
      },
    },
    {
      sequence: 1,
      recordEventId: "event-a",
      page: {
        folderId: "general",
        objectId: "page-a",
        status: "ready",
        text: "# Alpha\n\n[[Beta]]",
      },
    },
    {
      sequence: 2,
      recordEventId: "event-b",
      page: {
        folderId: "general",
        objectId: "page-b",
        status: "ready",
        text: "# Duplicate",
      },
    },
  ]);
  assert.equal(replay.length, 2);
  assert.deepEqual(
    Array.from(replay.map((frame) => frame.sequence)),
    [1, 2]
  );
  assert.equal(replay[0].nodeCount, 1);
  assert.equal(replay[1].nodeCount, 2);
  assert.equal(replay[1].edgeCount, 1);

  console.log("product-client deterministic seams ok");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
