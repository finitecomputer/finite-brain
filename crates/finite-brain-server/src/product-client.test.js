const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function element() {
  return {
    className: "",
    disabled: false,
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

  const lockedPage = await client.openFolderObject(client.createSessionKeyring(), {
    vaultId: "smoke",
    folderId: "general",
    objectId: "obj_000000000001",
    revision: 1,
    ciphertext: write.ciphertext,
  });
  assert.equal(lockedPage.status, "locked");

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

  console.log("product-client deterministic seams ok");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
