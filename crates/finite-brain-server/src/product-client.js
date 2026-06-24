const FiniteBrainProductClient = (() => {
  const state = {
    config: null,
    signerStatus: "checking",
    pubkeyHex: null,
    activeVaultId: "smoke",
    metadata: null,
    keyring: null,
    lastError: null,
    preparedWrite: null,
    preparedWriteTarget: null,
    okfPlan: null,
    projection: createClientProjection(),
    readerBusy: false,
    selectedFolderId: null,
    selectedPageKey: null,
    activeWorkspaceView: "page",
    activeSidebarMode: "files",
    expandedFolderIds: new Set(),
    contextMenuTarget: null,
  };

  const $ = (id) => document.getElementById(id);
  const CIPHER = "AES-256-GCM";
  const FOLDER_OBJECT_VERSION = "finite-folder-object-v1";
  const REVISION_VERSION = "finite-folder-object-revision-v1";
  const APP_EVENT_KIND = 30078;
  const MAX_OBJECT_ID_ATTEMPTS = 1000;
  const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const graphViewport = { height: 560, width: 900 };

  function shortKey(value) {
    if (!value) return "-";
    if (value.length <= 18) return value;
    return `${value.slice(0, 10)}...${value.slice(-8)}`;
  }

  function deriveSignerState(provider) {
    if (!provider) {
      return {
        status: "unavailable",
        label: "missing",
        detail: "No NIP-07 signer was found in this browser.",
        canConnect: false,
      };
    }
    if (typeof provider.getPublicKey !== "function" || typeof provider.signEvent !== "function") {
      return {
        status: "unsupported",
        label: "unsupported",
        detail: "A signer is present, but it does not expose getPublicKey and signEvent.",
        canConnect: false,
      };
    }
    return {
      status: "ready",
      label: "ready",
      detail: "NIP-07 signer detected. Connect to load protected Vault state.",
      canConnect: true,
    };
  }

  function folderStatus(folder) {
    if (folder.setupIncomplete) return "setup";
    if (folder.access === "restricted" && (folder.accessUserIds || []).length === 0) {
      return "locked";
    }
    return "ready";
  }

  function folderAccessLabel(access) {
    return (
      {
        admin_only: "admin only",
        all_members: "all members",
        restricted: "restricted",
      }[access] || access || "unknown access"
    );
  }

  function metadataFolderRows(metadata) {
    return (metadata?.folders || []).map((folder) => {
      const status = folderStatus(folder);
      const accessLabel = folderAccessLabel(folder.access);
      const flags = [];
      if (folder.sharedFolderSource) flags.push("source");
      if (folder.setupIncomplete) flags.push("setup needed");
      if (status === "locked") flags.push("locked");
      return {
        access: folder.access,
        accessLabel,
        currentKeyVersion: folder.currentKeyVersion,
        id: folder.id,
        path: folder.path,
        status,
        label: `${folder.path} - ${accessLabel} - key v${folder.currentKeyVersion}`,
        detail: flags.join(", "),
      };
    });
  }

  function metadataMountRows(metadata) {
    return (metadata?.mountedFolders || []).map((mount) => ({
      id: mount.mountId,
      label: `${mount.displayName} -> ${mount.sourceVaultId}/${mount.sourceFolderId}`,
      state: mount.state,
    }));
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  function hexToBytes(value) {
    if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
      throw new Error("hex value is invalid");
    }
    const bytes = new Uint8Array(value.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }

  function convertBits(data, fromBits, toBits, pad) {
    let accumulator = 0;
    let bits = 0;
    const result = [];
    const maxValue = (1 << toBits) - 1;
    for (const value of data) {
      if (value < 0 || value >> fromBits !== 0) throw new Error("invalid bech32 source value");
      accumulator = (accumulator << fromBits) | value;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        result.push((accumulator >> bits) & maxValue);
      }
    }
    if (pad && bits > 0) {
      result.push((accumulator << (toBits - bits)) & maxValue);
    } else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue) !== 0) {
      throw new Error("invalid bech32 padding");
    }
    return result;
  }

  function bech32Polymod(values) {
    const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let checksum = 1;
    for (const value of values) {
      const top = checksum >> 25;
      checksum = ((checksum & 0x1ffffff) << 5) ^ value;
      for (let index = 0; index < 5; index += 1) {
        if ((top >> index) & 1) checksum ^= generators[index];
      }
    }
    return checksum;
  }

  function bech32HrpExpand(hrp) {
    const result = [];
    for (let index = 0; index < hrp.length; index += 1) {
      result.push(hrp.charCodeAt(index) >> 5);
    }
    result.push(0);
    for (let index = 0; index < hrp.length; index += 1) {
      result.push(hrp.charCodeAt(index) & 31);
    }
    return result;
  }

  function bech32Encode(hrp, data) {
    const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
    const polymod = bech32Polymod(values) ^ 1;
    const checksum = [];
    for (let index = 0; index < 6; index += 1) {
      checksum.push((polymod >> (5 * (5 - index))) & 31);
    }
    return `${hrp}1${[...data, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
  }

  function npubFromHex(pubkeyHex) {
    return bech32Encode("npub", convertBits(hexToBytes(pubkeyHex), 8, 5, true));
  }

  function createClientProjection() {
    return {
      pages: new Map(),
      seenEventIds: new Set(),
      localDrafts: new Map(),
      conflicts: [],
    };
  }

  function pageKey(folderId, objectId) {
    return `${folderId}/${objectId}`;
  }

  function createSessionKeyring() {
    return {
      keys: new Map(),
      openedGrants: [],
    };
  }

  function folderKeyId(vaultId, folderId, keyVersion) {
    return `${vaultId}:${folderId}:${keyVersion}`;
  }

  async function importFolderKey(keyring, { vaultId, folderId, keyVersion, folderKey }) {
    const rawKey = base64ToBytes(folderKey);
    if (rawKey.length !== 32) throw new Error("Folder Key must be 32 bytes");
    const cryptoKey = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
    const id = folderKeyId(vaultId, folderId, keyVersion);
    keyring.keys.set(id, {
      cryptoKey,
      folderId,
      keyVersion,
      rawKey,
      vaultId,
    });
    return keyring.keys.get(id);
  }

  async function openFolderKeyGrantPlaintext(keyring, grantPlaintext) {
    if (grantPlaintext.version !== "finite-folder-key-grant-v1") {
      throw new Error("unsupported Folder Key Grant version");
    }
    const opened = await importFolderKey(keyring, grantPlaintext);
    const alreadyOpened = keyring.openedGrants.some(
      (grant) =>
        grant.folderId === grantPlaintext.folderId &&
        grant.keyVersion === grantPlaintext.keyVersion &&
        grant.recipientNpub === grantPlaintext.recipientNpub &&
        grant.vaultId === grantPlaintext.vaultId
    );
    if (!alreadyOpened) {
      keyring.openedGrants.push({
        folderId: grantPlaintext.folderId,
        issuerNpub: grantPlaintext.issuerNpub,
        keyVersion: grantPlaintext.keyVersion,
        recipientNpub: grantPlaintext.recipientNpub,
        vaultId: grantPlaintext.vaultId,
      });
    }
    return opened;
  }

  function plaintextGrantFromExportGrant(grant, expectedRecipientNpub = null) {
    if (!grant?.wrappedEventJson) return null;
    let wrapped;
    try {
      wrapped = JSON.parse(grant.wrappedEventJson);
    } catch (_) {
      return null;
    }
    if (typeof wrapped.content !== "string") return null;
    let plaintext;
    try {
      plaintext = JSON.parse(wrapped.content);
    } catch (_) {
      return null;
    }
    if (plaintext.version !== "finite-folder-key-grant-v1" || !plaintext.folderKey) return null;
    if (expectedRecipientNpub && plaintext.recipientNpub !== expectedRecipientNpub) return null;
    return plaintext;
  }

  async function openDevelopmentFolderKeyGrants(keyring, exportedVault, expectedRecipientNpub = null) {
    const opened = [];
    const skipped = [];
    for (const grant of exportedVault?.keyGrants || []) {
      const plaintext = plaintextGrantFromExportGrant(grant, expectedRecipientNpub);
      if (!plaintext) {
        skipped.push(grant.id || grant.folderId || "unknown-grant");
        continue;
      }
      await openFolderKeyGrantPlaintext(keyring, plaintext);
      opened.push({
        folderId: plaintext.folderId,
        keyVersion: plaintext.keyVersion,
      });
    }
    return { opened, skipped };
  }

  function canonicalFolderObjectAad({ vaultId, folderId, objectId, keyVersion }) {
    return `{"version":${JSON.stringify(FOLDER_OBJECT_VERSION)},"vaultId":${JSON.stringify(
      vaultId
    )},"folderId":${JSON.stringify(folderId)},"objectId":${JSON.stringify(
      objectId
    )},"keyVersion":${keyVersion}}`;
  }

  function canonicalEnvelope({ keyVersion, nonce, ciphertext }) {
    return `{"version":${JSON.stringify(FOLDER_OBJECT_VERSION)},"cipher":${JSON.stringify(
      CIPHER
    )},"keyVersion":${keyVersion},"nonce":${JSON.stringify(nonce)},"ciphertext":${JSON.stringify(
      ciphertext
    )}}`;
  }

  async function encryptFolderObject(keyring, input) {
    const key = keyring.keys.get(folderKeyId(input.vaultId, input.folderId, input.keyVersion));
    if (!key) throw new Error(`No Folder Key opened for ${input.folderId} v${input.keyVersion}`);
    const nonce = input.nonceBytes || crypto.getRandomValues(new Uint8Array(12));
    if (nonce.length !== 12) throw new Error("AES-GCM nonce must be 12 bytes");
    const aad = new TextEncoder().encode(canonicalFolderObjectAad(input));
    const plaintext = new TextEncoder().encode(input.plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad },
      key.cryptoKey,
      plaintext
    );
    return canonicalEnvelope({
      keyVersion: input.keyVersion,
      nonce: bytesToBase64(nonce),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    });
  }

  async function openFolderObject(keyring, input) {
    const envelope = typeof input.ciphertext === "string" ? JSON.parse(input.ciphertext) : input.ciphertext;
    const key = keyring.keys.get(folderKeyId(input.vaultId, input.folderId, envelope.keyVersion));
    if (!key) {
      return {
        folderId: input.folderId,
        objectId: input.objectId,
        revision: input.revision,
        status: "locked",
      };
    }
    const aad = new TextEncoder().encode(
      canonicalFolderObjectAad({
        vaultId: input.vaultId,
        folderId: input.folderId,
        objectId: input.objectId,
        keyVersion: envelope.keyVersion,
      })
    );
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(envelope.nonce),
        additionalData: aad,
      },
      key.cryptoKey,
      base64ToBytes(envelope.ciphertext)
    );
    return {
      folderId: input.folderId,
      objectId: input.objectId,
      revision: input.revision,
      status: "ready",
      text: new TextDecoder().decode(plaintext),
    };
  }

  async function ciphertextHash(envelopeJson) {
    return sha256Hex(envelopeJson);
  }

  function revisionCreatedAt(createdAtUnix) {
    return new Date(createdAtUnix * 1000).toISOString();
  }

  function canonicalRevisionPayload(input) {
    const baseRevision = input.baseRevision === undefined ? null : input.baseRevision;
    return `{"version":${JSON.stringify(REVISION_VERSION)},"vaultId":${JSON.stringify(
      input.vaultId
    )},"folderId":${JSON.stringify(input.folderId)},"objectId":${JSON.stringify(
      input.objectId
    )},"operation":${JSON.stringify(input.operation)},"revision":${
      input.revision
    },"baseRevision":${baseRevision === null ? "null" : baseRevision},"keyVersion":${
      input.keyVersion
    },"cipher":${JSON.stringify(CIPHER)},"ciphertextHash":${JSON.stringify(
      input.ciphertextHash
    )},"authorNpub":${JSON.stringify(input.authorNpub)},"createdAt":${JSON.stringify(
      input.createdAt
    )}}`;
  }

  async function buildPageWriteRequest(keyring, input) {
    const baseRevision =
      input.baseRevision === "" || input.baseRevision === undefined || input.baseRevision === null
        ? null
        : Number(input.baseRevision);
    const revision = baseRevision === null ? 1 : baseRevision + 1;
    const envelopeJson = await encryptFolderObject(keyring, {
      folderId: input.folderId,
      keyVersion: input.keyVersion,
      nonceBytes: input.nonceBytes,
      objectId: input.objectId,
      plaintext: input.plaintext,
      vaultId: input.vaultId,
    });
    const createdAtUnix = input.createdAtUnix || Math.floor(Date.now() / 1000);
    const payload = canonicalRevisionPayload({
      authorNpub: input.authorNpub,
      baseRevision,
      ciphertextHash: await ciphertextHash(envelopeJson),
      createdAt: revisionCreatedAt(createdAtUnix),
      folderId: input.folderId,
      keyVersion: input.keyVersion,
      objectId: input.objectId,
      operation: input.operation || (baseRevision === null ? "create" : "update"),
      revision,
      vaultId: input.vaultId,
    });
    const eventTemplate = {
      kind: APP_EVENT_KIND,
      created_at: createdAtUnix,
      tags: [],
      content: payload,
    };
    const revisionEvent = await input.signEvent(eventTemplate);
    return {
      baseRevision,
      keyVersion: input.keyVersion,
      cipher: CIPHER,
      ciphertext: envelopeJson,
      revisionEvent,
    };
  }

  function mergeSyncProjection(projection, sync) {
    const next = {
      pages: new Map(projection.pages),
      seenEventIds: new Set(projection.seenEventIds),
      localDrafts: new Map(projection.localDrafts),
      conflicts: [...projection.conflicts],
    };
    for (const record of sync.records || []) {
      if (next.seenEventIds.has(record.recordEventId)) continue;
      next.seenEventIds.add(record.recordEventId);
    }
    for (const object of sync.objects || []) {
      const key = pageKey(object.folderId, object.objectId);
      const localDraft = next.localDrafts.get(key);
      if (localDraft && object.revision > localDraft.baseRevision) {
        next.conflicts.push({
          folderId: object.folderId,
          objectId: object.objectId,
          localBaseRevision: localDraft.baseRevision,
          serverRevision: object.revision,
          status: "conflict",
        });
        continue;
      }
      next.pages.set(key, object);
    }
    return next;
  }

  async function openSyncObjects(keyring, sync) {
    if (!keyring) return sync;
    const objects = await Promise.all(
      (sync.objects || []).map(async (object) => {
        if (object.deleted) return object;
        try {
          const opened = await openFolderObject(keyring, object);
          return {
            ...object,
            ...opened,
            title: opened.text ? pageTitleFromText(opened.text, object.objectId) : object.title,
          };
        } catch (error) {
          return {
            ...object,
            error: error.message,
            status: "locked",
          };
        }
      })
    );
    return {
      ...sync,
      objects,
    };
  }

  function pageTitleFromText(text, fallback) {
    const heading = String(text || "").match(/^#\s+(.+)$/m);
    return heading ? heading[1].trim() : fallback;
  }

  function normalizePageReference(value) {
    return String(value || "")
      .trim()
      .replace(/^\.?\//, "")
      .replace(/\.md$/i, "")
      .replace(/^#/, "")
      .toLowerCase();
  }

  function extractPageLinks(text) {
    const links = new Set();
    const wikiPattern = /\[\[([^\]|#]+)(?:[|#][^\]]*)?\]\]/g;
    const markdownPattern = /\[[^\]]+\]\(([^)]+)\)/g;
    for (const match of String(text || "").matchAll(wikiPattern)) {
      links.add(normalizePageReference(match[1]));
    }
    for (const match of String(text || "").matchAll(markdownPattern)) {
      const target = match[1].split("#")[0];
      if (!/^https?:\/\//i.test(target)) links.add(normalizePageReference(target));
    }
    return [...links].filter(Boolean);
  }

  function normalizeSafeRelativePath(value, label = "path") {
    const normalized = String(value || "")
      .trim()
      .replace(/^\.\/+/, "");
    if (
      !normalized ||
      normalized.startsWith("/") ||
      normalized.includes("\\") ||
      normalized.split("/").some((segment) => !segment || segment === "." || segment === "..") ||
      [".finitebrain", "_admin", ".git"].includes(normalized.split("/")[0])
    ) {
      throw new Error(`${label} must be a safe relative path`);
    }
    return normalized;
  }

  function targetPathFromBundlePath(path) {
    const safePath = normalizeSafeRelativePath(path, "OKF object path");
    const parts = safePath.split("/");
    if (parts[0] === "content" && parts.length >= 3) return parts.slice(2).join("/");
    return safePath;
  }

  function parseOkfBundle(input, options = {}) {
    const source = typeof input === "string" ? JSON.parse(input) : input;
    if (!source || typeof source !== "object") throw new Error("OKF bundle must be a JSON object");

    const files = new Map();
    const sourceFiles = source.files || source;
    for (const [path, content] of Object.entries(sourceFiles || {})) {
      if (typeof content === "string" && (path.endsWith(".md") || path === "okf-vault.json")) {
        files.set(normalizeSafeRelativePath(path, "OKF file path"), content);
      }
    }

    const manifest =
      source.manifest ||
      (files.has("okf-vault.json") ? JSON.parse(files.get("okf-vault.json")) : null);
    const pages = [];
    if (Array.isArray(source.pages)) {
      source.pages.forEach((page, index) => {
        const sourcePath = normalizeSafeRelativePath(
          page.sourcePath || page.path || page.targetPath || `import/page-${index + 1}.md`,
          "OKF page source path"
        );
        const targetPath = normalizeSafeRelativePath(
          page.targetPath || page.pagePath || targetPathFromBundlePath(page.path || sourcePath),
          "OKF page target path"
        );
        const markdown = page.markdown ?? page.content;
        if (typeof markdown !== "string") throw new Error(`OKF page ${sourcePath} is missing content`);
        pages.push({
          sourceFolderId: page.folderId || null,
          sourceObjectId: page.objectId || null,
          sourcePath,
          folderId: options.destinationFolderId || page.targetFolderId || page.folderId || "general",
          targetPath,
          markdown,
          contentType: page.contentType || "text/markdown",
          links: extractPageLinks(markdown),
        });
      });
    } else if (manifest?.objects) {
      for (const object of manifest.objects) {
        const sourcePath = normalizeSafeRelativePath(object.path, "OKF manifest object path");
        const markdown = files.get(sourcePath);
        if (typeof markdown !== "string") throw new Error(`OKF file missing for ${sourcePath}`);
        pages.push({
          sourceFolderId: object.folderId || null,
          sourceObjectId: object.objectId || null,
          sourcePath,
          folderId: options.destinationFolderId || object.targetFolderId || object.folderId || "general",
          targetPath: normalizeSafeRelativePath(
            object.targetPath || object.pagePath || targetPathFromBundlePath(sourcePath),
            "OKF page target path"
          ),
          markdown,
          contentType: object.contentType || "text/markdown",
          links: extractPageLinks(markdown),
        });
      }
    } else {
      for (const [sourcePath, markdown] of files.entries()) {
        if (sourcePath === "okf-vault.json" || sourcePath.startsWith("_wiki/")) continue;
        pages.push({
          sourceFolderId: null,
          sourceObjectId: null,
          sourcePath,
          folderId: options.destinationFolderId || "general",
          targetPath: targetPathFromBundlePath(sourcePath),
          markdown,
          contentType: "text/markdown",
          links: extractPageLinks(markdown),
        });
      }
    }

    return {
      version: manifest?.version || source.version || "finite-okf-vault-import-v1",
      pages,
      omissions: manifest?.omissions || source.omissions || [],
    };
  }

  function normalizeExistingPageRecord(record) {
    const folderId = record.folderId || "general";
    const path =
      record.path ||
      record.pagePath ||
      record.targetPath ||
      (record.title ? `${slugForObjectId(record.title)}.md` : `${record.objectId}.md`);
    return {
      folderId,
      objectId: record.objectId,
      revision: Number(record.revision || 0),
      targetPath: normalizeSafeRelativePath(path, "existing Page path"),
    };
  }

  function targetKey(folderId, targetPath) {
    return `${folderId}\n${targetPath}`;
  }

  function slugForObjectId(value) {
    return String(value || "page")
      .trim()
      .toLowerCase()
      .replace(/\.md$/i, "")
      .replace(/[^a-z0-9_-]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 88) || "page";
  }

  function validObjectId(value) {
    return /^[A-Za-z0-9_-]{16,128}$/.test(value || "") && !String(value).includes(".");
  }

  function objectIdForTargetPath(targetPath, occupiedObjectIds) {
    const base = `obj_${slugForObjectId(targetPath)}`.padEnd(16, "0").slice(0, 112);
    let candidate = base;
    let index = 2;
    while (occupiedObjectIds.has(candidate) || !validObjectId(candidate)) {
      if (index > MAX_OBJECT_ID_ATTEMPTS) {
        throw new Error(`could not allocate import object id for ${targetPath}`);
      }
      candidate = `${base}_${index}`.slice(0, 128);
      index += 1;
    }
    occupiedObjectIds.add(candidate);
    return candidate;
  }

  function uniqueImportedCopyPath(folderId, targetPath, occupiedTargets) {
    const safePath = normalizeSafeRelativePath(targetPath, "copy target path");
    const [stem, extension] = safePath.toLowerCase().endsWith(".md")
      ? [safePath.slice(0, -3), ".md"]
      : [safePath, ""];
    for (let index = 1; index <= 1000; index += 1) {
      const suffix = index === 1 ? " imported" : ` imported ${index}`;
      const candidate = normalizeSafeRelativePath(`${stem}${suffix}${extension}`, "copy target path");
      if (!occupiedTargets.has(targetKey(folderId, candidate))) return candidate;
    }
    throw new Error(`Could not allocate copy path for ${targetPath}`);
  }

  function resolveRelativePath(fromPath, target) {
    if (!target || target.startsWith("#") || /^https?:\/\//i.test(target) || target.startsWith("mailto:")) {
      return null;
    }
    const cleanTarget = target.split("#")[0];
    if (cleanTarget.startsWith("/") || cleanTarget.includes("\\")) return null;
    const parts = fromPath.split("/");
    parts.pop();
    for (const segment of cleanTarget.split("/")) {
      if (!segment || segment === ".") continue;
      if (segment === "..") {
        if (!parts.length) return null;
        parts.pop();
      } else {
        parts.push(segment);
      }
    }
    try {
      return normalizeSafeRelativePath(parts.join("/"), "OKF link target");
    } catch (_) {
      return null;
    }
  }

  function relativePathBetween(fromPath, toPath) {
    const from = fromPath.split("/");
    from.pop();
    const to = toPath.split("/");
    let common = 0;
    while (common < from.length && common < to.length && from[common] === to[common]) common += 1;
    return [...Array(from.length - common).fill(".."), ...to.slice(common)].join("/") || toPath;
  }

  function rewriteOkfMarkdownLinks(markdown, sourcePath, targetPath, sourcePathToEntry) {
    return String(markdown || "").replace(/\[([^\]]+)\]\(([^)]+)\)/g, (original, label, href) => {
      const resolved = resolveRelativePath(sourcePath, href);
      if (!resolved) return original;
      const target = sourcePathToEntry.get(resolved);
      if (!target || target.action === "skip") return original;
      return `[${label}](${relativePathBetween(targetPath, target.targetPath)})`;
    });
  }

  function planOkfImport(bundleOrInput, existingPages = [], options = {}) {
    const bundle = bundleOrInput?.pages ? bundleOrInput : parseOkfBundle(bundleOrInput, options);
    const mode = options.conflictMode || "skip";
    if (!["skip", "copy", "overwrite"].includes(mode)) {
      throw new Error("OKF conflict mode must be skip, copy, or overwrite");
    }

    const existingByPath = new Map();
    const occupiedTargets = new Set();
    const occupiedObjectIds = new Set();
    for (const page of existingPages.map(normalizeExistingPageRecord)) {
      existingByPath.set(targetKey(page.folderId, page.targetPath), page);
      occupiedTargets.add(targetKey(page.folderId, page.targetPath));
      if (page.objectId) occupiedObjectIds.add(page.objectId);
    }

    const entries = [];
    for (const page of bundle.pages) {
      const folderId = page.folderId || options.destinationFolderId || "general";
      let targetPath = normalizeSafeRelativePath(page.targetPath, "OKF page target path");
      const existing = existingByPath.get(targetKey(folderId, targetPath));
      let action = "create";
      let objectId = null;
      let baseRevision = null;
      if (existing) {
        if (mode === "skip") {
          action = "skip";
          objectId = existing.objectId || null;
        }
        if (mode === "copy") {
          action = "copy";
          targetPath = uniqueImportedCopyPath(folderId, targetPath, occupiedTargets);
          objectId = objectIdForTargetPath(targetPath, occupiedObjectIds);
        }
        if (mode === "overwrite") {
          action = "overwrite";
          objectId = existing.objectId;
          baseRevision = existing.revision;
        }
      } else {
        objectId = objectIdForTargetPath(targetPath, occupiedObjectIds);
      }
      occupiedTargets.add(targetKey(folderId, targetPath));
      entries.push({
        action,
        baseRevision,
        contentType: page.contentType || "text/markdown",
        folderId,
        links: [...(page.links || extractPageLinks(page.markdown))],
        markdown: page.markdown,
        objectId,
        sourcePath: page.sourcePath,
        targetPath,
      });
    }

    const sourcePathToEntry = new Map(entries.map((entry) => [entry.sourcePath, entry]));
    for (const entry of entries) {
      if (entry.action !== "skip") {
        entry.markdown = rewriteOkfMarkdownLinks(
          entry.markdown,
          entry.sourcePath,
          entry.targetPath,
          sourcePathToEntry
        );
        entry.links = extractPageLinks(entry.markdown);
      }
    }

    return {
      mode,
      entries,
      summary: {
        create: entries.filter((entry) => entry.action === "create").length,
        copy: entries.filter((entry) => entry.action === "copy").length,
        overwrite: entries.filter((entry) => entry.action === "overwrite").length,
        skip: entries.filter((entry) => entry.action === "skip").length,
      },
    };
  }

  function folderKeyVersionForImport(folderId, options = {}) {
    if (options.keyVersionByFolderId instanceof Map && options.keyVersionByFolderId.has(folderId)) {
      return options.keyVersionByFolderId.get(folderId);
    }
    if (options.keyVersionByFolderId?.[folderId]) return options.keyVersionByFolderId[folderId];
    if (typeof options.currentKeyVersion === "function") return options.currentKeyVersion(folderId);
    return options.keyVersion || 1;
  }

  async function prepareOkfImportWrites(keyring, plan, options) {
    if (!keyring) throw new Error("Open destination Folder Keys before importing OKF");
    if (!options?.vaultId) throw new Error("OKF import requires a destination Vault");
    if (!options?.authorNpub) throw new Error("OKF import requires a connected signer");
    if (typeof options.signEvent !== "function") throw new Error("OKF import requires event signing");

    const writes = [];
    const skipped = [];
    let nonceIndex = 0;
    for (const entry of plan.entries) {
      if (entry.action === "skip") {
        skipped.push(entry);
        continue;
      }
      const keyVersion = folderKeyVersionForImport(entry.folderId, options);
      const keyId = folderKeyId(options.vaultId, entry.folderId, keyVersion);
      if (!keyring.keys.has(keyId)) {
        throw new Error(
          `Folder Key is not open for ${entry.folderId}; OKF import cannot write locked destination Folder`
        );
      }
      const nonceBytes =
        typeof options.nonceFactory === "function" ? options.nonceFactory(nonceIndex, entry) : undefined;
      nonceIndex += 1;
      const body = await buildPageWriteRequest(keyring, {
        authorNpub: options.authorNpub,
        baseRevision: entry.baseRevision,
        createdAtUnix: options.createdAtUnix,
        folderId: entry.folderId,
        keyVersion,
        nonceBytes,
        objectId: entry.objectId,
        operation: entry.action === "overwrite" ? "update" : "create",
        plaintext: entry.markdown,
        signEvent: options.signEvent,
        vaultId: options.vaultId,
      });
      writes.push({
        action: entry.action,
        body,
        folderId: entry.folderId,
        objectId: entry.objectId,
        path: `/_admin/vaults/${encodeURIComponent(options.vaultId)}/folders/${encodeURIComponent(
          entry.folderId
        )}/objects/${encodeURIComponent(entry.objectId)}`,
        sourcePath: entry.sourcePath,
        targetPath: entry.targetPath,
      });
    }
    return { skipped, writes };
  }

  function buildGraphProjection(pages, filterText = "") {
    const filter = normalizePageReference(filterText);
    const visiblePages = [...pages].filter((page) => page.status === "ready");
    const nodes = visiblePages.map((page) => {
      const id = pageKey(page.folderId, page.objectId);
      const title = page.title || pageTitleFromText(page.text, page.objectId);
      return {
        id,
        folderId: page.folderId,
        objectId: page.objectId,
        title,
        normalizedTitle: normalizePageReference(title),
      };
    });
    const titleToNode = new Map(nodes.map((node) => [node.normalizedTitle, node]));
    const includedNodeIds = new Set(
      nodes
        .filter((node) => !filter || node.normalizedTitle.includes(filter))
        .map((node) => node.id)
    );
    const edges = [];
    for (const page of visiblePages) {
      const source = nodes.find((node) => node.id === pageKey(page.folderId, page.objectId));
      if (!source) continue;
      for (const targetRef of extractPageLinks(page.text)) {
        const target = titleToNode.get(targetRef);
        if (!target) continue;
        if (filter && !includedNodeIds.has(source.id) && !includedNodeIds.has(target.id)) continue;
        includedNodeIds.add(source.id);
        includedNodeIds.add(target.id);
        edges.push({
          id: `${source.id}->${target.id}`,
          source: source.id,
          target: target.id,
        });
      }
    }
    return {
      nodes: nodes.filter((node) => includedNodeIds.has(node.id)),
      edges,
    };
  }

  function graphStats(graph, readablePageCount = graph.nodes.length) {
    return {
      edgeCount: graph.edges.length,
      filteredOutCount: Math.max(0, readablePageCount - graph.nodes.length),
      nodeCount: graph.nodes.length,
    };
  }

  function graphLayout(graph, options = {}) {
    const width = Number(options.width || graphViewport.width);
    const height = Number(options.height || graphViewport.height);
    const margin = Number(options.margin || 76);
    const centerX = width / 2;
    const centerY = height / 2;
    const positions = new Map();
    if (!graph.nodes.length) return positions;

    const degree = new Map(graph.nodes.map((node) => [node.id, 0]));
    for (const edge of graph.edges) {
      degree.set(edge.source, (degree.get(edge.source) || 0) + 1);
      degree.set(edge.target, (degree.get(edge.target) || 0) + 1);
    }
    const orderedNodes = [...graph.nodes].sort((left, right) => {
      const degreeDelta = (degree.get(right.id) || 0) - (degree.get(left.id) || 0);
      if (degreeDelta) return degreeDelta;
      return left.title.localeCompare(right.title);
    });
    const radiusX = Math.max(70, width / 2 - margin);
    const radiusY = Math.max(70, height / 2 - margin);
    if (orderedNodes.length === 1) {
      positions.set(orderedNodes[0].id, { x: centerX, y: centerY });
      return positions;
    }
    const hasHub = orderedNodes.length > 4 && (degree.get(orderedNodes[0].id) || 0) > 1;
    orderedNodes.forEach((node, index) => {
      const isHub = hasHub && index === 0;
      if (isHub) {
        positions.set(node.id, { x: centerX, y: centerY });
        return;
      }
      const ringIndex = hasHub ? index - 1 : index;
      const ringCount = hasHub ? orderedNodes.length - 1 : orderedNodes.length;
      const angle = (Math.PI * 2 * ringIndex) / ringCount - Math.PI / 2;
      positions.set(node.id, {
        x: Math.round(centerX + Math.cos(angle) * radiusX),
        y: Math.round(centerY + Math.sin(angle) * radiusY),
      });
    });
    return positions;
  }

  function buildReplayFrames(changes) {
    const ordered = [...changes].sort((left, right) => (left.sequence || 0) - (right.sequence || 0));
    const seen = new Set();
    const pages = new Map();
    const frames = [];
    for (const change of ordered) {
      if (change.recordEventId && seen.has(change.recordEventId)) continue;
      if (change.recordEventId) seen.add(change.recordEventId);
      if (change.deleted) {
        pages.delete(pageKey(change.folderId, change.objectId));
      } else if (change.page?.status === "ready") {
        pages.set(pageKey(change.page.folderId, change.page.objectId), change.page);
      }
      const graph = buildGraphProjection(pages.values());
      frames.push({
        sequence: change.sequence || frames.length + 1,
        action: change.deleted ? "delete" : "upsert",
        edgeCount: graph.edges.length,
        graph,
        nodeCount: graph.nodes.length,
        recordEventId: change.recordEventId || null,
      });
    }
    return frames;
  }

  function decryptedPagesForGraph() {
    const pages = [];
    for (const [key, draft] of state.projection.localDrafts.entries()) {
      const [folderId, objectId] = key.split("/");
      pages.push({
        folderId,
        objectId,
        status: "ready",
        text: draft.text,
      });
    }
    for (const [key, page] of state.projection.pages.entries()) {
      if (page.text) {
        const [folderId, objectId] = key.split("/");
        pages.push({
          folderId,
          objectId,
          status: "ready",
          text: page.text,
          title: page.title,
        });
      }
    }
    return pages;
  }

  function projectionPages() {
    return [...state.projection.pages.entries()].map(([key, page]) => ({
      key,
      title: page.title || pageTitleFromText(page.text || "", page.objectId),
      ...page,
    }));
  }

  function readablePages() {
    return projectionPages().filter((page) => page.status === "ready" && page.text);
  }

  function readerFolderRows(metadata, pages = projectionPages()) {
    const pageCounts = new Map();
    const readableCounts = new Map();
    for (const page of pages) {
      pageCounts.set(page.folderId, (pageCounts.get(page.folderId) || 0) + 1);
      if (page.status === "ready" && page.text) {
        readableCounts.set(page.folderId, (readableCounts.get(page.folderId) || 0) + 1);
      }
    }
    return metadataFolderRows(metadata).map((folder) => ({
      ...folder,
      pageCount: pageCounts.get(folder.id) || 0,
      readableCount: readableCounts.get(folder.id) || 0,
    }));
  }

  function readerPageRows(folderId, pages = projectionPages()) {
    return pages
      .filter((page) => !folderId || page.folderId === folderId)
      .sort((left, right) => left.title.localeCompare(right.title))
      .map((page) => ({
        ...page,
        label: page.title,
        detail:
          page.status === "ready"
            ? `revision ${page.revision}`
            : `locked ${page.folderId}/${page.objectId}`,
      }));
  }

  function pageCountLabel(count) {
    return `${count} ${count === 1 ? "page" : "pages"}`;
  }

  function readerFolderDetail(row) {
    if (!row.pageCount) return `No pages yet - ${row.accessLabel}`;
    if (row.readableCount === row.pageCount) {
      return `${pageCountLabel(row.pageCount)} readable - ${row.accessLabel}`;
    }
    if (!row.readableCount) {
      return `${pageCountLabel(row.pageCount)} present, Folder Key not open - ${row.accessLabel}`;
    }
    return `${row.readableCount}/${row.pageCount} readable - ${row.accessLabel}`;
  }

  function selectDefaultReaderTargets() {
    const folders = readerFolderRows(state.metadata);
    const folderStillExists = folders.some((folder) => folder.id === state.selectedFolderId);
    if (!folderStillExists) {
      const folderWithReadablePages = folders.find((folder) => folder.readableCount > 0);
      state.selectedFolderId = folderWithReadablePages?.id || folders[0]?.id || null;
    }
    if (state.selectedFolderId) state.expandedFolderIds.add(state.selectedFolderId);

    const pages = readerPageRows(state.selectedFolderId);
    const pageStillExists = pages.some((page) => page.key === state.selectedPageKey);
    if (!pageStillExists) {
      const readablePage = pages.find((page) => page.status === "ready");
      state.selectedPageKey = readablePage?.key || pages[0]?.key || null;
    }
  }

  function selectedReaderPage() {
    if (!state.selectedPageKey) return null;
    return projectionPages().find((page) => page.key === state.selectedPageKey) || null;
  }

  function workspaceTabTitle(metadata, page) {
    return page?.title || metadata?.name || "Open a Vault";
  }

  function normalizeSidebarMode(mode) {
    return ["files", "search", "access"].includes(mode) ? mode : "files";
  }

  function searchPageRows(query, pages = readablePages()) {
    const needle = String(query || "").trim().toLowerCase();
    if (!needle) return [];
    return pages
      .filter((page) => {
        const haystack = [page.title, page.path, page.folderId, page.text].filter(Boolean).join("\n").toLowerCase();
        return haystack.includes(needle);
      })
      .sort((left, right) =>
        (left.title || left.objectId).localeCompare(right.title || right.objectId)
      )
      .map((page) => ({
        ...page,
        label: page.title || page.objectId,
        detail: `${page.folderId}/${page.path || `${page.objectId}.md`}`,
      }));
  }

  function contextMenuItemsForTarget(target) {
    if (!target) return [];
    if (target.type === "page") {
      return [
        { action: "open-page", label: "Open Page" },
        { action: "new-page", label: "New Page in Folder" },
        { action: "open-graph", label: "Show in Graph View" },
        { separator: true },
        { action: "copy-page-id", label: "Copy Page ID" },
        { action: "copy-folder-id", label: "Copy Folder ID" },
        { separator: true },
        { action: "delete-page", label: "Delete Page", disabled: true, danger: true },
      ];
    }
    return [
      { action: "open-folder", label: "Open Folder" },
      { action: "new-page", label: "New Page" },
      { action: "new-folder", label: "New Folder Inside" },
      { separator: true },
      { action: "copy-folder-id", label: "Copy Folder ID" },
      { action: "manage-access", label: "Manage Access" },
      { action: "share-folder", label: "Share Folder" },
      { separator: true },
      { action: "delete-folder", label: "Delete Folder", disabled: true, danger: true },
    ];
  }

  function setSidebarMode(mode) {
    state.activeSidebarMode = normalizeSidebarMode(mode);
    closeContextMenu();
    render();
  }

  function setWorkspaceView(view) {
    state.activeWorkspaceView = view === "graph" ? "graph" : "page";
    if (state.activeWorkspaceView === "graph") renderGraphView();
    render();
  }

  function workspaceChromeState(view) {
    const pageActive = view !== "graph";
    return {
      graphHidden: pageActive,
      graphTabClass: `workspace-tab${pageActive ? "" : " active"}`,
      pageHidden: !pageActive,
      pageTabClass: `workspace-tab${pageActive ? " active" : ""}`,
      ribbonGraphClass: `ribbon-button${pageActive ? "" : " active"}`,
      shellView: pageActive ? "page" : "graph",
    };
  }

  function renderWorkspaceChrome(page = selectedReaderPage()) {
    const chrome = workspaceChromeState(state.activeWorkspaceView);
    document.querySelector(".obsidian-shell").dataset.workspaceView = chrome.shellView;
    $("pageWorkspace").hidden = chrome.pageHidden;
    $("graphWorkspace").hidden = chrome.graphHidden;
    $("pageTabButton").className = chrome.pageTabClass;
    $("graphTabButton").className = chrome.graphTabClass;
    $("ribbonGraphButton").className = chrome.ribbonGraphClass;
    setText("workspaceTitle", workspaceTabTitle(state.metadata, page));
  }

  function nextDraftObjectId() {
    return `obj_${Date.now().toString(36)}`;
  }

  function startNewPageDraft(folderIdOverride = null) {
    const folderId = folderIdOverride || state.selectedFolderId || "general";
    const objectId = nextDraftObjectId();
    state.selectedFolderId = folderId;
    state.selectedPageKey = null;
    state.preparedWrite = null;
    state.preparedWriteTarget = null;
    state.activeWorkspaceView = "page";
    state.expandedFolderIds.add(folderId);
    $("pageFolderIdInput").value = folderId;
    $("okfDestinationFolderInput").value = folderId;
    $("pageObjectIdInput").value = objectId;
    $("pageBaseRevisionInput").value = "";
    $("pageDraftInput").value = "# New Page\n\nStart writing here.";
    log("Started a new Page draft.", { folderId, objectId });
    render();
  }

  function selectReaderFolder(folderId, options = {}) {
    state.selectedFolderId = folderId;
    state.expandedFolderIds.add(folderId);
    if (options.selectFirstPage !== false) {
      const firstPage = readerPageRows(folderId).find((page) => page.status === "ready");
      state.selectedPageKey = firstPage?.key || null;
    }
    state.activeWorkspaceView = "page";
    $("pageFolderIdInput").value = folderId;
    $("okfDestinationFolderInput").value = folderId;
    render();
  }

  function toggleReaderFolder(folderId) {
    const isExpanded = state.expandedFolderIds.has(folderId);
    state.selectedFolderId = folderId;
    $("pageFolderIdInput").value = folderId;
    $("okfDestinationFolderInput").value = folderId;
    if (isExpanded) {
      state.expandedFolderIds.delete(folderId);
      state.selectedPageKey = null;
    } else {
      state.expandedFolderIds.add(folderId);
      const firstPage = readerPageRows(folderId).find((page) => page.status === "ready");
      state.selectedPageKey = firstPage?.key || null;
    }
    state.activeWorkspaceView = "page";
    closeContextMenu();
    render();
  }

  function selectReaderPage(pageKeyValue) {
    state.selectedPageKey = pageKeyValue;
    state.activeWorkspaceView = "page";
    const page = selectedReaderPage();
    if (page) {
      state.selectedFolderId = page.folderId;
      state.expandedFolderIds.add(page.folderId);
      $("pageFolderIdInput").value = page.folderId;
      $("pageObjectIdInput").value = page.objectId;
      $("pageBaseRevisionInput").value = String(page.revision || "");
      if (page.text) $("pageDraftInput").value = page.text;
    }
    render();
  }

  function existingPagesForImport() {
    const pages = [];
    for (const [key, draft] of state.projection.localDrafts.entries()) {
      const [folderId, objectId] = key.split("/");
      pages.push({
        folderId,
        objectId,
        revision: draft.baseRevision || 0,
        path: draft.path || `${objectId}.md`,
        title: pageTitleFromText(draft.text, objectId),
      });
    }
    for (const [key, page] of state.projection.pages.entries()) {
      const [folderId, objectId] = key.split("/");
      pages.push({
        folderId,
        objectId,
        revision: page.revision || 0,
        path: page.path || `${objectId}.md`,
        title: page.title || pageTitleFromText(page.text || "", objectId),
      });
    }
    return pages;
  }

  function drawGraph(graph) {
    const svg = $("graphCanvas");
    svg.replaceChildren();
    svg.setAttribute("viewBox", `0 0 ${graphViewport.width} ${graphViewport.height}`);
    if (!graph.nodes.length) {
      const empty = document.createElementNS("http://www.w3.org/2000/svg", "text");
      empty.setAttribute("x", "24");
      empty.setAttribute("y", "44");
      empty.textContent = "No accessible decrypted Pages match this graph.";
      svg.appendChild(empty);
      return;
    }
    const positions = graphLayout(graph);
    const edgeDegree = new Map(graph.nodes.map((node) => [node.id, 0]));
    for (const edge of graph.edges) {
      edgeDegree.set(edge.source, (edgeDegree.get(edge.source) || 0) + 1);
      edgeDegree.set(edge.target, (edgeDegree.get(edge.target) || 0) + 1);
    }
    for (const edge of graph.edges) {
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      if (!source || !target) continue;
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("class", "edge");
      line.setAttribute("x1", String(source.x));
      line.setAttribute("y1", String(source.y));
      line.setAttribute("x2", String(target.x));
      line.setAttribute("y2", String(target.y));
      svg.appendChild(line);
    }
    for (const node of graph.nodes) {
      const position = positions.get(node.id);
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("class", graph.edges.some((edge) => edge.source === node.id) ? "node focus" : "node");
      circle.setAttribute("cx", String(position.x));
      circle.setAttribute("cy", String(position.y));
      circle.setAttribute("r", String(Math.min(18, 9 + (edgeDegree.get(node.id) || 0) * 1.5)));
      circle.setAttribute("data-folder-id", node.folderId);
      svg.appendChild(circle);

      const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
      label.setAttribute("class", "node-label");
      label.setAttribute("x", String(position.x + 16));
      label.setAttribute("y", String(position.y + 4));
      label.textContent = node.title;
      svg.appendChild(label);
    }
  }

  function setPill(id, text, tone) {
    const element = $(id);
    element.textContent = text;
    element.className = `pill ${tone || "muted"}`;
  }

  function setText(id, text) {
    $(id).textContent = text;
  }

  function setGraphStats(graph, readablePageCount) {
    const stats = graphStats(graph, readablePageCount);
    const filtered =
      stats.filteredOutCount > 0 ? ` / ${stats.filteredOutCount} hidden by filter` : "";
    setPill(
      "graphStats",
      `${stats.nodeCount} ${stats.nodeCount === 1 ? "node" : "nodes"} / ${stats.edgeCount} ${
        stats.edgeCount === 1 ? "link" : "links"
      }${filtered}`,
      stats.nodeCount ? "ready" : "muted"
    );
  }

  function setList(id, rows, emptyText, renderRow) {
    const list = $(id);
    list.replaceChildren();
    if (!rows.length) {
      const item = document.createElement("li");
      item.className = "empty-row";
      item.textContent = emptyText;
      list.appendChild(item);
      return;
    }
    for (const row of rows) {
      const item = document.createElement("li");
      renderRow(item, row);
      list.appendChild(item);
    }
  }

  function log(message, value) {
    const suffix = value === undefined ? "" : `\n${JSON.stringify(value, null, 2)}`;
    $("activityLog").textContent = `${new Date().toISOString()} ${message}${suffix}`;
  }

  function closeContextMenu() {
    state.contextMenuTarget = null;
    const menu = $("contextMenu");
    if (!menu) return;
    menu.hidden = true;
    menu.replaceChildren();
  }

  function positionContextMenu(menu, x, y, itemCount) {
    const estimatedWidth = 240;
    const estimatedHeight = Math.max(40, itemCount * 34 + 14);
    const maxLeft = Math.max(8, window.innerWidth - estimatedWidth - 8);
    const maxTop = Math.max(8, window.innerHeight - estimatedHeight - 8);
    menu.style.left = `${Math.min(Math.max(8, x), maxLeft)}px`;
    menu.style.top = `${Math.min(Math.max(8, y), maxTop)}px`;
  }

  function writeClipboard(text) {
    if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
    return Promise.resolve();
  }

  function handleContextMenuAction(item, target) {
    if (item.disabled) return;
    closeContextMenu();
    if (item.action === "open-folder") {
      selectReaderFolder(target.folderId);
      return;
    }
    if (item.action === "open-page") {
      selectReaderPage(target.pageKey);
      return;
    }
    if (item.action === "new-page") {
      startNewPageDraft(target.folderId);
      return;
    }
    if (item.action === "new-folder") {
      log("New child Folder is queued for the Folder creation slice.", {
        parentFolderId: target.folderId,
      });
      return;
    }
    if (item.action === "open-graph") {
      $("graphFilterInput").value = target.title || target.objectId || "";
      setWorkspaceView("graph");
      return;
    }
    if (item.action === "copy-page-id") {
      writeClipboard(target.objectId).catch(() => {});
      log("Copied Page ID.", { objectId: target.objectId });
      return;
    }
    if (item.action === "copy-folder-id") {
      writeClipboard(target.folderId).catch(() => {});
      log("Copied Folder ID.", { folderId: target.folderId });
      return;
    }
    if (item.action === "manage-access") {
      setSidebarMode("access");
      log("Opened Folder access panel.", { folderId: target.folderId });
      return;
    }
    if (item.action === "share-folder") {
      setSidebarMode("access");
      log("Share Folder flow is surfaced in the access/share slice.", { folderId: target.folderId });
    }
  }

  function openContextMenu(target, x, y) {
    const menu = $("contextMenu");
    if (!menu) return;
    state.contextMenuTarget = target;
    menu.replaceChildren();
    const items = contextMenuItemsForTarget(target);
    for (const item of items) {
      if (item.separator) {
        const separator = document.createElement("div");
        separator.className = "context-menu-separator";
        menu.appendChild(separator);
        continue;
      }
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = item.label;
      button.disabled = Boolean(item.disabled);
      button.className = item.danger ? "danger" : "";
      button.addEventListener("click", () => handleContextMenuAction(item, target));
      menu.appendChild(button);
    }
    menu.hidden = false;
    positionContextMenu(menu, x, y, items.length);
  }

  function readerButton(label, detail, className, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    if (detail) {
      const detailElement = document.createElement("span");
      detailElement.className = "reader-list-detail";
      detailElement.textContent = detail;
      button.appendChild(detailElement);
    }
    button.addEventListener("click", onClick);
    return button;
  }

  function appendObsidianDetail(button, detail) {
    if (!detail) return;
    const detailElement = document.createElement("span");
    detailElement.className = "obsidian-file-detail";
    detailElement.textContent = detail;
    button.appendChild(detailElement);
  }

  function obsidianTreeButton(label, detail, className, onClick, options = {}) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    appendObsidianDetail(button, detail);
    button.addEventListener("click", onClick);
    if (options.contextTarget) {
      button.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        openContextMenu(options.contextTarget, event.clientX, event.clientY);
      });
    }
    return button;
  }

  function renderSidebarMode() {
    const mode = normalizeSidebarMode(state.activeSidebarMode);
    state.activeSidebarMode = mode;
    $("filesSidebarPanel").hidden = mode !== "files";
    $("searchSidebarPanel").hidden = mode !== "search";
    $("accessSidebarPanel").hidden = mode !== "access";
    $("ribbonFilesButton").className = `ribbon-button${mode === "files" ? " active" : ""}`;
    $("ribbonSearchButton").className = `ribbon-button${mode === "search" ? " active" : ""}`;
    $("ribbonAccessButton").className = `ribbon-button${mode === "access" ? " active" : ""}`;
  }

  function renderSearchPanel() {
    const query = $("sidebarSearchInput").value;
    const rows = searchPageRows(query);
    setPill("searchResultCount", `${rows.length}`, rows.length ? "ready" : "muted");
    setList("sidebarSearchResults", rows, "Search readable Pages", (item, row) => {
      const button = obsidianTreeButton(
        row.label,
        row.detail,
        `obsidian-page-button ${row.key === state.selectedPageKey ? " active" : ""}`,
        () => selectReaderPage(row.key),
        {
          contextTarget: {
            type: "page",
            folderId: row.folderId,
            objectId: row.objectId,
            pageKey: row.key,
            title: row.title,
          },
        }
      );
      item.appendChild(button);
    });
  }

  function renderAccessPanel() {
    const rows = readerFolderRows(state.metadata);
    setPill("accessFolderCount", `${rows.length}`, rows.length ? "ready" : "muted");
    setList("accessFolderList", rows, "Load a Vault to inspect access", (item, row) => {
      const button = obsidianTreeButton(
        row.path,
        `${row.accessLabel} - key v${row.currentKeyVersion || 1}${row.detail ? ` - ${row.detail}` : ""}`,
        `obsidian-folder-button ${row.status}${row.id === state.selectedFolderId ? " active" : ""}`,
        () => selectReaderFolder(row.id, { selectFirstPage: false }),
        {
          contextTarget: {
            type: "folder",
            folderId: row.id,
            path: row.path,
          },
        }
      );
      item.appendChild(button);
    });
  }

  function renderReader() {
    selectDefaultReaderTargets();
    const folderRows = readerFolderRows(state.metadata);
    const pageRows = readerPageRows(state.selectedFolderId);
    const readableCount = readablePages().length;
    const openedKeyCount = state.keyring?.openedGrants.length || 0;
    setPill("readerFolderSummary", `${folderRows.length} folders`, folderRows.length ? "ready" : "muted");
    setPill("readerPageSummary", `${readableCount} readable pages`, readableCount ? "ready" : "muted");
    setPill("readerKeySummary", `${openedKeyCount} keys open`, openedKeyCount ? "ready" : "muted");

    setList("readerFolderList", folderRows, "Load a Vault to browse folders", (item, row) => {
      const expanded = state.expandedFolderIds.has(row.id);
      const button = obsidianTreeButton(
        row.path,
        readerFolderDetail(row),
        `obsidian-folder-button ${row.status}${expanded ? " expanded" : ""}${
          row.id === state.selectedFolderId ? " active" : ""
        }`,
        () => toggleReaderFolder(row.id),
        {
          contextTarget: {
            type: "folder",
            folderId: row.id,
            path: row.path,
          },
        }
      );
      item.appendChild(button);
      const childPages = readerPageRows(row.id);
      if (expanded && childPages.length) {
        const childList = document.createElement("ol");
        childList.className = "obsidian-page-children";
        for (const pageRow of childPages) {
          const childItem = document.createElement("li");
          const pageButton = obsidianTreeButton(
            pageRow.label,
            pageRow.status === "ready" ? "" : "Locked",
            `obsidian-page-button ${pageRow.status}${pageRow.key === state.selectedPageKey ? " active" : ""}`,
            () => selectReaderPage(pageRow.key),
            {
              contextTarget: {
                type: "page",
                folderId: pageRow.folderId,
                objectId: pageRow.objectId,
                pageKey: pageRow.key,
                title: pageRow.title,
              },
            }
          );
          childItem.appendChild(pageButton);
          childList.appendChild(childItem);
        }
        item.appendChild(childList);
      }
    });

    setList("readerPageList", pageRows, "No Pages in this Folder yet", (item, row) => {
      const button = readerButton(
        row.label,
        row.detail,
        `reader-list-button ${row.status}${row.key === state.selectedPageKey ? " active" : ""}`,
        () => selectReaderPage(row.key)
      );
      item.appendChild(button);
    });

    const page = selectedReaderPage();
    if (!page) {
      setText("readerPageTitle", state.selectedFolderId ? "No readable page selected" : "No folder selected");
      setPill("readerPageMeta", "empty", "muted");
      setText("readerPageContent", "Open an accessible vault to read decrypted Pages here.");
      renderWorkspaceChrome(null);
      return;
    }

    setText("readerPageTitle", page.title || page.objectId);
    setPill(
      "readerPageMeta",
      `${page.folderId} r${page.revision || 0}`,
      page.status === "ready" ? "ready" : "warn"
    );
    setText(
      "readerPageContent",
      page.status === "ready" && page.text
        ? page.text
        : "This Page is present in sync, but its Folder Key is not open in this session."
    );
    renderWorkspaceChrome(page);
  }

  function render() {
    const signerTone =
      state.signerStatus === "connected"
        ? "ready"
        : state.signerStatus === "unavailable" || state.signerStatus === "unsupported"
          ? "error"
          : "muted";
    setPill("signerState", state.signerStatus, signerTone);
    setPill("configState", state.config ? "config ready" : "config", state.config ? "ready" : "muted");
    setPill("vaultState", state.metadata ? "vault loaded" : "vault", state.metadata ? "ready" : "muted");

    const rows = metadataFolderRows(state.metadata);
    const lockedCount = rows.filter((row) => row.status !== "ready").length;
    setPill("accessState", lockedCount ? `${lockedCount} locked` : "access ready", lockedCount ? "warn" : "ready");
    setText("folderCount", String(rows.length));

    $("connectSignerButton").disabled = !deriveSignerState(window.nostr).canConnect;
    $("loadVaultButton").disabled = state.signerStatus !== "connected" || !state.config;
    $("openFolderKeyButton").disabled = !state.metadata;
    $("encryptDraftButton").disabled = !state.keyring;
    $("savePageButton").disabled = !state.preparedWrite || state.signerStatus !== "connected";
    $("syncBootstrapButton").disabled = state.signerStatus !== "connected" || !state.config;
    $("openAccessibleVaultButton").disabled = state.readerBusy || !state.config;
    $("refreshReaderButton").disabled = state.readerBusy || state.signerStatus !== "connected" || !state.metadata;
    $("planOkfImportButton").disabled = !state.metadata;
    $("executeOkfImportButton").disabled =
      !state.okfPlan || !state.keyring || state.signerStatus !== "connected";
    $("vaultIdInput").value = state.activeVaultId;

    setText("workspaceTitle", state.metadata?.name || "Open a Vault");
    setText("vaultKind", state.metadata?.kind || "-");
    setText("memberCount", String((state.metadata?.members || []).length || "-"));
    setText("adminCount", String((state.metadata?.admins || []).length || "-"));
    setText("grantCount", String(state.metadata?.grantCount ?? "-"));

    setList("folderList", rows, "No folders loaded", (item, row) => {
      item.className = row.status;
      item.textContent = row.detail ? `${row.label} - ${row.detail}` : row.label;
    });

    setList("mountList", metadataMountRows(state.metadata), "No mounted Folders", (item, row) => {
      item.textContent = `${row.label} (${row.state})`;
    });

    $("spineSigner").className = state.signerStatus === "connected" ? "done" : "waiting";
    $("spineAuth").className = state.signerStatus === "connected" && state.config ? "done" : "waiting";
    $("spineVault").className = state.metadata ? "done" : "waiting";
    $("spineKeys").className = state.keyring?.openedGrants.length ? "done" : "waiting";
    $("spinePages").className = readablePages().length ? "done" : "waiting";
    renderSidebarMode();
    renderReader();
    renderSearchPanel();
    renderAccessPanel();
    renderOkfPlan();
  }

  function utf8Base64(text) {
    const bytes = new TextEncoder().encode(text);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function buildAuthEventTemplate(method, url, bodyText) {
    const tags = [
      ["u", url],
      ["method", method.toUpperCase()],
    ];
    if (bodyText) tags.push(["payload", await sha256Hex(bodyText)]);
    return {
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: "",
    };
  }

  async function signAuthHeader(path, options = {}) {
    if (!state.config) throw new Error("Product Client config has not loaded");
    if (!window.nostr?.signEvent) throw new Error("NIP-07 signer is unavailable");
    const method = options.method || "GET";
    const bodyText = options.body || "";
    const url = `${state.config.publicBaseUrl.replace(/\/$/, "")}${path}`;
    const eventTemplate = await buildAuthEventTemplate(method, url, bodyText);
    const signed = await window.nostr.signEvent(eventTemplate);
    return `${state.config.authScheme} ${utf8Base64(JSON.stringify(signed))}`;
  }

  async function protectedRequest(path, options = {}) {
    const headers = {
      Authorization: await signAuthHeader(path, options),
    };
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: options.body || undefined,
    });
    const text = await response.text();
    let body = text;
    try {
      body = JSON.parse(text);
    } catch (_) {
      body = text;
    }
    if (!response.ok) {
      const message = body?.error || `Request failed with ${response.status}`;
      throw new Error(message);
    }
    return body;
  }

  async function loadConfig() {
    const response = await fetch("/client/config.json");
    state.config = await response.json();
    state.activeVaultId = state.config.defaultVaultId || state.activeVaultId;
    log("Loaded Product Client config.", state.config);
    render();
  }

  async function detectSigner() {
    const derived = deriveSignerState(window.nostr);
    state.signerStatus = derived.status;
    setText("signerDetail", derived.detail);
    render();
  }

  async function connectSigner() {
    const derived = deriveSignerState(window.nostr);
    if (!derived.canConnect) {
      state.signerStatus = derived.status;
      setText("signerDetail", derived.detail);
      render();
      return;
    }
    const pubkey = await window.nostr.getPublicKey();
    state.pubkeyHex = pubkey;
    state.signerStatus = "connected";
    setText("signerDetail", `Connected as ${shortKey(pubkey)}.`);
    setText("authDetail", "Signed requests are ready for protected Vault routes.");
    log("Connected NIP-07 signer.", { pubkey: shortKey(pubkey) });
    render();
  }

  async function loadVaultMetadata() {
    state.activeVaultId = $("vaultIdInput").value.trim() || state.activeVaultId;
    const path = `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/metadata`;
    const metadata = await protectedRequest(path);
    state.metadata = metadata;
    log("Loaded Vault metadata.", metadata);
    render();
  }

  async function openAvailableDevelopmentGrants() {
    if (!state.keyring) state.keyring = createSessionKeyring();
    const exported = await protectedRequest(`/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/export`);
    const expectedRecipient = state.pubkeyHex ? npubFromHex(state.pubkeyHex) : null;
    return openDevelopmentFolderKeyGrants(state.keyring, exported, expectedRecipient);
  }

  async function openAccessibleVaultReader() {
    state.readerBusy = true;
    render();
    try {
      if (state.signerStatus !== "connected") await connectSigner();
      if (state.signerStatus !== "connected") throw new Error("Connect a NIP-07 signer first");
      await loadVaultMetadata();
      const grants = await openAvailableDevelopmentGrants();
      await pullSyncBootstrap();
      selectDefaultReaderTargets();
      renderGraphView();
      log("Opened accessible Vault reader.", {
        openedDevelopmentKeys: grants.opened.length,
        skippedOpaqueGrants: grants.skipped.length,
        readablePages: readablePages().length,
      });
    } finally {
      state.readerBusy = false;
      render();
    }
  }

  async function refreshReader() {
    state.readerBusy = true;
    render();
    try {
      await loadVaultMetadata();
      if (state.keyring?.openedGrants.length) await pullSyncBootstrap();
      selectDefaultReaderTargets();
      log("Refreshed Vault reader.", {
        readablePages: readablePages().length,
      });
    } finally {
      state.readerBusy = false;
      render();
    }
  }

  function activePageInput() {
    return {
      baseRevision: $("pageBaseRevisionInput").value.trim(),
      folderId: $("pageFolderIdInput").value.trim() || "general",
      objectId: $("pageObjectIdInput").value.trim() || "obj_000000000001",
      text: $("pageDraftInput").value,
    };
  }

  function currentFolderKeyVersion(folderId) {
    const folder = (state.metadata?.folders || []).find((candidate) => candidate.id === folderId);
    return folder?.currentKeyVersion || 1;
  }

  async function openEnteredFolderKey() {
    if (!state.keyring) state.keyring = createSessionKeyring();
    const input = activePageInput();
    const folderKey = $("folderKeyInput").value.trim();
    if (!folderKey) throw new Error("Paste a base64 raw Folder Key first");
    await openFolderKeyGrantPlaintext(state.keyring, {
      version: "finite-folder-key-grant-v1",
      vaultId: state.activeVaultId,
      folderId: input.folderId,
      keyVersion: currentFolderKeyVersion(input.folderId),
      issuerNpub: "npub-local-session",
      recipientNpub: state.pubkeyHex ? npubFromHex(state.pubkeyHex) : "npub-local-session",
      folderKey,
      issuedAt: new Date().toISOString(),
    });
    log("Opened Folder Key into the in-memory session keyring.", {
      folderId: input.folderId,
      keyVersion: currentFolderKeyVersion(input.folderId),
    });
    render();
  }

  async function prepareDraftWrite() {
    if (!state.keyring) throw new Error("Open a Folder Key before encrypting a Page draft");
    if (!state.pubkeyHex) throw new Error("Connect a signer before preparing a signed Page write");
    const input = activePageInput();
    const authorNpub = npubFromHex(state.pubkeyHex);
    const keyVersion = currentFolderKeyVersion(input.folderId);
    state.preparedWrite = await buildPageWriteRequest(state.keyring, {
      authorNpub,
      baseRevision: input.baseRevision,
      folderId: input.folderId,
      keyVersion,
      objectId: input.objectId,
      plaintext: input.text,
      signEvent: (event) => window.nostr.signEvent(event),
      vaultId: state.activeVaultId,
    });
    state.preparedWriteTarget = {
      folderId: input.folderId,
      objectId: input.objectId,
    };
    state.projection.localDrafts.set(pageKey(input.folderId, input.objectId), {
      baseRevision: state.preparedWrite.baseRevision || 0,
      text: input.text,
    });
    log("Encrypted Page draft and prepared signed revision request.", {
      folderId: input.folderId,
      objectId: input.objectId,
      baseRevision: state.preparedWrite.baseRevision,
      keyVersion,
    });
    render();
  }

  async function savePreparedPage() {
    if (!state.preparedWrite) throw new Error("Prepare a Page write before saving");
    const target = state.preparedWriteTarget || activePageInput();
    const path = `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/folders/${encodeURIComponent(
      target.folderId
    )}/objects/${encodeURIComponent(target.objectId)}`;
    const result = await protectedRequest(path, {
      method: "PUT",
      body: JSON.stringify(state.preparedWrite),
    });
    state.projection.pages.set(pageKey(target.folderId, target.objectId), {
      folderId: target.folderId,
      objectId: target.objectId,
      revision: result.revision,
      path: `${target.objectId}.md`,
      status: "ready",
      text: $("pageDraftInput").value,
    });
    state.projection.localDrafts.delete(pageKey(target.folderId, target.objectId));
    state.preparedWrite = null;
    state.preparedWriteTarget = null;
    $("pageBaseRevisionInput").value = String(result.revision);
    log("Saved encrypted Page revision.", result);
    render();
  }

  async function pullSyncBootstrap() {
    const path = `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/sync/bootstrap`;
    const sync = await protectedRequest(path);
    const openedSync = await openSyncObjects(state.keyring, sync);
    state.projection = mergeSyncProjection(state.projection, openedSync);
    log("Pulled sync bootstrap into local projection.", {
      conflicts: state.projection.conflicts,
      decryptedPages: openedSync.objects.filter((object) => object.status === "ready").length,
      pages: state.projection.pages.size,
      seenEvents: state.projection.seenEventIds.size,
    });
    render();
  }

  function renderGraphView() {
    const pages = decryptedPagesForGraph();
    const graph = buildGraphProjection(pages, $("graphFilterInput").value);
    drawGraph(graph);
    setGraphStats(graph, pages.length);
    log("Rendered graph from decrypted client index.", {
      edges: graph.edges.length,
      nodes: graph.nodes.length,
    });
  }

  function fitGraphView() {
    $("graphCanvas").setAttribute("viewBox", `0 0 ${graphViewport.width} ${graphViewport.height}`);
    log("Fit graph view to readable graph bounds.");
  }

  function resetGraphView() {
    $("graphFilterInput").value = "";
    renderGraphView();
  }

  function renderReplayFrames() {
    const changes = [];
    let sequence = 1;
    for (const [key, draft] of state.projection.localDrafts.entries()) {
      const [folderId, objectId] = key.split("/");
      changes.push({
        sequence,
        recordEventId: `local-draft-${sequence}`,
        page: {
          folderId,
          objectId,
          status: "ready",
          text: draft.text,
        },
      });
      sequence += 1;
    }
    for (const [key, page] of state.projection.pages.entries()) {
      if (!page.text) continue;
      const [folderId, objectId] = key.split("/");
      changes.push({
        sequence,
        recordEventId: `page-${sequence}`,
        page: {
          folderId,
          objectId,
          status: "ready",
          text: page.text,
          title: page.title,
        },
      });
      sequence += 1;
    }
    const frames = buildReplayFrames(changes);
    setList("replayList", frames, "No replay frames", (item, frame) => {
      item.textContent = `#${frame.sequence} ${frame.action}: ${frame.nodeCount} nodes, ${frame.edgeCount} edges`;
    });
    if (frames.length) {
      drawGraph(frames[frames.length - 1].graph);
      setGraphStats(frames[frames.length - 1].graph, frames[frames.length - 1].nodeCount);
    }
    log("Built graph replay frames.", frames.map((frame) => ({
      edgeCount: frame.edgeCount,
      nodeCount: frame.nodeCount,
      sequence: frame.sequence,
    })));
  }

  function renderOkfPlan() {
    const plan = state.okfPlan;
    if (!plan) {
      setList("okfPlanList", [], "No OKF import planned", () => {});
      return;
    }
    setList("okfPlanList", plan.entries, "No OKF import actions", (item, entry) => {
      item.textContent = `${entry.action}: ${entry.sourcePath} -> ${entry.folderId}/${entry.targetPath}`;
      item.className = entry.action === "skip" ? "warn-row" : "ready-row";
    });
  }

  function folderKeyVersionMap() {
    return new Map(
      (state.metadata?.folders || []).map((folder) => [folder.id, folder.currentKeyVersion || 1])
    );
  }

  function planEnteredOkfImport() {
    const destinationFolderId = $("okfDestinationFolderInput").value.trim() || activePageInput().folderId;
    const bundle = parseOkfBundle($("okfBundleInput").value, { destinationFolderId });
    state.okfPlan = planOkfImport(bundle, existingPagesForImport(), {
      conflictMode: $("okfConflictModeInput").value,
      destinationFolderId,
    });
    log("Planned OKF import.", state.okfPlan.summary);
    render();
  }

  async function executePlannedOkfImport() {
    if (!state.okfPlan) throw new Error("Plan an OKF import before executing it");
    if (!state.keyring) throw new Error("Open destination Folder Keys before importing OKF");
    if (!state.pubkeyHex) throw new Error("Connect a signer before importing OKF");
    const authorNpub = npubFromHex(state.pubkeyHex);
    const prepared = await prepareOkfImportWrites(state.keyring, state.okfPlan, {
      authorNpub,
      currentKeyVersion: (folderId) => folderKeyVersionMap().get(folderId) || 1,
      signEvent: (event) => window.nostr.signEvent(event),
      vaultId: state.activeVaultId,
    });
    const results = [];
    for (const write of prepared.writes) {
      const result = await protectedRequest(write.path, {
        method: "PUT",
        body: JSON.stringify(write.body),
      });
      state.projection.pages.set(pageKey(write.folderId, write.objectId), {
        folderId: write.folderId,
        objectId: write.objectId,
        path: write.targetPath,
        revision: result.revision,
        status: "ready",
        text: state.okfPlan.entries.find((entry) => entry.objectId === write.objectId)?.markdown || "",
        title: pageTitleFromText(
          state.okfPlan.entries.find((entry) => entry.objectId === write.objectId)?.markdown || "",
          write.targetPath
        ),
      });
      results.push({ ...result, targetPath: write.targetPath });
    }
    state.okfPlan = null;
    log("Executed OKF import through encrypted secure object routes.", {
      imported: results.length,
      skipped: prepared.skipped.length,
      results,
    });
    render();
  }

  function bind() {
    $("connectSignerButton").addEventListener("click", () => {
      connectSigner().catch((error) => {
        state.lastError = error.message;
        log("Failed to connect signer.", { error: error.message });
        render();
      });
    });
    $("loadVaultButton").addEventListener("click", () => {
      loadVaultMetadata().catch((error) => {
        state.lastError = error.message;
        log("Failed to load Vault metadata.", { error: error.message });
        render();
      });
    });
    $("openAccessibleVaultButton").addEventListener("click", () => {
      openAccessibleVaultReader().catch((error) => {
        state.lastError = error.message;
        log("Failed to open accessible Vault reader.", { error: error.message });
        state.readerBusy = false;
        render();
      });
    });
    $("refreshReaderButton").addEventListener("click", () => {
      refreshReader().catch((error) => {
        state.lastError = error.message;
        log("Failed to refresh Vault reader.", { error: error.message });
        state.readerBusy = false;
        render();
      });
    });
    $("pageTabButton").addEventListener("click", () => {
      setWorkspaceView("page");
    });
    $("graphTabButton").addEventListener("click", () => {
      setWorkspaceView("graph");
    });
    $("ribbonGraphButton").addEventListener("click", () => {
      setWorkspaceView("graph");
    });
    $("ribbonFilesButton").addEventListener("click", () => {
      setSidebarMode("files");
    });
    $("ribbonSearchButton").addEventListener("click", () => {
      setSidebarMode("search");
    });
    $("ribbonAccessButton").addEventListener("click", () => {
      setSidebarMode("access");
    });
    $("sidebarSearchInput").addEventListener("input", () => {
      renderSearchPanel();
    });
    $("obsidianNewPageButton").addEventListener("click", () => {
      startNewPageDraft();
    });
    $("obsidianNewFolderButton").addEventListener("click", () => {
      log("New Folder will be wired through the Folder creation flow in the access/share slice.", {
        parentFolderId: state.selectedFolderId || null,
      });
    });
    $("openFolderKeyButton").addEventListener("click", () => {
      openEnteredFolderKey().catch((error) => {
        state.lastError = error.message;
        log("Failed to open Folder Key.", { error: error.message });
        render();
      });
    });
    $("encryptDraftButton").addEventListener("click", () => {
      prepareDraftWrite().catch((error) => {
        state.lastError = error.message;
        log("Failed to encrypt Page draft.", { error: error.message });
        render();
      });
    });
    $("savePageButton").addEventListener("click", () => {
      savePreparedPage().catch((error) => {
        state.lastError = error.message;
        log("Failed to save Page.", { error: error.message });
        render();
      });
    });
    $("syncBootstrapButton").addEventListener("click", () => {
      pullSyncBootstrap().catch((error) => {
        state.lastError = error.message;
        log("Failed to pull sync.", { error: error.message });
        render();
      });
    });
    $("renderGraphButton").addEventListener("click", () => {
      try {
        renderGraphView();
      } catch (error) {
        state.lastError = error.message;
        log("Failed to render graph.", { error: error.message });
      }
    });
    $("graphFilterInput").addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      renderGraphView();
    });
    $("fitGraphButton").addEventListener("click", () => {
      fitGraphView();
    });
    $("resetGraphButton").addEventListener("click", () => {
      resetGraphView();
    });
    $("replayGraphButton").addEventListener("click", () => {
      try {
        renderReplayFrames();
      } catch (error) {
        state.lastError = error.message;
        log("Failed to build replay.", { error: error.message });
      }
    });
    $("planOkfImportButton").addEventListener("click", () => {
      try {
        planEnteredOkfImport();
      } catch (error) {
        state.lastError = error.message;
        log("Failed to plan OKF import.", { error: error.message });
        render();
      }
    });
    $("executeOkfImportButton").addEventListener("click", () => {
      executePlannedOkfImport().catch((error) => {
        state.lastError = error.message;
        log("Failed to execute OKF import.", { error: error.message });
        render();
      });
    });
    document.addEventListener("click", (event) => {
      const menu = $("contextMenu");
      if (!menu.hidden && !menu.contains(event.target)) closeContextMenu();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeContextMenu();
    });
  }

  async function start() {
    bind();
    await loadConfig();
    await detectSigner();
  }

  return {
    buildPageWriteRequest,
    buildAuthEventTemplate,
    buildGraphProjection,
    buildReplayFrames,
    contextMenuItemsForTarget,
    createClientProjection,
    createSessionKeyring,
    deriveSignerState,
    encryptFolderObject,
    extractPageLinks,
    graphLayout,
    graphStats,
    mergeSyncProjection,
    metadataFolderRows,
    metadataMountRows,
    normalizeSidebarMode,
    npubFromHex,
    openDevelopmentFolderKeyGrants,
    openFolderKeyGrantPlaintext,
    openFolderObject,
    openSyncObjects,
    parseOkfBundle,
    plaintextGrantFromExportGrant,
    planOkfImport,
    prepareOkfImportWrites,
    readerFolderDetail,
    readerFolderRows,
    readerPageRows,
    searchPageRows,
    shortKey,
    start,
    workspaceChromeState,
    workspaceTabTitle,
  };
})();

window.FiniteBrainProductClient = FiniteBrainProductClient;
if (!window.__FINITE_BRAIN_DISABLE_AUTOSTART__) {
  FiniteBrainProductClient.start();
}
