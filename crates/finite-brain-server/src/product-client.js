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
    projection: createClientProjection(),
  };

  const $ = (id) => document.getElementById(id);
  const CIPHER = "AES-256-GCM";
  const FOLDER_OBJECT_VERSION = "finite-folder-object-v1";
  const REVISION_VERSION = "finite-folder-object-revision-v1";
  const APP_EVENT_KIND = 30078;
  const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

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

  function metadataFolderRows(metadata) {
    return (metadata?.folders || []).map((folder) => {
      const status = folderStatus(folder);
      const flags = [];
      if (folder.sharedFolderSource) flags.push("source");
      if (folder.setupIncomplete) flags.push("setup needed");
      if (status === "locked") flags.push("locked");
      return {
        id: folder.id,
        path: folder.path,
        status,
        label: `${folder.path} (${folder.access}, v${folder.currentKeyVersion})`,
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
    keyring.openedGrants.push({
      folderId: grantPlaintext.folderId,
      issuerNpub: grantPlaintext.issuerNpub,
      keyVersion: grantPlaintext.keyVersion,
      recipientNpub: grantPlaintext.recipientNpub,
      vaultId: grantPlaintext.vaultId,
    });
    return opened;
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

  function drawGraph(graph) {
    const svg = $("graphCanvas");
    svg.replaceChildren();
    if (!graph.nodes.length) {
      const empty = document.createElementNS("http://www.w3.org/2000/svg", "text");
      empty.setAttribute("x", "24");
      empty.setAttribute("y", "44");
      empty.textContent = "No accessible decrypted Pages match this graph.";
      svg.appendChild(empty);
      return;
    }
    const centerX = 360;
    const centerY = 160;
    const radius = Math.min(118, 34 + graph.nodes.length * 12);
    const positions = new Map();
    graph.nodes.forEach((node, index) => {
      const angle = (Math.PI * 2 * index) / graph.nodes.length - Math.PI / 2;
      positions.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
      });
    });
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
      circle.setAttribute("r", "12");
      svg.appendChild(circle);

      const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
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

  function setList(id, rows, emptyText, renderRow) {
    const list = $(id);
    list.replaceChildren();
    if (!rows.length) {
      const item = document.createElement("li");
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
    $("spinePages").className = state.preparedWrite ? "done" : "waiting";
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
    state.projection = mergeSyncProjection(state.projection, sync);
    log("Pulled sync bootstrap into local projection.", {
      conflicts: state.projection.conflicts,
      pages: state.projection.pages.size,
      seenEvents: state.projection.seenEventIds.size,
    });
    render();
  }

  function renderGraphView() {
    const graph = buildGraphProjection(decryptedPagesForGraph(), $("graphFilterInput").value);
    drawGraph(graph);
    log("Rendered graph from decrypted client index.", {
      edges: graph.edges.length,
      nodes: graph.nodes.length,
    });
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
    if (frames.length) drawGraph(frames[frames.length - 1].graph);
    log("Built graph replay frames.", frames.map((frame) => ({
      edgeCount: frame.edgeCount,
      nodeCount: frame.nodeCount,
      sequence: frame.sequence,
    })));
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
    $("replayGraphButton").addEventListener("click", () => {
      try {
        renderReplayFrames();
      } catch (error) {
        state.lastError = error.message;
        log("Failed to build replay.", { error: error.message });
      }
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
    createClientProjection,
    createSessionKeyring,
    deriveSignerState,
    encryptFolderObject,
    extractPageLinks,
    mergeSyncProjection,
    metadataFolderRows,
    metadataMountRows,
    npubFromHex,
    openFolderKeyGrantPlaintext,
    openFolderObject,
    shortKey,
    start,
  };
})();

window.FiniteBrainProductClient = FiniteBrainProductClient;
if (!window.__FINITE_BRAIN_DISABLE_AUTOSTART__) {
  FiniteBrainProductClient.start();
}
