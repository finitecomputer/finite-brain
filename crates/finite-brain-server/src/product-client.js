const FiniteBrainProductClient = (() => {
  const state = {
    config: null,
    signerStatus: "checking",
    pubkeyHex: null,
    activeVaultId: "smoke",
    metadata: null,
    lastError: null,
  };

  const $ = (id) => document.getElementById(id);

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
    $("spineKeys").className = "waiting";
    $("spinePages").className = "waiting";
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
  }

  async function start() {
    bind();
    await loadConfig();
    await detectSigner();
  }

  return {
    buildAuthEventTemplate,
    deriveSignerState,
    metadataFolderRows,
    metadataMountRows,
    shortKey,
    start,
  };
})();

window.FiniteBrainProductClient = FiniteBrainProductClient;
if (!window.__FINITE_BRAIN_DISABLE_AUTOSTART__) {
  FiniteBrainProductClient.start();
}
