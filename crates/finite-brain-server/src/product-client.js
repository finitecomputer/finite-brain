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
    activeAccessFolderId: null,
    activeAccessIntent: "inspect",
    accessBusy: false,
    accessResult: null,
    lastShareLinkId: null,
    lastVaultInvitationCode: null,
    lastVaultInvitationId: null,
    readerMode: "reading",
    editorMode: "visual",
    vaultControlsCollapsedAfterLoad: false,
    expandedFolderIds: new Set(),
    contextMenuTarget: null,
    commandPaletteOpen: false,
  };

  const $ = (id) => document.getElementById(id);
  const setOptionalDisabled = (id, disabled) => {
    const element = $(id);
    if (element) element.disabled = disabled;
  };
  const onOptionalClick = (id, handler) => {
    const element = $(id);
    if (element) element.addEventListener("click", handler);
  };
  const CIPHER = "AES-256-GCM";
  const FOLDER_OBJECT_VERSION = "finite-folder-object-v1";
  const FOLDER_OBJECT_PAGE_VERSION = "finite-folder-object-page-v1";
  const REVISION_VERSION = "finite-folder-object-revision-v1";
  const TOMBSTONE_VERSION = "finite-folder-object-tombstone-v1";
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

  function normalizeAccessValue(access) {
    const value = String(access || "unknown")
      .trim()
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replace(/[-\s]+/g, "_")
      .toLowerCase();
    return value || "unknown";
  }

  function folderAccessValue(folder) {
    return normalizeAccessValue(folder?.access ?? folder?.accessMode ?? folder?.access_mode);
  }

  function folderAccessUsers(folder) {
    return folder?.accessUserIds || folder?.access_user_ids || [];
  }

  function folderStatus(folder) {
    if (folder?.setupIncomplete ?? folder?.setup_incomplete) return "setup";
    if (folderAccessValue(folder) === "restricted" && folderAccessUsers(folder).length === 0) {
      return "locked";
    }
    return "ready";
  }

  function folderAccessLabel(access) {
    const normalized = normalizeAccessValue(access);
    return (
      {
        admin_only: "admin only",
        all_members: "all members",
        owner: "owner",
        restricted: "restricted",
      }[normalized] || normalized.replaceAll("_", " ")
    );
  }

  function metadataFolderRows(metadata) {
    return (metadata?.folders || []).map((folder) => {
      const access = folderAccessValue(folder);
      const status = folderStatus(folder);
      const accessLabel = folderAccessLabel(access);
      const flags = [];
      if (folder.sharedFolderSource ?? folder.shared_folder_source) flags.push("source");
      if (folder.setupIncomplete ?? folder.setup_incomplete) flags.push("setup needed");
      if (status === "locked") flags.push("locked");
      const currentKeyVersion = folder.currentKeyVersion ?? folder.current_key_version ?? 1;
      return {
        access,
        accessLabel,
        accessUserIds: folderAccessUsers(folder),
        currentKeyVersion,
        id: folder.id,
        path: folder.path,
        setupIncomplete: Boolean(folder.setupIncomplete ?? folder.setup_incomplete),
        sharedFolderSource: Boolean(folder.sharedFolderSource ?? folder.shared_folder_source),
        status,
        label: `${folder.path} - ${accessLabel} - key v${currentKeyVersion}`,
        detail: flags.join(", "),
      };
    });
  }

  function folderKeyVersionKey(folderId, keyVersion) {
    return `${folderId}@${keyVersion || 1}`;
  }

  function accessBadgesForFolder(row, openedFolderKeys = new Set()) {
    if (!row) return [];
    const badges = [];
    if (row.access === "admin_only") {
      badges.push({ kind: "access", label: "admin", tone: "warn" });
    } else if (row.access === "restricted") {
      badges.push({ kind: "access", label: "restricted", tone: "warn" });
    } else if (row.access === "all_members") {
      badges.push({ kind: "access", label: "all", tone: "muted" });
    } else {
      badges.push({ kind: "access", label: row.accessLabel || "access", tone: "muted" });
    }
    if (row.sharedFolderSource) badges.push({ kind: "shared", label: "shared", tone: "ready" });
    if (row.setupIncomplete) badges.push({ kind: "setup", label: "setup", tone: "error" });
    if (row.status === "locked" || (row.pageCount > 0 && row.readableCount === 0)) {
      badges.push({ kind: "locked", label: "locked", tone: "warn" });
    }
    if (openedFolderKeys.has(folderKeyVersionKey(row.id, row.currentKeyVersion))) {
      badges.push({ kind: "key", label: "key open", tone: "ready" });
    }
    badges.push({ kind: "version", label: `v${row.currentKeyVersion || 1}`, tone: "muted" });
    return badges;
  }

  function sidebarAccessBadgesForFolder(row, openedFolderKeys = new Set()) {
    return [];
  }

  function accessActionRoute(action, target) {
    if (!target?.folderId) return null;
    if (action === "share-folder") {
      return { folderId: target.folderId, intent: "share", sidebarMode: "access" };
    }
    if (action === "manage-access") {
      return { folderId: target.folderId, intent: "manage", sidebarMode: "access" };
    }
    if (action === "inspect-access") {
      return { folderId: target.folderId, intent: "inspect", sidebarMode: "access" };
    }
    return null;
  }

  function accessPanelState(intent, row) {
    if (!row) {
      return {
        detail: "Load a Vault and select a Folder to inspect access.",
        primaryLabel: "Manage",
        secondaryLabel: "Share",
        status: "empty",
        title: "No Folder selected",
        tone: "muted",
      };
    }
    const pageDetail = readerFolderDetail(row);
    const restricted = row.access === "restricted";
    if (intent === "share" && restricted) {
      return {
        detail: `${pageDetail}. Choose who can see this Folder.`,
        primaryLabel: "Share",
        secondaryLabel: "Manage",
        status: "share",
        title: `Share ${row.path}`,
        tone: "ready",
      };
    }
    if (intent === "manage" && restricted) {
      return {
        detail: `${pageDetail}. Review who can open this Folder.`,
        primaryLabel: "Manage",
        secondaryLabel: "Share",
        status: "manage",
        title: `Manage ${row.path}`,
        tone: row.status === "ready" ? "ready" : "warn",
      };
    }
    return {
      detail: pageDetail,
      primaryLabel: "Manage",
      secondaryLabel: "Share",
      status: row.accessLabel,
      title: row.path,
      tone: row.status === "ready" ? "ready" : "warn",
    };
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

  function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
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

  function bech32Decode(value) {
    const source = String(value || "").trim();
    if (!source) throw new Error("bech32 value is empty");
    if (source !== source.toLowerCase() && source !== source.toUpperCase()) {
      throw new Error("bech32 value mixes upper and lower case");
    }
    const normalized = source.toLowerCase();
    const separator = normalized.lastIndexOf("1");
    if (separator < 1 || separator + 7 > normalized.length) {
      throw new Error("bech32 value is malformed");
    }
    const hrp = normalized.slice(0, separator);
    const data = normalized
      .slice(separator + 1)
      .split("")
      .map((char) => {
        const index = BECH32_CHARSET.indexOf(char);
        if (index === -1) throw new Error("bech32 value has an invalid character");
        return index;
      });
    if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 1) {
      throw new Error("bech32 checksum is invalid");
    }
    return { hrp, data: data.slice(0, -6) };
  }

  function npubFromHex(pubkeyHex) {
    return bech32Encode("npub", convertBits(hexToBytes(pubkeyHex), 8, 5, true));
  }

  function npubToHex(npub) {
    const decoded = bech32Decode(npub);
    if (decoded.hrp !== "npub") throw new Error("expected an npub");
    const bytes = Uint8Array.from(convertBits(decoded.data, 5, 8, false));
    if (bytes.length !== 32) throw new Error("npub must contain a 32-byte public key");
    return bytesToHex(bytes);
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

  function isHex64(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
  }

  function requireHex64(value, field) {
    if (!isHex64(value)) throw new Error(`${field} must be a 64-character hex public key`);
    return value.toLowerCase();
  }

  function parseJsonObject(value, field) {
    let parsed;
    try {
      parsed = JSON.parse(value);
    } catch (_) {
      throw new Error(`${field} is not valid JSON`);
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`${field} must be a JSON object`);
    }
    return parsed;
  }

  function publicKeyTags(event) {
    return (Array.isArray(event?.tags) ? event.tags : []).filter(
      (tag) => Array.isArray(tag) && tag[0] === "p" && typeof tag[1] === "string"
    );
  }

  function validateGiftWrapShell(event, expectedRecipientHex) {
    if (!event || typeof event !== "object") throw new Error("Folder Key Grant wrapper is missing");
    if (event.kind !== 1059) throw new Error("Folder Key Grant wrapper must be kind 1059");
    requireHex64(event.pubkey, "gift wrap pubkey");
    if (typeof event.content !== "string" || !event.content) {
      throw new Error("Folder Key Grant wrapper content is missing");
    }
    const recipients = publicKeyTags(event).map((tag) => requireHex64(tag[1], "gift wrap recipient tag"));
    if (!recipients.length) throw new Error("Folder Key Grant wrapper is missing a recipient tag");
    if (expectedRecipientHex && !recipients.includes(expectedRecipientHex)) {
      throw new Error("Folder Key Grant wrapper is not addressed to the connected signer");
    }
  }

  function validateSealEvent(event) {
    if (!event || typeof event !== "object") throw new Error("Folder Key Grant seal is missing");
    if (event.kind !== 13) throw new Error("Folder Key Grant seal must be kind 13");
    requireHex64(event.pubkey, "seal pubkey");
    if (typeof event.content !== "string" || !event.content) {
      throw new Error("Folder Key Grant seal content is missing");
    }
  }

  function canonicalNostrEventIdInput(event) {
    return JSON.stringify([
      0,
      event.pubkey,
      Number(event.created_at),
      Number(event.kind),
      Array.isArray(event.tags) ? event.tags : [],
      typeof event.content === "string" ? event.content : "",
    ]);
  }

  async function validateRumorEvent(event, expectedIssuerHex) {
    if (!event || typeof event !== "object") throw new Error("Folder Key Grant rumor is missing");
    if (event.kind !== APP_EVENT_KIND) throw new Error(`Folder Key Grant rumor must be kind ${APP_EVENT_KIND}`);
    const rumorPubkey = requireHex64(event.pubkey, "rumor pubkey");
    if (expectedIssuerHex && rumorPubkey !== expectedIssuerHex) {
      throw new Error("Folder Key Grant rumor issuer does not match the seal");
    }
    if (typeof event.content !== "string" || !event.content) {
      throw new Error("Folder Key Grant rumor content is missing");
    }
    if (event.id !== undefined && event.id !== null) {
      requireHex64(event.id, "rumor id");
      const expectedId = await sha256Hex(canonicalNostrEventIdInput(event));
      if (event.id.toLowerCase() !== expectedId) {
        throw new Error("Folder Key Grant rumor id does not match its content");
      }
    }
  }

  function validateFolderKeyGrantPlaintext(plaintext, expectedRecipientNpub = null, grant = null) {
    if (!plaintext || typeof plaintext !== "object") throw new Error("Folder Key Grant plaintext is missing");
    if (plaintext.version !== "finite-folder-key-grant-v1") throw new Error("unsupported Folder Key Grant version");
    if (!plaintext.folderKey) throw new Error("Folder Key Grant is missing a Folder Key");
    if (expectedRecipientNpub && plaintext.recipientNpub !== expectedRecipientNpub) {
      throw new Error("Folder Key Grant recipient does not match the connected signer");
    }
    if (grant?.folderId && plaintext.folderId !== grant.folderId) {
      throw new Error("Folder Key Grant folder does not match export metadata");
    }
    if (grant?.keyVersion && Number(plaintext.keyVersion) !== Number(grant.keyVersion)) {
      throw new Error("Folder Key Grant key version does not match export metadata");
    }
    if (grant?.recipientNpub && plaintext.recipientNpub !== grant.recipientNpub) {
      throw new Error("Folder Key Grant recipient does not match export metadata");
    }
    return plaintext;
  }

  function plaintextDevelopmentGrantFromExportGrant(grant, expectedRecipientNpub = null) {
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

  function nip44DecryptAdapter(options = {}) {
    if (options.decrypt) return options.decrypt;
    const provider = options.provider || window.nostr;
    if (provider?.nip44 && typeof provider.nip44.decrypt === "function") {
      return (pubkeyHex, ciphertext) =>
        invokeNip44ProviderMethod(provider, "decrypt", pubkeyHex, ciphertext);
    }
    return null;
  }

  function nip44EncryptAdapter(options = {}) {
    if (options.encrypt) return options.encrypt;
    const provider = options.provider || window.nostr;
    if (provider?.nip44 && typeof provider.nip44.encrypt === "function") {
      return (pubkeyHex, plaintext) =>
        invokeNip44ProviderMethod(provider, "encrypt", pubkeyHex, plaintext);
    }
    return null;
  }

  async function invokeNip44ProviderMethod(provider, method, peerHex, payload) {
    const api = provider?.nip44;
    const operation = api?.[method];
    if (typeof operation !== "function") throw new Error(`NIP-44 ${method} is unavailable`);
    try {
      return await operation.call(api, peerHex, payload);
    } catch (error) {
      if (!/reading 'enable'/.test(String(error?.message || error))) throw error;
      const receiver = Object.create(api || null);
      receiver.provider = provider;
      const prototypeOperation = Object.getPrototypeOf(api || {})?.[method];
      const fallbacks =
        typeof prototypeOperation === "function" && prototypeOperation !== operation
          ? [prototypeOperation, operation]
          : [operation];
      let fallbackError = error;
      for (const fallback of fallbacks) {
        try {
          return await fallback.call(receiver, peerHex, payload);
        } catch (nextError) {
          fallbackError = nextError;
        }
      }
      throw fallbackError;
    }
  }

  async function plaintextGrantFromGiftWrappedExportGrant(grant, expectedRecipientNpub = null, options = {}) {
    if (!grant?.wrappedEventJson) throw new Error("Folder Key Grant wrapper is missing");
    const decrypt = nip44DecryptAdapter(options);
    if (!decrypt) throw new Error("NIP-44 decryption is unavailable");
    const expectedRecipientHex = expectedRecipientNpub ? npubToHex(expectedRecipientNpub) : null;
    const giftWrap = parseJsonObject(grant.wrappedEventJson, "Folder Key Grant wrapper");
    validateGiftWrapShell(giftWrap, expectedRecipientHex);
    const sealPlaintext = await decrypt(requireHex64(giftWrap.pubkey, "gift wrap pubkey"), giftWrap.content);
    const seal = parseJsonObject(sealPlaintext, "Folder Key Grant seal");
    validateSealEvent(seal);
    const sealIssuerHex = requireHex64(seal.pubkey, "seal pubkey");
    const rumorPlaintext = await decrypt(sealIssuerHex, seal.content);
    const rumor = parseJsonObject(rumorPlaintext, "Folder Key Grant rumor");
    await validateRumorEvent(rumor, sealIssuerHex);
    const plaintext = parseJsonObject(rumor.content, "Folder Key Grant plaintext");
    return validateFolderKeyGrantPlaintext(plaintext, expectedRecipientNpub, grant);
  }

  async function openFolderKeyGrants(keyring, exportedVault, expectedRecipientNpub = null, options = {}) {
    const opened = [];
    const skipped = [];
    for (const grant of exportedVault?.keyGrants || []) {
      try {
        const plaintext = await plaintextGrantFromGiftWrappedExportGrant(grant, expectedRecipientNpub, options);
        await openFolderKeyGrantPlaintext(keyring, plaintext);
        opened.push({
          folderId: plaintext.folderId,
          keyVersion: plaintext.keyVersion,
        });
      } catch (error) {
        skipped.push({
          id: grant.id || grant.folderId || "unknown-grant",
          error: error.message,
        });
      }
    }
    return { opened, skipped };
  }

  async function openDevelopmentFolderKeyGrants(keyring, exportedVault, expectedRecipientNpub = null) {
    const opened = [];
    const skipped = [];
    for (const grant of exportedVault?.keyGrants || []) {
      const plaintext = plaintextDevelopmentGrantFromExportGrant(grant, expectedRecipientNpub);
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
    const page = decodeFolderObjectPagePlaintext(
      new TextDecoder().decode(plaintext),
      input.path || `${input.objectId}.md`
    );
    return {
      folderId: input.folderId,
      objectId: input.objectId,
      path: page.path,
      revision: input.revision,
      status: "ready",
      text: page.markdown,
    };
  }

  function decodeFolderObjectPagePlaintext(plaintext, fallbackPath) {
    const fallback = normalizeSafeRelativePath(fallbackPath || "page.md", "Page path");
    try {
      const page = JSON.parse(String(plaintext || ""));
      if (page?.version === FOLDER_OBJECT_PAGE_VERSION) {
        const path = normalizeSafeRelativePath(page.path, "Page path");
        if (!path.toLowerCase().endsWith(".md")) throw new Error("Page path must end in .md");
        if (typeof page.markdown !== "string") throw new Error("Page markdown must be a string");
        return { path, markdown: page.markdown };
      }
    } catch (error) {
      if (error instanceof SyntaxError) return { path: fallback, markdown: String(plaintext || "") };
      throw error;
    }
    return { path: fallback, markdown: String(plaintext || "") };
  }

  function encodeFolderObjectPagePlaintext(path, markdown) {
    const safePath = normalizeSafeRelativePath(path || "page.md", "Page path");
    if (!safePath.toLowerCase().endsWith(".md")) throw new Error("Page path must end in .md");
    return JSON.stringify({
      version: FOLDER_OBJECT_PAGE_VERSION,
      path: safePath,
      markdown: String(markdown || ""),
    });
  }

  async function ciphertextHash(envelopeJson) {
    return sha256Hex(envelopeJson);
  }

  function revisionCreatedAt(createdAtUnix) {
    return new Date(createdAtUnix * 1000).toISOString().replace(".000Z", "Z");
  }

  function accessChangeCreatedAt(createdAtUnix) {
    return new Date(createdAtUnix * 1000).toISOString().replace(".000Z", "Z");
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

  function revisionTags(input) {
    return [
      [
        "d",
        `finite-folder-object-revision:${input.vaultId}:${input.folderId}:${input.objectId}:${input.revision}`,
      ],
      ["vault", input.vaultId],
      ["folder", input.folderId],
      ["object", input.objectId],
      ["operation", input.operation],
      ["keyVersion", String(input.keyVersion)],
    ];
  }

  function canonicalTombstonePayload(input) {
    return `{"version":${JSON.stringify(TOMBSTONE_VERSION)},"vaultId":${JSON.stringify(
      input.vaultId
    )},"folderId":${JSON.stringify(input.folderId)},"objectId":${JSON.stringify(
      input.objectId
    )},"operation":"delete","revision":${input.revision},"baseRevision":${
      input.baseRevision
    },"authorNpub":${JSON.stringify(input.authorNpub)},"deletedAt":${JSON.stringify(
      input.deletedAt
    )}}`;
  }

  function tombstoneTags(input) {
    return [
      [
        "d",
        `finite-folder-object-tombstone:${input.vaultId}:${input.folderId}:${input.objectId}:${input.revision}`,
      ],
      ["vault", input.vaultId],
      ["folder", input.folderId],
      ["object", input.objectId],
      ["operation", "delete"],
    ];
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
      tags: revisionTags({
        folderId: input.folderId,
        objectId: input.objectId,
        operation: input.operation || (baseRevision === null ? "create" : "update"),
        keyVersion: input.keyVersion,
        revision,
        vaultId: input.vaultId,
      }),
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

  async function buildPageDeleteRequest(input) {
    const baseRevision = Number(input.baseRevision);
    if (!Number.isInteger(baseRevision) || baseRevision < 1) {
      throw new Error("Page delete requires a positive base revision");
    }
    const revision = baseRevision + 1;
    const createdAtUnix = input.createdAtUnix || Math.floor(Date.now() / 1000);
    const deletedAt = revisionCreatedAt(createdAtUnix);
    const payload = canonicalTombstonePayload({
      authorNpub: input.authorNpub,
      baseRevision,
      deletedAt,
      folderId: input.folderId,
      objectId: input.objectId,
      revision,
      vaultId: input.vaultId,
    });
    const eventTemplate = {
      kind: APP_EVENT_KIND,
      created_at: createdAtUnix,
      tags: tombstoneTags({
        folderId: input.folderId,
        objectId: input.objectId,
        revision,
        vaultId: input.vaultId,
      }),
      content: payload,
    };
    const tombstoneEvent = await input.signEvent(eventTemplate);
    return {
      baseRevision,
      tombstoneEvent,
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
            title: opened.text
              ? pageTitleFromText(opened.text, pageTitleFromPath(opened.path || object.path, object.objectId))
              : object.title,
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

  function pageTitleFromPath(path, fallback) {
    const filename = String(path || "")
      .split("/")
      .filter(Boolean)
      .pop();
    return filename ? filename.replace(/\.md$/i, "") : fallback;
  }

  function pageTitleForPage(page) {
    return page.title || pageTitleFromText(page.text ?? "", pageTitleFromPath(page.path, page.objectId));
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

  function inlineLinkSegments(text) {
    const source = String(text || "");
    const segments = [];
    const pattern = /\[\[([^\]|#]+)(?:#[^\]|]*)?(?:\|([^\]]+))?\]\]|\[([^\]]+)\]\(([^)]+)\)/g;
    let cursor = 0;
    for (const match of source.matchAll(pattern)) {
      if (match.index > cursor) {
        segments.push({ kind: "text", text: source.slice(cursor, match.index) });
      }
      if (match[1]) {
        segments.push({
          kind: "internal",
          target: normalizePageReference(match[1]),
          text: String(match[2] || match[1]).trim(),
        });
      } else {
        const target = String(match[4] || "").trim();
        const external = /^https?:\/\//i.test(target);
        segments.push({
          kind: external ? "external" : "internal",
          target: external ? target : normalizePageReference(target.split("#")[0]),
          text: String(match[3] || target).trim(),
        });
      }
      cursor = match.index + match[0].length;
    }
    if (cursor < source.length) {
      segments.push({ kind: "text", text: source.slice(cursor) });
    }
    return segments.filter((segment) => segment.text || segment.target);
  }

  function splitMarkdownTableRow(line) {
    let source = String(line || "").trim();
    if (!source.includes("|")) return null;
    if (source.startsWith("|")) source = source.slice(1);
    if (source.endsWith("|")) source = source.slice(0, -1);
    const cells = [];
    let cell = "";
    let escaped = false;
    for (const char of source) {
      if (char === "\\" && !escaped) {
        escaped = true;
        cell += char;
        continue;
      }
      if (char === "|" && !escaped) {
        cells.push(cell.trim().replaceAll("\\|", "|"));
        cell = "";
        continue;
      }
      escaped = false;
      cell += char;
    }
    cells.push(cell.trim().replaceAll("\\|", "|"));
    return cells.length > 1 ? cells : null;
  }

  function tableDelimiterAlignments(cells) {
    const alignments = [];
    for (const cell of cells || []) {
      const value = String(cell || "").trim();
      if (!/^:?-{3,}:?$/.test(value)) return null;
      if (value.startsWith(":") && value.endsWith(":")) alignments.push("center");
      else if (value.endsWith(":")) alignments.push("right");
      else if (value.startsWith(":")) alignments.push("left");
      else alignments.push("");
    }
    return alignments.length ? alignments : null;
  }

  function parseMarkdownListItem(line) {
    const trimmed = String(line || "").trim();
    const ordered = trimmed.match(/^(\d+)[.)]\s+(.+)$/);
    if (ordered) {
      return {
        checked: null,
        ordered: true,
        start: Number(ordered[1]) || 1,
        text: ordered[2].trim(),
      };
    }
    const unordered = trimmed.match(/^[-*+]\s+(.+)$/);
    if (!unordered) return null;
    const task = unordered[1].match(/^\[([ xX])\]\s+(.+)$/);
    return {
      checked: task ? task[1].toLowerCase() === "x" : null,
      ordered: false,
      start: null,
      text: (task ? task[2] : unordered[1]).trim(),
    };
  }

  function normalizeMarkdownTableRow(cells, width) {
    return Array.from({ length: width }, (_, index) => String(cells[index] || "").trim());
  }

  function normalizeCodeBlockText(value) {
    let lines = Array.isArray(value)
      ? value.map((line) => String(line || ""))
      : String(value || "").replace(/\r\n/g, "\n").split("\n");
    while (lines.length && !lines[0].trim()) lines.shift();
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
    const indentedLines = lines.filter((line) => line.trim()).map((line) => line.match(/^[ \t]*/)?.[0] || "");
    if (indentedLines.length && indentedLines.every((indent) => indent.length > 0)) {
      let sharedIndent = indentedLines[0];
      for (const indent of indentedLines.slice(1)) {
        while (sharedIndent && !indent.startsWith(sharedIndent)) sharedIndent = sharedIndent.slice(0, -1);
      }
      if (sharedIndent) {
        lines = lines.map((line) => (line.startsWith(sharedIndent) ? line.slice(sharedIndent.length) : line));
      }
    }
    return lines.join("\n");
  }

  function markdownPreviewBlocks(markdown) {
    const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
    const blocks = [];
    let paragraph = [];

    function flushParagraph() {
      if (!paragraph.length) return;
      blocks.push({ text: paragraph.join(" "), type: "paragraph" });
      paragraph = [];
    }

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const trimmed = line.trim();
      if (!trimmed) {
        flushParagraph();
        continue;
      }
      const fence = trimmed.match(/^(```|~~~)\s*([A-Za-z0-9_+.#-]+)?\s*$/);
      if (fence) {
        flushParagraph();
        const code = [];
        const fenceMarker = fence[1];
        const language = fence[2] || "";
        index += 1;
        while (index < lines.length && !lines[index].trim().startsWith(fenceMarker)) {
          code.push(lines[index]);
          index += 1;
        }
        blocks.push({ language, text: normalizeCodeBlockText(code), type: "code" });
        continue;
      }
      const heading = trimmed.match(/^(#{1,6})\s+(.+?)\s*#*$/);
      if (heading) {
        flushParagraph();
        blocks.push({ level: heading[1].length, text: heading[2].trim(), type: "heading" });
        continue;
      }
      const headerCells = splitMarkdownTableRow(trimmed);
      const delimiterCells = splitMarkdownTableRow(lines[index + 1] || "");
      const tableAlignments = tableDelimiterAlignments(delimiterCells);
      if (headerCells && tableAlignments && headerCells.length === tableAlignments.length) {
        flushParagraph();
        const width = headerCells.length;
        const rows = [];
        index += 2;
        while (index < lines.length) {
          const rowCells = splitMarkdownTableRow(lines[index]);
          if (!rowCells) break;
          rows.push(normalizeMarkdownTableRow(rowCells, width));
          index += 1;
        }
        index -= 1;
        blocks.push({
          alignments: tableAlignments,
          headers: normalizeMarkdownTableRow(headerCells, width),
          rows,
          type: "table",
        });
        continue;
      }
      const listItem = parseMarkdownListItem(trimmed);
      if (listItem) {
        flushParagraph();
        const ordered = listItem.ordered;
        const items = [];
        let start = listItem.start;
        while (index < lines.length) {
          const item = parseMarkdownListItem(lines[index]);
          if (!item || item.ordered !== ordered) break;
          if (start === null) start = item.start;
          items.push({
            checked: item.checked,
            text: item.text,
          });
          index += 1;
        }
        index -= 1;
        blocks.push({ items, ordered, start, type: "list" });
        continue;
      }
      if (/^>\s?/.test(trimmed)) {
        flushParagraph();
        const quotes = [];
        while (index < lines.length && /^>\s?/.test(lines[index].trim())) {
          quotes.push(lines[index].trim().replace(/^>\s?/, ""));
          index += 1;
        }
        index -= 1;
        blocks.push({ text: quotes.join(" "), type: "quote" });
        continue;
      }
      if (/^([-*_])(?:\s*\1){2,}$/.test(trimmed)) {
        flushParagraph();
        blocks.push({ type: "rule" });
        continue;
      }
      paragraph.push(trimmed);
    }
    flushParagraph();
    return blocks;
  }

  function pageStatsForText(text) {
    const clean = String(text || "").trim();
    const words = clean ? clean.split(/\s+/).filter(Boolean).length : 0;
    return {
      links: extractPageLinks(clean).length,
      words,
    };
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
        plaintext: encodeFolderObjectPagePlaintext(entry.targetPath, entry.markdown),
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
      const title = pageTitleForPage(page);
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

  function stableGraphHash(value) {
    let hash = 2166136261;
    for (const char of String(value || "")) {
      hash ^= char.charCodeAt(0);
      hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
  }

  function stableUnitInterval(value) {
    return stableGraphHash(value) / 0xffffffff;
  }

  function graphLayout(graph, options = {}) {
    const width = Number(options.width || graphViewport.width);
    const height = Number(options.height || graphViewport.height);
    const margin = Number(options.margin || 44);
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

    const folderIds = [...new Set(orderedNodes.map((node) => node.folderId || ""))].sort();
    const folderCenters = new Map();
    folderIds.forEach((folderId, index) => {
      const angle =
        (Math.PI * 2 * index) / Math.max(1, folderIds.length) +
        stableUnitInterval(`folder-angle:${folderId}`) * 0.82;
      const radius = 0.42 + stableUnitInterval(`folder-radius:${folderId}`) * 0.38;
      folderCenters.set(folderId, {
        x: centerX + Math.cos(angle) * radiusX * radius,
        y: centerY + Math.sin(angle) * radiusY * radius,
      });
    });

    const hasHub = orderedNodes.length > 4 && (degree.get(orderedNodes[0].id) || 0) > 1;
    const nodeState = orderedNodes.map((node) => {
      const nodeDegree = degree.get(node.id) || 0;
      const folderCenter = folderCenters.get(node.folderId || "") || { x: centerX, y: centerY };
      const jitterAngle = stableUnitInterval(`node-angle:${node.id}`) * Math.PI * 2;
      const jitterRadius = Math.sqrt(stableUnitInterval(`node-radius:${node.id}`)) * 136;
      const scatterAngle = stableUnitInterval(`loose-angle:${node.id}`) * Math.PI * 2;
      const scatterRadius = 0.2 + stableUnitInterval(`loose-radius:${node.id}`) * 0.72;
      const looseX = centerX + Math.cos(scatterAngle) * radiusX * scatterRadius;
      const looseY = centerY + Math.sin(scatterAngle) * radiusY * scatterRadius;
      const fixed = hasHub && node.id === orderedNodes[0].id && orderedNodes.length < 18;
      return {
        fixed,
        id: node.id,
        loose: nodeDegree === 0,
        x: fixed
          ? centerX
          : nodeDegree === 0
            ? looseX
            : folderCenter.x + Math.cos(jitterAngle) * jitterRadius,
        y: fixed
          ? centerY
          : nodeDegree === 0
            ? looseY
            : folderCenter.y + Math.sin(jitterAngle) * jitterRadius,
        vx: 0,
        vy: 0,
      };
    });
    const byId = new Map(nodeState.map((node) => [node.id, node]));
    const links = graph.edges
      .map((edge) => ({ source: byId.get(edge.source), target: byId.get(edge.target) }))
      .filter((edge) => edge.source && edge.target);
    const iterations = Math.min(220, Math.max(110, orderedNodes.length * 5));
    const linkDistance = Math.max(76, Math.min(138, 112 - Math.sqrt(orderedNodes.length) * 0.8));
    const repulsion = Math.max(380, Math.min(1120, 7600 / Math.sqrt(orderedNodes.length)));
    for (let iteration = 0; iteration < iterations; iteration += 1) {
      for (let leftIndex = 0; leftIndex < nodeState.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < nodeState.length; rightIndex += 1) {
          const left = nodeState[leftIndex];
          const right = nodeState[rightIndex];
          let dx = right.x - left.x;
          let dy = right.y - left.y;
          let distanceSq = dx * dx + dy * dy;
          if (distanceSq < 0.01) {
            dx = stableUnitInterval(`overlap-x:${left.id}:${right.id}`) - 0.5;
            dy = stableUnitInterval(`overlap-y:${left.id}:${right.id}`) - 0.5;
            distanceSq = dx * dx + dy * dy;
          }
          const distance = Math.sqrt(distanceSq);
          const force = repulsion / Math.max(distanceSq, 160);
          const fx = (dx / distance) * force;
          const fy = (dy / distance) * force;
          if (!left.fixed) {
            left.vx -= fx;
            left.vy -= fy;
          }
          if (!right.fixed) {
            right.vx += fx;
            right.vy += fy;
          }
        }
      }
      for (const link of links) {
        const dx = link.target.x - link.source.x;
        const dy = link.target.y - link.source.y;
        const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy));
        const force = (distance - linkDistance) * 0.018;
        const fx = (dx / distance) * force;
        const fy = (dy / distance) * force;
        if (!link.source.fixed) {
          link.source.vx += fx;
          link.source.vy += fy;
        }
        if (!link.target.fixed) {
          link.target.vx -= fx;
          link.target.vy -= fy;
        }
      }
      for (const node of nodeState) {
        if (node.fixed) {
          node.x = centerX;
          node.y = centerY;
          node.vx = 0;
          node.vy = 0;
          continue;
        }
        const centerForce = node.loose ? 0.00035 : 0.0012;
        node.vx += (centerX - node.x) * centerForce;
        node.vy += (centerY - node.y) * centerForce;
        node.vx *= 0.88;
        node.vy *= 0.88;
        node.x = Math.min(width - margin, Math.max(margin, node.x + node.vx));
        node.y = Math.min(height - margin, Math.max(margin, node.y + node.vy));
      }
    }

    for (const node of nodeState) {
      positions.set(node.id, {
        x: Math.round(node.fixed ? centerX : node.x),
        y: Math.round(node.fixed ? centerY : node.y),
      });
    }
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
        path: draft.path || `${objectId}.md`,
        status: "ready",
        text: draft.text,
        title: pageTitleFromText(draft.text, pageTitleFromPath(draft.path, objectId)),
      });
    }
    for (const [key, page] of state.projection.pages.entries()) {
      if (isReadablePage(page)) {
        const [folderId, objectId] = key.split("/");
        pages.push({
          folderId,
          objectId,
          path: page.path || `${objectId}.md`,
          status: "ready",
          text: page.text,
          title: pageTitleForPage({ ...page, objectId }),
        });
      }
    }
    return pages;
  }

  function projectionPagesFromProjection(projection) {
    const pages = new Map(
      [...projection.pages.entries()].map(([key, page]) => [
        key,
        {
          ...page,
          key,
          title: pageTitleForPage(page),
        },
      ])
    );
    for (const [key, draft] of projection.localDrafts.entries()) {
      const [folderId, objectId] = key.split("/");
      pages.set(key, {
        baseRevision: draft.baseRevision || 0,
        folderId,
        key,
        localDraft: true,
        objectId,
        path: draft.path || `${objectId}.md`,
        revision: draft.baseRevision || 0,
        status: "ready",
        text: draft.text,
        title: pageTitleFromText(draft.text, pageTitleFromPath(draft.path, objectId)),
      });
    }
    return [...pages.values()];
  }

  function projectionPages() {
    return projectionPagesFromProjection(state.projection);
  }

  function pageTextIsPresent(page) {
    return page?.text !== undefined && page?.text !== null;
  }

  function isReadablePage(page) {
    return page?.status === "ready" && pageTextIsPresent(page);
  }

  function readablePages() {
    return projectionPages().filter(isReadablePage);
  }

  function readerFolderRows(metadata, pages = projectionPages()) {
    const pageCounts = new Map();
    const readableCounts = new Map();
    for (const page of pages) {
      pageCounts.set(page.folderId, (pageCounts.get(page.folderId) || 0) + 1);
      if (isReadablePage(page)) {
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
      .map((page) => {
        const title = pageTitleForPage(page);
        return {
          ...page,
          title,
          label: title,
          detail: readerPageDetail({ ...page, title }),
        };
      })
      .sort((left, right) => left.title.localeCompare(right.title));
  }

  function pageLinkContext(page, pages = readablePages()) {
    if (!isReadablePage(page)) return { backlinks: [], outgoing: [] };
    const keyForPage = (candidate) => candidate.key || pageKey(candidate.folderId, candidate.objectId);
    const readable = [...pages].filter(isReadablePage);
    const referencesForPage = (candidate) =>
      [
        pageTitleForPage(candidate),
        candidate.path || `${candidate.objectId}.md`,
        String(candidate.path || `${candidate.objectId}.md`).split("/").pop(),
      ]
        .map(normalizePageReference)
        .filter(Boolean);
    const byReference = new Map();
    for (const candidate of readable) {
      for (const reference of referencesForPage(candidate)) {
        if (!byReference.has(reference)) byReference.set(reference, candidate);
      }
    }
    const currentKey = keyForPage(page);
    const currentReferences = new Set(referencesForPage(page));
    const outgoing = extractPageLinks(page.text).map((targetRef) => {
      const target = byReference.get(targetRef);
      if (!target) {
        return {
          detail: "unresolved",
          key: null,
          label: targetRef,
          status: "missing",
        };
      }
      return {
        detail: target.folderId,
        key: keyForPage(target),
        label: pageTitleForPage(target),
        status: "resolved",
      };
    });
    const backlinks = readable
      .filter((candidate) => keyForPage(candidate) !== currentKey)
      .filter((candidate) =>
        extractPageLinks(candidate.text).some((targetRef) => currentReferences.has(targetRef))
      )
      .map((candidate) => ({
        detail: candidate.folderId,
        key: keyForPage(candidate),
        label: pageTitleForPage(candidate),
        status: "resolved",
      }))
      .sort((left, right) => left.label.localeCompare(right.label));
    return { backlinks, outgoing };
  }

  function pageCountLabel(count) {
    return `${count} ${count === 1 ? "page" : "pages"}`;
  }

  function pagePathLabel(page) {
    if (!page) return "No page path loaded";
    return `${page.folderId}/${page.path || `${page.objectId}.md`}`;
  }

  function readerPageDetail(page) {
    if (!page) return "";
    if (page.status === "ready") {
      return page.path || `${page.objectId}.md`;
    }
    return `locked - ${page.folderId}/${page.objectId}`;
  }

  function readerFolderDetail(row) {
    if (!row.pageCount) return "Empty";
    if (row.readableCount === row.pageCount) {
      return pageCountLabel(row.pageCount);
    }
    if (!row.readableCount) {
      return "Locked";
    }
    return `${row.readableCount}/${row.pageCount}`;
  }

  function selectDefaultReaderTargets() {
    const folders = readerFolderRows(state.metadata);
    const folderStillExists = folders.some((folder) => folder.id === state.selectedFolderId);
    let selectedFolderChanged = false;
    if (!folderStillExists) {
      const folderWithReadablePages = folders.find((folder) => folder.readableCount > 0);
      state.selectedFolderId = folderWithReadablePages?.id || folders[0]?.id || null;
      selectedFolderChanged = Boolean(state.selectedFolderId);
    }
    if (selectedFolderChanged) state.expandedFolderIds.add(state.selectedFolderId);

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

  function sidebarModeLabel(mode) {
    return (
      {
        access: "Access",
        files: "Files",
        search: "Search",
      }[normalizeSidebarMode(mode)] || "Files"
    );
  }

  function normalizeSidebarMode(mode) {
    return ["files", "search", "access"].includes(mode) ? mode : "files";
  }

  function commandPaletteCommands() {
    return [
      { id: "files", kind: "command", label: "Files", detail: "Sidebar", target: "files" },
      { id: "search", kind: "command", label: "Search", detail: "Sidebar", target: "search" },
      { id: "access", kind: "command", label: "Access", detail: "Sidebar", target: "access" },
      { id: "graph", kind: "command", label: "Graph View", detail: "Workspace", target: "graph" },
      { id: "new-page", kind: "command", label: "New Page", detail: "Current Folder", target: "new-page" },
      { id: "refresh", kind: "command", label: "Refresh Vault", detail: "Sync", target: "refresh" },
    ];
  }

  function commandPaletteRows(query, pages = readablePages()) {
    const needle = String(query || "").trim().toLowerCase();
    const pageRows = pages.map((page) => ({
      detail: pagePathLabel(page),
      id: page.key || pageKey(page.folderId, page.objectId),
      kind: "page",
      label: pageTitleForPage(page),
      pageKey: page.key || pageKey(page.folderId, page.objectId),
    }));
    const rows = [...commandPaletteCommands(), ...pageRows];
    if (!needle) return rows.slice(0, 12);
    return rows
      .filter((row) =>
        [row.label, row.detail, row.kind].filter(Boolean).join("\n").toLowerCase().includes(needle)
      )
      .slice(0, 12);
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
        pageTitleForPage(left).localeCompare(pageTitleForPage(right))
      )
      .map((page) => ({
        ...page,
        label: pageTitleForPage(page),
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
        { action: "delete-page", label: "Delete Page", disabled: false, danger: true },
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
      pageHidden: !pageActive,
      ribbonGraphClass: `ribbon-button${pageActive ? "" : " active"}`,
      shellView: pageActive ? "page" : "graph",
    };
  }

  function renderWorkspaceChrome(page = selectedReaderPage()) {
    const chrome = workspaceChromeState(state.activeWorkspaceView);
    const workspaceTitle = workspaceTabTitle(state.metadata, page);
    const shell = document.querySelector(".obsidian-shell");
    shell.dataset.workspaceView = chrome.shellView;
    shell.dataset.vaultLoaded = state.metadata ? "true" : "false";
    $("pageWorkspace").hidden = chrome.pageHidden;
    $("graphWorkspace").hidden = chrome.graphHidden;
    $("ribbonGraphButton").className = chrome.ribbonGraphClass;
    setPressed("ribbonGraphButton", !chrome.graphHidden);
    document.title = chrome.shellView === "graph" ? "Graph View - FiniteBrain" : `${workspaceTitle} - FiniteBrain`;
  }

  function renderVaultControlChrome() {
    const details = $("vaultControlDetails");
    if (!details) return;
    setText("vaultControlSummary", state.metadata?.name || state.activeVaultId || "smoke");
    if (state.metadata && !state.vaultControlsCollapsedAfterLoad) {
      details.open = false;
      state.vaultControlsCollapsedAfterLoad = true;
    }
    if (!state.metadata && state.vaultControlsCollapsedAfterLoad) {
      details.open = true;
      state.vaultControlsCollapsedAfterLoad = false;
    }
  }

  function nextDraftObjectId() {
    return `obj_${Date.now().toString(36)}`.padEnd(16, "0").slice(0, 128);
  }

  function visualEditorElement() {
    return $("readerPageContent");
  }

  function focusInlineEditor() {
    const focusDraft = () => {
      if (state.editorMode === "source") {
        const draft = $("pageDraftInput");
        draft.focus?.();
        draft.setSelectionRange?.(draft.value.length, draft.value.length);
      } else {
        visualEditorElement()?.focus?.();
      }
    };
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(focusDraft);
    else focusDraft();
  }

  function startNewPageDraft(folderIdOverride = null) {
    const folderId = folderIdOverride || state.selectedFolderId || "general";
    const objectId = nextDraftObjectId();
    const draftKey = pageKey(folderId, objectId);
    const draftText = "# New Page\n\nStart writing here.";
    state.selectedFolderId = folderId;
    state.selectedPageKey = draftKey;
    state.preparedWrite = null;
    state.preparedWriteTarget = null;
    state.activeWorkspaceView = "page";
    state.expandedFolderIds.add(folderId);
    $("pageFolderIdInput").value = folderId;
    $("okfDestinationFolderInput").value = folderId;
    $("pageObjectIdInput").value = objectId;
    $("pageBaseRevisionInput").value = "";
    setEditorDraftText(draftText);
    state.projection.localDrafts.set(draftKey, {
      baseRevision: 0,
      path: `${objectId}.md`,
      text: draftText,
    });
    log("Started a new Page draft.", { folderId, objectId });
    render();
    focusInlineEditor();
  }

  function pageFromContextTarget(target) {
    if (!target || target.type !== "page") return null;
    const key = target.pageKey || pageKey(target.folderId, target.objectId);
    return projectionPages().find((page) => page.key === key) || null;
  }

  async function deletePageFromContextTarget(target) {
    const page = pageFromContextTarget(target);
    if (!page || !isReadablePage(page)) throw new Error("Select a readable Page before deleting");
    if (!page.revision) throw new Error("Page delete requires a saved revision");
    if (state.signerStatus !== "connected") throw new Error("Connect a NIP-07 signer before deleting");
    const title = pageTitleForPage(page);
    if (window.confirm && !window.confirm(`Delete "${title}"? This writes a signed tombstone.`)) return;
    const body = await buildPageDeleteRequest({
      authorNpub: currentActorNpub(),
      baseRevision: page.revision,
      folderId: page.folderId,
      objectId: page.objectId,
      signEvent: (event) => window.nostr.signEvent(event),
      vaultId: state.activeVaultId,
    });
    const route = `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/folders/${encodeURIComponent(
      page.folderId
    )}/objects/${encodeURIComponent(page.objectId)}`;
    const result = await protectedRequest(route, {
      method: "DELETE",
      body: JSON.stringify(body),
    });
    const key = page.key || pageKey(page.folderId, page.objectId);
    state.projection.pages.delete(key);
    state.projection.localDrafts.delete(key);
    if (state.selectedPageKey === key) state.selectedPageKey = null;
    selectDefaultReaderTargets();
    log("Deleted Page through signed tombstone.", {
      folderId: page.folderId,
      objectId: page.objectId,
      revision: result.revision,
      sequence: result.sequence,
    });
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

  function selectAccessFolder(folderId, intent = "inspect") {
    if (state.activeAccessFolderId !== folderId || state.activeAccessIntent !== intent) {
      state.accessResult = null;
    }
    state.activeAccessFolderId = folderId;
    state.activeAccessIntent = intent;
    selectReaderFolder(folderId, { selectFirstPage: false });
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
      if (pageTextIsPresent(page)) setEditorDraftText(page.text);
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
        title: pageTitleFromText(draft.text, pageTitleFromPath(draft.path, objectId)),
      });
    }
    for (const [key, page] of state.projection.pages.entries()) {
      const [folderId, objectId] = key.split("/");
      pages.push({
        folderId,
        objectId,
        revision: page.revision || 0,
        path: page.path || `${objectId}.md`,
        title: pageTitleForPage({ ...page, objectId }),
      });
    }
    return pages;
  }

  function graphEmptyStateCopy(options = {}) {
    const filterText = String(options.filterText || "").trim();
    const readablePageCount = Number(options.readablePageCount || 0);
    if (readablePageCount <= 0) {
      return {
        title: "No graph yet",
        copy: "Open a vault to build the local graph.",
      };
    }
    if (filterText) {
      return {
        title: "No matching Pages",
        copy: "Clear or change the graph filter.",
      };
    }
    return {
      title: "No links yet",
      copy: "Readable pages are open, but none link to another page yet.",
    };
  }

  function drawGraph(graph, options = {}) {
    const svg = $("graphCanvas");
    const emptyState = $("graphEmptyState");
    svg.replaceChildren();
    svg.setAttribute("viewBox", `0 0 ${graphViewport.width} ${graphViewport.height}`);
    if (!graph.nodes.length) {
      if (emptyState) {
        const copy = graphEmptyStateCopy(options);
        setText("graphEmptyTitle", copy.title);
        setText("graphEmptyCopy", copy.copy);
        emptyState.hidden = false;
      }
      return;
    }
    if (emptyState) emptyState.hidden = true;
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
      const degree = edgeDegree.get(node.id) || 0;
      const isSelected =
        state.selectedPageKey && node.id === state.selectedPageKey;
      circle.setAttribute(
        "class",
        `node${degree > 1 ? " focus" : ""}${isSelected ? " selected" : ""}`
      );
      circle.setAttribute("cx", String(position.x));
      circle.setAttribute("cy", String(position.y));
      circle.setAttribute("r", String(Math.min(5.6, 2.1 + degree * 0.36)));
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
    if (!element) return;
    element.textContent = text;
    element.className = `pill ${tone || "muted"}`;
  }

  function openedGrantFolderKeys() {
    return new Set(
      (state.keyring?.openedGrants || []).map((grant) =>
        folderKeyVersionKey(grant.folderId, grant.keyVersion)
      )
    );
  }

  function appendAccessBadges(parent, badges) {
    if (!badges.length) return;
    const row = document.createElement("span");
    row.className = "access-badge-row";
    for (const badge of badges) {
      const element = document.createElement("span");
      element.className = `access-badge ${badge.tone || "muted"}`;
      element.textContent = badge.label;
      row.appendChild(element);
    }
    parent.appendChild(row);
  }

  function renderAccessBadgeRow(id, badges) {
    const row = $(id);
    if (!row) return;
    row.replaceChildren();
    for (const badge of badges) {
      const element = document.createElement("span");
      element.className = `access-badge ${badge.tone || "muted"}`;
      element.textContent = badge.label;
      row.appendChild(element);
    }
  }

  function setText(id, text) {
    const element = $(id);
    if (element) element.textContent = text;
  }

  function setPressed(id, pressed) {
    const element = $(id);
    if (element) element.setAttribute("aria-pressed", String(Boolean(pressed)));
  }

  function appendFormattedText(parent, text) {
    const source = String(text || "");
    const pattern = /`([^`]+)`|\*\*([^*]+)\*\*|__([^_]+)__|~~([^~]+)~~|\*([^*]+)\*|_([^_]+)_/g;
    let cursor = 0;
    for (const match of source.matchAll(pattern)) {
      if (match.index > cursor) {
        parent.appendChild(document.createTextNode(source.slice(cursor, match.index)));
      }
      if (match[1]) {
        const code = document.createElement("code");
        code.textContent = match[1];
        parent.appendChild(code);
      } else if (match[2] || match[3]) {
        const strong = document.createElement("strong");
        strong.textContent = match[2] || match[3];
        parent.appendChild(strong);
      } else if (match[4]) {
        const strike = document.createElement("del");
        strike.textContent = match[4];
        parent.appendChild(strike);
      } else if (match[5] || match[6]) {
        const emphasis = document.createElement("em");
        emphasis.textContent = match[5] || match[6];
        parent.appendChild(emphasis);
      }
      cursor = match.index + match[0].length;
    }
    if (cursor < source.length) parent.appendChild(document.createTextNode(source.slice(cursor)));
  }

  function appendInlineSegments(parent, text) {
    for (const segment of inlineLinkSegments(text)) {
      if (segment.kind === "text") {
        appendFormattedText(parent, segment.text);
        continue;
      }
      const link = document.createElement("span");
      link.className = segment.kind === "external" ? "external-link" : "internal-link";
      appendFormattedText(link, segment.text || segment.target);
      if (segment.target) link.dataset.target = segment.target;
      parent.appendChild(link);
    }
  }

  function renderMarkdownPreview(container, markdown) {
    container.replaceChildren();
    for (const block of markdownPreviewBlocks(markdown)) {
      if (block.type === "heading") {
        const heading = document.createElement(`h${block.level}`);
        appendInlineSegments(heading, block.text);
        container.appendChild(heading);
        continue;
      }
      if (block.type === "list") {
        const list = document.createElement(block.ordered ? "ol" : "ul");
        if (block.ordered && block.start && block.start !== 1) list.start = block.start;
        if (!block.ordered && block.items.some((item) => item.checked !== null)) {
          list.className = "task-list";
        }
        for (const itemBlock of block.items) {
          const item = document.createElement("li");
          if (itemBlock.checked !== null) {
            item.className = "task-list-item";
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.checked = Boolean(itemBlock.checked);
            checkbox.disabled = true;
            item.appendChild(checkbox);
          }
          appendInlineSegments(item, itemBlock.text);
          list.appendChild(item);
        }
        container.appendChild(list);
        continue;
      }
      if (block.type === "quote") {
        const quote = document.createElement("blockquote");
        appendInlineSegments(quote, block.text);
        container.appendChild(quote);
        continue;
      }
      if (block.type === "code") {
        const pre = document.createElement("pre");
        pre.className = "code-block";
        if (block.language) {
          pre.dataset.language = block.language;
          pre.setAttribute?.("data-language", block.language);
        }
        const code = document.createElement("code");
        if (block.language) code.className = `language-${block.language}`;
        code.textContent = block.text;
        pre.appendChild(code);
        container.appendChild(pre);
        continue;
      }
      if (block.type === "table") {
        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const headerRow = document.createElement("tr");
        block.headers.forEach((header, index) => {
          const cell = document.createElement("th");
          if (block.alignments[index] && cell.style) cell.style.textAlign = block.alignments[index];
          appendInlineSegments(cell, header);
          headerRow.appendChild(cell);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);
        const tbody = document.createElement("tbody");
        for (const row of block.rows) {
          const tableRow = document.createElement("tr");
          row.forEach((value, index) => {
            const cell = document.createElement("td");
            if (block.alignments[index] && cell.style) cell.style.textAlign = block.alignments[index];
            appendInlineSegments(cell, value);
            tableRow.appendChild(cell);
          });
          tbody.appendChild(tableRow);
        }
        table.appendChild(tbody);
        container.appendChild(table);
        continue;
      }
      if (block.type === "rule") {
        container.appendChild(document.createElement("hr"));
        continue;
      }
      const paragraph = document.createElement("p");
      appendInlineSegments(paragraph, block.text);
      container.appendChild(paragraph);
    }
  }

  function renderMarkdownEditor(container, markdown) {
    renderMarkdownPreview(container, markdown);
    if (!container.childNodes.length) {
      const paragraph = document.createElement("p");
      paragraph.appendChild(document.createElement("br"));
      container.appendChild(paragraph);
    }
  }

  function escapeMarkdownCode(value) {
    return String(value || "").replaceAll("`", "\\`");
  }

  function inlineMarkdownFromEditorNode(node) {
    if (!node) return "";
    if (node.nodeType === 3) return String(node.nodeValue || "").replace(/\u00a0/g, " ");
    if (node.nodeType !== 1) return "";
    const tag = String(node.tagName || "").toLowerCase();
    if (tag === "br") return "\n";
    if (tag === "input") return "";
    const text = Array.from(node.childNodes || []).map(inlineMarkdownFromEditorNode).join("");
    if (!text && tag !== "img") return "";
    if (tag === "strong" || tag === "b") return `**${text}**`;
    if (tag === "em" || tag === "i") return `*${text}*`;
    if (tag === "del" || tag === "s") return `~~${text}~~`;
    if (tag === "code") return `\`${escapeMarkdownCode(text)}\``;
    if (tag === "a") {
      const target = node.getAttribute?.("href") || node.dataset?.target || "";
      return target ? `[${text || target}](${target})` : text;
    }
    const className = String(node.className || "");
    if (className.includes("internal-link") && node.dataset?.target) {
      return text && text !== node.dataset.target
        ? `[[${node.dataset.target}|${text}]]`
        : `[[${node.dataset.target}]]`;
    }
    if (className.includes("external-link") && node.dataset?.target) {
      return `[${text || node.dataset.target}](${node.dataset.target})`;
    }
    return text;
  }

  function markdownTableCellFromNode(node) {
    return inlineMarkdownFromEditorNode(node)
      .replace(/\n+/g, " ")
      .replaceAll("|", "\\|")
      .trim();
  }

  function tableRowsFromSection(section, cellTag) {
    const rows = [];
    for (const row of Array.from(section?.children || [])) {
      const cells = Array.from(row.children || []).filter(
        (cell) => String(cell.tagName || "").toLowerCase() === cellTag
      );
      if (cells.length) rows.push(cells.map(markdownTableCellFromNode));
    }
    return rows;
  }

  function tableMarkdownFromEditorNode(node) {
    const sections = Array.from(node.children || []);
    const head = sections.find((child) => String(child.tagName || "").toLowerCase() === "thead");
    const body = sections.find((child) => String(child.tagName || "").toLowerCase() === "tbody");
    let headers = tableRowsFromSection(head, "th")[0] || [];
    let rows = tableRowsFromSection(body, "td");
    if (!headers.length && rows.length) {
      headers = rows.shift();
    }
    if (!headers.length) return "";
    const width = Math.max(headers.length, ...rows.map((row) => row.length));
    const paddedHeaders = normalizeMarkdownTableRow(headers, width);
    const paddedRows = rows.map((row) => normalizeMarkdownTableRow(row, width));
    return [
      `| ${paddedHeaders.join(" | ")} |`,
      `| ${Array.from({ length: width }, () => "---").join(" | ")} |`,
      ...paddedRows.map((row) => `| ${row.join(" | ")} |`),
    ].join("\n");
  }

  function editorBlockMarkdown(node) {
    if (!node) return "";
    if (node.nodeType === 3) return String(node.nodeValue || "").trim();
    if (node.nodeType !== 1) return "";
    const tag = String(node.tagName || "").toLowerCase();
    if (/^h[1-6]$/.test(tag)) {
      return `${"#".repeat(Number(tag.slice(1)))} ${inlineMarkdownFromEditorNode(node).trim()}`;
    }
    if (tag === "ul" || tag === "ol") {
      return Array.from(node.children || [])
        .filter((child) => String(child.tagName || "").toLowerCase() === "li")
        .map((child, index) => {
          const checkbox = Array.from(child.children || []).find(
            (candidate) => String(candidate.tagName || "").toLowerCase() === "input"
          );
          const text = inlineMarkdownFromEditorNode(child).trim();
          if (!text) return "";
          if (checkbox) return `- [${checkbox.checked ? "x" : " "}] ${text}`;
          return tag === "ol" ? `${index + 1}. ${text}` : `- ${text}`;
        })
        .filter(Boolean)
        .join("\n");
    }
    if (tag === "blockquote") {
      const quote = inlineMarkdownFromEditorNode(node).trim();
      return quote
        .split("\n")
        .filter(Boolean)
        .map((line) => `> ${line}`)
        .join("\n");
    }
    if (tag === "pre") {
      const code = normalizeCodeBlockText(String(node.textContent || "").replace(/\n$/g, ""));
      const language = String(node.dataset?.language || node.getAttribute?.("data-language") || "").trim();
      return `\`\`\`${language}\n${code}\n\`\`\``;
    }
    if (tag === "table") return tableMarkdownFromEditorNode(node);
    if (tag === "hr") return "---";
    return inlineMarkdownFromEditorNode(node).trim();
  }

  function markdownFromEditorElement(editor) {
    const blocks = Array.from(editor?.childNodes || [])
      .map(editorBlockMarkdown)
      .map((block) => block.trim())
      .filter(Boolean);
    if (blocks.length) return blocks.join("\n\n");
    return String(editor?.textContent || "").trim();
  }

  function setEditorDraftText(markdown, options = {}) {
    const draft = $("pageDraftInput");
    if (draft) draft.value = markdown;
    if (options.syncVisual && state.readerMode !== "source") {
      renderMarkdownEditor(visualEditorElement(), markdown);
    }
    updateEditorChrome();
  }

  function invalidatePreparedWrite() {
    state.preparedWrite = null;
    state.preparedWriteTarget = null;
    updateSaveControls();
  }

  function activePageKeyFromInputs() {
    const folderId = $("pageFolderIdInput")?.value.trim() || state.selectedFolderId || "general";
    const objectId = $("pageObjectIdInput")?.value.trim() || selectedReaderPage()?.objectId || nextDraftObjectId();
    return { folderId, objectId, key: pageKey(folderId, objectId) };
  }

  function activeLocalDraft() {
    return state.projection.localDrafts.get(activePageKeyFromInputs().key) || null;
  }

  function canSaveActiveDraft() {
    return Boolean(state.signerStatus === "connected" && state.keyring && activeLocalDraft());
  }

  function updateSaveControls() {
    setOptionalDisabled("savePageButton", !canSaveActiveDraft());
  }

  function rememberActiveDraft(markdown) {
    const { folderId, objectId, key } = activePageKeyFromInputs();
    const baseRevision = Number($("pageBaseRevisionInput")?.value.trim() || 0) || 0;
    const existingDraft = state.projection.localDrafts.get(key);
    const existingPage = state.projection.pages.get(key);
    state.projection.localDrafts.set(key, {
      baseRevision,
      path: existingDraft?.path || existingPage?.path || `${objectId}.md`,
      text: markdown,
    });
    const draft = $("pageDraftInput");
    if (draft) draft.value = markdown;
    invalidatePreparedWrite();
    updateEditorChrome();
  }

  function syncDraftFromVisualEditor(options = {}) {
    const editor = visualEditorElement();
    const markdown = markdownFromEditorElement(editor);
    const draft = $("pageDraftInput");
    if (draft) draft.value = markdown;
    if (options.remember) rememberActiveDraft(markdown);
    updateEditorChrome();
    return markdown;
  }

  function setEditorMode(mode) {
    state.editorMode = mode === "source" ? "source" : "visual";
    if (state.editorMode === "source") {
      syncDraftFromVisualEditor();
      setPageContentEditable(visualEditorElement(), false);
    } else {
      renderMarkdownEditor(visualEditorElement(), $("pageDraftInput").value);
      if (isReadablePage(selectedReaderPage()) && state.readerMode !== "source") {
        setPageContentEditable(visualEditorElement(), true);
      }
    }
    updateEditorChrome();
  }

  function updateEditorChrome() {
    const toolbar = $("editorToolbar");
    const source = $("pageSourceEditorLabel");
    const page = selectedReaderPage();
    const canEditInline = isReadablePage(page) && state.readerMode !== "source" && state.editorMode !== "source";
    if (toolbar) toolbar.hidden = !canEditInline;
    if (source) source.hidden = state.editorMode !== "source";
    setText("editorStatusText", canEditInline ? "Inline editor active" : "Markdown source");
    updateSaveControls();
  }

  function selectedTextForEditor() {
    return String(window.getSelection?.()?.toString?.() || "");
  }

  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function runEditorCommand(command) {
    if (state.editorMode !== "visual") setEditorMode("visual");
    const editor = visualEditorElement();
    editor.focus?.();
    const exec = (name, value = null) => document.execCommand?.(name, false, value);
    if (command === "paragraph") exec("formatBlock", "p");
    if (command === "heading1") exec("formatBlock", "h1");
    if (command === "heading2") exec("formatBlock", "h2");
    if (command === "bold") exec("bold");
    if (command === "italic") exec("italic");
    if (command === "bullet") exec("insertUnorderedList");
    if (command === "quote") exec("formatBlock", "blockquote");
    if (command === "codeblock") exec("formatBlock", "pre");
    if (command === "rule") exec("insertHorizontalRule");
    if (command === "code") {
      exec("insertHTML", `<code>${escapeHtml(selectedTextForEditor() || "code")}</code>`);
    }
    if (command === "link") {
      const target = window.prompt?.("Link target")?.trim();
      if (target) exec("createLink", target);
    }
    syncDraftFromVisualEditor({ remember: true });
  }

  function setNoteEmptyState(isEmpty) {
    $("readerPageContent").className = isEmpty ? "note-content note-content-empty" : "note-content";
  }

  function setPageContentEditable(content, enabled) {
    if (!content) return;
    if (enabled) {
      content.setAttribute("contenteditable", "true");
      content.setAttribute("spellcheck", "true");
      content.setAttribute("role", "textbox");
      content.setAttribute("aria-label", "Page editor");
      content.setAttribute("aria-multiline", "true");
      return;
    }
    content.removeAttribute("contenteditable");
    content.removeAttribute("spellcheck");
    content.removeAttribute("role");
    content.removeAttribute("aria-label");
    content.removeAttribute("aria-multiline");
  }

  function renderPageContent(page) {
    const content = $("readerPageContent");
    content.replaceChildren();
    setPageContentEditable(content, false);
    if (!page) {
      content.className = "note-content note-content-empty";
      content.textContent = "Open a vault to read pages.";
      return;
    }
    if (!isReadablePage(page)) {
      content.className = "note-content note-content-empty";
      content.textContent = "This page is locked in this session.";
      return;
    }
    if (state.readerMode === "source") {
      content.className = "note-content note-source";
      content.textContent = page.text || "";
      return;
    }
    content.className = `note-content note-markdown inline-page-editor${page.localDraft ? " inline-page-editor-dirty" : ""}`;
    setPageContentEditable(content, state.editorMode !== "source");
    renderMarkdownEditor(content, page.text || "");
  }

  function renderPageStatus(page) {
    return page;
  }

  function renderLinkContext(page) {
    return page;
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
    if (!list) return;
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
    console.debug(`[FiniteBrain] ${message}`, value ?? "");
  }

  function closeContextMenu() {
    state.contextMenuTarget = null;
    const menu = $("contextMenu");
    if (!menu) return;
    menu.hidden = true;
    menu.replaceChildren();
  }

  function closeCommandPalette() {
    state.commandPaletteOpen = false;
    const palette = $("commandPalette");
    if (!palette) return;
    palette.hidden = true;
    setPressed("ribbonCommandButton", false);
    $("ribbonCommandButton").className = "ribbon-button";
  }

  function runCommandPaletteRow(row) {
    if (!row) return;
    closeCommandPalette();
    if (row.kind === "page") {
      selectReaderPage(row.pageKey);
      return;
    }
    if (row.target === "files" || row.target === "search" || row.target === "access") {
      setSidebarMode(row.target);
      return;
    }
    if (row.target === "graph") {
      setWorkspaceView("graph");
      return;
    }
    if (row.target === "new-page") {
      startNewPageDraft();
      return;
    }
    if (row.target === "refresh") {
      refreshReader().catch((error) => {
        state.lastError = error.message;
        log("Failed to refresh Vault reader.", { error: error.message });
        state.readerBusy = false;
        render();
      });
    }
  }

  function renderCommandPalette() {
    const palette = $("commandPalette");
    if (!palette) return;
    palette.hidden = !state.commandPaletteOpen;
    setPressed("ribbonCommandButton", state.commandPaletteOpen);
    $("ribbonCommandButton").className = `ribbon-button${state.commandPaletteOpen ? " utility-active" : ""}`;
    if (!state.commandPaletteOpen) return;
    const list = $("commandPaletteList");
    const rows = commandPaletteRows($("commandPaletteInput").value);
    list.replaceChildren();
    if (!rows.length) {
      const item = document.createElement("li");
      item.className = "empty-row";
      item.textContent = "No matching commands or Pages";
      list.appendChild(item);
      return;
    }
    rows.forEach((row, index) => {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = `command-palette-row${index === 0 ? " active" : ""}`;
      const copy = document.createElement("span");
      const title = document.createElement("span");
      title.className = "command-palette-row-title";
      title.textContent = row.label;
      const detail = document.createElement("span");
      detail.className = "command-palette-row-detail";
      detail.textContent = row.detail || "";
      copy.appendChild(title);
      copy.appendChild(detail);
      const kind = document.createElement("span");
      kind.className = "command-palette-row-kind";
      kind.textContent = row.kind;
      button.appendChild(copy);
      button.appendChild(kind);
      button.addEventListener("click", () => runCommandPaletteRow(row));
      item.appendChild(button);
      list.appendChild(item);
    });
  }

  function openCommandPalette(seed = "") {
    state.commandPaletteOpen = true;
    closeContextMenu();
    $("commandPaletteInput").value = seed;
    renderCommandPalette();
    if (typeof requestAnimationFrame === "function") {
      requestAnimationFrame(() => $("commandPaletteInput").focus());
    } else {
      $("commandPaletteInput").focus?.();
    }
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
      createFolderFromToolbar().catch((error) => {
        state.lastError = error.message;
        window.alert?.(error.message);
        log("Failed to create Folder from context menu.", { error: error.message });
        render();
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
    if (item.action === "delete-page") {
      deletePageFromContextTarget(target).catch((error) => {
        state.lastError = error.message;
        window.alert?.(error.message);
        log("Failed to delete Page.", { error: error.message });
        render();
      });
      return;
    }
    const accessRoute = accessActionRoute(item.action, target);
    if (accessRoute) {
      state.accessResult = null;
      state.activeAccessFolderId = accessRoute.folderId;
      state.activeAccessIntent = accessRoute.intent;
      state.selectedFolderId = accessRoute.folderId;
      state.expandedFolderIds.add(accessRoute.folderId);
      $("pageFolderIdInput").value = accessRoute.folderId;
      $("okfDestinationFolderInput").value = accessRoute.folderId;
      setSidebarMode(accessRoute.sidebarMode);
      log(accessRoute.intent === "share" ? "Opened Folder share panel." : "Opened Folder access panel.", {
        folderId: accessRoute.folderId,
        intent: accessRoute.intent,
      });
      return;
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
    const title = document.createElement("span");
    title.className = "obsidian-file-title";
    title.textContent = label;
    button.appendChild(title);
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
    setText("sidebarModeTitle", sidebarModeLabel(mode));
    setPressed("ribbonFilesButton", mode === "files");
    setPressed("ribbonSearchButton", mode === "search");
    setPressed("ribbonAccessButton", mode === "access");
  }

  function renderSearchPanel() {
    const query = $("sidebarSearchInput").value;
    const rows = searchPageRows(query);
    setPill("searchResultCount", `${rows.length}`, rows.length ? "ready" : "muted");
    setList(
      "sidebarSearchResults",
      rows,
      query.trim() ? "No matching pages" : "Search pages",
      (item, row) => {
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
      }
    );
  }

  function renderAccessResultPanel() {
    const panel = $("accessResultPanel");
    const result = state.accessResult;
    panel.hidden = !result;
    panel.className = `access-result ${result?.tone || ""}`;
    panel.replaceChildren();
    if (!result) return;
    const title = document.createElement("strong");
    title.textContent = result.title;
    panel.appendChild(title);
    const detail = document.createElement("span");
    detail.textContent = result.detail;
    panel.appendChild(detail);
    if (result.meta) {
      for (const [key, value] of Object.entries(result.meta)) {
        const line = document.createElement("span");
        line.textContent = `${key}: ${value}`;
        panel.appendChild(line);
      }
    }
  }

  function renderAccessFlowPanel(activeRow) {
    const intent = state.activeAccessIntent;
    const restricted = activeRow?.access === "restricted";
    const flowVisible = Boolean(activeRow && restricted && (intent === "manage" || intent === "share"));
    const keyOpen = hasOpenedAccessFolderKey(activeRow);
    const busy = state.accessBusy;
    $("accessFlowPanel").hidden = !flowVisible;
    const manageSection = $("accessManageSection");
    const shareSection = $("accessShareSection");
    const acceptSection = $("accessAcceptSection");
    if (manageSection) manageSection.open = flowVisible && intent !== "share";
    if (shareSection) shareSection.open = flowVisible && intent === "share";
    if (acceptSection) {
      acceptSection.open = flowVisible && intent === "share" && Boolean(state.lastShareLinkId || $("accessShareLinkInput").value);
    }
    if (!$("accessShareExpiresAtInput").value) {
      $("accessShareExpiresAtInput").value = defaultShareExpiryDateTimeLocal();
    }
    if (state.lastShareLinkId && !$("accessShareLinkInput").value) {
      $("accessShareLinkInput").value = state.lastShareLinkId;
    }
    const canUseFolderFlow = flowVisible && restricted && keyOpen && !busy && state.signerStatus === "connected";
    $("grantFolderAccessButton").disabled = !canUseFolderFlow;
    $("removeFolderAccessButton").disabled = !canUseFolderFlow;
    $("createShareLinkButton").disabled = !canUseFolderFlow;
    $("acceptShareLinkButton").disabled = !flowVisible || busy || state.signerStatus !== "connected";
    $("revokeShareLinkButton").disabled = !flowVisible || busy || state.signerStatus !== "connected";
    if (!flowVisible) {
      setText("accessFlowHint", restricted ? "Choose Manage or Share." : "Restricted folders only.");
    } else if (!keyOpen) {
      setText("accessFlowHint", "Open this Folder key before sharing.");
    } else if (intent === "manage") {
      setText("accessFlowHint", "Direct access rotates encrypted folder grants.");
    } else {
      setText("accessFlowHint", "Links are single-use and bound to the recipient npub.");
    }
    renderAccessResultPanel();
  }

  function renderVaultInvitationPanel() {
    if (!$("vaultInviteExpiresAtInput").value) {
      $("vaultInviteExpiresAtInput").value = defaultShareExpiryDateTimeLocal();
    }
    if (state.lastVaultInvitationCode && !$("vaultInviteCodeInput").value) {
      $("vaultInviteCodeInput").value = state.lastVaultInvitationCode;
    }
    const connected = state.signerStatus === "connected";
    const busy = state.accessBusy;
    const organizationVault = state.metadata?.kind === "organization";
    const codeAvailable = Boolean($("vaultInviteCodeInput").value.trim() || state.lastVaultInvitationCode);
    $("createVaultInvitationButton").disabled = !connected || busy || !state.activeVaultId || !organizationVault;
    $("getVaultInvitationButton").disabled = !connected || busy || !codeAvailable;
    $("acceptVaultInvitationButton").disabled = !connected || busy || !codeAvailable;
    $("revokeVaultInvitationButton").disabled = !connected || busy || !codeAvailable || !organizationVault;
    if (!connected) {
      setText("vaultInvitationHint", "Connect signer");
    } else if (state.metadata?.kind === "organization") {
      setText("vaultInvitationHint", "Organization Vault");
    } else {
      setText("vaultInvitationHint", "Accept works from any Vault");
    }
  }

  function renderAccessPanel() {
    const rows = readerFolderRows(state.metadata);
    const openedFolders = openedGrantFolderKeys();
    const activeFolderId = state.activeAccessFolderId || state.selectedFolderId;
    const activeRow = rows.find((row) => row.id === activeFolderId) || rows[0] || null;
    if (activeRow && !state.activeAccessFolderId && !state.selectedFolderId) {
      state.activeAccessFolderId = activeRow.id;
    }
    const panel = accessPanelState(state.activeAccessIntent, activeRow);
    setPill("accessFolderCount", `${rows.length}`, rows.length ? "ready" : "muted");
    setText("accessFolderTitle", panel.title);
    setPill("accessFolderStatus", panel.status, panel.tone);
    setText("accessFolderDetail", panel.detail);
    setText("accessManageButton", "Manage");
    setText("accessShareButton", "Share");
    const restricted = activeRow?.access === "restricted";
    $("accessIntentActions").hidden = !restricted;
    $("accessManageButton").disabled = !activeRow || !restricted || state.accessBusy;
    $("accessShareButton").disabled = !activeRow || !restricted || state.accessBusy;
    $("accessManageButton").className = state.activeAccessIntent === "manage" ? "active" : "";
    $("accessShareButton").className = state.activeAccessIntent === "share" ? "active" : "";
    setPressed("accessManageButton", state.activeAccessIntent === "manage");
    setPressed("accessShareButton", state.activeAccessIntent === "share");
    renderAccessBadgeRow("accessBadgeRow", accessBadgesForFolder(activeRow, openedFolders));
    renderAccessFlowPanel(activeRow);
    renderVaultInvitationPanel();
    setList("accessFolderList", rows, "Load a Vault to inspect access", (item, row) => {
      const button = obsidianTreeButton(
        row.path,
        `${row.accessLabel} - key v${row.currentKeyVersion || 1}${row.detail ? ` - ${row.detail}` : ""}`,
        `obsidian-folder-button ${row.status}${row.id === activeRow?.id ? " active" : ""}`,
        () => selectAccessFolder(row.id),
        {
          contextTarget: {
            type: "folder",
            folderId: row.id,
            path: row.path,
          },
        }
      );
      appendAccessBadges(button, accessBadgesForFolder(row, openedFolders));
      item.appendChild(button);
    });
  }

  function renderReader() {
    selectDefaultReaderTargets();
    const folderRows = readerFolderRows(state.metadata);

    setList("readerFolderList", folderRows, "Load a Vault to browse folders", (item, row) => {
      const expanded = state.expandedFolderIds.has(row.id);
      const button = obsidianTreeButton(
        row.path,
        "",
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

    const page = selectedReaderPage();
    $("readerModeButton").textContent = state.readerMode === "source" ? "Source" : "Reading";
    setPressed("readerModeButton", state.readerMode === "source");
    $("readerModeButton").disabled = !isReadablePage(page);
    if (!page) {
      setText("readerPageTitle", state.selectedFolderId ? "No page selected" : "No folder selected");
      setText("readerPagePath", state.selectedFolderId || "No page path loaded");
      setPill("readerPageMeta", "empty", "muted");
      renderPageContent(null);
      renderLinkContext(null);
      renderPageStatus(null);
      renderWorkspaceChrome(null);
      return;
    }

    setText("readerPageTitle", page.title || page.objectId);
    setText("readerPagePath", pagePathLabel(page));
    setPill(
      "readerPageMeta",
      page.localDraft ? "draft" : `rev ${page.revision || 0}`,
      page.status === "ready" ? "ready" : "warn"
    );
    renderPageContent(page);
    renderLinkContext(page);
    renderPageStatus(page);
    renderWorkspaceChrome(page);
  }

  function render() {
    setOptionalDisabled("connectSignerButton", !deriveSignerState(window.nostr).canConnect);
    setOptionalDisabled("loadVaultButton", state.signerStatus !== "connected" || !state.config);
    setOptionalDisabled("openFolderKeyButton", !state.metadata);
    setOptionalDisabled("encryptDraftButton", !state.keyring);
    setOptionalDisabled("syncBootstrapButton", state.signerStatus !== "connected" || !state.config);
    setOptionalDisabled("openAccessibleVaultButton", state.readerBusy || !state.config);
    setOptionalDisabled("refreshReaderButton", state.readerBusy || state.signerStatus !== "connected" || !state.metadata);
    setOptionalDisabled("planOkfImportButton", !state.metadata);
    setOptionalDisabled(
      "executeOkfImportButton",
      !state.okfPlan || !state.keyring || state.signerStatus !== "connected"
    );
    $("vaultIdInput").value = state.activeVaultId;

    renderVaultControlChrome();
    renderSidebarMode();
    renderReader();
    updateEditorChrome();
    renderSearchPanel();
    renderAccessPanel();
    renderCommandPalette();
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
    state.activeVaultId = $("vaultIdInput").value.trim() || state.activeVaultId;
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

  async function openAvailableFolderKeyGrants() {
    if (!state.keyring) state.keyring = createSessionKeyring();
    const exported = await protectedRequest(`/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/export`);
    const expectedRecipient = state.pubkeyHex ? npubFromHex(state.pubkeyHex) : null;
    return openFolderKeyGrants(state.keyring, exported, expectedRecipient);
  }

  async function openAccessibleVaultReader() {
    state.activeVaultId = $("vaultIdInput").value.trim() || state.activeVaultId;
    state.readerBusy = true;
    render();
    try {
      if (state.signerStatus !== "connected") await connectSigner();
      if (state.signerStatus !== "connected") throw new Error("Connect a NIP-07 signer first");
      await loadVaultMetadata();
      const grants = await openAvailableFolderKeyGrants();
      await pullSyncBootstrap();
      selectDefaultReaderTargets();
      renderGraphView();
      log("Opened accessible Vault reader.", {
        openedFolderKeys: grants.opened.length,
        skippedFolderKeyGrants: grants.skipped.length,
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
    if (state.editorMode === "source") {
      rememberActiveDraft($("pageDraftInput").value);
    } else if (visualEditorElement()?.getAttribute?.("contenteditable") === "true") {
      syncDraftFromVisualEditor();
    }
    const folderId = $("pageFolderIdInput").value.trim() || "general";
    const objectId = $("pageObjectIdInput").value.trim() || "obj_000000000001";
    const key = pageKey(folderId, objectId);
    const page = state.projection.pages.get(key);
    const draft = state.projection.localDrafts.get(key);
    return {
      baseRevision: $("pageBaseRevisionInput").value.trim(),
      folderId,
      objectId,
      path: draft?.path || page?.path || `${objectId}.md`,
      text: $("pageDraftInput").value,
    };
  }

  function currentFolderKeyVersion(folderId) {
    const folder = (state.metadata?.folders || []).find((candidate) => candidate.id === folderId);
    return folder?.currentKeyVersion || 1;
  }

  function currentActorNpub() {
    if (!state.pubkeyHex) throw new Error("Connect a signer first");
    return npubFromHex(state.pubkeyHex);
  }

  function activeAccessRow() {
    const rows = readerFolderRows(state.metadata);
    const activeFolderId = state.activeAccessFolderId || state.selectedFolderId;
    return rows.find((row) => row.id === activeFolderId) || rows[0] || null;
  }

  function requireRestrictedAccessRow() {
    const row = activeAccessRow();
    if (!row) throw new Error("Select a Folder first");
    if (row.access !== "restricted") {
      throw new Error("Folder sharing is available for restricted Folders");
    }
    return row;
  }

  function openedAccessFolderKey(row) {
    const keyVersion = row.currentKeyVersion || currentFolderKeyVersion(row.id);
    const key = state.keyring?.keys.get(folderKeyId(state.activeVaultId, row.id, keyVersion));
    if (!key) throw new Error(`Open the Folder Key for ${row.path} before sharing`);
    return key;
  }

  function hasOpenedAccessFolderKey(row) {
    if (!row) return false;
    const keyVersion = row.currentKeyVersion || currentFolderKeyVersion(row.id);
    return Boolean(state.keyring?.keys.has(folderKeyId(state.activeVaultId, row.id, keyVersion)));
  }

  function normalizedTargetNpub() {
    return normalizedNpubInput("accessTargetNpubInput", "Paste a target npub first");
  }

  function normalizedNpubInput(inputId, message) {
    const value = $(inputId).value.trim();
    if (!value) throw new Error(message);
    npubToHex(value);
    return value;
  }

  function defaultShareExpiryDateTimeLocal() {
    const date = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    date.setSeconds(0, 0);
    return date.toISOString().slice(0, 16);
  }

  function slugFromFolderName(name) {
    return String(name || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 96);
  }

  function uniqueFolderId(baseId) {
    const existing = new Set((state.metadata?.folders || []).map((folder) => folder.id));
    let candidate = baseId || "folder";
    let suffix = 2;
    while (existing.has(candidate)) {
      candidate = `${baseId || "folder"}-${suffix}`;
      suffix += 1;
    }
    return candidate;
  }

  function folderRecipientsForAccess(access, accessUserIds = []) {
    const recipients = new Set();
    if (access === "owner") {
      if (state.metadata?.ownerUserId) recipients.add(state.metadata.ownerUserId);
      else recipients.add(currentActorNpub());
      return [...recipients];
    }
    if (access === "admin_only" || access === "all_members" || access === "restricted") {
      for (const admin of state.metadata?.admins || []) recipients.add(admin);
    }
    if (access === "all_members") {
      for (const member of state.metadata?.members || []) recipients.add(member);
    }
    if (access === "restricted") {
      for (const user of accessUserIds) recipients.add(user);
    }
    if (!recipients.size) recipients.add(currentActorNpub());
    return [...recipients];
  }

  async function createFolderFromToolbar() {
    if (!state.metadata) throw new Error("Open a Vault before creating a Folder");
    if (state.signerStatus !== "connected") await connectSigner();
    if (state.signerStatus !== "connected") throw new Error("Connect a NIP-07 signer first");

    const name = window.prompt("Folder name", "Notes")?.trim();
    if (!name) return;
    const folderId = uniqueFolderId(slugFromFolderName(name));
    const access = state.metadata.kind === "personal" ? "owner" : "all_members";
    const accessUserIds = [];
    const rawKey = randomFolderKeyBytes();
    const recipients = folderRecipientsForAccess(access, accessUserIds);
    const createdAtUnix = Math.floor(Date.now() / 1000);
    const grants = [];
    for (const recipientNpub of recipients) {
      grants.push(
        await buildFolderKeyGrantRequest({
          createdAtUnix,
          folderId,
          keyVersion: 1,
          rawKey,
          recipientNpub,
          vaultId: state.activeVaultId,
        })
      );
    }
    if (!state.keyring) state.keyring = createSessionKeyring();
    await importFolderKey(state.keyring, {
      vaultId: state.activeVaultId,
      folderId,
      keyVersion: 1,
      folderKey: bytesToBase64(rawKey),
    });
    const accessChangeEvent = await buildAdminAccessChangeEvent({
      action: "set-folder-access-mode",
      createdAtUnix,
      folderId,
      keyVersion: 1,
    });
    const metadata = await protectedRequest(
      `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/folders`,
      {
        method: "POST",
        body: JSON.stringify({
          access,
          accessChangeEvent,
          accessUserIds,
          folderId,
          grants,
          name,
          parentFolderId: null,
          path: folderId,
          role: "folder",
          sharedFolderSource: false,
        }),
      }
    );
    state.metadata = metadata;
    state.selectedFolderId = folderId;
    state.expandedFolderIds.add(folderId);
    $("pageFolderIdInput").value = folderId;
    $("okfDestinationFolderInput").value = folderId;
    log("Created Folder from toolbar.", { folderId, recipients: recipients.length });
    render();
  }

  function shareExpiryIso() {
    const value = $("accessShareExpiresAtInput").value.trim();
    const date = value ? new Date(value) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    if (Number.isNaN(date.getTime())) throw new Error("Share link expiry is invalid");
    return date.toISOString();
  }

  function vaultInvitationExpiryIso() {
    const value = $("vaultInviteExpiresAtInput").value.trim();
    const date = value ? new Date(value) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    if (Number.isNaN(date.getTime())) throw new Error("Vault invitation expiry is invalid");
    return date.toISOString();
  }

  function initialVaultInvitationFolders(value = $("vaultInviteFoldersInput").value) {
    return uniqueValues(
      String(value || "")
        .split(/[,\s]+/)
        .map((part) => part.trim())
        .filter(Boolean)
    );
  }

  function buildVaultInvitationRequest(input) {
    const targetNpub = input.targetNpub;
    npubToHex(targetNpub);
    return {
      targetNpub,
      initialFolderAccess: initialVaultInvitationFolders(input.initialFolderAccess || ""),
      expiresAt: input.expiresAt,
    };
  }

  function currentVaultInvitationCode() {
    const value = $("vaultInviteCodeInput").value.trim() || state.lastVaultInvitationCode;
    if (!value) throw new Error("Paste an invitation code or id first");
    return value;
  }

  function vaultInvitationCreatePath(vaultId) {
    return `/_admin/vaults/${encodeURIComponent(vaultId)}/invitations`;
  }

  function vaultInvitationLinkPath(code) {
    return `/_admin/vault-invitation-links/${encodeURIComponent(code)}`;
  }

  function vaultInvitationAcceptPath(code) {
    return `${vaultInvitationLinkPath(code)}/accept`;
  }

  function vaultInvitationRevokePath(vaultId, invitationId) {
    return `/_admin/vaults/${encodeURIComponent(vaultId)}/invitations/${encodeURIComponent(invitationId)}`;
  }

  function uniqueValues(values) {
    return [...new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))];
  }

  function uniqueNpubs(values) {
    return uniqueValues(values);
  }

  function folderAccessRemovalRecipients(metadata, row, targetNpub) {
    if (!row || row.access !== "restricted") {
      throw new Error("Folder access removal is available for restricted Folders");
    }
    const accessUsers = uniqueNpubs(row.accessUserIds);
    if (!accessUsers.includes(targetNpub)) {
      throw new Error(`${shortKey(targetNpub)} does not have explicit access to ${row.path}`);
    }
    const admins = uniqueNpubs(metadata?.admins || []);
    if (admins.includes(targetNpub)) {
      throw new Error("Admins can still open restricted Folders; remove admin role first");
    }
    const remainingAccessUsers = accessUsers.filter((npub) => npub !== targetNpub);
    const recipients = uniqueNpubs([...admins, ...remainingAccessUsers]);
    if (!recipients.length) throw new Error("Folder Key rotation needs at least one remaining recipient");
    return { remainingAccessUsers, recipients };
  }

  function liveReadableFolderObjects(objects, folderId) {
    const rows = (objects || [])
      .filter((object) => object.folderId === folderId && !object.deleted)
      .sort((left, right) => String(left.objectId).localeCompare(String(right.objectId)));
    const unreadable = rows.filter((object) => object.status !== "ready" || typeof object.text !== "string");
    if (unreadable.length) {
      throw new Error("Every live Page in this Folder must be readable before rotating access");
    }
    return rows;
  }

  function randomFolderKeyBytes() {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  function deterministicClientId(prefix, parts) {
    return sha256Hex(parts.join("\n")).then((digest) => `${prefix}-${digest.slice(0, 16)}`);
  }

  function canonicalAdminAccessChangePayload(input) {
    const fields = [
      `"version":${JSON.stringify("finite-vault-admin-access-change-v1")}`,
      `"vaultId":${JSON.stringify(input.vaultId)}`,
      `"changeId":${JSON.stringify(input.changeId)}`,
      `"action":${JSON.stringify(input.action)}`,
      `"adminNpub":${JSON.stringify(input.adminNpub)}`,
    ];
    if (input.folderId) fields.push(`"folderId":${JSON.stringify(input.folderId)}`);
    if (input.targetNpub) fields.push(`"targetNpub":${JSON.stringify(input.targetNpub)}`);
    if (input.keyVersion !== undefined && input.keyVersion !== null) {
      fields.push(`"keyVersion":${Number(input.keyVersion)}`);
    }
    if (input.note) fields.push(`"note":${JSON.stringify(input.note)}`);
    fields.push(`"createdAt":${JSON.stringify(input.createdAt)}`);
    return `{${fields.join(",")}}`;
  }

  function adminAccessChangeTags(input) {
    const tags = [
      ["d", `finite-vault-admin-access-change:${input.vaultId}:${input.changeId}`],
      ["vault", input.vaultId],
      ["action", input.action],
    ];
    if (input.folderId) tags.push(["folder", input.folderId]);
    if (input.targetNpub) tags.push(["p", npubToHex(input.targetNpub)]);
    if (input.keyVersion !== undefined && input.keyVersion !== null) {
      tags.push(["keyVersion", String(input.keyVersion)]);
    }
    return tags;
  }

  async function buildAdminAccessChangeEvent(input) {
    const signEvent = input.signEvent || window.nostr?.signEvent;
    if (!signEvent) throw new Error("NIP-07 signer is unavailable");
    const createdAtUnix = input.createdAtUnix || Math.floor(Date.now() / 1000);
    const createdAt = accessChangeCreatedAt(createdAtUnix);
    const adminNpub = input.adminNpub || currentActorNpub();
    const vaultId = input.vaultId || state.activeVaultId;
    const changeId =
      input.changeId ||
      (await deterministicClientId("access-change", [
        vaultId,
        input.action,
        input.folderId || "-",
        input.targetNpub || "-",
        createdAt,
      ]));
    const payload = {
      version: "finite-vault-admin-access-change-v1",
      vaultId,
      changeId,
      action: input.action,
      adminNpub,
      folderId: input.folderId,
      targetNpub: input.targetNpub,
      keyVersion: input.keyVersion,
      note: input.note,
      createdAt,
    };
    return signEvent({
      kind: APP_EVENT_KIND,
      created_at: createdAtUnix,
      tags: adminAccessChangeTags(payload),
      content: canonicalAdminAccessChangePayload(payload),
    });
  }

  async function buildFolderKeyGrantRequest(input) {
    const signEvent = input.signEvent || window.nostr?.signEvent;
    if (!signEvent) throw new Error("NIP-07 signer is unavailable");
    const encrypt = nip44EncryptAdapter(input);
    if (!encrypt && !input.allowPlaintextDevelopmentGrant) {
      throw new Error("NIP-44 encryption is unavailable");
    }
    const recipientHex = npubToHex(input.recipientNpub);
    const issuerNpub = input.issuerNpub || currentActorNpub();
    const issuerHex = npubToHex(issuerNpub);
    const createdAtUnix = input.createdAtUnix || Math.floor(Date.now() / 1000);
    const createdAt = revisionCreatedAt(createdAtUnix);
    const folderKey = input.folderKey || bytesToBase64(input.rawKey);
    const grantId =
      input.id ||
      (await deterministicClientId("grant", [
        input.vaultId,
        input.folderId,
        String(input.keyVersion),
        input.recipientNpub,
        createdAt,
      ]));
    const plaintextGrant = {
      version: "finite-folder-key-grant-v1",
      vaultId: input.vaultId,
      folderId: input.folderId,
      keyVersion: input.keyVersion,
      folderKey,
      issuerNpub,
      recipientNpub: input.recipientNpub,
      createdAt,
    };
    const rumorTags = [
      ["d", `finite-folder-key-grant:${input.vaultId}:${input.folderId}:${input.keyVersion}`],
      ["vault", input.vaultId],
      ["folder", input.folderId],
      ["keyVersion", String(input.keyVersion)],
    ];
    let wrappedEvent;
    if (encrypt) {
      const rumorContent = JSON.stringify(plaintextGrant);
      const rumor = {
        pubkey: issuerHex,
        created_at: createdAtUnix,
        kind: APP_EVENT_KIND,
        tags: rumorTags,
        content: rumorContent,
      };
      rumor.id = await sha256Hex(canonicalNostrEventIdInput(rumor));
      const sealContent = await encrypt(recipientHex, JSON.stringify(rumor));
      const seal = await signEvent({
        kind: 13,
        created_at: createdAtUnix,
        tags: [],
        content: sealContent,
      });
      const wrappedContent = await encrypt(recipientHex, JSON.stringify(seal));
      wrappedEvent = await signEvent({
        kind: 1059,
        created_at: createdAtUnix,
        tags: [["p", recipientHex]],
        content: wrappedContent,
      });
    } else {
      wrappedEvent = await signEvent({
        kind: 1059,
        created_at: createdAtUnix,
        tags: [["p", recipientHex]],
        content: JSON.stringify(plaintextGrant),
      });
    }
    return {
      id: grantId,
      keyVersion: input.keyVersion,
      recipientNpub: input.recipientNpub,
      wrappedEventJson: JSON.stringify(wrappedEvent),
      createdAt,
    };
  }

  function setAccessResult(tone, title, detail, meta = null) {
    state.accessResult = { tone, title, detail, meta };
    render();
  }

  async function buildAccessGrantForRow(row, recipientNpub) {
    const key = openedAccessFolderKey(row);
    return buildFolderKeyGrantRequest({
      vaultId: state.activeVaultId,
      folderId: row.id,
      keyVersion: key.keyVersion,
      rawKey: key.rawKey,
      recipientNpub,
    });
  }

  async function buildFolderAccessRemovalRequest(keyring, input) {
    if (!keyring) throw new Error("Open this Folder key before removing access");
    const row = input.row;
    const vaultId = input.vaultId || state.activeVaultId;
    const metadata = input.metadata || state.metadata;
    const targetNpub = input.targetNpub;
    npubToHex(targetNpub);
    const currentKeyVersion = row.currentKeyVersion || 1;
    const currentKey = keyring.keys.get(folderKeyId(vaultId, row.id, currentKeyVersion));
    if (!currentKey) throw new Error(`Open the Folder Key for ${row.path} before removing access`);

    const { recipients } = folderAccessRemovalRecipients(metadata, row, targetNpub);
    const newKeyVersion = input.newKeyVersion || currentKeyVersion + 1;
    if (newKeyVersion !== currentKeyVersion + 1) {
      throw new Error("Folder access removal must rotate to the next key version");
    }
    const newRawKey = input.newRawKey || randomFolderKeyBytes();
    if (newRawKey.length !== 32) throw new Error("New Folder Key must be 32 bytes");
    const folderKey = bytesToBase64(newRawKey);
    const createdAtUnix = input.createdAtUnix || Math.floor(Date.now() / 1000);
    const actorNpub = input.actorNpub || currentActorNpub();
    const signEvent = input.signEvent || window.nostr?.signEvent;
    if (!signEvent) throw new Error("NIP-07 signer is unavailable");
    await importFolderKey(keyring, {
      vaultId,
      folderId: row.id,
      keyVersion: newKeyVersion,
      folderKey,
    });

    const grants = [];
    for (const recipientNpub of recipients) {
      grants.push(
        await buildFolderKeyGrantRequest({
          vaultId,
          folderId: row.id,
          keyVersion: newKeyVersion,
          rawKey: newRawKey,
          issuerNpub: actorNpub,
          recipientNpub,
          createdAtUnix,
          signEvent,
        })
      );
    }

    const reencryptedRecords = [];
    for (const object of liveReadableFolderObjects(input.objects, row.id)) {
      const write = await buildPageWriteRequest(keyring, {
        authorNpub: actorNpub,
        baseRevision: object.revision,
        createdAtUnix,
        folderId: row.id,
        keyVersion: newKeyVersion,
        objectId: object.objectId,
        operation: "update",
        plaintext: encodeFolderObjectPagePlaintext(object.path || `${object.objectId}.md`, object.text),
        signEvent,
        vaultId,
      });
      reencryptedRecords.push({
        objectId: object.objectId,
        ...write,
      });
    }

    const accessChangeEvent = await buildAdminAccessChangeEvent({
      action: "remove-folder-access",
      adminNpub: actorNpub,
      createdAtUnix,
      folderId: row.id,
      keyVersion: newKeyVersion,
      signEvent,
      targetNpub,
      vaultId,
    });

    return {
      newKeyVersion,
      grants,
      reencryptedRecords,
      accessChangeEvent,
      folderKey,
      recipientNpubs: recipients,
    };
  }

  async function grantFolderAccessFromPanel() {
    const row = requireRestrictedAccessRow();
    const targetNpub = normalizedTargetNpub();
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const grant = await buildAccessGrantForRow(row, targetNpub);
      const accessChangeEvent = await buildAdminAccessChangeEvent({
        action: "grant-folder-access",
        folderId: row.id,
        keyVersion: row.currentKeyVersion,
        targetNpub,
      });
      const body = JSON.stringify({
        targetNpub,
        grant,
        accessChangeEvent,
      });
      const metadata = await protectedRequest(
        `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/folders/${encodeURIComponent(row.id)}/access`,
        { method: "POST", body }
      );
      state.metadata = metadata;
      setAccessResult("ready", "Access granted", `${shortKey(targetNpub)} can open ${row.path}.`, {
        grantId: grant.id,
      });
      log("Granted restricted Folder access.", { folderId: row.id, targetNpub: shortKey(targetNpub) });
    } catch (error) {
      setAccessResult("error", "Grant failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function removeFolderAccessFromPanel() {
    const row = requireRestrictedAccessRow();
    const targetNpub = normalizedTargetNpub();
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const removal = await buildFolderAccessRemovalRequest(state.keyring, {
        vaultId: state.activeVaultId,
        metadata: state.metadata,
        row,
        targetNpub,
        objects: [...state.projection.pages.values()],
      });
      const body = JSON.stringify({
        newKeyVersion: removal.newKeyVersion,
        grants: removal.grants,
        reencryptedRecords: removal.reencryptedRecords,
        accessChangeEvent: removal.accessChangeEvent,
      });
      const metadata = await protectedRequest(
        `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/folders/${encodeURIComponent(
          row.id
        )}/access/${encodeURIComponent(targetNpub)}`,
        { method: "DELETE", body }
      );
      state.metadata = metadata;
      await openAvailableFolderKeyGrants();
      await pullSyncBootstrap();
      selectDefaultReaderTargets();
      renderGraphView();
      setAccessResult("warn", "Access removed", `${shortKey(targetNpub)} was removed from ${row.path}.`, {
        keyVersion: `v${removal.newKeyVersion}`,
        reencryptedPages: String(removal.reencryptedRecords.length),
      });
      log("Removed restricted Folder access with key rotation.", {
        folderId: row.id,
        keyVersion: removal.newKeyVersion,
        reencryptedPages: removal.reencryptedRecords.length,
        targetNpub: shortKey(targetNpub),
      });
    } catch (error) {
      setAccessResult("error", "Remove failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function createShareLinkFromPanel() {
    const row = requireRestrictedAccessRow();
    const recipientNpub = normalizedTargetNpub();
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const expiresAt = shareExpiryIso();
      const grant = await buildAccessGrantForRow(row, recipientNpub);
      const accessChangeEvent = await buildAdminAccessChangeEvent({
        action: "grant-folder-access",
        folderId: row.id,
        keyVersion: row.currentKeyVersion,
        targetNpub: recipientNpub,
      });
      const body = JSON.stringify({
        recipientNpub,
        grant,
        accessChangeEvent,
        expiresAt,
        createPersonalMount: $("accessShareMountInput").checked,
      });
      const shareLink = await protectedRequest(
        `/_admin/vaults/${encodeURIComponent(state.activeVaultId)}/folders/${encodeURIComponent(row.id)}/share-links`,
        { method: "POST", body }
      );
      state.lastShareLinkId = shareLink.id;
      $("accessShareLinkInput").value = shareLink.id;
      setAccessResult("ready", "Share link created", `${shareLink.id} is pending for ${shortKey(recipientNpub)}.`, {
        acceptPath: shareLink.acceptPath,
        expiresAt: shareLink.expiresAt,
      });
      log("Created Folder share link.", { folderId: row.id, shareLinkId: shareLink.id });
    } catch (error) {
      setAccessResult("error", "Share failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function acceptShareLinkFromPanel() {
    const shareLinkId = $("accessShareLinkInput").value.trim() || state.lastShareLinkId;
    if (!shareLinkId) throw new Error("Paste a share link id first");
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const shareLink = await protectedRequest(`/_admin/share-links/${encodeURIComponent(shareLinkId)}/accept`, {
        method: "POST",
      });
      state.lastShareLinkId = shareLink.id;
      await loadVaultMetadata();
      const grants = await openAvailableFolderKeyGrants();
      await pullSyncBootstrap();
      selectDefaultReaderTargets();
      setAccessResult(
        "ready",
        shareLink.duplicateAccept ? "Share link already accepted" : "Share link accepted",
        `${shareLink.folderId} is now available to this signer.`,
        {
          mounted: shareLink.personalMountId || "none",
          openedKeys: String(grants.opened.length),
        }
      );
      log("Accepted Folder share link.", { shareLinkId: shareLink.id });
    } catch (error) {
      setAccessResult("error", "Accept failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function revokeShareLinkFromPanel() {
    const shareLinkId = $("accessShareLinkInput").value.trim() || state.lastShareLinkId;
    if (!shareLinkId) throw new Error("Paste a share link id first");
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const shareLink = await protectedRequest(`/_admin/share-links/${encodeURIComponent(shareLinkId)}`, {
        method: "DELETE",
      });
      state.lastShareLinkId = shareLink.id;
      setAccessResult("warn", "Share link revoked", `${shareLink.id} is ${shareLink.status}.`, {
        updatedAt: shareLink.updatedAt,
      });
      log("Revoked Folder share link.", { shareLinkId: shareLink.id });
    } catch (error) {
      setAccessResult("error", "Revoke failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function createVaultInvitationFromPanel() {
    const targetNpub = normalizedNpubInput("vaultInviteTargetNpubInput", "Paste an invite npub first");
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const body = JSON.stringify(
        buildVaultInvitationRequest({
          targetNpub,
          initialFolderAccess: $("vaultInviteFoldersInput").value,
          expiresAt: vaultInvitationExpiryIso(),
        })
      );
      const invitation = await protectedRequest(
        vaultInvitationCreatePath(state.activeVaultId),
        { method: "POST", body }
      );
      state.lastVaultInvitationId = invitation.id;
      state.lastVaultInvitationCode = invitation.inviteCode;
      $("vaultInviteCodeInput").value = invitation.inviteCode;
      setAccessResult("ready", "Invitation created", `${shortKey(invitation.userId)} can join ${invitation.vaultId}.`, {
        code: invitation.inviteCode,
        acceptPath: invitation.acceptPath,
        expiresAt: invitation.expiresAt,
      });
      log("Created Vault invitation.", { invitationId: invitation.id, vaultId: invitation.vaultId });
    } catch (error) {
      setAccessResult("error", "Invite failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function inspectVaultInvitationFromPanel() {
    const code = currentVaultInvitationCode();
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const invitation = await protectedRequest(vaultInvitationLinkPath(code));
      state.lastVaultInvitationId = invitation.id;
      state.lastVaultInvitationCode = invitation.inviteCode;
      $("vaultInviteCodeInput").value = invitation.inviteCode;
      setAccessResult("ready", "Invitation loaded", `${shortKey(invitation.userId)} is ${invitation.status}.`, {
        vaultId: invitation.vaultId,
        invitationId: invitation.id,
        acceptPath: invitation.acceptPath,
      });
      log("Loaded Vault invitation.", { invitationId: invitation.id, vaultId: invitation.vaultId });
      return invitation;
    } catch (error) {
      setAccessResult("error", "Inspect failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function acceptVaultInvitationFromPanel() {
    const code = currentVaultInvitationCode();
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      const invitation = await protectedRequest(vaultInvitationAcceptPath(code), {
        method: "POST",
      });
      state.lastVaultInvitationId = invitation.id;
      state.lastVaultInvitationCode = invitation.inviteCode;
      state.activeVaultId = invitation.vaultId;
      $("vaultIdInput").value = invitation.vaultId;
      $("vaultInviteCodeInput").value = invitation.inviteCode;
      await loadVaultMetadata();
      setAccessResult(
        "ready",
        invitation.duplicateAccept ? "Invitation already accepted" : "Invitation accepted",
        `${invitation.vaultId} is now available to this signer.`,
        {
          status: invitation.status,
          initialFolders: (invitation.initialFolderAccess || []).join(", ") || "none",
        }
      );
      log("Accepted Vault invitation.", { invitationId: invitation.id, vaultId: invitation.vaultId });
    } catch (error) {
      setAccessResult("error", "Accept failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
  }

  async function revokeVaultInvitationFromPanel() {
    const value = currentVaultInvitationCode();
    state.accessBusy = true;
    state.accessResult = null;
    render();
    try {
      let invitationId = state.lastVaultInvitationId;
      let vaultId = state.activeVaultId;
      if (!invitationId || value !== invitationId) {
        if (value.startsWith("invitation-")) {
          invitationId = value;
        } else {
          const invitation = await protectedRequest(vaultInvitationLinkPath(value));
          invitationId = invitation.id;
          vaultId = invitation.vaultId;
          state.lastVaultInvitationId = invitation.id;
          state.lastVaultInvitationCode = invitation.inviteCode;
        }
      }
      const invitation = await protectedRequest(
        vaultInvitationRevokePath(vaultId, invitationId),
        { method: "DELETE" }
      );
      state.lastVaultInvitationId = invitation.id;
      state.lastVaultInvitationCode = invitation.inviteCode;
      setAccessResult("warn", "Invitation revoked", `${invitation.id} is ${invitation.status}.`, {
        updatedAt: invitation.updatedAt,
      });
      log("Revoked Vault invitation.", { invitationId: invitation.id, vaultId: invitation.vaultId });
    } catch (error) {
      setAccessResult("error", "Revoke failed", error.message);
      throw error;
    } finally {
      state.accessBusy = false;
      render();
    }
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

  async function prepareDraftWrite(options = {}) {
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
      plaintext: encodeFolderObjectPagePlaintext(input.path, input.text),
      signEvent: (event) => window.nostr.signEvent(event),
      vaultId: state.activeVaultId,
    });
    state.preparedWriteTarget = {
      folderId: input.folderId,
      objectId: input.objectId,
      path: input.path,
    };
    state.projection.localDrafts.set(pageKey(input.folderId, input.objectId), {
      baseRevision: state.preparedWrite.baseRevision || 0,
      path: input.path,
      text: input.text,
    });
    log("Encrypted Page draft and prepared signed revision request.", {
      folderId: input.folderId,
      objectId: input.objectId,
      baseRevision: state.preparedWrite.baseRevision,
      keyVersion,
    });
    if (options.renderAfter !== false) render();
    return state.preparedWrite;
  }

  async function savePreparedPage() {
    if (!state.preparedWrite) throw new Error("Prepare a Page write before saving");
    const savedInput = activePageInput();
    const target = state.preparedWriteTarget || savedInput;
    const savedText = savedInput.text;
    const savedPath = target.path || savedInput.path || `${target.objectId}.md`;
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
      path: savedPath,
      status: "ready",
      text: savedText,
      title: pageTitleFromText(savedText, pageTitleFromPath(savedPath, target.objectId)),
    });
    state.projection.localDrafts.delete(pageKey(target.folderId, target.objectId));
    state.preparedWrite = null;
    state.preparedWriteTarget = null;
    $("pageBaseRevisionInput").value = String(result.revision);
    setEditorDraftText(savedText);
    log("Saved encrypted Page revision.", result);
    render();
  }

  async function saveActivePage() {
    await prepareDraftWrite({ renderAfter: false });
    await savePreparedPage();
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
    const filterText = $("graphFilterInput").value;
    const graph = buildGraphProjection(pages, filterText);
    drawGraph(graph, { filterText, readablePageCount: pages.length });
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
      if (!isReadablePage(page)) continue;
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
      drawGraph(frames[frames.length - 1].graph, { readablePageCount: decryptedPagesForGraph().length });
      setGraphStats(frames[frames.length - 1].graph, decryptedPagesForGraph().length);
    }
    log("Built graph replay frames.", frames.map((frame) => ({
      edgeCount: frame.edgeCount,
      nodeCount: frame.nodeCount,
      sequence: frame.sequence,
    })));
  }

  function renderOkfPlan() {
    return state.okfPlan;
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
    $("readerModeButton").addEventListener("click", () => {
      state.readerMode = state.readerMode === "source" ? "reading" : "source";
      render();
    });
    $("ribbonGraphButton").addEventListener("click", () => {
      setWorkspaceView("graph");
    });
    $("ribbonFilesButton").addEventListener("click", () => {
      setWorkspaceView("page");
      setSidebarMode("files");
    });
    $("ribbonSearchButton").addEventListener("click", () => {
      setSidebarMode("search");
    });
    $("ribbonCommandButton").addEventListener("click", () => {
      if (state.commandPaletteOpen) {
        closeCommandPalette();
      } else {
        openCommandPalette();
      }
    });
    $("ribbonAccessButton").addEventListener("click", () => {
      setSidebarMode("access");
    });
    $("accessManageButton").addEventListener("click", () => {
      const folderId = state.activeAccessFolderId || state.selectedFolderId;
      if (!folderId) return;
      state.activeAccessIntent = "manage";
      state.activeAccessFolderId = folderId;
      state.accessResult = null;
      log("Access management is visible in the prototype panel.", { folderId });
      render();
    });
    $("accessShareButton").addEventListener("click", () => {
      const folderId = state.activeAccessFolderId || state.selectedFolderId;
      if (!folderId) return;
      state.activeAccessIntent = "share";
      state.activeAccessFolderId = folderId;
      state.accessResult = null;
      log("Share flow is visible in the prototype panel.", { folderId });
      render();
    });
    onOptionalClick("grantFolderAccessButton", () => {
      grantFolderAccessFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to grant Folder access.", { error: error.message });
      });
    });
    onOptionalClick("removeFolderAccessButton", () => {
      removeFolderAccessFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to remove Folder access.", { error: error.message });
      });
    });
    onOptionalClick("createShareLinkButton", () => {
      createShareLinkFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to create Folder share link.", { error: error.message });
      });
    });
    onOptionalClick("acceptShareLinkButton", () => {
      acceptShareLinkFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to accept Folder share link.", { error: error.message });
      });
    });
    onOptionalClick("revokeShareLinkButton", () => {
      revokeShareLinkFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to revoke Folder share link.", { error: error.message });
      });
    });
    onOptionalClick("createVaultInvitationButton", () => {
      createVaultInvitationFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to create Vault invitation.", { error: error.message });
      });
    });
    onOptionalClick("getVaultInvitationButton", () => {
      inspectVaultInvitationFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to inspect Vault invitation.", { error: error.message });
      });
    });
    onOptionalClick("acceptVaultInvitationButton", () => {
      acceptVaultInvitationFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to accept Vault invitation.", { error: error.message });
      });
    });
    onOptionalClick("revokeVaultInvitationButton", () => {
      revokeVaultInvitationFromPanel().catch((error) => {
        state.lastError = error.message;
        log("Failed to revoke Vault invitation.", { error: error.message });
      });
    });
    $("sidebarSearchInput").addEventListener("input", () => {
      renderSearchPanel();
    });
    $("commandPaletteInput").addEventListener("input", () => {
      renderCommandPalette();
    });
    $("commandPaletteInput").addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      runCommandPaletteRow(commandPaletteRows($("commandPaletteInput").value)[0]);
    });
    $("closeCommandPaletteButton").addEventListener("click", () => {
      closeCommandPalette();
    });
    $("commandPalette").addEventListener("click", (event) => {
      if (event.target === $("commandPalette")) closeCommandPalette();
    });
    $("obsidianNewPageButton").addEventListener("click", () => {
      startNewPageDraft();
    });
    $("obsidianNewFolderButton").addEventListener("click", () => {
      createFolderFromToolbar().catch((error) => {
        state.lastError = error.message;
        window.alert?.(error.message);
        log("Failed to create Folder from toolbar.", { error: error.message });
        render();
      });
    });
    $("readerPageContent").addEventListener("input", () => {
      if (visualEditorElement()?.getAttribute?.("contenteditable") === "true") {
        syncDraftFromVisualEditor({ remember: true });
      }
    });
    $("pageDraftInput").addEventListener("input", () => {
      rememberActiveDraft($("pageDraftInput").value);
    });
    $("editorDrawer").addEventListener("toggle", () => {
      setEditorMode($("editorDrawer").open ? "source" : "visual");
    });
    document.querySelectorAll?.("[data-editor-command]").forEach((button) => {
      button.addEventListener("mousedown", (event) => event.preventDefault());
      button.addEventListener("click", () => {
        runEditorCommand(button.dataset.editorCommand);
      });
    });
    onOptionalClick("openFolderKeyButton", () => {
      openEnteredFolderKey().catch((error) => {
        state.lastError = error.message;
        log("Failed to open Folder Key.", { error: error.message });
        render();
      });
    });
    onOptionalClick("encryptDraftButton", () => {
      prepareDraftWrite().catch((error) => {
        state.lastError = error.message;
        log("Failed to encrypt Page draft.", { error: error.message });
        render();
      });
    });
    $("savePageButton").addEventListener("click", () => {
      saveActivePage().catch((error) => {
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
    onOptionalClick("planOkfImportButton", () => {
      try {
        planEnteredOkfImport();
      } catch (error) {
        state.lastError = error.message;
        log("Failed to plan OKF import.", { error: error.message });
        render();
      }
    });
    onOptionalClick("executeOkfImportButton", () => {
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
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "p") {
        event.preventDefault();
        openCommandPalette();
        return;
      }
      if (event.key === "Escape") {
        closeContextMenu();
        closeCommandPalette();
      }
    });
  }

  async function start() {
    bind();
    setEditorDraftText($("pageDraftInput").value);
    await loadConfig();
    await detectSigner();
  }

  return {
    accessActionRoute,
    accessBadgesForFolder,
    accessPanelState,
    adminAccessChangeTags,
    buildAdminAccessChangeEvent,
    buildFolderKeyGrantRequest,
    buildPageDeleteRequest,
    buildPageWriteRequest,
    buildAuthEventTemplate,
    buildFolderAccessRemovalRequest,
    buildVaultInvitationRequest,
    buildGraphProjection,
    buildReplayFrames,
    canonicalAdminAccessChangePayload,
    commandPaletteCommands,
    commandPaletteRows,
    contextMenuItemsForTarget,
    createClientProjection,
    createSessionKeyring,
    deriveSignerState,
    encryptFolderObject,
    extractPageLinks,
    graphEmptyStateCopy,
    graphLayout,
    graphStats,
    inlineLinkSegments,
    initialVaultInvitationFolders,
    markdownFromEditorElement,
    markdownPreviewBlocks,
    mergeSyncProjection,
    metadataFolderRows,
    metadataMountRows,
    nextDraftObjectId,
    normalizeSidebarMode,
    npubFromHex,
    npubToHex,
    openFolderKeyGrants,
    openDevelopmentFolderKeyGrants,
    openFolderKeyGrantPlaintext,
    openFolderObject,
    openSyncObjects,
    parseOkfBundle,
    pageLinkContext,
    pagePathLabel,
    pageStatsForText,
    plaintextDevelopmentGrantFromExportGrant,
    plaintextGrantFromGiftWrappedExportGrant,
    planOkfImport,
    prepareOkfImportWrites,
    projectionPagesFromProjection,
    readerFolderDetail,
    readerFolderRows,
    readerPageDetail,
    readerPageRows,
    searchPageRows,
    sidebarAccessBadgesForFolder,
    sidebarModeLabel,
    shortKey,
    start,
    workspaceChromeState,
    workspaceTabTitle,
    vaultInvitationAcceptPath,
    vaultInvitationCreatePath,
    vaultInvitationLinkPath,
    vaultInvitationRevokePath,
  };
})();

window.FiniteBrainProductClient = FiniteBrainProductClient;
if (!window.__FINITE_BRAIN_DISABLE_AUTOSTART__) {
  FiniteBrainProductClient.start();
}
