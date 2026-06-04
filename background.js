import {
  base64ToArrayBuffer,
  arrayBufferToBase64,
  deriveKeyFromPassword,
  encryptAESGCM,
  decryptAESGCM,
  generateECDHKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveECDHSharedSecret,
  generateTOTP
} from './crypto-helper.js';

let activeSharedKey = null; // Transient ECDH key for popup IPC
const AUTO_LOCK_TIMEOUT = 5 * 60 * 1000; // 5 minutes inactivity

// --- Auto-Lock and State Management ---

async function checkAutoLock() {
  const session = await chrome.storage.session.get(["kek", "lastActive"]);
  if (!session.kek) {
    return false; // Vault is locked
  }
  const lastActive = session.lastActive || 0;
  if (Date.now() - lastActive > AUTO_LOCK_TIMEOUT) {
    await lockVault();
    return false; // Locked due to timeout
  }
  // Update activity timestamp
  await chrome.storage.session.set({ lastActive: Date.now() });
  return true;
}

async function lockVault() {
  await chrome.storage.session.remove(["kek", "lastActive", "activeSharedKey"]);
  activeSharedKey = null;
}

// --- Encrypted IPC Communications ---

function sendEncryptedResponse(sendResponse, payloadObj, success = true) {
  if (!activeSharedKey) {
    sendResponse({ success: false, error: "IPC security channel not established" });
    return;
  }
  encryptAESGCM(activeSharedKey, JSON.stringify({ success, data: payloadObj }))
    .then(encrypted => {
      sendResponse({ type: "ENCRYPTED_MSG", iv: encrypted.iv, ciphertext: encrypted.ciphertext });
    })
    .catch(err => {
      sendResponse({ success: false, error: "IPC encryption error: " + err.message });
    });
}

// --- Audit Logging (Encrypted) ---

async function writeAuditLog(eventText) {
  try {
    const session = await chrome.storage.session.get("kek");
    if (!session.kek) return; // Cannot write encrypted log while locked

    const rawKek = base64ToArrayBuffer(session.kek);
    const key = await crypto.subtle.importKey(
      "raw",
      rawKek,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    const local = await chrome.storage.local.get("logs");
    let logs = [];
    if (local.logs) {
      try {
        const decryptedLogsStr = await decryptAESGCM(key, local.logs.iv, local.logs.ciphertext);
        logs = JSON.parse(decryptedLogsStr);
      } catch (e) {
        console.error("Log decryption failed", e);
      }
    }

    logs.push({
      timestamp: Date.now(),
      event: eventText
    });

    if (logs.length > 100) {
      logs.shift(); // Cap logs size
    }

    const encryptedLogs = await encryptAESGCM(key, JSON.stringify(logs));
    await chrome.storage.local.set({ logs: encryptedLogs });
  } catch (err) {
    console.error("Audit log error:", err);
  }
}

// --- Request Handlers ---

async function getStatus() {
  const local = await chrome.storage.local.get("salt");
  const session = await chrome.storage.session.get("kek");
  return {
    initialized: !!local.salt,
    unlocked: !!session.kek
  };
}

async function initializeVault(password) {
  const local = await chrome.storage.local.get("salt");
  if (local.salt) {
    throw new Error("Vault already initialized");
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const saltBase64 = arrayBufferToBase64(saltBytes);

  const kek = await deriveKeyFromPassword(password, saltBytes);
  const sentinelEnc = await encryptAESGCM(kek, "ZeroTrustSentinel");
  const emptyVaultEnc = await encryptAESGCM(kek, JSON.stringify([]));

  await chrome.storage.local.set({
    salt: saltBase64,
    sentinel: sentinelEnc,
    vault: emptyVaultEnc
  });

  const rawKek = await crypto.subtle.exportKey("raw", kek);
  await chrome.storage.session.set({
    kek: arrayBufferToBase64(rawKek),
    lastActive: Date.now()
  });

  await writeAuditLog("Vault initialized");
  return { success: true };
}

async function unlockVault(password) {
  const local = await chrome.storage.local.get(["salt", "sentinel"]);
  if (!local.salt || !local.sentinel) {
    throw new Error("Vault not initialized");
  }

  const saltBytes = new Uint8Array(base64ToArrayBuffer(local.salt));
  const kek = await deriveKeyFromPassword(password, saltBytes);

  try {
    const sentinelDec = await decryptAESGCM(kek, local.sentinel.iv, local.sentinel.ciphertext);
    if (sentinelDec !== "ZeroTrustSentinel") {
      throw new Error("Sentinel mismatch");
    }
  } catch (e) {
    throw new Error("INCORRECT_PASSWORD");
  }

  const rawKek = await crypto.subtle.exportKey("raw", kek);
  await chrome.storage.session.set({
    kek: arrayBufferToBase64(rawKek),
    lastActive: Date.now()
  });

  await writeAuditLog("Vault unlocked");
  return { success: true };
}

async function getAccountsTotp() {
  const session = await chrome.storage.session.get("kek");
  const rawKek = base64ToArrayBuffer(session.kek);
  const key = await crypto.subtle.importKey(
    "raw",
    rawKek,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const local = await chrome.storage.local.get("vault");
  if (!local.vault) return [];

  const decryptedVaultStr = await decryptAESGCM(key, local.vault.iv, local.vault.ciphertext);
  const accounts = JSON.parse(decryptedVaultStr);
  const accountsWithCodes = [];

  for (const acc of accounts) {
    try {
      const code = await generateTOTP(acc.secret);
      accountsWithCodes.push({
        id: acc.id,
        issuer: acc.issuer,
        name: acc.name,
        totp: code
      });
    } catch (err) {
      console.error("TOTP Generation error:", err);
      accountsWithCodes.push({
        id: acc.id,
        issuer: acc.issuer,
        name: acc.name,
        totp: "ERR_KEY"
      });
    }
  }
  return accountsWithCodes;
}

async function addAccount(issuer, name, secret) {
  // Strict format enforcement
  secret = secret.replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z2-7]+=*$/.test(secret)) {
    throw new Error("Invalid Base32 secret key format");
  }

  const session = await chrome.storage.session.get("kek");
  const rawKek = base64ToArrayBuffer(session.kek);
  const key = await crypto.subtle.importKey(
    "raw",
    rawKek,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  const local = await chrome.storage.local.get("vault");
  let accounts = [];
  if (local.vault) {
    const decryptedVaultStr = await decryptAESGCM(key, local.vault.iv, local.vault.ciphertext);
    accounts = JSON.parse(decryptedVaultStr);
  }

  accounts.push({
    id: crypto.randomUUID(),
    issuer: issuer.trim(),
    name: name.trim(),
    secret: secret
  });

  const encryptedVault = await encryptAESGCM(key, JSON.stringify(accounts));
  await chrome.storage.local.set({ vault: encryptedVault });

  await writeAuditLog(`Added account: ${issuer.trim()} (${name.trim()})`);
  return { success: true };
}

async function deleteAccount(id) {
  const session = await chrome.storage.session.get("kek");
  const rawKek = base64ToArrayBuffer(session.kek);
  const key = await crypto.subtle.importKey(
    "raw",
    rawKek,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  const local = await chrome.storage.local.get("vault");
  if (!local.vault) throw new Error("Vault empty");

  const decryptedVaultStr = await decryptAESGCM(key, local.vault.iv, local.vault.ciphertext);
  const accounts = JSON.parse(decryptedVaultStr);

  const target = accounts.find(acc => acc.id === id);
  const filtered = accounts.filter(acc => acc.id !== id);

  const encryptedVault = await encryptAESGCM(key, JSON.stringify(filtered));
  await chrome.storage.local.set({ vault: encryptedVault });

  const label = target ? `${target.issuer} (${target.name})` : "Unknown";
  await writeAuditLog(`Deleted account: ${label}`);
  return { success: true };
}

async function exportBackup() {
  const local = await chrome.storage.local.get(["salt", "vault", "logs"]);
  if (!local.salt || !local.vault) {
    throw new Error("Vault database empty or uninitialized");
  }
  return {
    salt: local.salt,
    vault: local.vault,
    logs: local.logs || null
  };
}

async function importBackup(backupData, password) {
  if (!backupData || !backupData.salt || !backupData.vault) {
    throw new Error("Invalid backup format");
  }

  // Decrypt backup to verify password and structure integrity
  const backupSaltBytes = new Uint8Array(base64ToArrayBuffer(backupData.salt));
  const backupKek = await deriveKeyFromPassword(password, backupSaltBytes);

  let decryptedAccountsStr = "";
  try {
    decryptedAccountsStr = await decryptAESGCM(backupKek, backupData.vault.iv, backupData.vault.ciphertext);
    const parsed = JSON.parse(decryptedAccountsStr);
    if (!Array.isArray(parsed)) throw new Error("Backup core is not an array");
  } catch (e) {
    throw new Error("INCORRECT_PASSWORD");
  }

  // Re-encrypt with active session KEK
  const session = await chrome.storage.session.get("kek");
  const rawKek = base64ToArrayBuffer(session.kek);
  const activeKey = await crypto.subtle.importKey(
    "raw",
    rawKek,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const reEncryptedVault = await encryptAESGCM(activeKey, decryptedAccountsStr);
  await chrome.storage.local.set({ vault: reEncryptedVault });

  if (backupData.logs) {
    try {
      const decryptedLogsStr = await decryptAESGCM(backupKek, backupData.logs.iv, backupData.logs.ciphertext);
      const reEncryptedLogs = await encryptAESGCM(activeKey, decryptedLogsStr);
      await chrome.storage.local.set({ logs: reEncryptedLogs });
    } catch (err) {
      console.warn("Failed to decrypt backup logs, skipping", err);
    }
  }

  await writeAuditLog("Imported backup file successfully");
  return { success: true };
}

async function getAuditLogs() {
  const session = await chrome.storage.session.get("kek");
  const rawKek = base64ToArrayBuffer(session.kek);
  const key = await crypto.subtle.importKey(
    "raw",
    rawKek,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const local = await chrome.storage.local.get("logs");
  if (!local.logs) return [];

  try {
    const decryptedLogsStr = await decryptAESGCM(key, local.logs.iv, local.logs.ciphertext);
    return JSON.parse(decryptedLogsStr);
  } catch (e) {
    console.error("Logs decryption error", e);
    return [];
  }
}

// --- Encrypted Request Processing Switch ---

async function handleEncryptedRequest(action, params) {
  if (action !== "GET_STATUS" && action !== "INITIALIZE_VAULT" && action !== "UNLOCK_VAULT") {
    const isUnlocked = await checkAutoLock();
    if (!isUnlocked) {
      throw new Error("VAULT_LOCKED");
    }
  }

  switch (action) {
    case "GET_STATUS":
      return await getStatus();
    case "INITIALIZE_VAULT":
      return await initializeVault(params.password);
    case "UNLOCK_VAULT":
      return await unlockVault(params.password);
    case "LOCK_VAULT":
      await lockVault();
      return { success: true };
    case "GET_ACCOUNTS_TOTP":
      return await getAccountsTotp();
    case "ADD_ACCOUNT":
      return await addAccount(params.issuer, params.name, params.secret);
    case "DELETE_ACCOUNT":
      return await deleteAccount(params.id);
    case "EXPORT_BACKUP":
      return await exportBackup();
    case "IMPORT_BACKUP":
      return await importBackup(params.backupData, params.password);
    case "GET_AUDIT_LOGS":
      return await getAuditLogs();
    case "LOG_EVENT":
      await writeAuditLog(params.event);
      return { success: true };
    default:
      throw new Error("Unsupported action: " + action);
  }
}

async function getMatchedTotp(domain) {
  const session = await chrome.storage.session.get("kek");
  if (!session.kek) {
    return { success: false, error: "LOCKED" };
  }

  const accountsWithCodes = await getAccountsTotp();
  const cleanDomain = domain.toLowerCase();

  const matches = accountsWithCodes.filter(acc => {
    const cleanIssuer = acc.issuer.toLowerCase();
    if (cleanDomain.includes(cleanIssuer) || cleanIssuer.includes(cleanDomain)) {
      return true;
    }
    const aliases = {
      "google": ["google.com", "gmail.com", "youtube.com"],
      "microsoft": ["live.com", "outlook.com", "microsoft.com", "hotmail.com"],
      "facebook": ["facebook.com", "meta.com"],
      "discord": ["discord.com", "discordapp.com"],
      "binance": ["binance.com", "binance.us"],
      "github": ["github.com"]
    };
    for (const [key, hostnames] of Object.entries(aliases)) {
      if (cleanIssuer.includes(key)) {
        if (hostnames.some(h => cleanDomain.includes(h))) return true;
      }
    }
    return false;
  });

  return { success: true, matches };
}

// --- Message Listener ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Get matched TOTP for content script (Unencrypted but secured via internal Chrome runtime message isolation)
  if (message.type === "GET_MATCHED_TOTP") {
    getMatchedTotp(message.domain)
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async response
  }

  // Handshake CONNECT_IPC (Unencrypted)
  if (message.type === "CONNECT_IPC") {
    generateECDHKeyPair()
      .then(async (keyPair) => {
        const popupPubKey = await importPublicKey(message.publicKey);
        activeSharedKey = await deriveECDHSharedSecret(keyPair.privateKey, popupPubKey);

        // Save activeSharedKey to session storage so it survives service worker suspension
        const rawSharedKey = await crypto.subtle.exportKey("raw", activeSharedKey);
        const sharedKeyBase64 = arrayBufferToBase64(rawSharedKey);
        await chrome.storage.session.set({ activeSharedKey: sharedKeyBase64 });

        const myPubKeyBase64 = await exportPublicKey(keyPair.publicKey);
        sendResponse({ success: true, publicKey: myPubKeyBase64 });
      })
      .catch(err => {
        console.error("ECDH Handshake failed:", err);
        sendResponse({ success: false, error: "ECDH Handshake failed: " + err.message });
      });
    return true; // Keep message channel open for async response
  }

  // Standard encrypted API requests
  if (message.type === "ENCRYPTED_MSG") {
    (async () => {
      try {
        let key = activeSharedKey;
        if (!key) {
          // Attempt to restore shared key from session storage if worker terminated
          const session = await chrome.storage.session.get("activeSharedKey");
          if (session.activeSharedKey) {
            const rawKey = base64ToArrayBuffer(session.activeSharedKey);
            key = await crypto.subtle.importKey(
              "raw",
              rawKey,
              { name: "AES-GCM" },
              false,
              ["encrypt", "decrypt"]
            );
            activeSharedKey = key;
          }
        }

        if (!key) {
          sendResponse({ success: false, error: "IPC channel not established" });
          return;
        }

        const decryptedStr = await decryptAESGCM(key, message.iv, message.ciphertext);
        const req = JSON.parse(decryptedStr);
        const result = await handleEncryptedRequest(req.action, req.params);
        sendEncryptedResponse(sendResponse, result, true);
      } catch (err) {
        console.error("Error processing request:", err);
        sendEncryptedResponse(sendResponse, { error: err.message }, false);
      }
    })();
    return true; // Keep message channel open for async response
  }

  sendResponse({ success: false, error: "Invalid IPC request type" });
  return false;
});
