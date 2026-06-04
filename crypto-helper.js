/**
 * Zero-Trust Cryptographic Core Helper Module
 * Uses Native Web Crypto API
 */

// --- Base64 Serialization Utilities ---

export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// --- Base32 Decoding ---

export function base32ToBuf(str) {
  // Remove whitespace, hyphens, and force uppercase
  str = str.replace(/[\s-]/g, '').toUpperCase();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (let i = 0; i < str.length; i++) {
    const val = alphabet.indexOf(str[i]);
    if (val === -1) continue; // Skip padding (=) and invalid characters
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

// --- Double-Key Derivation (PBKDF2) ---

export async function deriveKeyFromPassword(password, saltBytes) {
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true, // Extractable to store in chrome.storage.session
    ["encrypt", "decrypt"]
  );
}

// --- Symmetric Cryptography (AES-GCM 256-bit) ---

export async function encryptAESGCM(key, plaintext) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(plaintext)
  );
  return {
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext)
  };
}

export async function decryptAESGCM(key, ivBase64, ciphertextBase64) {
  const dec = new TextDecoder();
  const iv = base64ToArrayBuffer(ivBase64);
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ciphertext
  );
  return dec.decode(decrypted);
}

// --- ECDH (Elliptic Curve Diffie-Hellman) IPC Encryption Key Exchange ---

export async function generateECDHKeyPair() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true, // Must be extractable to export public key
    ["deriveKey", "deriveBits"]
  );
}

export async function exportPublicKey(key) {
  const exported = await crypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exported);
}

export async function importPublicKey(spkiBase64) {
  const spkiBuffer = base64ToArrayBuffer(spkiBase64);
  return crypto.subtle.importKey(
    "spki",
    spkiBuffer,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
}

export async function deriveECDHSharedSecret(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false, // Shared secret itself should NEVER be extractable
    ["encrypt", "decrypt"]
  );
}

// --- TOTP Generation (RFC 6238) with Memory Zeroing ---

export async function generateTOTP(secretBase32, timeStepSeconds = 30) {
  let secretBytes = null;
  let cryptoKey = null;
  try {
    secretBytes = base32ToBuf(secretBase32);
    if (secretBytes.length === 0) {
      throw new Error("Invalid Base32 secret");
    }

    const time = Math.floor(Date.now() / 1000);
    const counter = Math.floor(time / timeStepSeconds);

    // Build 8-byte big-endian counter buffer
    const counterBuf = new ArrayBuffer(8);
    const view = new DataView(counterBuf);
    view.setUint32(4, counter);
    view.setUint32(0, 0);
    const counterBytes = new Uint8Array(counterBuf);

    // Import the secret bytes for HMAC signing
    cryptoKey = await crypto.subtle.importKey(
      "raw",
      secretBytes,
      { name: "HMAC", hash: { name: "SHA-1" } },
      false,
      ["sign"]
    );

    // HMAC execution
    const signature = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      counterBytes
    );

    const hmacResult = new Uint8Array(signature);
    
    // Dynamic truncation
    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const codePart = 
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff);

    const totp = (codePart % 1000000).toString().padStart(6, '0');
    return totp;
  } finally {
    // Memory Sanitization: Zero-out the raw secret bytes immediately after compute
    if (secretBytes) {
      secretBytes.fill(0);
    }
  }
}
