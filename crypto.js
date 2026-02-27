// AES-256-GCM encryption/decryption for Cookie Vault
// Uses Web Crypto API (available in service workers and extension pages)
// Cross-platform compatible: same PBKDF2 params work in Python (cryptography) and Node.js (crypto)

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;    // 128-bit salt
const IV_LENGTH = 12;      // 96-bit IV (recommended for GCM)
const KEY_LENGTH = 256;    // AES-256

/**
 * Derive AES-256 key from passphrase using PBKDF2
 * @param {string} passphrase - The vault key
 * @param {Uint8Array} salt - Random salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(passphrase, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Convert ArrayBuffer to base64 string
 */
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encrypt cookie array for a domain
 * @param {Array} cookieArray - Array of cookie objects
 * @param {string} vaultKey - The COOKIE_VAULT_KEY passphrase
 * @returns {Promise<{encrypted_data: string, iv: string, salt: string}>} All base64-encoded
 */
async function encryptCookies(cookieArray, vaultKey) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(vaultKey, salt);

  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(cookieArray));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    plaintext
  );

  return {
    encrypted_data: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv),
    salt: bufferToBase64(salt)
  };
}

/**
 * Decrypt cookie array
 * @param {string} encryptedData - Base64-encoded ciphertext
 * @param {string} ivBase64 - Base64-encoded IV
 * @param {string} saltBase64 - Base64-encoded salt
 * @param {string} vaultKey - The COOKIE_VAULT_KEY passphrase
 * @returns {Promise<Array>} Decrypted cookie array
 */
async function decryptCookies(encryptedData, ivBase64, saltBase64, vaultKey) {
  const salt = base64ToBuffer(saltBase64);
  const iv = base64ToBuffer(ivBase64);
  const ciphertext = base64ToBuffer(encryptedData);
  const key = await deriveKey(vaultKey, salt);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext));
}

// Auth cookie detection (shared utility)
function isAuthCookie(cookie) {
  const authPatterns = [
    'auth', 'session', 'token', 'login', 'user', 'csrf', 'xsrf',
    'li_at', 'c_user', 'xs', 'fr', 'sb', 'datr',
    'auth_token', 'twid', 'ct0',
    'sessionid', 'csrftoken',
    'SID', 'HSID', 'SSID', 'APISID', 'SAPISID',
    'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId'
  ];
  return authPatterns.some(pattern =>
    cookie.name.toLowerCase().includes(pattern.toLowerCase())
  );
}
