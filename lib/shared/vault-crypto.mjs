// ============================================================================
// Cookie Vault v3 — canonical envelope-encryption module (Web Crypto API).
//
// Runs unchanged in:
//   - the Chrome extension's module service worker (globalThis.crypto.subtle)
//   - Node.js  (globalThis.crypto.subtle, Node >= 18)
// The Python client mirrors this exactly in lib/python/vault_crypto.py.
//
// Scheme (validated cross-runtime, see test/interop):
//   cookies  -> AES-256-GCM(DEK)                         : {ciphertext, iv}
//   DEK -> server  : X25519 ECDH -> HKDF-SHA256 -> AES-GCM : {epk, iv, ct}  (ECIES)
//   DEK -> owner   : PBKDF2(passphrase) -> AES-GCM         : {salt, iv, ct}
// ============================================================================

const subtle = globalThis.crypto.subtle;
const HKDF_SALT = new Uint8Array(32);                       // explicit 32 zero bytes
const HKDF_INFO = new TextEncoder().encode('cookie-vault-v3/dek-wrap');
const PBKDF2_ITERATIONS = 100000;

// ---- base64 helpers (browser + Node safe; no Buffer dependency) ------------
export function b64(bytes) {
  let bin = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}
export function fromB64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return fromB64(s);
}

function randomBytes(n) { return globalThis.crypto.getRandomValues(new Uint8Array(n)); }

// ---- capability check ------------------------------------------------------
// Web Crypto X25519 landed in Chrome 137 / Node 18. Fail loudly if missing.
export async function assertCryptoSupport() {
  try {
    await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  } catch (_e) {
    throw new Error('Web Crypto X25519 unavailable (needs Chrome 137+ / Node 18+). Zero-knowledge vault cannot run here.');
  }
}

// ---- X25519 keypair (raw 32-byte keys, base64url) --------------------------
export async function generateServerKeypair() {
  const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pubRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const jwk = await subtle.exportKey('jwk', kp.privateKey);
  return { publicKey: b64url(pubRaw), privateKey: jwk.d };  // jwk.d is already base64url
}

async function importPub(pubB64url) {
  return subtle.importKey('raw', fromB64url(pubB64url), { name: 'X25519' }, false, []);
}
async function importPriv(privB64url, pubB64url) {
  return subtle.importKey('jwk',
    { kty: 'OKP', crv: 'X25519', d: privB64url, x: pubB64url, key_ops: ['deriveBits'], ext: true },
    { name: 'X25519' }, false, ['deriveBits']);
}
async function eciesKey(privKey, pubKey) {
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pubKey }, privKey, 256));
  const base = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO }, base, 256);
  return subtle.importKey('raw', new Uint8Array(bits), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---- DEK generation + cookie payload encryption ----------------------------
export function generateDEK() { return randomBytes(32); }

export async function encryptCookies(cookieArray, dek) {
  const key = await subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = randomBytes(12);
  const pt = new TextEncoder().encode(JSON.stringify(cookieArray));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, pt));
  return { ciphertext: b64(ct), iv: b64(iv) };
}
export async function decryptCookies(ciphertextB64, ivB64, dek) {
  const key = await subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ciphertextB64));
  return JSON.parse(new TextDecoder().decode(pt));
}

// ---- DEK wrapping: server (ECIES) ------------------------------------------
export async function sealDEKForServer(dek, serverPubB64url) {
  const eph = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const ephPubRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const key = await eciesKey(eph.privateKey, await importPub(serverPubB64url));
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, dek));
  return { epk: b64url(ephPubRaw), iv: b64(iv), ct: b64(ct) };
}
export async function unsealDEKForServer(wrap, privB64url, pubB64url) {
  const key = await eciesKey(await importPriv(privB64url, pubB64url), await importPub(wrap.epk));
  const dek = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(wrap.iv) }, key, fromB64(wrap.ct));
  return new Uint8Array(dek);
}

// ---- DEK wrapping: owner (PBKDF2 passphrase) -------------------------------
async function ownerKey(passphrase, salt) {
  const material = await subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export function generateOwnerSalt() { return b64(randomBytes(16)); }

export async function wrapDEKForOwner(dek, passphrase, ownerSaltB64) {
  const salt = fromB64(ownerSaltB64);
  const key = await ownerKey(passphrase, salt);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, dek));
  return { salt: ownerSaltB64, iv: b64(iv), ct: b64(ct) };
}
export async function unwrapDEKForOwner(wrap, passphrase) {
  const key = await ownerKey(passphrase, fromB64(wrap.salt));
  const dek = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(wrap.iv) }, key, fromB64(wrap.ct));
  return new Uint8Array(dek);
}

// ---- shared: domain scope match (mirrors the broker's rule) ----------------
// candidate matches pattern if pattern is '*', equal (ignoring leading dots),
// or candidate is a subdomain of pattern.
export function domainMatches(candidate, pattern) {
  if (pattern === '*') return true;
  const c = (candidate || '').replace(/^\.+/, '').toLowerCase();
  const p = (pattern || '').replace(/^\.+/, '').toLowerCase();
  return c === p || c.endsWith('.' + p);
}

// ---- shared: auth-cookie heuristic (used by extension sync filter) ---------
export function isAuthCookie(cookie) {
  const patterns = [
    'auth', 'session', 'token', 'login', 'user', 'csrf', 'xsrf',
    'li_at', 'c_user', 'xs', 'fr', 'sb', 'datr', 'twid', 'ct0',
    'sessionid', 'csrftoken', 'sid', 'hsid', 'ssid', 'apisid', 'sapisid',
    'jsessionid', 'phpsessid', 'asp.net_sessionid',
  ];
  const name = (cookie.name || '').toLowerCase();
  return patterns.some((p) => name.includes(p));
}
