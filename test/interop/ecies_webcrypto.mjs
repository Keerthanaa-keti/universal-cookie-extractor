// Web Crypto (crypto.subtle) ECIES — the exact path the browser extension will use.
// Proves the browser interoperates with Python/Node servers.
const subtle = globalThis.crypto.subtle;
const HKDF_SALT = new Uint8Array(32);
const HKDF_INFO = new TextEncoder().encode('cookie-vault-v3/dek-wrap');

const b64 = (b) => Buffer.from(b).toString('base64');
const b64url = (b) => Buffer.from(b).toString('base64url');
const fb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const fb64url = (s) => new Uint8Array(Buffer.from(s, 'base64url'));

async function importPub(raw) {
  return subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
}
async function importPriv(dRaw, xRaw) {
  return subtle.importKey('jwk',
    { kty: 'OKP', crv: 'X25519', d: b64url(dRaw), x: b64url(xRaw), key_ops: ['deriveBits'], ext: true },
    { name: 'X25519' }, false, ['deriveBits']);
}
async function deriveKey(privKey, pubKey) {
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pubKey }, privKey, 256));
  const base = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO }, base, 256);
  return subtle.importKey('raw', new Uint8Array(bits), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function seal(dek, recipientPubRaw) {
  const eph = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const ephPubRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const aesKey = await deriveKey(eph.privateKey, await importPub(recipientPubRaw));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, dek));
  return { epk: b64url(ephPubRaw), iv: b64(iv), ct: b64(ct) };
}
async function unseal(wrap, privRaw, pubRaw) {
  const aesKey = await deriveKey(await importPriv(privRaw, pubRaw), await importPub(fb64url(wrap.epk)));
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fb64(wrap.iv) }, aesKey, fb64(wrap.ct));
  return new Uint8Array(pt);
}

const mode = process.argv[2];
if (mode === 'seal') {
  const pubRaw = fb64url(process.argv[3]);
  const dek = fb64(process.argv[4]);
  console.log(JSON.stringify(await seal(dek, pubRaw)));
} else if (mode === 'unseal') {
  const privRaw = fb64url(process.argv[3]);
  const pubRaw = fb64url(process.argv[4]);
  console.log(b64(await unseal(JSON.parse(process.argv[5]), privRaw, pubRaw)));
} else if (mode === 'genkey') {
  const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const jwk = await subtle.exportKey('jwk', kp.privateKey);
  console.log(JSON.stringify({ pub: b64url(pub), priv: b64url(fb64url(jwk.d)) }));
}
