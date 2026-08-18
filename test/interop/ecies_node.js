// ECIES interop spike: X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM
// Standardized wire format for Cookie Vault v3 zero-knowledge envelope.
const crypto = require('crypto');

const HKDF_SALT = Buffer.alloc(32, 0);            // explicit 32 zero bytes (no ambiguity)
const HKDF_INFO = Buffer.from('cookie-vault-v3/dek-wrap');

const b64 = (buf) => Buffer.from(buf).toString('base64');
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64 = (s) => Buffer.from(s, 'base64');
const fromB64url = (s) => Buffer.from(s, 'base64url');

function genKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const pubRaw = fromB64url(publicKey.export({ format: 'jwk' }).x);
  const privRaw = fromB64url(privateKey.export({ format: 'jwk' }).d);
  return { pubRaw, privRaw };
}

function importPub(pubRaw) {
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: b64url(pubRaw) }, format: 'jwk',
  });
}
function importPriv(privRaw, pubRaw) {
  return crypto.createPrivateKey({
    key: { kty: 'OKP', crv: 'X25519', d: b64url(privRaw), x: b64url(pubRaw) }, format: 'jwk',
  });
}

// Seal a DEK to a recipient public key. Returns {epk, iv, ct}.
function sealDek(dek, recipientPubRaw) {
  const eph = crypto.generateKeyPairSync('x25519');
  const ephPubRaw = fromB64url(eph.publicKey.export({ format: 'jwk' }).x);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: importPub(recipientPubRaw) });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, HKDF_SALT, HKDF_INFO, 32));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(dek), cipher.final(), cipher.getAuthTag()]);
  return { epk: b64url(ephPubRaw), iv: b64(iv), ct: b64(ct) };
}

// Unseal a DEK using the recipient private key.
function unsealDek(wrap, recipientPrivRaw, recipientPubRaw) {
  const ephPubRaw = fromB64url(wrap.epk);
  const priv = importPriv(recipientPrivRaw, recipientPubRaw);
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: importPub(ephPubRaw) });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, HKDF_SALT, HKDF_INFO, 32));
  const iv = fromB64(wrap.iv);
  const raw = fromB64(wrap.ct);
  const tag = raw.subarray(raw.length - 16);
  const body = raw.subarray(0, raw.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

const mode = process.argv[2];
if (mode === 'genkey') {
  const kp = genKeypair();
  console.log(JSON.stringify({ pub: b64url(kp.pubRaw), priv: b64url(kp.privRaw) }));
} else if (mode === 'seal') {
  // args: pub(b64url) dek(b64)
  const pubRaw = fromB64url(process.argv[3]);
  const dek = fromB64(process.argv[4]);
  console.log(JSON.stringify(sealDek(dek, pubRaw)));
} else if (mode === 'unseal') {
  // args: priv(b64url) pub(b64url) wrapJson
  const privRaw = fromB64url(process.argv[3]);
  const pubRaw = fromB64url(process.argv[4]);
  const wrap = JSON.parse(process.argv[5]);
  console.log(b64(unsealDek(wrap, privRaw, pubRaw)));
} else if (mode === 'selftest') {
  const kp = genKeypair();
  const dek = crypto.randomBytes(32);
  const wrap = sealDek(dek, kp.pubRaw);
  const out = unsealDek(wrap, kp.privRaw, kp.pubRaw);
  console.log('node selftest match:', out.equals(dek));
}
