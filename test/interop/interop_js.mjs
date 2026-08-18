// Interop harness around the REAL shared module lib/shared/vault-crypto.mjs.
// Reads one JSON command from stdin, prints one JSON result to stdout.
import * as V from '../../lib/shared/vault-crypto.mjs';

const readStdin = () => new Promise((res) => {
  let d = ''; process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => (d += c)).on('end', () => res(d));
});

const b64ToBytes = (s) => V.fromB64(s);
const bytesToB64 = (b) => V.b64(b);

const req = JSON.parse(await readStdin());
let out;
switch (req.cmd) {
  case 'genkey':
    out = await V.generateServerKeypair();
    break;
  case 'owner-salt':
    out = { salt: V.generateOwnerSalt() };
    break;
  case 'make-entry': {
    const dek = V.generateDEK();
    const payload = await V.encryptCookies(req.cookies, dek);
    const server_wrap = await V.sealDEKForServer(dek, req.serverPub);
    const owner_wrap = await V.wrapDEKForOwner(dek, req.passphrase, req.ownerSalt);
    out = { ...payload, server_wrap, owner_wrap };
    break;
  }
  case 'read-entry-server': {
    const dek = await V.unsealDEKForServer(req.entry.server_wrap, req.priv, req.pub);
    out = { cookies: await V.decryptCookies(req.entry.ciphertext, req.entry.iv, dek) };
    break;
  }
  case 'read-entry-owner': {
    const dek = await V.unwrapDEKForOwner(req.entry.owner_wrap, req.passphrase);
    out = { cookies: await V.decryptCookies(req.entry.ciphertext, req.entry.iv, dek) };
    break;
  }
  case 'seal':
    out = await V.sealDEKForServer(b64ToBytes(req.dek), req.serverPub);
    break;
  case 'unseal':
    out = { dek: bytesToB64(await V.unsealDEKForServer(req.wrap, req.priv, req.pub)) };
    break;
  default:
    out = { error: 'unknown cmd ' + req.cmd };
}
process.stdout.write(JSON.stringify(out));
