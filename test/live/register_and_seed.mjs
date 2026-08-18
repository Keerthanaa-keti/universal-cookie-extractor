// Register a server's public key (generated on that server) into the live vault,
// issue a token, and seed a test linkedin cookie sealed to it. Prints the token.
// Usage: node test/live/register_and_seed.mjs <server_public_key_b64url> [label]
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import * as V from '../../lib/shared/vault-crypto.mjs';
import { VaultSync } from '../../vault-sync.js';

const PUB = process.argv[2];
const LABEL = process.argv[3] || 'kiket-ec2';
if (!PUB) { console.error('need public key arg'); process.exit(2); }

const REF = readFileSync('/tmp/cv_ref', 'utf8').trim();
const URL = `https://${REF}.supabase.co`;
const BROKER = `${URL}/functions/v1/cookie-broker`;
const ANON = readFileSync('/tmp/cv_anon', 'utf8').trim();
const SERVICE = readFileSync(join(homedir(), '.cookie-vault-service'), 'utf8').trim();
const OWNER_PW = readFileSync(join(homedir(), '.cookie-vault-owner'), 'utf8').trim();
const OWNER_EMAIL = 'vault-owner@cookie-vault.local';
const sha = (s) => createHash('sha256').update(s).digest('hex');
const svcH = { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'Content-Type': 'application/json' };

async function rest(method, path, body) {
  const r = await fetch(`${URL}/rest/v1/${path}`, { method, headers: { ...svcH, Prefer: 'return=representation' }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text();
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${t}`);
  return t ? JSON.parse(t) : null;
}

// owner id
const si = await fetch(`${URL}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { apikey: ANON, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: OWNER_EMAIL, password: OWNER_PW }) });
const ownerId = (await si.json()).user.id;

// replace any prior server key of this label (cascade removes its tokens + entry_keys)
await rest('DELETE', `server_keys?user_id=eq.${ownerId}&label=eq.${LABEL}`).catch(() => {});
const sk = await rest('POST', 'server_keys', { user_id: ownerId, label: LABEL, public_key: PUB, allowed_domains: ['linkedin.com', 'higgsfield.ai'] });
const serverKeyId = sk[0].id;

// issue token
const token = 'cvk_' + V.b64url(crypto.getRandomValues(new Uint8Array(32)));
await rest('POST', 'access_tokens', { user_id: ownerId, server_key_id: serverKeyId, token_hash: sha(token), token_prefix: token.slice(0, 12), label: LABEL });

// seed a test linkedin cookie (writer seals to all registered servers, incl. this one)
const writer = new VaultSync();
await writer.syncToVault({ '.linkedin.com': [{ name: 'li_at', value: 'LIVE-KIKET-' + REF.slice(0, 6), domain: '.linkedin.com', path: '/', secure: true, httpOnly: true }] }, {
  vault_enabled: true, supabase_url: URL, supabase_anon_key: ANON, vault_key: 'live-smoke-passphrase',
  sync_mode: 'all', selected_domains: [], sync_interval_minutes: 5, vault_email: OWNER_EMAIL, vault_password: OWNER_PW, vault_refresh_token: '',
});

console.log('BROKER=' + BROKER);
console.log('TOKEN=' + token);
console.log('SERVER_KEY_ID=' + serverKeyId);
