// Live smoke test against the REAL provisioned Supabase project + deployed broker.
// Runs the real writer (VaultSync) and reader (CookieVault) end-to-end.
// Not part of run_all.sh (needs live creds). Invoked by provisioning only.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import * as V from '../../lib/shared/vault-crypto.mjs';
import { VaultSync } from '../../vault-sync.js';
import { CookieVault } from '../../lib/node/cookie-vault.js';

const REF = readFileSync('/tmp/cv_ref', 'utf8').trim();
const URL = `https://${REF}.supabase.co`;
const BROKER = `${URL}/functions/v1/cookie-broker`;
const ANON = readFileSync('/tmp/cv_anon', 'utf8').trim();
const SERVICE = readFileSync(join(homedir(), '.cookie-vault-service'), 'utf8').trim();
const sha = (s) => createHash('sha256').update(s).digest('hex');
const svcH = { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'Content-Type': 'application/json' };

let PASS = 0, FAIL = 0;
const check = (n, ok) => { console.log(`  [${ok ? 'PASS ✅' : 'FAIL ❌'}] ${n}`); ok ? PASS++ : FAIL++; };
const SAMPLE = [
  { name: 'li_at', value: 'LIVE-TEST-' + REF.slice(0, 6), domain: '.linkedin.com', path: '/', secure: true, httpOnly: true },
];

async function rest(method, path, body) {
  const r = await fetch(`${URL}/rest/v1/${path}`, { method, headers: { ...svcH, Prefer: 'return=representation' }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text();
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${t}`);
  return t ? JSON.parse(t) : null;
}

async function ensureOwner() {
  const email = 'vault-owner@cookie-vault.local';
  let pw;
  try { pw = readFileSync(join(homedir(), '.cookie-vault-owner'), 'utf8').trim(); }
  catch { pw = 'Ow' + V.b64url(crypto.getRandomValues(new Uint8Array(18))); writeFileSync(join(homedir(), '.cookie-vault-owner'), pw); chmodSync(join(homedir(), '.cookie-vault-owner'), 0o600); }
  // create (idempotent)
  const cr = await fetch(`${URL}/auth/v1/admin/users`, { method: 'POST', headers: svcH, body: JSON.stringify({ email, password: pw, email_confirm: true }) });
  if (!cr.ok && cr.status !== 422 && cr.status !== 409) console.log('  (admin create note:', cr.status, (await cr.text()).slice(0, 120), ')');
  // sign in to get id
  const si = await fetch(`${URL}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { apikey: ANON, 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: pw }) });
  const d = await si.json();
  return { email, pw, id: d.user.id };
}

console.log(`\nLive smoke test — project ${REF} (${URL})\n`);

// 1. owner
const owner = await ensureOwner();
check('owner user exists + can sign in', !!owner.id);

// 2. register a smoke server key (as the extension would)
const kiketDir = join(homedir(), '.cookie-vault');
mkdirSync(kiketDir, { recursive: true });
const kp = await V.generateServerKeypair();
const keyFile = join(kiketDir, 'smoke-test.key');
writeFileSync(keyFile, JSON.stringify({ label: 'smoke-test', public_key: kp.publicKey, private_key: kp.privateKey }, null, 2));
chmodSync(keyFile, 0o600);
// clean any prior smoke rows for idempotency
await rest('DELETE', `server_keys?user_id=eq.${owner.id}&label=eq.smoke-test`).catch(() => {});
const sk = await rest('POST', 'server_keys', { user_id: owner.id, label: 'smoke-test', public_key: kp.publicKey, allowed_domains: ['linkedin.com', 'higgsfield.ai'] });
const serverKeyId = sk[0].id;
check('smoke server registered (scope linkedin.com, higgsfield.ai)', !!serverKeyId);

// 3. WRITER: real VaultSync seeds a linkedin cookie sealed to owner + Kiket
const writer = new VaultSync();
const wr = await writer.syncToVault({ '.linkedin.com': SAMPLE }, {
  vault_enabled: true, supabase_url: URL, supabase_anon_key: ANON,
  vault_key: 'live-smoke-passphrase', sync_mode: 'all', selected_domains: [], sync_interval_minutes: 5,
  vault_email: owner.email, vault_password: owner.pw, vault_refresh_token: '',
});
check('writer synced to real Supabase (1 domain, 1 server)', wr.synced && wr.domains === 1 && wr.servers >= 1);

// 4. issue a smoke token
const token = 'cvk_' + V.b64url(crypto.getRandomValues(new Uint8Array(32)));
await rest('POST', 'access_tokens', { user_id: owner.id, server_key_id: serverKeyId, token_hash: sha(token), token_prefix: token.slice(0, 12), label: 'smoke-test' });
writeFileSync(join(homedir(), '.cookie-vault-smoke-token'), token); chmodSync(join(homedir(), '.cookie-vault-smoke-token'), 0o600);
check('smoke token issued', true);

// 5. READER: real client via the DEPLOYED broker
const vault = new CookieVault({ brokerUrl: BROKER, token, keyFile });
const got = await vault.getCookies('linkedin.com');
check('smoke reader decrypts linkedin cookie via LIVE broker', JSON.stringify(got) === JSON.stringify(SAMPLE));

// 6. scope: bank.com must be denied
const denied = await fetch(`${BROKER}/cookies?domain=bank.com`, { headers: { Authorization: `Bearer ${token}` } });
check('out-of-scope domain denied by live broker (403)', denied.status === 403);

// 7. audit logged
const log = await rest('GET', `access_log?server_key_id=eq.${serverKeyId}&order=created_at.desc&limit=5`);
check('read recorded in live access_log', Array.isArray(log) && log.some((l) => l.status === 'ok'));

console.log(`\n${FAIL === 0 ? 'LIVE SMOKE PASSED' : 'LIVE SMOKE FAILURES: ' + FAIL} (${PASS} passed)`);
console.log(`\nProject URL : ${URL}`);
console.log(`Broker URL  : ${BROKER}`);
console.log(`Smoke key   : ${keyFile}`);
console.log(`Smoke token : ~/.cookie-vault-smoke-token`);
process.exit(FAIL === 0 ? 0 : 1);
