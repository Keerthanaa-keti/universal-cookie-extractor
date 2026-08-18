// ============================================================================
// Cookie Vault v3 — end-to-end test.
//
// Runs the REAL broker (supabase/functions/cookie-broker/index.ts via Deno)
// against an in-memory mock of Supabase PostgREST, then exercises it with:
//   - raw HTTP (happy path, scope denial, bad token, revoked token, /domains)
//   - the REAL Python client (lib/python/cookie_vault.py) end-to-end
//
// Proves: token auth, scope enforcement, zero-knowledge sealing, and client
// decryption all work together — without touching live Supabase.
//
// Run from repo root:  node test/e2e/run_e2e.mjs
// Requires: deno, node>=18, python3 with `cryptography` + `requests`.
// ============================================================================
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as V from '../../lib/shared/vault-crypto.mjs';
import { CookieVault } from '../../lib/node/cookie-vault.js';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const MOCK_PORT = 8971;
const BROKER_PORT = 8972;
const BROKER = `http://127.0.0.1:${BROKER_PORT}/cookie-broker`;

const COOKIES = [
  { name: 'li_at', value: 'AQEDA-secret', domain: '.linkedin.com', path: '/', secure: true, httpOnly: true },
  { name: 'JSESSIONID', value: 'ajax:42', domain: '.linkedin.com', path: '/' },
];
const sha256hex = (s) => createHash('sha256').update(s).digest('hex');

let PASS = 0, FAIL = 0;
const check = (name, ok) => { console.log(`  [${ok ? 'PASS ✅' : 'FAIL ❌'}] ${name}`); ok ? PASS++ : FAIL++; };

// ---- build fixtures (zero-knowledge entry sealed to a test server key) ------
const serverKp = await V.generateServerKeypair();
const dek = V.generateDEK();
const payload = await V.encryptCookies(COOKIES, dek);
const serverWrap = await V.sealDEKForServer(dek, serverKp.publicKey);
const TOKEN = 'cvk_' + V.b64url(crypto.getRandomValues(new Uint8Array(32)));

const db = {
  tokens: [{
    id: 'tok-1', user_id: 'user-1', server_key_id: 'sk-1', revoked: false, expires_at: null,
    token_hash: sha256hex(TOKEN),
    server_keys: { label: 'test-server', allowed_domains: ['linkedin.com'], revoked: false },
  }],
  entries: [{
    id: 'e-1', user_id: 'user-1', domain: '.linkedin.com', ciphertext: payload.ciphertext, iv: payload.iv,
    cookie_count: COOKIES.length, has_auth_cookies: true, synced_at: new Date().toISOString(), expires_at: null,
  }],
  entry_keys: [{ entry_id: 'e-1', recipient_type: 'server', server_key_id: 'sk-1', wrapped_dek: serverWrap }],
  access_log: [],
};

// ---- mock Supabase PostgREST (only the queries the broker makes) -----------
function param(qs, key) {
  const v = qs.get(key);
  if (!v) return null;
  return v.replace(/^eq\./, '').replace(/^gte\./, '');
}
const mock = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const u = new URL(req.url, `http://127.0.0.1:${MOCK_PORT}`);
    const table = u.pathname.replace('/rest/v1/', '').split('?')[0];
    const qs = u.searchParams;
    const send = (obj, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

    if (req.method === 'GET' && table === 'access_tokens') {
      const h = param(qs, 'token_hash');
      send(db.tokens.filter((t) => t.token_hash === h));
    } else if (req.method === 'GET' && table === 'access_log') {
      const tid = param(qs, 'token_id');
      send(db.access_log.filter((l) => l.token_id === tid && l.status === 'ok'));
    } else if (req.method === 'GET' && table === 'cookie_entries') {
      send(db.entries);
    } else if (req.method === 'GET' && table === 'entry_keys') {
      const skid = param(qs, 'server_key_id');
      const inRaw = (qs.get('entry_id') || '').replace(/^in\.\(/, '').replace(/\)$/, '');
      const ids = inRaw ? inRaw.split(',') : [];
      send(db.entry_keys
        .filter((k) => k.server_key_id === skid && ids.includes(k.entry_id))
        .map((k) => ({ entry_id: k.entry_id, wrapped_dek: k.wrapped_dek })));
    } else if (req.method === 'POST' && table === 'access_log') {
      db.access_log.push({ ...JSON.parse(body || '{}'), id: 'log-' + db.access_log.length, created_at: new Date().toISOString() });
      send({}, 201);
    } else if (req.method === 'PATCH') {
      send({}, 200);
    } else {
      send({ error: 'mock: unhandled ' + req.method + ' ' + table }, 500);
    }
  });
});

async function waitFor(url, tries = 100) {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(url); if (r.ok) return true; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200)); // pace retries; deno cold start ~1-2s
  }
  return false;
}

const get = (path, token = TOKEN) =>
  fetch(`${BROKER}/${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });

let broker, pyProc;
try {
  await new Promise((r) => mock.listen(MOCK_PORT, r));

  broker = spawn('deno', ['run', '--allow-net', '--allow-env',
    join(ROOT, 'supabase/functions/cookie-broker/index.ts')], {
    env: { ...process.env, SUPABASE_URL: `http://127.0.0.1:${MOCK_PORT}`, SERVICE_ROLE_KEY: 'testkey', BROKER_PORT: String(BROKER_PORT) },
    stdio: ['ignore', 'inherit', 'inherit'],
  });

  if (!(await waitFor(`${BROKER}/health`))) throw new Error('broker did not start');

  console.log('\nBroker e2e (real function + real Python client):');

  // 1. happy path — decrypt round trip
  let r = await get('cookies?domain=linkedin.com');
  let j = await r.json();
  check('GET /cookies returns one sealed entry', r.status === 200 && j.entries.length === 1);
  if (j.entries[0]) {
    const d = await V.unsealDEKForServer(j.entries[0].wrapped_dek, serverKp.privateKey, serverKp.publicKey);
    const cookies = await V.decryptCookies(j.entries[0].ciphertext, j.entries[0].iv, d);
    check('decrypted cookies match original', JSON.stringify(cookies) === JSON.stringify(COOKIES));
  } else { check('decrypted cookies match original', false); }

  // 2. scope denial
  r = await get('cookies?domain=example.com');
  check('out-of-scope domain rejected (403)', r.status === 403);

  // 3. bad token
  r = await get('cookies?domain=linkedin.com', 'cvk_bogus');
  check('invalid token rejected (401)', r.status === 401);

  // 4. /domains
  r = await get('domains');
  j = await r.json();
  check('/domains lists in-scope domain', r.status === 200 && j.domains.some((d) => d.domain.includes('linkedin')));

  // 5. revoked token
  db.tokens[0].revoked = true;
  r = await get('cookies?domain=linkedin.com');
  check('revoked token rejected (403)', r.status === 403);
  db.tokens[0].revoked = false;

  // key file shared by the Node + Python client checks
  const dir = mkdtempSync(join(tmpdir(), 'cv-e2e-'));
  const keyFile = join(dir, 'test-server.key');
  writeFileSync(keyFile, JSON.stringify({ label: 'test-server', public_key: serverKp.publicKey, private_key: serverKp.privateKey }));

  // 6. REAL Node client end-to-end
  const nodeVault = new CookieVault({ brokerUrl: BROKER, token: TOKEN, keyFile });
  const nodeCookies = await nodeVault.getCookies('linkedin.com');
  check('Node client decrypts via broker', JSON.stringify(nodeCookies) === JSON.stringify(COOKIES));

  // 7. REAL Python client end-to-end
  const pyOut = await new Promise((resolve) => {
    pyProc = spawn('python3', ['-m', 'cookie_vault', 'get', 'linkedin.com'], {
      cwd: join(ROOT, 'lib/python'),
      env: { ...process.env, COOKIE_VAULT_BROKER_URL: BROKER, COOKIE_VAULT_TOKEN: TOKEN, COOKIE_VAULT_KEY_FILE: keyFile },
    });
    let out = ''; pyProc.stdout.on('data', (c) => (out += c)); pyProc.stderr.on('data', (c) => process.stderr.write(c));
    pyProc.on('close', () => resolve(out));
  });
  let pyCookies = [];
  try { pyCookies = JSON.parse(pyOut); } catch { /* leave empty */ }
  check('Python client decrypts via broker', JSON.stringify(pyCookies) === JSON.stringify(COOKIES));
} finally {
  if (broker) broker.kill('SIGKILL');
  mock.close();
}

console.log(`\n${FAIL === 0 ? 'ALL E2E CHECKS PASSED' : 'E2E FAILURES: ' + FAIL} (${PASS} passed)`);
process.exit(FAIL === 0 ? 0 : 1);
