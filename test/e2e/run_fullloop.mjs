// ============================================================================
// Cookie Vault v3 — FULL-LOOP test.
//
//   extension writer (VaultSync)  ->  mock Supabase  ->  real broker (Deno)
//        (real envelope crypto)                              ->  real clients
//
// Proves the entire product works together with real cryptography:
//   - the writer encrypts + seals per-domain DEKs to a registered server
//   - an out-of-scope domain is sealed to the owner ONLY (never the server)
//   - the broker enforces scope; the Python + Node clients decrypt in-scope cookies
//
// Run from repo root:  node test/e2e/run_fullloop.mjs
// ============================================================================
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as V from '../../lib/shared/vault-crypto.mjs';
import { VaultSync } from '../../vault-sync.js';
import { CookieVault } from '../../lib/node/cookie-vault.js';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const MOCK_PORT = 8973;
const BROKER_PORT = 8974;
const BROKER = `http://127.0.0.1:${BROKER_PORT}/cookie-broker`;
const sha256hex = (s) => createHash('sha256').update(s).digest('hex');

let PASS = 0, FAIL = 0;
const check = (n, ok) => { console.log(`  [${ok ? 'PASS ✅' : 'FAIL ❌'}] ${n}`); ok ? PASS++ : FAIL++; };

const LINKEDIN = [
  { name: 'li_at', value: 'AQEDA-linked', domain: '.linkedin.com', path: '/', secure: true, httpOnly: true },
  { name: 'JSESSIONID', value: 'ajax:7', domain: '.linkedin.com', path: '/' },
];
const BANK = [{ name: 'SESSION', value: 'super-secret-bank', domain: '.bank.com', path: '/', secure: true }];
const cookiesByDomain = { '.linkedin.com': LINKEDIN, '.bank.com': BANK };

// ---- server the owner will grant linkedin-only access to --------------------
const serverKp = await V.generateServerKeypair();
const TOKEN = 'cvk_' + V.b64url(crypto.getRandomValues(new Uint8Array(32)));

// ---- in-memory Supabase (owner writes + broker reads) ----------------------
const db = {
  vaults: [],
  server_keys: [{ id: 'sk-1', user_id: 'user-1', label: 'linkedin-bot',
    public_key: serverKp.publicKey, allowed_domains: ['linkedin.com'], revoked: false }],
  cookie_entries: [],
  entry_keys: [],
  access_tokens: [{ id: 'tok-1', user_id: 'user-1', server_key_id: 'sk-1', token_hash: sha256hex(TOKEN),
    revoked: false, expires_at: null,
    server_keys: { label: 'linkedin-bot', allowed_domains: ['linkedin.com'], revoked: false } }],
  access_log: [],
  sync_log: [],
};

const bare = (v) => (v || '').replace(/^(eq|gte)\./, '');
const mock = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const u = new URL(req.url, `http://127.0.0.1:${MOCK_PORT}`);
    const qs = u.searchParams;
    const send = (obj, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    const P = u.pathname;

    // --- owner auth ---
    if (req.method === 'POST' && P === '/auth/v1/token') {
      return send({ access_token: 'owner-access', refresh_token: 'owner-refresh', expires_in: 3600, user: { id: 'user-1' } });
    }
    const table = P.replace('/rest/v1/', '');

    // --- owner writes (VaultSync) ---
    if (req.method === 'GET' && table === 'cookie_vaults') return send(db.vaults);
    if (req.method === 'POST' && table === 'cookie_vaults') {
      const b = JSON.parse(body); const row = { id: 'vault-1', ...b }; db.vaults.push(row); return send([row], 201);
    }
    if (req.method === 'GET' && table === 'server_keys') return send(db.server_keys.filter((s) => !s.revoked));
    if (req.method === 'POST' && table.startsWith('cookie_entries')) {
      const b = JSON.parse(body);
      let row = db.cookie_entries.find((e) => e.vault_id === b.vault_id && e.domain === b.domain);
      if (row) Object.assign(row, b); else { row = { id: 'entry-' + b.domain, ...b }; db.cookie_entries.push(row); }
      return send([row], 201);
    }
    if (req.method === 'DELETE' && table.startsWith('entry_keys')) {
      const eid = bare(qs.get('entry_id')); db.entry_keys = db.entry_keys.filter((k) => k.entry_id !== eid); return send({}, 200);
    }
    if (req.method === 'POST' && table === 'entry_keys') { JSON.parse(body).forEach((r) => db.entry_keys.push(r)); return send({}, 201); }
    if (req.method === 'POST' && table === 'sync_log') { db.sync_log.push(JSON.parse(body)); return send({}, 201); }

    // --- broker reads ---
    if (req.method === 'GET' && table === 'access_tokens') {
      return send(db.access_tokens.filter((t) => t.token_hash === bare(qs.get('token_hash'))));
    }
    if (req.method === 'GET' && table === 'access_log') {
      return send(db.access_log.filter((l) => l.token_id === bare(qs.get('token_id')) && l.status === 'ok'));
    }
    if (req.method === 'GET' && table === 'cookie_entries') return send(db.cookie_entries);
    if (req.method === 'GET' && table === 'entry_keys') {
      const skid = bare(qs.get('server_key_id'));
      const ids = (qs.get('entry_id') || '').replace(/^in\.\(/, '').replace(/\)$/, '').split(',').filter(Boolean);
      return send(db.entry_keys.filter((k) => k.recipient_type === 'server' && k.server_key_id === skid && ids.includes(k.entry_id))
        .map((k) => ({ entry_id: k.entry_id, wrapped_dek: k.wrapped_dek })));
    }
    if (req.method === 'POST' && table === 'access_log') { db.access_log.push({ ...JSON.parse(body), created_at: new Date().toISOString() }); return send({}, 201); }
    if (req.method === 'PATCH') return send({}, 200);
    return send({ error: 'mock unhandled ' + req.method + ' ' + P }, 500);
  });
});

const waitFor = async (url, tries = 100) => {
  for (let i = 0; i < tries; i++) {
    try { if ((await fetch(url)).ok) return true; } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
};
const get = (path, token = TOKEN) => fetch(`${BROKER}/${path}`, { headers: { Authorization: `Bearer ${token}` } });

let broker;
try {
  await new Promise((r) => mock.listen(MOCK_PORT, r));

  // 1. WRITER: run the real extension VaultSync against the mock
  console.log('\nFull loop (writer -> broker -> clients):');
  const writer = new VaultSync();
  const settings = {
    vault_enabled: true, supabase_url: `http://127.0.0.1:${MOCK_PORT}`, supabase_anon_key: 'anon',
    vault_key: 'owner-passphrase-🔐', sync_mode: 'all', selected_domains: [], sync_interval_minutes: 5,
    vault_email: 'owner@example.com', vault_password: 'pw', vault_refresh_token: '',
  };
  const wr = await writer.syncToVault(cookiesByDomain, settings);
  check('writer synced both domains to 1 server', wr.synced && wr.domains === 2 && wr.servers === 1);

  // 2. crypto invariant: linkedin sealed to server+owner; bank sealed to owner ONLY
  const liKeys = db.entry_keys.filter((k) => k.entry_id === 'entry-.linkedin.com');
  const bankKeys = db.entry_keys.filter((k) => k.entry_id === 'entry-.bank.com');
  check('linkedin sealed to owner + server', liKeys.some((k) => k.recipient_type === 'owner') && liKeys.some((k) => k.recipient_type === 'server'));
  check('bank sealed to owner ONLY (server out of scope)',
    bankKeys.some((k) => k.recipient_type === 'owner') && !bankKeys.some((k) => k.recipient_type === 'server'));

  // 3. start the real broker
  broker = spawn('deno', ['run', '--allow-net', '--allow-env', join(ROOT, 'supabase/functions/cookie-broker/index.ts')], {
    env: { ...process.env, SUPABASE_URL: `http://127.0.0.1:${MOCK_PORT}`, SERVICE_ROLE_KEY: 'svc', BROKER_PORT: String(BROKER_PORT) },
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  if (!(await waitFor(`${BROKER}/health`))) throw new Error('broker did not start');

  // 4. clients read linkedin (in scope) and are denied bank (out of scope)
  const dir = mkdtempSync(join(tmpdir(), 'cv-full-'));
  const keyFile = join(dir, 'linkedin-bot.key');
  writeFileSync(keyFile, JSON.stringify({ label: 'linkedin-bot', public_key: serverKp.publicKey, private_key: serverKp.privateKey }));

  const nodeVault = new CookieVault({ brokerUrl: BROKER, token: TOKEN, keyFile });
  const nodeLi = await nodeVault.getCookies('linkedin.com');
  check('Node client reads linkedin cookies (writer -> broker -> client)', JSON.stringify(nodeLi) === JSON.stringify(LINKEDIN));

  const bankRes = await get('cookies?domain=bank.com');
  check('bank.com denied to the linkedin-scoped server (403)', bankRes.status === 403);

  const pyOut = await new Promise((resolve) => {
    const p = spawn('python3', ['-m', 'cookie_vault', 'get', 'linkedin.com'], {
      cwd: join(ROOT, 'lib/python'),
      env: { ...process.env, COOKIE_VAULT_BROKER_URL: BROKER, COOKIE_VAULT_TOKEN: TOKEN, COOKIE_VAULT_KEY_FILE: keyFile },
    });
    let out = ''; p.stdout.on('data', (c) => (out += c)); p.stderr.on('data', (c) => process.stderr.write(c));
    p.on('close', () => resolve(out));
  });
  let pyLi = []; try { pyLi = JSON.parse(pyOut); } catch { /* empty */ }
  check('Python client reads linkedin cookies', JSON.stringify(pyLi) === JSON.stringify(LINKEDIN));

  // 5. audit trail recorded the reads
  check('reads were logged to access_log', db.access_log.filter((l) => l.status === 'ok').length >= 2);
} finally {
  if (broker) broker.kill('SIGKILL');
  mock.close();
}

console.log(`\n${FAIL === 0 ? 'FULL-LOOP PASSED' : 'FULL-LOOP FAILURES: ' + FAIL} (${PASS} passed)`);
process.exit(FAIL === 0 ? 0 : 1);
