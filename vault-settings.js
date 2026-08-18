// Cookie Vault v3 — options page (owner management: Connection/Servers/Tokens/Audit).
// Talks to Supabase directly with the owner session. Secrets that must never sync
// (vault passphrase, refresh token) live in chrome.storage.local.
import { b64url } from './lib/shared/vault-crypto.mjs';

const $ = (id) => document.getElementById(id);
const el = {};
['statusBar', 'syncDot', 'syncStatusText', 'vaultEnabled', 'supabaseUrl', 'supabaseAnonKey',
 'vaultEmail', 'vaultPassword', 'authState', 'signInBtn', 'vaultKey', 'syncMode',
 'selectedDomains', 'selectedDomainsField', 'syncInterval', 'saveBtn', 'testBtn', 'syncNowBtn',
 'srvLabel', 'srvPubKey', 'srvDomains', 'addServerBtn', 'rewrapBtn', 'serversBody', 'serversEmpty',
 'tokServer', 'tokLabel', 'tokExpiry', 'issueTokenBtn', 'tokenReveal', 'tokensBody', 'tokensEmpty',
 'auditBody', 'auditEmpty', 'refreshAuditBtn'].forEach((k) => (el[k] = $(k)));

function status(msg, type = 'info') {
  el.statusBar.textContent = msg;
  el.statusBar.className = `status-bar ${type}`;
  if (type === 'success') setTimeout(() => (el.statusBar.className = 'status-bar'), 3000);
}

// ---------------- config + auth + REST --------------------------------------
async function getConfig() {
  const sync = await chrome.storage.sync.get({
    vault_enabled: false, supabase_url: '', supabase_anon_key: '',
    sync_mode: 'auth_only', selected_domains: [], sync_interval_minutes: 5,
  });
  const local = await chrome.storage.local.get({ vault_key: '', vault_refresh_token: '', vault_email: '' });
  return { ...sync, ...local };
}

let _access = null, _uid = null, _exp = 0;
async function tokenReq(cfg, grant, body) {
  const res = await fetch(`${cfg.supabase_url}/auth/v1/token?grant_type=${grant}`, {
    method: 'POST', headers: { apikey: cfg.supabase_anon_key, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`auth ${grant}: ${res.status} ${await res.text()}`);
  return res.json();
}
async function auth(forcePassword = false) {
  const cfg = await getConfig();
  if (!forcePassword && _access && Date.now() < _exp - 60000) return { accessToken: _access, userId: _uid };
  let data = null;
  if (!forcePassword && cfg.vault_refresh_token) {
    try { data = await tokenReq(cfg, 'refresh_token', { refresh_token: cfg.vault_refresh_token }); } catch { data = null; }
  }
  if (!data) {
    const email = el.vaultEmail.value.trim(), pw = el.vaultPassword.value;
    if (!email || !pw) throw new Error('Sign in: enter email + password first.');
    data = await tokenReq(cfg, 'password', { email, password: pw });
    await chrome.storage.local.set({ vault_refresh_token: data.refresh_token, vault_email: email });
    el.vaultPassword.value = '';
  }
  _access = data.access_token; _uid = data.user.id; _exp = Date.now() + data.expires_in * 1000;
  return { accessToken: _access, userId: _uid };
}
async function rest(method, path, body, prefer) {
  const cfg = await getConfig();
  const { accessToken } = await auth();
  const res = await fetch(`${cfg.supabase_url}/rest/v1/${path}`, {
    method,
    headers: { apikey: cfg.supabase_anon_key, Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', ...(prefer ? { Prefer: prefer } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
  const ct = res.headers.get('content-type') || '';
  return ct.includes('json') ? res.json() : null;
}

// ---------------- Connection tab --------------------------------------------
async function loadConnection() {
  const c = await getConfig();
  el.vaultEnabled.checked = c.vault_enabled;
  el.supabaseUrl.value = c.supabase_url;
  el.supabaseAnonKey.value = c.supabase_anon_key;
  el.vaultKey.value = c.vault_key;
  el.syncMode.value = c.sync_mode;
  el.selectedDomains.value = (c.selected_domains || []).join('\n');
  el.syncInterval.value = c.sync_interval_minutes;
  el.vaultEmail.value = c.vault_email;
  el.selectedDomainsField.style.display = c.sync_mode === 'selected_domains' ? 'block' : 'none';
  el.authState.textContent = c.vault_refresh_token ? 'Signed in (refresh token stored).' : 'Not signed in.';
  updateDot(c);
}
function updateDot(c) {
  if (!c.vault_enabled) { el.syncDot.className = 'dot disabled'; el.syncStatusText.textContent = 'Sync disabled'; }
  else if (!c.supabase_url || !c.vault_key) { el.syncDot.className = 'dot disconnected'; el.syncStatusText.textContent = 'Not configured'; }
  else { el.syncDot.className = 'dot connected'; el.syncStatusText.textContent = 'Configured'; }
}
el.syncMode.addEventListener('change', () => { el.selectedDomainsField.style.display = el.syncMode.value === 'selected_domains' ? 'block' : 'none'; });

el.saveBtn.addEventListener('click', async () => {
  const domains = el.selectedDomains.value.split('\n').map((d) => d.trim()).filter(Boolean);
  await chrome.storage.sync.set({
    vault_enabled: el.vaultEnabled.checked, supabase_url: el.supabaseUrl.value.replace(/\/$/, ''),
    supabase_anon_key: el.supabaseAnonKey.value.trim(), sync_mode: el.syncMode.value,
    selected_domains: domains, sync_interval_minutes: parseInt(el.syncInterval.value) || 5,
  });
  await chrome.storage.local.set({ vault_key: el.vaultKey.value });
  chrome.runtime.sendMessage({ type: 'VAULT_SETTINGS_UPDATED' });
  status('Settings saved', 'success');
  loadConnection();
});
el.signInBtn.addEventListener('click', async () => {
  try { await auth(true); status('Signed in — refresh token stored, password cleared.', 'success'); loadConnection(); }
  catch (e) { status(e.message, 'error'); }
});
el.testBtn.addEventListener('click', async () => {
  try { await rest('GET', 'cookie_vaults?select=id&limit=1'); status('Connection OK — schema reachable.', 'success'); }
  catch (e) { status('Failed: ' + e.message, 'error'); }
});
el.syncNowBtn.addEventListener('click', () => {
  status('Triggering sync...', 'info');
  chrome.runtime.sendMessage({ type: 'VAULT_SYNC_NOW' }, (r) => {
    if (chrome.runtime.lastError) status('Failed: ' + chrome.runtime.lastError.message, 'error');
    else if (r && r.success) status(`Synced ${r.cookies} cookies, ${r.domains} domains, ${r.servers} server(s).`, 'success');
    else status('Sync issue: ' + (r ? r.reason : 'unknown'), 'error');
  });
});

// ---------------- Servers tab -----------------------------------------------
function fmtTime(t) { return t ? new Date(t).toLocaleString() : '—'; }
function parseDomains(s) { return s.split(/[\n,]/).map((d) => d.trim()).filter(Boolean); }

async function loadServers() {
  try {
    const rows = await rest('GET', 'server_keys?select=*&order=created_at.desc');
    el.serversBody.innerHTML = '';
    el.serversEmpty.style.display = rows.length ? 'none' : 'block';
    for (const s of rows) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${esc(s.label)} ${s.revoked ? '<span class="badge bad">revoked</span>' : ''}</td>
        <td class="mono">${esc((s.allowed_domains || []).join(', ') || '—')}</td>
        <td class="mono">${esc(s.public_key.slice(0, 14))}…</td>
        <td>${fmtTime(s.last_used_at)}</td>
        <td>${s.revoked ? '' : `<button class="btn-danger btn-sm" data-revoke-server="${s.id}">Revoke</button>`}</td>`;
      el.serversBody.appendChild(tr);
    }
    // token dropdown
    el.tokServer.innerHTML = rows.filter((s) => !s.revoked).map((s) => `<option value="${s.id}">${esc(s.label)}</option>`).join('');
  } catch (e) { status('Load servers failed: ' + e.message, 'error'); }
}
el.addServerBtn.addEventListener('click', async () => {
  const label = el.srvLabel.value.trim(), pub = el.srvPubKey.value.trim(), domains = parseDomains(el.srvDomains.value);
  if (!label || !pub || !domains.length) return status('Label, public key, and at least one domain are required.', 'error');
  try {
    const { userId } = await auth();
    await rest('POST', 'server_keys', { user_id: userId, label, public_key: pub, allowed_domains: domains }, 'return=minimal');
    el.srvLabel.value = el.srvPubKey.value = el.srvDomains.value = '';
    status('Server registered. Click "Rewrap now" to seal existing cookies to it.', 'success');
    loadServers();
  } catch (e) { status('Register failed: ' + e.message, 'error'); }
});
el.rewrapBtn.addEventListener('click', () => el.syncNowBtn.click());
el.serversBody.addEventListener('click', async (e) => {
  const id = e.target.getAttribute('data-revoke-server');
  if (!id) return;
  try {
    await rest('PATCH', `server_keys?id=eq.${id}`, { revoked: true, revoked_at: new Date().toISOString() }, 'return=minimal');
    await rest('DELETE', `entry_keys?server_key_id=eq.${id}`, null, 'return=minimal');
    await rest('PATCH', `access_tokens?server_key_id=eq.${id}`, { revoked: true }, 'return=minimal');
    status('Server revoked. Its wraps and tokens are disabled immediately.', 'success');
    loadServers(); loadTokens();
  } catch (err) { status('Revoke failed: ' + err.message, 'error'); }
});

// ---------------- Tokens tab ------------------------------------------------
function randToken() { return 'cvk_' + b64url(crypto.getRandomValues(new Uint8Array(32))); }
async function sha256hex(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function loadTokens() {
  try {
    const rows = await rest('GET', 'access_tokens?select=*,server_keys(label)&order=created_at.desc');
    el.tokensBody.innerHTML = '';
    el.tokensEmpty.style.display = rows.length ? 'none' : 'block';
    for (const t of rows) {
      const expired = t.expires_at && new Date(t.expires_at) < new Date();
      const badge = t.revoked ? '<span class="badge bad">revoked</span>' : expired ? '<span class="badge warn">expired</span>' : '<span class="badge ok">active</span>';
      const tr = document.createElement('tr');
      tr.innerHTML = `<td class="mono">${esc(t.token_prefix)}…</td><td>${esc(t.server_keys ? t.server_keys.label : '—')}</td>
        <td>${esc(t.label || '—')}</td><td>${t.expires_at ? fmtTime(t.expires_at) : 'never'}</td><td>${badge}</td>
        <td>${t.revoked ? '' : `<button class="btn-danger btn-sm" data-revoke-token="${t.id}">Revoke</button>`}</td>`;
      el.tokensBody.appendChild(tr);
    }
  } catch (e) { status('Load tokens failed: ' + e.message, 'error'); }
}
el.issueTokenBtn.addEventListener('click', async () => {
  const serverId = el.tokServer.value;
  if (!serverId) return status('Register a server first.', 'error');
  try {
    const { userId } = await auth();
    const token = randToken();
    const days = parseInt(el.tokExpiry.value);
    const expires_at = days ? new Date(Date.now() + days * 86400000).toISOString() : null;
    await rest('POST', 'access_tokens', {
      user_id: userId, server_key_id: serverId, token_hash: await sha256hex(token),
      token_prefix: token.slice(0, 12), label: el.tokLabel.value.trim() || null, expires_at,
    }, 'return=minimal');
    el.tokenReveal.innerHTML = `<div class="token-reveal"><div class="help-text">Copy this now — it is shown only once:</div><div class="mono" style="margin-top:6px">${esc(token)}</div></div>`;
    el.tokLabel.value = el.tokExpiry.value = '';
    status('Token issued.', 'success');
    loadTokens();
  } catch (e) { status('Issue failed: ' + e.message, 'error'); }
});
el.tokensBody.addEventListener('click', async (e) => {
  const id = e.target.getAttribute('data-revoke-token');
  if (!id) return;
  try { await rest('PATCH', `access_tokens?id=eq.${id}`, { revoked: true }, 'return=minimal'); status('Token revoked.', 'success'); loadTokens(); }
  catch (err) { status('Revoke failed: ' + err.message, 'error'); }
});

// ---------------- Audit tab -------------------------------------------------
async function loadAudit() {
  try {
    const rows = await rest('GET', 'access_log?select=*,server_keys(label)&order=created_at.desc&limit=100');
    el.auditBody.innerHTML = '';
    el.auditEmpty.style.display = rows.length ? 'none' : 'block';
    for (const a of rows) {
      const cls = a.status === 'ok' ? 'ok' : a.status === 'rate_limited' ? 'warn' : 'bad';
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${fmtTime(a.created_at)}</td><td>${esc(a.server_keys ? a.server_keys.label : '—')}</td>
        <td class="mono">${esc(a.domain || '—')}</td><td><span class="badge ${cls}">${esc(a.status)}</span></td><td class="mono">${esc(a.ip || '—')}</td>`;
      el.auditBody.appendChild(tr);
    }
  } catch (e) { status('Load audit failed: ' + e.message, 'error'); }
}
el.refreshAuditBtn.addEventListener('click', loadAudit);

// ---------------- tabs + init -----------------------------------------------
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    const name = tab.dataset.tab;
    $(`panel-${name}`).classList.add('active');
    if (name === 'servers') loadServers();
    else if (name === 'tokens') { loadServers(); loadTokens(); }
    else if (name === 'audit') loadAudit();
  });
});
loadConnection();
