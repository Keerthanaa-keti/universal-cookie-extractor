// ============================================================================
// Cookie Vault v3 — VaultSync (extension writer, ES module).
//
// Runs in the background service worker. Encrypts cookies with a per-entry DEK,
// wraps the DEK for the owner (passphrase) AND seals it to each registered
// server's X25519 public key — but only for the domains that server is scoped
// to. Uploads only ciphertext + wrapped DEKs, so Supabase never sees plaintext.
//
// Secrets live in chrome.storage.local (NEVER chrome.storage.sync): the vault
// passphrase and the Supabase refresh token. The account password is used once
// to obtain a refresh token and is not persisted.
// ============================================================================

import {
  isAuthCookie, domainMatches, assertCryptoSupport,
  generateDEK, encryptCookies,
  wrapDEKForOwner, sealDEKForServer, generateOwnerSalt,
} from './lib/shared/vault-crypto.mjs';

const hasChrome = typeof chrome !== 'undefined' && chrome.storage;

export class VaultSync {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.userId = null;
    this.vaultId = null;
    this.ownerSalt = null;
    this.tokenExpiresAt = 0;
    // overridable for tests
    this._fetch = (typeof fetch !== 'undefined') ? fetch.bind(globalThis) : null;
  }

  async getSettings() {
    const sync = await chrome.storage.sync.get({
      vault_enabled: false,
      supabase_url: '',
      supabase_anon_key: '',
      sync_mode: 'auth_only',
      selected_domains: [],
      sync_interval_minutes: 5,
    });
    const local = await chrome.storage.local.get({
      vault_key: '',
      vault_refresh_token: '',
      vault_email: '',
      vault_password: '',   // transient: present only until first successful login
    });
    return { ...sync, ...local };
  }

  async isReady() {
    const s = await this.getSettings();
    return !!(s.vault_enabled && s.supabase_url && s.supabase_anon_key && s.vault_key &&
      (s.vault_refresh_token || (s.vault_email && s.vault_password)));
  }

  // --- Supabase auth: prefer refresh token; fall back to password once -------
  async authenticate(settings) {
    if (this.accessToken && Date.now() < this.tokenExpiresAt - 60000) return;

    const attempt = async (grant, body) => {
      const res = await this._fetch(`${settings.supabase_url}/auth/v1/token?grant_type=${grant}`, {
        method: 'POST',
        headers: { apikey: settings.supabase_anon_key, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`auth ${grant}: ${res.status} ${await res.text()}`);
      return res.json();
    };

    let data;
    const refresh = this.refreshToken || settings.vault_refresh_token;
    if (refresh) {
      try {
        data = await attempt('refresh_token', { refresh_token: refresh });
      } catch (_e) {
        this.refreshToken = null; // stale; fall through to password if available
      }
    }
    if (!data) {
      if (!settings.vault_email || !settings.vault_password) {
        throw new Error('Not authenticated: sign in once with email + password.');
      }
      data = await attempt('password', { email: settings.vault_email, password: settings.vault_password });
    }

    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    this.userId = data.user.id;
    this.tokenExpiresAt = Date.now() + (data.expires_in * 1000);

    // Persist the refresh token; drop the password so it is not kept at rest.
    if (hasChrome && data.refresh_token) {
      await chrome.storage.local.set({ vault_refresh_token: data.refresh_token });
      await chrome.storage.local.remove('vault_password');
    }
  }

  _headers(settings, extraPrefer) {
    const h = {
      apikey: settings.supabase_anon_key,
      Authorization: `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json',
    };
    if (extraPrefer) h.Prefer = extraPrefer;
    return h;
  }

  async _rest(settings, method, path, body, prefer) {
    const res = await this._fetch(`${settings.supabase_url}/rest/v1/${path}`, {
      method,
      headers: this._headers(settings, prefer),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
    const ct = res.headers.get('content-type') || '';
    return ct.includes('application/json') ? res.json() : null;
  }

  async ensureVault(settings) {
    if (this.vaultId && this.ownerSalt) return;
    await this.authenticate(settings);

    const existing = await this._rest(settings, 'GET', 'cookie_vaults?vault_name=eq.default&select=id,owner_salt');
    if (existing && existing.length > 0) {
      this.vaultId = existing[0].id;
      this.ownerSalt = existing[0].owner_salt;
      return;
    }
    const created = await this._rest(settings, 'POST', 'cookie_vaults',
      { user_id: this.userId, vault_name: 'default', owner_salt: generateOwnerSalt() },
      'return=representation');
    this.vaultId = created[0].id;
    this.ownerSalt = created[0].owner_salt;
  }

  async getServerKeys(settings) {
    return (await this._rest(settings, 'GET',
      'server_keys?revoked=eq.false&select=id,public_key,allowed_domains')) || [];
  }

  filterDomains(cookiesByDomain, settings) {
    const domains = Object.keys(cookiesByDomain);
    switch (settings.sync_mode) {
      case 'auth_only':
        return domains.filter((d) => cookiesByDomain[d].some((c) => isAuthCookie(c)));
      case 'selected_domains':
        return domains.filter((d) => settings.selected_domains.some((sel) => domainMatches(d, sel) || domainMatches(sel, d)));
      case 'all':
        return domains;
      default:
        return [];
    }
  }

  // --- main entry point ------------------------------------------------------
  async syncToVault(cookiesByDomain, settingsOverride) {
    const settings = settingsOverride || await this.getSettings();
    if (!settings.vault_enabled) return { synced: false, reason: 'disabled' };
    if (!settings.supabase_url || !settings.vault_key) return { synced: false, reason: 'not_configured' };

    try {
      await assertCryptoSupport();
      await this.authenticate(settings);
      await this.ensureVault(settings);
      const servers = await this.getServerKeys(settings);
      const domainsToSync = this.filterDomains(cookiesByDomain, settings);
      if (domainsToSync.length === 0) return { synced: true, domains: 0, cookies: 0, servers: servers.length };

      let totalCookies = 0;
      const errors = [];

      for (const domain of domainsToSync) {
        try {
          const cookies = cookiesByDomain[domain];
          const hasAuth = cookies.some((c) => isAuthCookie(c));
          const earliest = cookies.filter((c) => c.expirationDate)
            .reduce((min, c) => (c.expirationDate < min ? c.expirationDate : min), Infinity);

          const dek = generateDEK();
          const { ciphertext, iv } = await encryptCookies(cookies, dek);

          // upsert the entry, get its id
          const rows = await this._rest(settings, 'POST', 'cookie_entries?on_conflict=vault_id,domain', {
            vault_id: this.vaultId, user_id: this.userId, domain,
            ciphertext, iv, cookie_count: cookies.length, has_auth_cookies: hasAuth,
            expires_at: earliest === Infinity ? null : new Date(earliest * 1000).toISOString(),
            synced_at: new Date().toISOString(),
          }, 'resolution=merge-duplicates,return=representation');
          const entryId = rows[0].id;

          // rewrap: owner + each in-scope server
          await this._rest(settings, 'DELETE', `entry_keys?entry_id=eq.${entryId}`, null, 'return=minimal');
          const keyRows = [{
            entry_id: entryId, user_id: this.userId, recipient_type: 'owner', server_key_id: null,
            wrapped_dek: await wrapDEKForOwner(dek, settings.vault_key, this.ownerSalt),
          }];
          for (const s of servers) {
            const inScope = (s.allowed_domains || []).some((a) => domainMatches(domain, a));
            if (!inScope) continue; // a server can only ever decrypt its scoped domains
            keyRows.push({
              entry_id: entryId, user_id: this.userId, recipient_type: 'server', server_key_id: s.id,
              wrapped_dek: await sealDEKForServer(dek, s.public_key),
            });
          }
          await this._rest(settings, 'POST', 'entry_keys', keyRows, 'return=minimal');
          totalCookies += cookies.length;
        } catch (err) {
          errors.push({ domain, error: err.message });
        }
      }

      // audit
      try {
        await this._rest(settings, 'POST', 'sync_log', {
          user_id: this.userId, vault_id: this.vaultId, action: 'sync',
          domain_count: domainsToSync.length, cookie_count: totalCookies,
          server_count: servers.length, client_type: 'extension',
        }, 'return=minimal');
      } catch (_e) { /* non-fatal */ }

      await this._saveStatus({
        vault_last_sync: new Date().toISOString(),
        vault_last_sync_domains: domainsToSync.length,
        vault_last_sync_cookies: totalCookies,
        vault_last_sync_servers: servers.length,
        vault_sync_errors: errors.length ? errors : null,
        vault_sync_error: null,
      });
      return { synced: true, domains: domainsToSync.length, cookies: totalCookies, servers: servers.length, errors: errors.length ? errors : undefined };
    } catch (err) {
      await this._saveStatus({ vault_sync_error: err.message, vault_sync_error_at: new Date().toISOString() });
      return { synced: false, reason: err.message };
    }
  }

  async _saveStatus(obj) {
    if (hasChrome) await chrome.storage.local.set(obj);
  }

  async getStatus() {
    const settings = await this.getSettings();
    const local = await chrome.storage.local.get([
      'vault_last_sync', 'vault_last_sync_domains', 'vault_last_sync_cookies',
      'vault_last_sync_servers', 'vault_sync_error', 'vault_sync_error_at', 'vault_sync_errors',
    ]);
    return {
      enabled: settings.vault_enabled,
      configured: !!(settings.supabase_url && settings.vault_key && (settings.vault_refresh_token || settings.vault_email)),
      syncMode: settings.sync_mode,
      lastSync: local.vault_last_sync,
      lastSyncDomains: local.vault_last_sync_domains,
      lastSyncCookies: local.vault_last_sync_cookies,
      lastSyncServers: local.vault_last_sync_servers,
      lastError: local.vault_sync_error,
      lastErrorAt: local.vault_sync_error_at,
    };
  }
}
