// Vault Sync: Supabase client + sync logic for Cookie Vault
// Runs in background.js service worker context

class VaultSync {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.userId = null;
    this.vaultId = null;
    this.tokenExpiresAt = 0;
  }

  /**
   * Load vault settings from chrome.storage
   */
  async getSettings() {
    const result = await chrome.storage.sync.get({
      vault_enabled: false,
      supabase_url: '',
      supabase_anon_key: '',
      vault_key: '',
      sync_mode: 'auth_only',
      selected_domains: [],
      sync_interval_minutes: 5
    });
    const local = await chrome.storage.local.get({
      vault_email: '',
      vault_password: ''
    });
    return { ...result, ...local };
  }

  /**
   * Check if vault is configured and enabled
   */
  async isReady() {
    const s = await this.getSettings();
    return s.vault_enabled && s.supabase_url && s.supabase_anon_key &&
           s.vault_key && s.vault_email && s.vault_password;
  }

  /**
   * Supabase REST call helper
   */
  async supabaseRequest(settings, method, path, body = null, useServiceRole = false) {
    const url = `${settings.supabase_url}/rest/v1/${path}`;
    const headers = {
      'apikey': settings.supabase_anon_key,
      'Content-Type': 'application/json',
      'Prefer': method === 'POST' ? 'return=representation' : 'return=minimal'
    };

    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    } else {
      headers['Authorization'] = `Bearer ${settings.supabase_anon_key}`;
    }

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const response = await fetch(url, options);
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Supabase ${method} ${path}: ${response.status} ${text}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return response.json();
    }
    return null;
  }

  /**
   * Authenticate with Supabase (email/password)
   */
  async authenticate(settings) {
    if (this.accessToken && Date.now() < this.tokenExpiresAt - 60000) {
      return; // Token still valid (with 1-min buffer)
    }

    let url, body;
    if (this.refreshToken) {
      url = `${settings.supabase_url}/auth/v1/token?grant_type=refresh_token`;
      body = { refresh_token: this.refreshToken };
    } else {
      url = `${settings.supabase_url}/auth/v1/token?grant_type=password`;
      body = { email: settings.vault_email, password: settings.vault_password };
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'apikey': settings.supabase_anon_key,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      this.refreshToken = null; // Clear stale refresh token
      if (body.refresh_token) {
        // Retry with password
        return this.authenticate(settings);
      }
      const text = await response.text();
      throw new Error(`Auth failed: ${response.status} ${text}`);
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    this.userId = data.user.id;
    this.tokenExpiresAt = Date.now() + (data.expires_in * 1000);

    console.log('[Vault] Authenticated as', settings.vault_email);
  }

  /**
   * Get or create the default vault
   */
  async ensureVault(settings) {
    if (this.vaultId) return this.vaultId;

    await this.authenticate(settings);

    // Try to find existing vault
    const vaults = await this.supabaseRequest(
      settings, 'GET',
      'cookie_vaults?vault_name=eq.default&select=id'
    );

    if (vaults && vaults.length > 0) {
      this.vaultId = vaults[0].id;
      return this.vaultId;
    }

    // Create new vault
    const headers = {
      'apikey': settings.supabase_anon_key,
      'Authorization': `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation'
    };

    const response = await fetch(`${settings.supabase_url}/rest/v1/cookie_vaults`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        user_id: this.userId,
        vault_name: 'default'
      })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Failed to create vault: ${response.status} ${text}`);
    }

    const created = await response.json();
    this.vaultId = created[0].id;
    console.log('[Vault] Created vault:', this.vaultId);
    return this.vaultId;
  }

  /**
   * Filter domains based on sync_mode setting
   */
  filterDomains(cookiesByDomain, settings) {
    const domains = Object.keys(cookiesByDomain);

    switch (settings.sync_mode) {
      case 'auth_only':
        // Only sync domains that have auth cookies
        return domains.filter(domain =>
          cookiesByDomain[domain].some(c => isAuthCookie(c))
        );

      case 'selected_domains':
        // Only sync explicitly selected domains
        return domains.filter(domain =>
          settings.selected_domains.some(sel =>
            domain.includes(sel) || sel.includes(domain)
          )
        );

      case 'all':
        return domains;

      default:
        return [];
    }
  }

  /**
   * Sync cookies to vault (main entry point)
   */
  async syncToVault(cookiesByDomain) {
    const settings = await this.getSettings();
    if (!settings.vault_enabled) return { synced: false, reason: 'disabled' };
    if (!settings.supabase_url || !settings.vault_key) {
      return { synced: false, reason: 'not_configured' };
    }

    try {
      await this.authenticate(settings);
      const vaultId = await this.ensureVault(settings);
      const domainsToSync = this.filterDomains(cookiesByDomain, settings);

      if (domainsToSync.length === 0) {
        return { synced: true, domains: 0, cookies: 0 };
      }

      let totalCookies = 0;
      let errors = [];

      for (const domain of domainsToSync) {
        try {
          const cookies = cookiesByDomain[domain];
          const hasAuth = cookies.some(c => isAuthCookie(c));
          const earliestExpiry = cookies
            .filter(c => c.expirationDate)
            .reduce((min, c) => c.expirationDate < min ? c.expirationDate : min, Infinity);

          // Encrypt the cookies
          const { encrypted_data, iv, salt } = await encryptCookies(cookies, settings.vault_key);

          // Upsert to Supabase
          const headers = {
            'apikey': settings.supabase_anon_key,
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
            'Prefer': 'resolution=merge-duplicates,return=minimal'
          };

          const entry = {
            vault_id: vaultId,
            user_id: this.userId,
            domain: domain,
            encrypted_data: encrypted_data,
            iv: iv,
            salt: salt,
            cookie_count: cookies.length,
            has_auth_cookies: hasAuth,
            expires_at: earliestExpiry === Infinity ? null : new Date(earliestExpiry * 1000).toISOString(),
            synced_at: new Date().toISOString()
          };

          await fetch(`${settings.supabase_url}/rest/v1/cookie_entries`, {
            method: 'POST',
            headers,
            body: JSON.stringify(entry)
          });

          totalCookies += cookies.length;
        } catch (err) {
          errors.push({ domain, error: err.message });
          console.error(`[Vault] Failed to sync ${domain}:`, err);
        }
      }

      // Log the sync
      try {
        await fetch(`${settings.supabase_url}/rest/v1/sync_log`, {
          method: 'POST',
          headers: {
            'apikey': settings.supabase_anon_key,
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
          },
          body: JSON.stringify({
            user_id: this.userId,
            vault_id: vaultId,
            action: 'sync',
            domain_count: domainsToSync.length,
            cookie_count: totalCookies,
            client_type: 'extension'
          })
        });
      } catch (logErr) {
        console.warn('[Vault] Failed to write sync log:', logErr);
      }

      // Store last sync info locally
      await chrome.storage.local.set({
        vault_last_sync: new Date().toISOString(),
        vault_last_sync_domains: domainsToSync.length,
        vault_last_sync_cookies: totalCookies,
        vault_sync_errors: errors.length > 0 ? errors : null
      });

      console.log(`[Vault] Synced ${totalCookies} cookies from ${domainsToSync.length} domains`);
      return {
        synced: true,
        domains: domainsToSync.length,
        cookies: totalCookies,
        errors: errors.length > 0 ? errors : undefined
      };
    } catch (err) {
      console.error('[Vault] Sync failed:', err);
      await chrome.storage.local.set({
        vault_sync_error: err.message,
        vault_sync_error_at: new Date().toISOString()
      });
      return { synced: false, reason: err.message };
    }
  }

  /**
   * Get vault status for popup display
   */
  async getStatus() {
    const settings = await this.getSettings();
    const local = await chrome.storage.local.get([
      'vault_last_sync', 'vault_last_sync_domains',
      'vault_last_sync_cookies', 'vault_sync_error',
      'vault_sync_error_at', 'vault_sync_errors'
    ]);

    return {
      enabled: settings.vault_enabled,
      configured: !!(settings.supabase_url && settings.vault_key && settings.vault_email),
      syncMode: settings.sync_mode,
      lastSync: local.vault_last_sync,
      lastSyncDomains: local.vault_last_sync_domains,
      lastSyncCookies: local.vault_last_sync_cookies,
      lastError: local.vault_sync_error,
      lastErrorAt: local.vault_sync_error_at
    };
  }
}
