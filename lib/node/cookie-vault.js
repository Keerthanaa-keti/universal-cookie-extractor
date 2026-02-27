/**
 * Cookie Vault - Node.js client for encrypted cloud cookie storage.
 *
 * Zero external dependencies - uses Node.js built-in crypto module.
 *
 * Usage:
 *   const { CookieVault } = require('./cookie-vault');
 *   const vault = new CookieVault(); // reads from env vars
 *   const cookies = await vault.getCookies('.linkedin.com');
 *   await vault.loadIntoPuppeteer(page, '.linkedin.com');
 *   const headers = await vault.cookieHeader('.linkedin.com');
 */

const crypto = require('crypto');
const https = require('https');
const http = require('http');

const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 32; // 256 bits

/**
 * Derive AES-256 key from passphrase using PBKDF2 (matching browser Web Crypto params).
 */
function deriveKey(passphrase, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256', (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/**
 * Decrypt AES-256-GCM encrypted cookie data.
 */
async function decrypt(encryptedData, ivBase64, saltBase64, vaultKey) {
  const salt = Buffer.from(saltBase64, 'base64');
  const iv = Buffer.from(ivBase64, 'base64');
  const ciphertext = Buffer.from(encryptedData, 'base64');

  const key = await deriveKey(vaultKey, salt);

  // GCM auth tag is the last 16 bytes of the ciphertext
  const authTagLength = 16;
  const encrypted = ciphertext.subarray(0, ciphertext.length - authTagLength);
  const authTag = ciphertext.subarray(ciphertext.length - authTagLength);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

/**
 * Simple HTTPS/HTTP request helper (no dependencies).
 */
function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: options.headers || {},
    };

    const req = mod.request(reqOptions, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        if (res.statusCode >= 400) {
          reject(new Error(`${res.statusCode}: ${body}`));
        } else {
          try {
            resolve(JSON.parse(body));
          } catch {
            resolve(body);
          }
        }
      });
    });

    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

class CookieVault {
  /**
   * @param {Object} [config]
   * @param {string} [config.vaultKey] - Encryption key (or COOKIE_VAULT_KEY env)
   * @param {string} [config.supabaseUrl] - Supabase URL (or COOKIE_VAULT_SUPABASE_URL env)
   * @param {string} [config.supabaseKey] - Supabase anon key (or COOKIE_VAULT_SUPABASE_KEY env)
   * @param {string} [config.email] - Auth email (or COOKIE_VAULT_EMAIL env)
   * @param {string} [config.password] - Auth password (or COOKIE_VAULT_PASSWORD env)
   */
  constructor(config = {}) {
    this.vaultKey = config.vaultKey || process.env.COOKIE_VAULT_KEY || '';
    this.supabaseUrl = (config.supabaseUrl || process.env.COOKIE_VAULT_SUPABASE_URL || '').replace(/\/$/, '');
    this.supabaseKey = config.supabaseKey || process.env.COOKIE_VAULT_SUPABASE_KEY || '';
    this.email = config.email || process.env.COOKIE_VAULT_EMAIL || '';
    this.password = config.password || process.env.COOKIE_VAULT_PASSWORD || '';

    if (!this.vaultKey || !this.supabaseUrl || !this.supabaseKey) {
      throw new Error(
        'Missing config. Set COOKIE_VAULT_KEY, COOKIE_VAULT_SUPABASE_URL, ' +
        'COOKIE_VAULT_SUPABASE_KEY env vars (or pass to constructor).'
      );
    }

    this._accessToken = null;
    this._refreshToken = null;
    this._tokenExpiresAt = 0;
    this._userId = null;
  }

  async _authenticate() {
    if (this._accessToken && Date.now() < this._tokenExpiresAt - 60000) {
      return;
    }

    let url, body;
    if (this._refreshToken) {
      url = `${this.supabaseUrl}/auth/v1/token?grant_type=refresh_token`;
      body = JSON.stringify({ refresh_token: this._refreshToken });
    } else {
      url = `${this.supabaseUrl}/auth/v1/token?grant_type=password`;
      body = JSON.stringify({ email: this.email, password: this.password });
    }

    try {
      const data = await request(url, {
        method: 'POST',
        headers: {
          'apikey': this.supabaseKey,
          'Content-Type': 'application/json',
        },
        body,
      });

      this._accessToken = data.access_token;
      this._refreshToken = data.refresh_token;
      this._userId = data.user.id;
      this._tokenExpiresAt = Date.now() + (data.expires_in * 1000);
    } catch (err) {
      this._refreshToken = null;
      if (body.includes('refresh_token')) {
        return this._authenticate();
      }
      throw err;
    }
  }

  _headers() {
    return {
      'apikey': this.supabaseKey,
      'Authorization': `Bearer ${this._accessToken}`,
      'Content-Type': 'application/json',
    };
  }

  async _query(path) {
    await this._authenticate();
    return request(`${this.supabaseUrl}/rest/v1/${path}`, {
      headers: this._headers(),
    });
  }

  /**
   * Get decrypted cookies for a domain.
   * @param {string} domain - e.g. '.linkedin.com'
   * @param {Object} [options]
   * @param {number} [options.maxAgeSeconds] - Reject entries older than this
   * @returns {Promise<Array>} Array of cookie objects
   */
  async getCookies(domain, options = {}) {
    const entries = await this._query(
      `cookie_entries?domain=ilike.*${encodeURIComponent(domain)}*` +
      `&select=encrypted_data,iv,salt,synced_at,domain`
    );

    if (!entries || entries.length === 0) return [];

    const now = Date.now();
    const allCookies = [];

    for (const entry of entries) {
      if (options.maxAgeSeconds) {
        const syncedAt = new Date(entry.synced_at).getTime();
        if ((now - syncedAt) / 1000 > options.maxAgeSeconds) continue;
      }

      const cookies = await decrypt(
        entry.encrypted_data,
        entry.iv,
        entry.salt,
        this.vaultKey
      );
      allCookies.push(...cookies);
    }

    return allCookies;
  }

  /**
   * Get Cookie header string for use with any HTTP client.
   * @param {string} domain
   * @param {Object} [options]
   * @returns {Promise<Object>} { Cookie: 'name1=value1; name2=value2' }
   */
  async cookieHeader(domain, options = {}) {
    const cookies = await this.getCookies(domain, options);
    if (cookies.length === 0) return {};
    const str = cookies.map(c => `${c.name}=${c.value}`).join('; ');
    return { Cookie: str };
  }

  /**
   * Load cookies into a Puppeteer page.
   * @param {Object} page - Puppeteer Page instance
   * @param {string} domain
   * @param {Object} [options]
   */
  async loadIntoPuppeteer(page, domain, options = {}) {
    const cookies = await this.getCookies(domain, options);
    const puppeteerCookies = cookies.map(c => {
      const cookie = {
        name: c.name,
        value: c.value,
        domain: c.domain || domain,
        path: c.path || '/',
      };
      if (c.secure) cookie.secure = true;
      if (c.httpOnly) cookie.httpOnly = true;
      if (c.sameSite) {
        const map = { no_restriction: 'None', lax: 'Lax', strict: 'Strict' };
        cookie.sameSite = map[c.sameSite.toLowerCase()] || 'Lax';
      }
      if (c.expirationDate) cookie.expires = c.expirationDate;
      return cookie;
    });

    if (puppeteerCookies.length > 0) {
      await page.setCookie(...puppeteerCookies);
    }
  }

  /**
   * Create a Playwright browser context with cookies loaded.
   * @param {Object} browser - Playwright Browser instance
   * @param {string} domain
   * @param {Object} [options]
   * @returns {Promise<Object>} BrowserContext
   */
  async playwrightContext(browser, domain, options = {}) {
    const cookies = await this.getCookies(domain, options);
    const context = await browser.newContext();

    const pwCookies = cookies.map(c => {
      const cookie = {
        name: c.name,
        value: c.value,
        domain: c.domain || domain,
        path: c.path || '/',
      };
      if (c.secure) cookie.secure = true;
      if (c.sameSite) {
        const map = { no_restriction: 'None', lax: 'Lax', strict: 'Strict' };
        cookie.sameSite = map[c.sameSite.toLowerCase()] || 'Lax';
      }
      if (c.expirationDate) cookie.expires = c.expirationDate;
      return cookie;
    });

    if (pwCookies.length > 0) {
      await context.addCookies(pwCookies);
    }

    return context;
  }

  /**
   * Use with node-fetch or similar: returns fetch-compatible options.
   * @param {string} domain
   * @param {Object} [options]
   * @returns {Promise<Object>} { headers: { Cookie: '...' } }
   */
  async fetchOptions(domain, options = {}) {
    const headers = await this.cookieHeader(domain, options);
    return { headers };
  }

  /**
   * List all domains that have cookies stored in the vault.
   * @returns {Promise<Array>}
   */
  async listDomains() {
    const entries = await this._query(
      'cookie_entries?select=domain,cookie_count,has_auth_cookies,synced_at'
    );
    return entries.map(e => ({
      domain: e.domain,
      cookieCount: e.cookie_count,
      hasAuthCookies: e.has_auth_cookies,
      syncedAt: e.synced_at,
    }));
  }
}

module.exports = { CookieVault };
