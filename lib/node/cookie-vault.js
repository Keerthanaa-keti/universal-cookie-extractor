/**
 * Cookie Vault v3 — Node.js client (zero-knowledge).
 *
 * A remote server reads cookies the owner synced from their browser. The server
 * holds ONLY a scoped token (COOKIE_VAULT_TOKEN) and its own X25519 private key.
 * No password, no master key, no Supabase credential. It talks only to the broker,
 * which returns ciphertext sealed to this server; decryption happens locally.
 *
 * Setup:
 *   node cookie-vault.js keygen --label my-server     # once, on the server
 *   export COOKIE_VAULT_BROKER_URL="https://<ref>.supabase.co/functions/v1/cookie-broker"
 *   export COOKIE_VAULT_TOKEN="cvk_..."
 *   export COOKIE_VAULT_KEY_FILE="~/.cookie-vault/my-server.key"
 *
 * Usage:
 *   import { CookieVault } from './cookie-vault.js';
 *   const vault = new CookieVault();
 *   const cookies = await vault.getCookies('linkedin.com');
 *   await vault.loadIntoPuppeteer(page, 'linkedin.com');
 */

import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import * as vc from '../shared/vault-crypto.mjs';

const DEFAULT_KEY_DIR = join(homedir(), '.cookie-vault');
const expand = (p) => (p && p.startsWith('~') ? join(homedir(), p.slice(1)) : p);

function loadKey({ privateKey, keyFile, label } = {}) {
  if (privateKey) {
    // Not enough to derive pub without an X25519 scalar-mult; require a key file instead.
    throw new Error('Pass a key file (COOKIE_VAULT_KEY_FILE); raw private key alone is unsupported in Node.');
  }
  let path = keyFile || process.env.COOKIE_VAULT_KEY_FILE;
  if (!path && label) path = join(DEFAULT_KEY_DIR, `${label}.key`);
  if (!path && process.env.COOKIE_VAULT_KEY_LABEL) path = join(DEFAULT_KEY_DIR, `${process.env.COOKIE_VAULT_KEY_LABEL}.key`);
  if (!path) {
    throw new Error('No key file. Set COOKIE_VAULT_KEY_FILE or run: node cookie-vault.js keygen --label <name>');
  }
  const data = JSON.parse(readFileSync(expand(path), 'utf8'));
  return { publicKey: data.public_key, privateKey: data.private_key };
}

export class CookieVault {
  constructor(config = {}) {
    this.brokerUrl = (config.brokerUrl || process.env.COOKIE_VAULT_BROKER_URL || '').replace(/\/$/, '');
    this.token = config.token || process.env.COOKIE_VAULT_TOKEN || '';
    if (!this.brokerUrl || !this.token) {
      throw new Error('Set COOKIE_VAULT_BROKER_URL and COOKIE_VAULT_TOKEN.');
    }
    const key = loadKey(config);
    this.publicKey = key.publicKey;
    this.privateKey = key.privateKey;
  }

  async _get(path, params = {}) {
    const qs = new URLSearchParams(params).toString();
    const url = `${this.brokerUrl}/${path}${qs ? `?${qs}` : ''}`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${this.token}` } });
    if (!res.ok) throw new Error(`broker ${path}: ${res.status} ${await res.text()}`);
    return res.json();
  }

  async getCookies(domain, options = {}) {
    const data = await this._get('cookies', { domain });
    const out = [];
    const now = Date.now();
    for (const entry of data.entries || []) {
      if (options.maxAgeSeconds) {
        const age = (now - new Date(entry.synced_at).getTime()) / 1000;
        if (age > options.maxAgeSeconds) continue;
      }
      const dek = await vc.unsealDEKForServer(entry.wrapped_dek, this.privateKey, this.publicKey);
      const cookies = await vc.decryptCookies(entry.ciphertext, entry.iv, dek);
      out.push(...cookies);
    }
    return out;
  }

  async listDomains() {
    return (await this._get('domains')).domains || [];
  }

  async cookieHeader(domain, options = {}) {
    const cookies = await this.getCookies(domain, options);
    if (cookies.length === 0) return {};
    return { Cookie: cookies.map((c) => `${c.name}=${c.value}`).join('; ') };
  }

  async fetchOptions(domain, options = {}) {
    return { headers: await this.cookieHeader(domain, options) };
  }

  _toBrowserCookies(cookies, domain) {
    return cookies.map((c) => {
      const ck = { name: c.name, value: c.value, domain: c.domain || domain, path: c.path || '/' };
      if (c.secure) ck.secure = true;
      if (c.httpOnly) ck.httpOnly = true;
      if (c.sameSite) {
        ck.sameSite = { no_restriction: 'None', lax: 'Lax', strict: 'Strict' }[String(c.sameSite).toLowerCase()] || 'Lax';
      }
      if (c.expirationDate) ck.expires = c.expirationDate;
      return ck;
    });
  }

  async loadIntoPuppeteer(page, domain, options = {}) {
    const cookies = this._toBrowserCookies(await this.getCookies(domain, options), domain);
    if (cookies.length) await page.setCookie(...cookies);
  }

  async playwrightContext(browser, domain, options = {}) {
    const cookies = this._toBrowserCookies(await this.getCookies(domain, options), domain);
    const context = await browser.newContext();
    if (cookies.length) await context.addCookies(cookies);
    return context;
  }
}

export async function keygen(label, outDir = DEFAULT_KEY_DIR) {
  const { publicKey, privateKey } = await vc.generateServerKeypair();
  mkdirSync(outDir, { recursive: true });
  const path = join(outDir, `${label}.key`);
  writeFileSync(path, JSON.stringify(
    { label, public_key: publicKey, private_key: privateKey, created_at: new Date().toISOString() }, null, 2));
  chmodSync(path, 0o600);
  console.log(`Private key written to ${path} (mode 600). Keep it on this server only.\n`);
  console.log('Register this server in the extension (Servers tab):');
  console.log(`  label:       ${label}`);
  console.log(`  public key:  ${publicKey}`);
  console.log('\nThen issue a token (Tokens tab) and set COOKIE_VAULT_TOKEN on this server.');
  return path;
}

// ---- CLI ----
if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, ...rest] = process.argv.slice(2);
  const flag = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
  const run = async () => {
    if (cmd === 'keygen') {
      const label = flag('--label');
      if (!label) throw new Error('keygen requires --label <name>');
      await keygen(label);
    } else if (cmd === 'get') {
      const domain = rest[0];
      console.log(JSON.stringify(await new CookieVault({ label: flag('--label') }).getCookies(domain), null, 2));
    } else if (cmd === 'domains') {
      console.log(JSON.stringify(await new CookieVault().listDomains(), null, 2));
    } else {
      console.log('usage: cookie-vault.js keygen --label <name> | get <domain> | domains');
      process.exit(1);
    }
  };
  run().catch((e) => { console.error(e.message); process.exit(1); });
}
