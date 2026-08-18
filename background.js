// Background service worker (ES module) — collects all cookies into
// chrome.storage.local for Claude-in-Chrome, and syncs them to Cookie Vault v3
// (zero-knowledge envelope encryption) when enabled.

import { isAuthCookie } from './lib/shared/vault-crypto.mjs';
import { VaultSync } from './vault-sync.js';

let debounceTimer = null;
let vaultSyncDebounce = null;
const vaultSync = new VaultSync();

async function collectAllCookies() {
  try {
    const allCookies = await chrome.cookies.getAll({});
    const cookiesByDomain = {};
    allCookies.forEach((cookie) => {
      (cookiesByDomain[cookie.domain] ||= []).push({
        name: cookie.name, value: cookie.value, domain: cookie.domain, path: cookie.path,
        secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite,
        expirationDate: cookie.expirationDate, session: !cookie.expirationDate,
      });
    });
    const data = {
      timestamp: new Date().toISOString(),
      totalCookies: allCookies.length,
      domainCount: Object.keys(cookiesByDomain).length,
      domains: Object.keys(cookiesByDomain).sort(),
      cookiesByDomain,
    };
    await chrome.storage.local.set({ cookieData: data });
    console.log(`[Cookie Extractor] Collected ${allCookies.length} cookies from ${data.domainCount} domains`);
    return cookiesByDomain;
  } catch (error) {
    console.error('[Cookie Extractor] Collection error:', error);
    return null;
  }
}

async function collectAndSync() {
  const cookiesByDomain = await collectAllCookies();
  if (!cookiesByDomain) return { synced: false, reason: 'collection_failed' };
  const result = await vaultSync.syncToVault(cookiesByDomain);
  if (result.synced && result.domains > 0) {
    console.log(`[Vault] Synced ${result.cookies} cookies from ${result.domains} domains to ${result.servers} server(s)`);
  }
  return result;
}

async function setupVaultAlarm() {
  const settings = await vaultSync.getSettings();
  await chrome.alarms.clear('vaultSync');
  if (settings.vault_enabled && settings.supabase_url) {
    const interval = settings.sync_interval_minutes || 5;
    chrome.alarms.create('vaultSync', { periodInMinutes: interval });
    console.log(`[Vault] Sync alarm set: every ${interval} minutes`);
  }
}

chrome.runtime.onInstalled.addListener(() => { collectAllCookies(); setupVaultAlarm(); });
chrome.runtime.onStartup.addListener(() => { collectAllCookies(); setupVaultAlarm(); });

chrome.alarms.create('cookieRefresh', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cookieRefresh') collectAllCookies();
  else if (alarm.name === 'vaultSync') collectAndSync();
});

// Debounced local collection + earlier vault sync when an auth cookie changes.
chrome.cookies.onChanged.addListener((changeInfo) => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => { collectAllCookies(); debounceTimer = null; }, 2000);
  if (isAuthCookie({ name: changeInfo.cookie.name })) {
    clearTimeout(vaultSyncDebounce);
    vaultSyncDebounce = setTimeout(() => { collectAndSync(); vaultSyncDebounce = null; }, 5000);
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  switch (message.type) {
    case 'REQUEST_FRESH_COOKIES':
      collectAllCookies().then(() => sendResponse({ success: true }));
      return true;
    case 'VAULT_SETTINGS_UPDATED':
      setupVaultAlarm().then(() => sendResponse({ success: true }));
      return true;
    case 'VAULT_SYNC_NOW': // also used as "rewrap now" after registering a server
      collectAndSync().then((r) => sendResponse({ success: r.synced, domains: r.domains, cookies: r.cookies, servers: r.servers, reason: r.reason }));
      return true;
    case 'GET_VAULT_STATUS':
      vaultSync.getStatus().then((status) => sendResponse(status));
      return true;
    default:
      return false;
  }
});
