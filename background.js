// Background service worker - auto-collects all cookies and stores in chrome.storage.local
// This enables Claude in Chrome to read cookies via content script DOM injection
// Also syncs to Cookie Vault (encrypted cloud storage) when enabled

importScripts('crypto.js', 'vault-sync.js');

let debounceTimer = null;
let vaultSyncDebounce = null;
const vaultSync = new VaultSync();

// Auth cookie detection (uses shared isAuthCookie from crypto.js)
function hasAuthCookieChanged(cookie) {
  return isAuthCookie({ name: cookie.name });
}

async function collectAllCookies() {
  try {
    const allCookies = await chrome.cookies.getAll({});

    // Group cookies by domain
    const cookiesByDomain = {};
    allCookies.forEach(cookie => {
      const domain = cookie.domain;
      if (!cookiesByDomain[domain]) {
        cookiesByDomain[domain] = [];
      }
      cookiesByDomain[domain].push({
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: cookie.sameSite,
        expirationDate: cookie.expirationDate,
        session: !cookie.expirationDate
      });
    });

    const data = {
      timestamp: new Date().toISOString(),
      totalCookies: allCookies.length,
      domainCount: Object.keys(cookiesByDomain).length,
      domains: Object.keys(cookiesByDomain).sort(),
      cookiesByDomain: cookiesByDomain
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
  if (cookiesByDomain) {
    const result = await vaultSync.syncToVault(cookiesByDomain);
    if (result.synced && result.domains > 0) {
      console.log(`[Vault] Synced ${result.cookies} cookies from ${result.domains} domains`);
    }
    return result;
  }
  return { synced: false, reason: 'collection_failed' };
}

// Setup vault sync alarm based on settings
async function setupVaultAlarm() {
  const settings = await vaultSync.getSettings();
  // Remove existing vault alarm
  await chrome.alarms.clear('vaultSync');

  if (settings.vault_enabled && settings.supabase_url) {
    const interval = settings.sync_interval_minutes || 5;
    chrome.alarms.create('vaultSync', { periodInMinutes: interval });
    console.log(`[Vault] Sync alarm set: every ${interval} minutes`);
  }
}

// Collect on extension install
chrome.runtime.onInstalled.addListener(() => {
  console.log('[Cookie Extractor] Installed - collecting cookies');
  collectAllCookies();
  setupVaultAlarm();
});

// Collect on browser startup
chrome.runtime.onStartup.addListener(() => {
  console.log('[Cookie Extractor] Startup - collecting cookies');
  collectAllCookies();
  setupVaultAlarm();
});

// Set up periodic alarm (every 60 seconds for local collection)
chrome.alarms.create('cookieRefresh', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cookieRefresh') {
    collectAllCookies();
  } else if (alarm.name === 'vaultSync') {
    collectAndSync();
  }
});

// Collect on cookie changes (debounced 2s)
// Trigger immediate vault sync if auth cookie changed (debounced 5s)
chrome.cookies.onChanged.addListener((changeInfo) => {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  debounceTimer = setTimeout(() => {
    collectAllCookies();
    debounceTimer = null;
  }, 2000);

  // If auth cookie changed, trigger vault sync sooner
  if (hasAuthCookieChanged(changeInfo.cookie)) {
    if (vaultSyncDebounce) clearTimeout(vaultSyncDebounce);
    vaultSyncDebounce = setTimeout(() => {
      collectAndSync();
      vaultSyncDebounce = null;
    }, 5000);
  }
});

// Handle messages from popup, content script, and settings page
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'REQUEST_FRESH_COOKIES') {
    collectAllCookies().then(() => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'VAULT_SETTINGS_UPDATED') {
    setupVaultAlarm();
    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'VAULT_SYNC_NOW') {
    collectAndSync().then((result) => {
      sendResponse({
        success: result.synced,
        domains: result.domains,
        cookies: result.cookies,
        reason: result.reason
      });
    });
    return true;
  }

  if (message.type === 'GET_VAULT_STATUS') {
    vaultSync.getStatus().then((status) => {
      sendResponse(status);
    });
    return true;
  }
});
