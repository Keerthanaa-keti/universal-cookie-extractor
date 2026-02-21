// Background service worker - auto-collects all cookies and stores in chrome.storage.local
// This enables Claude in Chrome to read cookies via content script DOM injection

let debounceTimer = null;

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
  } catch (error) {
    console.error('[Cookie Extractor] Collection error:', error);
  }
}

// Collect on extension install
chrome.runtime.onInstalled.addListener(() => {
  console.log('[Cookie Extractor] Installed - collecting cookies');
  collectAllCookies();
});

// Collect on browser startup
chrome.runtime.onStartup.addListener(() => {
  console.log('[Cookie Extractor] Startup - collecting cookies');
  collectAllCookies();
});

// Set up periodic alarm (every 60 seconds)
chrome.alarms.create('cookieRefresh', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cookieRefresh') {
    collectAllCookies();
  }
});

// Collect on cookie changes (debounced 2s)
chrome.cookies.onChanged.addListener(() => {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  debounceTimer = setTimeout(() => {
    collectAllCookies();
    debounceTimer = null;
  }, 2000);
});

// Handle on-demand refresh requests from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'REQUEST_FRESH_COOKIES') {
    collectAllCookies().then(() => {
      sendResponse({ success: true });
    });
    return true; // Keep message channel open for async response
  }
});
