// Mock Chrome APIs for testing outside extension context
// Simulates realistic cookies from popular sites

const MOCK_COOKIES = {
  'www.linkedin.com': [
    { name: 'li_at', value: 'AQEDASxxxxxMOCKxxxxxx', domain: '.linkedin.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*365 },
    { name: 'JSESSIONID', value: 'ajax:mock-session-123', domain: 'www.linkedin.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', session: true },
    { name: 'li_sugr', value: 'mock-sugr-value', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*90 },
    { name: 'bcookie', value: '"v=mock-bcookie-value"', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'bscookie', value: '"v=mock-bscookie-value"', domain: '.www.linkedin.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'lang', value: 'v=2&lang=en-us', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400 },
    { name: 'lidc', value: '"b=mock-lidc-value"', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400 },
    { name: '_gcl_au', value: 'mock-gcl-value', domain: '.linkedin.com', path: '/', secure: false, httpOnly: false, sameSite: 'lax', expirationDate: Date.now()/1000 + 86400*90 },
    { name: 'AnalyticsSyncHistory', value: 'mock-analytics', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*30 },
    { name: 'UserMatchHistory', value: 'mock-usermatch', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*30 },
    { name: 'li_theme', value: 'light', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*365 },
    { name: 'li_theme_set', value: 'app', domain: '.linkedin.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*365 },
  ],
  'www.facebook.com': [
    { name: 'c_user', value: 'mock-fb-user-id', domain: '.facebook.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*365 },
    { name: 'xs', value: 'mock-xs-token', domain: '.facebook.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*365 },
    { name: 'fr', value: 'mock-fr-value', domain: '.facebook.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*90 },
    { name: 'sb', value: 'mock-sb-value', domain: '.facebook.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'datr', value: 'mock-datr-value', domain: '.facebook.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'wd', value: '1920x1080', domain: '.facebook.com', path: '/', secure: true, httpOnly: false, sameSite: 'lax' },
  ],
  'www.google.com': [
    { name: 'SID', value: 'mock-google-sid', domain: '.google.com', path: '/', secure: false, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'HSID', value: 'mock-google-hsid', domain: '.google.com', path: '/', secure: false, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'SSID', value: 'mock-google-ssid', domain: '.google.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'APISID', value: 'mock-google-apisid', domain: '.google.com', path: '/', secure: false, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'SAPISID', value: 'mock-google-sapisid', domain: '.google.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
    { name: 'NID', value: 'mock-nid-value', domain: '.google.com', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*180 },
    { name: '1P_JAR', value: 'mock-1pjar', domain: '.google.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*30 },
  ],
  'example.com': [
    { name: 'session_token', value: 'mock-session-abc123', domain: 'example.com', path: '/', secure: true, httpOnly: true, sameSite: 'strict' },
    { name: 'csrf_token', value: 'mock-csrf-xyz789', domain: 'example.com', path: '/', secure: true, httpOnly: false, sameSite: 'strict', expirationDate: Date.now()/1000 + 3600 },
    { name: '_ga', value: 'GA1.2.mock.12345', domain: '.example.com', path: '/', secure: false, httpOnly: false, sameSite: 'no_restriction', expirationDate: Date.now()/1000 + 86400*730 },
  ],
};

// Flatten all cookies for "getAll with no domain" calls
const ALL_COOKIES = Object.values(MOCK_COOKIES).flat();

// --- Mock chrome.storage.local ---
const _storageData = {};
const _storageChangeListeners = [];

const mockStorageLocal = {
  get: function(keys, callback) {
    if (typeof keys === 'string') {
      const result = {};
      if (_storageData[keys] !== undefined) {
        result[keys] = _storageData[keys];
      }
      if (callback) callback(result);
      return Promise.resolve(result);
    }
    if (Array.isArray(keys)) {
      const result = {};
      keys.forEach(k => {
        if (_storageData[k] !== undefined) result[k] = _storageData[k];
      });
      if (callback) callback(result);
      return Promise.resolve(result);
    }
    // No keys = return all
    if (callback) callback({ ..._storageData });
    return Promise.resolve({ ..._storageData });
  },
  set: function(items, callback) {
    const changes = {};
    Object.keys(items).forEach(key => {
      const oldValue = _storageData[key];
      _storageData[key] = items[key];
      changes[key] = { oldValue, newValue: items[key] };
    });
    // Notify storage change listeners
    _storageChangeListeners.forEach(fn => fn(changes, 'local'));
    if (callback) callback();
    return Promise.resolve();
  },
  remove: function(keys, callback) {
    const keyList = typeof keys === 'string' ? [keys] : keys;
    keyList.forEach(k => delete _storageData[k]);
    if (callback) callback();
    return Promise.resolve();
  },
  clear: function(callback) {
    Object.keys(_storageData).forEach(k => delete _storageData[k]);
    if (callback) callback();
    return Promise.resolve();
  }
};

// --- Mock chrome.storage.onChanged ---
const mockStorageOnChanged = {
  addListener: function(fn) {
    _storageChangeListeners.push(fn);
  },
  removeListener: function(fn) {
    const idx = _storageChangeListeners.indexOf(fn);
    if (idx !== -1) _storageChangeListeners.splice(idx, 1);
  }
};

// --- Mock chrome.runtime ---
const _messageListeners = [];

const mockRuntime = {
  onMessage: {
    addListener: function(fn) {
      _messageListeners.push(fn);
    },
    removeListener: function(fn) {
      const idx = _messageListeners.indexOf(fn);
      if (idx !== -1) _messageListeners.splice(idx, 1);
    }
  },
  onInstalled: {
    addListener: function(fn) {
      // Simulate install event after a short delay
      setTimeout(() => fn({ reason: 'install' }), 50);
    }
  },
  onStartup: {
    addListener: function(fn) {
      // Store but don't auto-trigger startup
    }
  },
  sendMessage: function(message, callback) {
    // Route to background message listeners
    _messageListeners.forEach(fn => {
      fn(message, { tab: { id: 1 } }, (response) => {
        if (callback) callback(response);
      });
    });
  }
};

// --- Mock chrome.alarms ---
const _alarmListeners = [];

const mockAlarms = {
  create: function(name, options) {
    // Store alarm config but don't actually set up periodic triggers in test
    console.log(`[Mock Chrome] Alarm created: ${name}`, options);
  },
  onAlarm: {
    addListener: function(fn) {
      _alarmListeners.push(fn);
    }
  },
  // Helper for tests to trigger alarm manually
  _triggerAlarm: function(name) {
    _alarmListeners.forEach(fn => fn({ name }));
  }
};

// --- Mock chrome.cookies.onChanged ---
const _cookieChangeListeners = [];

const mockCookiesOnChanged = {
  addListener: function(fn) {
    _cookieChangeListeners.push(fn);
  },
  // Helper for tests to simulate cookie changes
  _triggerChange: function(changeInfo) {
    _cookieChangeListeners.forEach(fn => fn(changeInfo || {
      removed: false,
      cookie: { name: 'test', value: 'changed', domain: '.test.com' },
      cause: 'explicit'
    }));
  }
};

// Mock chrome.cookies API
window.chrome = {
  cookies: {
    getAll: function(filter) {
      return new Promise((resolve) => {
        setTimeout(() => {
          if (!filter || (!filter.domain && Object.keys(filter).length === 0)) {
            resolve(ALL_COOKIES);
          } else if (filter.domain) {
            const domain = filter.domain.replace(/^\./, '');
            const matches = ALL_COOKIES.filter(c => {
              const cookieDomain = c.domain.replace(/^\./, '');
              return cookieDomain.includes(domain) || domain.includes(cookieDomain);
            });
            resolve(matches);
          } else {
            resolve([]);
          }
        }, 150); // Simulate async delay
      });
    },
    onChanged: mockCookiesOnChanged
  },
  tabs: {
    query: function(queryInfo, callback) {
      // Simulate being on a website - use the selected mock site
      const mockSite = window.__MOCK_SITE__ || 'www.linkedin.com';
      const mockUrl = `https://${mockSite}/feed/`;
      callback([{
        id: 1,
        url: mockUrl,
        title: `Mock - ${mockSite}`
      }]);
    }
  },
  storage: {
    local: mockStorageLocal,
    onChanged: mockStorageOnChanged
  },
  runtime: mockRuntime,
  alarms: mockAlarms
};

// Read mock site from URL param (set by test harness iframe reload)
(function() {
    const params = new URLSearchParams(window.location.search);
    if (params.get('site')) {
        window.__MOCK_SITE__ = params.get('site');
    }
})();

// Expose internals for testing
window.__MOCK_INTERNALS__ = {
  storageData: _storageData,
  storageChangeListeners: _storageChangeListeners,
  messageListeners: _messageListeners,
  alarmListeners: _alarmListeners,
  cookieChangeListeners: _cookieChangeListeners,
  MOCK_COOKIES: MOCK_COOKIES,
  ALL_COOKIES: ALL_COOKIES
};

console.log('[Mock Chrome] APIs loaded with', ALL_COOKIES.length, 'mock cookies across', Object.keys(MOCK_COOKIES).length, 'domains');
