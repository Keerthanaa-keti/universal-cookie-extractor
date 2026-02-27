document.addEventListener('DOMContentLoaded', async function() {
  const elements = {
    vaultEnabled: document.getElementById('vaultEnabled'),
    supabaseUrl: document.getElementById('supabaseUrl'),
    supabaseAnonKey: document.getElementById('supabaseAnonKey'),
    vaultEmail: document.getElementById('vaultEmail'),
    vaultPassword: document.getElementById('vaultPassword'),
    vaultKey: document.getElementById('vaultKey'),
    syncMode: document.getElementById('syncMode'),
    selectedDomains: document.getElementById('selectedDomains'),
    selectedDomainsField: document.getElementById('selectedDomainsField'),
    syncInterval: document.getElementById('syncInterval'),
    saveBtn: document.getElementById('saveBtn'),
    testBtn: document.getElementById('testBtn'),
    syncNowBtn: document.getElementById('syncNowBtn'),
    statusBar: document.getElementById('statusBar'),
    syncDot: document.getElementById('syncDot'),
    syncStatusText: document.getElementById('syncStatusText')
  };

  function showStatus(message, type = 'info') {
    elements.statusBar.textContent = message;
    elements.statusBar.className = `status-bar ${type}`;
    if (type === 'success') {
      setTimeout(() => { elements.statusBar.className = 'status-bar'; }, 3000);
    }
  }

  // Show/hide selected domains field
  elements.syncMode.addEventListener('change', () => {
    elements.selectedDomainsField.style.display =
      elements.syncMode.value === 'selected_domains' ? 'block' : 'none';
  });

  // Load saved settings
  async function loadSettings() {
    const sync = await chrome.storage.sync.get({
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
      vault_password: '',
      vault_last_sync: null,
      vault_sync_error: null
    });

    elements.vaultEnabled.checked = sync.vault_enabled;
    elements.supabaseUrl.value = sync.supabase_url;
    elements.supabaseAnonKey.value = sync.supabase_anon_key;
    elements.vaultKey.value = sync.vault_key;
    elements.syncMode.value = sync.sync_mode;
    elements.selectedDomains.value = sync.selected_domains.join('\n');
    elements.syncInterval.value = sync.sync_interval_minutes;
    elements.vaultEmail.value = local.vault_email;
    elements.vaultPassword.value = local.vault_password;

    elements.selectedDomainsField.style.display =
      sync.sync_mode === 'selected_domains' ? 'block' : 'none';

    updateSyncStatus(sync, local);
  }

  function updateSyncStatus(sync, local) {
    if (!sync.vault_enabled) {
      elements.syncDot.className = 'sync-dot disabled';
      elements.syncStatusText.textContent = 'Vault sync disabled';
    } else if (!sync.supabase_url || !sync.vault_key) {
      elements.syncDot.className = 'sync-dot disconnected';
      elements.syncStatusText.textContent = 'Not configured';
    } else if (local.vault_sync_error) {
      elements.syncDot.className = 'sync-dot disconnected';
      elements.syncStatusText.textContent = `Error: ${local.vault_sync_error}`;
    } else if (local.vault_last_sync) {
      elements.syncDot.className = 'sync-dot connected';
      const ago = timeSince(new Date(local.vault_last_sync));
      elements.syncStatusText.textContent = `Connected - last sync ${ago}`;
    } else {
      elements.syncDot.className = 'sync-dot connected';
      elements.syncStatusText.textContent = 'Connected - no sync yet';
    }
  }

  function timeSince(date) {
    const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  }

  // Save settings
  elements.saveBtn.addEventListener('click', async () => {
    const selectedDomains = elements.selectedDomains.value
      .split('\n')
      .map(d => d.trim())
      .filter(d => d.length > 0);

    await chrome.storage.sync.set({
      vault_enabled: elements.vaultEnabled.checked,
      supabase_url: elements.supabaseUrl.value.replace(/\/$/, ''),
      supabase_anon_key: elements.supabaseAnonKey.value.trim(),
      vault_key: elements.vaultKey.value,
      sync_mode: elements.syncMode.value,
      selected_domains: selectedDomains,
      sync_interval_minutes: parseInt(elements.syncInterval.value) || 5
    });

    await chrome.storage.local.set({
      vault_email: elements.vaultEmail.value.trim(),
      vault_password: elements.vaultPassword.value
    });

    // Notify background to update alarm
    chrome.runtime.sendMessage({ type: 'VAULT_SETTINGS_UPDATED' });

    showStatus('Settings saved', 'success');
    loadSettings(); // Refresh status display
  });

  // Test connection
  elements.testBtn.addEventListener('click', async () => {
    const url = elements.supabaseUrl.value.replace(/\/$/, '');
    const key = elements.supabaseAnonKey.value.trim();
    const email = elements.vaultEmail.value.trim();
    const password = elements.vaultPassword.value;

    if (!url || !key || !email || !password) {
      showStatus('Fill in Supabase URL, anon key, email, and password first', 'error');
      return;
    }

    showStatus('Testing connection...', 'info');

    try {
      // Test auth
      const authRes = await fetch(`${url}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: { 'apikey': key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!authRes.ok) {
        const text = await authRes.text();
        throw new Error(`Auth failed (${authRes.status}): ${text}`);
      }

      const authData = await authRes.json();

      // Test table access
      const tableRes = await fetch(`${url}/rest/v1/cookie_vaults?select=id&limit=1`, {
        headers: {
          'apikey': key,
          'Authorization': `Bearer ${authData.access_token}`
        }
      });

      if (!tableRes.ok) {
        throw new Error(`Table access failed (${tableRes.status}). Run schema.sql first.`);
      }

      showStatus(`Connection successful! User: ${authData.user.email}`, 'success');
    } catch (err) {
      showStatus(`Connection failed: ${err.message}`, 'error');
    }
  });

  // Sync now
  elements.syncNowBtn.addEventListener('click', async () => {
    showStatus('Triggering sync...', 'info');
    chrome.runtime.sendMessage({ type: 'VAULT_SYNC_NOW' }, (response) => {
      if (chrome.runtime.lastError) {
        showStatus('Failed to trigger sync: ' + chrome.runtime.lastError.message, 'error');
      } else if (response && response.success) {
        showStatus(`Sync complete: ${response.domains} domains, ${response.cookies} cookies`, 'success');
        loadSettings();
      } else if (response) {
        showStatus(`Sync issue: ${response.reason || 'unknown'}`, 'error');
      }
    });
  });

  loadSettings();
});
