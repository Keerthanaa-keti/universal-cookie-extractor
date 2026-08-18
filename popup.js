document.addEventListener('DOMContentLoaded', function () {
  const $ = (id) => document.getElementById(id);
  const loadCookiesBtn = $('loadCookiesBtn');
  const extractAllBtn = $('extractAllBtn');
  const extractSelectedBtn = $('extractSelectedBtn');
  const copyBtn = $('copyBtn');
  const clearBtn = $('clearBtn');
  const selectAllBtn = $('selectAllBtn');
  const selectAuthBtn = $('selectAuthBtn');
  const selectSessionBtn = $('selectSessionBtn');
  const selectNoneBtn = $('selectNoneBtn');
  const filterInput = $('filterInput');
  const cookieSelector = $('cookieSelector');
  const cookieList = $('cookieList');
  const output = $('output');
  const status = $('status');
  const currentSite = $('currentSite');
  const siteMeta = $('siteMeta');
  const selectedCount = $('selectedCount');
  const resultCard = $('resultCard');
  const resultMeta = $('resultMeta');
  const vaultBar = $('vaultBar');
  const vaultDot = $('vaultDot');
  const vaultStatusText = $('vaultStatusText');

  let currentDomain = '';
  let currentUrl = '';
  let availableCookies = [];

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---- Vault status pill ----
  chrome.runtime.sendMessage({ type: 'GET_VAULT_STATUS' }, (s) => {
    if (chrome.runtime.lastError || !s) return;
    vaultBar.style.display = 'inline-flex';
    if (!s.enabled) { vaultDot.className = 'led off'; vaultStatusText.textContent = 'Vault off'; }
    else if (!s.configured) { vaultDot.className = 'led off'; vaultStatusText.textContent = 'Set up vault'; }
    else if (s.lastError) { vaultDot.className = 'led error'; vaultStatusText.textContent = 'Sync error'; }
    else if (s.lastSync) { vaultDot.className = 'led on'; vaultStatusText.textContent = `Synced ${timeSince(new Date(s.lastSync))}`; }
    else { vaultDot.className = 'led on'; vaultStatusText.textContent = 'Vault ready'; }
  });
  vaultBar.addEventListener('click', (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });

  function timeSince(date) {
    const s = Math.floor((Date.now() - date.getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  function showStatus(message, type = 'info') {
    status.textContent = message;
    status.className = `toast ${type} show`;
  }
  function hideStatus() { status.className = 'toast info'; }

  function showOutput(data, meta) {
    output.value = data;
    resultMeta.textContent = meta;
    resultCard.style.display = 'flex';
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  function hideOutput() { resultCard.style.display = 'none'; output.value = ''; }

  function getDomainFromUrl(url) { try { return new URL(url).hostname; } catch { return 'unknown'; } }

  function isAuthCookie(cookie) {
    const p = ['auth', 'session', 'token', 'login', 'user', 'csrf', 'xsrf', 'li_at', 'c_user', 'xs', 'fr', 'sb', 'datr',
      'auth_token', 'twid', 'ct0', 'sessionid', 'csrftoken', 'sid', 'hsid', 'ssid', 'apisid', 'sapisid',
      'jsessionid', 'phpsessid', 'asp.net_sessionid'];
    const n = cookie.name.toLowerCase();
    return p.some((x) => n.includes(x));
  }

  function flagChips(cookie) {
    const f = [];
    if (cookie.secure) f.push('Secure');
    if (cookie.httpOnly) f.push('HttpOnly');
    f.push(cookie.session ? 'Session' : 'Persistent');
    if (cookie.sameSite && cookie.sameSite !== 'unspecified') f.push(cookie.sameSite);
    return f.map((x) => `<span class="flag">${esc(x)}</span>`).join('');
  }

  function updateSelectedCount() {
    const n = cookieList.querySelectorAll('.cookie-checkbox:checked').length;
    selectedCount.textContent = n;
    extractSelectedBtn.disabled = n === 0;
    extractSelectedBtn.textContent = n ? `Extract ${n}` : 'Extract';
  }

  function renderCookieList(cookies) {
    const filter = filterInput.value.toLowerCase();
    const filtered = cookies.filter((c) => !filter || c.name.toLowerCase().includes(filter) || c.domain.toLowerCase().includes(filter));
    // auth cookies first, then alphabetical
    filtered.sort((a, b) => (isAuthCookie(b) - isAuthCookie(a)) || a.name.localeCompare(b.name));

    if (filtered.length === 0) { cookieList.innerHTML = '<div class="empty">No cookies match.</div>'; updateSelectedCount(); return; }

    cookieList.innerHTML = filtered.map((cookie, i) => {
      const idx = availableCookies.indexOf(cookie);
      const auth = isAuthCookie(cookie);
      return `<label class="cookie-item${auth ? ' is-auth' : ''}" style="animation-delay:${Math.min(i * 18, 260)}ms">
        <input type="checkbox" class="cookie-checkbox" data-cookie-index="${idx}" ${auth ? 'checked' : ''}>
        <div class="cookie-info">
          <div class="cookie-line">
            <span class="cookie-name">${esc(cookie.name)}</span>
            ${auth ? '<span class="badge auth">Auth</span>' : ''}
          </div>
          <div class="cookie-domain">${esc(cookie.domain)}${esc(cookie.path || '')}</div>
          <div class="cookie-flags">${flagChips(cookie)}</div>
        </div>
      </label>`;
    }).join('');
    updateSelectedCount();
  }

  function updateCookieSelection(selector) {
    cookieList.querySelectorAll('.cookie-checkbox').forEach((cb) => {
      const cookie = availableCookies[parseInt(cb.dataset.cookieIndex)];
      if (selector === 'all') cb.checked = true;
      else if (selector === 'none') cb.checked = false;
      else if (selector === 'auth') cb.checked = isAuthCookie(cookie);
      else if (selector === 'session') cb.checked = cookie.session;
    });
    updateSelectedCount();
  }

  function flashChip(btn) {
    [selectAllBtn, selectAuthBtn, selectSessionBtn, selectNoneBtn].forEach((b) => b.classList.remove('is-on'));
    btn.classList.add('is-on');
  }

  // update counter on any manual checkbox toggle
  cookieList.addEventListener('change', (e) => { if (e.target.classList.contains('cookie-checkbox')) updateSelectedCount(); });

  // ---- current tab ----
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      currentUrl = tabs[0].url;
      currentDomain = getDomainFromUrl(currentUrl);
      currentSite.textContent = currentDomain;
    } else {
      currentSite.textContent = 'No active tab';
      loadCookiesBtn.disabled = true;
    }
  });

  // ---- scan this site ----
  loadCookiesBtn.addEventListener('click', async () => {
    if (!currentDomain) { showStatus('Open a website first.', 'error'); return; }
    try {
      loadCookiesBtn.disabled = true;
      const cookies = await chrome.cookies.getAll({ domain: currentDomain });
      const parent = await chrome.cookies.getAll({ domain: '.' + currentDomain.replace(/^www\./, '') });
      availableCookies = [...cookies, ...parent].filter((c, i, self) =>
        i === self.findIndex((x) => x.name === c.name && x.domain === c.domain));
      availableCookies.forEach((c) => { c.session = !c.expirationDate; });

      if (availableCookies.length === 0) {
        showStatus(`No cookies for ${currentDomain}. Try logging in first.`, 'error');
        cookieSelector.style.display = 'none';
      } else {
        const authN = availableCookies.filter(isAuthCookie).length;
        siteMeta.innerHTML = `<b>${authN}</b> auth · ${availableCookies.length} total`;
        cookieSelector.style.display = 'block';
        renderCookieList(availableCookies);
        loadCookiesBtn.textContent = 'Rescan';
        hideStatus();
      }
    } catch (err) {
      showStatus(`Error: ${err.message}`, 'error');
    } finally {
      loadCookiesBtn.disabled = false;
    }
  });

  // ---- extract selected ----
  extractSelectedBtn.addEventListener('click', () => {
    const checked = cookieList.querySelectorAll('.cookie-checkbox:checked');
    if (checked.length === 0) { showStatus('Select at least one cookie.', 'error'); return; }
    const selected = [...checked].map((cb) => {
      const c = availableCookies[parseInt(cb.dataset.cookieIndex)];
      return { name: c.name, value: c.value, domain: c.domain, path: c.path, secure: c.secure,
        httpOnly: c.httpOnly, sameSite: c.sameSite, expirationDate: c.expirationDate, session: c.session };
    });
    const data = { timestamp: new Date().toISOString(), extractionType: 'selected_cookies', currentUrl,
      domain: currentDomain, totalAvailable: availableCookies.length, selectedCount: selected.length, cookies: selected };
    const json = JSON.stringify(data, null, 2);
    showOutput(json, `${selected.length} cookies · ${fmtBytes(json.length)}`);
    hideStatus();
  });

  // ---- extract all sites ----
  extractAllBtn.addEventListener('click', async () => {
    try {
      extractAllBtn.disabled = true;
      showStatus('Reading all cookies…', 'info');
      const all = await chrome.cookies.getAll({});
      if (all.length === 0) { showStatus('No cookies in browser.', 'error'); return; }
      const byDomain = {};
      all.forEach((c) => {
        (byDomain[c.domain] ||= []).push({ name: c.name, value: c.value, domain: c.domain, path: c.path,
          secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, expirationDate: c.expirationDate, session: !c.expirationDate });
      });
      const data = { timestamp: new Date().toISOString(), extractionType: 'all_sites', totalCookies: all.length,
        domainCount: Object.keys(byDomain).length, domains: Object.keys(byDomain).sort(), cookiesByDomain: byDomain };
      const json = JSON.stringify(data, null, 2);
      showOutput(json, `${all.length} cookies · ${Object.keys(byDomain).length} sites · ${fmtBytes(json.length)}`);
      hideStatus();
    } catch (err) {
      showStatus(`Error: ${err.message}`, 'error');
    } finally {
      extractAllBtn.disabled = false;
    }
  });

  function fmtBytes(n) { return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`; }

  selectAllBtn.addEventListener('click', () => { updateCookieSelection('all'); flashChip(selectAllBtn); });
  selectAuthBtn.addEventListener('click', () => { updateCookieSelection('auth'); flashChip(selectAuthBtn); });
  selectSessionBtn.addEventListener('click', () => { updateCookieSelection('session'); flashChip(selectSessionBtn); });
  selectNoneBtn.addEventListener('click', () => { updateCookieSelection('none'); flashChip(selectNoneBtn); });

  filterInput.addEventListener('input', () => { if (availableCookies.length) renderCookieList(availableCookies); });

  copyBtn.addEventListener('click', async () => {
    if (!output.value) { showStatus('Nothing to copy yet.', 'error'); return; }
    try {
      await navigator.clipboard.writeText(output.value);
      const orig = copyBtn.textContent; copyBtn.textContent = 'Copied ✓';
      setTimeout(() => { copyBtn.textContent = orig; }, 1400);
    } catch (err) {
      output.closest('details').open = true; output.focus(); output.select();
      showStatus(`Clipboard blocked — press Cmd+C.`, 'error');
    }
  });

  clearBtn.addEventListener('click', () => { hideOutput(); hideStatus(); });
});
