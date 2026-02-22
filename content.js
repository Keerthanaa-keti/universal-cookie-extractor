// Content script - injects cookie data into DOM for Claude in Chrome access
// Runs on every http/https page at document_idle

const DATA_ELEMENT_ID = '__cookie_extractor_data__';
const META_ELEMENT_ID = '__cookie_extractor_meta__';

function createOrUpdateElement(id, content) {
  let el = document.getElementById(id);
  if (!el) {
    el = document.createElement('div');
    el.id = id;
    el.style.display = 'none';
    el.setAttribute('aria-hidden', 'true');
    document.documentElement.appendChild(el);
  }
  el.textContent = typeof content === 'string' ? content : JSON.stringify(content);
  return el;
}

function updateDOM(data) {
  if (!data) {
    createOrUpdateElement(DATA_ELEMENT_ID, '{}');
    createOrUpdateElement(META_ELEMENT_ID, JSON.stringify({
      timestamp: new Date().toISOString(),
      totalCookies: 0,
      domainCount: 0,
      status: 'no_data'
    }));
    return;
  }

  createOrUpdateElement(DATA_ELEMENT_ID, JSON.stringify(data));
  createOrUpdateElement(META_ELEMENT_ID, JSON.stringify({
    timestamp: data.timestamp,
    totalCookies: data.totalCookies,
    domainCount: data.domainCount,
    domains: data.domains,
    status: 'ok'
  }));
}

// Initial load from storage
chrome.storage.local.get('cookieData', (result) => {
  updateDOM(result.cookieData || null);
});

// Auto-update when storage changes
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && changes.cookieData) {
    updateDOM(changes.cookieData.newValue);
  }
});

// Listen for refresh requests from page JavaScript (Claude in Chrome)
document.addEventListener('__cookie_extractor_refresh__', () => {
  chrome.runtime.sendMessage({ type: 'REQUEST_FRESH_COOKIES' }, () => {
    // After background refreshes, storage.onChanged will auto-update DOM
    // But also do an explicit read in case the data didn't change
    chrome.storage.local.get('cookieData', (result) => {
      updateDOM(result.cookieData || null);
    });
  });
});

// File upload bridge - allows Claude in Chrome to inject files into file inputs
// bypassing page CSP restrictions by using the extension's host_permissions
window.addEventListener('message', async (event) => {
  if (event.source !== window) return;
  if (!event.data || event.data.type !== '__cookie_extractor_upload_file__') return;

  const { url, inputSelector, fileName, mimeType } = event.data;
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Fetch failed: ${response.status}`);

    const blob = await response.blob();
    const file = new File([blob], fileName, { type: mimeType });
    const dt = new DataTransfer();
    dt.items.add(file);

    const input = document.querySelector(inputSelector);
    if (!input) throw new Error(`Input not found: ${inputSelector}`);

    input.files = dt.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));

    window.postMessage({
      type: '__cookie_extractor_upload_result__',
      success: true,
      fileSize: file.size,
      fileName: file.name
    }, '*');
  } catch (err) {
    window.postMessage({
      type: '__cookie_extractor_upload_result__',
      success: false,
      error: err.message
    }, '*');
  }
});
