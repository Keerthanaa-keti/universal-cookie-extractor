# Cookie Vault v3 — UI test cases (options page)

Manual checks after loading the unpacked extension and opening the options page
(Extensions → Universal Cookie Extractor → Details → Extension options).

| # | Test Case | Steps | Expected | Status |
|---|-----------|-------|----------|--------|
| U1 | Options page loads | open options | Tabs: Connection / Servers / Tokens / Audit render; no console errors | ⬜ |
| U2 | Module SW registers | chrome://extensions → service worker | "service worker (Inactive/Active)"; no import errors | ⬜ |
| U3 | X25519 available | SW console: `await crypto.subtle.generateKey({name:'X25519'},true,['deriveBits'])` | resolves (Chrome ≥137) | ✅ (Chrome 151 verified live) |
| U4 | Save settings | fill Supabase URL + anon key, passphrase, save | "Settings saved"; passphrase persisted to `chrome.storage.local` only | ⬜ |
| U5 | Sign in | enter email+password, Sign in | "Signed in — refresh token stored, password cleared"; password field empties | ⬜ |
| U6 | Test connection | Test connection | "Connection OK — schema reachable" | ⬜ |
| U7 | Register server | Servers → paste public key + label + domains → Register | row appears in table with scope + key prefix | ⬜ |
| U8 | Rewrap now | Servers → Rewrap now | status shows synced N domains to M servers | ⬜ |
| U9 | Issue token | Tokens → pick server → Issue | `cvk_...` shown once in reveal box; row added (active badge) | ⬜ |
| U10 | Revoke token | Tokens → Revoke | badge → revoked; server can no longer read | ⬜ |
| U11 | Revoke server | Servers → Revoke | badge → revoked; its entry_keys + tokens disabled | ⬜ |
| U12 | Audit view | Audit → Refresh after a server read | recent read row(s) with server, domain, status, IP | ⬜ |
| U13 | Sync mode toggle | Connection → sync mode = selected_domains | domains textarea appears | ⬜ |
| U14 | Popup vault status | open popup | vault bar shows enabled/configured/last sync | ⬜ |
| U15 | Secret hygiene | after save, inspect `chrome.storage.sync` | contains URL/anon/mode only — NOT passphrase, NOT password, NOT refresh token | ⬜ |
