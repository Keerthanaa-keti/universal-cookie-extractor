# Cookie Vault v3 — server clients

Zero-knowledge cookie access for remote servers. A server reads the owner's
browser cookies **for its allowed domains only**, holding nothing that could
take over the account.

## What a server holds
| Secret | What it is | If stolen |
|--------|-----------|-----------|
| `COOKIE_VAULT_TOKEN` (`cvk_…`) | scoped, revocable API token | revoke it in the extension; access dies |
| X25519 private key (key file) | this server's decryption key | only decrypts this server's scoped cookies |

**Never on a server:** the owner password, the master vault key, or any Supabase key.

## Setup (per server)

```bash
# 1. Generate this server's keypair (private key stays here, 0600)
python -m cookie_vault keygen --label my-server        # Python
node cookie-vault.js keygen --label my-server          # or Node (key files are interchangeable)

# 2. In the extension → Servers: paste the printed public key + label + allowed domains
#    In the extension → Tokens: issue a token (shown once)

# 3. Configure this server
export COOKIE_VAULT_BROKER_URL="https://<ref>.supabase.co/functions/v1/cookie-broker"
export COOKIE_VAULT_TOKEN="cvk_..."
export COOKIE_VAULT_KEY_FILE="$HOME/.cookie-vault/my-server.key"
```

## Python

```python
from cookie_vault import CookieVault
vault = CookieVault()

cookies = vault.get_cookies("linkedin.com")          # list of cookie dicts
headers = vault.cookie_header("linkedin.com")         # {'Cookie': 'a=1; b=2'}
session = vault.requests_session("linkedin.com")      # requests.Session, cookies loaded
# Playwright: ctx = await vault.playwright_context(browser, "linkedin.com")
domains = vault.list_domains()                        # what this server may read
```

Install: `pip install -r lib/python/requirements.txt`

## Node (>= 18, ESM)

```js
import { CookieVault } from './cookie-vault.js';
const vault = new CookieVault();

const cookies = await vault.getCookies('linkedin.com');
const headers = await vault.cookieHeader('linkedin.com');
await vault.loadIntoPuppeteer(page, 'linkedin.com');
const ctx = await vault.playwrightContext(browser, 'linkedin.com');
```

## Look like the real browser (not just cookies)

Cookies alone are often not enough — sites also fingerprint the client (User-Agent,
client hints, TLS/JA3). The extension captures a **browser profile** (UA + client
hints + language + timezone) into the vault. The clients replay it:

```python
vault.get_profile()                       # {'user_agent': 'Mozilla/5.0…Chrome/151…', …}
vault.browser_headers("linkedin.com")      # profile headers + Cookie header
session = vault.impersonate_session("linkedin.com")   # curl_cffi: Chrome TLS(JA3) + UA + cookies
r = session.get("https://www.linkedin.com/…")          # looks like your Chrome, at TLS + header level
```

- `requests_session()` sets the browser headers but uses OpenSSL TLS (fine for soft sites).
- `impersonate_session()` (needs `curl_cffi`) matches **Chrome's JA3/JA4** too — use it for
  strong anti-bot sites. Pin a target with `COOKIE_VAULT_IMPERSONATE=chrome131` if needed.
- Playwright/Puppeteer contexts also get the UA, locale, and timezone from the profile.

### Test that a session actually works
```bash
# fetch a URL as the browser+session; PASS if it looks logged in (`contains` present only when authed)
python -m cookie_vault verify linkedin.com https://www.linkedin.com/feed/ --contains '"plainId"'
python -m cookie_vault profile         # show the captured browser profile
```
Verified live on 2026-08-24: on the Kiket EC2 box, the stealth session presents a real
Chrome JA3 + the captured UA (not the `python-requests` bot signature). See
`test/live/fingerprint_test.py`.

> **For claude.ai / OpenAI and other AI services, prefer their official APIs** (Anthropic
> API, OpenAI API). Driving the web apps via session cookies + TLS impersonation is fragile
> and against those services' terms; the APIs are stable and need none of this.

## Notes
- `get_cookies(domain, max_age_seconds=N)` rejects entries synced longer than N seconds ago.
- Every read is logged in the vault's `access_log` (owner sees it in the extension Audit tab).
- Requesting a domain outside your scope returns HTTP 403; the broker never leaks it.
- See `docs/superpowers/specs/2026-08-18-cookie-vault-v3-design.md` for the full threat model.
