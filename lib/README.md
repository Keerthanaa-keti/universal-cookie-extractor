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

## Notes
- `get_cookies(domain, max_age_seconds=N)` rejects entries synced longer than N seconds ago.
- Every read is logged in the vault's `access_log` (owner sees it in the extension Audit tab).
- Requesting a domain outside your scope returns HTTP 403; the broker never leaks it.
- See `docs/superpowers/specs/2026-08-18-cookie-vault-v3-design.md` for the full threat model.
