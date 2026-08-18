# Cookie Vault v3 — Zero-Knowledge Scoped Broker

**Status:** Approved (design) · **Date:** 2026-08-18 · **Owner:** Kishore Natarajan
**Supersedes:** Cookie Vault v2.1.00 (`037b2b6`)

## 1. Problem & goal

Kishore runs many remote servers (Kiket fleet on EC2, Higgsfield/LinkedIn automation, etc.)
that need to reuse his logged-in browser sessions. The v2.1.00 Cookie Vault syncs cookies to
Supabase, but the way remote servers consume them is unsafe.

**Goal:** Let any number of remote servers use the owner's cookies **securely** — meaning:
least privilege per server, instant revocation, full read audit, and no single server able to
take over the account or read everything.

## 2. Why v2.1.00 is unsafe for remote servers

| # | Weakness (v2) | Consequence |
|---|---|---|
| 1 | Each server holds `COOKIE_VAULT_EMAIL` + `COOKIE_VAULT_PASSWORD` | One breach = full Supabase account takeover (write/delete all) |
| 2 | Each server holds the master symmetric `vault_key` | One breach = decrypt **all** cookies for **all** domains |
| 3 | No per-server scope | A LinkedIn worker can also read bank/email cookies |
| 4 | No revocation | Can't cut off one server without rotating the shared key everywhere |
| 5 | Reads are not logged | No visibility into who read what, when |
| 6 | `vault_key` stored in `chrome.storage.sync` | Decryption key rides to Google's cloud |
| 7 | `sync_mode: 'all'` uploads everything | Over-collection of sensitive cookies |
| 8 | `_authenticate()` `body.includes('refresh_token')` bug | Infinite recursion if password contains that substring (BUGS.md) |

Root cause: **secrets are shared, symmetric, and unscoped.**

## 3. Target architecture

Three pillars: **(A) envelope encryption (zero-knowledge)**, **(B) scoped per-server tokens
(never the password)**, **(C) a broker that enforces scope + rate-limit + audit**.

```
 Owner's Chrome (writer)                Supabase (storage, sees only ciphertext)
 ┌───────────────────────┐              ┌──────────────────────────────────────┐
 │ extension: collect     │  owner auth  │ cookie_entries  (ciphertext, iv)      │
 │ cookies → gen DEK      │─────────────▶│ entry_keys      (wrapped DEK / recip) │
 │ AES-GCM encrypt        │  (RLS: owner)│ server_keys     (X25519 pubkeys)      │
 │ wrap DEK → owner       │              │ access_tokens   (sha256 hashes)       │
 │ seal DEK → each server │              │ access_log / sync_log                 │
 └───────────────────────┘              └───────────────┬──────────────────────┘
                                                         │ service role (secret)
                                          ┌──────────────▼───────────────┐
   Remote server (reader)                 │ cookie-broker (Edge Function) │
   ┌─────────────────────────┐   cvk_tok  │ - verify token (hash lookup)  │
   │ private X25519 key (local│──────────▶ │ - check scope (allowed_domains)│
   │  only, never sent)       │  GET       │ - rate limit                   │
   │ scoped token cvk_...     │ /cookies   │ - return ciphertext+wrapped DEK│
   │ get_cookies(domain):     │◀────────── │ - log read to access_log       │
   │  unseal DEK → AES-GCM dec │  {entries} │ (NEVER sees DEK or plaintext)  │
   └─────────────────────────┘            └───────────────────────────────┘
```

**Zero-knowledge guarantee:** Supabase and the broker only ever hold ciphertext + DEKs that are
themselves sealed to a recipient public key. Neither can read cookie plaintext. Only a holder of
a recipient private key (a specific server, or the owner via passphrase) can decrypt.

## 4. Cryptography (VALIDATED — see §4.3)

### 4.1 Envelope scheme
- **Cookies → ciphertext:** random 256-bit **DEK** per entry; `AES-256-GCM(DEK, iv12, cookiesJSON)`.
- **DEK → owner:** `AES-256-GCM(K_owner, iv12, DEK)` where `K_owner = PBKDF2-HMAC-SHA256(passphrase, ownerSalt, 100000, 32)`. Lets the owner recover any entry with only the passphrase.
- **DEK → each server (ECIES):** X25519 ECDH to the server's public key → HKDF → AES-GCM wrap:
  1. ephemeral X25519 keypair `(ephPriv, ephPub)`
  2. `shared = X25519(ephPriv, serverPub)`
  3. `key = HKDF-SHA256(ikm=shared, salt=32×0x00, info="cookie-vault-v3/dek-wrap", len=32)`
  4. `wrap = AES-256-GCM(key, iv12, DEK)`; store `{epk: ephPub, iv, ct}`

### 4.2 Wire formats (base64; keys base64url of raw 32 bytes)
- server keypair: raw 32-byte X25519. Import via JWK `{kty:OKP,crv:X25519,x,d}` (JS/Node) or `from_*_bytes` (Python).
- `cookie_entries.ciphertext` = `AES-GCM(DEK)` base64; `.iv` base64.
- `entry_keys.wrapped_dek` (server) = JSON `{epk,iv,ct}`; (owner) = JSON `{salt,iv,ct}`.

### 4.3 Interop proof
`X25519 → HKDF-SHA256 → AES-256-GCM` uses **only built-in crypto** in all three runtimes
(Web Crypto `subtle`, Node `crypto`, Python `cryptography`). Cross-runtime seal/unseal verified
in every direction on 2026-08-18 (browser↔Python, browser↔Node, Node↔Python all PASS). **No
third-party crypto dependency.** Spike scripts archived in `test/interop/`.

## 5. Data model (Supabase)

New/changed tables (full DDL in `supabase/schema_v3.sql`):

- **`cookie_vaults`** (unchanged): one per user, holds `owner_salt` (new col) for the owner-wrap KDF.
- **`cookie_entries`** (changed): `ciphertext`, `iv` replace `encrypted_data/iv/salt`; keep
  `domain, cookie_count, has_auth_cookies, expires_at, synced_at, vault_id, user_id`. `unique(vault_id, domain)`.
- **`server_keys`** (new): `id, user_id, label, public_key, allowed_domains text[], revoked, created_at, revoked_at, last_used_at`.
- **`entry_keys`** (new): `id, entry_id→cookie_entries, recipient_type ('owner'|'server'), server_key_id→server_keys, wrapped_dek jsonb, created_at`. `unique(entry_id, recipient_type, server_key_id)`.
- **`access_tokens`** (new): `id, user_id, server_key_id, token_hash (sha256 hex), token_prefix, label, expires_at, revoked, created_at, last_used_at`.
- **`access_log`** (new): `id, user_id, server_key_id, token_id, domain, ip, user_agent, bytes, status, created_at`.
- **`sync_log`** (unchanged): owner write audit.

**RLS:** owner (`auth.uid() = user_id`) may CRUD own rows on every table. Servers have **no**
Supabase credentials. The broker uses the **service-role key** (function secret) to read/write,
bypassing RLS. `access_tokens.token_hash` never stores the raw token.

## 6. The broker (Supabase Edge Function `cookie-broker`, Deno/TypeScript)

Single function, routed by path. Auth: `Authorization: Bearer cvk_<token>`.

- **`GET /cookies?domain=<d>`**
  1. hash token (SHA-256 hex), look up `access_tokens` join `server_keys`; reject if missing/revoked/expired.
  2. scope: `<d>` must match `server_keys.allowed_domains` (exact, suffix, or `*`).
  3. rate-limit: reject if > N reads/min for this token (count recent `access_log`).
  4. fetch `cookie_entries` (user + domain match) + the `entry_keys` row for this `server_key_id`.
  5. return `{entries:[{domain, ciphertext, iv, wrapped_dek, synced_at, cookie_count}]}`.
  6. insert `access_log`; update `last_used_at`.
- **`GET /domains`** — list domains this token may read that have entries.
- **`GET /health`** — liveness (no auth).

The broker only moves ciphertext + a DEK **already sealed to the requesting server**. It cannot
decrypt. Deployed with `supabase functions deploy cookie-broker`; secrets set via
`supabase secrets set SERVICE_ROLE_KEY=... SUPABASE_URL=...`.

## 7. Server client libraries (v3)

Config (env): `COOKIE_VAULT_BROKER_URL`, `COOKIE_VAULT_TOKEN` (`cvk_...`),
`COOKIE_VAULT_PRIVATE_KEY` (base64url raw, or `COOKIE_VAULT_KEY_FILE` path, `chmod 600`).
**Removed:** email, password, master vault_key, service-role, direct Supabase access.

Python (`lib/python/cookie_vault.py`) & Node (`lib/node/cookie-vault.js`):
- `keygen(label)` → writes private key `~/.cookie-vault/<label>.key` (0600), prints public key to register.
- `get_cookies(domain, max_age_seconds=None)` → broker GET → unseal DEK (X25519) → AES-GCM decrypt → list.
- Ergonomic helpers kept: `cookie_header`, `requests_session`, `playwright_context` (Py);
  `getCookies`, `cookieHeader`, `loadIntoPuppeteer`, `playwrightContext`, `fetchOptions` (Node).
- `list_domains()` → broker `/domains`.
- A tiny CLI: `python -m cookie_vault keygen|get|domains`.

## 8. Extension changes (writer + owner management UI)

- **`crypto.js` → envelope:** `generateDEK`, `encryptWithDEK`, `wrapDEKForOwner`, `sealDEKForServer` (Web Crypto X25519, no libs).
- **`vault-sync.js`:** on sync, fetch non-revoked `server_keys`; per domain: gen DEK, encrypt, upsert `cookie_entries`, upsert `entry_keys` (owner + one per server). "Rewrap now" seals existing entries for newly added servers.
- **Secret hygiene:** move `vault_key` out of `chrome.storage.sync` → `chrome.storage.local` (never synced). Store the Supabase **refresh token**, not the password (login once). Default `sync_mode` stays `auth_only`; add an explicit domain allowlist so sensitive domains never leave.
- **Options page (`vault-settings.html`) tabs:** *Connection* (Supabase, owner login, vault key), *Servers* (register public key + label + `allowed_domains`; revoke; rewrap), *Tokens* (issue `cvk_` shown once, rotate, revoke), *Audit* (recent `access_log`).

## 9. Owner workflow (how a server gets access)

1. **On server:** `python -m cookie_vault keygen --label kiket-ec2` → writes private key locally, prints public key.
2. **Owner (extension → Servers):** paste public key + label + `allowed_domains` (e.g. `linkedin.com, higgsfield.ai`) → creates `server_keys` row.
3. **Owner (extension → Tokens):** "Issue token" → `cvk_...` shown **once** → give to server.
4. Extension rewraps entries for the new server on next sync (or "rewrap now").
5. **On server:** set `COOKIE_VAULT_BROKER_URL`, `COOKIE_VAULT_TOKEN`, key file → `vault.get_cookies('linkedin.com')` works, zero-knowledge.
6. **Revoke** anytime: Servers → Revoke (drops `entry_keys` + revokes tokens). Access dies immediately.

## 10. Threat model (what a compromised server yields)

| Attacker capability | v2.1.00 | v3 |
|---|---|---|
| Read all cookies (all domains) | ✅ yes | ❌ only its `allowed_domains` |
| Take over Supabase account | ✅ yes (password) | ❌ no password, no account access |
| Persist after revocation | ✅ (shared key) | ❌ token revoke kills it instantly |
| Read historical/other data | ✅ | ❌ scoped + no direct DB access |
| Go undetected | ✅ (no read log) | ❌ every read in `access_log` |
| Supabase/DB breach reveals cookies | ✅ (if key leaks) | ❌ zero-knowledge ciphertext only |

Residual risk (inherent): a live, non-revoked, scoped server necessarily obtains **plaintext for
its own domains** while it runs — it must, to use the cookies. v3 minimizes blast radius, enables
instant revocation, and makes every access auditable.

## 11. Phased roadmap

| Phase | Deliverable | Gate |
|---|---|---|
| 0 | Safety: git identity, `.gitignore` (keys/secrets), spike archived, this spec | committed |
| 1 | `supabase/schema_v3.sql` (tables, RLS, indexes) + migration notes | SQL lints |
| 2 | Envelope crypto: `crypto.js` (ext), `envelope.py`, `envelope.js` + interop test in `test/interop/` | 3-way interop passes in CI script |
| 3 | Broker `supabase/functions/cookie-broker/index.ts` + deploy doc | deno check |
| 4 | Client v3: `cookie_vault.py`, `cookie-vault.js`, keygen + CLI | unit + local broker mock |
| 5 | Extension: `vault-sync.js` envelope + rewrap; options-page Servers/Tokens/Audit; secret hygiene | loads, sync round-trips |
| 6 | Docs, `README`, `test-cases/`, `ROADMAP.html`, version bump, commit + push | all green |
| 7 | **Provisioning (with owner):** create free Supabase project, apply schema, deploy broker, set secrets, register first server, e2e test | live e2e |

## 12. Non-goals (YAGNI)
- Multi-user / team sharing (single owner).
- Cookie value rotation at source (re-login) — out of scope; revocation is via tokens.
- A hosted management dashboard beyond the extension options page (a CLI covers headless).
