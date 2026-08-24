# Cookie Vault — Multi-user Google Sign-in: implementation runbook

> Status: **planned, not started.** Deferred 2026-08-25 because Google Cloud Console
> needs Kishore's passkey/biometric (a human-present step). This runbook has every
> value + command so a future session can drive it end to end once Kishore is present
> for the one console auth.

## Why (vision)
Cookie Vault is a **multi-user product**: people connect their browser sessions and
grant AI agents / remote servers scoped, revocable, audited access to act as them.
So auth = real multi-user login = **Google OAuth** (Supabase Google provider) on the
**dedicated `cookie-vault` project** (NOT hosted inside leadership-hiring). Everything
else already built (zero-knowledge per user, per-agent scoped tokens, broker, audit,
RLS by `auth.uid()`) is already correct for multi-tenant. Only the login changes.

## Known values (verified)
| Thing | Value |
|---|---|
| Supabase project (vault) | `cookie-vault`, ref **`apjfsrnbykcezznjhhdq`** |
| Supabase URL | `https://apjfsrnbykcezznjhhdq.supabase.co` |
| Google callback (per project) | `https://apjfsrnbykcezznjhhdq.supabase.co/auth/v1/callback` |
| Extension ID (unpacked, this repo) | `lpehchphbciibpaihecfjpmnminlldeh` |
| Extension OAuth redirect | `https://lpehchphbciibpaihecfjpmnminlldeh.chromiumapp.org/` |
| Google Cloud project (chosen) | HyperVerge **`734233405092`** (same as leadership-hiring) |
| Existing LH Google client | `734233405092-kcgkevt9du3blr0hltn…` (reuse OR make a new "Cookie Vault" client) |
| Supabase Management PAT | `~/.cookie-vault-pat` (Kishore can revoke anytime) |
| Broker URL | `https://apjfsrnbykcezznjhhdq.supabase.co/functions/v1/cookie-broker` |

## Phase A — Google Cloud (needs Kishore's passkey once; then I drive)
Console → project `734233405092` → **APIs & Services → Credentials**.
1. **Create Credentials → OAuth client ID**. Application type: **Web application**. Name: `Cookie Vault`.
2. **Authorized redirect URIs** → add `https://apjfsrnbykcezznjhhdq.supabase.co/auth/v1/callback`.
   (No authorized JS origins needed for the Supabase server-side authorize flow.)
3. **Create** → copy **Client ID** + **Client secret**.
   - *Alternative (faster):* open the existing LH client and just ADD the redirect URI above; reuse its id + secret. Downside: shares the project's consent-screen branding.
4. Consent screen is already configured for this project (LH uses it). If it's "External/Testing", add `kishore@hyperverge.co` as a test user (scopes are only `email profile openid` = non-sensitive, so no Google verification needed to start).

## Phase B — Supabase config (Management API; secret goes Google→Supabase, not chat)
Prefer: Kishore pastes the **client secret** directly into Supabase Studio → Auth →
Providers → Google. Otherwise set via API:
```bash
TOKEN=$(cat ~/.cookie-vault-pat)
REF=apjfsrnbykcezznjhhdq
# 1) enable Google provider
curl -s -X PATCH "https://api.supabase.com/v1/projects/$REF/config/auth" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "User-Agent: curl/8" \
  -d '{"external_google_enabled":true,"external_google_client_id":"<CLIENT_ID>","external_google_secret":"<SECRET>"}'
# 2) allow the extension redirect (keep any existing entries; comma-separated, supports **)
curl -s -X PATCH "https://api.supabase.com/v1/projects/$REF/config/auth" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "User-Agent: curl/8" \
  -d '{"uri_allow_list":"https://lpehchphbciibpaihecfjpmnminlldeh.chromiumapp.org/**"}'
```
Verify: `GET /v1/projects/$REF/config/auth` → `external_google_enabled:true`, allow list set.

## Phase C — Extension: Google sign-in (code)
Sign-in runs in the **options page** (has a user gesture; the service worker cannot call
`launchWebAuthFlow`). The SW keeps using the stored refresh token for background sync.
1. `manifest.json`: add `"identity"` to `permissions`. Bump version (→ 3.1.0, new-feature; ASK first).
2. `vault-settings.js` — replace the email/password Connect with a **Continue with Google** button:
   ```js
   const redirectUrl = chrome.identity.getRedirectURL(); // https://<id>.chromiumapp.org/
   const cfg = await getConfig();
   const authUrl = `${cfg.supabase_url}/auth/v1/authorize?provider=google`
                 + `&redirect_to=${encodeURIComponent(redirectUrl)}`;
   const resp = await chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true });
   const hash = new URL(resp).hash.slice(1);           // access_token=…&refresh_token=…&expires_in=…
   const p = new URLSearchParams(hash);
   await chrome.storage.local.set({ vault_refresh_token: p.get('refresh_token') });
   // then enable sync + first sync (reuse the current connect flow tail)
   ```
   Keep email/password under **Advanced** as a fallback, or remove it.
3. The existing writer (`vault-sync.js`) works unchanged — owner = the Google user; it
   authenticates with the stored refresh token and writes via RLS.

## Phase D — Owner migration (Kishore's Google identity becomes owner)
After the first Google sign-in:
1. Get the Google user's `user_id` (from the session, or `auth.users` by email in cookie-vault).
2. Re-register **kiket-ec2** under that user_id (scope `linkedin.com, higgsfield.ai`) + issue a new `cvk_` token (service_role, like `test/live/register_and_seed.mjs`).
3. Update the Kiket box: `~/cookie-vault/kiket.env` → new `COOKIE_VAULT_TOKEN` (broker URL unchanged).
4. Re-sync from the extension → cookies + browser_profile land under the Google user, sealed to Kiket.
5. Optional: delete the old `vault-owner@cookie-vault.local` user + its rows.

## Phase E — Verify
1. Extension: **Continue with Google** → vault created under the Google user → sync.
2. Kiket: `python -m cookie_vault get linkedin.com` (new token) → real cookies decrypt.
3. `test/live/fingerprint_test.py` + `verify_session` still pass.

## Later, for a true public product
- Dedicated Google Cloud project + **verified OAuth consent screen** ("Cookie Vault" branding).
- Publish the extension to the **Chrome Web Store** → it gets a *different, stable* extension ID.
  The `chromiumapp.org` redirect changes → update the Supabase allow list to the store ID
  (support both the dev `lpehc…` and the store ID during transition).
- Smooth agent onboarding (one-line install that keygens + registers + gets a scoped token).

## Blockers / notes
- **Phase A needs Kishore present** for the Google account passkey/biometric.
- Keep the **client secret** out of chat — paste it into Supabase Studio directly.
- The unpacked extension ID (`lpehc…`) is stable for this folder path; the Web Store ID will differ.
