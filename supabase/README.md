# Cookie Vault v3 — Supabase setup

Zero-knowledge scoped broker backend. Free plan is enough.

## 1. Create the project
Create a **new dedicated** Supabase project (smallest blast radius). Note its
`Project URL` and, from *Project Settings → API*, the `anon` key and the
`service_role` key. **The service_role key is a master credential — it goes only
into the broker Edge Function's secrets, never onto a server and never into git.**

## 2. Apply the schema
```bash
# with the Supabase CLI linked to the project:
supabase db push --file supabase/schema_v3.sql
# or paste supabase/schema_v3.sql into the SQL editor and run it.
```
Creates: `cookie_vaults, server_keys, cookie_entries, entry_keys, access_tokens,
access_log, sync_log` with RLS (owner-only) + indexes. Validated against Postgres 16.

## 3. Deploy the broker
```bash
supabase functions deploy cookie-broker --no-verify-jwt
supabase secrets set SUPABASE_URL="https://<ref>.supabase.co" \
                     SERVICE_ROLE_KEY="<service_role key>"
```
`--no-verify-jwt` because servers authenticate with their own `cvk_` token (checked
inside the function), not a Supabase JWT. The function uses the service_role key
server-side to read/write, bypassing RLS. It only ever returns ciphertext + a DEK
already sealed to the requesting server — it cannot decrypt cookies.

## 4. Owner (extension) config
In the extension options page → *Connection*: set the Project URL + anon key, sign
in once (a dedicated vault account is recommended), and set the vault passphrase.

## 5. Register a server → issue a token → use it
See `docs/superpowers/specs/2026-08-18-cookie-vault-v3-design.md` §9 and
`lib/python/README` / `lib/node/README` for the per-server flow.

## Roles recap
| Who | Credential | Can decrypt cookies? |
|-----|-----------|----------------------|
| Owner (extension/CLI) | Supabase login + vault passphrase | yes (own vault) |
| Broker (Edge Function) | service_role key (secret) | **no** (zero-knowledge) |
| Server (reader) | `cvk_` token + own X25519 private key | only its `allowed_domains` |
| Supabase / DB thief | — | **no** (ciphertext only) |
