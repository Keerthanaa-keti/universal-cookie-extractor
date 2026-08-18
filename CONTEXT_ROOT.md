# Cookie Extractor & Voice Pipeline — Context Root

> Last updated: 2026-08-18

## Status: Active — Cookie Vault v3 built (Phases 0–6), provisioning pending

Chrome extension for cookie extraction + **Cookie Vault v3** (zero-knowledge,
per-server scoped cookie access for remote servers) + voice-clone video pipeline.

## Cookie Vault v3 (current focus)

Zero-knowledge envelope encryption (X25519 → HKDF → AES-256-GCM). Servers hold only
a scoped `cvk_` token + their own X25519 private key — no password, no master key.
A Supabase Edge Function broker enforces per-domain scope, rate limits, and audits
every read. See `docs/architecture/ROADMAP.html` and the design spec.

| Path | Purpose |
|------|---------|
| `docs/superpowers/specs/2026-08-18-cookie-vault-v3-design.md` | Full design + threat model |
| `docs/architecture/ROADMAP.html` | Canonical visual roadmap (open in browser) |
| `supabase/schema_v3.sql` | Tables + RLS (validated) |
| `supabase/functions/cookie-broker/index.ts` | Zero-knowledge broker |
| `lib/shared/vault-crypto.mjs` | Envelope crypto (extension + Node) |
| `lib/python/` · `lib/node/` | Server clients (v3) |
| `vault-sync.js` · `background.js` | Extension writer (module SW) |
| `vault-settings.html/js` | Owner console (Connection/Servers/Tokens/Audit) |
| `test/run_all.sh` | All checks (interop + e2e + full loop): 24 green |

**Next:** Phase 7 — create a new free Supabase project, apply schema, deploy the
broker, register the first server, issue a token, live e2e. Needs the owner's
Supabase account.

## Other entry points
| Path | Purpose |
|------|---------|
| `content.js` | Content script (exposes cookies to Claude-in-Chrome) |
| `explorer.html` | Cookie explorer UI |
| `batch_personalized_videos.py` | Voice-clone video pipeline |
| `BUGS.md` | Bug tracker (v2 `_authenticate` recursion bug fixed in v3) |
