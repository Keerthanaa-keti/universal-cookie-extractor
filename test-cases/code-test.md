# Cookie Vault v3 — code test cases

Automated: `bash test/run_all.sh`. Status legend: ✅ pass · ⬜ manual/pending.

| # | Test Case | Steps / Input | Expected | Status |
|---|-----------|---------------|----------|--------|
| C1 | X25519 ECIES interop (browser↔Node↔Python) | `test/interop/run_interop.py` | Seal in any runtime, unseal in the others; DEK matches | ✅ |
| C2 | Owner-wrap round trip | interop test | PBKDF2 wrap in JS, unwrap in Python, and vice versa | ✅ |
| C3 | Wrong passphrase rejected | interop negative case | AES-GCM auth failure, no plaintext | ✅ |
| C4 | Wrong server key rejected | interop negative case | decrypt fails | ✅ |
| C5 | Broker type-checks | `deno check .../cookie-broker/index.ts` | no type errors | ✅ |
| C6 | Broker returns sealed entry | e2e GET /cookies (in scope) | 200, one entry, decrypts to original cookies | ✅ |
| C7 | Scope enforcement | e2e GET /cookies?domain=out-of-scope | 403 `denied_scope`, no data | ✅ |
| C8 | Invalid token | e2e bad bearer | 401 | ✅ |
| C9 | Revoked token | e2e set revoked, GET | 403 `denied_token` | ✅ |
| C10 | `/domains` scoping | e2e GET /domains | only in-scope domains listed | ✅ |
| C11 | Read audit written | e2e | each read appended to `access_log` | ✅ |
| C12 | Node + Python clients decrypt | e2e | both return original cookies | ✅ |
| C13 | Writer envelope (full loop) | `test/e2e/run_fullloop.mjs` | per-domain DEK, entry + entry_keys written | ✅ |
| C14 | Out-of-scope domain never sealed to server | full loop | bank.com sealed to owner ONLY; linkedin to owner+server | ✅ |
| C15 | Schema validity | `pglast` parse of `schema_v3.sql` | 40 statements, no grammar errors | ✅ |
| C16 | Rate limit | >N reads/min for one token | 429 `rate_limited` | ⬜ (logic in broker; not load-tested) |
| C17 | Key file interoperability | keygen in Python, load in Node (and reverse) | same public/private usable both sides | ✅ (format identical; used in e2e) |
| C18 | Refresh-token auth (no password bug) | password containing `refresh_token` | no infinite recursion (old BUGS.md bug) | ✅ (code path removed) |
