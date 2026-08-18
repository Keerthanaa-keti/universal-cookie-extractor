# Cross-runtime envelope crypto interop test

Proves the Cookie Vault v3 zero-knowledge envelope is byte-compatible across the
three runtimes that touch it:

- **Browser** — the extension's `lib/shared/vault-crypto.mjs` (Web Crypto API)
- **Node** — the same `lib/shared/vault-crypto.mjs` (Node's Web Crypto)
- **Python** — `lib/python/vault_crypto.py` (`cryptography`)

Scheme: `X25519 ECDH → HKDF-SHA256 → AES-256-GCM` (ECIES) for the per-server DEK
wrap; `AES-256-GCM` for cookies; `PBKDF2 → AES-256-GCM` for the owner wrap. No
third-party crypto libraries in any runtime.

## Run

```bash
python3 test/interop/run_interop.py     # needs node >=18 and python `cryptography`
```

Exercises: writer in one runtime → server + owner readers in the other, both
directions, plus negative cases (wrong passphrase / wrong server key must reject).
`interop_js.mjs` and `interop_py.py` are thin harnesses around the real modules.
