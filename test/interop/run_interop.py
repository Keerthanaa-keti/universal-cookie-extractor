#!/usr/bin/env python3
"""
Cross-runtime interop test for the Cookie Vault v3 envelope crypto.

Exercises the REAL modules (lib/shared/vault-crypto.mjs via Node, and
lib/python/vault_crypto.py via Python) and asserts a writer in one runtime can
be read by a server in the other, plus owner recovery. Run from the repo root:

    python3 test/interop/run_interop.py

Exit code 0 = all pass. Requires `node` (>=18) and `python3` with `cryptography`.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JS = ["node", str(ROOT / "test/interop/interop_js.mjs")]
PY = [sys.executable, str(ROOT / "test/interop/interop_py.py")]

FAILS = []


def call(runtime, req):
    p = subprocess.run(runtime, input=json.dumps(req), capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{runtime[0]} failed: {p.stderr.strip()}")
    return json.loads(p.stdout)


def check(name, ok):
    mark = "PASS ✅" if ok else "FAIL ❌"
    print(f"  [{mark}] {name}")
    if not ok:
        FAILS.append(name)


COOKIES = [
    {"name": "li_at", "value": "AQEDA-token-123", "domain": ".linkedin.com",
     "path": "/", "secure": True, "httpOnly": True, "sameSite": "no_restriction",
     "expirationDate": 1999999999.5},
    {"name": "JSESSIONID", "value": "ajax:0099", "domain": ".linkedin.com", "path": "/"},
    {"name": "unicode_ключ", "value": "日本語 🍪 value", "domain": ".linkedin.com", "path": "/"},
]
PASSPHRASE = "correct horse battery staple 🐴"


def main():
    print("Cookie Vault v3 — cross-runtime envelope interop\n")

    # Key material
    py_kp = call(PY, {"cmd": "genkey"})
    js_kp = call(JS, {"cmd": "genkey"})
    owner_salt = call(JS, {"cmd": "owner-salt"})["salt"]

    # 1. JS writer -> Python server + Node server + both owners
    print("1. Writer = JS (Web Crypto), server pubkey from Python:")
    entry = call(JS, {"cmd": "make-entry", "cookies": COOKIES,
                      "serverPub": py_kp["publicKey"], "passphrase": PASSPHRASE, "ownerSalt": owner_salt})
    r = call(PY, {"cmd": "read-entry-server", "entry": entry,
                  "priv": py_kp["privateKey"], "pub": py_kp["publicKey"]})
    check("JS writer -> Python server decrypt", r["cookies"] == COOKIES)
    r = call(PY, {"cmd": "read-entry-owner", "entry": entry, "passphrase": PASSPHRASE})
    check("JS writer -> Python owner decrypt", r["cookies"] == COOKIES)
    r = call(JS, {"cmd": "read-entry-owner", "entry": entry, "passphrase": PASSPHRASE})
    check("JS writer -> JS owner decrypt", r["cookies"] == COOKIES)

    # 2. Python writer -> JS server + Python server
    print("2. Writer = Python, server pubkey from JS:")
    entry2 = call(PY, {"cmd": "make-entry", "cookies": COOKIES,
                       "serverPub": js_kp["publicKey"], "passphrase": PASSPHRASE, "ownerSalt": owner_salt})
    r = call(JS, {"cmd": "read-entry-server", "entry": entry2,
                  "priv": js_kp["privateKey"], "pub": js_kp["publicKey"]})
    check("Python writer -> JS server decrypt", r["cookies"] == COOKIES)
    r = call(PY, {"cmd": "read-entry-owner", "entry": entry2, "passphrase": PASSPHRASE})
    check("Python writer -> Python owner decrypt", r["cookies"] == COOKIES)

    # 3. Low-level DEK seal/unseal both directions
    print("3. Low-level DEK seal/unseal:")
    import base64
    import os
    dek = base64.b64encode(os.urandom(32)).decode()
    w = call(JS, {"cmd": "seal", "dek": dek, "serverPub": py_kp["publicKey"]})
    r = call(PY, {"cmd": "unseal", "wrap": w, "priv": py_kp["privateKey"]})
    check("JS seal -> Python unseal", r["dek"] == dek)
    w = call(PY, {"cmd": "seal", "dek": dek, "serverPub": js_kp["publicKey"]})
    r = call(JS, {"cmd": "unseal", "wrap": w, "priv": js_kp["privateKey"], "pub": js_kp["publicKey"]})
    check("Python seal -> JS unseal", r["dek"] == dek)

    # 4. Negative: wrong passphrase and wrong server key must FAIL to decrypt
    print("4. Negative cases (must reject):")
    def rejects(runtime, req):
        p = subprocess.run(runtime, input=json.dumps(req), capture_output=True, text=True)
        return p.returncode != 0
    check("wrong owner passphrase rejected",
          rejects(PY, {"cmd": "read-entry-owner", "entry": entry, "passphrase": "wrong"}))
    check("wrong server key rejected",
          rejects(PY, {"cmd": "read-entry-server", "entry": entry,
                       "priv": js_kp["privateKey"], "pub": js_kp["publicKey"]}))

    print()
    if FAILS:
        print(f"FAILED: {len(FAILS)} check(s): {FAILS}")
        sys.exit(1)
    print("ALL INTEROP CHECKS PASSED — envelope crypto is correct across runtimes.")


if __name__ == "__main__":
    main()
