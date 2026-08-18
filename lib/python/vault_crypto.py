"""
Cookie Vault v3 — envelope-encryption primitives (Python).

Mirrors lib/shared/vault-crypto.mjs byte-for-byte. Uses only the `cryptography`
package (built on OpenSSL); no third-party crypto beyond it.

Scheme:
  cookies -> AES-256-GCM(DEK)                            : {ciphertext, iv}
  DEK -> server : X25519 ECDH -> HKDF-SHA256 -> AES-GCM  : {epk, iv, ct}
  DEK -> owner  : PBKDF2(passphrase) -> AES-GCM          : {salt, iv, ct}

Keys are raw 32-byte X25519, base64url-encoded (matching WebCrypto jwk x/d).
"""

import base64
import json
import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HKDF_SALT = bytes(32)
HKDF_INFO = b"cookie-vault-v3/dek-wrap"
PBKDF2_ITERATIONS = 100_000


# ---- base64 helpers --------------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def from_b64(s: str) -> bytes:
    return base64.b64decode(s)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def from_b64url(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ---- X25519 keypair --------------------------------------------------------
def generate_server_keypair() -> Tuple[str, str]:
    """Return (public_key_b64url, private_key_b64url), raw 32-byte keys."""
    priv = X25519PrivateKey.generate()
    return (
        b64url(priv.public_key().public_bytes_raw()),
        b64url(priv.private_bytes_raw()),
    )


def _ecies_key(shared: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=HKDF_SALT, info=HKDF_INFO).derive(shared)


# ---- DEK + cookie payload --------------------------------------------------
def generate_dek() -> bytes:
    return os.urandom(32)


def encrypt_cookies(cookie_array: list, dek: bytes) -> dict:
    iv = os.urandom(12)
    pt = json.dumps(cookie_array).encode()
    ct = AESGCM(dek).encrypt(iv, pt, None)
    return {"ciphertext": b64(ct), "iv": b64(iv)}


def decrypt_cookies(ciphertext_b64: str, iv_b64: str, dek: bytes) -> list:
    pt = AESGCM(dek).decrypt(from_b64(iv_b64), from_b64(ciphertext_b64), None)
    return json.loads(pt.decode())


# ---- DEK wrapping: server (ECIES) ------------------------------------------
def seal_dek_for_server(dek: bytes, server_pub_b64url: str) -> dict:
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(from_b64url(server_pub_b64url)))
    key = _ecies_key(shared)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, dek, None)
    return {"epk": b64url(eph.public_key().public_bytes_raw()), "iv": b64(iv), "ct": b64(ct)}


def unseal_dek_for_server(wrap: dict, priv_b64url: str) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(from_b64url(priv_b64url))
    shared = priv.exchange(X25519PublicKey.from_public_bytes(from_b64url(wrap["epk"])))
    key = _ecies_key(shared)
    return AESGCM(key).decrypt(from_b64(wrap["iv"]), from_b64(wrap["ct"]), None)


# ---- DEK wrapping: owner (PBKDF2 passphrase) -------------------------------
def _owner_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt,
                      iterations=PBKDF2_ITERATIONS).derive(passphrase.encode())


def generate_owner_salt() -> str:
    return b64(os.urandom(16))


def wrap_dek_for_owner(dek: bytes, passphrase: str, owner_salt_b64: str) -> dict:
    salt = from_b64(owner_salt_b64)
    key = _owner_key(passphrase, salt)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, dek, None)
    return {"salt": owner_salt_b64, "iv": b64(iv), "ct": b64(ct)}


def unwrap_dek_for_owner(wrap: dict, passphrase: str) -> bytes:
    key = _owner_key(passphrase, from_b64(wrap["salt"]))
    return AESGCM(key).decrypt(from_b64(wrap["iv"]), from_b64(wrap["ct"]), None)


# ---- shared auth-cookie heuristic ------------------------------------------
_AUTH_PATTERNS = [
    "auth", "session", "token", "login", "user", "csrf", "xsrf",
    "li_at", "c_user", "xs", "fr", "sb", "datr", "twid", "ct0",
    "sessionid", "csrftoken", "sid", "hsid", "ssid", "apisid", "sapisid",
    "jsessionid", "phpsessid", "asp.net_sessionid",
]


def is_auth_cookie(cookie: dict) -> bool:
    name = (cookie.get("name") or "").lower()
    return any(p in name for p in _AUTH_PATTERNS)
