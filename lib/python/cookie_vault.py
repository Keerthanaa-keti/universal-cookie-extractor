"""
Cookie Vault v3 — Python client (zero-knowledge).

A remote server uses this to read cookies the owner synced from their browser.
The server holds ONLY:
  - a scoped API token   (COOKIE_VAULT_TOKEN, 'cvk_...')
  - its own X25519 private key (never leaves the server)
It never holds the owner's password, the master key, or any Supabase credential.
It talks only to the broker Edge Function, which returns ciphertext sealed to
this server; decryption happens locally.

Setup:
    python -m cookie_vault keygen --label my-server      # once, on the server
    # register the printed public key + scope in the extension, get a cvk_ token
    export COOKIE_VAULT_BROKER_URL="https://<ref>.supabase.co/functions/v1/cookie-broker"
    export COOKIE_VAULT_TOKEN="cvk_..."
    export COOKIE_VAULT_KEY_FILE="~/.cookie-vault/my-server.key"

Usage:
    from cookie_vault import CookieVault
    vault = CookieVault()
    cookies = vault.get_cookies("linkedin.com")
    session = vault.requests_session("linkedin.com")
    headers = vault.cookie_header("linkedin.com")
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests as _requests

try:
    from . import vault_crypto as vc  # package import
except ImportError:  # run as a script / `python -m`
    import vault_crypto as vc

DEFAULT_KEY_DIR = Path(os.path.expanduser("~/.cookie-vault"))


def _load_key(private_key: Optional[str], key_file: Optional[str], label: Optional[str]):
    """Return (public_key_b64url, private_key_b64url) from the first available source."""
    if private_key:
        # raw private key given directly; derive public from it
        priv_raw = vc.from_b64url(private_key)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        pub = X25519PrivateKey.from_private_bytes(priv_raw).public_key().public_bytes_raw()
        return vc.b64url(pub), private_key
    path = key_file or (os.environ.get("COOKIE_VAULT_KEY_FILE"))
    if not path and label:
        path = str(DEFAULT_KEY_DIR / f"{label}.key")
    if not path and os.environ.get("COOKIE_VAULT_KEY_LABEL"):
        path = str(DEFAULT_KEY_DIR / f"{os.environ['COOKIE_VAULT_KEY_LABEL']}.key")
    if not path:
        raise ValueError(
            "No private key. Set COOKIE_VAULT_PRIVATE_KEY or COOKIE_VAULT_KEY_FILE, "
            "or run: python -m cookie_vault keygen --label <name>"
        )
    data = json.loads(Path(os.path.expanduser(path)).read_text())
    return data["public_key"], data["private_key"]


def _headers_from_profile(profile: Optional[dict]) -> dict:
    """Build the HTTP headers a real Chrome would send, from a captured browser profile."""
    if not profile:
        return {}
    h = {}
    if profile.get("user_agent"):
        h["User-Agent"] = profile["user_agent"]
    if profile.get("accept_language"):
        h["Accept-Language"] = profile["accept_language"]
    uad = profile.get("ua_data") or {}
    brands = uad.get("brands")
    if brands:
        h["sec-ch-ua"] = ", ".join(f'"{b["brand"]}";v="{b["version"]}"' for b in brands)
        h["sec-ch-ua-mobile"] = "?1" if uad.get("mobile") else "?0"
        if uad.get("platform"):
            h["sec-ch-ua-platform"] = f'"{uad["platform"]}"'
    fvl = uad.get("fullVersionList")
    if fvl:
        h["sec-ch-ua-full-version-list"] = ", ".join(f'"{b["brand"]}";v="{b["version"]}"' for b in fvl)
    return h


class CookieVault:
    def __init__(
        self,
        broker_url: Optional[str] = None,
        token: Optional[str] = None,
        private_key: Optional[str] = None,
        key_file: Optional[str] = None,
        label: Optional[str] = None,
    ):
        self.broker_url = (broker_url or os.environ.get("COOKIE_VAULT_BROKER_URL", "")).rstrip("/")
        self.token = token or os.environ.get("COOKIE_VAULT_TOKEN", "")
        if not self.broker_url or not self.token:
            raise ValueError("Set COOKIE_VAULT_BROKER_URL and COOKIE_VAULT_TOKEN.")
        self.public_key, self.private_key = _load_key(
            private_key or os.environ.get("COOKIE_VAULT_PRIVATE_KEY"), key_file, label
        )
        self._profile = None

    def _get(self, path: str, params: dict) -> dict:
        r = _requests.get(
            f"{self.broker_url}/{path}",
            params=params,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=30,
        )
        if not r.ok:
            raise RuntimeError(f"broker {path}: {r.status_code} {r.text}")
        return r.json()

    def get_cookies(self, domain: str, max_age_seconds: Optional[int] = None) -> list:
        """Fetch + decrypt cookies for a domain (within this server's scope)."""
        data = self._get("cookies", {"domain": domain})
        cookies: list = []
        now = time.time()
        for entry in data.get("entries", []):
            if max_age_seconds:
                synced = datetime.fromisoformat(entry["synced_at"].replace("Z", "+00:00"))
                if now - synced.timestamp() > max_age_seconds:
                    continue
            dek = vc.unseal_dek_for_server(entry["wrapped_dek"], self.private_key)
            cookies.extend(vc.decrypt_cookies(entry["ciphertext"], entry["iv"], dek))
        return cookies

    def list_domains(self) -> list:
        return self._get("domains", {}).get("domains", [])

    def cookie_header(self, domain: str, max_age_seconds: Optional[int] = None) -> dict:
        cookies = self.get_cookies(domain, max_age_seconds)
        if not cookies:
            return {}
        return {"Cookie": "; ".join(f"{c['name']}={c['value']}" for c in cookies)}

    def get_profile(self) -> dict:
        """Fetch the captured browser profile (User-Agent, client hints, languages, timezone)."""
        if self._profile is None:
            try:
                self._profile = self._get("profile", {}).get("profile") or {}
            except Exception:
                self._profile = {}
        return self._profile

    def browser_headers(self, domain: str, max_age_seconds: Optional[int] = None) -> dict:
        """Headers a real Chrome would send for this site: profile headers + the Cookie header."""
        h = dict(_headers_from_profile(self.get_profile()))
        h.update(self.cookie_header(domain, max_age_seconds))
        return h

    def requests_session(self, domain: str, max_age_seconds: Optional[int] = None) -> "_requests.Session":
        """A requests.Session with cookies + the browser's headers (UA + client hints).
        NOTE: this still uses OpenSSL TLS. For strong anti-bot sites use impersonate_session()."""
        session = _requests.Session()
        for c in self.get_cookies(domain, max_age_seconds):
            session.cookies.set(c["name"], c["value"], domain=c.get("domain", domain), path=c.get("path", "/"))
        session.headers.update(_headers_from_profile(self.get_profile()))
        return session

    def impersonate_session(self, domain: str, impersonate: Optional[str] = None, max_age_seconds: Optional[int] = None):
        """Full stealth: a curl_cffi session that matches Chrome's TLS (JA3/JA4) AND sets the
        captured User-Agent + client hints + cookies. Indistinguishable from the real browser.
        `impersonate` picks the browser target (default env COOKIE_VAULT_IMPERSONATE or "chrome" =
        latest). Requires: pip install curl_cffi"""
        try:
            from curl_cffi import requests as _cffi
        except ImportError as e:
            raise RuntimeError("Install curl_cffi for full-stealth TLS impersonation: pip install curl_cffi") from e
        target = impersonate or os.environ.get("COOKIE_VAULT_IMPERSONATE", "chrome")
        session = _cffi.Session(impersonate=target)
        for c in self.get_cookies(domain, max_age_seconds):
            session.cookies.set(c["name"], c["value"], domain=c.get("domain", domain), path=c.get("path", "/"))
        session.headers.update(_headers_from_profile(self.get_profile()))
        return session

    def verify_session(self, domain: str, url: str, contains: Optional[str] = None,
                       impersonate: bool = True) -> dict:
        """Test that this session actually works on the server: fetch `url` as the browser and
        report whether it looks logged in. `contains` = a string present only when authenticated.
        Returns {ok, status, final_url, matched, bytes}."""
        session = self.impersonate_session(domain) if impersonate else self.requests_session(domain)
        r = session.get(url, allow_redirects=True)
        text = getattr(r, "text", "") or ""
        ok = 200 <= r.status_code < 400
        matched = (contains in text) if contains is not None else None
        if contains is not None:
            ok = ok and bool(matched)
        return {"ok": ok, "status": r.status_code, "final_url": str(getattr(r, "url", url)),
                "matched": matched, "bytes": len(text)}

    async def playwright_context(self, browser, domain: str, max_age_seconds: Optional[int] = None):
        cookies = self.get_cookies(domain, max_age_seconds)
        # Match the real browser: user agent, locale, and timezone from the captured profile.
        p = self.get_profile() or {}
        opts = {}
        if p.get("user_agent"):
            opts["user_agent"] = p["user_agent"]
        if p.get("languages"):
            opts["locale"] = p["languages"][0]
        if p.get("timezone"):
            opts["timezone_id"] = p["timezone"]
        context = await browser.new_context(**opts)
        pw = []
        for c in cookies:
            ck = {"name": c["name"], "value": c["value"],
                  "domain": c.get("domain", domain), "path": c.get("path", "/")}
            if c.get("secure"):
                ck["secure"] = True
            if c.get("httpOnly"):
                ck["httpOnly"] = True
            if c.get("sameSite"):
                ck["sameSite"] = {"no_restriction": "None", "lax": "Lax", "strict": "Strict"}.get(
                    str(c["sameSite"]).lower(), "Lax")
            if c.get("expirationDate"):
                ck["expires"] = c["expirationDate"]
            pw.append(ck)
        if pw:
            await context.add_cookies(pw)
        return context


def keygen(label: str, out_dir: Path = DEFAULT_KEY_DIR) -> Path:
    """Generate an X25519 keypair, save the private key (0600), print the public key."""
    pub, priv = vc.generate_server_keypair()
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{label}.key"
    path.write_text(json.dumps(
        {"label": label, "public_key": pub, "private_key": priv,
         "created_at": datetime.now(timezone.utc).isoformat()}, indent=2))
    path.chmod(0o600)
    print(f"Private key written to {path} (mode 600). Keep it on this server only.\n")
    print("Register this server in the extension (Servers tab):")
    print(f"  label:       {label}")
    print(f"  public key:  {pub}")
    print("\nThen issue a token (Tokens tab) and set COOKIE_VAULT_TOKEN on this server.")
    return path


def _main():
    import argparse
    ap = argparse.ArgumentParser(prog="cookie_vault", description="Cookie Vault v3 client")
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="generate this server's keypair")
    kg.add_argument("--label", required=True)
    g = sub.add_parser("get", help="fetch cookies for a domain")
    g.add_argument("domain")
    g.add_argument("--label")
    sub.add_parser("domains", help="list domains this server may read")
    sub.add_parser("profile", help="show the captured browser profile")
    v = sub.add_parser("verify", help="test that a session works on a URL")
    v.add_argument("domain")
    v.add_argument("url")
    v.add_argument("--contains", help="text present only when logged in")
    v.add_argument("--label")
    v.add_argument("--no-impersonate", action="store_true", help="use plain requests instead of TLS impersonation")
    args = ap.parse_args()

    try:
        if args.cmd == "keygen":
            keygen(args.label)
        elif args.cmd == "get":
            print(json.dumps(CookieVault(label=args.label).get_cookies(args.domain), indent=2))
        elif args.cmd == "domains":
            print(json.dumps(CookieVault().list_domains(), indent=2))
        elif args.cmd == "profile":
            print(json.dumps(CookieVault().get_profile(), indent=2))
        elif args.cmd == "verify":
            import sys
            r = CookieVault(label=args.label).verify_session(
                args.domain, args.url, contains=args.contains, impersonate=not args.no_impersonate)
            print(json.dumps(r, indent=2))
            sys.exit(0 if r["ok"] else 1)
    except RuntimeError as e:
        import sys
        msg = str(e)
        dom = getattr(args, "domain", "")
        if " 403 " in msg:
            print(f"denied: '{dom}' is not in this server's scope.", file=sys.stderr)
        elif " 401 " in msg:
            print("unauthorized: check COOKIE_VAULT_TOKEN (it may be revoked or wrong).", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
