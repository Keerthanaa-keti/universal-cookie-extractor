"""
Cookie Vault - Python client for encrypted cloud cookie storage.

Retrieves cookies from Supabase that were synced by the Cookie Extractor extension.
Provides pre-built integrations with requests, Playwright, and raw HTTP headers.

Usage:
    from cookie_vault import CookieVault

    vault = CookieVault()  # reads from env vars
    cookies = vault.get_cookies('.linkedin.com')
    session = vault.requests_session('.linkedin.com')
    headers = vault.cookie_header('.linkedin.com')
"""

import base64
import json
import os
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import requests as _requests

PBKDF2_ITERATIONS = 100_000
KEY_LENGTH = 32  # 256 bits


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive AES-256 key from passphrase using PBKDF2 (matching browser Web Crypto params)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def _decrypt(encrypted_data: str, iv: str, salt: str, vault_key: str) -> list:
    """Decrypt AES-256-GCM encrypted cookie data."""
    salt_bytes = base64.b64decode(salt)
    iv_bytes = base64.b64decode(iv)
    ciphertext = base64.b64decode(encrypted_data)

    key = _derive_key(vault_key, salt_bytes)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv_bytes, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))


class CookieVault:
    """Client for retrieving cookies from Cookie Vault (Supabase)."""

    def __init__(
        self,
        vault_key: Optional[str] = None,
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
        email: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.vault_key = vault_key or os.environ.get('COOKIE_VAULT_KEY', '')
        self.supabase_url = (supabase_url or os.environ.get('COOKIE_VAULT_SUPABASE_URL', '')).rstrip('/')
        self.supabase_key = supabase_key or os.environ.get('COOKIE_VAULT_SUPABASE_KEY', '')
        self.email = email or os.environ.get('COOKIE_VAULT_EMAIL', '')
        self.password = password or os.environ.get('COOKIE_VAULT_PASSWORD', '')

        if not all([self.vault_key, self.supabase_url, self.supabase_key]):
            raise ValueError(
                'Missing config. Set COOKIE_VAULT_KEY, COOKIE_VAULT_SUPABASE_URL, '
                'COOKIE_VAULT_SUPABASE_KEY env vars (or pass to constructor).'
            )

        self._access_token = None
        self._token_expires_at = 0
        self._user_id = None
        self._refresh_token = None

    def _authenticate(self):
        """Authenticate with Supabase and get JWT."""
        if self._access_token and time.time() < self._token_expires_at - 60:
            return

        if self._refresh_token:
            url = f'{self.supabase_url}/auth/v1/token?grant_type=refresh_token'
            body = {'refresh_token': self._refresh_token}
        else:
            url = f'{self.supabase_url}/auth/v1/token?grant_type=password'
            body = {'email': self.email, 'password': self.password}

        resp = _requests.post(
            url,
            headers={'apikey': self.supabase_key, 'Content-Type': 'application/json'},
            json=body,
        )

        if not resp.ok:
            self._refresh_token = None
            if 'refresh_token' in body:
                return self._authenticate()
            resp.raise_for_status()

        data = resp.json()
        self._access_token = data['access_token']
        self._refresh_token = data.get('refresh_token')
        self._user_id = data['user']['id']
        self._token_expires_at = time.time() + data.get('expires_in', 3600)

    def _headers(self) -> dict:
        """Build request headers with auth token."""
        self._authenticate()
        return {
            'apikey': self.supabase_key,
            'Authorization': f'Bearer {self._access_token}',
            'Content-Type': 'application/json',
        }

    def _query(self, path: str) -> list:
        """Execute Supabase REST query."""
        resp = _requests.get(
            f'{self.supabase_url}/rest/v1/{path}',
            headers=self._headers(),
        )
        resp.raise_for_status()
        return resp.json()

    def get_cookies(self, domain: str, max_age_seconds: Optional[int] = None) -> list:
        """
        Get decrypted cookies for a domain.

        Args:
            domain: Domain to fetch cookies for (e.g. '.linkedin.com')
            max_age_seconds: If set, reject entries synced more than this many seconds ago

        Returns:
            List of cookie dicts with name, value, domain, path, secure, httpOnly, etc.
        """
        # Query with domain filter (supports partial match with ilike)
        entries = self._query(
            f'cookie_entries?domain=ilike.*{domain}*'
            f'&select=encrypted_data,iv,salt,synced_at,domain'
        )

        if not entries:
            return []

        all_cookies = []
        now = time.time()

        for entry in entries:
            if max_age_seconds:
                from datetime import datetime, timezone
                synced = datetime.fromisoformat(entry['synced_at'].replace('Z', '+00:00'))
                age = now - synced.timestamp()
                if age > max_age_seconds:
                    continue

            cookies = _decrypt(
                entry['encrypted_data'],
                entry['iv'],
                entry['salt'],
                self.vault_key,
            )
            all_cookies.extend(cookies)

        return all_cookies

    def cookie_header(self, domain: str, max_age_seconds: Optional[int] = None) -> dict:
        """
        Get Cookie header dict for use with any HTTP client.

        Returns:
            Dict like {'Cookie': 'name1=value1; name2=value2'}
        """
        cookies = self.get_cookies(domain, max_age_seconds)
        if not cookies:
            return {}
        cookie_str = '; '.join(f"{c['name']}={c['value']}" for c in cookies)
        return {'Cookie': cookie_str}

    def requests_session(self, domain: str, max_age_seconds: Optional[int] = None) -> _requests.Session:
        """
        Create a requests.Session pre-loaded with cookies from the vault.

        Args:
            domain: Domain to load cookies for
            max_age_seconds: Max age of synced data

        Returns:
            requests.Session with cookies set
        """
        session = _requests.Session()
        cookies = self.get_cookies(domain, max_age_seconds)
        for c in cookies:
            session.cookies.set(
                c['name'],
                c['value'],
                domain=c.get('domain', domain),
                path=c.get('path', '/'),
            )
        return session

    async def playwright_context(self, browser, domain: str, max_age_seconds: Optional[int] = None):
        """
        Create a Playwright browser context with cookies loaded from the vault.

        Args:
            browser: Playwright Browser instance
            domain: Domain to load cookies for
            max_age_seconds: Max age of synced data

        Returns:
            BrowserContext with cookies set
        """
        cookies = self.get_cookies(domain, max_age_seconds)
        context = await browser.new_context()

        pw_cookies = []
        for c in cookies:
            cookie_domain = c.get('domain', domain)
            pw_cookie = {
                'name': c['name'],
                'value': c['value'],
                'domain': cookie_domain,
                'path': c.get('path', '/'),
            }
            if c.get('secure'):
                pw_cookie['secure'] = True
            if c.get('sameSite'):
                samesite_map = {'no_restriction': 'None', 'lax': 'Lax', 'strict': 'Strict'}
                pw_cookie['sameSite'] = samesite_map.get(c['sameSite'].lower(), 'Lax')
            if c.get('expirationDate'):
                pw_cookie['expires'] = c['expirationDate']
            pw_cookies.append(pw_cookie)

        if pw_cookies:
            await context.add_cookies(pw_cookies)

        return context

    def list_domains(self) -> list:
        """List all domains that have cookies in the vault."""
        entries = self._query('cookie_entries?select=domain,cookie_count,has_auth_cookies,synced_at')
        return [
            {
                'domain': e['domain'],
                'cookie_count': e['cookie_count'],
                'has_auth_cookies': e['has_auth_cookies'],
                'synced_at': e['synced_at'],
            }
            for e in entries
        ]
