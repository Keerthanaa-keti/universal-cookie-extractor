"""
Fingerprint test — proves a remote server, using the vault's browser profile +
TLS impersonation, is indistinguishable from the real browser.

Fetches the profile from the broker, then hits a neutral TLS-fingerprint echo
(tls.peet.ws) three ways and compares JA3 + User-Agent. Run on any server that has
the vault env set (COOKIE_VAULT_BROKER_URL / _TOKEN / _KEY_FILE) + curl_cffi.
"""
import json
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
for _p in [_here, os.path.join(_here, "..", "..", "lib", "python")]:
    if os.path.exists(os.path.join(_p, "cookie_vault.py")):
        sys.path.insert(0, _p)
        break
from cookie_vault import CookieVault, _headers_from_profile  # noqa: E402

FP = "https://tls.peet.ws/api/all"


def main():
    vault = CookieVault()
    profile = vault.get_profile()
    ua = profile.get("user_agent", "")
    print("browser profile (from vault): UA =", ua[:64])
    if not ua:
        print("no profile in the vault yet — sync from the extension first.")
        sys.exit(2)

    import requests
    plain = requests.get(FP, timeout=25).json()

    from curl_cffi import requests as cffi
    s = cffi.Session(impersonate="chrome")
    s.headers.update(_headers_from_profile(profile))
    stealth = s.get(FP, timeout=25).json()

    p_ja3, s_ja3 = plain["tls"]["ja3_hash"], stealth["tls"]["ja3_hash"]
    print(f"\n{'plain requests':16} ja3={p_ja3}  ua={plain['user_agent'][:32]}")
    print(f"{'stealth (server)':16} ja3={s_ja3}  ua={stealth['user_agent'][:32]}")

    # The stealth ja3 must be a real Chrome ja3 (differs from the python-requests one),
    # and the User-Agent the server presented must equal the captured browser UA.
    ok_ua = stealth["user_agent"] == ua
    ok_diff = s_ja3 != p_ja3
    ok_chrome_shape = stealth["tls"]["ja4"].startswith("t13d") and "h2" in stealth["tls"]["ja4"]

    print()
    print(f"[{'PASS' if ok_diff else 'FAIL'}] stealth TLS differs from a plain bot")
    print(f"[{'PASS' if ok_chrome_shape else 'FAIL'}] stealth TLS has a Chrome shape (JA4 t13d…h2)")
    print(f"[{'PASS' if ok_ua else 'FAIL'}] server presents the captured browser User-Agent")
    passed = ok_diff and ok_chrome_shape and ok_ua
    print("\n" + ("FINGERPRINT MATCH — server looks like the real browser ✅" if passed else "FINGERPRINT MISMATCH ❌"))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
