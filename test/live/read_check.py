"""Non-invasive check: decrypt real cookies for a domain ON this server and print a
masked summary. Touches only the vault (no request to the target site).
Usage: python read_check.py [domain]   (default linkedin.com)"""
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
for _p in [_here, os.path.join(_here, "..", "..", "lib", "python")]:
    if os.path.exists(os.path.join(_p, "cookie_vault.py")):
        sys.path.insert(0, _p)
        break
from cookie_vault import CookieVault  # noqa: E402

domain = sys.argv[1] if len(sys.argv) > 1 else "linkedin.com"
v = CookieVault()
ck = v.get_cookies(domain)
print("decrypted %d real %s cookies on this box" % (len(ck), domain))
names = sorted(c["name"] for c in ck)
print("names:", ", ".join(names[:16]) + (" ..." if len(names) > 16 else ""))
li = next((c for c in ck if c["name"] in ("li_at", "sessionid", "sid", "__Secure-next-auth.session-token")), None)
if li:
    val = li.get("value", "")
    print("session cookie '%s': len=%d, starts %s..., secure=%s, httpOnly=%s"
          % (li["name"], len(val), val[:6], li.get("secure"), li.get("httpOnly")))
prof = v.get_profile()
print("browser profile UA:", (prof.get("user_agent") or "")[:60])
print("browser profile tz:", prof.get("timezone"))
