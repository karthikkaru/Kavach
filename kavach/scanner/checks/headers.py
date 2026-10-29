"""HTTP to HTTPS redirect, security headers and cookie flags."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from .. import target
from ..models import Finding, ScanError


def check_http_and_headers(host: str) -> list[Finding]:
    out: list[Finding] = []
    # 1) does plain http redirect to https?
    try:
        resp, final_url, chain = target.safe_get(f"http://{host}/")
        if urlsplit(final_url).scheme == "https":
            out.append(Finding("https_redirect", "Transport", "HTTP redirects to HTTPS", "info", True,
                               "Visitors who type the plain http:// address are sent to the secure site."))
        else:
            out.append(Finding("no_https_redirect", "Transport", "HTTP does not redirect to HTTPS", "medium", False,
                               "Visitors can use the site over an unencrypted connection.",
                               "Redirect all http:// traffic to https:// (301) on your server or CDN."))
    except ScanError:
        raise
    except httpx.HTTPError:
        pass  # port 80 closed is acceptable if HTTPS works

    # 2) fetch the https page and inspect headers
    try:
        resp, final_url, _ = target.safe_get(f"https://{host}/")
    except ScanError:
        raise
    except httpx.HTTPError:
        out.append(Finding("site_unreachable", "Headers", "Website did not respond over HTTPS", "info", False,
                           "We could not read security headers because the HTTPS request failed."))
        return out

    h = {k.lower(): v for k, v in resp.headers.items()}
    csp = h.get("content-security-policy", "")

    def header_finding(fid, title, name, severity, why, fix, present=None):
        ok = (name in h) if present is None else present
        out.append(Finding(
            fid, "Headers", title if not ok else title.replace("missing", "present"),
            "info" if ok else severity, ok,
            "Header is set." if ok else why, "" if ok else fix,
        ))

    header_finding("hsts", "Strict-Transport-Security header missing", "strict-transport-security", "medium",
                   "Browsers are not told to always use HTTPS for this site.",
                   "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    header_finding("csp", "Content-Security-Policy header missing", "content-security-policy", "medium",
                   "No policy limits where scripts can load from, which makes cross-site scripting easier.",
                   "Add a Content-Security-Policy header. Start with: default-src 'self'")
    header_finding("xfo", "Clickjacking protection missing", "x-frame-options", "low",
                   "Other sites may be able to show your pages inside a hidden frame.",
                   "Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors.",
                   present=("x-frame-options" in h) or ("frame-ancestors" in csp))
    header_finding("xcto", "X-Content-Type-Options header missing", "x-content-type-options", "low",
                   "Browsers may guess file types, which can allow some attacks.",
                   "Add: X-Content-Type-Options: nosniff")
    header_finding("referrer", "Referrer-Policy header missing", "referrer-policy", "low",
                   "Full page addresses may be shared with other sites.",
                   "Add: Referrer-Policy: strict-origin-when-cross-origin")
    header_finding("permissions", "Permissions-Policy header missing", "permissions-policy", "low",
                   "Browser features such as camera or location are not restricted.",
                   "Add a Permissions-Policy header, for example: camera=(), microphone=(), geolocation=()")

    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", server) or powered:
        out.append(Finding("info_leak", "Headers", "Server software details are exposed", "low", False,
                           f"Headers reveal: {', '.join(x for x in [server, powered] if x)}.",
                           "Hide version details (for example 'ServerTokens Prod' in Apache, "
                           "'server_tokens off' in Nginx, and remove X-Powered-By)."))
    else:
        out.append(Finding("info_leak_ok", "Headers", "No server version details exposed", "info", True,
                           "Headers do not reveal software versions."))

    # cookies
    cookies = resp.headers.get_list("set-cookie")
    if cookies:
        weak = [c.split("=", 1)[0] for c in cookies
                if "secure" not in c.lower() or "httponly" not in c.lower()]
        if weak:
            out.append(Finding("cookie_flags", "Headers", "Cookies missing Secure or HttpOnly flag", "medium", False,
                               f"Affected cookies: {', '.join(sorted(set(weak))[:5])}.",
                               "Set the Secure and HttpOnly flags (and SameSite) on all cookies."))
        else:
            out.append(Finding("cookie_flags_ok", "Headers", "Cookies use Secure and HttpOnly flags", "info", True, ""))
    return out
