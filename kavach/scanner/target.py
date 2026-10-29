"""Target handling: input validation, SSRF protection and a safe HTTP fetch.

Everything that touches a user-supplied address goes through this module.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit, urljoin

import httpx

from .constants import HTTP_TIMEOUT, MAX_BODY, MAX_REDIRECTS, USER_AGENT
from .models import ScanError

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)


def normalize_domain(raw: str) -> str:
    """Accept 'example.com', 'https://example.com/path' etc. Return bare hostname."""
    if not raw or len(raw) > 300:
        raise ScanError("Please enter a valid website, for example example.com")
    value = raw.strip().lower()
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
    except ValueError:
        raise ScanError("Please enter a valid website, for example example.com")
    if parts.port not in (None, 80, 443):
        raise ScanError("Only standard web addresses (ports 80 and 443) can be checked.")
    host = host.rstrip(".")
    try:
        ipaddress.ip_address(host)
        raise ScanError("Please enter a domain name, not an IP address.")
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ScanError("That domain name is not valid.")
    if host == "localhost" or not _HOST_RE.match(host):
        raise ScanError("Please enter a valid website, for example example.com")
    return host


def _ip_is_public(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public_ips(host: str) -> list[str]:
    """Resolve host and refuse anything that points to a private/internal address."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ScanError("We could not find that website. Check the spelling and try again.")
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise ScanError("We could not find that website. Check the spelling and try again.")
    if not all(_ip_is_public(ip) for ip in ips):
        raise ScanError("That address points to a private or internal network and cannot be checked.")
    return ips


# --------------------------------------------------------------------------
# HTTP helper (manual redirects so every hop is re-validated)
# --------------------------------------------------------------------------
def safe_get(url: str, *, max_redirects: int = MAX_REDIRECTS, verify: bool = True):
    """GET url, following up to N redirects, re-checking each host is public.

    Returns (response, final_url, redirect_chain). Body is capped at MAX_BODY.
    """
    chain = [url]
    current = url
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        follow_redirects=False,
        verify=verify,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    ) as client:
        for _ in range(max_redirects + 1):
            host = urlsplit(current).hostname or ""
            if urlsplit(current).scheme not in ("http", "https"):
                raise ScanError("Redirected to an unsupported address.")
            resolve_public_ips(host)
            with client.stream("GET", current) as resp:
                body = b""
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
                resp._content = body[:MAX_BODY]  # keep capped body accessible
                if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                    current = urljoin(current, resp.headers["location"])
                    chain.append(current)
                    continue
                return resp, current, chain
    raise ScanError("The website redirected too many times.")
