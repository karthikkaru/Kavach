import httpx
import pytest

from kavach.scanner import ScanError, normalize_domain, target


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("https://Example.com/path?q=1", "example.com"),
    ("http://www.example.co.in:443/", "www.example.co.in"),
    ("  example.com.  ", "example.com"),
])
def test_normalize_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "localhost", "127.0.0.1", "http://10.0.0.5/", "192.168.1.1", "[::1]",
    "example.com:8080", "not a domain", "-bad.com", "a" * 300, "http://", "ftp://example",
    "example", "exa_mple.com",
])
def test_normalize_rejects(raw):
    with pytest.raises(ScanError):
        normalize_domain(raw)


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("127.0.0.1", False), ("10.1.2.3", False), ("172.16.0.1", False),
    ("192.168.0.1", False), ("169.254.169.254", False), ("::1", False),
    ("::ffff:127.0.0.1", False), ("100.64.0.1", False), ("0.0.0.0", False), ("224.0.0.1", False),
])
def test_ip_is_public(ip, public):
    assert target._ip_is_public(ip) is public


def test_resolve_blocks_private(monkeypatch):
    monkeypatch.setattr(target.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.7", 0))])
    with pytest.raises(ScanError, match="private or internal"):
        target.resolve_public_ips("evil.example.com")


def test_resolve_blocks_mixed_records(monkeypatch):
    monkeypatch.setattr(target.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0)), (2, 1, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(ScanError):
        target.resolve_public_ips("mixed.example.com")


def test_redirect_to_internal_is_blocked(monkeypatch):
    """A public site that redirects to an internal address must not be followed."""
    def fake_resolve(host):
        if host == "internal.local.test":
            raise ScanError("That address points to a private or internal network and cannot be checked.")
        return ["8.8.8.8"]
    monkeypatch.setattr(target, "resolve_public_ips", fake_resolve)

    def handler(request):
        return httpx.Response(302, headers={"location": "http://internal.local.test/admin"})

    real_client = httpx.Client
    monkeypatch.setattr(target.httpx, "Client",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    with pytest.raises(ScanError, match="private or internal"):
        target.safe_get("https://public.example.com/")
