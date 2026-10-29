import httpx

from kavach.scanner import target
from kavach.scanner.checks import exposure, headers


def _validator(path):
    return next(v for p, _, v in exposure._EXPOSED if p == path)


def test_env_validator_ignores_soft_404():
    v = _validator("/.env")
    assert v(200, b"<html><body>Not found = 404</body></html>") is False
    assert v(404, b"DB_PASSWORD=secret") is False
    assert v(200, b"APP_ENV=prod\nDB_PASSWORD=secret\n") is True


def test_git_and_phpinfo_validators():
    assert _validator("/.git/HEAD")(200, b"ref: refs/heads/main\n") is True
    assert _validator("/.git/HEAD")(200, b"<html>hello</html>") is False
    assert _validator("/phpinfo.php")(200, b"<title>phpinfo()</title>") is True
    assert _validator("/phpinfo.php")(200, b"<title>Home</title>") is False


def _fake_site(monkeypatch, response_headers, cookies=()):
    def fake_get(url, **kw):
        if url.startswith("http://"):
            return httpx.Response(200, content=b""), url.replace("http://", "https://"), [url]
        resp = httpx.Response(200, headers=[*response_headers.items(), *[("set-cookie", c) for c in cookies]],
                              content=b"<html></html>")
        return resp, url, [url]
    monkeypatch.setattr(target, "safe_get", fake_get)


def test_headers_weak_site(monkeypatch):
    _fake_site(monkeypatch, {"server": "Apache/2.4.1", "x-powered-by": "PHP/7.0"}, cookies=["sid=abc; Path=/"])
    out = {f.id: f for f in headers.check_http_and_headers("example.com")}
    for fid in ("hsts", "csp", "xfo", "xcto", "referrer", "permissions", "info_leak", "cookie_flags"):
        assert out[fid].passed is False, fid
    assert "Apache/2.4.1" in out["info_leak"].detail


def test_headers_strong_site(monkeypatch):
    _fake_site(monkeypatch, {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()", "server": "nginx"}, cookies=["sid=abc; Secure; HttpOnly"])
    out = {f.id: f for f in headers.check_http_and_headers("example.com")}
    for fid in ("hsts", "csp", "xfo", "xcto", "referrer", "permissions", "info_leak_ok", "cookie_flags_ok"):
        assert out[fid].passed is True, fid
