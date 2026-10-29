import pytest
from fastapi.testclient import TestClient

import kavach.scanner as scanner
from kavach.main import create_app


def _fake_scan(host, **kw):
    return {"domain": host, "score": 62, "grade": "C", "scanned_at": "2026-01-01T00:00:00+00:00",
            "duration_seconds": 1.0,
            "findings": [f.to_dict() for f in [
                scanner.Finding("a", "Headers", "<script>alert(1)</script>", "high", False, "d", "f"),
                scanner.Finding("b", "Headers", "B", "medium", False, "d", "f"),
                scanner.Finding("c", "Headers", "C", "low", False, "d", "f"),
                scanner.Finding("d", "Headers", "D", "low", False, "d", "f"),
                scanner.Finding("e", "SSL/TLS", "E ok", "info", True, "d")]]}


@pytest.fixture()
def make_client(tmp_path, monkeypatch):
    def _make(**env):
        monkeypatch.setenv("KAVACH_DB_PATH", str(tmp_path / "t.db"))
        monkeypatch.setenv("KAVACH_ADMIN_TOKEN", "secret-token")
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr(scanner, "run_scan", _fake_scan)
        return TestClient(create_app())
    return _make


def test_requires_consent(make_client):
    r = make_client().post("/api/scan", json={"domain": "example.com", "consent": False})
    assert r.status_code == 400 and "permission" in r.json()["error"]


def test_rejects_internal_target(make_client):
    assert make_client().post("/api/scan", json={"domain": "127.0.0.1", "consent": True}).status_code == 400


def test_free_view_is_gated_then_unlocked(make_client):
    c = make_client()
    r = c.post("/api/scan", json={"domain": "example.com", "consent": True}).json()
    assert r["full"] is False and len(r["findings"]) == 3 and r["hidden_count"] == 2
    assert r["summary"] == {"high": 1, "medium": 1, "low": 2, "passed": 1}

    assert c.post("/api/lead", json={"scan_id": r["scan_id"], "email": "nope"}).status_code == 400
    assert c.post("/api/lead", json={"scan_id": "zzz", "email": "a@b.co"}).status_code == 404

    full = c.post("/api/lead", json={"scan_id": r["scan_id"], "email": "A@B.co", "name": "A", "company": "B"}).json()
    assert full["full"] is True and len(full["findings"]) == 5 and full["hidden_count"] == 0


def test_admin_leads_protected(make_client):
    c = make_client()
    r = c.post("/api/scan", json={"domain": "example.com", "consent": True}).json()
    c.post("/api/lead", json={"scan_id": r["scan_id"], "email": "a@b.co"})
    assert c.get("/api/admin/leads").status_code == 404
    assert c.get("/api/admin/leads", headers={"x-admin-token": "wrong"}).status_code == 404
    rows = c.get("/api/admin/leads", headers={"x-admin-token": "secret-token"}).json()
    assert rows[0]["email"] == "a@b.co" and rows[0]["domain"] == "example.com"


def test_admin_disabled_without_token(make_client):
    c = make_client(KAVACH_ADMIN_TOKEN="")
    assert c.get("/api/admin/leads", headers={"x-admin-token": ""}).status_code == 404


def test_rate_limit(make_client):
    c = make_client(KAVACH_SCANS_PER_HOUR="2")
    codes = [c.post("/api/scan", json={"domain": f"site{i}.com", "consent": True}).status_code for i in range(4)]
    assert codes == [200, 200, 429, 429]


def test_index_and_health(make_client):
    c = make_client()
    r = c.get("/")
    assert r.status_code == 200 and "Kavach" in r.text
    assert c.get("/healthz").json() == {"ok": True}
