"""Kavach - website security health check API and web page.

Run:  uvicorn kavach.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import scanner
from .config import get_settings
from .db import Database
from .ratelimit import RateLimited, ResultCache, ScanLimiter
from .schemas import EMAIL_RE, LeadRequest, ScanRequest, public_view


def visitor_id(request: Request) -> str:
    # Behind a reverse proxy, run uvicorn with --proxy-headers so the real
    # visitor address is used for rate limiting.
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def create_app() -> FastAPI:
    settings = get_settings()
    db = Database(settings.db_path)
    limiter = ScanLimiter(settings.scans_per_hour)
    cache = ResultCache(settings.cache_seconds)

    app = FastAPI(title="Kavach", docs_url=None, redoc_url=None)
    app.state.settings, app.state.db, app.state.limiter, app.state.cache = settings, db, limiter, cache

    def view(result: dict, full: bool) -> dict:
        return public_view(result, full=full, free_findings=settings.free_findings)

    @app.exception_handler(HTTPException)
    async def http_error(_, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.post("/api/scan")
    def api_scan(body: ScanRequest, request: Request):
        if not body.consent:
            raise HTTPException(400, "Please confirm that you own this website or have permission to check it.")
        try:
            host = scanner.normalize_domain(body.domain)
        except scanner.ScanError as e:
            raise HTTPException(400, str(e))

        cached = cache.get(host)
        if cached:
            return view(cached, full=False)

        visitor = visitor_id(request)
        try:
            limiter.check(visitor)
        except RateLimited as e:
            raise HTTPException(429, str(e))

        try:
            result = scanner.run_scan(host)
        except scanner.ScanError as e:
            raise HTTPException(400, str(e))
        except Exception:  # never leak internals to visitors
            raise HTTPException(502, "The scan could not be completed. Please try again later.")

        result["scan_id"] = secrets.token_urlsafe(12)
        with db.connect() as c:
            c.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?)",
                      (result["scan_id"], host, result["score"], result["grade"],
                       json.dumps(result), visitor, time.time()))
        cache.put(host, result)
        return view(result, full=False)

    @app.post("/api/lead")
    def api_lead(body: LeadRequest):
        email = body.email.strip().lower()
        if not EMAIL_RE.match(email):
            raise HTTPException(400, "Please enter a valid email address.")
        with db.connect() as c:
            row = c.execute("SELECT result_json, domain FROM scans WHERE id=?", (body.scan_id,)).fetchone()
            if not row:
                raise HTTPException(404, "Scan not found. Please run the check again.")
            c.execute("INSERT INTO leads (email,name,company,domain,scan_id,created) VALUES (?,?,?,?,?,?)",
                      (email, body.name.strip(), body.company.strip(), row["domain"], body.scan_id, time.time()))
        return view(json.loads(row["result_json"]), full=True)

    @app.get("/api/admin/leads")
    def admin_leads(x_admin_token: str = Header(default="")):
        if not settings.admin_token or not secrets.compare_digest(x_admin_token, settings.admin_token):
            raise HTTPException(404, "Not found")
        with db.connect() as c:
            rows = c.execute("""SELECT l.email,l.name,l.company,l.domain,s.score,s.grade,l.created
                                FROM leads l LEFT JOIN scans s ON s.id=l.scan_id
                                ORDER BY l.created DESC LIMIT 500""").fetchall()
        return [dict(r) for r in rows]

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    app.mount("/static", StaticFiles(directory=settings.frontend_dir), name="static")

    @app.get("/")
    def index():
        return FileResponse(settings.frontend_dir / "index.html")

    return app


app = create_app()
