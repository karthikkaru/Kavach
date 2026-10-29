# Kavach

**A free website security health check by [Tech Silicon](https://www.techsilicon.com).**
Enter a domain, get a score out of 100 and a plain-English list of fixes in about a minute.

Kavach reads only what a website already shows publicly. It does not exploit, log in or change anything.

| Check | What it looks for |
|---|---|
| SSL/TLS | Valid, unexpired certificate; modern TLS version |
| Transport | Does `http://` redirect to `https://` |
| Headers | HSTS, CSP, clickjacking, nosniff, referrer and permissions policies; server version leaks |
| Cookies | `Secure` and `HttpOnly` flags |
| Email | SPF, DKIM (common selectors) and DMARC |
| Exposure | Public `.env`, `.git`, phpinfo, server-status, backups, `.DS_Store` |
| Network | Databases, RDP, FTP, Telnet, SMB, Redis, MongoDB open to the internet |

Visitors see the top issues free and unlock the full report with fixes by giving an email address.

## Quick start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # optional; settings have safe defaults
uvicorn kavach.main:app --reload
# open http://localhost:8000
```

Run the tests:
```bash
pytest -q
```

Run with Docker:
```bash
docker build -t kavach .
docker run -p 8000:8000 -v kavach-data:/data -e KAVACH_ADMIN_TOKEN=change-me kavach
```

## Project layout
```
kavach/
  main.py          API routes and app factory
  config.py        settings from KAVACH_* environment variables
  db.py            SQLite storage (scans, leads)
  ratelimit.py     per-visitor scan limit and result cache
  schemas.py       request models and the public (gated) view
  scanner/
    target.py      input validation, SSRF protection, safe HTTP fetch
    engine.py      runs all checks and builds the result
    scoring.py     score and grade
    models.py      Finding, ScanError
    constants.py   limits and severity weights
    checks/        tls, headers, email_dns, exposure, ports
frontend/index.html  single-page UI (plain HTML/JS)
tests/               unit and API tests
docs/                architecture and roadmap
```

To add a check: create a module in `kavach/scanner/checks/` that returns a list of `Finding`
objects, then add it to `engine.py`. Add a test in `tests/test_checks.py`.

## Settings
| Variable | Default | Purpose |
|---|---|---|
| `KAVACH_ADMIN_TOKEN` | empty (admin off) | Long random value to read leads |
| `KAVACH_DB_PATH` | `./kavach.db` | SQLite file |
| `KAVACH_SCANS_PER_HOUR` | `5` | Scans per visitor per hour |
| `KAVACH_CACHE_SECONDS` | `600` | Reuse a domain's result for this long |
| `KAVACH_FREE_FINDINGS` | `3` | Issues shown before an email is given |

View leads:
```bash
curl -H "x-admin-token: YOUR_TOKEN" http://localhost:8000/api/admin/leads
```

## Safety
- A consent checkbox is required for every scan.
- Only domain names on ports 80 and 443. IP addresses, `localhost` and private or internal addresses are refused, and every redirect hop is re-checked.
- Per-visitor rate limit and a short per-domain cache.
- Text taken from a scanned site is shown as plain text, never as HTML.

## Known limits
- A health check, **not** a vulnerability scan or penetration test. Say so on any page that uses it.
- DNS rebinding could in theory bypass the internal-address check. Run the scanner in a network-isolated container before public launch.
- DKIM is checked only for common selector names.
- Rate limit and cache are in memory and per process: use one worker, or move them to Redis before scaling.
- Not built yet: accounts, scan history, scheduled re-scans, payments, branded PDF, active scanning. See `docs/ROADMAP.md`.

More detail: `docs/ARCHITECTURE.md`.
