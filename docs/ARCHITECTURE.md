# Architecture

## Flow
```
Browser -> POST /api/scan {domain, consent}
            |- normalize + validate domain          (scanner/target.py)
            |- return cached result if < 10 min old (ratelimit.py)
            |- per-visitor rate limit               (ratelimit.py)
            |- run checks in parallel               (scanner/engine.py)
            |    tls | headers | email_dns | exposure | ports
            |- score + grade                        (scanner/scoring.py)
            |- store scan in SQLite                 (db.py)
            '- return summary + top issues only     (schemas.public_view)

Browser -> POST /api/lead {scan_id, email, ...}
            |- validate email, find the scan
            |- store lead
            '- return the full report
```

## Design rules
1. **Passive only.** Checks read public information. No exploitation, logins or fuzzing.
2. **Every outbound request goes through `scanner/target.py`.** It refuses private/internal addresses and re-checks each redirect. New checks must not open their own connections to user-supplied hosts without going through it (the TLS and port checks connect directly, to the already-validated public address).
3. **Untrusted text.** Header values and error text come from the scanned site. The UI renders them with `textContent`.
4. **Findings are the contract.** Each check returns `Finding(id, category, title, severity, passed, detail, fix)`. Failed findings reduce the score by severity (high 15, medium 8, low 3).
5. **Gating is server-side.** The free response never contains the hidden findings.

## Data
SQLite, two tables: `scans` (full result JSON, hashed visitor id) and `leads` (email, name, company, domain, scan id). Leads are personal data: back the file up, restrict access, and add an unsubscribe link before any marketing email.

## Scaling notes
Single process today. For multiple workers or servers, move the rate limiter and cache to Redis and the database to Postgres.
