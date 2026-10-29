# Roadmap

## Done (v0.1 demo)
- Passive checks: TLS, headers, cookies, email DNS, exposed files, risky ports
- Score and grade, gated full report, lead capture, admin lead list
- Consent, SSRF protection, rate limit, cache
- Tests and Docker image

## Beta
| Item | Notes |
|---|---|
| Branded PDF report | Server-side PDF; today the browser's Print / Save as PDF is used |
| Domain ownership verification | DNS TXT record or uploaded file; required before any deeper scan |
| Email the report | Needs an email provider and an unsubscribe link |
| Fix guides | Step-by-step guide per finding (Nginx, Apache, Cloudflare, WordPress) |
| Isolated scan worker | Run scans in a network-isolated container |

## Paid MVP
- Accounts and scan history
- Scheduled re-scans and alerts
- Plans and payments
- Admin dashboard

## Later
- Active scanning with open-source engines (OWASP ZAP, Nuclei), only after ownership verification
- Compliance checker (SEBI CSCRF, CERT-In) sharing the same accounts
- HR hiring workflow modules
