"""Runs all checks for a domain and assembles the result."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import target
from .checks import email_dns, exposure, headers, ports, tls
from .constants import SEVERITY_ORDER
from .models import Finding
from .scoring import grade, score


def run_scan(raw_domain: str, *, include_ports: bool = True) -> dict:
    host = target.normalize_domain(raw_domain)
    ips = target.resolve_public_ips(host)
    started = time.time()

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [
            pool.submit(tls.check_tls, host),
            pool.submit(headers.check_http_and_headers, host),
            pool.submit(email_dns.check_email_dns, host),
            pool.submit(exposure.check_exposed_files, host),
        ]
        if include_ports:
            futures.append(pool.submit(ports.check_open_ports, host, ips))
        for fut in futures:
            findings.extend(fut.result())

    findings.sort(key=lambda f: (f.passed, SEVERITY_ORDER[f.severity]))
    s = score(findings)
    return {
        "domain": host,
        "score": s,
        "grade": grade(s),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_seconds": round(time.time() - started, 1),
        "findings": [f.to_dict() for f in findings],
    }
