"""Request bodies and the public view of a scan result."""
from __future__ import annotations

import re

from pydantic import BaseModel, Field

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


class ScanRequest(BaseModel):
    domain: str = Field(..., max_length=300)
    consent: bool = False


class LeadRequest(BaseModel):
    scan_id: str = Field(..., max_length=64)
    email: str = Field(..., max_length=200)
    name: str = Field("", max_length=120)
    company: str = Field("", max_length=160)


def public_view(result: dict, *, full: bool, free_findings: int) -> dict:
    """What the visitor sees. Without an email, only the top issues are included."""
    findings = result["findings"]
    failed = [f for f in findings if not f["passed"] and f["severity"] != "info"]
    shown = findings if full else failed[:free_findings]
    return {
        "scan_id": result["scan_id"],
        "domain": result["domain"],
        "score": result["score"],
        "grade": result["grade"],
        "scanned_at": result["scanned_at"],
        "summary": {
            "high": sum(1 for f in failed if f["severity"] == "high"),
            "medium": sum(1 for f in failed if f["severity"] == "medium"),
            "low": sum(1 for f in failed if f["severity"] == "low"),
            "passed": sum(1 for f in findings if f["passed"]),
        },
        "full": full,
        "hidden_count": 0 if full else max(0, len(findings) - len(shown)),
        "findings": shown,
    }
