"""Turn findings into a score and a grade."""
from __future__ import annotations

from .constants import SEVERITY_PENALTY
from .models import Finding


def score(findings: list[Finding]) -> int:
    total = 100
    for f in findings:
        if not f.passed:
            total -= SEVERITY_PENALTY.get(f.severity, 0)
    return max(0, min(100, total))


def grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
