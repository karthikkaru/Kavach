"""Shared result types."""
from __future__ import annotations

from dataclasses import asdict, dataclass


class ScanError(Exception):
    """User-facing error (bad input, unreachable host, blocked target)."""


@dataclass
class Finding:
    id: str
    category: str
    title: str
    severity: str  # high | medium | low | info
    passed: bool
    detail: str
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
