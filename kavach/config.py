"""Runtime settings, read from environment variables each time the app is created."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    db_path: str
    scans_per_hour: int
    admin_token: str
    cache_seconds: int
    free_findings: int
    frontend_dir: Path


def get_settings() -> Settings:
    return Settings(
        db_path=os.environ.get("KAVACH_DB_PATH", str(ROOT / "kavach.db")),
        scans_per_hour=int(os.environ.get("KAVACH_SCANS_PER_HOUR", "5")),
        admin_token=os.environ.get("KAVACH_ADMIN_TOKEN", ""),
        cache_seconds=int(os.environ.get("KAVACH_CACHE_SECONDS", "600")),
        free_findings=int(os.environ.get("KAVACH_FREE_FINDINGS", "3")),
        frontend_dir=Path(os.environ.get("KAVACH_FRONTEND_DIR", str(ROOT / "frontend"))),
    )
