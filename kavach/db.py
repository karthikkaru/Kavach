"""Small SQLite store for scans and leads."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, domain TEXT, score INTEGER, grade TEXT,
    result_json TEXT, visitor TEXT, created REAL);
CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, name TEXT, company TEXT,
    domain TEXT, scan_id TEXT, created REAL);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        with self.connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def connect(self):
        with self._lock:
            conn = sqlite3.connect(self.path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()
