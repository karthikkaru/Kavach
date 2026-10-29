"""In-memory limits: scans per visitor per hour, and a short per-domain result cache.

Both reset when the app restarts and are per process. Use one worker, or move
this to Redis before scaling out.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimited(Exception):
    def __init__(self, wait_minutes: int):
        super().__init__(f"Scan limit reached. Please try again in about {wait_minutes} minutes.")
        self.wait_minutes = wait_minutes


class ScanLimiter:
    def __init__(self, per_hour: int):
        self.per_hour = per_hour
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, visitor: str) -> None:
        now = time.time()
        with self._lock:
            q = self._hits[visitor]
            while q and now - q[0] > 3600:
                q.popleft()
            if len(q) >= self.per_hour:
                raise RateLimited(int((3600 - (now - q[0])) / 60) + 1)
            q.append(now)


class ResultCache:
    def __init__(self, ttl_seconds: int):
        self.ttl = ttl_seconds
        self._items: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._items.get(key)
            if item and time.time() - item[0] < self.ttl:
                return item[1]
        return None

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._items[key] = (time.time(), value)
