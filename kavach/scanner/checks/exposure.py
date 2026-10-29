"""Well-known sensitive files that should never be public."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

import httpx

from .. import target
from ..models import Finding, ScanError


_EXPOSED = [
    ("/.env", "Environment file (.env)",
     lambda s, b: s == 200 and b"<html" not in b[:500].lower() and re.search(rb"^[A-Z0-9_]{3,}\s*=", b, re.M) is not None),
    ("/.git/HEAD", "Git repository (.git)",
     lambda s, b: s == 200 and b.strip().startswith(b"ref:")),
    ("/wp-config.php.bak", "WordPress config backup",
     lambda s, b: s == 200 and b"DB_NAME" in b),
    ("/phpinfo.php", "PHP info page",
     lambda s, b: s == 200 and b"phpinfo()" in b),
    ("/server-status", "Apache server-status page",
     lambda s, b: s == 200 and b"Apache Server Status" in b),
    ("/.DS_Store", "macOS .DS_Store file",
     lambda s, b: s == 200 and b.startswith(b"\x00\x00\x00\x01Bud1")),
]


def check_exposed_files(host: str) -> list[Finding]:
    exposed: list[str] = []

    def probe(item):
        path, label, validator = item
        try:
            resp, _, _ = target.safe_get(f"https://{host}{path}", max_redirects=0)
            if validator(resp.status_code, resp.content):
                return path
        except (httpx.HTTPError, ScanError):
            return None
        return None

    with ThreadPoolExecutor(max_workers=6) as pool:
        for result in pool.map(probe, _EXPOSED):
            if result:
                exposed.append(result)

    if exposed:
        return [Finding("exposed_files", "Exposure", "Sensitive files are publicly accessible", "high", False,
                        f"Reachable without login: {', '.join(exposed)}. These can leak passwords or source code.",
                        "Remove these files from the web root, block them in your server configuration, "
                        "and rotate any keys or passwords they contained.")]
    return [Finding("exposed_files_ok", "Exposure", "No common sensitive files found", "info", True,
                    f"Checked {len(_EXPOSED)} well-known paths.")]
