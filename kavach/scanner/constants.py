"""Tunable limits and scoring weights for the scanner."""

USER_AGENT = "Kavach-SecurityHealthCheck/0.1 (+passive; contact: security@techsilicon.com)"
HTTP_TIMEOUT = 6.0
MAX_BODY = 20_000  # bytes read from any response
MAX_REDIRECTS = 3

SEVERITY_PENALTY = {"high": 15, "medium": 8, "low": 3, "info": 0}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
